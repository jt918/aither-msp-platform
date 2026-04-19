"""
AITHER Platform - SIEM Ingest Pipeline
Logic Card: LC-014b

Ingests security events from syslog, Windows Event Log, Elasticsearch/Wazuh,
Splunk, CSV, and generic JSON sources.  Normalizes, correlates, and feeds
incidents into the Cyber-911 incident response system.

G-46: DB persistence with in-memory fallback.
"""

import re
import uuid
import time
import logging
from collections import deque
from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from xml.etree import ElementTree

logger = logging.getLogger(__name__)

try:
    from sqlalchemy.orm import Session
    from models.siem import (
        SIEMSource as SIEMSourceModel,
        RawEvent as RawEventModel,
        ParseRule as ParseRuleModel,
        CorrelationRule as CorrelationRuleModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

# Import Cyber-911 types for incident creation
try:
    from services.msp.cyber_911 import (
        Cyber911Service,
        SecurityEvent,
        ThreatType,
        SeverityLevel,
    )
    CYBER911_AVAILABLE = True
except Exception:
    CYBER911_AVAILABLE = False


# ============================================================
# Enums
# ============================================================

class SourceType(str, Enum):
    SYSLOG = "syslog"
    ELASTIC = "elastic"
    WAZUH = "wazuh"
    WINDOWS_EVENT = "windows_event"
    SPLUNK = "splunk"
    CSV_IMPORT = "csv_import"
    API = "api"


class CorrelationAction(str, Enum):
    CREATE_INCIDENT = "create_incident"
    ALERT = "alert"
    LOG = "log"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class SIEMSourceDC:
    """Registered event source."""
    source_id: str
    name: str
    source_type: str
    config: Dict[str, Any] = field(default_factory=dict)
    is_enabled: bool = True
    events_received: int = 0
    events_processed: int = 0
    last_event_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RawEventDC:
    """Raw ingested event."""
    event_id: str
    source_id: str
    timestamp: datetime
    raw_data: Dict[str, Any] = field(default_factory=dict)
    parsed: bool = False
    event_type: str = ""
    severity_raw: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    hostname: str = ""
    user: str = ""
    message: str = ""


@dataclass
class ParseRuleDC:
    """Normalization rule for a source type."""
    rule_id: str
    source_type: str
    field_mappings: Dict[str, str] = field(default_factory=dict)
    severity_mapping: Dict[str, str] = field(default_factory=dict)
    event_type_mapping: Dict[str, str] = field(default_factory=dict)
    is_default: bool = False


@dataclass
class CorrelationRuleDC:
    """Correlation rule that can trigger Cyber-911 incidents."""
    rule_id: str
    name: str
    description: str = ""
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    time_window_seconds: int = 300
    min_events: int = 1
    action: str = "create_incident"
    severity: str = "HIGH"
    threat_type: str = ""
    is_enabled: bool = True


@dataclass
class IngestStats:
    """Live ingest statistics."""
    total_received: int = 0
    total_parsed: int = 0
    total_correlated: int = 0
    total_incidents_created: int = 0
    events_per_second: float = 0.0
    error_count: int = 0


# ============================================================
# Syslog severity → Cyber-911 SeverityLevel
# ============================================================

SYSLOG_SEVERITY_MAP: Dict[int, str] = {
    0: "CRITICAL",   # Emergency
    1: "CRITICAL",   # Alert
    2: "HIGH",       # Critical
    3: "HIGH",       # Error
    4: "MEDIUM",     # Warning
    5: "LOW",        # Notice
    6: "INFO",       # Informational
    7: "INFO",       # Debug
}

GENERIC_SEVERITY_MAP: Dict[str, str] = {
    "emergency": "CRITICAL",
    "emerg": "CRITICAL",
    "alert": "CRITICAL",
    "critical": "HIGH",
    "crit": "HIGH",
    "error": "HIGH",
    "err": "HIGH",
    "warning": "MEDIUM",
    "warn": "MEDIUM",
    "notice": "LOW",
    "informational": "INFO",
    "info": "INFO",
    "debug": "INFO",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "1": "CRITICAL",
    "2": "HIGH",
    "3": "HIGH",
    "4": "MEDIUM",
    "5": "LOW",
    "6": "INFO",
    "7": "INFO",
}

# ============================================================
# Windows Event ID → threat classification
# ============================================================

WINDOWS_EVENT_THREAT_MAP: Dict[int, Dict[str, Any]] = {
    4625: {"event_type": "failed_login", "severity": "MEDIUM", "threat": "CREDENTIAL_COMPROMISE"},
    4720: {"event_type": "account_created", "severity": "MEDIUM", "threat": "UNAUTHORIZED_ACCESS"},
    4732: {"event_type": "admin_group_add", "severity": "HIGH", "threat": "UNAUTHORIZED_ACCESS"},
    1102: {"event_type": "audit_log_cleared", "severity": "HIGH", "threat": "INSIDER_THREAT"},
    4688: {"event_type": "process_created", "severity": "LOW", "threat": "MALWARE"},
    4624: {"event_type": "successful_login", "severity": "INFO", "threat": ""},
    4648: {"event_type": "explicit_credential_logon", "severity": "MEDIUM", "threat": "CREDENTIAL_COMPROMISE"},
    7045: {"event_type": "service_installed", "severity": "MEDIUM", "threat": "MALWARE"},
}

SUSPICIOUS_PROCESSES = [
    "powershell.exe -enc", "cmd.exe /c", "certutil", "bitsadmin",
    "mshta", "wscript", "cscript", "regsvr32", "rundll32",
    "mimikatz", "psexec", "procdump", "lazagne",
]


# ============================================================
# Pre-built correlation rules
# ============================================================

DEFAULT_CORRELATION_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "COR-WIN-BRUTE-001",
        "name": "Windows Brute Force (5 failed logins in 300s)",
        "conditions": [{"field": "event_type", "op": "eq", "value": "failed_login"}],
        "time_window_seconds": 300,
        "min_events": 5,
        "action": "create_incident",
        "severity": "HIGH",
        "threat_type": "CREDENTIAL_COMPROMISE",
    },
    {
        "rule_id": "COR-WIN-PRIVESC-001",
        "name": "Windows Privilege Escalation (account created + admin group add in 60s)",
        "conditions": [
            {"field": "event_type", "op": "in", "value": ["account_created", "admin_group_add"]},
        ],
        "time_window_seconds": 60,
        "min_events": 2,
        "action": "create_incident",
        "severity": "CRITICAL",
        "threat_type": "UNAUTHORIZED_ACCESS",
    },
    {
        "rule_id": "COR-WIN-TAMPER-001",
        "name": "Windows Audit Log Cleared",
        "conditions": [{"field": "event_type", "op": "eq", "value": "audit_log_cleared"}],
        "time_window_seconds": 1,
        "min_events": 1,
        "action": "create_incident",
        "severity": "HIGH",
        "threat_type": "INSIDER_THREAT",
    },
    {
        "rule_id": "COR-WIN-MALWARE-001",
        "name": "Suspicious Process Execution",
        "conditions": [
            {"field": "event_type", "op": "eq", "value": "process_created"},
            {"field": "message", "op": "contains_any", "value": SUSPICIOUS_PROCESSES},
        ],
        "time_window_seconds": 1,
        "min_events": 1,
        "action": "create_incident",
        "severity": "HIGH",
        "threat_type": "MALWARE",
    },
]


# ============================================================
# Service
# ============================================================

class SIEMIngestService:
    """
    SIEM Ingest Pipeline

    TRIGGER: External security events from syslog, Windows Event Log,
             Elasticsearch/Wazuh, Splunk, CSV, or generic JSON.
    INPUT: Raw security events in various formats.
    PROCESS:
        1. Ingest raw event from source
        2. Parse / normalize using parse rules
        3. Store normalized event
        4. Run correlation rules against event window
        5. Auto-create Cyber-911 incidents on correlation match
    OUTPUT: Normalized events, correlated incidents.
    STORAGE: siem_sources, siem_raw_events, siem_parse_rules,
             siem_correlation_rules tables.

    Accepts optional db: Session for persistence.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory state
        self.sources: Dict[str, SIEMSourceDC] = {}
        self.events: deque = deque(maxlen=10_000)
        self.parse_rules: Dict[str, ParseRuleDC] = {}
        self.correlation_rules: Dict[str, CorrelationRuleDC] = {}
        self.stats = IngestStats()

        # Timing for events/sec calculation
        self._window_start = time.time()
        self._window_count = 0

        # Hydrate
        if self._use_db:
            self._hydrate_from_db()

        # Ensure default correlation rules exist
        self._ensure_default_rules()

    # ----------------------------------------------------------
    # Hydration
    # ----------------------------------------------------------

    def _hydrate_from_db(self) -> None:
        """Load persisted state from the database."""
        try:
            for row in self.db.query(SIEMSourceModel).all():
                self.sources[row.source_id] = SIEMSourceDC(
                    source_id=row.source_id, name=row.name,
                    source_type=row.source_type, config=row.config or {},
                    is_enabled=row.is_enabled, events_received=row.events_received or 0,
                    events_processed=row.events_processed or 0,
                    last_event_at=row.last_event_at,
                    created_at=row.created_at or datetime.utcnow(),
                )
            for row in self.db.query(ParseRuleModel).all():
                self.parse_rules[row.rule_id] = ParseRuleDC(
                    rule_id=row.rule_id, source_type=row.source_type,
                    field_mappings=row.field_mappings or {},
                    severity_mapping=row.severity_mapping or {},
                    event_type_mapping=row.event_type_mapping or {},
                    is_default=row.is_default,
                )
            for row in self.db.query(CorrelationRuleModel).all():
                self.correlation_rules[row.rule_id] = CorrelationRuleDC(
                    rule_id=row.rule_id, name=row.name,
                    description=row.description or "",
                    conditions=row.conditions or [],
                    time_window_seconds=row.time_window_seconds or 300,
                    min_events=row.min_events or 1,
                    action=row.action or "create_incident",
                    severity=row.severity or "HIGH",
                    threat_type=row.threat_type or "",
                    is_enabled=row.is_enabled,
                )
            # Load recent events into ring buffer
            recent = (
                self.db.query(RawEventModel)
                .order_by(RawEventModel.timestamp.desc())
                .limit(5000)
                .all()
            )
            for row in reversed(recent):
                self.events.append(RawEventDC(
                    event_id=row.event_id, source_id=row.source_id,
                    timestamp=row.timestamp, raw_data=row.raw_data or {},
                    parsed=row.parsed, event_type=row.event_type or "",
                    severity_raw=row.severity_raw or "",
                    source_ip=row.source_ip or "", dest_ip=row.dest_ip or "",
                    hostname=row.hostname or "", user=row.user or "",
                    message=row.message or "",
                ))
        except Exception as e:
            logger.error(f"DB error hydrating SIEM state: {e}")

    def _ensure_default_rules(self) -> None:
        """Seed default correlation rules if not present."""
        for rule_def in DEFAULT_CORRELATION_RULES:
            rid = rule_def["rule_id"]
            if rid not in self.correlation_rules:
                rule = CorrelationRuleDC(
                    rule_id=rid,
                    name=rule_def["name"],
                    conditions=rule_def["conditions"],
                    time_window_seconds=rule_def["time_window_seconds"],
                    min_events=rule_def["min_events"],
                    action=rule_def["action"],
                    severity=rule_def["severity"],
                    threat_type=rule_def.get("threat_type", ""),
                )
                self.correlation_rules[rid] = rule
                self._persist_correlation_rule(rule)

    # ----------------------------------------------------------
    # Persistence helpers
    # ----------------------------------------------------------

    def _persist_source(self, src: SIEMSourceDC) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(SIEMSourceModel).filter(
                SIEMSourceModel.source_id == src.source_id
            ).first()
            if existing:
                existing.name = src.name
                existing.source_type = src.source_type
                existing.config = src.config
                existing.is_enabled = src.is_enabled
                existing.events_received = src.events_received
                existing.events_processed = src.events_processed
                existing.last_event_at = src.last_event_at
            else:
                self.db.add(SIEMSourceModel(
                    source_id=src.source_id, name=src.name,
                    source_type=src.source_type, config=src.config,
                    is_enabled=src.is_enabled,
                    events_received=src.events_received,
                    events_processed=src.events_processed,
                    last_event_at=src.last_event_at,
                ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting source: {e}")
            self.db.rollback()

    def _persist_event(self, evt: RawEventDC, severity_normalized: str = "") -> None:
        if not self._use_db:
            return
        try:
            self.db.add(RawEventModel(
                event_id=evt.event_id, source_id=evt.source_id,
                timestamp=evt.timestamp, raw_data=evt.raw_data,
                parsed=evt.parsed, event_type=evt.event_type,
                severity_raw=evt.severity_raw,
                severity_normalized=severity_normalized,
                source_ip=evt.source_ip, dest_ip=evt.dest_ip,
                hostname=evt.hostname, user=evt.user,
                message=evt.message,
            ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting event: {e}")
            self.db.rollback()

    def _persist_parse_rule(self, rule: ParseRuleDC) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(ParseRuleModel).filter(
                ParseRuleModel.rule_id == rule.rule_id
            ).first()
            if existing:
                existing.source_type = rule.source_type
                existing.field_mappings = rule.field_mappings
                existing.severity_mapping = rule.severity_mapping
                existing.event_type_mapping = rule.event_type_mapping
                existing.is_default = rule.is_default
            else:
                self.db.add(ParseRuleModel(
                    rule_id=rule.rule_id, source_type=rule.source_type,
                    field_mappings=rule.field_mappings,
                    severity_mapping=rule.severity_mapping,
                    event_type_mapping=rule.event_type_mapping,
                    is_default=rule.is_default,
                ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting parse rule: {e}")
            self.db.rollback()

    def _persist_correlation_rule(self, rule: CorrelationRuleDC) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(CorrelationRuleModel).filter(
                CorrelationRuleModel.rule_id == rule.rule_id
            ).first()
            if existing:
                existing.name = rule.name
                existing.description = rule.description
                existing.conditions = rule.conditions
                existing.time_window_seconds = rule.time_window_seconds
                existing.min_events = rule.min_events
                existing.action = rule.action
                existing.severity = rule.severity
                existing.threat_type = rule.threat_type
                existing.is_enabled = rule.is_enabled
            else:
                self.db.add(CorrelationRuleModel(
                    rule_id=rule.rule_id, name=rule.name,
                    description=rule.description,
                    conditions=rule.conditions,
                    time_window_seconds=rule.time_window_seconds,
                    min_events=rule.min_events,
                    action=rule.action, severity=rule.severity,
                    threat_type=rule.threat_type,
                    is_enabled=rule.is_enabled,
                ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting correlation rule: {e}")
            self.db.rollback()

    def _delete_db_row(self, model, filter_col, filter_val) -> None:
        if not self._use_db:
            return
        try:
            self.db.query(model).filter(filter_col == filter_val).delete()
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error deleting row: {e}")
            self.db.rollback()

    # ----------------------------------------------------------
    # Source CRUD
    # ----------------------------------------------------------

    def register_source(self, name: str, source_type: str,
                        config: Dict[str, Any] = None) -> SIEMSourceDC:
        """Register a new event source."""
        src = SIEMSourceDC(
            source_id=f"SRC-{uuid.uuid4().hex[:12].upper()}",
            name=name,
            source_type=source_type,
            config=config or {},
        )
        self.sources[src.source_id] = src
        self._persist_source(src)
        logger.info(f"Registered SIEM source {src.source_id}: {name} ({source_type})")
        return src

    def update_source(self, source_id: str, **kwargs) -> Optional[SIEMSourceDC]:
        src = self.sources.get(source_id)
        if not src:
            return None
        for k, v in kwargs.items():
            if hasattr(src, k):
                setattr(src, k, v)
        self._persist_source(src)
        return src

    def delete_source(self, source_id: str) -> bool:
        if source_id not in self.sources:
            return False
        del self.sources[source_id]
        if self._use_db:
            self._delete_db_row(SIEMSourceModel, SIEMSourceModel.source_id, source_id)
        return True

    def list_sources(self) -> List[SIEMSourceDC]:
        return list(self.sources.values())

    def get_source(self, source_id: str) -> Optional[SIEMSourceDC]:
        return self.sources.get(source_id)

    # ----------------------------------------------------------
    # Parse Rule CRUD
    # ----------------------------------------------------------

    def create_parse_rule(self, source_type: str,
                          field_mappings: Dict = None,
                          severity_mapping: Dict = None,
                          event_type_mapping: Dict = None,
                          is_default: bool = False) -> ParseRuleDC:
        rule = ParseRuleDC(
            rule_id=f"PR-{uuid.uuid4().hex[:12].upper()}",
            source_type=source_type,
            field_mappings=field_mappings or {},
            severity_mapping=severity_mapping or {},
            event_type_mapping=event_type_mapping or {},
            is_default=is_default,
        )
        self.parse_rules[rule.rule_id] = rule
        self._persist_parse_rule(rule)
        return rule

    def update_parse_rule(self, rule_id: str, **kwargs) -> Optional[ParseRuleDC]:
        rule = self.parse_rules.get(rule_id)
        if not rule:
            return None
        for k, v in kwargs.items():
            if hasattr(rule, k):
                setattr(rule, k, v)
        self._persist_parse_rule(rule)
        return rule

    def list_parse_rules(self, source_type: str = None) -> List[ParseRuleDC]:
        rules = list(self.parse_rules.values())
        if source_type:
            rules = [r for r in rules if r.source_type == source_type]
        return rules

    # ----------------------------------------------------------
    # Correlation Rule CRUD
    # ----------------------------------------------------------

    def create_correlation_rule(self, name: str, conditions: List[Dict],
                                time_window_seconds: int = 300,
                                min_events: int = 1,
                                action: str = "create_incident",
                                severity: str = "HIGH",
                                threat_type: str = "",
                                description: str = "") -> CorrelationRuleDC:
        rule = CorrelationRuleDC(
            rule_id=f"COR-{uuid.uuid4().hex[:12].upper()}",
            name=name, description=description,
            conditions=conditions,
            time_window_seconds=time_window_seconds,
            min_events=min_events,
            action=action, severity=severity,
            threat_type=threat_type,
        )
        self.correlation_rules[rule.rule_id] = rule
        self._persist_correlation_rule(rule)
        return rule

    def update_correlation_rule(self, rule_id: str, **kwargs) -> Optional[CorrelationRuleDC]:
        rule = self.correlation_rules.get(rule_id)
        if not rule:
            return None
        for k, v in kwargs.items():
            if hasattr(rule, k):
                setattr(rule, k, v)
        self._persist_correlation_rule(rule)
        return rule

    def list_correlation_rules(self) -> List[CorrelationRuleDC]:
        return list(self.correlation_rules.values())

    # ----------------------------------------------------------
    # Ingest endpoints
    # ----------------------------------------------------------

    def ingest_syslog(self, raw_message: str, source_ip: str = "") -> RawEventDC:
        """
        Parse RFC 5424 / RFC 3164 syslog message and ingest.
        RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
        RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG
        """
        event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
        pri = None
        facility = None
        severity_int = None
        hostname = ""
        message = raw_message
        timestamp = datetime.utcnow()

        # Extract PRI
        pri_match = re.match(r"<(\d{1,3})>", raw_message)
        if pri_match:
            pri = int(pri_match.group(1))
            facility = pri // 8
            severity_int = pri % 8
            rest = raw_message[pri_match.end():]

            # Try RFC 5424 (starts with version digit)
            rfc5424 = re.match(
                r"(\d)\s+"                            # version
                r"(\d{4}-\d{2}-\d{2}T[\d:.]+\S*)\s+"  # timestamp
                r"(\S+)\s+"                            # hostname
                r"(\S+)\s+"                            # app-name
                r"(\S+)\s+"                            # procid
                r"(\S+)\s*"                            # msgid
                r"(.*)",                               # message
                rest, re.DOTALL,
            )
            if rfc5424:
                try:
                    ts_str = rfc5424.group(2)
                    timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    pass
                hostname = rfc5424.group(3)
                message = rfc5424.group(7).strip()
            else:
                # RFC 3164
                rfc3164 = re.match(
                    r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
                    r"(\S+)\s+"
                    r"(.*)",
                    rest, re.DOTALL,
                )
                if rfc3164:
                    hostname = rfc3164.group(2)
                    message = rfc3164.group(3).strip()

        severity_raw = str(severity_int) if severity_int is not None else ""
        severity_normalized = self._normalize_severity(severity_raw, "syslog")

        evt = RawEventDC(
            event_id=event_id, source_id="syslog",
            timestamp=timestamp,
            raw_data={"raw_message": raw_message, "facility": facility, "severity_int": severity_int},
            parsed=True,
            event_type="syslog",
            severity_raw=severity_raw,
            source_ip=source_ip,
            hostname=hostname,
            message=message,
        )
        self._store_event(evt, severity_normalized)
        return evt

    def ingest_windows_event(self, event_xml: str) -> RawEventDC:
        """Parse Windows Event Log XML and ingest."""
        event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.utcnow()
        win_event_id = 0
        hostname = ""
        user = ""
        message = ""
        source_ip = ""

        try:
            # Strip namespace for easier parsing
            clean_xml = re.sub(r'\sxmlns=["\'][^"\']*["\']', '', event_xml)
            root = ElementTree.fromstring(clean_xml)

            # System block
            sys_node = root.find(".//System")
            if sys_node is not None:
                eid_node = sys_node.find("EventID")
                if eid_node is not None and eid_node.text:
                    win_event_id = int(eid_node.text)
                time_node = sys_node.find("TimeCreated")
                if time_node is not None:
                    ts_str = time_node.get("SystemTime", "")
                    if ts_str:
                        try:
                            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                        except Exception:
                            pass
                comp_node = sys_node.find("Computer")
                if comp_node is not None and comp_node.text:
                    hostname = comp_node.text

            # EventData block
            data_node = root.find(".//EventData")
            data_fields: Dict[str, str] = {}
            if data_node is not None:
                for d in data_node.findall("Data"):
                    name = d.get("Name", "")
                    val = d.text or ""
                    if name:
                        data_fields[name] = val

            user = data_fields.get("TargetUserName", data_fields.get("SubjectUserName", ""))
            source_ip = data_fields.get("IpAddress", "")
            message = data_fields.get("CommandLine", data_fields.get("NewProcessName", ""))
            if not message:
                message = f"Windows EventID {win_event_id}"

        except ElementTree.ParseError as e:
            logger.warning(f"Failed to parse Windows Event XML: {e}")
            message = event_xml[:500]

        # Map event ID
        mapping = WINDOWS_EVENT_THREAT_MAP.get(win_event_id, {})
        event_type = mapping.get("event_type", f"win_event_{win_event_id}")
        severity_raw = mapping.get("severity", "INFO")

        evt = RawEventDC(
            event_id=event_id, source_id="windows_event",
            timestamp=timestamp,
            raw_data={"xml": event_xml, "event_id_win": win_event_id, "fields": data_fields if 'data_fields' in dir() else {}},
            parsed=True,
            event_type=event_type,
            severity_raw=severity_raw,
            source_ip=source_ip,
            hostname=hostname,
            user=user,
            message=message,
        )
        severity_normalized = self._normalize_severity(severity_raw, "windows_event")
        self._store_event(evt, severity_normalized)
        return evt

    def ingest_elastic_alert(self, alert_json: Dict[str, Any]) -> RawEventDC:
        """Parse Elasticsearch / Wazuh alert JSON and ingest."""
        event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.utcnow()

        # Elastic common schema fields
        ts_str = alert_json.get("@timestamp", alert_json.get("timestamp", ""))
        if ts_str:
            try:
                timestamp = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass

        # Wazuh-specific fields
        rule_info = alert_json.get("rule", {})
        agent_info = alert_json.get("agent", {})

        event_type = rule_info.get("description", alert_json.get("event.category", "elastic_alert"))
        severity_raw = str(rule_info.get("level", alert_json.get("event.severity", "")))
        source_ip = (
            alert_json.get("source", {}).get("ip", "")
            or alert_json.get("data", {}).get("srcip", "")
            or alert_json.get("src_ip", "")
        )
        dest_ip = (
            alert_json.get("destination", {}).get("ip", "")
            or alert_json.get("data", {}).get("dstip", "")
            or alert_json.get("dest_ip", "")
        )
        hostname = agent_info.get("name", alert_json.get("host", {}).get("name", ""))
        user = alert_json.get("user", {}).get("name", alert_json.get("data", {}).get("srcuser", ""))
        message = rule_info.get("description", alert_json.get("message", ""))

        evt = RawEventDC(
            event_id=event_id, source_id="elastic",
            timestamp=timestamp,
            raw_data=alert_json,
            parsed=True,
            event_type=event_type,
            severity_raw=severity_raw,
            source_ip=source_ip,
            dest_ip=dest_ip,
            hostname=hostname,
            user=user,
            message=message,
        )
        severity_normalized = self._normalize_severity(severity_raw, "elastic")
        self._store_event(evt, severity_normalized)
        return evt

    def ingest_generic(self, event_dict: Dict[str, Any]) -> RawEventDC:
        """Generic JSON event ingest with best-effort field extraction."""
        event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.utcnow()

        ts_str = event_dict.get("timestamp", event_dict.get("@timestamp", ""))
        if ts_str:
            try:
                timestamp = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass

        evt = RawEventDC(
            event_id=event_id,
            source_id=event_dict.get("source_id", "generic"),
            timestamp=timestamp,
            raw_data=event_dict,
            parsed=True,
            event_type=event_dict.get("event_type", event_dict.get("type", "")),
            severity_raw=str(event_dict.get("severity", event_dict.get("level", ""))),
            source_ip=event_dict.get("source_ip", event_dict.get("src_ip", "")),
            dest_ip=event_dict.get("dest_ip", event_dict.get("dst_ip", "")),
            hostname=event_dict.get("hostname", event_dict.get("host", "")),
            user=event_dict.get("user", event_dict.get("username", "")),
            message=event_dict.get("message", event_dict.get("msg", "")),
        )
        severity_normalized = self._normalize_severity(evt.severity_raw, "generic")
        self._store_event(evt, severity_normalized)
        return evt

    def ingest_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk ingest list of generic JSON events."""
        results = []
        errors = 0
        for e in events:
            try:
                evt = self.ingest_generic(e)
                results.append({"event_id": evt.event_id, "success": True})
            except Exception as ex:
                errors += 1
                self.stats.error_count += 1
                results.append({"event_id": None, "success": False, "error": str(ex)})
        return {
            "total": len(events),
            "ingested": len(events) - errors,
            "errors": errors,
            "results": results,
        }

    # ----------------------------------------------------------
    # Parse / normalize
    # ----------------------------------------------------------

    def parse_event(self, raw_event: RawEventDC, source_type: str = "") -> RawEventDC:
        """Apply parse rules to further normalize a raw event."""
        st = source_type or raw_event.source_id
        applicable = [r for r in self.parse_rules.values() if r.source_type == st]
        if not applicable:
            return raw_event

        rule = applicable[0]
        raw = raw_event.raw_data

        # Apply field mappings
        for target_field, source_path in rule.field_mappings.items():
            val = raw.get(source_path, "")
            if val and hasattr(raw_event, target_field):
                setattr(raw_event, target_field, str(val))

        # Apply severity mapping
        if raw_event.severity_raw in rule.severity_mapping:
            raw_event.severity_raw = rule.severity_mapping[raw_event.severity_raw]

        # Apply event type mapping
        if raw_event.event_type in rule.event_type_mapping:
            raw_event.event_type = rule.event_type_mapping[raw_event.event_type]

        raw_event.parsed = True
        return raw_event

    def _normalize_severity(self, raw_severity: str, source_type: str) -> str:
        """Map various severity formats to Cyber-911 SeverityLevel names."""
        raw = raw_severity.strip().lower()

        # Syslog numeric
        if source_type == "syslog":
            try:
                return SYSLOG_SEVERITY_MAP.get(int(raw), "INFO")
            except (ValueError, TypeError):
                pass

        # Wazuh / Elastic numeric levels (1-15 scale)
        if source_type in ("elastic", "wazuh"):
            try:
                level = int(raw)
                if level >= 12:
                    return "CRITICAL"
                elif level >= 8:
                    return "HIGH"
                elif level >= 5:
                    return "MEDIUM"
                elif level >= 3:
                    return "LOW"
                else:
                    return "INFO"
            except (ValueError, TypeError):
                pass

        # Generic string lookup
        return GENERIC_SEVERITY_MAP.get(raw, "INFO")

    def _classify_threat_type(self, event: RawEventDC) -> str:
        """Map an event to a Cyber-911 ThreatType value."""
        et = event.event_type.lower()
        msg = event.message.lower()

        if "failed_login" in et or "brute" in et:
            return "credential_compromise"
        if "account_created" in et or "admin_group" in et or "unauthorized" in et:
            return "unauthorized_access"
        if "audit_log_cleared" in et or "insider" in et:
            return "insider_threat"
        if "malware" in et or "virus" in et or "trojan" in et:
            return "malware"
        if "ransomware" in msg or "ransom" in msg:
            return "ransomware"
        if "phishing" in et or "phish" in msg:
            return "phishing"
        if "ddos" in et or "flood" in et:
            return "ddos"
        if "exfil" in msg or "data_transfer" in msg:
            return "data_exfiltration"
        if any(proc in msg for proc in SUSPICIOUS_PROCESSES):
            return "malware"
        if "process_created" in et:
            return "malware"
        return "policy_violation"

    # ----------------------------------------------------------
    # Storage
    # ----------------------------------------------------------

    def _store_event(self, evt: RawEventDC, severity_normalized: str = "") -> None:
        """Append event to ring buffer, update source stats, persist."""
        self.events.append(evt)
        self.stats.total_received += 1
        if evt.parsed:
            self.stats.total_parsed += 1

        # Update source counters
        src = self.sources.get(evt.source_id)
        if src:
            src.events_received += 1
            if evt.parsed:
                src.events_processed += 1
            src.last_event_at = evt.timestamp
            self._persist_source(src)

        # Events/sec calculation (sliding 60s window)
        self._window_count += 1
        elapsed = time.time() - self._window_start
        if elapsed >= 60:
            self.stats.events_per_second = round(self._window_count / elapsed, 2)
            self._window_start = time.time()
            self._window_count = 0
        elif elapsed > 0:
            self.stats.events_per_second = round(self._window_count / elapsed, 2)

        self._persist_event(evt, severity_normalized)

    # ----------------------------------------------------------
    # Correlation engine
    # ----------------------------------------------------------

    def correlate_events(self) -> List[Dict[str, Any]]:
        """
        Run all enabled correlation rules against the recent event window.
        Returns list of triggered correlation results.
        """
        results: List[Dict[str, Any]] = []
        now = datetime.utcnow()

        for rule in self.correlation_rules.values():
            if not rule.is_enabled:
                continue

            window_start = now - timedelta(seconds=rule.time_window_seconds)
            matching_events = []

            for evt in self.events:
                if evt.timestamp < window_start:
                    continue
                if self._event_matches_conditions(evt, rule.conditions):
                    matching_events.append(evt)

            if len(matching_events) >= rule.min_events:
                self.stats.total_correlated += 1
                result = {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "matched_events": len(matching_events),
                    "action": rule.action,
                    "severity": rule.severity,
                    "threat_type": rule.threat_type,
                }

                if rule.action == "create_incident":
                    incident = self._create_cyber911_incident(matching_events, rule)
                    if incident:
                        result["incident_id"] = incident.get("incident_id", "")
                        self.stats.total_incidents_created += 1

                results.append(result)
                logger.warning(
                    f"Correlation rule triggered: {rule.name} "
                    f"({len(matching_events)} events in {rule.time_window_seconds}s)"
                )

        return results

    def _event_matches_conditions(self, evt: RawEventDC,
                                   conditions: List[Dict[str, Any]]) -> bool:
        """Check if an event matches all conditions in a list."""
        for cond in conditions:
            field_name = cond.get("field", "")
            op = cond.get("op", "eq")
            value = cond.get("value", "")

            evt_val = getattr(evt, field_name, None)
            if evt_val is None:
                evt_val = evt.raw_data.get(field_name, "")
            evt_val_str = str(evt_val).lower()

            if op == "eq":
                if evt_val_str != str(value).lower():
                    return False
            elif op == "in":
                if isinstance(value, list):
                    if evt_val_str not in [str(v).lower() for v in value]:
                        return False
                else:
                    if evt_val_str != str(value).lower():
                        return False
            elif op == "contains":
                if str(value).lower() not in evt_val_str:
                    return False
            elif op == "contains_any":
                if isinstance(value, list):
                    if not any(str(v).lower() in evt_val_str for v in value):
                        return False
                else:
                    if str(value).lower() not in evt_val_str:
                        return False
            elif op == "regex":
                if not re.search(str(value), str(evt_val), re.IGNORECASE):
                    return False

        return True

    def _create_cyber911_incident(self, correlated_events: List[RawEventDC],
                                   rule: CorrelationRuleDC) -> Optional[Dict[str, Any]]:
        """Create an incident in Cyber-911 from correlated events."""
        if not CYBER911_AVAILABLE:
            logger.warning("Cyber-911 not available; logging correlation only")
            return {"incident_id": f"SIEM-{uuid.uuid4().hex[:8]}", "status": "logged_only"}

        # Build SecurityEvent list for Cyber-911
        threat_type_str = rule.threat_type or self._classify_threat_type(correlated_events[0])
        try:
            threat_type = ThreatType(threat_type_str.lower())
        except ValueError:
            threat_type = ThreatType.POLICY_VIOLATION

        severity_str = rule.severity.upper()
        try:
            severity = SeverityLevel[severity_str]
        except KeyError:
            severity = SeverityLevel.MEDIUM

        # Build Cyber-911 SecurityEvent objects
        security_events = []
        affected_assets = set()
        indicators: Dict[str, Any] = {}

        for evt in correlated_events:
            se = SecurityEvent(
                event_id=evt.event_id,
                source="SIEM",
                timestamp=evt.timestamp,
                event_type=evt.event_type,
                source_ip=evt.source_ip or None,
                destination_ip=evt.dest_ip or None,
                user=evt.user or None,
                hostname=evt.hostname or None,
                description=evt.message,
                raw_data=evt.raw_data,
            )
            security_events.append(se)
            if evt.hostname:
                affected_assets.add(evt.hostname)
            if evt.dest_ip:
                affected_assets.add(evt.dest_ip)
            if evt.source_ip:
                indicators["source_ip"] = evt.source_ip
            if evt.user:
                indicators["user"] = evt.user

        # Create the Cyber-911 service (reuse DB session if available)
        try:
            cyber911 = Cyber911Service(db=self.db)

            from services.msp.cyber_911 import Threat, IncidentResponse, _event_to_dict
            threat = Threat(
                threat_id=f"THR-SIEM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{rule.rule_id}",
                threat_type=threat_type,
                severity=severity,
                events=security_events,
                affected_assets=list(affected_assets),
                indicators=indicators,
            )

            incident = IncidentResponse(
                incident_id=f"INC-SIEM-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}",
                threat=threat,
                actions_taken=[{
                    "action": "siem_correlation",
                    "rule": rule.name,
                    "matched_events": len(correlated_events),
                }],
                containment_status="monitoring",
                investigation_notes=(
                    f"Auto-created by SIEM correlation rule '{rule.name}'. "
                    f"{len(correlated_events)} events matched in {rule.time_window_seconds}s window."
                ),
            )

            cyber911.incidents.append(incident)
            cyber911._persist_incident(incident)

            logger.info(f"Created Cyber-911 incident {incident.incident_id} from SIEM correlation")
            return {
                "incident_id": incident.incident_id,
                "threat_type": threat_type.value,
                "severity": severity.value,
                "affected_assets": list(affected_assets),
            }
        except Exception as e:
            logger.error(f"Failed to create Cyber-911 incident: {e}")
            return {"incident_id": f"SIEM-ERR-{uuid.uuid4().hex[:8]}", "error": str(e)}

    # ----------------------------------------------------------
    # Query / dashboard
    # ----------------------------------------------------------

    def get_event_log(self, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Query ingested events with optional filters."""
        filters = filters or {}
        result = []

        source_id = filters.get("source_id")
        event_type = filters.get("event_type")
        severity = filters.get("severity")
        hostname = filters.get("hostname")
        source_ip = filters.get("source_ip")
        since = filters.get("since")  # datetime or ISO string
        limit = filters.get("limit", 100)

        if isinstance(since, str):
            try:
                since = datetime.fromisoformat(since)
            except Exception:
                since = None

        for evt in reversed(list(self.events)):
            if source_id and evt.source_id != source_id:
                continue
            if event_type and evt.event_type != event_type:
                continue
            if severity and evt.severity_raw.upper() != severity.upper():
                continue
            if hostname and evt.hostname != hostname:
                continue
            if source_ip and evt.source_ip != source_ip:
                continue
            if since and evt.timestamp < since:
                continue

            result.append({
                "event_id": evt.event_id,
                "source_id": evt.source_id,
                "timestamp": evt.timestamp.isoformat(),
                "event_type": evt.event_type,
                "severity_raw": evt.severity_raw,
                "source_ip": evt.source_ip,
                "dest_ip": evt.dest_ip,
                "hostname": evt.hostname,
                "user": evt.user,
                "message": evt.message[:500],
                "parsed": evt.parsed,
            })
            if len(result) >= limit:
                break

        return result

    def get_dashboard(self) -> Dict[str, Any]:
        """Ingest stats, events/sec, top sources, recent correlations."""
        # Top sources by event count
        top_sources = sorted(
            self.sources.values(),
            key=lambda s: s.events_received,
            reverse=True,
        )[:10]

        # Event type distribution from recent events
        type_counts: Dict[str, int] = {}
        for evt in self.events:
            t = evt.event_type or "unknown"
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "stats": {
                "total_received": self.stats.total_received,
                "total_parsed": self.stats.total_parsed,
                "total_correlated": self.stats.total_correlated,
                "total_incidents_created": self.stats.total_incidents_created,
                "events_per_second": self.stats.events_per_second,
                "error_count": self.stats.error_count,
            },
            "sources": [
                {
                    "source_id": s.source_id,
                    "name": s.name,
                    "source_type": s.source_type,
                    "events_received": s.events_received,
                    "is_enabled": s.is_enabled,
                    "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
                }
                for s in top_sources
            ],
            "event_type_distribution": type_counts,
            "correlation_rules_active": sum(
                1 for r in self.correlation_rules.values() if r.is_enabled
            ),
            "events_in_buffer": len(self.events),
        }
