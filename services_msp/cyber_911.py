"""
AITHER Platform - Cyber-911 Incident Response
Logic Card: LC-014

Automated security incident detection and response.

G-46: Refactored for DB persistence with in-memory fallback.
"""

import asyncio
import logging
from enum import Enum
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    from sqlalchemy.orm import Session
    from models.msp import (
        Cyber911Incident as Cyber911IncidentModel,
        Cyber911BlockedIP as Cyber911BlockedIPModel,
        Cyber911IsolatedHost as Cyber911IsolatedHostModel,
        Cyber911DisabledAccount as Cyber911DisabledAccountModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None


class ThreatType(Enum):
    """Classification of security threats"""
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DDOS = "ddos"
    INSIDER_THREAT = "insider_threat"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    POLICY_VIOLATION = "policy_violation"


class SeverityLevel(Enum):
    """Threat severity levels"""
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 3
    INFO = 1


class ResponseAction(Enum):
    """Automated response actions"""
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    REVOKE_CREDENTIALS = "revoke_credentials"
    QUARANTINE_FILE = "quarantine_file"
    DISABLE_ACCOUNT = "disable_account"
    CAPTURE_FORENSICS = "capture_forensics"
    ALERT_SECURITY_TEAM = "alert_security_team"
    INITIATE_BACKUP = "initiate_backup"


@dataclass
class SecurityEvent:
    """Raw security event from SIEM or monitoring"""
    event_id: str
    source: str  # SIEM, EDR, Firewall, etc.
    timestamp: datetime
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    description: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Threat:
    """Classified security threat"""
    threat_id: str
    threat_type: ThreatType
    severity: SeverityLevel
    events: List[SecurityEvent]
    affected_assets: List[str]
    indicators: Dict[str, Any]  # IOCs
    detected_at: datetime = field(default_factory=datetime.utcnow)
    status: str = "active"


@dataclass
class IncidentResponse:
    """Incident response record"""
    incident_id: str
    threat: Threat
    actions_taken: List[Dict[str, Any]]
    containment_status: str
    investigation_notes: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None


def _event_to_dict(event: SecurityEvent) -> Dict[str, Any]:
    """Serialize a SecurityEvent for JSON storage."""
    return {
        "event_id": event.event_id,
        "source": event.source,
        "timestamp": event.timestamp.isoformat() if event.timestamp else "",
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "user": event.user,
        "hostname": event.hostname,
        "description": event.description,
    }


class Cyber911Service:
    """
    Automated Security Incident Response

    TRIGGER: Security event from SIEM/EDR/Firewall
    INPUT: Security alerts, threat intelligence, system logs
    PROCESS:
        1. Classify threat type
        2. Calculate severity (1-10)
        3. If severity > 7: AUTO-EXECUTE containment
        4. Initiate forensics
        5. Generate incident report
        6. Notify stakeholders
    OUTPUT: Incident reports, automated response logs
    STORAGE: cyber911_incidents table

    Accepts optional db: Session for persistence.
    """

    # Severity threshold for automatic containment
    AUTO_CONTAINMENT_THRESHOLD = 7

    # Response playbooks by threat type
    PLAYBOOKS: Dict[ThreatType, List[ResponseAction]] = {
        ThreatType.MALWARE: [
            ResponseAction.ISOLATE_HOST,
            ResponseAction.QUARANTINE_FILE,
            ResponseAction.CAPTURE_FORENSICS,
            ResponseAction.ALERT_SECURITY_TEAM,
        ],
        ThreatType.RANSOMWARE: [
            ResponseAction.ISOLATE_HOST,
            ResponseAction.INITIATE_BACKUP,
            ResponseAction.REVOKE_CREDENTIALS,
            ResponseAction.ALERT_SECURITY_TEAM,
        ],
        ThreatType.INTRUSION: [
            ResponseAction.BLOCK_IP,
            ResponseAction.ISOLATE_HOST,
            ResponseAction.CAPTURE_FORENSICS,
            ResponseAction.ALERT_SECURITY_TEAM,
        ],
        ThreatType.CREDENTIAL_COMPROMISE: [
            ResponseAction.DISABLE_ACCOUNT,
            ResponseAction.REVOKE_CREDENTIALS,
            ResponseAction.ALERT_SECURITY_TEAM,
        ],
        ThreatType.DATA_EXFILTRATION: [
            ResponseAction.ISOLATE_HOST,
            ResponseAction.BLOCK_IP,
            ResponseAction.CAPTURE_FORENSICS,
            ResponseAction.ALERT_SECURITY_TEAM,
        ],
        ThreatType.PHISHING: [
            ResponseAction.QUARANTINE_FILE,
            ResponseAction.ALERT_SECURITY_TEAM,
        ],
        ThreatType.DDOS: [
            ResponseAction.BLOCK_IP,
            ResponseAction.ALERT_SECURITY_TEAM,
        ],
        ThreatType.INSIDER_THREAT: [
            ResponseAction.DISABLE_ACCOUNT,
            ResponseAction.CAPTURE_FORENSICS,
            ResponseAction.ALERT_SECURITY_TEAM,
        ],
    }

    def __init__(self, db: Session = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        self.incidents: List[IncidentResponse] = []
        self.blocked_ips: set = set()
        self.isolated_hosts: set = set()
        self.disabled_accounts: set = set()

        # Hydrate from DB
        if self._use_db:
            self._hydrate_from_db()

    def _hydrate_from_db(self) -> None:
        """Load persisted state from the database."""
        try:
            # Load blocked IPs
            ip_rows = self.db.query(Cyber911BlockedIPModel).all()
            for row in ip_rows:
                self.blocked_ips.add(row.ip_address)

            # Load isolated hosts
            host_rows = self.db.query(Cyber911IsolatedHostModel).all()
            for row in host_rows:
                self.isolated_hosts.add(row.hostname)

            # Load disabled accounts
            acct_rows = self.db.query(Cyber911DisabledAccountModel).all()
            for row in acct_rows:
                self.disabled_accounts.add(row.username)

            # Load incidents (reconstruct IncidentResponse objects)
            inc_rows = self.db.query(Cyber911IncidentModel).order_by(
                Cyber911IncidentModel.created_at.desc()
            ).limit(500).all()
            for row in inc_rows:
                threat = Threat(
                    threat_id=row.threat_id or "",
                    threat_type=ThreatType(row.threat_type),
                    severity=self._severity_from_int(row.severity or 1),
                    events=[],  # Events are not fully reconstructed from JSON
                    affected_assets=row.affected_assets or [],
                    indicators=row.indicators or {},
                    detected_at=row.detected_at or row.created_at or datetime.utcnow(),
                    status="resolved" if row.resolved_at else "active",
                )
                incident = IncidentResponse(
                    incident_id=row.incident_id,
                    threat=threat,
                    actions_taken=row.actions_taken or [],
                    containment_status=row.containment_status or "pending",
                    investigation_notes=row.investigation_notes or "",
                    created_at=row.created_at or datetime.utcnow(),
                    resolved_at=row.resolved_at,
                )
                self.incidents.append(incident)
        except Exception as e:
            logger.error(f"DB error hydrating cyber-911 state: {e}")

    @staticmethod
    def _severity_from_int(val: int) -> SeverityLevel:
        """Map an integer severity to the closest SeverityLevel enum."""
        for sl in sorted(SeverityLevel, key=lambda s: s.value, reverse=True):
            if val >= sl.value:
                return sl
        return SeverityLevel.INFO

    def _persist_incident(self, incident: IncidentResponse) -> None:
        """Persist an incident to the database."""
        if not self._use_db:
            return
        try:
            existing = self.db.query(Cyber911IncidentModel).filter(
                Cyber911IncidentModel.incident_id == incident.incident_id
            ).first()
            if existing:
                existing.actions_taken = incident.actions_taken
                existing.containment_status = incident.containment_status
                existing.investigation_notes = incident.investigation_notes
                existing.resolved_at = incident.resolved_at
            else:
                events_json = [_event_to_dict(e) for e in incident.threat.events]
                row = Cyber911IncidentModel(
                    incident_id=incident.incident_id,
                    threat_id=incident.threat.threat_id,
                    threat_type=incident.threat.threat_type.value,
                    severity=incident.threat.severity.value,
                    affected_assets=incident.threat.affected_assets,
                    indicators=incident.threat.indicators,
                    events=events_json,
                    actions_taken=incident.actions_taken,
                    containment_status=incident.containment_status,
                    investigation_notes=incident.investigation_notes,
                    detected_at=incident.threat.detected_at,
                    resolved_at=incident.resolved_at,
                )
                self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting incident: {e}")
            self.db.rollback()

    def _persist_blocked_ip(self, ip: str, add: bool = True) -> None:
        if not self._use_db:
            return
        try:
            if add:
                exists = self.db.query(Cyber911BlockedIPModel).filter(
                    Cyber911BlockedIPModel.ip_address == ip
                ).first()
                if not exists:
                    self.db.add(Cyber911BlockedIPModel(ip_address=ip))
                    self.db.commit()
            else:
                self.db.query(Cyber911BlockedIPModel).filter(
                    Cyber911BlockedIPModel.ip_address == ip
                ).delete()
                self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting blocked IP: {e}")
            self.db.rollback()

    def _persist_isolated_host(self, hostname: str, add: bool = True) -> None:
        if not self._use_db:
            return
        try:
            if add:
                exists = self.db.query(Cyber911IsolatedHostModel).filter(
                    Cyber911IsolatedHostModel.hostname == hostname
                ).first()
                if not exists:
                    self.db.add(Cyber911IsolatedHostModel(hostname=hostname))
                    self.db.commit()
            else:
                self.db.query(Cyber911IsolatedHostModel).filter(
                    Cyber911IsolatedHostModel.hostname == hostname
                ).delete()
                self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting isolated host: {e}")
            self.db.rollback()

    def _persist_disabled_account(self, username: str, add: bool = True) -> None:
        if not self._use_db:
            return
        try:
            if add:
                exists = self.db.query(Cyber911DisabledAccountModel).filter(
                    Cyber911DisabledAccountModel.username == username
                ).first()
                if not exists:
                    self.db.add(Cyber911DisabledAccountModel(username=username))
                    self.db.commit()
            else:
                self.db.query(Cyber911DisabledAccountModel).filter(
                    Cyber911DisabledAccountModel.username == username
                ).delete()
                self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting disabled account: {e}")
            self.db.rollback()

    async def process_event(self, event: SecurityEvent) -> Optional[IncidentResponse]:
        """
        Process a security event and trigger response if needed.
        """
        logger.info(f"Processing security event {event.event_id}")

        # Classify the threat
        threat = self._classify_threat(event)

        if not threat:
            logger.debug(f"Event {event.event_id} classified as benign")
            return None

        logger.warning(f"Threat detected: {threat.threat_type.value} (Severity: {threat.severity.value})")

        # Execute response
        response = await self._execute_response(threat)
        self.incidents.append(response)
        self._persist_incident(response)

        return response

    def _classify_threat(self, event: SecurityEvent) -> Optional[Threat]:
        """
        Classify event into threat type and severity.
        Uses rule-based classification (could be enhanced with ML).
        """
        # Classification rules
        threat_type = None
        severity = SeverityLevel.INFO
        indicators = {}

        event_lower = event.event_type.lower()
        desc_lower = event.description.lower()

        # Malware detection
        if any(kw in event_lower for kw in ['malware', 'virus', 'trojan', 'worm']):
            threat_type = ThreatType.MALWARE
            severity = SeverityLevel.HIGH

        # Ransomware
        elif any(kw in desc_lower for kw in ['ransomware', 'encrypt', 'bitcoin', 'ransom']):
            threat_type = ThreatType.RANSOMWARE
            severity = SeverityLevel.CRITICAL

        # Intrusion attempts
        elif any(kw in event_lower for kw in ['intrusion', 'brute_force', 'failed_login']):
            threat_type = ThreatType.INTRUSION
            severity = SeverityLevel.HIGH if 'success' in desc_lower else SeverityLevel.MEDIUM

        # Credential issues
        elif any(kw in event_lower for kw in ['credential', 'password', 'authentication']):
            threat_type = ThreatType.CREDENTIAL_COMPROMISE
            severity = SeverityLevel.HIGH

        # Data exfiltration
        elif any(kw in desc_lower for kw in ['exfil', 'data_transfer', 'large_upload']):
            threat_type = ThreatType.DATA_EXFILTRATION
            severity = SeverityLevel.CRITICAL

        # Phishing
        elif any(kw in event_lower for kw in ['phishing', 'spam', 'suspicious_email']):
            threat_type = ThreatType.PHISHING
            severity = SeverityLevel.MEDIUM

        # DDoS
        elif any(kw in event_lower for kw in ['ddos', 'dos', 'flood', 'syn_flood']):
            threat_type = ThreatType.DDOS
            severity = SeverityLevel.HIGH

        # Insider threat
        elif any(kw in event_lower for kw in ['insider', 'insider_threat']):
            threat_type = ThreatType.INSIDER_THREAT
            severity = SeverityLevel.HIGH

        # Policy violation
        elif any(kw in event_lower for kw in ['policy', 'violation', 'unauthorized']):
            threat_type = ThreatType.POLICY_VIOLATION
            severity = SeverityLevel.LOW

        if not threat_type:
            return None

        # Build IOCs
        if event.source_ip:
            indicators['source_ip'] = event.source_ip
        if event.user:
            indicators['user'] = event.user
        if event.hostname:
            indicators['hostname'] = event.hostname

        # Build affected assets list
        affected = []
        if event.hostname:
            affected.append(event.hostname)
        if event.destination_ip:
            affected.append(event.destination_ip)

        return Threat(
            threat_id=f"THR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{event.event_id[:8]}",
            threat_type=threat_type,
            severity=severity,
            events=[event],
            affected_assets=affected,
            indicators=indicators
        )

    async def _execute_response(self, threat: Threat) -> IncidentResponse:
        """
        Execute automated response based on threat type and severity.
        """
        actions_taken = []
        containment_status = "pending"

        # Get playbook for this threat type
        playbook = self.PLAYBOOKS.get(threat.threat_type, [ResponseAction.ALERT_SECURITY_TEAM])

        # Only auto-contain for high severity threats
        auto_contain = threat.severity.value >= self.AUTO_CONTAINMENT_THRESHOLD

        for action in playbook:
            if action == ResponseAction.ALERT_SECURITY_TEAM:
                # Always alert
                result = await self._alert_security_team(threat)
                actions_taken.append({"action": action.value, "result": result})

            elif auto_contain:
                # Execute containment action
                result = await self._execute_action(action, threat)
                actions_taken.append({"action": action.value, "result": result})

        if auto_contain:
            containment_status = "contained"
        else:
            containment_status = "monitoring"

        return IncidentResponse(
            incident_id=f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{threat.threat_id[-8:]}",
            threat=threat,
            actions_taken=actions_taken,
            containment_status=containment_status,
            investigation_notes=f"Auto-response executed. Severity: {threat.severity.value}/10"
        )

    async def _execute_action(self, action: ResponseAction, threat: Threat) -> Dict[str, Any]:
        """Execute a specific response action"""

        result = {"success": False, "details": ""}

        try:
            if action == ResponseAction.ISOLATE_HOST:
                for host in threat.affected_assets:
                    self.isolated_hosts.add(host)
                    self._persist_isolated_host(host, add=True)
                result = {"success": True, "details": f"Isolated hosts: {threat.affected_assets}"}

            elif action == ResponseAction.BLOCK_IP:
                ip = threat.indicators.get('source_ip')
                if ip:
                    self.blocked_ips.add(ip)
                    self._persist_blocked_ip(ip, add=True)
                    result = {"success": True, "details": f"Blocked IP: {ip}"}
                else:
                    result = {"success": False, "details": "No source IP to block"}

            elif action == ResponseAction.REVOKE_CREDENTIALS:
                user = threat.indicators.get('user')
                if user:
                    # In production, would call identity provider API
                    result = {"success": True, "details": f"Credentials revoked for: {user}"}
                else:
                    result = {"success": False, "details": "No user identified"}

            elif action == ResponseAction.DISABLE_ACCOUNT:
                user = threat.indicators.get('user')
                if user:
                    self.disabled_accounts.add(user)
                    self._persist_disabled_account(user, add=True)
                    result = {"success": True, "details": f"Account disabled: {user}"}
                else:
                    result = {"success": False, "details": "No user identified"}

            elif action == ResponseAction.QUARANTINE_FILE:
                result = {"success": True, "details": "File quarantined (simulated)"}

            elif action == ResponseAction.CAPTURE_FORENSICS:
                result = {"success": True, "details": "Forensics capture initiated"}

            elif action == ResponseAction.INITIATE_BACKUP:
                result = {"success": True, "details": "Emergency backup initiated"}

            logger.info(f"Action {action.value}: {result}")

        except Exception as e:
            result = {"success": False, "details": str(e)}
            logger.error(f"Action {action.value} failed: {e}")

        return result

    async def _alert_security_team(self, threat: Threat) -> Dict[str, Any]:
        """Send alert to security team"""
        # In production, would send email, Slack, PagerDuty, etc.
        alert_message = f"""
        SECURITY ALERT

        Threat ID: {threat.threat_id}
        Type: {threat.threat_type.value}
        Severity: {threat.severity.value}/10
        Affected Assets: {', '.join(threat.affected_assets)}

        Indicators:
        {threat.indicators}

        Detected: {threat.detected_at.isoformat()}
        """

        logger.warning(alert_message)
        return {"success": True, "details": "Security team alerted"}

    def get_defcon_level(self) -> int:
        """
        Calculate current DEFCON level based on active threats.

        DEFCON 5: Normal operations
        DEFCON 4: Elevated risk
        DEFCON 3: Significant threat
        DEFCON 2: Severe threat
        DEFCON 1: Maximum alert - total lockdown
        """
        active_incidents = [i for i in self.incidents if i.containment_status != "resolved"]

        if not active_incidents:
            return 5

        max_severity = max(i.threat.severity.value for i in active_incidents)
        active_count = len(active_incidents)

        # Calculate DEFCON
        if max_severity >= 10 or active_count >= 5:
            return 1
        elif max_severity >= 8 or active_count >= 3:
            return 2
        elif max_severity >= 6 or active_count >= 2:
            return 3
        elif max_severity >= 4:
            return 4
        else:
            return 5

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for security dashboard"""
        active = [i for i in self.incidents if i.containment_status != "resolved"]

        # Calculate MTTR from resolved incidents
        resolution_times = []
        for i in self.incidents:
            if i.resolved_at and i.created_at:
                delta = (i.resolved_at - i.created_at).total_seconds() / 60.0
                resolution_times.append(delta)
        mttr_minutes = (
            round(sum(resolution_times) / len(resolution_times), 1)
            if resolution_times
            else 0.0
        )

        return {
            "defcon_level": self.get_defcon_level(),
            "active_incidents": len(active),
            "total_incidents": len(self.incidents),
            "mttr_minutes": mttr_minutes,
            "blocked_ips": len(self.blocked_ips),
            "isolated_hosts": len(self.isolated_hosts),
            "disabled_accounts": len(self.disabled_accounts),
            "recent_incidents": [
                {
                    "id": i.incident_id,
                    "type": i.threat.threat_type.value,
                    "severity": i.threat.severity.value,
                    "status": i.containment_status,
                    "created_at": i.created_at.isoformat()
                }
                for i in active[:10]
            ]
        }
