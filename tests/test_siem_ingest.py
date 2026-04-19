"""
Tests for SIEM Ingest Pipeline Service
"""

import pytest
from datetime import datetime, timedelta

from services.msp.siem_ingest import (
    SIEMIngestService,
    SIEMSourceDC,
    RawEventDC,
    ParseRuleDC,
    CorrelationRuleDC,
    IngestStats,
    SYSLOG_SEVERITY_MAP,
    WINDOWS_EVENT_THREAT_MAP,
)


class TestSIEMIngestService:
    """Tests for SIEMIngestService"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = SIEMIngestService()

    # ========== Source CRUD Tests ==========

    def test_register_source(self):
        src = self.service.register_source("Test Firewall", "syslog", {"port": 514})
        assert src.source_id.startswith("SRC-")
        assert src.name == "Test Firewall"
        assert src.source_type == "syslog"
        assert src.config["port"] == 514
        assert src.is_enabled is True

    def test_list_sources(self):
        self.service.register_source("FW1", "syslog")
        self.service.register_source("ES1", "elastic")
        sources = self.service.list_sources()
        assert len(sources) == 2

    def test_get_source(self):
        src = self.service.register_source("FW1", "syslog")
        fetched = self.service.get_source(src.source_id)
        assert fetched is not None
        assert fetched.name == "FW1"

    def test_update_source(self):
        src = self.service.register_source("FW1", "syslog")
        updated = self.service.update_source(src.source_id, name="FW1-Updated", is_enabled=False)
        assert updated.name == "FW1-Updated"
        assert updated.is_enabled is False

    def test_delete_source(self):
        src = self.service.register_source("FW1", "syslog")
        assert self.service.delete_source(src.source_id) is True
        assert self.service.get_source(src.source_id) is None

    def test_delete_nonexistent_source(self):
        assert self.service.delete_source("SRC-NONEXIST") is False

    # ========== Syslog Ingest Tests ==========

    def test_ingest_syslog_rfc5424(self):
        """Test RFC 5424 syslog parsing."""
        msg = "<34>1 2026-04-19T12:00:00Z firewall.local sshd 1234 - - Failed password for root from 192.168.1.100"
        evt = self.service.ingest_syslog(msg, source_ip="10.0.0.1")
        assert evt.event_id.startswith("EVT-")
        assert evt.parsed is True
        assert evt.hostname == "firewall.local"
        assert evt.source_ip == "10.0.0.1"
        assert "Failed password" in evt.message

    def test_ingest_syslog_rfc3164(self):
        """Test RFC 3164 syslog parsing."""
        msg = "<13>Apr 19 12:00:00 myhost sshd[1234]: Connection closed by 10.0.0.5"
        evt = self.service.ingest_syslog(msg)
        assert evt.parsed is True
        assert evt.hostname == "myhost"
        assert "Connection closed" in evt.message

    def test_ingest_syslog_severity_mapping(self):
        """Test that syslog PRI severity is correctly mapped."""
        # PRI 8 = facility 1, severity 0 (Emergency) -> CRITICAL
        msg = "<8>1 2026-04-19T12:00:00Z host app - - - Emergency message"
        evt = self.service.ingest_syslog(msg)
        assert evt.severity_raw == "0"

        # PRI 12 = facility 1, severity 4 (Warning) -> MEDIUM
        msg2 = "<12>1 2026-04-19T12:00:00Z host app - - - Warning message"
        evt2 = self.service.ingest_syslog(msg2)
        assert evt2.severity_raw == "4"

    def test_syslog_increments_stats(self):
        msg = "<14>1 2026-04-19T12:00:00Z host app - - - Info message"
        self.service.ingest_syslog(msg)
        assert self.service.stats.total_received >= 1
        assert self.service.stats.total_parsed >= 1

    # ========== Windows Event Ingest Tests ==========

    def test_ingest_windows_event_4625(self):
        """Test Windows failed login event parsing."""
        xml = """<Event>
          <System>
            <EventID>4625</EventID>
            <TimeCreated SystemTime="2026-04-19T12:00:00Z"/>
            <Computer>DC01.corp.local</Computer>
          </System>
          <EventData>
            <Data Name="TargetUserName">admin</Data>
            <Data Name="IpAddress">192.168.1.50</Data>
          </EventData>
        </Event>"""
        evt = self.service.ingest_windows_event(xml)
        assert evt.parsed is True
        assert evt.event_type == "failed_login"
        assert evt.hostname == "DC01.corp.local"
        assert evt.user == "admin"
        assert evt.source_ip == "192.168.1.50"

    def test_ingest_windows_event_1102(self):
        """Test audit log cleared event."""
        xml = """<Event>
          <System>
            <EventID>1102</EventID>
            <TimeCreated SystemTime="2026-04-19T13:00:00Z"/>
            <Computer>SERVER01</Computer>
          </System>
          <EventData>
            <Data Name="SubjectUserName">badactor</Data>
          </EventData>
        </Event>"""
        evt = self.service.ingest_windows_event(xml)
        assert evt.event_type == "audit_log_cleared"
        assert evt.user == "badactor"

    def test_ingest_windows_event_4688_suspicious(self):
        """Test process creation with suspicious command."""
        xml = """<Event>
          <System>
            <EventID>4688</EventID>
            <TimeCreated SystemTime="2026-04-19T14:00:00Z"/>
            <Computer>WS01</Computer>
          </System>
          <EventData>
            <Data Name="SubjectUserName">user1</Data>
            <Data Name="CommandLine">powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYg==</Data>
          </EventData>
        </Event>"""
        evt = self.service.ingest_windows_event(xml)
        assert evt.event_type == "process_created"
        assert "powershell.exe -enc" in evt.message

    def test_ingest_windows_invalid_xml(self):
        """Test graceful handling of invalid XML."""
        evt = self.service.ingest_windows_event("<not valid xml")
        assert evt.event_id.startswith("EVT-")
        assert evt.parsed is True  # Still marks parsed, just with raw data

    # ========== Elastic / Wazuh Ingest Tests ==========

    def test_ingest_elastic_alert(self):
        """Test Elasticsearch alert ingestion."""
        alert = {
            "@timestamp": "2026-04-19T12:00:00Z",
            "rule": {
                "level": 10,
                "description": "SSH brute force attempt",
            },
            "agent": {"name": "webserver01"},
            "source": {"ip": "10.0.0.99"},
            "destination": {"ip": "10.0.0.1"},
        }
        evt = self.service.ingest_elastic_alert(alert)
        assert evt.parsed is True
        assert evt.hostname == "webserver01"
        assert evt.source_ip == "10.0.0.99"
        assert evt.dest_ip == "10.0.0.1"
        assert "brute force" in evt.message.lower()

    def test_ingest_wazuh_alert(self):
        """Test Wazuh-style alert with data block."""
        alert = {
            "@timestamp": "2026-04-19T15:00:00Z",
            "rule": {"level": 12, "description": "Rootkit detected"},
            "agent": {"name": "db-server"},
            "data": {"srcip": "172.16.0.5", "dstip": "172.16.0.1", "srcuser": "root"},
        }
        evt = self.service.ingest_elastic_alert(alert)
        assert evt.source_ip == "172.16.0.5"
        assert evt.dest_ip == "172.16.0.1"
        assert evt.user == "root"

    # ========== Generic / Batch Ingest Tests ==========

    def test_ingest_generic(self):
        evt = self.service.ingest_generic({
            "event_type": "firewall_block",
            "severity": "high",
            "source_ip": "1.2.3.4",
            "hostname": "fw01",
            "message": "Blocked suspicious traffic",
        })
        assert evt.event_type == "firewall_block"
        assert evt.source_ip == "1.2.3.4"

    def test_ingest_batch(self):
        events = [
            {"event_type": "login", "severity": "info", "user": "alice"},
            {"event_type": "login", "severity": "info", "user": "bob"},
            {"event_type": "failed_login", "severity": "medium", "user": "charlie"},
        ]
        result = self.service.ingest_batch(events)
        assert result["total"] == 3
        assert result["ingested"] == 3
        assert result["errors"] == 0

    # ========== Severity Normalization Tests ==========

    def test_normalize_syslog_severity(self):
        assert self.service._normalize_severity("0", "syslog") == "CRITICAL"
        assert self.service._normalize_severity("1", "syslog") == "CRITICAL"
        assert self.service._normalize_severity("2", "syslog") == "HIGH"
        assert self.service._normalize_severity("3", "syslog") == "HIGH"
        assert self.service._normalize_severity("4", "syslog") == "MEDIUM"
        assert self.service._normalize_severity("5", "syslog") == "LOW"
        assert self.service._normalize_severity("6", "syslog") == "INFO"
        assert self.service._normalize_severity("7", "syslog") == "INFO"

    def test_normalize_elastic_severity(self):
        assert self.service._normalize_severity("12", "elastic") == "CRITICAL"
        assert self.service._normalize_severity("8", "elastic") == "HIGH"
        assert self.service._normalize_severity("5", "elastic") == "MEDIUM"
        assert self.service._normalize_severity("3", "elastic") == "LOW"
        assert self.service._normalize_severity("1", "elastic") == "INFO"

    def test_normalize_generic_string_severity(self):
        assert self.service._normalize_severity("critical", "generic") == "HIGH"
        assert self.service._normalize_severity("warning", "generic") == "MEDIUM"
        assert self.service._normalize_severity("info", "generic") == "INFO"

    # ========== Threat Classification Tests ==========

    def test_classify_failed_login(self):
        evt = RawEventDC(
            event_id="E1", source_id="win", timestamp=datetime.utcnow(),
            event_type="failed_login", message="",
        )
        assert self.service._classify_threat_type(evt) == "credential_compromise"

    def test_classify_audit_cleared(self):
        evt = RawEventDC(
            event_id="E2", source_id="win", timestamp=datetime.utcnow(),
            event_type="audit_log_cleared", message="",
        )
        assert self.service._classify_threat_type(evt) == "insider_threat"

    def test_classify_suspicious_process(self):
        evt = RawEventDC(
            event_id="E3", source_id="win", timestamp=datetime.utcnow(),
            event_type="process_created",
            message="powershell.exe -enc base64data",
        )
        assert self.service._classify_threat_type(evt) == "malware"

    # ========== Correlation Tests ==========

    def test_correlation_brute_force(self):
        """5 failed logins in 300s should trigger correlation."""
        now = datetime.utcnow()
        for i in range(6):
            evt = RawEventDC(
                event_id=f"E-{i}", source_id="win",
                timestamp=now - timedelta(seconds=60 - i),
                event_type="failed_login",
                severity_raw="MEDIUM",
                source_ip="10.0.0.50",
                hostname="DC01",
                user="admin",
                message=f"Failed login attempt {i}",
            )
            self.service.events.append(evt)

        results = self.service.correlate_events()
        brute = [r for r in results if r["rule_id"] == "COR-WIN-BRUTE-001"]
        assert len(brute) >= 1
        assert brute[0]["matched_events"] >= 5

    def test_correlation_audit_cleared(self):
        """Single audit log cleared event should trigger correlation."""
        now = datetime.utcnow()
        evt = RawEventDC(
            event_id="E-AUDIT", source_id="win",
            timestamp=now,
            event_type="audit_log_cleared",
            severity_raw="HIGH",
            hostname="SERVER01",
            user="badactor",
            message="Security log was cleared",
        )
        self.service.events.append(evt)

        results = self.service.correlate_events()
        tamper = [r for r in results if r["rule_id"] == "COR-WIN-TAMPER-001"]
        assert len(tamper) >= 1

    def test_correlation_privilege_escalation(self):
        """Account created + admin group add in 60s should trigger."""
        now = datetime.utcnow()
        self.service.events.append(RawEventDC(
            event_id="E-PRIV1", source_id="win",
            timestamp=now - timedelta(seconds=30),
            event_type="account_created",
            severity_raw="MEDIUM",
            hostname="DC01", user="newuser", message="Account created",
        ))
        self.service.events.append(RawEventDC(
            event_id="E-PRIV2", source_id="win",
            timestamp=now,
            event_type="admin_group_add",
            severity_raw="HIGH",
            hostname="DC01", user="newuser", message="Added to Administrators",
        ))

        results = self.service.correlate_events()
        privesc = [r for r in results if r["rule_id"] == "COR-WIN-PRIVESC-001"]
        assert len(privesc) >= 1

    def test_no_false_correlation(self):
        """Single failed login should NOT trigger brute force rule."""
        now = datetime.utcnow()
        self.service.events.append(RawEventDC(
            event_id="E-SINGLE", source_id="win",
            timestamp=now,
            event_type="failed_login",
            severity_raw="MEDIUM",
            hostname="DC01", user="admin", message="Single failed login",
        ))
        results = self.service.correlate_events()
        brute = [r for r in results if r["rule_id"] == "COR-WIN-BRUTE-001"]
        assert len(brute) == 0

    # ========== Correlation Rule CRUD Tests ==========

    def test_create_correlation_rule(self):
        rule = self.service.create_correlation_rule(
            name="Custom Rule",
            conditions=[{"field": "event_type", "op": "eq", "value": "custom"}],
            time_window_seconds=120,
            min_events=3,
            severity="MEDIUM",
        )
        assert rule.rule_id.startswith("COR-")
        assert rule.name == "Custom Rule"
        assert rule.min_events == 3

    def test_update_correlation_rule(self):
        rule = self.service.create_correlation_rule(
            name="Temp Rule",
            conditions=[{"field": "event_type", "op": "eq", "value": "x"}],
        )
        updated = self.service.update_correlation_rule(rule.rule_id, is_enabled=False)
        assert updated.is_enabled is False

    def test_list_correlation_rules_includes_defaults(self):
        rules = self.service.list_correlation_rules()
        rule_ids = [r.rule_id for r in rules]
        assert "COR-WIN-BRUTE-001" in rule_ids
        assert "COR-WIN-TAMPER-001" in rule_ids
        assert "COR-WIN-PRIVESC-001" in rule_ids
        assert "COR-WIN-MALWARE-001" in rule_ids

    # ========== Parse Rule Tests ==========

    def test_create_parse_rule(self):
        rule = self.service.create_parse_rule(
            source_type="syslog",
            field_mappings={"hostname": "host"},
            severity_mapping={"warn": "MEDIUM"},
        )
        assert rule.rule_id.startswith("PR-")
        assert rule.source_type == "syslog"

    def test_list_parse_rules_filter(self):
        self.service.create_parse_rule(source_type="syslog")
        self.service.create_parse_rule(source_type="elastic")
        syslog_rules = self.service.list_parse_rules("syslog")
        assert len(syslog_rules) == 1

    # ========== Event Log & Dashboard Tests ==========

    def test_get_event_log(self):
        self.service.ingest_generic({"event_type": "test", "severity": "info"})
        self.service.ingest_generic({"event_type": "test2", "severity": "high"})
        log = self.service.get_event_log({"event_type": "test"})
        assert len(log) == 1

    def test_get_event_log_limit(self):
        for i in range(10):
            self.service.ingest_generic({"event_type": "bulk", "severity": "info"})
        log = self.service.get_event_log({"limit": 3})
        assert len(log) == 3

    def test_get_dashboard(self):
        self.service.register_source("FW", "syslog")
        self.service.ingest_generic({"event_type": "test", "severity": "info"})
        dashboard = self.service.get_dashboard()
        assert "stats" in dashboard
        assert dashboard["stats"]["total_received"] >= 1
        assert "sources" in dashboard
        assert "event_type_distribution" in dashboard
        assert "correlation_rules_active" in dashboard

    # ========== Cyber-911 Incident Creation Tests ==========

    def test_incident_creation_from_correlation(self):
        """Correlation should create a Cyber-911 incident."""
        now = datetime.utcnow()
        # Inject enough events to trigger brute force rule
        for i in range(6):
            self.service.events.append(RawEventDC(
                event_id=f"INC-E-{i}", source_id="win",
                timestamp=now - timedelta(seconds=10 - i),
                event_type="failed_login",
                severity_raw="MEDIUM",
                source_ip="10.0.0.50",
                hostname="DC01",
                user="admin",
                message=f"Failed password for admin",
            ))

        results = self.service.correlate_events()
        brute = [r for r in results if r["rule_id"] == "COR-WIN-BRUTE-001"]
        assert len(brute) >= 1
        # Should have created an incident
        assert "incident_id" in brute[0]
        assert self.service.stats.total_incidents_created >= 1

    # ========== Condition Matching Tests ==========

    def test_condition_contains(self):
        evt = RawEventDC(
            event_id="CM1", source_id="x", timestamp=datetime.utcnow(),
            event_type="process", message="Found mimikatz.exe running",
        )
        assert self.service._event_matches_conditions(
            evt, [{"field": "message", "op": "contains", "value": "mimikatz"}]
        )

    def test_condition_contains_any(self):
        evt = RawEventDC(
            event_id="CM2", source_id="x", timestamp=datetime.utcnow(),
            event_type="process", message="certutil -decode payload.b64",
        )
        assert self.service._event_matches_conditions(
            evt, [{"field": "message", "op": "contains_any", "value": ["mimikatz", "certutil"]}]
        )

    def test_condition_in(self):
        evt = RawEventDC(
            event_id="CM3", source_id="x", timestamp=datetime.utcnow(),
            event_type="account_created", message="",
        )
        assert self.service._event_matches_conditions(
            evt, [{"field": "event_type", "op": "in", "value": ["account_created", "admin_group_add"]}]
        )

    def test_condition_no_match(self):
        evt = RawEventDC(
            event_id="CM4", source_id="x", timestamp=datetime.utcnow(),
            event_type="login_success", message="",
        )
        assert not self.service._event_matches_conditions(
            evt, [{"field": "event_type", "op": "eq", "value": "failed_login"}]
        )
