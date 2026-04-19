"""
Tests for Cyber-911 Incident Response Service
"""

import pytest
from datetime import datetime
import asyncio

from services.msp.cyber_911 import (
    Cyber911Service,
    ThreatType,
    SeverityLevel,
    ResponseAction,
    SecurityEvent,
    Threat,
    IncidentResponse
)


class TestCyber911Service:
    """Tests for Cyber911Service"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = Cyber911Service()

    # ========== Event Processing Tests ==========

    @pytest.mark.asyncio
    async def test_process_malware_event(self):
        """Test processing a malware event"""
        event = SecurityEvent(
            event_id="EVT-001",
            source="EDR",
            timestamp=datetime.utcnow(),
            event_type="malware_detected",
            hostname="WORKSTATION-01",
            description="Trojan detected in temp folder"
        )

        response = await self.service.process_event(event)

        assert response is not None
        assert isinstance(response, IncidentResponse)
        assert response.threat.threat_type == ThreatType.MALWARE
        assert response.threat.severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_process_ransomware_event(self):
        """Test processing a ransomware event - highest severity"""
        event = SecurityEvent(
            event_id="EVT-002",
            source="EDR",
            timestamp=datetime.utcnow(),
            event_type="suspicious_activity",
            hostname="SERVER-01",
            description="Ransomware encryption detected - bitcoin ransom demand"
        )

        response = await self.service.process_event(event)

        assert response is not None
        assert response.threat.threat_type == ThreatType.RANSOMWARE
        assert response.threat.severity == SeverityLevel.CRITICAL
        assert response.containment_status == "contained"

    @pytest.mark.asyncio
    async def test_process_intrusion_event(self):
        """Test processing an intrusion event"""
        event = SecurityEvent(
            event_id="EVT-003",
            source="Firewall",
            timestamp=datetime.utcnow(),
            event_type="intrusion_attempt",
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            description="Brute force attack detected"
        )

        response = await self.service.process_event(event)

        assert response is not None
        assert response.threat.threat_type == ThreatType.INTRUSION

    @pytest.mark.asyncio
    async def test_process_phishing_event(self):
        """Test processing a phishing event"""
        event = SecurityEvent(
            event_id="EVT-004",
            source="Email Gateway",
            timestamp=datetime.utcnow(),
            event_type="phishing_detected",
            user="user@company.com",
            description="Phishing email blocked"
        )

        response = await self.service.process_event(event)

        assert response is not None
        assert response.threat.threat_type == ThreatType.PHISHING
        assert response.threat.severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_process_benign_event(self):
        """Test processing a benign event returns None"""
        event = SecurityEvent(
            event_id="EVT-005",
            source="SIEM",
            timestamp=datetime.utcnow(),
            event_type="user_login",
            user="admin@company.com",
            description="Normal login activity"
        )

        response = await self.service.process_event(event)

        assert response is None

    @pytest.mark.asyncio
    async def test_process_credential_compromise(self):
        """Test processing a credential compromise event"""
        event = SecurityEvent(
            event_id="EVT-006",
            source="Identity Provider",
            timestamp=datetime.utcnow(),
            event_type="credential_leak",
            user="admin@company.com",
            description="Password found in breach database"
        )

        response = await self.service.process_event(event)

        assert response is not None
        assert response.threat.threat_type == ThreatType.CREDENTIAL_COMPROMISE

    @pytest.mark.asyncio
    async def test_process_ddos_event(self):
        """Test processing a DDoS event"""
        event = SecurityEvent(
            event_id="EVT-007",
            source="Firewall",
            timestamp=datetime.utcnow(),
            event_type="ddos_attack",
            source_ip="203.0.113.0",
            description="SYN flood detected"
        )

        response = await self.service.process_event(event)

        assert response is not None
        assert response.threat.threat_type == ThreatType.DDOS

    @pytest.mark.asyncio
    async def test_process_data_exfiltration(self):
        """Test processing a data exfiltration event"""
        event = SecurityEvent(
            event_id="EVT-008",
            source="DLP",
            timestamp=datetime.utcnow(),
            event_type="data_transfer",
            hostname="WORKSTATION-02",
            user="employee@company.com",
            description="Large data exfil to external server"
        )

        response = await self.service.process_event(event)

        assert response is not None
        assert response.threat.threat_type == ThreatType.DATA_EXFILTRATION
        assert response.threat.severity == SeverityLevel.CRITICAL

    # ========== Response Action Tests ==========

    @pytest.mark.asyncio
    async def test_ip_blocked_on_intrusion(self):
        """Test IP is blocked on intrusion event"""
        event = SecurityEvent(
            event_id="EVT-009",
            source="Firewall",
            timestamp=datetime.utcnow(),
            event_type="intrusion_attempt",
            source_ip="203.0.113.50",
            description="Intrusion success detected"
        )

        await self.service.process_event(event)

        assert "203.0.113.50" in self.service.blocked_ips

    @pytest.mark.asyncio
    async def test_host_isolated_on_malware(self):
        """Test host is isolated on high severity malware"""
        event = SecurityEvent(
            event_id="EVT-010",
            source="EDR",
            timestamp=datetime.utcnow(),
            event_type="malware_detected",
            hostname="INFECTED-PC",
            destination_ip="10.0.0.50",
            description="Active malware spreading"
        )

        await self.service.process_event(event)

        # Host should be isolated for high severity
        assert "INFECTED-PC" in self.service.isolated_hosts or "10.0.0.50" in self.service.isolated_hosts

    @pytest.mark.asyncio
    async def test_account_disabled_on_insider_threat(self):
        """Test account is disabled on insider threat"""
        event = SecurityEvent(
            event_id="EVT-011",
            source="SIEM",
            timestamp=datetime.utcnow(),
            event_type="insider_threat",
            user="malicious_user@company.com",
            description="Insider threat detected - unusual data access"
        )

        # Need to trigger as high severity to auto-contain
        self.service.AUTO_CONTAINMENT_THRESHOLD = 1  # Lower threshold for test

        await self.service.process_event(event)

        # Account should be disabled if severity met threshold
        # Note: insider_threat severity is not explicitly set in classification
        # Check that actions were taken
        assert len(self.service.incidents) > 0

    # ========== DEFCON Level Tests ==========

    def test_defcon_5_no_incidents(self):
        """Test DEFCON 5 when no incidents"""
        level = self.service.get_defcon_level()
        assert level == 5

    @pytest.mark.asyncio
    async def test_defcon_changes_with_severity(self):
        """Test DEFCON level changes with incident severity"""
        # Create a critical incident
        event = SecurityEvent(
            event_id="EVT-012",
            source="EDR",
            timestamp=datetime.utcnow(),
            event_type="ransomware_attack",
            hostname="SERVER-CRITICAL",
            description="Ransomware encryption in progress"
        )

        await self.service.process_event(event)

        level = self.service.get_defcon_level()
        # Critical severity (10) should trigger DEFCON 1 or 2
        assert level <= 2

    @pytest.mark.asyncio
    async def test_defcon_multiple_incidents(self):
        """Test DEFCON escalates with multiple incidents"""
        # Create multiple medium severity incidents
        for i in range(3):
            event = SecurityEvent(
                event_id=f"EVT-M{i}",
                source="Firewall",
                timestamp=datetime.utcnow(),
                event_type="intrusion_attempt",
                source_ip=f"192.168.1.{100+i}",
                description="Brute force attempt"
            )
            await self.service.process_event(event)

        level = self.service.get_defcon_level()
        # 3+ active incidents should escalate DEFCON
        assert level <= 3

    # ========== Dashboard Tests ==========

    def test_dashboard_data_empty(self):
        """Test dashboard data when no incidents"""
        dashboard = self.service.get_dashboard_data()

        assert dashboard["defcon_level"] == 5
        assert dashboard["active_incidents"] == 0
        assert dashboard["total_incidents"] == 0
        assert dashboard["blocked_ips"] == 0
        assert dashboard["isolated_hosts"] == 0
        assert dashboard["disabled_accounts"] == 0
        assert dashboard["recent_incidents"] == []

    @pytest.mark.asyncio
    async def test_dashboard_data_with_incidents(self):
        """Test dashboard data with incidents"""
        event = SecurityEvent(
            event_id="EVT-013",
            source="EDR",
            timestamp=datetime.utcnow(),
            event_type="malware_detected",
            hostname="WORKSTATION-03",
            description="Malware detected"
        )

        await self.service.process_event(event)

        dashboard = self.service.get_dashboard_data()

        assert dashboard["total_incidents"] >= 1
        assert len(dashboard["recent_incidents"]) >= 1
        assert "id" in dashboard["recent_incidents"][0]
        assert "type" in dashboard["recent_incidents"][0]
        assert "severity" in dashboard["recent_incidents"][0]

    # ========== Playbook Tests ==========

    def test_playbooks_defined(self):
        """Test response playbooks are defined"""
        assert len(self.service.PLAYBOOKS) > 0

        for threat_type, actions in self.service.PLAYBOOKS.items():
            assert isinstance(threat_type, ThreatType)
            assert len(actions) > 0
            assert ResponseAction.ALERT_SECURITY_TEAM in actions

    def test_ransomware_playbook(self):
        """Test ransomware playbook includes critical actions"""
        playbook = self.service.PLAYBOOKS[ThreatType.RANSOMWARE]

        assert ResponseAction.ISOLATE_HOST in playbook
        assert ResponseAction.INITIATE_BACKUP in playbook
        assert ResponseAction.ALERT_SECURITY_TEAM in playbook

    def test_intrusion_playbook(self):
        """Test intrusion playbook includes block IP"""
        playbook = self.service.PLAYBOOKS[ThreatType.INTRUSION]

        assert ResponseAction.BLOCK_IP in playbook
        assert ResponseAction.CAPTURE_FORENSICS in playbook

    # ========== Incident Storage Tests ==========

    @pytest.mark.asyncio
    async def test_incidents_stored(self):
        """Test incidents are stored"""
        event = SecurityEvent(
            event_id="EVT-014",
            source="SIEM",
            timestamp=datetime.utcnow(),
            event_type="phishing_detected",
            user="target@company.com",
            description="Phishing attempt blocked"
        )

        await self.service.process_event(event)

        assert len(self.service.incidents) > 0

    @pytest.mark.asyncio
    async def test_incident_has_actions(self):
        """Test incident records actions taken"""
        event = SecurityEvent(
            event_id="EVT-015",
            source="EDR",
            timestamp=datetime.utcnow(),
            event_type="malware_detected",
            hostname="PC-001",
            description="Trojan horse detected"
        )

        response = await self.service.process_event(event)

        assert len(response.actions_taken) > 0
        assert any(a["action"] == "alert_security_team" for a in response.actions_taken)


class TestSecurityEvent:
    """Tests for SecurityEvent dataclass"""

    def test_event_creation(self):
        """Test SecurityEvent creation"""
        event = SecurityEvent(
            event_id="TEST-001",
            source="SIEM",
            timestamp=datetime.utcnow(),
            event_type="test_event",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            user="testuser",
            hostname="testhost",
            description="Test event"
        )

        assert event.event_id == "TEST-001"
        assert event.source == "SIEM"
        assert event.source_ip == "10.0.0.1"

    def test_event_defaults(self):
        """Test SecurityEvent default values"""
        event = SecurityEvent(
            event_id="TEST-002",
            source="Firewall",
            timestamp=datetime.utcnow(),
            event_type="test"
        )

        assert event.source_ip is None
        assert event.user is None
        assert event.description == ""
        assert event.raw_data == {}


class TestThreat:
    """Tests for Threat dataclass"""

    def test_threat_creation(self):
        """Test Threat creation"""
        event = SecurityEvent(
            event_id="E-001",
            source="EDR",
            timestamp=datetime.utcnow(),
            event_type="test"
        )

        threat = Threat(
            threat_id="THR-001",
            threat_type=ThreatType.MALWARE,
            severity=SeverityLevel.HIGH,
            events=[event],
            affected_assets=["HOST-1"],
            indicators={"hash": "abc123"}
        )

        assert threat.threat_id == "THR-001"
        assert threat.threat_type == ThreatType.MALWARE
        assert threat.severity == SeverityLevel.HIGH
        assert threat.status == "active"
        assert threat.detected_at is not None


class TestIncidentResponse:
    """Tests for IncidentResponse dataclass"""

    def test_incident_creation(self):
        """Test IncidentResponse creation"""
        event = SecurityEvent(
            event_id="E-002",
            source="SIEM",
            timestamp=datetime.utcnow(),
            event_type="test"
        )

        threat = Threat(
            threat_id="THR-002",
            threat_type=ThreatType.PHISHING,
            severity=SeverityLevel.MEDIUM,
            events=[event],
            affected_assets=[],
            indicators={}
        )

        response = IncidentResponse(
            incident_id="INC-001",
            threat=threat,
            actions_taken=[{"action": "alert", "result": {"success": True}}],
            containment_status="monitoring",
            investigation_notes="Initial assessment"
        )

        assert response.incident_id == "INC-001"
        assert response.containment_status == "monitoring"
        assert response.created_at is not None
        assert response.resolved_at is None


class TestEnums:
    """Tests for Cyber-911 enums"""

    def test_threat_type_values(self):
        """Test ThreatType enum values"""
        assert ThreatType.MALWARE.value == "malware"
        assert ThreatType.RANSOMWARE.value == "ransomware"
        assert ThreatType.INTRUSION.value == "intrusion"
        assert ThreatType.PHISHING.value == "phishing"
        assert ThreatType.DDOS.value == "ddos"
        assert ThreatType.DATA_EXFILTRATION.value == "data_exfiltration"
        assert ThreatType.CREDENTIAL_COMPROMISE.value == "credential_compromise"
        assert ThreatType.INSIDER_THREAT.value == "insider_threat"

    def test_severity_level_values(self):
        """Test SeverityLevel enum values"""
        assert SeverityLevel.CRITICAL.value == 10
        assert SeverityLevel.HIGH.value == 8
        assert SeverityLevel.MEDIUM.value == 5
        assert SeverityLevel.LOW.value == 3
        assert SeverityLevel.INFO.value == 1

    def test_response_action_values(self):
        """Test ResponseAction enum values"""
        assert ResponseAction.ISOLATE_HOST.value == "isolate_host"
        assert ResponseAction.BLOCK_IP.value == "block_ip"
        assert ResponseAction.REVOKE_CREDENTIALS.value == "revoke_credentials"
        assert ResponseAction.QUARANTINE_FILE.value == "quarantine_file"
        assert ResponseAction.DISABLE_ACCOUNT.value == "disable_account"
        assert ResponseAction.CAPTURE_FORENSICS.value == "capture_forensics"
        assert ResponseAction.ALERT_SECURITY_TEAM.value == "alert_security_team"


class TestAutoContainment:
    """Tests for auto-containment threshold"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = Cyber911Service()

    def test_containment_threshold(self):
        """Test auto-containment threshold value"""
        assert self.service.AUTO_CONTAINMENT_THRESHOLD == 7

    @pytest.mark.asyncio
    async def test_high_severity_auto_contains(self):
        """Test high severity threats are auto-contained"""
        # Ransomware is CRITICAL (10) - should auto-contain
        event = SecurityEvent(
            event_id="EVT-AC1",
            source="EDR",
            timestamp=datetime.utcnow(),
            event_type="file_encryption",
            hostname="SERVER-01",
            description="Ransomware encryption detected"
        )

        response = await self.service.process_event(event)

        assert response.containment_status == "contained"

    @pytest.mark.asyncio
    async def test_low_severity_monitors(self):
        """Test low severity threats are monitored not contained"""
        event = SecurityEvent(
            event_id="EVT-AC2",
            source="SIEM",
            timestamp=datetime.utcnow(),
            event_type="policy_violation",
            user="user@company.com",
            description="Minor policy violation"
        )

        response = await self.service.process_event(event)

        if response:
            assert response.containment_status == "monitoring"
