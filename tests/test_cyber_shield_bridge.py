"""
Tests for Cyber-911 / Shield Integration Bridge

Covers:
- backend/services/integrations/cyber_shield_bridge.py
- Threat intelligence sharing (Shield -> Cyber-911, Cyber-911 -> Shield)
- Signature update creation and deployment
- Incident escalation (auto and manual)
- Coordinated IP/domain blocklist management
- Unified threat intelligence feed with filters
- Dashboard statistics
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from services.integrations.cyber_shield_bridge import (
    CyberShieldBridge,
    SharedThreatType,
    ThreatIntelligence,
    get_cyber_shield_bridge,
)


# ============================================================
# ENUM AND DATA CLASS TESTS
# ============================================================


class TestSharedThreatTypeEnum:
    """Test threat type enum values."""

    def test_core_threat_types(self):
        assert SharedThreatType.MALWARE.value == "malware"
        assert SharedThreatType.RANSOMWARE.value == "ransomware"
        assert SharedThreatType.PHISHING.value == "phishing"
        assert SharedThreatType.DDOS.value == "ddos"

    def test_shield_specific_types(self):
        assert SharedThreatType.PUP.value == "pup"
        assert SharedThreatType.ADWARE.value == "adware"

    def test_all_types_count(self):
        assert len(SharedThreatType) == 12


class TestThreatIntelligence:
    """Test ThreatIntelligence data class."""

    def test_initialization(self):
        now = datetime.utcnow()
        ti = ThreatIntelligence(
            indicator_id="ti-1",
            indicator_type="ip",
            value="10.0.0.1",
            threat_type=SharedThreatType.INTRUSION,
            severity=8,
            confidence=0.95,
            source="cyber911",
            first_seen=now,
            last_seen=now,
        )
        assert ti.indicator_id == "ti-1"
        assert ti.severity == 8
        assert ti.metadata == {}


# ============================================================
# BRIDGE INITIALIZATION TESTS
# ============================================================


class TestCyberShieldBridgeInit:
    """Test bridge initialization and singleton."""

    def test_init_empty_stores(self):
        bridge = CyberShieldBridge()
        assert bridge.threat_intel_feed == []
        assert bridge.shared_blocklist == {}
        assert bridge.escalated_incidents == []
        assert bridge.signature_updates == []

    def test_get_bridge_singleton(self):
        import services.integrations.cyber_shield_bridge as mod
        mod._bridge_instance = None
        b1 = get_cyber_shield_bridge()
        b2 = get_cyber_shield_bridge()
        assert b1 is b2
        mod._bridge_instance = None


# ============================================================
# THREAT INTELLIGENCE SHARING TESTS
# ============================================================


class TestThreatSharingFromShield:
    """Test sharing threat intelligence from Shield to Cyber-911."""

    def setup_method(self):
        self.bridge = CyberShieldBridge()

    def test_share_low_severity_threat(self):
        result = self.bridge.share_threat_from_shield(
            device_id="dev-100",
            threat_data={
                "indicator_type": "hash",
                "value": "abc123hash",
                "type": "malware",
                "severity": 3,
                "confidence": 0.7,
            },
        )
        assert result["status"] == "shared"
        assert result["auto_escalated"] is False
        assert result["cyber911_incident"] is None
        assert len(self.bridge.threat_intel_feed) == 1

    def test_share_high_severity_auto_escalates(self):
        result = self.bridge.share_threat_from_shield(
            device_id="dev-200",
            threat_data={
                "type": "ransomware",
                "severity": 9,
                "confidence": 0.95,
                "value": "evil.exe",
            },
        )
        assert result["auto_escalated"] is True
        assert result["cyber911_incident"] is not None
        assert len(self.bridge.escalated_incidents) == 1

    def test_share_threat_stores_metadata(self):
        self.bridge.share_threat_from_shield(
            device_id="dev-300",
            threat_data={
                "type": "trojan",
                "severity": 5,
                "value": "trojan.dll",
                "file_path": "C:\\Windows\\trojan.dll",
                "detection_method": "signature",
            },
        )
        intel = self.bridge.threat_intel_feed[0]
        assert intel.metadata["device_id"] == "dev-300"
        assert intel.metadata["file_path"] == "C:\\Windows\\trojan.dll"


class TestThreatSharingFromCyber911:
    """Test sharing threat intelligence from Cyber-911 to Shield."""

    def setup_method(self):
        self.bridge = CyberShieldBridge()

    def test_share_indicators(self):
        indicators = [
            {"type": "hash", "value": "deadbeef", "threat_type": "malware", "severity": 7},
            {"type": "domain", "value": "evil.com", "threat_type": "phishing", "severity": 6},
            {"type": "ip", "value": "192.168.1.100", "threat_type": "intrusion", "severity": 8},
        ]
        result = self.bridge.share_threat_from_cyber911("INC-001", indicators)
        assert result["status"] == "shared"
        assert result["indicators_shared"] == 3
        assert result["signature_update_queued"] is True
        assert len(self.bridge.threat_intel_feed) == 3

    def test_share_creates_signature_update(self):
        indicators = [
            {"type": "hash", "value": "abc123", "threat_name": "Trojan.Gen", "severity": 5},
        ]
        self.bridge.share_threat_from_cyber911("INC-002", indicators)
        assert len(self.bridge.signature_updates) == 1
        update = self.bridge.signature_updates[0]
        assert update["source"] == "cyber911"
        assert len(update["signatures"]) == 1
        assert update["signatures"][0]["type"] == "file_hash"


# ============================================================
# SIGNATURE UPDATE TESTS
# ============================================================


class TestSignatureUpdates:
    """Test signature update lifecycle."""

    def setup_method(self):
        self.bridge = CyberShieldBridge()
        self.bridge.share_threat_from_cyber911("INC-010", [
            {"type": "hash", "value": "sig1", "threat_name": "Test", "severity": 5},
        ])

    def test_get_pending_signature_updates(self):
        updates = self.bridge.get_pending_signature_updates()
        assert len(updates) == 1

    def test_mark_signature_deployed(self):
        update_id = self.bridge.signature_updates[0]["update_id"]
        result = self.bridge.mark_signature_deployed(update_id)
        assert result is True
        assert self.bridge.signature_updates[0]["status"] == "deployed"

    def test_mark_nonexistent_signature(self):
        result = self.bridge.mark_signature_deployed("nonexistent")
        assert result is False


# ============================================================
# INCIDENT ESCALATION TESTS
# ============================================================


class TestIncidentEscalation:
    """Test manual and auto incident escalation."""

    def setup_method(self):
        self.bridge = CyberShieldBridge()

    def test_manual_escalation(self):
        result = self.bridge.escalate_shield_incident(
            device_id="dev-500",
            threat_id="thr-100",
            reason="Persistent threat detected",
            additional_context={"user": "jdoe"},
        )
        assert result["status"] == "escalated"
        assert result["incident_id"].startswith("ESC-")

    def test_get_escalated_incidents_all(self):
        self.bridge.escalate_shield_incident("d1", "t1", "Reason 1")
        self.bridge.escalate_shield_incident("d2", "t2", "Reason 2")
        incidents = self.bridge.get_escalated_incidents()
        assert len(incidents) == 2

    def test_get_escalated_incidents_by_status(self):
        self.bridge.escalate_shield_incident("d1", "t1", "Reason")
        incidents = self.bridge.get_escalated_incidents(status="new")
        assert len(incidents) == 1
        incidents = self.bridge.get_escalated_incidents(status="resolved")
        assert len(incidents) == 0

    def test_get_escalated_incidents_limit(self):
        for i in range(5):
            self.bridge.escalate_shield_incident(f"d{i}", f"t{i}", f"Reason {i}")
        incidents = self.bridge.get_escalated_incidents(limit=3)
        assert len(incidents) == 3


# ============================================================
# COORDINATED BLOCKLIST TESTS
# ============================================================


class TestSharedBlocklist:
    """Test coordinated IP/domain blocklist operations."""

    def setup_method(self):
        self.bridge = CyberShieldBridge()

    def test_add_ip_to_blocklist(self):
        result = self.bridge.add_to_shared_blocklist(
            indicator_type="ip",
            value="10.0.0.1",
            source="cyber911",
            reason="C2 server",
            severity=9,
        )
        assert result["type"] == "ip"
        assert result["propagated_to"] == ["cyber911", "shield"]
        assert result["expires_at"] is None

    def test_add_domain_with_expiry(self):
        expires = datetime.utcnow() + timedelta(days=7)
        result = self.bridge.add_to_shared_blocklist(
            indicator_type="domain",
            value="malware.com",
            source="shield",
            reason="Phishing site",
            expires_at=expires,
        )
        assert result["expires_at"] is not None

    def test_check_blocklist_found(self):
        self.bridge.add_to_shared_blocklist("ip", "10.0.0.2", "cyber911", "Bad actor")
        result = self.bridge.check_blocklist("ip", "10.0.0.2")
        assert result is not None
        assert result["value"] == "10.0.0.2"

    def test_check_blocklist_not_found(self):
        result = self.bridge.check_blocklist("ip", "1.1.1.1")
        assert result is None

    def test_check_blocklist_expired_entry_removed(self):
        past = datetime.utcnow() - timedelta(hours=1)
        self.bridge.add_to_shared_blocklist(
            "domain", "old.com", "shield", "Expired", expires_at=past,
        )
        result = self.bridge.check_blocklist("domain", "old.com")
        assert result is None
        assert "domain:old.com" not in self.bridge.shared_blocklist

    def test_get_blocklist_all(self):
        self.bridge.add_to_shared_blocklist("ip", "10.0.0.1", "cyber911", "Test")
        self.bridge.add_to_shared_blocklist("domain", "bad.com", "shield", "Test")
        blocks = self.bridge.get_blocklist()
        assert len(blocks) == 2

    def test_get_blocklist_filtered_by_type(self):
        self.bridge.add_to_shared_blocklist("ip", "10.0.0.1", "cyber911", "Test")
        self.bridge.add_to_shared_blocklist("domain", "bad.com", "shield", "Test")
        assert len(self.bridge.get_blocklist("ip")) == 1
        assert len(self.bridge.get_blocklist("domain")) == 1

    def test_remove_from_blocklist(self):
        self.bridge.add_to_shared_blocklist("ip", "10.0.0.3", "cyber911", "Remove me")
        result = self.bridge.remove_from_blocklist("ip", "10.0.0.3")
        assert result is True
        assert self.bridge.check_blocklist("ip", "10.0.0.3") is None

    def test_remove_nonexistent_from_blocklist(self):
        result = self.bridge.remove_from_blocklist("ip", "1.2.3.4")
        assert result is False


# ============================================================
# THREAT INTEL FEED TESTS
# ============================================================


class TestThreatIntelFeed:
    """Test unified threat intelligence feed queries."""

    def setup_method(self):
        self.bridge = CyberShieldBridge()
        self.bridge.share_threat_from_shield("d1", {
            "type": "malware", "severity": 5, "value": "mal1", "confidence": 0.8,
        })
        self.bridge.share_threat_from_shield("d2", {
            "type": "phishing", "severity": 8, "value": "phish1", "confidence": 0.9,
        })
        self.bridge.share_threat_from_cyber911("INC-1", [
            {"type": "hash", "value": "h1", "threat_type": "ransomware", "severity": 9},
        ])

    def test_get_all_feed(self):
        feed = self.bridge.get_threat_intel_feed()
        assert len(feed) == 3

    def test_filter_by_source(self):
        feed = self.bridge.get_threat_intel_feed(source="shield")
        assert len(feed) == 2
        feed = self.bridge.get_threat_intel_feed(source="cyber911")
        assert len(feed) == 1

    def test_filter_by_min_severity(self):
        feed = self.bridge.get_threat_intel_feed(min_severity=8)
        assert len(feed) == 2

    def test_filter_by_threat_type(self):
        feed = self.bridge.get_threat_intel_feed(threat_type=SharedThreatType.MALWARE)
        assert len(feed) == 1

    def test_feed_limit(self):
        feed = self.bridge.get_threat_intel_feed(limit=1)
        assert len(feed) == 1


# ============================================================
# DASHBOARD STATS TESTS
# ============================================================


class TestDashboardStats:
    """Test integration statistics for dashboard."""

    def setup_method(self):
        self.bridge = CyberShieldBridge()

    def test_empty_stats(self):
        stats = self.bridge.get_integration_stats()
        assert stats["threat_intel_count"] == 0
        assert stats["blocklist_count"] == 0
        assert stats["escalated_incidents"] == 0

    def test_stats_after_operations(self):
        self.bridge.share_threat_from_shield("d1", {
            "type": "malware", "severity": 9, "value": "bad.exe",
        })
        self.bridge.add_to_shared_blocklist("ip", "10.0.0.1", "cyber911", "Test")
        self.bridge.add_to_shared_blocklist("domain", "evil.com", "shield", "Test")
        stats = self.bridge.get_integration_stats()
        assert stats["threat_intel_count"] == 1
        assert stats["shield_threats"] == 1
        assert stats["blocklist_count"] == 2
        assert stats["blocked_ips"] == 1
        assert stats["blocked_domains"] == 1
        # severity 9 -> auto-escalation
        assert stats["escalated_incidents"] == 1
        assert stats["pending_escalations"] == 1
