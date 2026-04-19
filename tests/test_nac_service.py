"""
Tests for Network Access Control (NAC) Service
Full coverage: policy CRUD, posture assessment, quarantine, blocking,
guest registration, captive portal, compliance, and dashboard.
"""

import pytest
from datetime import datetime, timezone

from services.msp.nac_service import (
    NACService,
    NetworkZone,
    PostureResult,
    AccessDecisionType,
    AntivirusStatus,
    GuestStatus,
    _policy_to_dict,
    _posture_to_dict,
    _decision_to_dict,
    _guest_to_dict,
    _portal_to_dict,
    _blocked_to_dict,
)


@pytest.fixture
def svc():
    """Fresh NACService instance (in-memory mode)."""
    return NACService()


@pytest.fixture
def compliant_device():
    """Device data that meets Corporate Standard policy."""
    return {
        "device_id": "DEV-CORP-001",
        "mac_address": "AA:BB:CC:DD:EE:01",
        "ip_address": "10.0.1.100",
        "hostname": "workstation-01",
        "os_type": "Windows",
        "os_version": "11",
        "antivirus_status": AntivirusStatus.INSTALLED.value,
        "firewall_enabled": True,
        "disk_encrypted": True,
        "patch_compliance_pct": 95.0,
    }


@pytest.fixture
def non_compliant_device():
    """Device data that fails posture checks."""
    return {
        "device_id": "DEV-BAD-001",
        "mac_address": "AA:BB:CC:DD:EE:02",
        "ip_address": "10.0.1.200",
        "hostname": "rogue-laptop",
        "os_type": "Windows",
        "os_version": "7",
        "antivirus_status": AntivirusStatus.MISSING.value,
        "firewall_enabled": False,
        "disk_encrypted": False,
        "patch_compliance_pct": 20.0,
    }


# ============================================================
# Default Policies
# ============================================================

class TestDefaultPolicies:
    def test_default_policies_created(self, svc):
        policies = svc.list_policies()
        names = [p.name for p in policies]
        assert "Corporate Standard" in names
        assert "BYOD Minimum" in names
        assert "IoT Restricted" in names
        assert "Guest WiFi" in names

    def test_corporate_standard_requirements(self, svc):
        policies = svc.list_policies()
        corp = next(p for p in policies if p.name == "Corporate Standard")
        reqs = corp.posture_requirements
        assert reqs["antivirus_required"] is True
        assert reqs["firewall_required"] is True
        assert reqs["encryption_required"] is True
        assert reqs["patch_compliance_min_pct"] == 80.0

    def test_policies_sorted_by_priority(self, svc):
        policies = svc.list_policies()
        priorities = [p.priority for p in policies]
        assert priorities == sorted(priorities)


# ============================================================
# Policy CRUD
# ============================================================

class TestPolicyCRUD:
    def test_create_policy(self, svc):
        policy = svc.create_policy(
            name="Test Policy", client_id="C1",
            posture_requirements={"antivirus_required": True},
            network_assignment=NetworkZone.BYOD.value,
            vlan_id=60,
        )
        assert policy.policy_id.startswith("NAC-POL-")
        assert policy.name == "Test Policy"
        assert policy.client_id == "C1"
        assert policy.vlan_id == 60
        assert policy.is_enabled is True

    def test_get_policy(self, svc):
        p = svc.create_policy(name="Fetch Me")
        found = svc.get_policy(p.policy_id)
        assert found is not None
        assert found.name == "Fetch Me"

    def test_get_policy_not_found(self, svc):
        assert svc.get_policy("NAC-POL-NONEXIST") is None

    def test_update_policy(self, svc):
        p = svc.create_policy(name="Old Name")
        updated = svc.update_policy(p.policy_id, name="New Name", vlan_id=77)
        assert updated.name == "New Name"
        assert updated.vlan_id == 77

    def test_update_policy_not_found(self, svc):
        assert svc.update_policy("NAC-POL-NONEXIST", name="X") is None

    def test_delete_policy(self, svc):
        p = svc.create_policy(name="Delete Me")
        assert svc.delete_policy(p.policy_id) is True
        assert svc.get_policy(p.policy_id) is None

    def test_delete_policy_not_found(self, svc):
        assert svc.delete_policy("NAC-POL-NONEXIST") is False

    def test_list_policies_by_client(self, svc):
        svc.create_policy(name="Client A Policy", client_id="A")
        svc.create_policy(name="Client B Policy", client_id="B")
        a_policies = svc.list_policies(client_id="A")
        assert all(p.client_id == "A" for p in a_policies)

    def test_list_policies_enabled_only(self, svc):
        p = svc.create_policy(name="Disabled", is_enabled=False)
        enabled = svc.list_policies(enabled_only=True)
        assert p.policy_id not in [e.policy_id for e in enabled]

    def test_policy_to_dict(self, svc):
        p = svc.create_policy(name="Dict Test")
        d = _policy_to_dict(p)
        assert d["name"] == "Dict Test"
        assert "policy_id" in d
        assert "created_at" in d


# ============================================================
# Device Posture Assessment
# ============================================================

class TestPostureAssessment:
    def test_assess_compliant_device(self, svc, compliant_device):
        result = svc.assess_device_posture(compliant_device)
        assert result["blocked"] is False
        assert result["posture"] is not None
        assert result["decision"]["decision"] == AccessDecisionType.ALLOW.value
        assert result["posture"]["compliant"] is True
        assert result["posture"]["posture_score"] == 100

    def test_assess_non_compliant_device(self, svc, non_compliant_device):
        result = svc.assess_device_posture(non_compliant_device)
        assert result["blocked"] is False
        posture = result["posture"]
        assert posture["compliant"] is False
        assert posture["posture_score"] < 100
        assert len(posture["violations"]) > 0

    def test_assess_blocked_device(self, svc, compliant_device):
        svc.block_device(compliant_device["mac_address"], reason="stolen")
        result = svc.assess_device_posture(compliant_device)
        assert result["blocked"] is True
        assert result["decision"]["decision"] == AccessDecisionType.DENY.value

    def test_assess_outdated_antivirus(self, svc):
        device = {
            "device_id": "DEV-OUTDATED",
            "mac_address": "AA:BB:CC:DD:EE:03",
            "os_type": "Windows",
            "os_version": "11",
            "antivirus_status": AntivirusStatus.OUTDATED.value,
            "firewall_enabled": True,
            "disk_encrypted": True,
            "patch_compliance_pct": 90.0,
        }
        result = svc.assess_device_posture(device)
        posture = result["posture"]
        # Outdated AV should count as a violation for Corporate Standard
        assert posture["posture_score"] < 100

    def test_assess_generates_decision(self, svc, compliant_device):
        result = svc.assess_device_posture(compliant_device)
        dec = result["decision"]
        assert dec["decision_id"].startswith("DEC-")
        assert dec["device_id"] == "DEV-CORP-001"
        assert "assigned_vlan" in dec

    def test_get_posture(self, svc, compliant_device):
        svc.assess_device_posture(compliant_device)
        posture = svc.get_posture("DEV-CORP-001")
        assert posture is not None
        assert posture.device_id == "DEV-CORP-001"

    def test_get_posture_not_found(self, svc):
        assert svc.get_posture("NONEXIST") is None

    def test_list_postures(self, svc, compliant_device, non_compliant_device):
        svc.assess_device_posture(compliant_device)
        svc.assess_device_posture(non_compliant_device)
        all_postures = svc.list_postures()
        assert len(all_postures) >= 2

    def test_list_postures_filter_compliant(self, svc, compliant_device, non_compliant_device):
        svc.assess_device_posture(compliant_device)
        svc.assess_device_posture(non_compliant_device)
        compliant_list = svc.list_postures(compliant=True)
        assert all(p.compliant for p in compliant_list)

    def test_list_postures_filter_network(self, svc, compliant_device, non_compliant_device):
        svc.assess_device_posture(compliant_device)
        svc.assess_device_posture(non_compliant_device)
        quarantined = svc.list_postures(network=NetworkZone.QUARANTINE.value)
        assert all(p.assigned_network == NetworkZone.QUARANTINE.value for p in quarantined)

    def test_reassess_device(self, svc, compliant_device):
        svc.assess_device_posture(compliant_device)
        result = svc.reassess_device("DEV-CORP-001")
        assert result is not None
        assert result["posture"]["device_id"] == "DEV-CORP-001"

    def test_reassess_device_not_found(self, svc):
        assert svc.reassess_device("NONEXIST") is None

    def test_posture_to_dict(self, svc, compliant_device):
        svc.assess_device_posture(compliant_device)
        posture = svc.get_posture("DEV-CORP-001")
        d = _posture_to_dict(posture)
        assert d["device_id"] == "DEV-CORP-001"
        assert "posture_score" in d
        assert "violations" in d


# ============================================================
# Quarantine Management
# ============================================================

class TestQuarantine:
    def test_get_quarantined_devices(self, svc, non_compliant_device):
        svc.assess_device_posture(non_compliant_device)
        quarantined = svc.get_quarantined_devices()
        assert len(quarantined) >= 1

    def test_release_from_quarantine(self, svc, non_compliant_device):
        svc.assess_device_posture(non_compliant_device)
        result = svc.release_from_quarantine("DEV-BAD-001")
        assert result is not None
        assert result["posture"]["assigned_network"] == NetworkZone.CORPORATE.value

    def test_release_from_quarantine_custom_network(self, svc, non_compliant_device):
        svc.assess_device_posture(non_compliant_device)
        result = svc.release_from_quarantine("DEV-BAD-001", target_network=NetworkZone.BYOD.value)
        assert result["posture"]["assigned_network"] == NetworkZone.BYOD.value

    def test_release_not_quarantined(self, svc, compliant_device):
        svc.assess_device_posture(compliant_device)
        result = svc.release_from_quarantine("DEV-CORP-001")
        assert result is None

    def test_release_not_found(self, svc):
        assert svc.release_from_quarantine("NONEXIST") is None


# ============================================================
# Device Blocking
# ============================================================

class TestBlocking:
    def test_block_device(self, svc):
        blocked = svc.block_device("AA:BB:CC:DD:EE:FF", reason="security threat")
        assert blocked.mac_address == "AA:BB:CC:DD:EE:FF"
        assert blocked.reason == "security threat"

    def test_unblock_device(self, svc):
        svc.block_device("AA:BB:CC:DD:EE:FF")
        assert svc.unblock_device("AA:BB:CC:DD:EE:FF") is True

    def test_unblock_not_found(self, svc):
        assert svc.unblock_device("XX:XX:XX:XX:XX:XX") is False

    def test_get_blocked_devices(self, svc):
        svc.block_device("AA:BB:CC:00:00:01", reason="r1")
        svc.block_device("AA:BB:CC:00:00:02", reason="r2")
        blocked = svc.get_blocked_devices()
        assert len(blocked) == 2

    def test_blocked_device_denied_access(self, svc):
        svc.block_device("AA:BB:CC:DD:EE:01")
        result = svc.assess_device_posture({
            "device_id": "DEV-BLK",
            "mac_address": "AA:BB:CC:DD:EE:01",
        })
        assert result["blocked"] is True
        assert result["decision"]["decision"] == AccessDecisionType.DENY.value

    def test_blocked_to_dict(self, svc):
        b = svc.block_device("11:22:33:44:55:66", reason="test")
        d = _blocked_to_dict(b)
        assert d["mac_address"] == "11:22:33:44:55:66"
        assert "blocked_at" in d


# ============================================================
# Guest Registration
# ============================================================

class TestGuestRegistration:
    def test_register_guest(self, svc):
        guest = svc.register_guest(
            name="John Doe", email="john@example.com",
            company="Acme Corp", sponsor_email="sponsor@corp.com",
            mac_address="AA:BB:CC:00:00:10", hours=4,
        )
        assert guest.guest_id.startswith("GUEST-")
        assert guest.name == "John Doe"
        assert guest.status == GuestStatus.PENDING.value
        assert guest.access_end is not None

    def test_approve_guest(self, svc):
        guest = svc.register_guest(name="Jane Doe")
        approved = svc.approve_guest(guest.guest_id)
        assert approved is not None
        assert approved.status == GuestStatus.APPROVED.value

    def test_approve_guest_not_found(self, svc):
        assert svc.approve_guest("GUEST-NONEXIST") is None

    def test_revoke_guest(self, svc):
        guest = svc.register_guest(name="Revoke Me")
        svc.approve_guest(guest.guest_id)
        revoked = svc.revoke_guest(guest.guest_id)
        assert revoked.status == GuestStatus.REVOKED.value

    def test_revoke_guest_not_found(self, svc):
        assert svc.revoke_guest("GUEST-NONEXIST") is None

    def test_list_guests(self, svc):
        svc.register_guest(name="Guest A", client_id="C1")
        svc.register_guest(name="Guest B", client_id="C2")
        all_guests = svc.list_guests()
        assert len(all_guests) >= 2

    def test_list_guests_by_client(self, svc):
        svc.register_guest(name="Guest A", client_id="C1")
        svc.register_guest(name="Guest B", client_id="C2")
        c1_guests = svc.list_guests(client_id="C1")
        assert all(g.client_id == "C1" for g in c1_guests)

    def test_list_guests_by_status(self, svc):
        g = svc.register_guest(name="Pending Guest")
        svc.approve_guest(g.guest_id)
        pending = svc.list_guests(status=GuestStatus.PENDING.value)
        approved = svc.list_guests(status=GuestStatus.APPROVED.value)
        assert g.guest_id not in [p.guest_id for p in pending]
        assert g.guest_id in [a.guest_id for a in approved]

    def test_guest_to_dict(self, svc):
        guest = svc.register_guest(name="Dict Test")
        d = _guest_to_dict(guest)
        assert d["name"] == "Dict Test"
        assert "access_start" in d
        assert "access_end" in d


# ============================================================
# Captive Portal
# ============================================================

class TestCaptivePortal:
    def test_configure_portal(self, svc):
        config = svc.configure_captive_portal(
            client_id="C1",
            branding={"logo_url": "https://example.com/logo.png"},
            terms_of_use="Accept all terms.",
            session_timeout_minutes=240,
            bandwidth_limit_mbps=5.0,
        )
        assert config.portal_id.startswith("PORTAL-")
        assert config.client_id == "C1"
        assert config.session_timeout_minutes == 240
        assert config.bandwidth_limit_mbps == 5.0

    def test_get_portal_config(self, svc):
        svc.configure_captive_portal(client_id="C1", terms_of_use="Terms here")
        config = svc.get_portal_config("C1")
        assert config is not None
        assert config.terms_of_use == "Terms here"

    def test_get_portal_not_found(self, svc):
        assert svc.get_portal_config("NONEXIST") is None

    def test_portal_to_dict(self, svc):
        config = svc.configure_captive_portal(client_id="C1")
        d = _portal_to_dict(config)
        assert d["client_id"] == "C1"
        assert "session_timeout_minutes" in d
        assert "bandwidth_limit_mbps" in d


# ============================================================
# Access Log
# ============================================================

class TestAccessLog:
    def test_access_log_populated(self, svc, compliant_device):
        svc.assess_device_posture(compliant_device)
        log = svc.get_access_log()
        assert len(log) >= 1

    def test_access_log_filter_device(self, svc, compliant_device, non_compliant_device):
        svc.assess_device_posture(compliant_device)
        svc.assess_device_posture(non_compliant_device)
        log = svc.get_access_log(device_id="DEV-CORP-001")
        assert all(e["device_id"] == "DEV-CORP-001" for e in log)

    def test_access_log_filter_decision(self, svc, compliant_device, non_compliant_device):
        svc.assess_device_posture(compliant_device)
        svc.assess_device_posture(non_compliant_device)
        allow_log = svc.get_access_log(decision=AccessDecisionType.ALLOW.value)
        assert all(e["decision"] == "allow" for e in allow_log)

    def test_access_log_limit(self, svc, compliant_device):
        for i in range(5):
            device = compliant_device.copy()
            device["device_id"] = f"DEV-{i}"
            svc.assess_device_posture(device)
        log = svc.get_access_log(limit=3)
        assert len(log) <= 3


# ============================================================
# Compliance & Reporting
# ============================================================

class TestComplianceReporting:
    def test_compliance_report_empty(self, svc):
        report = svc.get_compliance_report()
        assert report["total_devices"] == 0
        assert report["compliance_pct"] == 0.0

    def test_compliance_report_with_devices(self, svc, compliant_device, non_compliant_device):
        svc.assess_device_posture(compliant_device)
        svc.assess_device_posture(non_compliant_device)
        report = svc.get_compliance_report()
        assert report["total_devices"] == 2
        assert report["compliant_count"] >= 1
        assert report["non_compliant_count"] >= 1
        assert "by_category" in report
        assert "antivirus" in report["by_category"]
        assert "firewall" in report["by_category"]
        assert "encryption" in report["by_category"]
        assert "patch_compliance" in report["by_category"]

    def test_compliance_categories_have_pct(self, svc, compliant_device):
        svc.assess_device_posture(compliant_device)
        report = svc.get_compliance_report()
        for cat_name, cat_data in report["by_category"].items():
            assert "compliant" in cat_data
            assert "total" in cat_data
            assert "pct" in cat_data

    def test_zone_distribution_empty(self, svc):
        dist = svc.get_network_zone_distribution()
        assert isinstance(dist, dict)

    def test_zone_distribution_with_devices(self, svc, compliant_device, non_compliant_device):
        svc.assess_device_posture(compliant_device)
        svc.assess_device_posture(non_compliant_device)
        dist = svc.get_network_zone_distribution()
        total = sum(dist.values())
        assert total >= 2


# ============================================================
# Dashboard
# ============================================================

class TestDashboard:
    def test_dashboard_structure(self, svc):
        dash = svc.get_dashboard()
        assert "total_devices" in dash
        assert "compliant_devices" in dash
        assert "non_compliant_devices" in dash
        assert "compliance_pct" in dash
        assert "quarantined_devices" in dash
        assert "blocked_devices" in dash
        assert "active_guests" in dash
        assert "total_policies" in dash
        assert "enabled_policies" in dash
        assert "zone_distribution" in dash
        assert "recent_decisions" in dash

    def test_dashboard_with_data(self, svc, compliant_device, non_compliant_device):
        svc.assess_device_posture(compliant_device)
        svc.assess_device_posture(non_compliant_device)
        svc.block_device("FF:FF:FF:FF:FF:FF")
        svc.register_guest(name="Active Guest")
        dash = svc.get_dashboard()
        assert dash["total_devices"] >= 2
        assert dash["blocked_devices"] >= 1
        assert dash["total_policies"] >= 4  # defaults

    def test_dashboard_empty(self, svc):
        dash = svc.get_dashboard()
        assert dash["total_devices"] == 0
        assert dash["compliance_pct"] == 0.0


# ============================================================
# Enum Values
# ============================================================

class TestEnums:
    def test_network_zones(self):
        assert NetworkZone.CORPORATE.value == "corporate"
        assert NetworkZone.GUEST.value == "guest"
        assert NetworkZone.QUARANTINE.value == "quarantine"
        assert NetworkZone.RESTRICTED.value == "restricted"
        assert NetworkZone.IOT.value == "iot"
        assert NetworkZone.BYOD.value == "byod"

    def test_posture_results(self):
        assert PostureResult.COMPLIANT.value == "compliant"
        assert PostureResult.NON_COMPLIANT.value == "non_compliant"
        assert PostureResult.PARTIAL.value == "partial"
        assert PostureResult.UNKNOWN.value == "unknown"

    def test_access_decision_types(self):
        assert AccessDecisionType.ALLOW.value == "allow"
        assert AccessDecisionType.QUARANTINE.value == "quarantine"
        assert AccessDecisionType.DENY.value == "deny"
        assert AccessDecisionType.GUEST.value == "guest"

    def test_antivirus_status(self):
        assert AntivirusStatus.INSTALLED.value == "installed"
        assert AntivirusStatus.OUTDATED.value == "outdated"
        assert AntivirusStatus.MISSING.value == "missing"

    def test_guest_status(self):
        assert GuestStatus.PENDING.value == "pending"
        assert GuestStatus.APPROVED.value == "approved"
        assert GuestStatus.REVOKED.value == "revoked"
