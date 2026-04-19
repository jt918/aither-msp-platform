"""
AITHER Platform - MDM Enhanced Service Tests

Full test coverage for MDMService: device management, policies,
app management, compliance, actions, geofencing, BYOD, and dashboard.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.msp.mdm_service import (
    MDMService,
    EnrollmentStatus,
    ComplianceStatus,
    DeviceActionType,
    PolicyType,
)


@pytest.fixture
def svc():
    """Fresh MDM service instance for each test."""
    return MDMService()


@pytest.fixture
def enrolled_device(svc):
    """Enroll a test device and return its ID."""
    result = svc.enroll_device({
        "device_name": "Test iPhone",
        "user_id": "user-001",
        "client_id": "client-001",
        "platform": "ios",
        "os_version": "17.4",
        "model": "iPhone 15",
        "serial_number": "SN-TEST-001",
        "imei": "123456789012345",
    })
    return result["device_id"]


# ── Device Management Tests ──────────────────────────────────────────


class TestDeviceManagement:
    def test_enroll_device(self, svc):
        result = svc.enroll_device({
            "device_name": "Test Android",
            "user_id": "user-002",
            "client_id": "client-001",
            "platform": "android",
            "os_version": "14",
            "model": "Pixel 8",
        })
        assert result["success"] is True
        assert result["device_id"].startswith("DEV-")
        assert result["enrollment_status"] == "enrolled"

    def test_enroll_device_defaults(self, svc):
        result = svc.enroll_device({"device_name": "Minimal Device"})
        assert result["success"] is True
        device = svc.get_device(result["device_id"])
        assert device["device"]["platform"] == "android"

    def test_get_device(self, svc, enrolled_device):
        result = svc.get_device(enrolled_device)
        assert result["success"] is True
        assert result["device"]["device_name"] == "Test iPhone"
        assert result["device"]["platform"] == "ios"

    def test_get_device_not_found(self, svc):
        result = svc.get_device("NONEXISTENT")
        assert result["success"] is False

    def test_list_devices(self, svc, enrolled_device):
        result = svc.list_devices()
        assert result["total"] >= 1

    def test_list_devices_filter_platform(self, svc, enrolled_device):
        result = svc.list_devices(platform="ios")
        assert all(d["platform"] == "ios" for d in result["devices"])

    def test_list_devices_filter_enrollment(self, svc, enrolled_device):
        result = svc.list_devices(enrollment_status="enrolled")
        assert all(d["enrollment_status"] == "enrolled" for d in result["devices"])

    def test_list_devices_filter_client(self, svc, enrolled_device):
        result = svc.list_devices(client_id="client-001")
        assert all(d["client_id"] == "client-001" for d in result["devices"])

    def test_update_device_info(self, svc, enrolled_device):
        result = svc.update_device_info(enrolled_device, {
            "os_version": "17.5",
            "battery_level": 85,
        })
        assert result["success"] is True
        assert "os_version" in result["updated_fields"]
        device = svc.get_device(enrolled_device)
        assert device["device"]["os_version"] == "17.5"
        assert device["device"]["battery_level"] == 85

    def test_update_device_not_found(self, svc):
        result = svc.update_device_info("BAD-ID", {"os_version": "1"})
        assert result["success"] is False

    def test_unenroll_device(self, svc, enrolled_device):
        result = svc.unenroll_device(enrolled_device)
        assert result["success"] is True
        assert result["status"] == "unenrolled"
        device = svc.get_device(enrolled_device)
        assert device["device"]["enrollment_status"] == "unenrolled"
        assert device["device"]["management_profile_installed"] is False

    def test_unenroll_not_found(self, svc):
        result = svc.unenroll_device("BAD-ID")
        assert result["success"] is False

    def test_checkin(self, svc, enrolled_device):
        result = svc.checkin(enrolled_device, {
            "battery_level": 72,
            "encryption_enabled": True,
            "passcode_set": True,
            "jailbroken": False,
            "latitude": 35.46,
            "longitude": -97.51,
        })
        assert result["success"] is True
        assert result["checkin_time"] is not None
        device = svc.get_device(enrolled_device)
        assert device["device"]["battery_level"] == 72
        assert device["device"]["last_latitude"] == 35.46

    def test_checkin_not_found(self, svc):
        result = svc.checkin("BAD-ID", {})
        assert result["success"] is False


# ── Policy Tests ─────────────────────────────────────────────────────


class TestPolicies:
    def test_create_policy(self, svc):
        result = svc.create_policy({
            "name": "VPN Required",
            "platform": "ios",
            "policy_type": PolicyType.VPN_CONFIG.value,
            "settings": {"vpn_server": "vpn.aither.com"},
            "is_mandatory": True,
        })
        assert result["success"] is True
        assert result["policy_id"].startswith("POL-")

    def test_list_policies(self, svc):
        result = svc.list_policies()
        assert result["total"] >= 1  # baseline policy seeded

    def test_list_policies_filter(self, svc):
        svc.create_policy({"name": "iOS Only", "platform": "ios"})
        result = svc.list_policies(platform="ios")
        # Should include ios-specific AND "all" platform policies
        assert result["total"] >= 1

    def test_update_policy(self, svc):
        created = svc.create_policy({"name": "Temp Policy"})
        result = svc.update_policy(created["policy_id"], {"name": "Updated Policy", "is_mandatory": True})
        assert result["success"] is True

    def test_update_policy_not_found(self, svc):
        result = svc.update_policy("BAD-ID", {"name": "X"})
        assert result["success"] is False

    def test_delete_policy(self, svc):
        created = svc.create_policy({"name": "To Delete"})
        result = svc.delete_policy(created["policy_id"])
        assert result["success"] is True
        # Verify deleted
        listing = svc.list_policies()
        ids = [p["policy_id"] for p in listing["policies"]]
        assert created["policy_id"] not in ids

    def test_delete_policy_not_found(self, svc):
        result = svc.delete_policy("BAD-ID")
        assert result["success"] is False

    def test_assign_policy_to_group(self, svc):
        created = svc.create_policy({"name": "Group Policy"})
        result = svc.assign_policy_to_group(created["policy_id"], "engineering")
        assert result["success"] is True
        assert "engineering" in result["assigned_groups"]

    def test_assign_policy_not_found(self, svc):
        result = svc.assign_policy_to_group("BAD-ID", "group")
        assert result["success"] is False

    def test_get_effective_policies(self, svc, enrolled_device):
        result = svc.get_effective_policies(enrolled_device)
        assert result["device_id"] == enrolled_device
        # Should include baseline mandatory policy
        assert result["count"] >= 1

    def test_get_effective_policies_not_found(self, svc):
        result = svc.get_effective_policies("BAD-ID")
        assert result.get("success") is False


# ── App Management Tests ─────────────────────────────────────────────


class TestAppManagement:
    def test_register_app(self, svc):
        result = svc.register_app({
            "name": "Aither Shield",
            "bundle_id": "com.aither.shield",
            "platform": "ios",
            "version": "2.1.0",
            "category": "security",
        })
        assert result["success"] is True
        assert result["app_id"].startswith("APP-")

    def test_list_apps(self, svc):
        svc.register_app({"name": "Test App", "bundle_id": "com.test"})
        result = svc.list_apps()
        assert result["total"] >= 1

    def test_list_apps_filter(self, svc):
        svc.register_app({"name": "iOS App", "platform": "ios", "bundle_id": "com.ios"})
        result = svc.list_apps(platform="ios")
        assert result["total"] >= 1

    def test_block_app(self, svc):
        created = svc.register_app({"name": "Bad App", "bundle_id": "com.bad"})
        result = svc.block_app(created["app_id"])
        assert result["success"] is True
        assert result["status"] == "blocked"

    def test_block_app_not_found(self, svc):
        result = svc.block_app("BAD-ID")
        assert result["success"] is False

    def test_require_app(self, svc):
        created = svc.register_app({"name": "Required App", "bundle_id": "com.req"})
        result = svc.require_app(created["app_id"])
        assert result["success"] is True
        assert result["status"] == "required"

    def test_require_app_not_found(self, svc):
        result = svc.require_app("BAD-ID")
        assert result["success"] is False

    def test_get_app_install_status(self, svc, enrolled_device):
        svc.register_app({"name": "Req App", "bundle_id": "com.req", "platform": "ios", "is_required": True})
        svc.register_app({"name": "Bad App", "bundle_id": "com.bad", "platform": "ios", "is_blocked": True})
        result = svc.get_app_install_status(enrolled_device)
        assert result["device_id"] == enrolled_device
        assert result["required_count"] >= 1
        assert result["blocked_count"] >= 1

    def test_get_app_install_status_not_found(self, svc):
        result = svc.get_app_install_status("BAD-ID")
        assert result["success"] is False


# ── Compliance Tests ─────────────────────────────────────────────────


class TestCompliance:
    def test_create_compliance_rule(self, svc):
        result = svc.create_compliance_rule({
            "name": "Custom Rule",
            "check_type": "encryption_required",
            "expected_value": "true",
            "severity": "critical",
        })
        assert result["success"] is True
        assert result["rule_id"].startswith("RULE-")

    def test_evaluate_compliance_compliant(self, svc, enrolled_device):
        # Set device as fully compliant
        svc.checkin(enrolled_device, {
            "encryption_enabled": True,
            "passcode_set": True,
            "jailbroken": False,
            "roaming": False,
            "os_version": "17.4",
        })
        result = svc.evaluate_compliance(enrolled_device)
        assert result["device_id"] == enrolled_device
        assert result["compliant"] is True
        assert len(result["violations"]) == 0

    def test_evaluate_compliance_non_compliant(self, svc, enrolled_device):
        # Device without encryption
        svc.checkin(enrolled_device, {
            "encryption_enabled": False,
            "passcode_set": False,
            "jailbroken": True,
        })
        result = svc.evaluate_compliance(enrolled_device)
        assert result["compliant"] is False
        assert len(result["violations"]) >= 2

    def test_evaluate_compliance_not_found(self, svc):
        result = svc.evaluate_compliance("BAD-ID")
        assert result["success"] is False

    def test_evaluate_all_compliance(self, svc, enrolled_device):
        result = svc.evaluate_all_compliance()
        assert result["total_evaluated"] >= 1

    def test_get_compliance_report(self, svc, enrolled_device):
        svc.checkin(enrolled_device, {"encryption_enabled": True, "passcode_set": True, "jailbroken": False, "roaming": False, "os_version": "17.4"})
        report = svc.get_compliance_report()
        assert report["total_enrolled"] >= 1
        assert "compliance_rate" in report
        assert "top_non_compliant_rules" in report


# ── Device Actions Tests ─────────────────────────────────────────────


class TestDeviceActions:
    def test_send_lock_action(self, svc, enrolled_device):
        result = svc.send_action(enrolled_device, DeviceActionType.LOCK.value, {"message": "Locked by test"})
        assert result["success"] is True
        assert result["action_type"] == "lock"
        assert result["status"] == "completed"

    def test_send_wipe_action(self, svc, enrolled_device):
        result = svc.send_action(enrolled_device, DeviceActionType.WIPE.value)
        assert result["success"] is True
        # Device should now be wiped
        device = svc.get_device(enrolled_device)
        assert device["device"]["enrollment_status"] == "wiped"

    def test_send_selective_wipe(self, svc, enrolled_device):
        svc.separate_work_personal(enrolled_device)
        result = svc.send_action(enrolled_device, DeviceActionType.SELECTIVE_WIPE.value)
        assert result["success"] is True
        device = svc.get_device(enrolled_device)
        assert device["device"]["work_profile_enabled"] is False

    def test_send_ring_action(self, svc, enrolled_device):
        result = svc.send_action(enrolled_device, DeviceActionType.RING.value)
        assert result["success"] is True

    def test_send_action_invalid_type(self, svc, enrolled_device):
        result = svc.send_action(enrolled_device, "invalid_action")
        assert result["success"] is False

    def test_send_action_not_enrolled(self, svc, enrolled_device):
        svc.unenroll_device(enrolled_device)
        result = svc.send_action(enrolled_device, DeviceActionType.LOCK.value)
        assert result["success"] is False

    def test_send_action_not_found(self, svc):
        result = svc.send_action("BAD-ID", DeviceActionType.LOCK.value)
        assert result["success"] is False

    def test_get_action_status(self, svc, enrolled_device):
        sent = svc.send_action(enrolled_device, DeviceActionType.RING.value)
        result = svc.get_action_status(sent["action_id"])
        assert result["success"] is True
        assert result["action"]["status"] == "completed"

    def test_get_action_status_not_found(self, svc):
        result = svc.get_action_status("BAD-ID")
        assert result["success"] is False

    def test_list_actions(self, svc, enrolled_device):
        svc.send_action(enrolled_device, DeviceActionType.RING.value)
        svc.send_action(enrolled_device, DeviceActionType.LOCATE.value)
        result = svc.list_actions()
        assert result["total"] >= 2

    def test_list_actions_filter_device(self, svc, enrolled_device):
        svc.send_action(enrolled_device, DeviceActionType.RING.value)
        result = svc.list_actions(device_id=enrolled_device)
        assert all(a["device_id"] == enrolled_device for a in result["actions"])


# ── Geofencing Tests ─────────────────────────────────────────────────


class TestGeofencing:
    def test_create_zone(self, svc):
        result = svc.create_zone({
            "name": "HQ Perimeter",
            "latitude": 35.4676,
            "longitude": -97.5164,
            "radius_meters": 1000,
            "action_on_exit": "alert",
        })
        assert result["success"] is True
        assert result["zone_id"].startswith("GEO-")

    def test_list_zones(self, svc):
        svc.create_zone({"name": "Zone A", "latitude": 0, "longitude": 0})
        result = svc.list_zones()
        assert result["total"] >= 1

    def test_update_zone(self, svc):
        created = svc.create_zone({"name": "Zone B", "latitude": 10, "longitude": 20})
        result = svc.update_zone(created["zone_id"], {"name": "Updated Zone B", "radius_meters": 2000})
        assert result["success"] is True

    def test_update_zone_not_found(self, svc):
        result = svc.update_zone("BAD-ID", {"name": "X"})
        assert result["success"] is False

    def test_delete_zone(self, svc):
        created = svc.create_zone({"name": "To Delete", "latitude": 0, "longitude": 0})
        result = svc.delete_zone(created["zone_id"])
        assert result["success"] is True
        listing = svc.list_zones()
        ids = [z["zone_id"] for z in listing["zones"]]
        assert created["zone_id"] not in ids

    def test_delete_zone_not_found(self, svc):
        result = svc.delete_zone("BAD-ID")
        assert result["success"] is False

    def test_check_device_inside_zone(self, svc, enrolled_device):
        zone = svc.create_zone({
            "name": "HQ",
            "latitude": 35.4676,
            "longitude": -97.5164,
            "radius_meters": 5000,
            "assigned_devices": [enrolled_device],
        })
        result = svc.check_device_location(enrolled_device, 35.4680, -97.5160)
        assert result["inside_all_zones"] is True
        assert len(result["alerts"]) == 0

    def test_check_device_outside_zone(self, svc, enrolled_device):
        svc.create_zone({
            "name": "Office",
            "latitude": 35.4676,
            "longitude": -97.5164,
            "radius_meters": 100,
            "action_on_exit": "alert",
            "assigned_devices": [enrolled_device],
        })
        result = svc.check_device_location(enrolled_device, 40.0, -80.0)
        assert result["inside_all_zones"] is False
        assert len(result["alerts"]) >= 1
        assert result["alerts"][0]["status"] == "outside_geofence"

    def test_check_device_not_found(self, svc):
        result = svc.check_device_location("BAD-ID", 0, 0)
        assert result["success"] is False

    def test_geofence_auto_lock(self, svc, enrolled_device):
        svc.create_zone({
            "name": "Secure Zone",
            "latitude": 35.4676,
            "longitude": -97.5164,
            "radius_meters": 100,
            "action_on_exit": "lock",
            "assigned_devices": [enrolled_device],
        })
        result = svc.check_device_location(enrolled_device, 40.0, -80.0)
        assert len(result["alerts"]) >= 1
        assert result["alerts"][0]["action"] == "lock"
        # Lock action should have been auto-triggered
        actions = svc.list_actions(device_id=enrolled_device)
        lock_actions = [a for a in actions["actions"] if a["action_type"] == "lock"]
        assert len(lock_actions) >= 1


# ── BYOD Tests ───────────────────────────────────────────────────────


class TestBYOD:
    def test_separate_work_personal(self, svc, enrolled_device):
        result = svc.separate_work_personal(enrolled_device)
        assert result["success"] is True
        assert result["work_profile_enabled"] is True
        assert result["personal_apps_separated"] is True

    def test_separate_not_found(self, svc):
        result = svc.separate_work_personal("BAD-ID")
        assert result["success"] is False

    def test_get_work_profile_status(self, svc, enrolled_device):
        svc.separate_work_personal(enrolled_device)
        result = svc.get_work_profile_status(enrolled_device)
        assert result["work_profile_enabled"] is True
        assert result["platform"] == "ios"

    def test_get_work_profile_not_found(self, svc):
        result = svc.get_work_profile_status("BAD-ID")
        assert result["success"] is False


# ── Dashboard Tests ──────────────────────────────────────────────────


class TestDashboard:
    def test_dashboard_empty(self, svc):
        dashboard = svc.get_dashboard()
        assert "total_devices" in dashboard
        assert "compliance_rate" in dashboard
        assert "by_platform" in dashboard

    def test_dashboard_with_devices(self, svc, enrolled_device):
        svc.checkin(enrolled_device, {
            "encryption_enabled": True,
            "passcode_set": True,
            "jailbroken": False,
            "roaming": False,
            "os_version": "17.4",
        })
        dashboard = svc.get_dashboard()
        assert dashboard["enrolled"] >= 1
        assert dashboard["total_policies"] >= 1

    def test_dashboard_non_compliant(self, svc, enrolled_device):
        svc.checkin(enrolled_device, {
            "encryption_enabled": False,
            "passcode_set": False,
        })
        svc.evaluate_compliance(enrolled_device)
        dashboard = svc.get_dashboard()
        assert dashboard["non_compliant_devices"] >= 1


# ── Seeded Defaults Tests ────────────────────────────────────────────


class TestDefaults:
    def test_default_rules_seeded(self, svc):
        assert len(svc._rules) >= 5

    def test_default_baseline_policy(self, svc):
        assert "POL-BASELINE" in svc._policies
        baseline = svc._policies["POL-BASELINE"]
        assert baseline.is_mandatory is True

    def test_os_version_compliance_check(self, svc, enrolled_device):
        svc.checkin(enrolled_device, {
            "os_version": "12.0",
            "encryption_enabled": True,
            "passcode_set": True,
            "jailbroken": False,
            "roaming": False,
        })
        result = svc.evaluate_compliance(enrolled_device)
        os_violations = [v for v in result["violations"] if "OS version" in v["detail"]]
        assert len(os_violations) >= 1

    def test_roaming_compliance_check(self, svc, enrolled_device):
        svc.checkin(enrolled_device, {
            "roaming": True,
            "encryption_enabled": True,
            "passcode_set": True,
            "jailbroken": False,
            "os_version": "17.4",
        })
        result = svc.evaluate_compliance(enrolled_device)
        roaming_violations = [v for v in result["violations"] if "roaming" in v["detail"].lower()]
        assert len(roaming_violations) >= 1
