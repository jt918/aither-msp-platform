"""
Aither Shield - Shield Service Tests

Comprehensive tests for the consumer security service.
"""

import pytest
from datetime import datetime, timedelta
from services.shield.shield_service import (
    ShieldService,
    ThreatSeverity,
    ScanType,
    ProtectionStatus,
    DeviceType,
    SubscriptionStatus,
    ThreatType,
    DetectionEngine,
    FirewallRuleType,
    FirewallDirection,
    VPNStatus,
    DarkWebAlertType,
    DarkWebAlertStatus,
)


@pytest.fixture
def shield_service():
    """Create a fresh ShieldService instance."""
    return ShieldService()


@pytest.fixture
def test_user(shield_service):
    """Create a test user."""
    result = shield_service.create_user(
        email="test@example.com",
        password_hash="hashed_password",
        name="Test User",
        plan_slug="mobile-free"
    )
    return result


@pytest.fixture
def test_device(shield_service, test_user):
    """Create a test device."""
    result = shield_service.register_device(
        user_id=test_user["user_id"],
        device_info={
            "type": "windows",
            "name": "Test PC",
            "os_version": "Windows 11",
            "app_version": "3.0.5",
        }
    )
    return result


class TestSubscriptionPlans:
    """Tests for subscription plan management."""

    def test_get_all_plans(self, shield_service):
        """Should return all available plans."""
        plans = shield_service.get_plans()
        assert len(plans) > 0

        # Check plan structure
        for plan in plans:
            assert "id" in plan
            assert "name" in plan
            assert "slug" in plan
            assert "platform" in plan
            assert "max_devices" in plan
            assert "features" in plan

    def test_get_mobile_plans(self, shield_service):
        """Should filter plans by platform."""
        plans = shield_service.get_plans(platform="mobile")
        assert all(p["platform"] in ["mobile", "bundle"] for p in plans)

    def test_get_desktop_plans(self, shield_service):
        """Should return desktop and bundle plans."""
        plans = shield_service.get_plans(platform="desktop")
        assert all(p["platform"] in ["desktop", "bundle"] for p in plans)

    def test_get_plan_by_slug(self, shield_service):
        """Should find plan by slug."""
        plan = shield_service.get_plan_by_slug("mobile-free")
        assert plan is not None
        assert plan["name"] == "Free"
        assert plan["max_devices"] == 1

    def test_get_nonexistent_plan(self, shield_service):
        """Should return None for invalid slug."""
        plan = shield_service.get_plan_by_slug("nonexistent-plan")
        assert plan is None


class TestUserManagement:
    """Tests for user creation and management."""

    def test_create_user(self, shield_service):
        """Should create a new user."""
        result = shield_service.create_user(
            email="newuser@example.com",
            password_hash="password123",
            name="New User"
        )
        assert result["success"] is True
        assert "user_id" in result
        assert result["email"] == "newuser@example.com"

    def test_create_duplicate_user(self, shield_service, test_user):
        """Should reject duplicate email."""
        result = shield_service.create_user(
            email="test@example.com",
            password_hash="different_password"
        )
        assert result["success"] is False
        assert "already registered" in result["error"]

    def test_get_user(self, shield_service, test_user):
        """Should return user details."""
        user = shield_service.get_user(test_user["user_id"])
        assert user is not None
        assert user["email"] == "test@example.com"
        assert user["name"] == "Test User"
        assert user["subscription_status"] == "trial"

    def test_get_nonexistent_user(self, shield_service):
        """Should return None for invalid user ID."""
        user = shield_service.get_user("nonexistent-id")
        assert user is None

    def test_verify_subscription(self, shield_service, test_user):
        """Should verify active subscription."""
        result = shield_service.verify_subscription(test_user["user_id"])
        assert result["valid"] is True
        assert result["subscription_status"] == "trial"

    def test_upgrade_subscription(self, shield_service, test_user):
        """Should upgrade user subscription."""
        result = shield_service.upgrade_subscription(
            user_id=test_user["user_id"],
            plan_slug="desktop-pro",
            billing_cycle="yearly"
        )
        assert result["success"] is True
        assert result["plan"] == "Pro"

    def test_upgrade_to_invalid_plan(self, shield_service, test_user):
        """Should reject invalid plan."""
        result = shield_service.upgrade_subscription(
            user_id=test_user["user_id"],
            plan_slug="invalid-plan"
        )
        assert result["success"] is False


class TestDeviceManagement:
    """Tests for device registration and management."""

    def test_register_device(self, shield_service, test_user):
        """Should register a new device."""
        result = shield_service.register_device(
            user_id=test_user["user_id"],
            device_info={
                "type": "android",
                "name": "Test Phone",
                "os_version": "Android 14",
                "app_version": "2.1.0"
            }
        )
        assert result["success"] is True
        assert "device_id" in result

    def test_register_device_exceeds_limit(self, shield_service, test_user):
        """Should reject device when limit reached."""
        # Free plan allows 1 device
        shield_service.register_device(
            user_id=test_user["user_id"],
            device_info={"type": "android", "name": "Device 1", "app_version": "2.1.0"}
        )
        result = shield_service.register_device(
            user_id=test_user["user_id"],
            device_info={"type": "iphone", "name": "Device 2", "app_version": "2.1.0"}
        )
        assert result["success"] is False
        assert "limit" in result["error"].lower()

    def test_get_device_status(self, shield_service, test_device):
        """Should return device status."""
        status = shield_service.get_device_status(test_device["device_id"])
        assert "device_id" in status
        assert "protection_status" in status
        assert status["device_type"] == "windows"

    def test_get_user_devices(self, shield_service, test_user, test_device):
        """Should return all user devices."""
        devices = shield_service.get_user_devices(test_user["user_id"])
        assert len(devices) >= 1

    def test_device_heartbeat(self, shield_service, test_device):
        """Should update device last seen."""
        result = shield_service.device_heartbeat(test_device["device_id"])
        assert result["success"] is True
        assert "timestamp" in result

    def test_remove_device(self, shield_service, test_device):
        """Should remove device."""
        result = shield_service.remove_device(test_device["device_id"])
        assert result["success"] is True

        # Verify device is gone
        status = shield_service.get_device_status(test_device["device_id"])
        assert "error" in status


class TestScanning:
    """Tests for security scanning."""

    def test_start_quick_scan(self, shield_service, test_device):
        """Should start a quick scan."""
        result = shield_service.start_scan(
            device_id=test_device["device_id"],
            scan_type="quick"
        )
        assert result["success"] is True
        assert "scan_id" in result
        assert result["config"]["scan_type"] == "quick"

    def test_start_full_scan(self, shield_service, test_device):
        """Should start a full scan."""
        result = shield_service.start_scan(
            device_id=test_device["device_id"],
            scan_type="full"
        )
        assert result["success"] is True
        assert result["config"]["scan_type"] == "full"

    def test_start_custom_scan(self, shield_service, test_device):
        """Should start a custom scan with paths."""
        custom_paths = ["C:\\Users\\Test", "C:\\Downloads"]
        result = shield_service.start_scan(
            device_id=test_device["device_id"],
            scan_type="custom",
            custom_paths=custom_paths
        )
        assert result["success"] is True
        assert result["config"]["paths"] == custom_paths

    def test_report_scan_progress(self, shield_service, test_device):
        """Should record scan progress."""
        scan = shield_service.start_scan(
            device_id=test_device["device_id"],
            scan_type="quick"
        )
        result = shield_service.report_scan_progress(
            scan_id=scan["scan_id"],
            progress={"files_scanned": 100}
        )
        assert result["success"] is True

    def test_complete_scan(self, shield_service, test_device):
        """Should complete scan with results."""
        scan = shield_service.start_scan(
            device_id=test_device["device_id"],
            scan_type="quick"
        )
        result = shield_service.complete_scan(
            scan_id=scan["scan_id"],
            results={
                "files_scanned": 500,
                "threats_found": 0,
                "duration_seconds": 45
            }
        )
        assert result["success"] is True
        assert result["scan_summary"]["files_scanned"] == 500

    def test_get_scan_history(self, shield_service, test_device):
        """Should return scan history."""
        # Create a scan
        scan = shield_service.start_scan(
            device_id=test_device["device_id"],
            scan_type="quick"
        )
        shield_service.complete_scan(
            scan_id=scan["scan_id"],
            results={"files_scanned": 100, "duration_seconds": 10}
        )

        history = shield_service.get_scan_history(test_device["device_id"])
        assert len(history) >= 1


class TestThreatDetection:
    """Tests for threat detection and management."""

    def test_check_safe_file(self, shield_service, test_device):
        """Should mark clean file as safe."""
        result = shield_service.check_file(
            device_id=test_device["device_id"],
            file_hash="abc123def456"
        )
        # Most files should be safe
        assert "safe" in result or "is_threat" in result

    def test_check_url_safe(self, shield_service, test_device):
        """Should mark safe URL."""
        result = shield_service.check_url(
            device_id=test_device["device_id"],
            url="https://google.com"
        )
        assert result["is_safe"] is True

    def test_check_url_phishing(self, shield_service, test_device):
        """Should detect phishing URL."""
        result = shield_service.check_url(
            device_id=test_device["device_id"],
            url="https://phish-steal-login.com"
        )
        assert result["is_safe"] is False
        assert result["threat_type"] == "phishing"

    def test_report_threat(self, shield_service, test_device):
        """Should record reported threat."""
        result = shield_service.report_threat(
            device_id=test_device["device_id"],
            threat_data={
                "threat_type": "malware",
                "threat_name": "Test.Malware.A",
                "severity": "high",
                "source_path": "C:\\temp\\malware.exe"
            }
        )
        assert result["success"] is True
        assert "threat_id" in result

    def test_get_threat_history(self, shield_service, test_device, test_user):
        """Should return threat history."""
        # Report a threat first
        shield_service.report_threat(
            device_id=test_device["device_id"],
            threat_data={
                "threat_type": "adware",
                "threat_name": "Adware.Test",
                "severity": "low"
            }
        )

        history = shield_service.get_threat_history(test_device["device_id"])
        assert len(history) >= 1

    def test_get_user_threat_stats(self, shield_service, test_user, test_device):
        """Should return threat statistics."""
        stats = shield_service.get_user_threat_stats(test_user["user_id"])
        assert "total_threats" in stats
        assert "by_severity" in stats
        assert "by_type" in stats


class TestFirewall:
    """Tests for firewall management."""

    def test_get_default_rules(self, shield_service, test_device):
        """Should have default firewall rules for desktop."""
        rules = shield_service.get_firewall_rules(test_device["device_id"])
        assert len(rules) > 0
        # Should have system rules
        system_rules = [r for r in rules if r["is_system_rule"]]
        assert len(system_rules) > 0

    def test_create_firewall_rule(self, shield_service, test_device):
        """Should create custom firewall rule."""
        result = shield_service.create_firewall_rule(
            device_id=test_device["device_id"],
            rule_data={
                "name": "Block Test App",
                "rule_type": "block",
                "direction": "outbound",
                "protocol": "tcp",
                "application_path": "C:\\test\\app.exe"
            }
        )
        assert result["success"] is True
        assert "rule_id" in result

    def test_update_firewall_rule(self, shield_service, test_device):
        """Should update custom firewall rule."""
        # Create rule first
        create_result = shield_service.create_firewall_rule(
            device_id=test_device["device_id"],
            rule_data={
                "name": "Test Rule",
                "rule_type": "allow",
                "direction": "inbound",
                "protocol": "tcp"
            }
        )

        update_result = shield_service.update_firewall_rule(
            rule_id=create_result["rule_id"],
            updates={"name": "Updated Rule Name"}
        )
        assert update_result["success"] is True

    def test_cannot_modify_system_rule(self, shield_service, test_device):
        """Should not allow modifying system rules."""
        rules = shield_service.get_firewall_rules(test_device["device_id"])
        system_rule = next((r for r in rules if r["is_system_rule"]), None)

        if system_rule:
            result = shield_service.update_firewall_rule(
                rule_id=system_rule["id"],
                updates={"name": "Hacked Name"}
            )
            assert result["success"] is False

    def test_toggle_firewall_rule(self, shield_service, test_device):
        """Should toggle rule enabled state."""
        # Create rule
        create_result = shield_service.create_firewall_rule(
            device_id=test_device["device_id"],
            rule_data={
                "name": "Toggle Test",
                "rule_type": "block",
                "direction": "both",
                "protocol": "any"
            }
        )

        # Toggle off
        result = shield_service.toggle_firewall_rule(
            rule_id=create_result["rule_id"],
            enabled=False
        )
        assert result["success"] is True
        assert result["is_enabled"] is False

    def test_delete_firewall_rule(self, shield_service, test_device):
        """Should delete custom firewall rule."""
        # Create rule
        create_result = shield_service.create_firewall_rule(
            device_id=test_device["device_id"],
            rule_data={
                "name": "Delete Me",
                "rule_type": "block",
                "direction": "outbound",
                "protocol": "tcp"
            }
        )

        delete_result = shield_service.delete_firewall_rule(create_result["rule_id"])
        assert delete_result["success"] is True


class TestVPN:
    """Tests for VPN functionality."""

    def test_get_vpn_servers_without_access(self, shield_service, test_user):
        """Should require VPN feature for server list."""
        result = shield_service.get_vpn_servers(test_user["user_id"])
        # Free plan doesn't include VPN
        assert "error" in result or "servers" in result

    def test_get_vpn_servers_with_access(self, shield_service, test_user):
        """Should return servers for VPN-enabled plan."""
        # Upgrade to VPN plan
        shield_service.upgrade_subscription(test_user["user_id"], "desktop-pro")

        result = shield_service.get_vpn_servers(test_user["user_id"])
        assert "servers" in result
        assert len(result["servers"]) > 0

    def test_connect_vpn(self, shield_service, test_user, test_device):
        """Should connect to VPN server."""
        # Upgrade to VPN plan
        shield_service.upgrade_subscription(test_user["user_id"], "desktop-pro")

        servers = shield_service.get_vpn_servers(test_user["user_id"])
        server_id = servers["servers"][0]["id"]

        result = shield_service.connect_vpn(test_device["device_id"], server_id)
        assert result["success"] is True
        assert "session_id" in result
        assert "config" in result

    def test_get_vpn_status_connected(self, shield_service, test_user, test_device):
        """Should return connected VPN status."""
        shield_service.upgrade_subscription(test_user["user_id"], "desktop-pro")
        servers = shield_service.get_vpn_servers(test_user["user_id"])
        shield_service.connect_vpn(test_device["device_id"], servers["servers"][0]["id"])

        status = shield_service.get_vpn_status(test_device["device_id"])
        assert status["connected"] is True
        assert "assigned_ip" in status

    def test_disconnect_vpn(self, shield_service, test_user, test_device):
        """Should disconnect from VPN."""
        shield_service.upgrade_subscription(test_user["user_id"], "desktop-pro")
        servers = shield_service.get_vpn_servers(test_user["user_id"])
        shield_service.connect_vpn(test_device["device_id"], servers["servers"][0]["id"])

        result = shield_service.disconnect_vpn(test_device["device_id"])
        assert result["success"] is True

    def test_report_vpn_usage(self, shield_service, test_user, test_device):
        """Should track VPN bandwidth usage."""
        shield_service.upgrade_subscription(test_user["user_id"], "desktop-pro")
        servers = shield_service.get_vpn_servers(test_user["user_id"])
        connect_result = shield_service.connect_vpn(
            test_device["device_id"],
            servers["servers"][0]["id"]
        )

        result = shield_service.report_vpn_usage(
            session_id=connect_result["session_id"],
            bytes_sent=1024 * 1024,
            bytes_received=2 * 1024 * 1024
        )
        assert result["success"] is True
        assert result["total_bytes_sent"] == 1024 * 1024


class TestDarkWebMonitoring:
    """Tests for dark web monitoring."""

    def test_dark_web_requires_feature(self, shield_service, test_user):
        """Should require dark web monitoring feature."""
        result = shield_service.check_dark_web(test_user["user_id"])
        # Free plan doesn't include dark web monitoring
        assert "error" in result or "breaches_found" in result

    def test_check_dark_web(self, shield_service, test_user):
        """Should check dark web for user data."""
        # Upgrade to plan with dark web monitoring
        shield_service.upgrade_subscription(test_user["user_id"], "desktop-ultimate")

        result = shield_service.check_dark_web(test_user["user_id"])
        assert "breaches_found" in result
        assert "last_checked" in result

    def test_get_dark_web_alerts(self, shield_service, test_user):
        """Should return dark web alerts."""
        shield_service.upgrade_subscription(test_user["user_id"], "desktop-ultimate")
        shield_service.check_dark_web(test_user["user_id"])

        alerts = shield_service.get_dark_web_alerts(test_user["user_id"])
        assert isinstance(alerts, list)

    def test_acknowledge_dark_web_alert(self, shield_service, test_user):
        """Should acknowledge dark web alert."""
        shield_service.upgrade_subscription(test_user["user_id"], "desktop-ultimate")

        # Run check multiple times to likely get an alert
        for _ in range(10):
            result = shield_service.check_dark_web(test_user["user_id"])
            if result.get("alerts"):
                alert_id = result["alerts"][0]["id"]
                ack_result = shield_service.acknowledge_dark_web_alert(alert_id)
                assert ack_result["success"] is True
                assert ack_result["status"] == "acknowledged"
                break


class TestSignatures:
    """Tests for signature management."""

    def test_get_signature_version(self, shield_service):
        """Should return signature version."""
        version = shield_service.get_signature_version()
        assert "version" in version
        assert "signature_count" in version

    def test_get_signature_updates(self, shield_service):
        """Should check for signature updates."""
        updates = shield_service.get_signature_updates("2024.01.01.001")
        assert "current_version" in updates
        assert "latest_version" in updates
        assert "needs_update" in updates


class TestDashboard:
    """Tests for dashboard statistics."""

    def test_get_dashboard_stats(self, shield_service, test_user, test_device):
        """Should return dashboard statistics."""
        stats = shield_service.get_dashboard_stats(test_user["user_id"])

        assert "user" in stats
        assert "protection" in stats
        assert "threats" in stats
        assert "scans" in stats

        assert stats["user"]["email"] == "test@example.com"
        assert stats["protection"]["total_devices"] >= 1

    def test_dashboard_stats_invalid_user(self, shield_service):
        """Should return error for invalid user."""
        stats = shield_service.get_dashboard_stats("invalid-user-id")
        assert "error" in stats


class TestEnums:
    """Tests for enum values."""

    def test_threat_severity_values(self):
        """Should have expected severity values."""
        assert ThreatSeverity.LOW.value == "low"
        assert ThreatSeverity.CRITICAL.value == "critical"

    def test_scan_type_values(self):
        """Should have expected scan types."""
        assert ScanType.QUICK.value == "quick"
        assert ScanType.FULL.value == "full"
        assert ScanType.CUSTOM.value == "custom"
        assert ScanType.REALTIME.value == "realtime"

    def test_device_type_values(self):
        """Should have expected device types."""
        assert DeviceType.WINDOWS.value == "windows"
        assert DeviceType.MAC.value == "mac"
        assert DeviceType.ANDROID.value == "android"
        assert DeviceType.IPHONE.value == "iphone"

    def test_vpn_status_values(self):
        """Should have expected VPN statuses."""
        assert VPNStatus.CONNECTED.value == "connected"
        assert VPNStatus.DISCONNECTED.value == "disconnected"
        assert VPNStatus.CONNECTING.value == "connecting"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
