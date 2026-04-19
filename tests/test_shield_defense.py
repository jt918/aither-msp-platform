"""
Tests for Shield Defense - Consumer-Grade Cybersecurity Protection Service
"""

import pytest
from unittest.mock import patch

from services.defense.shield_defense import (
    ShieldDefenseService,
    ProtectionStatus,
    ThreatCategory,
    ScanType,
    QuarantineStatus,
    FirewallAction,
    DetectedThreat,
    ScanResult,
    FirewallRule,
    DeviceProtection,
)


class TestShieldDefenseInitialization:
    """Tests for ShieldDefenseService initialization"""

    def setup_method(self):
        self.shield = ShieldDefenseService()

    def test_initialization_creates_instance(self):
        """Test service initializes without error"""
        assert self.shield is not None

    def test_seed_devices_loaded(self):
        """Test that demonstration devices are seeded on init"""
        assert len(self.shield.devices) == 3
        assert "DEV-001" in self.shield.devices
        assert "DEV-002" in self.shield.devices
        assert "DEV-003" in self.shield.devices

    def test_seed_device_properties(self):
        """Test seed devices have correct properties"""
        dev = self.shield.devices["DEV-001"]
        assert dev.device_name == "Dan's Workstation"
        assert dev.device_type == "desktop"
        assert dev.os == "Windows 11"
        assert dev.status == ProtectionStatus.ACTIVE
        assert dev.owner_id == "user-001"

    def test_definitions_version_set(self):
        """Test threat definitions version is initialized"""
        assert self.shield._definitions_version == "2024.06.150"

    def test_empty_threat_store(self):
        """Test threats dict starts empty"""
        assert len(self.shield.threats) == 0

    def test_empty_scan_store(self):
        """Test scans dict starts empty"""
        assert len(self.shield.scans) == 0

    def test_custom_config(self):
        """Test service accepts custom config"""
        svc = ShieldDefenseService(config={"max_devices": 10})
        assert svc.config["max_devices"] == 10


class TestRegisterDevice:
    """Tests for device registration"""

    def setup_method(self):
        self.shield = ShieldDefenseService()

    def test_register_device_returns_device(self):
        """Test registering a new device returns DeviceProtection"""
        device = self.shield.register_device(
            device_name="Test PC",
            device_type="desktop",
            os="Linux",
            owner_id="user-100",
        )
        assert isinstance(device, DeviceProtection)
        assert device.device_name == "Test PC"
        assert device.device_type == "desktop"
        assert device.os == "Linux"
        assert device.owner_id == "user-100"

    def test_register_device_generates_id(self):
        """Test device ID is auto-generated with DEV- prefix"""
        device = self.shield.register_device(
            device_name="New Device",
            device_type="laptop",
            os="Windows 10",
            owner_id="user-200",
        )
        assert device.device_id.startswith("DEV-")

    def test_register_device_stored(self):
        """Test registered device is stored in devices dict"""
        initial_count = len(self.shield.devices)
        device = self.shield.register_device(
            device_name="Stored Device",
            device_type="phone",
            os="Android 14",
            owner_id="user-300",
        )
        assert len(self.shield.devices) == initial_count + 1
        assert self.shield.devices[device.device_id] is device

    def test_register_device_active_status(self):
        """Test new device starts with ACTIVE status"""
        device = self.shield.register_device(
            device_name="Active Device",
            device_type="tablet",
            os="iPadOS 17",
            owner_id="user-400",
        )
        assert device.status == ProtectionStatus.ACTIVE

    def test_register_device_default_protection_level(self):
        """Test default protection level is standard"""
        device = self.shield.register_device(
            device_name="Std Device",
            device_type="laptop",
            os="macOS 14",
            owner_id="user-500",
        )
        assert device.protection_level == "standard"

    def test_register_device_custom_protection_level(self):
        """Test custom protection level is applied"""
        device = self.shield.register_device(
            device_name="Premium Device",
            device_type="desktop",
            os="Windows 11",
            owner_id="user-600",
            protection_level="premium",
        )
        assert device.protection_level == "premium"


# ========== Scanning Tests ==========

class TestRunScan:
    """Tests for security scanning"""

    def setup_method(self):
        self.shield = ShieldDefenseService()

    def test_scan_existing_device(self):
        """Test scanning an existing device returns success"""
        result = self.shield.run_scan("DEV-001", ScanType.QUICK)
        assert result["success"] is True
        assert result["scan_type"] == "quick"
        assert result["files_scanned"] == 15000

    def test_scan_nonexistent_device(self):
        """Test scanning nonexistent device returns error"""
        result = self.shield.run_scan("DEV-INVALID", ScanType.QUICK)
        assert result["success"] is False
        assert "Device not found" in result["error"]

    def test_scan_generates_id(self):
        """Test scan result has a scan ID"""
        result = self.shield.run_scan("DEV-001", ScanType.FULL)
        assert "scan_id" in result
        assert result["scan_id"].startswith("SCN-")

    def test_scan_stored(self):
        """Test scan result is stored in scans dict"""
        result = self.shield.run_scan("DEV-001", ScanType.QUICK)
        scan_id = result["scan_id"]
        assert scan_id in self.shield.scans
        assert self.shield.scans[scan_id].scan_type == ScanType.QUICK

    def test_full_scan_more_files(self):
        """Test full scan checks more files than quick scan"""
        quick = self.shield.run_scan("DEV-001", ScanType.QUICK)
        full = self.shield.run_scan("DEV-001", ScanType.FULL)
        assert full["files_scanned"] > quick["files_scanned"]

    def test_scan_updates_last_scan(self):
        """Test scanning updates device last_scan timestamp"""
        device = self.shield.devices["DEV-001"]
        old_scan = device.last_scan
        self.shield.run_scan("DEV-001", ScanType.QUICK)
        assert device.last_scan is not None

    def test_memory_scan_type(self):
        """Test memory scan has expected file count"""
        result = self.shield.run_scan("DEV-001", ScanType.MEMORY)
        assert result["files_scanned"] == 2000


# ========== Threat Management Tests ==========

class TestThreatManagement:
    """Tests for threat quarantine and deletion"""

    def setup_method(self):
        self.shield = ShieldDefenseService()
        # Create a threat manually for testing
        self.threat = self.shield._create_threat(
            "DEV-001", "Test.Malware", ThreatCategory.MALWARE, "high"
        )

    def test_quarantine_threat_success(self):
        """Test quarantining an existing threat"""
        result = self.shield.quarantine_threat("DEV-001", self.threat.threat_id)
        assert result["success"] is True
        assert result["status"] == "quarantined"

    def test_quarantine_nonexistent_threat(self):
        """Test quarantining a nonexistent threat returns error"""
        result = self.shield.quarantine_threat("DEV-001", "THR-INVALID")
        assert result["success"] is False
        assert "Threat not found" in result["error"]

    def test_quarantine_wrong_device(self):
        """Test quarantining a threat on the wrong device returns error"""
        result = self.shield.quarantine_threat("DEV-002", self.threat.threat_id)
        assert result["success"] is False
        assert "does not belong" in result["error"]

    def test_delete_threat_success(self):
        """Test permanently deleting a threat"""
        result = self.shield.delete_threat(self.threat.threat_id)
        assert result["success"] is True
        assert result["status"] == "deleted"
        assert self.shield.threats[self.threat.threat_id].quarantine_status == QuarantineStatus.DELETED

    def test_delete_threat_sets_resolved_at(self):
        """Test deleting a threat sets resolved_at timestamp"""
        self.shield.delete_threat(self.threat.threat_id)
        assert self.shield.threats[self.threat.threat_id].resolved_at is not None

    def test_delete_nonexistent_threat(self):
        """Test deleting a nonexistent threat returns error"""
        result = self.shield.delete_threat("THR-INVALID")
        assert result["success"] is False

    def test_create_threat_increments_blocked_count(self):
        """Test creating a threat increments device threats_blocked"""
        device = self.shield.devices["DEV-001"]
        old_count = device.threats_blocked
        self.shield._create_threat("DEV-001", "Another.Threat", ThreatCategory.SPYWARE, "medium")
        assert device.threats_blocked == old_count + 1


# ========== Definition Updates Tests ==========

class TestUpdateDefinitions:
    """Tests for threat definition updates"""

    def setup_method(self):
        self.shield = ShieldDefenseService()

    def test_update_definitions_success(self):
        """Test definitions update returns success"""
        result = self.shield.update_definitions()
        assert result["success"] is True

    def test_update_definitions_increments_version(self):
        """Test version number increments after update"""
        old_version = self.shield._definitions_version
        result = self.shield.update_definitions()
        assert result["new_version"] != old_version
        assert result["previous_version"] == old_version

    def test_update_definitions_propagates_to_devices(self):
        """Test updated version propagates to online devices"""
        result = self.shield.update_definitions()
        new_version = result["new_version"]
        for device in self.shield.devices.values():
            if device.status != ProtectionStatus.OFFLINE:
                assert device.definitions_version == new_version

    def test_update_definitions_skips_offline_devices(self):
        """Test offline devices are not updated"""
        self.shield.devices["DEV-001"].status = ProtectionStatus.OFFLINE
        result = self.shield.update_definitions()
        assert self.shield.devices["DEV-001"].definitions_version != result["new_version"]
        assert result["devices_updated"] == 2

    def test_update_definitions_returns_updated_count(self):
        """Test result includes count of updated devices"""
        result = self.shield.update_definitions()
        assert result["devices_updated"] == 3


# ========== Dashboard Tests ==========

class TestThreatDashboard:
    """Tests for threat dashboard aggregation"""

    def setup_method(self):
        self.shield = ShieldDefenseService()

    def test_dashboard_structure(self):
        """Test dashboard returns expected keys"""
        dashboard = self.shield.get_threat_dashboard()
        assert "total_threats_detected" in dashboard
        assert "active_quarantined" in dashboard
        assert "threats_by_category" in dashboard
        assert "threats_by_severity" in dashboard
        assert "devices_total" in dashboard
        assert "devices_online" in dashboard
        assert "definitions_version" in dashboard
        assert "scans_completed" in dashboard
        assert "timestamp" in dashboard

    def test_dashboard_empty_threats(self):
        """Test dashboard with no threats detected"""
        dashboard = self.shield.get_threat_dashboard()
        assert dashboard["total_threats_detected"] == 0
        assert dashboard["active_quarantined"] == 0

    def test_dashboard_with_threats(self):
        """Test dashboard reflects created threats"""
        self.shield._create_threat("DEV-001", "Test.Malware", ThreatCategory.MALWARE, "high")
        self.shield._create_threat("DEV-002", "Test.Spyware", ThreatCategory.SPYWARE, "medium")
        dashboard = self.shield.get_threat_dashboard()
        assert dashboard["total_threats_detected"] == 2
        assert dashboard["threats_by_category"]["malware"] == 1
        assert dashboard["threats_by_category"]["spyware"] == 1

    def test_dashboard_devices_online_count(self):
        """Test online device count on dashboard"""
        dashboard = self.shield.get_threat_dashboard()
        assert dashboard["devices_online"] == 3
        assert dashboard["devices_total"] == 3


# ========== Firewall Tests ==========

class TestFirewallConfiguration:
    """Tests for firewall rule management"""

    def setup_method(self):
        self.shield = ShieldDefenseService()

    def test_configure_firewall_success(self):
        """Test applying firewall rules to a device"""
        result = self.shield.configure_firewall("DEV-001", [
            {"name": "Block SSH", "direction": "inbound", "protocol": "tcp", "port": "22", "action": "block"},
        ])
        assert result["success"] is True
        assert result["rules_applied"] == 1

    def test_configure_firewall_nonexistent_device(self):
        """Test firewall config on nonexistent device"""
        result = self.shield.configure_firewall("DEV-INVALID", [
            {"name": "Rule", "direction": "inbound", "protocol": "tcp", "action": "block"},
        ])
        assert result["success"] is False

    def test_configure_firewall_multiple_rules(self):
        """Test applying multiple firewall rules"""
        rules = [
            {"name": "Block SSH", "direction": "inbound", "protocol": "tcp", "port": "22", "action": "block"},
            {"name": "Allow HTTPS", "direction": "outbound", "protocol": "tcp", "port": "443", "action": "allow"},
        ]
        result = self.shield.configure_firewall("DEV-001", rules)
        assert result["rules_applied"] == 2
        assert len(result["rule_ids"]) == 2


# ========== Security Report Tests ==========

class TestSecurityReport:
    """Tests for device security report generation"""

    def setup_method(self):
        self.shield = ShieldDefenseService()

    def test_generate_report_structure(self):
        """Test report has expected structure"""
        report = self.shield.generate_security_report("DEV-001")
        assert "device" in report
        assert "threats" in report
        assert "scans" in report
        assert "firewall" in report

    def test_generate_report_nonexistent_device(self):
        """Test report for nonexistent device returns error"""
        report = self.shield.generate_security_report("DEV-INVALID")
        assert "error" in report

    def test_report_device_info(self):
        """Test report contains correct device info"""
        report = self.shield.generate_security_report("DEV-001")
        assert report["device"]["name"] == "Dan's Workstation"
        assert report["device"]["type"] == "desktop"


# ========== Health Status Tests ==========

class TestHealthStatus:
    """Tests for overall health status"""

    def setup_method(self):
        self.shield = ShieldDefenseService()

    def test_health_status_healthy(self):
        """Test health status is healthy with all devices active"""
        status = self.shield.get_health_status()
        assert status["health_score"] >= 0.8
        assert status["status"] == "healthy"
        assert status["total_devices"] == 3
        assert status["active_protection"] == 3

    def test_health_score_degrades_with_offline_devices(self):
        """Test health score degrades when devices go offline"""
        self.shield.devices["DEV-001"].status = ProtectionStatus.OFFLINE
        self.shield.devices["DEV-002"].status = ProtectionStatus.OFFLINE
        status = self.shield.get_health_status()
        assert status["health_score"] < 1.0
        assert status["offline_devices"] == 2


# ========== Enum Tests ==========

class TestEnums:
    """Tests for enum values"""

    def test_protection_status_values(self):
        assert ProtectionStatus.ACTIVE.value == "active"
        assert ProtectionStatus.DEGRADED.value == "degraded"
        assert ProtectionStatus.OFFLINE.value == "offline"

    def test_threat_category_values(self):
        assert ThreatCategory.MALWARE.value == "malware"
        assert ThreatCategory.RANSOMWARE.value == "ransomware"
        assert ThreatCategory.PHISHING.value == "phishing"

    def test_scan_type_values(self):
        assert ScanType.QUICK.value == "quick"
        assert ScanType.FULL.value == "full"
        assert ScanType.MEMORY.value == "memory"

    def test_quarantine_status_values(self):
        assert QuarantineStatus.QUARANTINED.value == "quarantined"
        assert QuarantineStatus.DELETED.value == "deleted"
        assert QuarantineStatus.RESTORED.value == "restored"
        assert QuarantineStatus.PENDING.value == "pending"
