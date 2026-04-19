"""
Tests for Network Discovery Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.network_discovery import (
    NetworkDiscoveryService,
    DeviceType,
    ScanStatus,
    ScanType,
    DiscoveredDevice,
    DiscoveryScan,
    classify_device,
    lookup_vendor,
    SNMP_OIDS,
    VENDOR_OUI,
)


class TestNetworkDiscoveryService:
    """Tests for NetworkDiscoveryService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = NetworkDiscoveryService()

    # ========== Device Classification Tests ==========

    def test_classify_switch(self):
        """Test switch classification"""
        assert classify_device("Cisco Catalyst 2960 Switch") == DeviceType.SWITCH
        assert classify_device("HP ProCurve 2530") == DeviceType.SWITCH
        assert classify_device("UniFi Switch 24 PoE") == DeviceType.SWITCH

    def test_classify_router(self):
        """Test router classification"""
        assert classify_device("Cisco ISR 4331 Router") == DeviceType.ROUTER
        assert classify_device("Ubiquiti EdgeRouter X") == DeviceType.ROUTER
        assert classify_device("MikroTik RouterOS") == DeviceType.ROUTER

    def test_classify_access_point(self):
        """Test AP classification"""
        assert classify_device("UniFi AP AC Pro") == DeviceType.ACCESS_POINT
        assert classify_device("Cisco Aironet 2802i Wireless") == DeviceType.ACCESS_POINT
        assert classify_device("Aruba AP-305") == DeviceType.ACCESS_POINT

    def test_classify_printer(self):
        """Test printer classification"""
        assert classify_device("HP LaserJet Pro M404n") == DeviceType.PRINTER
        assert classify_device("Brother HL-L2350DW Printer") == DeviceType.PRINTER
        assert classify_device("Kyocera ECOSYS M2540dn") == DeviceType.PRINTER

    def test_classify_ups(self):
        """Test UPS classification"""
        assert classify_device("APC Smart-UPS 1500") == DeviceType.UPS
        assert classify_device("Eaton 5PX UPS") == DeviceType.UPS
        assert classify_device("CyberPower Uninterruptible Power") == DeviceType.UPS

    def test_classify_firewall(self):
        """Test firewall classification"""
        assert classify_device("Fortinet FortiGate 60F") == DeviceType.FIREWALL
        assert classify_device("pfSense Firewall") == DeviceType.FIREWALL
        assert classify_device("Palo Alto PA-220") == DeviceType.FIREWALL

    def test_classify_server(self):
        """Test server classification"""
        assert classify_device("Dell PowerEdge R740") == DeviceType.SERVER
        assert classify_device("VMware ESXi 7.0") == DeviceType.SERVER
        assert classify_device("Windows Server 2022") == DeviceType.SERVER

    def test_classify_unknown(self):
        """Test unknown device classification"""
        assert classify_device("") == DeviceType.UNKNOWN
        assert classify_device("Some Random Device") == DeviceType.UNKNOWN

    def test_classify_with_vendor_model(self):
        """Test classification using vendor and model fields"""
        assert classify_device("", vendor="Fortinet", model="FortiGate-60F") == DeviceType.FIREWALL
        assert classify_device("", vendor="HP", model="LaserJet") == DeviceType.PRINTER

    # ========== Vendor OUI Lookup Tests ==========

    def test_lookup_vendor_cisco(self):
        """Test Cisco MAC lookup"""
        assert lookup_vendor("00:00:0C:11:22:33") == "Cisco"

    def test_lookup_vendor_ubiquiti(self):
        """Test Ubiquiti MAC lookup"""
        assert lookup_vendor("00:1A:4A:11:22:33") == "Ubiquiti"

    def test_lookup_vendor_hp(self):
        """Test HP MAC lookup"""
        assert lookup_vendor("00:17:A4:11:22:33") == "HP"

    def test_lookup_vendor_dell(self):
        """Test Dell MAC lookup"""
        assert lookup_vendor("A4:1F:72:11:22:33") == "Dell"

    def test_lookup_vendor_vmware(self):
        """Test VMware MAC lookup"""
        assert lookup_vendor("00:50:56:11:22:33") == "VMware"

    def test_lookup_vendor_unknown(self):
        """Test unknown vendor"""
        assert lookup_vendor("FF:FF:FF:11:22:33") == ""

    def test_lookup_vendor_empty(self):
        """Test empty MAC"""
        assert lookup_vendor("") == ""

    def test_lookup_vendor_dash_format(self):
        """Test MAC with dash separators"""
        assert lookup_vendor("00-00-0C-11-22-33") == "Cisco"

    # ========== SNMP OID Tests ==========

    def test_snmp_oids_populated(self):
        """Test that SNMP OID mappings are populated"""
        assert "sysDescr" in SNMP_OIDS
        assert "sysName" in SNMP_OIDS
        assert "sysUpTime" in SNMP_OIDS
        assert "ifTable" in SNMP_OIDS
        assert "sysObjectID" in SNMP_OIDS
        assert len(SNMP_OIDS) >= 20

    def test_vendor_oui_populated(self):
        """Test that vendor OUI table is populated"""
        assert len(VENDOR_OUI) >= 20

    # ========== Subnet Parsing Tests ==========

    def test_subnet_hosts_single(self):
        """Test single IP (no CIDR)"""
        hosts = self.service._subnet_hosts("192.168.1.1")
        assert hosts == ["192.168.1.1"]

    def test_subnet_hosts_24(self):
        """Test /24 subnet"""
        hosts = self.service._subnet_hosts("192.168.1.0/24")
        assert len(hosts) == 254
        assert "192.168.1.1" in hosts
        assert "192.168.1.254" in hosts
        assert "192.168.1.0" not in hosts  # network address excluded
        assert "192.168.1.255" not in hosts  # broadcast excluded

    def test_subnet_hosts_28(self):
        """Test /28 subnet"""
        hosts = self.service._subnet_hosts("10.0.0.0/28")
        assert len(hosts) == 14

    # ========== Scan Lifecycle Tests ==========

    def test_start_scan_creates_scan(self):
        """Test that start_scan creates a scan record"""
        # Patch ping_sweep to avoid real network calls
        self.service.ping_sweep = lambda subnet: []
        self.service.arp_scan = lambda iface="": []

        scan = self.service.start_scan("192.168.1.0/24")

        assert scan is not None
        assert scan.scan_id.startswith("SCAN-")
        assert scan.subnet == "192.168.1.0/24"
        assert scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED)
        assert scan.started_at is not None

    def test_start_scan_ping_sweep(self):
        """Test ping sweep scan type"""
        self.service.ping_sweep = lambda subnet: ["192.168.1.1", "192.168.1.2"]
        self.service.arp_scan = lambda iface="": []

        scan = self.service.start_scan(
            "192.168.1.0/24", scan_type=ScanType.PING_SWEEP,
        )

        assert scan.status == ScanStatus.COMPLETED
        assert scan.devices_found == 2

    def test_start_scan_arp_scan(self):
        """Test ARP scan type"""
        self.service.ping_sweep = lambda subnet: []
        self.service.arp_scan = lambda iface="": [
            {"ip": "10.0.0.1", "mac": "00:00:0C:11:22:33"},
            {"ip": "10.0.0.2", "mac": "00:1A:4A:44:55:66"},
        ]

        scan = self.service.start_scan("10.0.0.0/24", scan_type=ScanType.ARP_SCAN)

        assert scan.status == ScanStatus.COMPLETED
        assert scan.devices_found == 2

    def test_get_scan_status(self):
        """Test retrieving scan status"""
        self.service.ping_sweep = lambda subnet: []
        self.service.arp_scan = lambda iface="": []

        scan = self.service.start_scan("192.168.1.0/24")
        fetched = self.service.get_scan_status(scan.scan_id)

        assert fetched is not None
        assert fetched.scan_id == scan.scan_id

    def test_get_scan_status_not_found(self):
        """Test scan not found"""
        result = self.service.get_scan_status("SCAN-INVALID")
        assert result is None

    def test_list_scans(self):
        """Test listing scans"""
        self.service.ping_sweep = lambda subnet: []
        self.service.arp_scan = lambda iface="": []

        self.service.start_scan("192.168.1.0/24")
        self.service.start_scan("10.0.0.0/24")

        scans = self.service.list_scans()
        assert len(scans) == 2

    # ========== Device CRUD Tests ==========

    def test_create_device_via_scan(self):
        """Test device creation through scan"""
        self.service.ping_sweep = lambda subnet: ["192.168.1.1"]
        self.service.arp_scan = lambda iface="": []

        scan = self.service.start_scan(
            "192.168.1.0/24", scan_type=ScanType.PING_SWEEP,
        )

        devices = self.service.get_devices()
        assert len(devices) >= 1
        dev = devices[0]
        assert dev.ip == "192.168.1.1"
        assert dev.device_id.startswith("ND-")

    def test_get_device_by_id(self):
        """Test get device by ID"""
        self.service.ping_sweep = lambda subnet: ["192.168.1.50"]
        self.service.arp_scan = lambda iface="": []

        self.service.start_scan("192.168.1.0/24", scan_type=ScanType.PING_SWEEP)

        devices = self.service.get_devices()
        assert len(devices) >= 1

        fetched = self.service.get_device_by_id(devices[0].device_id)
        assert fetched is not None
        assert fetched.ip == "192.168.1.50"

    def test_get_device_not_found(self):
        """Test device not found"""
        result = self.service.get_device_by_id("ND-INVALID")
        assert result is None

    def test_update_device(self):
        """Test updating a device"""
        self.service.ping_sweep = lambda subnet: ["192.168.1.1"]
        self.service.arp_scan = lambda iface="": []

        self.service.start_scan("192.168.1.0/24", scan_type=ScanType.PING_SWEEP)
        devices = self.service.get_devices()
        dev_id = devices[0].device_id

        updated = self.service.update_device(
            dev_id,
            hostname="core-switch-01",
            device_type="switch",
            notes="Main distribution switch",
            tags=["core", "critical"],
        )

        assert updated is not None
        assert updated.hostname == "core-switch-01"
        assert updated.device_type == DeviceType.SWITCH
        assert updated.notes == "Main distribution switch"
        assert "core" in updated.tags
        assert updated.updated_at is not None

    def test_update_device_not_found(self):
        """Test update non-existent device"""
        result = self.service.update_device("ND-INVALID", hostname="test")
        assert result is None

    def test_delete_device(self):
        """Test deleting a device"""
        self.service.ping_sweep = lambda subnet: ["192.168.1.1"]
        self.service.arp_scan = lambda iface="": []

        self.service.start_scan("192.168.1.0/24", scan_type=ScanType.PING_SWEEP)
        devices = self.service.get_devices()
        dev_id = devices[0].device_id

        result = self.service.delete_device(dev_id)
        assert result is True

        fetched = self.service.get_device_by_id(dev_id)
        assert fetched is None

    def test_delete_device_not_found(self):
        """Test delete non-existent device"""
        result = self.service.delete_device("ND-INVALID")
        assert result is False

    # ========== Device Filtering Tests ==========

    def test_filter_devices_by_type(self):
        """Test filtering devices by type"""
        self.service.ping_sweep = lambda subnet: ["192.168.1.1", "192.168.1.2"]
        self.service.arp_scan = lambda iface="": []

        self.service.start_scan("192.168.1.0/24", scan_type=ScanType.PING_SWEEP)

        # Update one to be a switch
        devices = self.service.get_devices()
        self.service.update_device(devices[0].device_id, device_type="switch")

        switches = self.service.get_devices(device_type=DeviceType.SWITCH)
        assert len(switches) == 1

    def test_filter_devices_by_vendor(self):
        """Test filtering devices by vendor"""
        # Create device with known vendor MAC
        self.service._create_or_update_device(
            ip="192.168.1.1", mac="00:00:0C:11:22:33",
        )
        self.service._create_or_update_device(
            ip="192.168.1.2", mac="00:1A:4A:44:55:66",
        )

        cisco_devices = self.service.get_devices(vendor="Cisco")
        assert len(cisco_devices) == 1
        assert cisco_devices[0].vendor == "Cisco"

    # ========== SNMP Enrichment Tests ==========

    def test_snmp_walk_simulated(self):
        """Test SNMP walk returns simulated data when pysnmp unavailable"""
        data = self.service.snmp_walk("192.168.1.1")
        assert "sysDescr" in data
        assert "sysName" in data
        assert "sysUpTime" in data

    def test_enrich_device_with_snmp(self):
        """Test device enrichment with SNMP data"""
        self.service._create_or_update_device(ip="192.168.1.1")

        snmp_data = {
            "sysDescr": "Cisco Catalyst 2960 Switch",
            "sysName": "core-sw-01",
            "sysUpTime": "1234567",
            "sysLocation": "Server Room A",
            "sysContact": "admin@example.com",
            "sysObjectID": "1.3.6.1.4.1.9.1.1208",
            "ifNumber": "48",
        }

        self.service._enrich_device("192.168.1.1", snmp_data)

        device = self.service._find_device_by_ip("192.168.1.1")
        assert device is not None
        assert device.sys_descr == "Cisco Catalyst 2960 Switch"
        assert device.hostname == "core-sw-01"
        assert device.location == "Server Room A"
        assert device.contact == "admin@example.com"
        assert device.interface_count == 48
        assert device.uptime == 12345  # hundredths -> seconds
        assert device.device_type == DeviceType.SWITCH

    def test_snmp_walk_device(self):
        """Test SNMP walk on specific device"""
        self.service._create_or_update_device(ip="192.168.1.1")
        devices = self.service.get_devices()
        dev_id = devices[0].device_id

        result = self.service.snmp_walk_device(dev_id)
        assert result["success"] is True
        assert result["device_id"] == dev_id
        assert "data" in result

    def test_snmp_walk_device_not_found(self):
        """Test SNMP walk on non-existent device"""
        result = self.service.snmp_walk_device("ND-INVALID")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    # ========== Topology Tests ==========

    def test_topology_map_empty(self):
        """Test topology map with no devices"""
        topo = self.service.get_topology_map()
        assert topo["total_devices"] == 0
        assert topo["nodes"] == []
        assert topo["edges"] == []

    def test_topology_map_with_devices(self):
        """Test topology map generation"""
        self.service._create_or_update_device(ip="192.168.1.1", mac="00:00:0C:11:22:33")
        self.service._create_or_update_device(ip="192.168.1.2", mac="00:17:A4:44:55:66")
        self.service._create_or_update_device(ip="192.168.1.3", mac="A4:1F:72:77:88:99")

        # Make one a switch so topology infers edges
        devices = self.service.get_devices()
        self.service.update_device(devices[0].device_id, device_type="switch")

        topo = self.service.get_topology_map()
        assert topo["total_devices"] == 3
        assert len(topo["nodes"]) == 3
        # Should infer edges from switch to other devices
        assert topo["total_connections"] >= 2

    def test_topology_subnets(self):
        """Test topology subnet grouping"""
        self.service._create_or_update_device(ip="192.168.1.1")
        self.service._create_or_update_device(ip="192.168.1.2")
        self.service._create_or_update_device(ip="10.0.0.1")

        topo = self.service.get_topology_map()
        assert len(topo["subnets"]) == 2
        assert "192.168.1" in topo["subnets"]
        assert "10.0.0" in topo["subnets"]

    # ========== Dashboard Tests ==========

    def test_dashboard_empty(self):
        """Test dashboard with no data"""
        dash = self.service.get_dashboard()
        assert dash["total_devices"] == 0
        assert dash["online_devices"] == 0
        assert dash["total_scans"] == 0
        assert dash["last_scan"] is None

    def test_dashboard_with_data(self):
        """Test dashboard with devices and scans"""
        self.service.ping_sweep = lambda subnet: ["192.168.1.1", "192.168.1.2"]
        self.service.arp_scan = lambda iface="": []

        self.service.start_scan("192.168.1.0/24", scan_type=ScanType.PING_SWEEP)

        # Update one device type
        devices = self.service.get_devices()
        self.service.update_device(devices[0].device_id, device_type="switch")

        dash = self.service.get_dashboard()
        assert dash["total_devices"] == 2
        assert dash["online_devices"] == 2  # just created, should be within 10 min window
        assert dash["total_scans"] >= 1
        assert dash["completed_scans"] >= 1
        assert dash["last_scan"] is not None
        assert "switch" in dash["device_types"]

    def test_dashboard_vendor_counts(self):
        """Test dashboard vendor distribution"""
        self.service._create_or_update_device(ip="192.168.1.1", mac="00:00:0C:11:22:33")
        self.service._create_or_update_device(ip="192.168.1.2", mac="00:00:0C:44:55:66")
        self.service._create_or_update_device(ip="192.168.1.3", mac="00:1A:4A:77:88:99")

        dash = self.service.get_dashboard()
        assert "Cisco" in dash["top_vendors"]
        assert dash["top_vendors"]["Cisco"] == 2
        assert "Ubiquiti" in dash["top_vendors"]

    # ========== ARP Scan Tests ==========

    def test_arp_scan_returns_list(self):
        """Test ARP scan returns list (may be empty if no ARP table)"""
        entries = self.service.arp_scan()
        assert isinstance(entries, list)

    # ========== Device De-duplication Tests ==========

    def test_device_dedup_by_ip(self):
        """Test that same IP doesn't create duplicate devices"""
        self.service._create_or_update_device(ip="192.168.1.1")
        self.service._create_or_update_device(ip="192.168.1.1")

        devices = self.service.get_devices()
        ips = [d.ip for d in devices if d.ip == "192.168.1.1"]
        assert len(ips) == 1

    def test_device_mac_updated_on_rediscovery(self):
        """Test that MAC is updated when device is rediscovered"""
        self.service._create_or_update_device(ip="192.168.1.1")
        self.service._create_or_update_device(
            ip="192.168.1.1", mac="00:00:0C:11:22:33",
        )

        device = self.service._find_device_by_ip("192.168.1.1")
        assert device.mac == "00:00:0C:11:22:33"
        assert device.vendor == "Cisco"

    # ========== Enum Tests ==========

    def test_device_type_enum(self):
        """Test DeviceType enum values"""
        assert DeviceType.SWITCH.value == "switch"
        assert DeviceType.ROUTER.value == "router"
        assert DeviceType.UNKNOWN.value == "unknown"

    def test_scan_status_enum(self):
        """Test ScanStatus enum values"""
        assert ScanStatus.QUEUED.value == "queued"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"

    def test_scan_type_enum(self):
        """Test ScanType enum values"""
        assert ScanType.PING_SWEEP.value == "ping_sweep"
        assert ScanType.SNMP_WALK.value == "snmp_walk"
        assert ScanType.ARP_SCAN.value == "arp_scan"
        assert ScanType.FULL.value == "full"
