"""
AITHER Platform - Network Discovery Service
SNMP-based network device auto-discovery and classification

Provides:
- Subnet scanning via ping sweep
- SNMP device interrogation (v1/v2c/v3)
- ARP table scanning
- Automatic device classification (switch, router, AP, printer, UPS, etc.)
- Vendor identification via OUI lookup
- Network topology mapping
- Device inventory management

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import asyncio
import socket
import struct
import subprocess
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set
from enum import Enum

try:
    from pysnmp.hlapi import (
        getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
    )
    PYSNMP_AVAILABLE = True
except Exception:
    PYSNMP_AVAILABLE = False

try:
    from sqlalchemy.orm import Session
    from models.msp import (
        NetworkDevice as NetworkDeviceModel,
        NetworkScan as NetworkScanModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class DeviceType(str, Enum):
    """Network device type classification"""
    SWITCH = "switch"
    ROUTER = "router"
    ACCESS_POINT = "access_point"
    PRINTER = "printer"
    UPS = "ups"
    FIREWALL = "firewall"
    SERVER = "server"
    WORKSTATION = "workstation"
    IP_PHONE = "ip_phone"
    CAMERA = "camera"
    NAS = "nas"
    UNKNOWN = "unknown"


class ScanStatus(str, Enum):
    """Discovery scan status"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    """Discovery scan type"""
    PING_SWEEP = "ping_sweep"
    SNMP_WALK = "snmp_walk"
    ARP_SCAN = "arp_scan"
    FULL = "full"


# ============================================================
# SNMP OID Mappings
# ============================================================

SNMP_OIDS = {
    # System group (RFC 1213)
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysServices": "1.3.6.1.2.1.1.7.0",

    # Interface table
    "ifNumber": "1.3.6.1.2.1.2.1.0",
    "ifTable": "1.3.6.1.2.1.2.2",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",

    # IP address table
    "ipAddrTable": "1.3.6.1.2.1.4.20",

    # ARP / Net-to-media table
    "ipNetToMediaTable": "1.3.6.1.2.1.4.22",

    # Entity MIB
    "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
    "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
    "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    "entPhysicalFirmwareRev": "1.3.6.1.2.1.47.1.1.1.1.9",

    # Printer MIB
    "prtGeneralPrinterName": "1.3.6.1.2.1.43.5.1.1.16",
    "prtMarkerSuppliesLevel": "1.3.6.1.2.1.43.11.1.1.9",

    # UPS MIB (RFC 1628)
    "upsBatteryStatus": "1.3.6.1.2.1.33.1.2.1.0",
    "upsBatteryTimeRemaining": "1.3.6.1.2.1.33.1.2.3.0",
    "upsOutputVoltage": "1.3.6.1.2.1.33.1.4.4.1.2",

    # LLDP
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",

    # CDP (Cisco)
    "cdpCacheDeviceId": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
    "cdpCachePlatform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8",
}


# ============================================================
# Vendor OUI Lookup (first 3 octets of MAC -> vendor)
# ============================================================

VENDOR_OUI = {
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:1A:A1": "Cisco",
    "00:1B:54": "Cisco", "00:50:56": "VMware", "00:0C:29": "VMware",
    "00:15:5D": "Microsoft", "00:1A:4A": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "24:5A:4C": "Ubiquiti", "DC:9F:DB": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "00:1E:58": "D-Link", "00:26:5A": "D-Link", "28:10:7B": "D-Link",
    "00:1A:1E": "Aruba", "00:0B:86": "Aruba", "24:DE:C6": "Aruba",
    "00:17:A4": "HP", "3C:D9:2B": "HP", "00:1E:0B": "HP",
    "A4:1F:72": "Dell", "00:14:22": "Dell", "18:A9:05": "Dell",
    "00:1C:B3": "Apple", "F0:18:98": "Apple", "AC:BC:32": "Apple",
    "D8:9E:F3": "Fortinet", "00:09:0F": "Fortinet", "70:4C:A5": "Fortinet",
    "00:23:69": "Juniper", "00:05:85": "Juniper", "28:8A:1C": "Juniper",
    "00:26:F2": "Netgear", "C0:FF:D4": "Netgear", "28:C6:8E": "Netgear",
    "EC:08:6B": "TP-Link", "50:C7:BF": "TP-Link", "14:CC:20": "TP-Link",
    "B4:FB:E4": "Ubiquiti", "00:27:22": "Ubiquiti",
    "00:04:A3": "Eaton", "00:20:85": "Eaton",
    "00:06:DC": "APC", "00:C0:B7": "APC",
    "00:1E:68": "Quanta", "00:80:77": "Brother",
    "00:1B:A9": "Brother", "30:CD:A7": "Brother",
    "00:00:48": "Epson", "00:26:AB": "Epson",
    "00:17:C8": "Kyocera", "00:C0:EE": "Kyocera",
    "00:00:AA": "Xerox", "00:00:74": "Ricoh",
    "3C:2A:F4": "Brother", "00:1F:3A": "Dell",
    "00:25:B3": "Hewlett Packard", "38:63:BB": "Hewlett Packard Enterprise",
    "00:1C:C4": "Hewlett Packard", "EC:B1:D7": "Hewlett Packard",
    "F8:B1:56": "Dell", "00:22:19": "Dell",
    "F0:9F:C2": "Ubiquiti", "00:50:C2": "IEEE",
    "B0:BE:76": "TP-Link", "60:A4:4C": "TP-Link",
    "00:03:2D": "IBASE", "00:A0:C9": "Intel",
    "8C:DC:D4": "Intel", "00:1B:21": "Intel",
}


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class DiscoveredDevice:
    """A discovered network device"""
    device_id: str
    ip: str
    mac: str = ""
    hostname: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    vendor: str = ""
    model: str = ""
    firmware_version: str = ""
    serial_number: str = ""
    snmp_community: str = ""
    ports_open: List[int] = field(default_factory=list)
    uptime: int = 0  # seconds
    location: str = ""
    contact: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    interface_count: int = 0
    neighbors: List[str] = field(default_factory=list)  # neighbor device_ids
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    scan_id: str = ""
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class DiscoveryScan:
    """A network discovery scan"""
    scan_id: str
    subnet: str
    scan_type: ScanType = ScanType.FULL
    status: ScanStatus = ScanStatus.QUEUED
    community: str = "public"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    devices_found: int = 0
    error: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _device_from_row(row) -> DiscoveredDevice:
    """Convert NetworkDeviceModel row to DiscoveredDevice dataclass."""
    return DiscoveredDevice(
        device_id=row.device_id,
        ip=row.ip_address,
        mac=row.mac_address or "",
        hostname=row.hostname or "",
        device_type=DeviceType(row.device_type) if row.device_type else DeviceType.UNKNOWN,
        vendor=row.vendor or "",
        model=row.model or "",
        firmware_version=row.firmware_version or "",
        serial_number=row.serial_number or "",
        snmp_community=row.snmp_community or "",
        ports_open=row.ports_open or [],
        uptime=row.uptime or 0,
        location=row.location or "",
        contact=row.contact or "",
        sys_descr=row.sys_descr or "",
        sys_object_id=row.sys_object_id or "",
        interface_count=row.interface_count or 0,
        neighbors=row.neighbors or [],
        tags=row.tags or [],
        notes=row.notes or "",
        scan_id=row.scan_id or "",
        first_seen=row.first_seen or datetime.now(timezone.utc),
        last_seen=row.last_seen or datetime.now(timezone.utc),
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _scan_from_row(row) -> DiscoveryScan:
    """Convert NetworkScanModel row to DiscoveryScan dataclass."""
    return DiscoveryScan(
        scan_id=row.scan_id,
        subnet=row.subnet,
        scan_type=ScanType(row.scan_type) if row.scan_type else ScanType.FULL,
        status=ScanStatus(row.status) if row.status else ScanStatus.QUEUED,
        community=row.community or "public",
        started_at=row.started_at,
        completed_at=row.completed_at,
        devices_found=row.devices_found or 0,
        error=row.error or "",
        created_at=row.created_at or datetime.now(timezone.utc),
    )


# ============================================================
# Device Classification Logic
# ============================================================

# sysDescr keywords -> DeviceType mapping
_CLASSIFICATION_KEYWORDS = {
    DeviceType.SWITCH: [
        "switch", "catalyst", "nexus", "procurve", "aruba cx",
        "powerconnect", "unifi switch", "edgeswitch",
    ],
    DeviceType.ROUTER: [
        "router", "isr", "asr", "edgerouter", "routeros", "mikrotik",
        "vyos", "vyatta",
    ],
    DeviceType.ACCESS_POINT: [
        "access point", "wireless", "wap", "unifi ap", "aruba ap",
        "aironet", "ruckus",
    ],
    DeviceType.PRINTER: [
        "printer", "laserjet", "officejet", "pagewide", "brother",
        "kyocera", "ricoh", "xerox", "canon imagerunner", "epson",
    ],
    DeviceType.UPS: [
        "ups", "smart-ups", "symmetra", "eaton", "apc", "cyberpower",
        "liebert", "uninterruptible",
    ],
    DeviceType.FIREWALL: [
        "firewall", "fortigate", "pfsense", "opnsense", "asa",
        "sonicwall", "watchguard", "palo alto", "sophos",
    ],
    DeviceType.SERVER: [
        "server", "poweredge", "proliant", "esxi", "vmware",
        "hyper-v", "linux", "windows server",
    ],
    DeviceType.IP_PHONE: [
        "phone", "voip", "sip", "polycom", "yealink", "cisco ip phone",
    ],
    DeviceType.CAMERA: [
        "camera", "ipcam", "hikvision", "dahua", "axis", "surveillance",
    ],
    DeviceType.NAS: [
        "nas", "synology", "qnap", "netapp", "freenas", "truenas",
    ],
}


def classify_device(sys_descr: str, vendor: str = "", model: str = "") -> DeviceType:
    """Classify a device based on its SNMP sysDescr, vendor, and model."""
    text = f"{sys_descr} {vendor} {model}".lower()
    for dtype, keywords in _CLASSIFICATION_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                return dtype
    return DeviceType.UNKNOWN


def lookup_vendor(mac: str) -> str:
    """Look up vendor from MAC address OUI prefix."""
    if not mac:
        return ""
    # Normalise to colon-separated uppercase
    clean = mac.upper().replace("-", ":").replace(".", ":")
    # Handle xxxx.xxxx.xxxx Cisco format
    if len(clean) == 14 and ":" not in clean:
        clean = ":".join([clean[i:i+2] for i in range(0, 12, 2)])
    prefix = ":".join(clean.split(":")[:3])
    return VENDOR_OUI.get(prefix, "")


# ============================================================
# Service
# ============================================================

class NetworkDiscoveryService:
    """
    Network Discovery Service - SNMP-based device auto-discovery

    Scans network subnets to discover and classify devices such as
    switches, routers, APs, printers, UPS units, firewalls, and servers.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: Session = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._devices: Dict[str, DiscoveredDevice] = {}
        self._scans: Dict[str, DiscoveryScan] = {}

        # Default SNMP communities to try
        self._default_communities = ["public", "private"]

        # Common ports to probe
        self._probe_ports = [22, 23, 80, 443, 161, 162, 8080, 8443, 9100]

    # ========== Scanning Methods ==========

    def start_scan(
        self,
        subnet: str,
        scan_type: ScanType = ScanType.FULL,
        community: str = "public",
    ) -> DiscoveryScan:
        """Start a network discovery scan."""
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        scan = DiscoveryScan(
            scan_id=scan_id,
            subnet=subnet,
            scan_type=scan_type,
            status=ScanStatus.RUNNING,
            community=community,
            started_at=now,
        )

        self._scans[scan_id] = scan

        if self._use_db:
            try:
                row = NetworkScanModel(
                    scan_id=scan_id,
                    subnet=subnet,
                    scan_type=scan_type.value,
                    status=ScanStatus.RUNNING.value,
                    community=community,
                    started_at=now,
                    devices_found=0,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating scan: {e}")
                self.db.rollback()

        # Execute the scan synchronously (in production this would be async)
        try:
            devices = self._execute_scan(scan)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.devices_found = len(devices)
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            scan.error = str(e)

        self._scans[scan_id] = scan

        if self._use_db:
            try:
                row = self.db.query(NetworkScanModel).filter(
                    NetworkScanModel.scan_id == scan_id
                ).first()
                if row:
                    row.status = scan.status.value
                    row.completed_at = scan.completed_at
                    row.devices_found = scan.devices_found
                    row.error = scan.error
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating scan: {e}")
                self.db.rollback()

        return scan

    def _execute_scan(self, scan: DiscoveryScan) -> List[DiscoveredDevice]:
        """Execute the discovery scan based on type."""
        devices: List[DiscoveredDevice] = []

        if scan.scan_type in (ScanType.PING_SWEEP, ScanType.FULL):
            hosts = self.ping_sweep(scan.subnet)
            for ip in hosts:
                dev = self._create_or_update_device(
                    ip=ip, scan_id=scan.scan_id, community=scan.community,
                )
                if dev:
                    devices.append(dev)

        if scan.scan_type in (ScanType.SNMP_WALK, ScanType.FULL):
            # SNMP walk on already-discovered or all subnet hosts
            known_ips = [d.ip for d in devices] if devices else self._subnet_hosts(scan.subnet)
            for ip in known_ips:
                snmp_data = self.snmp_walk(ip, scan.community)
                if snmp_data:
                    self._enrich_device(ip, snmp_data, scan.scan_id)

        if scan.scan_type in (ScanType.ARP_SCAN, ScanType.FULL):
            arp_entries = self.arp_scan()
            for entry in arp_entries:
                dev = self._create_or_update_device(
                    ip=entry["ip"],
                    mac=entry.get("mac", ""),
                    scan_id=scan.scan_id,
                    community=scan.community,
                )
                if dev:
                    devices.append(dev)

        return devices

    def ping_sweep(self, subnet: str) -> List[str]:
        """Ping sweep a subnet and return list of responding IPs."""
        responsive = []
        hosts = self._subnet_hosts(subnet)

        for ip in hosts:
            try:
                # Use system ping with short timeout
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "500", ip],
                    capture_output=True, text=True, timeout=3,
                )
                if result.returncode == 0:
                    responsive.append(ip)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue

        return responsive

    def snmp_walk(self, host: str, community: str = "public") -> Dict[str, Any]:
        """Perform SNMP GET on common OIDs for a host."""
        if not PYSNMP_AVAILABLE:
            logger.debug("pysnmp not available, returning simulated SNMP data")
            return self._simulated_snmp_response(host)

        result: Dict[str, Any] = {}
        target_oids = [
            "sysDescr", "sysName", "sysUpTime", "sysContact",
            "sysLocation", "sysObjectID", "sysServices", "ifNumber",
        ]

        try:
            for oid_name in target_oids:
                oid = SNMP_OIDS.get(oid_name)
                if not oid:
                    continue
                error_indication, error_status, error_index, var_binds = next(
                    getCmd(
                        SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((host, 161), timeout=2, retries=1),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                    )
                )
                if not error_indication and not error_status:
                    for var_bind in var_binds:
                        result[oid_name] = str(var_bind[1])
        except Exception as e:
            logger.debug(f"SNMP walk failed for {host}: {e}")

        return result

    def arp_scan(self, interface: str = "") -> List[Dict[str, str]]:
        """Read ARP table from the local system."""
        entries: List[Dict[str, str]] = []
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,17})", line
                    )
                    if match:
                        entries.append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.debug(f"ARP scan failed: {e}")

        return entries

    def _simulated_snmp_response(self, host: str) -> Dict[str, Any]:
        """Return a simulated SNMP response for testing without pysnmp."""
        return {
            "sysDescr": f"Simulated device at {host}",
            "sysName": f"device-{host.replace('.', '-')}",
            "sysUpTime": "123456789",
            "sysContact": "",
            "sysLocation": "",
            "sysObjectID": "",
            "sysServices": "72",
            "ifNumber": "24",
        }

    def _subnet_hosts(self, subnet: str) -> List[str]:
        """Generate list of host IPs for a subnet (CIDR notation)."""
        if "/" not in subnet:
            return [subnet]

        try:
            network, prefix_len = subnet.rsplit("/", 1)
            prefix_len = int(prefix_len)
            parts = network.split(".")
            base_ip = sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
            host_bits = 32 - prefix_len
            num_hosts = (1 << host_bits) - 2  # exclude network and broadcast
            if num_hosts <= 0 or num_hosts > 1024:
                # Clamp to /22 max to prevent enormous scans
                num_hosts = min(num_hosts, 1022)

            hosts = []
            for i in range(1, num_hosts + 1):
                ip_int = (base_ip & (0xFFFFFFFF << host_bits)) + i
                hosts.append(
                    f"{(ip_int >> 24) & 0xFF}."
                    f"{(ip_int >> 16) & 0xFF}."
                    f"{(ip_int >> 8) & 0xFF}."
                    f"{ip_int & 0xFF}"
                )
            return hosts
        except (ValueError, IndexError):
            return [subnet.split("/")[0]]

    # ========== Device Management ==========

    def _create_or_update_device(
        self, ip: str, scan_id: str = "",
        mac: str = "", community: str = "public",
    ) -> Optional[DiscoveredDevice]:
        """Create a new device or update if already discovered at this IP."""
        # Check if device already exists by IP
        existing = self._find_device_by_ip(ip)
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            if mac and not existing.mac:
                existing.mac = mac
            if not existing.vendor and mac:
                existing.vendor = lookup_vendor(mac)
            self._devices[existing.device_id] = existing
            self._persist_device(existing)
            return existing

        device_id = f"ND-{uuid.uuid4().hex[:8].upper()}"
        vendor = lookup_vendor(mac) if mac else ""

        device = DiscoveredDevice(
            device_id=device_id,
            ip=ip,
            mac=mac,
            hostname=self._resolve_hostname(ip),
            vendor=vendor,
            snmp_community=community,
            scan_id=scan_id,
        )

        self._devices[device_id] = device
        self._persist_device(device, create=True)
        return device

    def _enrich_device(self, ip: str, snmp_data: Dict[str, Any], scan_id: str = "") -> None:
        """Enrich a device record with SNMP data."""
        device = self._find_device_by_ip(ip)
        if not device:
            return

        device.sys_descr = snmp_data.get("sysDescr", "")
        device.hostname = snmp_data.get("sysName", device.hostname) or device.hostname
        device.sys_object_id = snmp_data.get("sysObjectID", "")
        device.location = snmp_data.get("sysLocation", "")
        device.contact = snmp_data.get("sysContact", "")

        try:
            device.interface_count = int(snmp_data.get("ifNumber", 0))
        except (ValueError, TypeError):
            device.interface_count = 0

        try:
            ticks = int(snmp_data.get("sysUpTime", 0))
            device.uptime = ticks // 100  # hundredths of a second -> seconds
        except (ValueError, TypeError):
            device.uptime = 0

        # Classify
        device.device_type = classify_device(
            device.sys_descr, device.vendor, device.model,
        )

        device.last_seen = datetime.now(timezone.utc)
        device.updated_at = datetime.now(timezone.utc)
        self._devices[device.device_id] = device
        self._persist_device(device)

    def _find_device_by_ip(self, ip: str) -> Optional[DiscoveredDevice]:
        """Find device by IP address."""
        for dev in self._devices.values():
            if dev.ip == ip:
                return dev

        if self._use_db:
            try:
                row = self.db.query(NetworkDeviceModel).filter(
                    NetworkDeviceModel.ip_address == ip
                ).first()
                if row:
                    dev = _device_from_row(row)
                    self._devices[dev.device_id] = dev
                    return dev
            except Exception as e:
                logger.error(f"DB error finding device by IP: {e}")

        return None

    def _resolve_hostname(self, ip: str) -> str:
        """Attempt reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    def _persist_device(self, device: DiscoveredDevice, create: bool = False) -> None:
        """Persist device to DB."""
        if not self._use_db:
            return
        try:
            if create:
                row = NetworkDeviceModel(
                    device_id=device.device_id,
                    ip_address=device.ip,
                    mac_address=device.mac,
                    hostname=device.hostname,
                    device_type=device.device_type.value,
                    vendor=device.vendor,
                    model=device.model,
                    firmware_version=device.firmware_version,
                    serial_number=device.serial_number,
                    snmp_community=device.snmp_community,
                    ports_open=device.ports_open,
                    uptime=device.uptime,
                    location=device.location,
                    contact=device.contact,
                    sys_descr=device.sys_descr,
                    sys_object_id=device.sys_object_id,
                    interface_count=device.interface_count,
                    neighbors=device.neighbors,
                    tags=device.tags,
                    notes=device.notes,
                    scan_id=device.scan_id,
                    first_seen=device.first_seen,
                    last_seen=device.last_seen,
                )
                self.db.add(row)
            else:
                row = self.db.query(NetworkDeviceModel).filter(
                    NetworkDeviceModel.device_id == device.device_id
                ).first()
                if row:
                    for attr in [
                        "ip_address", "mac_address", "hostname", "vendor",
                        "model", "firmware_version", "serial_number",
                        "snmp_community", "ports_open", "uptime", "location",
                        "contact", "sys_descr", "sys_object_id",
                        "interface_count", "neighbors", "tags", "notes",
                    ]:
                        db_attr = attr
                        dc_attr = attr
                        if attr == "ip_address":
                            dc_attr = "ip"
                        elif attr == "mac_address":
                            dc_attr = "mac"
                        val = getattr(device, dc_attr, None)
                        if isinstance(val, Enum):
                            val = val.value
                        setattr(row, db_attr, val)
                    row.device_type = device.device_type.value
                    row.last_seen = device.last_seen
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting device: {e}")
            self.db.rollback()

    # ========== Query Methods ==========

    def get_scan_status(self, scan_id: str) -> Optional[DiscoveryScan]:
        """Get scan status by ID."""
        scan = self._scans.get(scan_id)
        if scan:
            return scan

        if self._use_db:
            try:
                row = self.db.query(NetworkScanModel).filter(
                    NetworkScanModel.scan_id == scan_id
                ).first()
                if row:
                    scan = _scan_from_row(row)
                    self._scans[scan_id] = scan
                    return scan
            except Exception as e:
                logger.error(f"DB error getting scan: {e}")

        return None

    def list_scans(self, limit: int = 50) -> List[DiscoveryScan]:
        """List recent scans."""
        if self._use_db:
            try:
                rows = (
                    self.db.query(NetworkScanModel)
                    .order_by(NetworkScanModel.created_at.desc())
                    .limit(limit)
                    .all()
                )
                return [_scan_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing scans: {e}")

        scans = sorted(
            self._scans.values(),
            key=lambda s: s.created_at,
            reverse=True,
        )
        return scans[:limit]

    def get_devices(
        self,
        device_type: Optional[DeviceType] = None,
        vendor: Optional[str] = None,
        subnet: Optional[str] = None,
        limit: int = 200,
    ) -> List[DiscoveredDevice]:
        """Get discovered devices with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(NetworkDeviceModel)
                if device_type:
                    q = q.filter(NetworkDeviceModel.device_type == device_type.value)
                if vendor:
                    q = q.filter(NetworkDeviceModel.vendor.ilike(f"%{vendor}%"))
                if subnet:
                    # simple prefix match
                    prefix = subnet.split("/")[0].rsplit(".", 1)[0]
                    q = q.filter(NetworkDeviceModel.ip_address.like(f"{prefix}.%"))
                rows = q.order_by(NetworkDeviceModel.last_seen.desc()).limit(limit).all()
                return [_device_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing devices: {e}")

        devices = list(self._devices.values())
        if device_type:
            devices = [d for d in devices if d.device_type == device_type]
        if vendor:
            devices = [d for d in devices if vendor.lower() in d.vendor.lower()]
        if subnet:
            prefix = subnet.split("/")[0].rsplit(".", 1)[0]
            devices = [d for d in devices if d.ip.startswith(prefix)]
        return sorted(devices, key=lambda d: d.last_seen, reverse=True)[:limit]

    def get_device_by_id(self, device_id: str) -> Optional[DiscoveredDevice]:
        """Get a device by its ID."""
        device = self._devices.get(device_id)
        if device:
            return device

        if self._use_db:
            try:
                row = self.db.query(NetworkDeviceModel).filter(
                    NetworkDeviceModel.device_id == device_id
                ).first()
                if row:
                    device = _device_from_row(row)
                    self._devices[device_id] = device
                    return device
            except Exception as e:
                logger.error(f"DB error getting device: {e}")

        return None

    def update_device(self, device_id: str, **updates) -> Optional[DiscoveredDevice]:
        """Update device properties (label, type override, notes, tags)."""
        device = self.get_device_by_id(device_id)
        if not device:
            return None

        for key, value in updates.items():
            if key == "device_type" and isinstance(value, str):
                value = DeviceType(value)
            if hasattr(device, key):
                setattr(device, key, value)

        device.updated_at = datetime.now(timezone.utc)
        self._devices[device_id] = device
        self._persist_device(device)
        return device

    def delete_device(self, device_id: str) -> bool:
        """Remove a device from inventory."""
        if device_id not in self._devices:
            # Try loading from DB first
            if not self.get_device_by_id(device_id):
                return False

        self._devices.pop(device_id, None)

        if self._use_db:
            try:
                self.db.query(NetworkDeviceModel).filter(
                    NetworkDeviceModel.device_id == device_id
                ).delete()
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error deleting device: {e}")
                self.db.rollback()

        return True

    # ========== Topology ==========

    def get_topology_map(self) -> Dict[str, Any]:
        """Generate a network topology map from discovered devices."""
        devices = self.get_devices(limit=500)
        nodes = []
        edges = []
        subnets: Dict[str, List[str]] = {}

        for dev in devices:
            nodes.append({
                "id": dev.device_id,
                "label": dev.hostname or dev.ip,
                "ip": dev.ip,
                "type": dev.device_type.value,
                "vendor": dev.vendor,
                "mac": dev.mac,
            })

            # Group by /24 subnet
            prefix = dev.ip.rsplit(".", 1)[0] if "." in dev.ip else dev.ip
            subnets.setdefault(prefix, []).append(dev.device_id)

            # Edges from neighbor list
            for neighbor_id in dev.neighbors:
                edges.append({
                    "source": dev.device_id,
                    "target": neighbor_id,
                    "type": "lldp",
                })

        # Infer edges: within same subnet, core devices connect to others
        core_types = {DeviceType.SWITCH, DeviceType.ROUTER, DeviceType.FIREWALL}
        for prefix, dev_ids in subnets.items():
            cores = [did for did in dev_ids
                     if self._devices.get(did) and self._devices[did].device_type in core_types]
            non_cores = [did for did in dev_ids if did not in cores]
            if cores:
                primary_core = cores[0]
                for nc in non_cores:
                    edges.append({
                        "source": primary_core,
                        "target": nc,
                        "type": "inferred",
                    })
                for c in cores[1:]:
                    edges.append({
                        "source": primary_core,
                        "target": c,
                        "type": "inferred",
                    })

        return {
            "nodes": nodes,
            "edges": edges,
            "subnets": {k: len(v) for k, v in subnets.items()},
            "total_devices": len(nodes),
            "total_connections": len(edges),
        }

    # ========== Dashboard ==========

    def get_dashboard(self) -> Dict[str, Any]:
        """Get discovery dashboard stats."""
        devices = self.get_devices(limit=10000)
        scans = self.list_scans(limit=100)

        type_counts: Dict[str, int] = {}
        vendor_counts: Dict[str, int] = {}
        subnet_counts: Dict[str, int] = {}
        online_count = 0

        for dev in devices:
            t = dev.device_type.value
            type_counts[t] = type_counts.get(t, 0) + 1
            if dev.vendor:
                vendor_counts[dev.vendor] = vendor_counts.get(dev.vendor, 0) + 1
            prefix = dev.ip.rsplit(".", 1)[0] if "." in dev.ip else dev.ip
            subnet_counts[prefix] = subnet_counts.get(prefix, 0) + 1
            # Consider online if seen in last 10 minutes
            if dev.last_seen and (
                datetime.now(timezone.utc) - dev.last_seen
            ) < timedelta(minutes=10):
                online_count += 1

        completed_scans = [s for s in scans if s.status == ScanStatus.COMPLETED]
        last_scan = completed_scans[0] if completed_scans else None

        return {
            "total_devices": len(devices),
            "online_devices": online_count,
            "offline_devices": len(devices) - online_count,
            "device_types": type_counts,
            "top_vendors": dict(
                sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "subnets_scanned": len(subnet_counts),
            "subnet_distribution": subnet_counts,
            "total_scans": len(scans),
            "completed_scans": len(completed_scans),
            "last_scan": {
                "scan_id": last_scan.scan_id,
                "subnet": last_scan.subnet,
                "devices_found": last_scan.devices_found,
                "completed_at": last_scan.completed_at.isoformat() if last_scan.completed_at else None,
            } if last_scan else None,
            "pysnmp_available": PYSNMP_AVAILABLE,
        }

    # ========== SNMP Walk for Specific Device ==========

    def snmp_walk_device(self, device_id: str, community: Optional[str] = None) -> Dict[str, Any]:
        """Run SNMP walk on a specific device and update its record."""
        device = self.get_device_by_id(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}

        comm = community or device.snmp_community or "public"
        snmp_data = self.snmp_walk(device.ip, comm)

        if snmp_data:
            self._enrich_device(device.ip, snmp_data)
            device = self.get_device_by_id(device_id)
            return {
                "success": True,
                "device_id": device_id,
                "data": snmp_data,
                "device_type": device.device_type.value if device else "unknown",
            }

        return {
            "success": False,
            "error": "No SNMP response from device",
            "device_id": device_id,
        }
