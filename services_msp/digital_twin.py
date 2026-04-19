"""
AITHER Platform - Digital Twin Network Simulation Service
Creates virtual replicas of MSP customer networks for continuous
Red Team / Blue Team security posture assessment.

Provides:
- Network twin creation from discovery scans or manual input
- Device and connection management within twins
- Vulnerability scanning simulation using known CVE patterns
- Red Team attack simulations (8 pre-built attack scenarios)
- Blue Team defense/remediation simulations
- Purple Team combined assessments
- Attack path analysis and blast radius calculation
- Security posture scoring and trend tracking
- Per-client dashboards

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.digital_twin import (
        NetworkTwinModel,
        TwinDeviceModel,
        TwinConnectionModel,
        TwinVulnerabilityModel,
        SimulationRunModel,
        SimulationFindingModel,
        AttackScenarioModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class SimulationType(str, Enum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"
    STRESS_TEST = "stress_test"
    DISASTER_RECOVERY = "disaster_recovery"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    POLICY_VIOLATION = "policy_violation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXPOSURE = "data_exposure"
    WEAK_CREDENTIALS = "weak_credentials"
    UNPATCHED_SOFTWARE = "unpatched_software"
    OPEN_PORT = "open_port"
    MISSING_ENCRYPTION = "missing_encryption"


class AttackType(str, Enum):
    RANSOMWARE_PROPAGATION = "ransomware_propagation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    DDOS = "ddos"
    PHISHING_CHAIN = "phishing_chain"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER_THREAT = "insider_threat"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class TwinVulnerability:
    vuln_id: str = ""
    cve_id: str = ""
    title: str = ""
    severity: str = "medium"
    cvss_score: float = 5.0
    affected_service: str = ""
    is_exploitable: bool = True
    remediation: str = ""
    discovered_by: str = "scanner"
    discovered_at: str = ""

    def __post_init__(self):
        if not self.vuln_id:
            self.vuln_id = str(uuid.uuid4())
        if not self.discovered_at:
            self.discovered_at = _now_iso()


@dataclass
class TwinDevice:
    device_id: str = ""
    twin_id: str = ""
    hostname: str = ""
    ip_address: str = ""
    mac_address: str = ""
    device_type: str = "unknown"
    os_type: str = ""
    os_version: str = ""
    open_ports: List[int] = field(default_factory=list)
    services_running: List[str] = field(default_factory=list)
    vulnerabilities: List[TwinVulnerability] = field(default_factory=list)
    patch_level: str = "unknown"
    is_critical_asset: bool = False
    security_score: float = 50.0

    def __post_init__(self):
        if not self.device_id:
            self.device_id = str(uuid.uuid4())


@dataclass
class TwinConnection:
    connection_id: str = ""
    source_device_id: str = ""
    target_device_id: str = ""
    connection_type: str = "ethernet"
    bandwidth_mbps: float = 1000.0
    is_encrypted: bool = False
    firewall_rules: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.connection_id:
            self.connection_id = str(uuid.uuid4())


@dataclass
class NetworkTwin:
    twin_id: str = ""
    client_id: str = ""
    name: str = ""
    description: str = ""
    created_from: str = "manual"
    devices: List[Dict] = field(default_factory=list)
    connections: List[Dict] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
    security_posture_score: float = 50.0
    last_simulation_at: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if not self.twin_id:
            self.twin_id = str(uuid.uuid4())
        if not self.created_at:
            self.created_at = _now_iso()


@dataclass
class AttackStep:
    step_number: int = 1
    action: str = ""
    target_device_id: str = ""
    technique_id: str = ""
    success_probability: float = 0.5
    detection_probability: float = 0.5


@dataclass
class AttackScenario:
    scenario_id: str = ""
    name: str = ""
    description: str = ""
    attack_type: str = ""
    steps: List[Dict] = field(default_factory=list)
    difficulty: str = "medium"
    estimated_impact: str = "high"

    def __post_init__(self):
        if not self.scenario_id:
            self.scenario_id = str(uuid.uuid4())


@dataclass
class SimulationFinding:
    finding_id: str = ""
    sim_id: str = ""
    finding_type: str = "vulnerability"
    severity: str = "medium"
    title: str = ""
    description: str = ""
    affected_devices: List[str] = field(default_factory=list)
    attack_path: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    was_auto_remediated: bool = False

    def __post_init__(self):
        if not self.finding_id:
            self.finding_id = str(uuid.uuid4())


@dataclass
class SimulationRun:
    sim_id: str = ""
    twin_id: str = ""
    sim_type: str = "red_team"
    status: str = "pending"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    attack_vectors_tested: int = 0
    vulnerabilities_found: int = 0
    vulnerabilities_remediated: int = 0
    score_before: float = 0.0
    score_after: float = 0.0
    findings: List[Dict] = field(default_factory=list)
    persona_id: str = ""

    def __post_init__(self):
        if not self.sim_id:
            self.sim_id = str(uuid.uuid4())


# ============================================================
# Helpers
# ============================================================

def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# CVE Database (20+ common CVEs)
# ============================================================

_CVE_DATABASE = [
    {"cve_id": "CVE-2021-44228", "title": "Log4Shell - Apache Log4j RCE", "severity": "critical", "cvss_score": 10.0, "affected_service": "log4j", "remediation": "Upgrade to Log4j 2.17.1+"},
    {"cve_id": "CVE-2021-34527", "title": "PrintNightmare - Windows Print Spooler RCE", "severity": "critical", "cvss_score": 8.8, "affected_service": "print_spooler", "remediation": "Disable Print Spooler service or apply KB5004945"},
    {"cve_id": "CVE-2017-0144", "title": "EternalBlue - SMBv1 RCE", "severity": "critical", "cvss_score": 9.8, "affected_service": "smb", "remediation": "Apply MS17-010, disable SMBv1"},
    {"cve_id": "CVE-2020-1472", "title": "Zerologon - Netlogon privilege escalation", "severity": "critical", "cvss_score": 10.0, "affected_service": "netlogon", "remediation": "Apply August 2020 patch, enforce secure RPC"},
    {"cve_id": "CVE-2019-0708", "title": "BlueKeep - RDP RCE", "severity": "critical", "cvss_score": 9.8, "affected_service": "rdp", "remediation": "Patch KB4499175, enable NLA, restrict RDP access"},
    {"cve_id": "CVE-2023-44487", "title": "HTTP/2 Rapid Reset DDoS", "severity": "high", "cvss_score": 7.5, "affected_service": "http", "remediation": "Update web server, implement rate limiting"},
    {"cve_id": "CVE-2021-26855", "title": "ProxyLogon - Exchange Server SSRF", "severity": "critical", "cvss_score": 9.8, "affected_service": "exchange", "remediation": "Apply March 2021 security update"},
    {"cve_id": "CVE-2022-22965", "title": "Spring4Shell - Spring Framework RCE", "severity": "critical", "cvss_score": 9.8, "affected_service": "spring", "remediation": "Upgrade Spring to 5.3.18+"},
    {"cve_id": "CVE-2021-21972", "title": "VMware vCenter Server RCE", "severity": "critical", "cvss_score": 9.8, "affected_service": "vcenter", "remediation": "Apply VMSA-2021-0002"},
    {"cve_id": "CVE-2018-13379", "title": "Fortinet FortiOS path traversal", "severity": "high", "cvss_score": 9.8, "affected_service": "fortios_vpn", "remediation": "Upgrade FortiOS, reset credentials"},
    {"cve_id": "CVE-2019-19781", "title": "Citrix ADC path traversal RCE", "severity": "critical", "cvss_score": 9.8, "affected_service": "citrix_adc", "remediation": "Apply Citrix mitigation, upgrade firmware"},
    {"cve_id": "CVE-2020-5902", "title": "F5 BIG-IP TMUI RCE", "severity": "critical", "cvss_score": 9.8, "affected_service": "f5_bigip", "remediation": "Upgrade to fixed version, restrict TMUI access"},
    {"cve_id": "CVE-2023-27997", "title": "Fortinet FortiOS heap overflow RCE", "severity": "critical", "cvss_score": 9.8, "affected_service": "fortios_sslvpn", "remediation": "Upgrade FortiOS immediately"},
    {"cve_id": "CVE-2019-11510", "title": "Pulse Secure VPN arbitrary file read", "severity": "critical", "cvss_score": 10.0, "affected_service": "pulse_vpn", "remediation": "Upgrade firmware, reset credentials"},
    {"cve_id": "CVE-2020-0688", "title": "Exchange Server deserialization RCE", "severity": "high", "cvss_score": 8.8, "affected_service": "exchange", "remediation": "Apply Feb 2020 patch"},
    {"cve_id": "CVE-2017-5638", "title": "Apache Struts 2 RCE (Equifax)", "severity": "critical", "cvss_score": 10.0, "affected_service": "struts", "remediation": "Upgrade Struts to 2.5.10.1+"},
    {"cve_id": "CVE-2014-0160", "title": "Heartbleed - OpenSSL info leak", "severity": "high", "cvss_score": 7.5, "affected_service": "openssl", "remediation": "Upgrade OpenSSL, rotate keys and certificates"},
    {"cve_id": "CVE-2018-7600", "title": "Drupalgeddon2 - Drupal RCE", "severity": "critical", "cvss_score": 9.8, "affected_service": "drupal", "remediation": "Update to Drupal 7.58 / 8.5.1"},
    {"cve_id": "CVE-2021-27065", "title": "ProxyShell - Exchange post-auth RCE", "severity": "high", "cvss_score": 7.8, "affected_service": "exchange", "remediation": "Apply April 2021 CU"},
    {"cve_id": "CVE-2016-3088", "title": "Apache ActiveMQ web console RCE", "severity": "high", "cvss_score": 8.6, "affected_service": "activemq", "remediation": "Restrict console access, upgrade ActiveMQ"},
    {"cve_id": "CVE-2024-3400", "title": "Palo Alto PAN-OS command injection", "severity": "critical", "cvss_score": 10.0, "affected_service": "panos_globalprotect", "remediation": "Apply hotfix, disable GlobalProtect telemetry"},
    {"cve_id": "CVE-2023-46805", "title": "Ivanti Connect Secure auth bypass", "severity": "critical", "cvss_score": 8.2, "affected_service": "ivanti_vpn", "remediation": "Apply vendor patch, implement external integrity tool"},
]

# Service-to-CVE mapping for vulnerability scanning
_SERVICE_CVE_MAP: Dict[str, List[str]] = {
    "smb": ["CVE-2017-0144"],
    "rdp": ["CVE-2019-0708"],
    "http": ["CVE-2023-44487", "CVE-2017-5638"],
    "https": ["CVE-2023-44487", "CVE-2014-0160"],
    "exchange": ["CVE-2021-26855", "CVE-2020-0688", "CVE-2021-27065"],
    "print_spooler": ["CVE-2021-34527"],
    "netlogon": ["CVE-2020-1472"],
    "log4j": ["CVE-2021-44228"],
    "spring": ["CVE-2022-22965"],
    "vcenter": ["CVE-2021-21972"],
    "fortios_vpn": ["CVE-2018-13379", "CVE-2023-27997"],
    "citrix_adc": ["CVE-2019-19781"],
    "f5_bigip": ["CVE-2020-5902"],
    "pulse_vpn": ["CVE-2019-11510"],
    "activemq": ["CVE-2016-3088"],
    "drupal": ["CVE-2018-7600"],
    "panos_globalprotect": ["CVE-2024-3400"],
    "ivanti_vpn": ["CVE-2023-46805"],
}

# Port-to-service mapping
_PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "rpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http", 8443: "https", 27017: "mongodb",
}

# MITRE ATT&CK Technique IDs
_MITRE_TECHNIQUES = {
    "phishing": "T1566",
    "exploit_public": "T1190",
    "credential_dump": "T1003",
    "lateral_smb": "T1021.002",
    "lateral_rdp": "T1021.001",
    "privilege_escalation": "T1068",
    "data_exfil_dns": "T1048.001",
    "ransomware_encrypt": "T1486",
    "supply_chain": "T1195",
    "insider_access": "T1078",
    "brute_force": "T1110",
    "service_stop": "T1489",
    "command_control": "T1071",
    "persistence": "T1547",
    "discovery": "T1046",
}


# ============================================================
# Pre-built Attack Scenarios
# ============================================================

def _build_attack_scenarios() -> List[AttackScenario]:
    """Generate the 8 pre-built attack scenarios."""
    return [
        AttackScenario(
            scenario_id="SCENARIO-001",
            name="Ransomware Propagation",
            description="Phish a user, execute payload, spread via SMB, encrypt critical data",
            attack_type=AttackType.RANSOMWARE_PROPAGATION,
            steps=[
                asdict(AttackStep(1, "Send phishing email with malicious attachment", "", _MITRE_TECHNIQUES["phishing"], 0.6, 0.3)),
                asdict(AttackStep(2, "User opens attachment, payload executes", "", _MITRE_TECHNIQUES["exploit_public"], 0.7, 0.4)),
                asdict(AttackStep(3, "Ransomware spreads via SMB to adjacent hosts", "", _MITRE_TECHNIQUES["lateral_smb"], 0.8, 0.5)),
                asdict(AttackStep(4, "Encrypt files on all reachable systems", "", _MITRE_TECHNIQUES["ransomware_encrypt"], 0.9, 0.7)),
            ],
            difficulty="medium",
            estimated_impact="critical",
        ),
        AttackScenario(
            scenario_id="SCENARIO-002",
            name="Lateral Movement",
            description="Compromise workstation, dump credentials, move to server, escalate",
            attack_type=AttackType.LATERAL_MOVEMENT,
            steps=[
                asdict(AttackStep(1, "Exploit vulnerable workstation service", "", _MITRE_TECHNIQUES["exploit_public"], 0.5, 0.3)),
                asdict(AttackStep(2, "Dump cached credentials from memory", "", _MITRE_TECHNIQUES["credential_dump"], 0.7, 0.4)),
                asdict(AttackStep(3, "Move laterally to server via RDP/SMB", "", _MITRE_TECHNIQUES["lateral_rdp"], 0.6, 0.5)),
                asdict(AttackStep(4, "Escalate privileges to domain admin", "", _MITRE_TECHNIQUES["privilege_escalation"], 0.4, 0.6)),
            ],
            difficulty="hard",
            estimated_impact="critical",
        ),
        AttackScenario(
            scenario_id="SCENARIO-003",
            name="Privilege Escalation",
            description="Start as standard user, exploit local vuln, get admin, then domain admin",
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            steps=[
                asdict(AttackStep(1, "Authenticate as standard domain user", "", _MITRE_TECHNIQUES["insider_access"], 0.9, 0.1)),
                asdict(AttackStep(2, "Exploit local privilege escalation vulnerability", "", _MITRE_TECHNIQUES["privilege_escalation"], 0.5, 0.4)),
                asdict(AttackStep(3, "Obtain local administrator access", "", _MITRE_TECHNIQUES["credential_dump"], 0.6, 0.5)),
                asdict(AttackStep(4, "Escalate to domain admin via Zerologon/PrintNightmare", "", _MITRE_TECHNIQUES["privilege_escalation"], 0.4, 0.7)),
            ],
            difficulty="hard",
            estimated_impact="critical",
        ),
        AttackScenario(
            scenario_id="SCENARIO-004",
            name="Data Exfiltration",
            description="Access file server, identify sensitive data, exfiltrate via DNS tunnel",
            attack_type=AttackType.DATA_EXFILTRATION,
            steps=[
                asdict(AttackStep(1, "Gain access to file server with stolen credentials", "", _MITRE_TECHNIQUES["insider_access"], 0.6, 0.3)),
                asdict(AttackStep(2, "Discover and enumerate sensitive data stores", "", _MITRE_TECHNIQUES["discovery"], 0.8, 0.2)),
                asdict(AttackStep(3, "Stage data for exfiltration", "", _MITRE_TECHNIQUES["persistence"], 0.7, 0.3)),
                asdict(AttackStep(4, "Exfiltrate data via DNS tunneling", "", _MITRE_TECHNIQUES["data_exfil_dns"], 0.6, 0.4)),
            ],
            difficulty="medium",
            estimated_impact="high",
        ),
        AttackScenario(
            scenario_id="SCENARIO-005",
            name="DDoS Attack",
            description="Flood public-facing services, exhaust resources, cause service disruption",
            attack_type=AttackType.DDOS,
            steps=[
                asdict(AttackStep(1, "Identify public-facing services and endpoints", "", _MITRE_TECHNIQUES["discovery"], 0.9, 0.1)),
                asdict(AttackStep(2, "Launch volumetric flood against web servers", "", _MITRE_TECHNIQUES["service_stop"], 0.7, 0.8)),
                asdict(AttackStep(3, "Exploit HTTP/2 Rapid Reset for amplification", "", _MITRE_TECHNIQUES["service_stop"], 0.6, 0.7)),
                asdict(AttackStep(4, "Sustain attack until resource exhaustion", "", _MITRE_TECHNIQUES["service_stop"], 0.8, 0.9)),
            ],
            difficulty="easy",
            estimated_impact="high",
        ),
        AttackScenario(
            scenario_id="SCENARIO-006",
            name="Phishing Chain",
            description="Spearphish exec, harvest creds, access email, initiate BEC wire transfer",
            attack_type=AttackType.PHISHING_CHAIN,
            steps=[
                asdict(AttackStep(1, "Craft targeted spearphishing email for executive", "", _MITRE_TECHNIQUES["phishing"], 0.5, 0.3)),
                asdict(AttackStep(2, "Harvest credentials via fake login page", "", _MITRE_TECHNIQUES["brute_force"], 0.6, 0.4)),
                asdict(AttackStep(3, "Access executive email and study communication patterns", "", _MITRE_TECHNIQUES["insider_access"], 0.8, 0.2)),
                asdict(AttackStep(4, "Send BEC wire transfer request to finance team", "", _MITRE_TECHNIQUES["insider_access"], 0.4, 0.5)),
            ],
            difficulty="medium",
            estimated_impact="critical",
        ),
        AttackScenario(
            scenario_id="SCENARIO-007",
            name="Supply Chain Attack",
            description="Compromise update server, push malicious update, mass infection",
            attack_type=AttackType.SUPPLY_CHAIN,
            steps=[
                asdict(AttackStep(1, "Identify internal software update/patch server", "", _MITRE_TECHNIQUES["discovery"], 0.7, 0.2)),
                asdict(AttackStep(2, "Compromise update server via known vulnerability", "", _MITRE_TECHNIQUES["exploit_public"], 0.4, 0.5)),
                asdict(AttackStep(3, "Inject malicious payload into legitimate update package", "", _MITRE_TECHNIQUES["supply_chain"], 0.5, 0.3)),
                asdict(AttackStep(4, "Endpoints auto-install trojanized update", "", _MITRE_TECHNIQUES["persistence"], 0.8, 0.6)),
            ],
            difficulty="hard",
            estimated_impact="critical",
        ),
        AttackScenario(
            scenario_id="SCENARIO-008",
            name="Insider Threat",
            description="Rogue employee accesses beyond role, downloads data, covers tracks",
            attack_type=AttackType.INSIDER_THREAT,
            steps=[
                asdict(AttackStep(1, "Authenticate with legitimate credentials", "", _MITRE_TECHNIQUES["insider_access"], 0.95, 0.05)),
                asdict(AttackStep(2, "Access resources beyond authorized role", "", _MITRE_TECHNIQUES["discovery"], 0.6, 0.3)),
                asdict(AttackStep(3, "Download sensitive data to removable media", "", _MITRE_TECHNIQUES["data_exfil_dns"], 0.7, 0.4)),
                asdict(AttackStep(4, "Clear audit logs to cover tracks", "", _MITRE_TECHNIQUES["persistence"], 0.5, 0.6)),
            ],
            difficulty="easy",
            estimated_impact="high",
        ),
    ]


# Build scenarios at module load
ATTACK_SCENARIOS = _build_attack_scenarios()


# ============================================================
# Digital Twin Service
# ============================================================

class DigitalTwinService:
    """
    Digital Twin Network Simulation Service.
    Creates virtual replicas of MSP customer networks that Red Team and
    Blue Team personas can attack/defend for continuous security posture
    assessment.
    """

    def __init__(self, db: "Session | None" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE
        # In-memory stores (fallback)
        self._twins: Dict[str, NetworkTwin] = {}
        self._devices: Dict[str, TwinDevice] = {}
        self._connections: Dict[str, TwinConnection] = {}
        self._vulnerabilities: Dict[str, TwinVulnerability] = {}
        self._simulations: Dict[str, SimulationRun] = {}
        self._findings: Dict[str, SimulationFinding] = {}
        self._scenarios: Dict[str, AttackScenario] = {}
        # Seed built-in scenarios
        for sc in ATTACK_SCENARIOS:
            self._scenarios[sc.scenario_id] = sc
        logger.info("DigitalTwinService initialized (db=%s)", "yes" if self._use_db else "in-memory")

    # ------------------------------------------------------------------
    # Internal DB helpers
    # ------------------------------------------------------------------

    def _persist_twin(self, twin: NetworkTwin):
        if not self._use_db:
            return
        try:
            row = self.db.query(NetworkTwinModel).filter_by(twin_id=twin.twin_id).first()
            d = asdict(twin)
            if row:
                for k, v in d.items():
                    if hasattr(row, k):
                        setattr(row, k, v)
            else:
                row = NetworkTwinModel(**{k: v for k, v in d.items() if hasattr(NetworkTwinModel, k)})
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.warning("DB persist twin failed: %s", exc)
            self.db.rollback()

    def _persist_device(self, dev: TwinDevice):
        if not self._use_db:
            return
        try:
            row = self.db.query(TwinDeviceModel).filter_by(device_id=dev.device_id).first()
            d = asdict(dev)
            # Convert vulnerabilities list to dicts
            if "vulnerabilities" in d:
                d["vulnerabilities"] = [asdict(v) if not isinstance(v, dict) else v for v in d["vulnerabilities"]]
            if row:
                for k, v in d.items():
                    if hasattr(row, k):
                        setattr(row, k, v)
            else:
                row = TwinDeviceModel(**{k: v for k, v in d.items() if hasattr(TwinDeviceModel, k)})
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.warning("DB persist device failed: %s", exc)
            self.db.rollback()

    def _persist_simulation(self, sim: SimulationRun):
        if not self._use_db:
            return
        try:
            row = self.db.query(SimulationRunModel).filter_by(sim_id=sim.sim_id).first()
            d = asdict(sim)
            if row:
                for k, v in d.items():
                    if hasattr(row, k):
                        setattr(row, k, v)
            else:
                row = SimulationRunModel(**{k: v for k, v in d.items() if hasattr(SimulationRunModel, k)})
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.warning("DB persist simulation failed: %s", exc)
            self.db.rollback()

    # ------------------------------------------------------------------
    # Twin CRUD
    # ------------------------------------------------------------------

    def create_twin_from_discovery(self, client_id: str, discovery_scan_id: str,
                                   discovered_devices: Optional[List[Dict]] = None) -> Dict:
        """Auto-create a network twin from network discovery scan data."""
        twin = NetworkTwin(
            client_id=client_id,
            name=f"Twin-{client_id}-{discovery_scan_id[:8]}",
            description=f"Auto-created from discovery scan {discovery_scan_id}",
            created_from=discovery_scan_id,
        )

        devices_list = discovered_devices or []
        device_records = []
        for dd in devices_list:
            dev = TwinDevice(
                twin_id=twin.twin_id,
                hostname=dd.get("hostname", "unknown"),
                ip_address=dd.get("ip_address", "0.0.0.0"),
                mac_address=dd.get("mac_address", ""),
                device_type=dd.get("device_type", "unknown"),
                os_type=dd.get("os_type", ""),
                os_version=dd.get("os_version", ""),
                open_ports=dd.get("open_ports", []),
                services_running=dd.get("services_running", []),
                is_critical_asset=dd.get("is_critical_asset", False),
            )
            # Infer services from ports
            for port in dev.open_ports:
                svc = _PORT_SERVICES.get(port)
                if svc and svc not in dev.services_running:
                    dev.services_running.append(svc)
            self._devices[dev.device_id] = dev
            self._persist_device(dev)
            device_records.append(asdict(dev))

        twin.devices = device_records
        # Auto-create connections between devices on same subnet
        conns = self._auto_connect_devices(twin.twin_id, device_records)
        twin.connections = conns
        twin.subnets = list({self._subnet_from_ip(d.get("ip_address", "")) for d in device_records if d.get("ip_address")})

        self._twins[twin.twin_id] = twin
        self._persist_twin(twin)

        return asdict(twin)

    def create_twin_manual(self, client_id: str, name: str,
                           devices: Optional[List[Dict]] = None,
                           connections: Optional[List[Dict]] = None) -> Dict:
        """Manually create a network twin with provided devices and connections."""
        twin = NetworkTwin(
            client_id=client_id,
            name=name,
            description=f"Manually created twin: {name}",
            created_from="manual",
        )

        device_records = []
        for dd in (devices or []):
            dev = TwinDevice(
                twin_id=twin.twin_id,
                hostname=dd.get("hostname", "unknown"),
                ip_address=dd.get("ip_address", "0.0.0.0"),
                mac_address=dd.get("mac_address", ""),
                device_type=dd.get("device_type", "unknown"),
                os_type=dd.get("os_type", ""),
                os_version=dd.get("os_version", ""),
                open_ports=dd.get("open_ports", []),
                services_running=dd.get("services_running", []),
                is_critical_asset=dd.get("is_critical_asset", False),
            )
            for port in dev.open_ports:
                svc = _PORT_SERVICES.get(port)
                if svc and svc not in dev.services_running:
                    dev.services_running.append(svc)
            self._devices[dev.device_id] = dev
            self._persist_device(dev)
            device_records.append(asdict(dev))

        conn_records = []
        for cc in (connections or []):
            conn = TwinConnection(
                source_device_id=cc.get("source_device_id", ""),
                target_device_id=cc.get("target_device_id", ""),
                connection_type=cc.get("connection_type", "ethernet"),
                bandwidth_mbps=cc.get("bandwidth_mbps", 1000.0),
                is_encrypted=cc.get("is_encrypted", False),
                firewall_rules=cc.get("firewall_rules", []),
            )
            self._connections[conn.connection_id] = conn
            conn_records.append(asdict(conn))

        twin.devices = device_records
        twin.connections = conn_records
        twin.subnets = list({self._subnet_from_ip(d.get("ip_address", "")) for d in device_records if d.get("ip_address")})

        self._twins[twin.twin_id] = twin
        self._persist_twin(twin)

        return asdict(twin)

    def get_twin(self, twin_id: str) -> Optional[Dict]:
        """Get a network twin by ID."""
        twin = self._twins.get(twin_id)
        if twin:
            return asdict(twin)
        if self._use_db:
            try:
                row = self.db.query(NetworkTwinModel).filter_by(twin_id=twin_id).first()
                if row:
                    return {c.name: getattr(row, c.name) for c in row.__table__.columns}
            except Exception:
                pass
        return None

    def list_twins(self, client_id: Optional[str] = None) -> List[Dict]:
        """List all twins, optionally filtered by client_id."""
        results = []
        for t in self._twins.values():
            if client_id and t.client_id != client_id:
                continue
            results.append(asdict(t))
        return results

    def update_twin(self, twin_id: str, updates: Dict) -> Optional[Dict]:
        """Update a twin's metadata."""
        twin = self._twins.get(twin_id)
        if not twin:
            return None
        for key, val in updates.items():
            if hasattr(twin, key) and key not in ("twin_id", "created_at"):
                setattr(twin, key, val)
        twin.updated_at = _now_iso()
        self._persist_twin(twin)
        return asdict(twin)

    def delete_twin(self, twin_id: str) -> bool:
        """Delete a twin and all associated data."""
        if twin_id not in self._twins:
            return False
        twin = self._twins.pop(twin_id)
        # Remove associated devices
        dev_ids = [d.get("device_id") for d in twin.devices if d.get("device_id")]
        for did in dev_ids:
            self._devices.pop(did, None)
        # Remove associated connections
        conn_ids = [c.get("connection_id") for c in twin.connections if c.get("connection_id")]
        for cid in conn_ids:
            self._connections.pop(cid, None)
        if self._use_db:
            try:
                self.db.query(NetworkTwinModel).filter_by(twin_id=twin_id).delete()
                self.db.query(TwinDeviceModel).filter_by(twin_id=twin_id).delete()
                self.db.query(TwinConnectionModel).filter_by(twin_id=twin_id).delete()
                self.db.commit()
            except Exception:
                self.db.rollback()
        return True

    # ------------------------------------------------------------------
    # Device Management
    # ------------------------------------------------------------------

    def add_device(self, twin_id: str, device_data: Dict) -> Optional[Dict]:
        """Add a device to a twin."""
        twin = self._twins.get(twin_id)
        if not twin:
            return None
        dev = TwinDevice(
            twin_id=twin_id,
            hostname=device_data.get("hostname", "unknown"),
            ip_address=device_data.get("ip_address", "0.0.0.0"),
            mac_address=device_data.get("mac_address", ""),
            device_type=device_data.get("device_type", "unknown"),
            os_type=device_data.get("os_type", ""),
            os_version=device_data.get("os_version", ""),
            open_ports=device_data.get("open_ports", []),
            services_running=device_data.get("services_running", []),
            is_critical_asset=device_data.get("is_critical_asset", False),
        )
        for port in dev.open_ports:
            svc = _PORT_SERVICES.get(port)
            if svc and svc not in dev.services_running:
                dev.services_running.append(svc)
        self._devices[dev.device_id] = dev
        self._persist_device(dev)
        twin.devices.append(asdict(dev))
        self._persist_twin(twin)
        return asdict(dev)

    def update_device(self, device_id: str, updates: Dict) -> Optional[Dict]:
        """Update a device's properties."""
        dev = self._devices.get(device_id)
        if not dev:
            return None
        for key, val in updates.items():
            if hasattr(dev, key) and key not in ("device_id", "twin_id"):
                setattr(dev, key, val)
        self._persist_device(dev)
        # Update in twin's devices list
        twin = self._twins.get(dev.twin_id)
        if twin:
            twin.devices = [asdict(d) if isinstance(d, TwinDevice) else d for d in
                            [self._devices[dd["device_id"]] if dd.get("device_id") in self._devices else dd
                             for dd in twin.devices]]
            self._persist_twin(twin)
        return asdict(dev)

    def remove_device(self, twin_id: str, device_id: str) -> bool:
        """Remove a device from a twin."""
        twin = self._twins.get(twin_id)
        if not twin:
            return False
        self._devices.pop(device_id, None)
        twin.devices = [d for d in twin.devices if d.get("device_id") != device_id]
        # Remove connections involving this device
        twin.connections = [c for c in twin.connections
                           if c.get("source_device_id") != device_id and c.get("target_device_id") != device_id]
        self._persist_twin(twin)
        if self._use_db:
            try:
                self.db.query(TwinDeviceModel).filter_by(device_id=device_id).delete()
                self.db.commit()
            except Exception:
                self.db.rollback()
        return True

    # ------------------------------------------------------------------
    # Connection Management
    # ------------------------------------------------------------------

    def add_connection(self, twin_id: str, connection_data: Dict) -> Optional[Dict]:
        """Add a connection between two devices in a twin."""
        twin = self._twins.get(twin_id)
        if not twin:
            return None
        conn = TwinConnection(
            source_device_id=connection_data.get("source_device_id", ""),
            target_device_id=connection_data.get("target_device_id", ""),
            connection_type=connection_data.get("connection_type", "ethernet"),
            bandwidth_mbps=connection_data.get("bandwidth_mbps", 1000.0),
            is_encrypted=connection_data.get("is_encrypted", False),
            firewall_rules=connection_data.get("firewall_rules", []),
        )
        self._connections[conn.connection_id] = conn
        twin.connections.append(asdict(conn))
        self._persist_twin(twin)
        return asdict(conn)

    def remove_connection(self, twin_id: str, connection_id: str) -> bool:
        """Remove a connection from a twin."""
        twin = self._twins.get(twin_id)
        if not twin:
            return False
        self._connections.pop(connection_id, None)
        twin.connections = [c for c in twin.connections if c.get("connection_id") != connection_id]
        self._persist_twin(twin)
        return True

    # ------------------------------------------------------------------
    # Vulnerability Scanning
    # ------------------------------------------------------------------

    def scan_device_vulnerabilities(self, device_id: str) -> Dict:
        """Simulate a vulnerability scan on a twin device using known CVE patterns."""
        dev = self._devices.get(device_id)
        if not dev:
            return {"error": "Device not found", "device_id": device_id}

        found_vulns = []
        for svc in dev.services_running:
            cve_ids = _SERVICE_CVE_MAP.get(svc, [])
            for cve_id in cve_ids:
                cve_data = next((c for c in _CVE_DATABASE if c["cve_id"] == cve_id), None)
                if cve_data:
                    vuln = TwinVulnerability(
                        cve_id=cve_data["cve_id"],
                        title=cve_data["title"],
                        severity=cve_data["severity"],
                        cvss_score=cve_data["cvss_score"],
                        affected_service=svc,
                        is_exploitable=True,
                        remediation=cve_data["remediation"],
                        discovered_by="scanner",
                    )
                    found_vulns.append(vuln)
                    self._vulnerabilities[vuln.vuln_id] = vuln

        # Check for risky open ports
        risky_ports = {23: "Telnet (unencrypted)", 21: "FTP (unencrypted)", 5900: "VNC (often unencrypted)"}
        for port in dev.open_ports:
            if port in risky_ports:
                vuln = TwinVulnerability(
                    cve_id="",
                    title=f"Risky service: {risky_ports[port]} on port {port}",
                    severity="medium",
                    cvss_score=5.0,
                    affected_service=_PORT_SERVICES.get(port, "unknown"),
                    is_exploitable=True,
                    remediation=f"Disable or replace {risky_ports[port]} with encrypted alternative",
                    discovered_by="scanner",
                )
                found_vulns.append(vuln)
                self._vulnerabilities[vuln.vuln_id] = vuln

        dev.vulnerabilities = found_vulns
        dev.security_score = self._calculate_device_score(dev)
        self._persist_device(dev)

        return {
            "device_id": device_id,
            "hostname": dev.hostname,
            "vulnerabilities_found": len(found_vulns),
            "vulnerabilities": [asdict(v) for v in found_vulns],
            "security_score": dev.security_score,
        }

    # ------------------------------------------------------------------
    # Simulation Engine
    # ------------------------------------------------------------------

    def run_red_team_simulation(self, twin_id: str,
                                 scenario_id: Optional[str] = None) -> Dict:
        """Simulate a red team attack against the twin, finding weaknesses."""
        twin = self._twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found", "twin_id": twin_id}

        scenario = self._scenarios.get(scenario_id) if scenario_id else random.choice(list(self._scenarios.values()))
        if not scenario:
            return {"error": "Scenario not found", "scenario_id": scenario_id}

        score_before = twin.security_posture_score
        sim = SimulationRun(
            twin_id=twin_id,
            sim_type=SimulationType.RED_TEAM,
            status="running",
            started_at=_now_iso(),
            score_before=score_before,
            persona_id="red_team_persona",
        )

        findings = []
        vectors_tested = len(scenario.steps)

        # Simulate each attack step against twin devices
        devices = [self._devices.get(d.get("device_id")) for d in twin.devices if d.get("device_id") in self._devices]
        if not devices:
            devices = []

        for step_data in scenario.steps:
            step_num = step_data.get("step_number", 0)
            technique = step_data.get("technique_id", "")
            success_prob = step_data.get("success_probability", 0.5)

            # Check if attack step would succeed based on device vulnerabilities
            for dev in devices:
                step_findings = self._evaluate_attack_step(dev, step_data, scenario.attack_type)
                findings.extend(step_findings)

        # Generate additional findings based on network-level analysis
        network_findings = self._assess_network_weaknesses(twin)
        findings.extend(network_findings)

        sim.status = "completed"
        sim.completed_at = _now_iso()
        sim.attack_vectors_tested = vectors_tested
        sim.vulnerabilities_found = len(findings)
        sim.findings = [asdict(f) for f in findings]

        # Update posture score (red team typically reveals lower score)
        vuln_penalty = min(len(findings) * 3, 40)
        severity_penalty = sum(
            {"critical": 8, "high": 5, "medium": 3, "low": 1, "info": 0}.get(f.severity, 0)
            for f in findings
        )
        new_score = max(0, score_before - vuln_penalty - min(severity_penalty, 30))
        sim.score_after = new_score
        twin.security_posture_score = new_score
        twin.last_simulation_at = sim.completed_at

        self._simulations[sim.sim_id] = sim
        for f in findings:
            self._findings[f.finding_id] = f
        self._persist_twin(twin)
        self._persist_simulation(sim)

        return asdict(sim)

    def run_blue_team_simulation(self, twin_id: str,
                                  findings: Optional[List[Dict]] = None) -> Dict:
        """Simulate blue team defense/remediation against known findings."""
        twin = self._twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found", "twin_id": twin_id}

        score_before = twin.security_posture_score
        sim = SimulationRun(
            twin_id=twin_id,
            sim_type=SimulationType.BLUE_TEAM,
            status="running",
            started_at=_now_iso(),
            score_before=score_before,
            persona_id="blue_team_persona",
        )

        # Use provided findings or gather from recent red team sims
        input_findings = findings or []
        if not input_findings:
            recent_sims = [s for s in self._simulations.values()
                          if s.twin_id == twin_id and s.sim_type == SimulationType.RED_TEAM]
            if recent_sims:
                latest = max(recent_sims, key=lambda s: s.started_at or "")
                input_findings = latest.findings

        remediated = 0
        blue_findings = []
        for f_data in input_findings:
            severity = f_data.get("severity", "medium")
            # Blue team remediates based on severity
            remediation_prob = {"critical": 0.9, "high": 0.85, "medium": 0.7, "low": 0.5, "info": 0.3}.get(severity, 0.5)
            was_remediated = random.random() < remediation_prob

            bf = SimulationFinding(
                sim_id=sim.sim_id,
                finding_type=f_data.get("finding_type", "vulnerability"),
                severity=severity,
                title=f"Remediation: {f_data.get('title', 'Unknown')}",
                description=f"Blue team {'successfully remediated' if was_remediated else 'attempted but could not remediate'} this finding",
                affected_devices=f_data.get("affected_devices", []),
                remediation_steps=f_data.get("remediation_steps", ["Apply vendor patch", "Update configuration"]),
                was_auto_remediated=was_remediated,
            )
            blue_findings.append(bf)
            if was_remediated:
                remediated += 1

        sim.status = "completed"
        sim.completed_at = _now_iso()
        sim.vulnerabilities_found = len(input_findings)
        sim.vulnerabilities_remediated = remediated
        sim.findings = [asdict(f) for f in blue_findings]

        # Calculate improved score
        improvement = min(remediated * 4, 40)
        new_score = min(100, score_before + improvement)
        sim.score_after = new_score
        twin.security_posture_score = new_score
        twin.last_simulation_at = sim.completed_at

        self._simulations[sim.sim_id] = sim
        self._persist_twin(twin)
        self._persist_simulation(sim)

        return asdict(sim)

    def run_purple_team(self, twin_id: str,
                        scenario_id: Optional[str] = None) -> Dict:
        """Run red team then blue team in sequence for complete assessment."""
        twin = self._twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found", "twin_id": twin_id}

        # Phase 1: Red team attack
        red_result = self.run_red_team_simulation(twin_id, scenario_id)
        if "error" in red_result:
            return red_result

        # Phase 2: Blue team defense
        blue_result = self.run_blue_team_simulation(twin_id, red_result.get("findings", []))
        if "error" in blue_result:
            return blue_result

        # Create a combined purple team simulation record
        sim = SimulationRun(
            twin_id=twin_id,
            sim_type=SimulationType.PURPLE_TEAM,
            status="completed",
            started_at=red_result.get("started_at"),
            completed_at=blue_result.get("completed_at"),
            attack_vectors_tested=red_result.get("attack_vectors_tested", 0),
            vulnerabilities_found=red_result.get("vulnerabilities_found", 0),
            vulnerabilities_remediated=blue_result.get("vulnerabilities_remediated", 0),
            score_before=red_result.get("score_before", 0),
            score_after=blue_result.get("score_after", 0),
            findings=red_result.get("findings", []) + blue_result.get("findings", []),
            persona_id="purple_team_combined",
        )

        self._simulations[sim.sim_id] = sim
        self._persist_simulation(sim)

        return {
            "purple_team_sim": asdict(sim),
            "red_team_sim_id": red_result.get("sim_id"),
            "blue_team_sim_id": blue_result.get("sim_id"),
            "initial_score": red_result.get("score_before", 0),
            "post_attack_score": red_result.get("score_after", 0),
            "post_defense_score": blue_result.get("score_after", 0),
            "total_vulnerabilities_found": red_result.get("vulnerabilities_found", 0),
            "total_remediated": blue_result.get("vulnerabilities_remediated", 0),
        }

    # ------------------------------------------------------------------
    # Simulation Retrieval
    # ------------------------------------------------------------------

    def get_simulation(self, sim_id: str) -> Optional[Dict]:
        """Get a simulation run by ID."""
        sim = self._simulations.get(sim_id)
        if sim:
            return asdict(sim)
        return None

    def list_simulations(self, twin_id: Optional[str] = None,
                         sim_type: Optional[str] = None) -> List[Dict]:
        """List simulations, optionally filtered by twin_id or type."""
        results = []
        for s in self._simulations.values():
            if twin_id and s.twin_id != twin_id:
                continue
            if sim_type and s.sim_type != sim_type:
                continue
            results.append(asdict(s))
        return sorted(results, key=lambda x: x.get("started_at") or "", reverse=True)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def calculate_security_posture(self, twin_id: str) -> Dict:
        """Calculate weighted security posture score for a twin."""
        twin = self._twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found"}

        devices = [self._devices.get(d.get("device_id")) for d in twin.devices if d.get("device_id") in self._devices]
        if not devices:
            return {
                "twin_id": twin_id,
                "score": twin.security_posture_score,
                "breakdown": {"device_scores": [], "average_device_score": 0, "vulnerability_count": 0},
            }

        device_scores = []
        total_vulns = 0
        critical_count = 0
        for dev in devices:
            score = self._calculate_device_score(dev)
            dev.security_score = score
            device_scores.append({"device_id": dev.device_id, "hostname": dev.hostname, "score": score})
            total_vulns += len(dev.vulnerabilities)
            critical_count += sum(1 for v in dev.vulnerabilities
                                  if (v.severity if isinstance(v, TwinVulnerability) else v.get("severity", "")) == "critical")

        avg_score = sum(d["score"] for d in device_scores) / len(device_scores) if device_scores else 50.0

        # Weighted: device scores (60%), no critical vulns bonus (20%), encryption (20%)
        encrypted_conns = sum(1 for c in twin.connections if c.get("is_encrypted", False))
        total_conns = len(twin.connections) or 1
        encryption_ratio = encrypted_conns / total_conns

        critical_penalty = min(critical_count * 10, 20)
        posture = (avg_score * 0.6) + ((20 - critical_penalty)) + (encryption_ratio * 20)
        posture = max(0, min(100, posture))

        twin.security_posture_score = round(posture, 1)
        self._persist_twin(twin)

        return {
            "twin_id": twin_id,
            "score": twin.security_posture_score,
            "breakdown": {
                "device_scores": device_scores,
                "average_device_score": round(avg_score, 1),
                "vulnerability_count": total_vulns,
                "critical_vulnerabilities": critical_count,
                "encryption_ratio": round(encryption_ratio, 2),
            },
        }

    def get_attack_path_analysis(self, twin_id: str, target_device_id: str) -> Dict:
        """Find all possible attack paths to reach a target device."""
        twin = self._twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found"}

        # Build adjacency graph from connections
        graph: Dict[str, List[str]] = {}
        for conn in twin.connections:
            src = conn.get("source_device_id", "")
            dst = conn.get("target_device_id", "")
            if src:
                graph.setdefault(src, []).append(dst)
            if dst:
                graph.setdefault(dst, []).append(src)

        # Find all paths using BFS
        paths = []
        for dev_data in twin.devices:
            dev_id = dev_data.get("device_id", "")
            if dev_id == target_device_id:
                continue
            device_paths = self._find_all_paths(graph, dev_id, target_device_id, max_depth=6)
            for path in device_paths:
                # Assess risk of each path
                risk = self._assess_path_risk(path)
                paths.append({
                    "source_device_id": dev_id,
                    "target_device_id": target_device_id,
                    "path": path,
                    "hops": len(path) - 1,
                    "risk_score": risk,
                })

        paths.sort(key=lambda p: p["risk_score"], reverse=True)

        return {
            "twin_id": twin_id,
            "target_device_id": target_device_id,
            "attack_paths": paths,
            "total_paths": len(paths),
            "highest_risk": paths[0]["risk_score"] if paths else 0,
        }

    def get_blast_radius(self, twin_id: str, compromised_device_id: str) -> Dict:
        """Calculate what can be reached from a compromised device."""
        twin = self._twins.get(twin_id)
        if not twin:
            return {"error": "Twin not found"}

        # Build adjacency graph
        graph: Dict[str, List[str]] = {}
        for conn in twin.connections:
            src = conn.get("source_device_id", "")
            dst = conn.get("target_device_id", "")
            if src:
                graph.setdefault(src, []).append(dst)
            if dst:
                graph.setdefault(dst, []).append(src)

        # BFS from compromised device
        visited = set()
        queue = [(compromised_device_id, 0)]
        reachable = []

        while queue:
            current, depth = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            if current != compromised_device_id:
                dev = self._devices.get(current)
                reachable.append({
                    "device_id": current,
                    "hostname": dev.hostname if dev else "unknown",
                    "device_type": dev.device_type if dev else "unknown",
                    "is_critical_asset": dev.is_critical_asset if dev else False,
                    "hops_from_source": depth,
                })
            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))

        critical_assets_affected = [r for r in reachable if r.get("is_critical_asset")]

        return {
            "twin_id": twin_id,
            "compromised_device_id": compromised_device_id,
            "reachable_devices": reachable,
            "total_reachable": len(reachable),
            "critical_assets_affected": len(critical_assets_affected),
            "blast_radius_percentage": round(len(reachable) / max(len(twin.devices), 1) * 100, 1),
        }

    def compare_posture_over_time(self, twin_id: str) -> Dict:
        """Return posture score trend from simulation history."""
        sims = [s for s in self._simulations.values() if s.twin_id == twin_id]
        sims.sort(key=lambda s: s.started_at or "")

        trend = []
        for s in sims:
            trend.append({
                "sim_id": s.sim_id,
                "sim_type": s.sim_type,
                "date": s.completed_at or s.started_at,
                "score_before": s.score_before,
                "score_after": s.score_after,
            })

        current = self._twins.get(twin_id)
        return {
            "twin_id": twin_id,
            "current_score": current.security_posture_score if current else 0,
            "trend": trend,
            "total_simulations": len(trend),
            "improvement": (trend[-1]["score_after"] - trend[0]["score_before"]) if len(trend) >= 2 else 0,
        }

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def get_scenario(self, scenario_id: str) -> Optional[Dict]:
        """Get attack scenario by ID."""
        sc = self._scenarios.get(scenario_id)
        return asdict(sc) if sc else None

    def list_scenarios(self) -> List[Dict]:
        """List all available attack scenarios."""
        return [asdict(s) for s in self._scenarios.values()]

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self, client_id: str) -> Dict:
        """Get dashboard data for a client: twins, scores, recent sims, top vulns."""
        twins = self.list_twins(client_id)
        twin_ids = {t["twin_id"] for t in twins}

        recent_sims = []
        for s in self._simulations.values():
            if s.twin_id in twin_ids:
                recent_sims.append(asdict(s))
        recent_sims.sort(key=lambda x: x.get("completed_at") or x.get("started_at") or "", reverse=True)
        recent_sims = recent_sims[:10]

        # Collect top vulnerabilities across all twin devices
        top_vulns = []
        for t in twins:
            for d in t.get("devices", []):
                dev = self._devices.get(d.get("device_id"))
                if dev:
                    for v in dev.vulnerabilities:
                        if isinstance(v, TwinVulnerability):
                            top_vulns.append(asdict(v))
                        elif isinstance(v, dict):
                            top_vulns.append(v)
        top_vulns.sort(key=lambda v: v.get("cvss_score", 0), reverse=True)
        top_vulns = top_vulns[:20]

        avg_score = sum(t.get("security_posture_score", 0) for t in twins) / len(twins) if twins else 0

        return {
            "client_id": client_id,
            "twins": twins,
            "twin_count": len(twins),
            "average_posture_score": round(avg_score, 1),
            "recent_simulations": recent_sims,
            "top_vulnerabilities": top_vulns,
            "total_devices": sum(len(t.get("devices", [])) for t in twins),
            "scenarios_available": len(self._scenarios),
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _subnet_from_ip(ip: str) -> str:
        """Extract /24 subnet from IP address."""
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "unknown"

    def _auto_connect_devices(self, twin_id: str, devices: List[Dict]) -> List[Dict]:
        """Auto-create connections between devices on the same subnet."""
        conns = []
        subnet_groups: Dict[str, List[str]] = {}
        for d in devices:
            subnet = self._subnet_from_ip(d.get("ip_address", ""))
            subnet_groups.setdefault(subnet, []).append(d.get("device_id", ""))

        for subnet, dev_ids in subnet_groups.items():
            if len(dev_ids) < 2:
                continue
            # Connect each device to the next (simple chain topology)
            for i in range(len(dev_ids) - 1):
                conn = TwinConnection(
                    source_device_id=dev_ids[i],
                    target_device_id=dev_ids[i + 1],
                    connection_type="ethernet",
                )
                self._connections[conn.connection_id] = conn
                conns.append(asdict(conn))
        return conns

    @staticmethod
    def _calculate_device_score(dev: TwinDevice) -> float:
        """Calculate security score for a single device."""
        score = 100.0
        # Penalty for vulnerabilities
        for v in dev.vulnerabilities:
            severity = v.severity if isinstance(v, TwinVulnerability) else v.get("severity", "medium")
            penalty = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}.get(severity, 3)
            score -= penalty

        # Penalty for risky open ports
        risky = {23, 21, 5900, 135, 139}
        for port in dev.open_ports:
            if port in risky:
                score -= 3

        # Bonus for patched status
        if dev.patch_level == "current":
            score += 5

        return max(0, min(100, round(score, 1)))

    def _evaluate_attack_step(self, dev: TwinDevice, step_data: Dict,
                               attack_type: str) -> List[SimulationFinding]:
        """Evaluate a single attack step against a device, generating findings."""
        findings = []
        technique = step_data.get("technique_id", "")
        success_prob = step_data.get("success_probability", 0.5)

        # Check if device has vulnerabilities that enable this technique
        vuln_match = False
        for v in dev.vulnerabilities:
            sev = v.severity if isinstance(v, TwinVulnerability) else v.get("severity", "medium")
            if sev in ("critical", "high"):
                vuln_match = True
                break

        # Check for open ports enabling lateral movement
        if technique in (_MITRE_TECHNIQUES["lateral_smb"], _MITRE_TECHNIQUES["lateral_rdp"]):
            if 445 in dev.open_ports or 3389 in dev.open_ports:
                findings.append(SimulationFinding(
                    finding_type=FindingType.LATERAL_MOVEMENT,
                    severity="high",
                    title=f"Lateral movement possible to {dev.hostname}",
                    description=f"Device has {'SMB (445)' if 445 in dev.open_ports else 'RDP (3389)'} open, enabling lateral movement",
                    affected_devices=[dev.device_id],
                    attack_path=[step_data.get("action", "")],
                    remediation_steps=["Restrict SMB/RDP access via firewall rules", "Enable NLA for RDP", "Implement network segmentation"],
                ))

        # Check for weak credentials indicators
        if technique == _MITRE_TECHNIQUES["brute_force"]:
            findings.append(SimulationFinding(
                finding_type=FindingType.WEAK_CREDENTIALS,
                severity="medium",
                title=f"Credential attack surface on {dev.hostname}",
                description="Device exposes authentication services without rate limiting",
                affected_devices=[dev.device_id],
                remediation_steps=["Implement account lockout policies", "Enable MFA", "Use strong password policies"],
            ))

        # Check unpatched software
        if dev.patch_level not in ("current", "recent") and vuln_match:
            findings.append(SimulationFinding(
                finding_type=FindingType.UNPATCHED_SOFTWARE,
                severity="high",
                title=f"Unpatched software on {dev.hostname}",
                description=f"Device patch level '{dev.patch_level}' with known vulnerabilities present",
                affected_devices=[dev.device_id],
                remediation_steps=["Apply all pending patches", "Enable automatic updates", "Prioritize critical CVE patches"],
            ))

        return findings

    def _assess_network_weaknesses(self, twin: NetworkTwin) -> List[SimulationFinding]:
        """Assess network-level weaknesses in the twin topology."""
        findings = []

        # Check for unencrypted connections
        unencrypted = [c for c in twin.connections if not c.get("is_encrypted", False)]
        if unencrypted:
            findings.append(SimulationFinding(
                finding_type=FindingType.MISSING_ENCRYPTION,
                severity="medium",
                title=f"{len(unencrypted)} unencrypted network connections detected",
                description="Network traffic between devices is not encrypted, enabling sniffing/MITM attacks",
                affected_devices=[],
                remediation_steps=["Enable TLS/IPSec on all inter-device connections", "Implement 802.1X authentication"],
            ))

        # Check for missing firewall rules
        no_fw = [c for c in twin.connections if not c.get("firewall_rules", [])]
        if no_fw:
            findings.append(SimulationFinding(
                finding_type=FindingType.MISCONFIGURATION,
                severity="medium",
                title=f"{len(no_fw)} connections without firewall rules",
                description="Connections lack firewall rules, allowing unrestricted traffic flow",
                affected_devices=[],
                remediation_steps=["Implement micro-segmentation", "Define deny-by-default firewall policies"],
            ))

        return findings

    def _find_all_paths(self, graph: Dict[str, List[str]], start: str,
                        end: str, max_depth: int = 6) -> List[List[str]]:
        """Find all paths between two nodes in the connection graph."""
        paths = []
        stack = [(start, [start])]
        while stack:
            current, path = stack.pop()
            if current == end:
                paths.append(path)
                continue
            if len(path) > max_depth:
                continue
            for neighbor in graph.get(current, []):
                if neighbor not in path:
                    stack.append((neighbor, path + [neighbor]))
        return paths

    def _assess_path_risk(self, path: List[str]) -> float:
        """Assess the risk score of an attack path based on device security."""
        if not path:
            return 0.0
        scores = []
        for dev_id in path:
            dev = self._devices.get(dev_id)
            if dev:
                # Lower device score = higher risk
                scores.append(100 - dev.security_score)
            else:
                scores.append(50)
        # Average vulnerability along path, shorter paths are riskier
        avg_vuln = sum(scores) / len(scores) if scores else 0
        length_factor = max(0.5, 1.0 - (len(path) - 2) * 0.1)
        return round(avg_vuln * length_factor, 1)
