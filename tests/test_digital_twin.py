"""
Tests for Digital Twin Network Simulation Service
Full coverage: twin creation, device CRUD, simulation lifecycle,
red/blue/purple team, attack paths, blast radius, posture scoring,
scenarios, dashboard.
"""

import pytest
from datetime import datetime

from services.msp.digital_twin import (
    DigitalTwinService,
    SimulationType,
    FindingSeverity,
    FindingType,
    AttackType,
    NetworkTwin,
    TwinDevice,
    TwinConnection,
    TwinVulnerability,
    SimulationRun,
    SimulationFinding,
    AttackScenario,
    AttackStep,
    ATTACK_SCENARIOS,
)


# ============================================================
# Test fixtures
# ============================================================

def _sample_devices():
    """Return a list of sample device dicts for twin creation."""
    return [
        {
            "hostname": "DC-01",
            "ip_address": "192.168.1.10",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "device_type": "server",
            "os_type": "Windows Server",
            "os_version": "2019",
            "open_ports": [445, 3389, 135, 139],
            "services_running": ["smb", "rdp", "netlogon"],
            "is_critical_asset": True,
        },
        {
            "hostname": "WEB-01",
            "ip_address": "192.168.1.20",
            "mac_address": "AA:BB:CC:DD:EE:02",
            "device_type": "server",
            "os_type": "Linux",
            "os_version": "Ubuntu 22.04",
            "open_ports": [80, 443, 22],
            "services_running": ["http", "https", "ssh"],
            "is_critical_asset": True,
        },
        {
            "hostname": "WS-001",
            "ip_address": "192.168.1.100",
            "mac_address": "AA:BB:CC:DD:EE:03",
            "device_type": "workstation",
            "os_type": "Windows",
            "os_version": "10",
            "open_ports": [445, 3389],
            "services_running": ["smb", "rdp"],
            "is_critical_asset": False,
        },
        {
            "hostname": "FW-01",
            "ip_address": "192.168.1.1",
            "mac_address": "AA:BB:CC:DD:EE:04",
            "device_type": "firewall",
            "os_type": "FortiOS",
            "os_version": "7.0",
            "open_ports": [443],
            "services_running": ["https", "fortios_vpn"],
            "is_critical_asset": True,
        },
    ]


def _sample_connections():
    """Return sample connection dicts (source/target will be overwritten)."""
    return [
        {
            "source_device_id": "placeholder-1",
            "target_device_id": "placeholder-2",
            "connection_type": "ethernet",
            "bandwidth_mbps": 1000.0,
            "is_encrypted": True,
            "firewall_rules": ["allow_https", "deny_telnet"],
        },
    ]


class TestDigitalTwinService:
    """Tests for DigitalTwinService"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = DigitalTwinService()

    # ========== Twin Creation ==========

    def test_create_twin_manual(self):
        """Test manual twin creation with devices and connections"""
        result = self.service.create_twin_manual(
            client_id="CLIENT-001",
            name="Test Office Network",
            devices=_sample_devices(),
        )
        assert result is not None
        assert result["client_id"] == "CLIENT-001"
        assert result["name"] == "Test Office Network"
        assert result["created_from"] == "manual"
        assert len(result["devices"]) == 4
        assert result["twin_id"] is not None

    def test_create_twin_from_discovery(self):
        """Test auto-creation from discovery scan"""
        result = self.service.create_twin_from_discovery(
            client_id="CLIENT-002",
            discovery_scan_id="SCAN-ABC123",
            discovered_devices=_sample_devices()[:2],
        )
        assert result is not None
        assert result["client_id"] == "CLIENT-002"
        assert result["created_from"] == "SCAN-ABC123"
        assert len(result["devices"]) == 2
        assert len(result["subnets"]) >= 1

    def test_create_twin_auto_connects_same_subnet(self):
        """Devices on same subnet should be auto-connected"""
        result = self.service.create_twin_from_discovery(
            client_id="CLIENT-003",
            discovery_scan_id="SCAN-DEF456",
            discovered_devices=_sample_devices(),
        )
        # All 4 devices are on 192.168.1.x, should have connections
        assert len(result["connections"]) >= 1

    # ========== Twin CRUD ==========

    def test_get_twin(self):
        """Test retrieving a twin by ID"""
        created = self.service.create_twin_manual("CLIENT-001", "Test Net")
        twin_id = created["twin_id"]
        result = self.service.get_twin(twin_id)
        assert result is not None
        assert result["twin_id"] == twin_id

    def test_get_twin_not_found(self):
        """Test retrieving a non-existent twin"""
        result = self.service.get_twin("non-existent-id")
        assert result is None

    def test_list_twins(self):
        """Test listing all twins"""
        self.service.create_twin_manual("CLIENT-001", "Net A")
        self.service.create_twin_manual("CLIENT-002", "Net B")
        results = self.service.list_twins()
        assert len(results) >= 2

    def test_list_twins_filtered_by_client(self):
        """Test listing twins filtered by client_id"""
        self.service.create_twin_manual("CLIENT-X", "Net X")
        self.service.create_twin_manual("CLIENT-Y", "Net Y")
        results = self.service.list_twins(client_id="CLIENT-X")
        assert all(r["client_id"] == "CLIENT-X" for r in results)

    def test_update_twin(self):
        """Test updating twin metadata"""
        created = self.service.create_twin_manual("CLIENT-001", "Old Name")
        result = self.service.update_twin(created["twin_id"], {"name": "New Name", "description": "Updated"})
        assert result is not None
        assert result["name"] == "New Name"
        assert result["description"] == "Updated"

    def test_delete_twin(self):
        """Test deleting a twin"""
        created = self.service.create_twin_manual("CLIENT-001", "To Delete")
        twin_id = created["twin_id"]
        assert self.service.delete_twin(twin_id) is True
        assert self.service.get_twin(twin_id) is None

    def test_delete_twin_not_found(self):
        """Test deleting a non-existent twin"""
        assert self.service.delete_twin("non-existent") is False

    # ========== Device CRUD ==========

    def test_add_device(self):
        """Test adding a device to a twin"""
        created = self.service.create_twin_manual("CLIENT-001", "Net")
        result = self.service.add_device(created["twin_id"], {
            "hostname": "NEW-SRV",
            "ip_address": "192.168.1.50",
            "device_type": "server",
            "open_ports": [80, 443],
        })
        assert result is not None
        assert result["hostname"] == "NEW-SRV"
        assert "http" in result["services_running"]

    def test_add_device_twin_not_found(self):
        """Test adding a device to non-existent twin"""
        result = self.service.add_device("non-existent", {"hostname": "X"})
        assert result is None

    def test_update_device(self):
        """Test updating a device"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        device_id = created["devices"][0]["device_id"]
        result = self.service.update_device(device_id, {"hostname": "RENAMED-DC"})
        assert result is not None
        assert result["hostname"] == "RENAMED-DC"

    def test_remove_device(self):
        """Test removing a device from a twin"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        device_id = created["devices"][0]["device_id"]
        original_count = len(created["devices"])
        assert self.service.remove_device(twin_id, device_id) is True
        updated = self.service.get_twin(twin_id)
        assert len(updated["devices"]) == original_count - 1

    # ========== Connection Management ==========

    def test_add_connection(self):
        """Test adding a connection between devices"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        dev_a = created["devices"][0]["device_id"]
        dev_b = created["devices"][1]["device_id"]
        result = self.service.add_connection(twin_id, {
            "source_device_id": dev_a,
            "target_device_id": dev_b,
            "connection_type": "vpn",
            "is_encrypted": True,
        })
        assert result is not None
        assert result["connection_type"] == "vpn"
        assert result["is_encrypted"] is True

    def test_remove_connection(self):
        """Test removing a connection"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        dev_a = created["devices"][0]["device_id"]
        dev_b = created["devices"][1]["device_id"]
        conn = self.service.add_connection(twin_id, {
            "source_device_id": dev_a,
            "target_device_id": dev_b,
        })
        assert self.service.remove_connection(twin_id, conn["connection_id"]) is True

    # ========== Vulnerability Scanning ==========

    def test_scan_device_vulnerabilities(self):
        """Test vulnerability scanning on a device with known services"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        # DC-01 has smb, rdp, netlogon -- should find EternalBlue, BlueKeep, Zerologon
        device_id = created["devices"][0]["device_id"]
        result = self.service.scan_device_vulnerabilities(device_id)
        assert result["vulnerabilities_found"] > 0
        cve_ids = [v["cve_id"] for v in result["vulnerabilities"]]
        assert "CVE-2017-0144" in cve_ids  # EternalBlue via SMB
        assert "CVE-2019-0708" in cve_ids  # BlueKeep via RDP
        assert "CVE-2020-1472" in cve_ids  # Zerologon via netlogon

    def test_scan_device_not_found(self):
        """Test scanning a non-existent device"""
        result = self.service.scan_device_vulnerabilities("non-existent")
        assert "error" in result

    def test_scan_updates_security_score(self):
        """Vulnerability scan should lower device security score"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        device_id = created["devices"][0]["device_id"]
        result = self.service.scan_device_vulnerabilities(device_id)
        # Device with critical vulns should have lower score
        assert result["security_score"] < 100

    # ========== Red Team Simulation ==========

    def test_run_red_team_simulation(self):
        """Test running a red team simulation"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        # Scan devices first so they have vulnerabilities
        for d in created["devices"]:
            self.service.scan_device_vulnerabilities(d["device_id"])

        result = self.service.run_red_team_simulation(twin_id, "SCENARIO-001")
        assert result["sim_type"] == "red_team"
        assert result["status"] == "completed"
        assert result["attack_vectors_tested"] > 0
        assert result["score_after"] <= result["score_before"]

    def test_run_red_team_random_scenario(self):
        """Test red team with no scenario (random selection)"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        result = self.service.run_red_team_simulation(created["twin_id"])
        assert result["status"] == "completed"

    def test_run_red_team_twin_not_found(self):
        """Test red team on non-existent twin"""
        result = self.service.run_red_team_simulation("non-existent")
        assert "error" in result

    # ========== Blue Team Simulation ==========

    def test_run_blue_team_simulation(self):
        """Test running a blue team simulation"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        for d in created["devices"]:
            self.service.scan_device_vulnerabilities(d["device_id"])

        # Run red team first
        red_result = self.service.run_red_team_simulation(twin_id, "SCENARIO-002")
        # Then blue team
        blue_result = self.service.run_blue_team_simulation(twin_id, red_result.get("findings", []))
        assert blue_result["sim_type"] == "blue_team"
        assert blue_result["status"] == "completed"
        assert blue_result["score_after"] >= blue_result["score_before"]

    def test_run_blue_team_no_findings(self):
        """Test blue team with no explicit findings (uses latest red team)"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        self.service.run_red_team_simulation(twin_id)
        result = self.service.run_blue_team_simulation(twin_id)
        assert result["status"] == "completed"

    # ========== Purple Team Simulation ==========

    def test_run_purple_team(self):
        """Test combined red + blue team assessment"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        for d in created["devices"]:
            self.service.scan_device_vulnerabilities(d["device_id"])

        result = self.service.run_purple_team(twin_id, "SCENARIO-001")
        assert "purple_team_sim" in result
        assert result["purple_team_sim"]["sim_type"] == "purple_team"
        assert result["red_team_sim_id"] is not None
        assert result["blue_team_sim_id"] is not None
        assert result["post_defense_score"] >= result["post_attack_score"]

    def test_run_purple_team_twin_not_found(self):
        """Test purple team on non-existent twin"""
        result = self.service.run_purple_team("non-existent")
        assert "error" in result

    # ========== Security Posture ==========

    def test_calculate_security_posture(self):
        """Test posture calculation"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        result = self.service.calculate_security_posture(twin_id)
        assert "score" in result
        assert "breakdown" in result
        assert 0 <= result["score"] <= 100

    def test_calculate_posture_with_vulns(self):
        """Posture should be lower after vulnerabilities are found"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        initial = self.service.calculate_security_posture(twin_id)
        for d in created["devices"]:
            self.service.scan_device_vulnerabilities(d["device_id"])
        after_scan = self.service.calculate_security_posture(twin_id)
        assert after_scan["score"] <= initial["score"]

    # ========== Attack Path Analysis ==========

    def test_get_attack_path_analysis(self):
        """Test finding attack paths to a target device"""
        created = self.service.create_twin_from_discovery(
            "CLIENT-001", "SCAN-001", _sample_devices()
        )
        twin_id = created["twin_id"]
        target_id = created["devices"][0]["device_id"]
        result = self.service.get_attack_path_analysis(twin_id, target_id)
        assert "attack_paths" in result
        assert "total_paths" in result
        assert result["target_device_id"] == target_id

    def test_attack_path_twin_not_found(self):
        """Test attack path on non-existent twin"""
        result = self.service.get_attack_path_analysis("non-existent", "dev-1")
        assert "error" in result

    # ========== Blast Radius ==========

    def test_get_blast_radius(self):
        """Test blast radius from compromised device"""
        created = self.service.create_twin_from_discovery(
            "CLIENT-001", "SCAN-001", _sample_devices()
        )
        twin_id = created["twin_id"]
        compromised_id = created["devices"][1]["device_id"]
        result = self.service.get_blast_radius(twin_id, compromised_id)
        assert "reachable_devices" in result
        assert "blast_radius_percentage" in result
        assert result["total_reachable"] >= 0

    def test_blast_radius_twin_not_found(self):
        """Test blast radius on non-existent twin"""
        result = self.service.get_blast_radius("non-existent", "dev-1")
        assert "error" in result

    # ========== Posture Trend ==========

    def test_compare_posture_over_time(self):
        """Test posture trend tracking after multiple simulations"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        self.service.run_red_team_simulation(twin_id)
        self.service.run_blue_team_simulation(twin_id)
        result = self.service.compare_posture_over_time(twin_id)
        assert result["total_simulations"] >= 2
        assert len(result["trend"]) >= 2

    # ========== Scenarios ==========

    def test_list_scenarios(self):
        """Test listing all attack scenarios"""
        scenarios = self.service.list_scenarios()
        assert len(scenarios) == 8  # 8 pre-built scenarios

    def test_get_scenario(self):
        """Test getting a specific scenario"""
        result = self.service.get_scenario("SCENARIO-001")
        assert result is not None
        assert result["name"] == "Ransomware Propagation"
        assert result["attack_type"] == AttackType.RANSOMWARE_PROPAGATION
        assert len(result["steps"]) == 4

    def test_get_scenario_not_found(self):
        """Test getting non-existent scenario"""
        result = self.service.get_scenario("non-existent")
        assert result is None

    def test_all_scenarios_have_steps(self):
        """All 8 scenarios should have attack steps with MITRE technique IDs"""
        for sc in ATTACK_SCENARIOS:
            assert len(sc.steps) >= 3
            for step in sc.steps:
                assert step.get("technique_id", "") != ""

    # ========== Simulation Retrieval ==========

    def test_get_simulation(self):
        """Test retrieving a simulation by ID"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        sim = self.service.run_red_team_simulation(created["twin_id"])
        result = self.service.get_simulation(sim["sim_id"])
        assert result is not None
        assert result["sim_id"] == sim["sim_id"]

    def test_list_simulations(self):
        """Test listing simulations"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        self.service.run_red_team_simulation(twin_id)
        self.service.run_blue_team_simulation(twin_id)
        results = self.service.list_simulations(twin_id=twin_id)
        assert len(results) >= 2

    def test_list_simulations_by_type(self):
        """Test listing simulations filtered by type"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", _sample_devices())
        twin_id = created["twin_id"]
        self.service.run_red_team_simulation(twin_id)
        self.service.run_blue_team_simulation(twin_id)
        red_only = self.service.list_simulations(sim_type="red_team")
        assert all(s["sim_type"] == "red_team" for s in red_only)

    # ========== Dashboard ==========

    def test_get_dashboard(self):
        """Test client dashboard"""
        client_id = "CLIENT-DASH"
        self.service.create_twin_manual(client_id, "Net A", _sample_devices())
        self.service.create_twin_manual(client_id, "Net B", _sample_devices()[:2])
        dashboard = self.service.get_dashboard(client_id)
        assert dashboard["client_id"] == client_id
        assert dashboard["twin_count"] == 2
        assert dashboard["total_devices"] >= 6
        assert dashboard["scenarios_available"] == 8

    def test_get_dashboard_empty_client(self):
        """Test dashboard for client with no twins"""
        dashboard = self.service.get_dashboard("NO-TWINS-CLIENT")
        assert dashboard["twin_count"] == 0
        assert dashboard["average_posture_score"] == 0

    # ========== Dataclass Construction ==========

    def test_twin_vulnerability_defaults(self):
        """Test TwinVulnerability auto-generates vuln_id and timestamp"""
        v = TwinVulnerability(title="Test Vuln")
        assert v.vuln_id != ""
        assert v.discovered_at != ""

    def test_twin_device_defaults(self):
        """Test TwinDevice auto-generates device_id"""
        d = TwinDevice(hostname="test")
        assert d.device_id != ""

    def test_twin_connection_defaults(self):
        """Test TwinConnection auto-generates connection_id"""
        c = TwinConnection()
        assert c.connection_id != ""

    def test_attack_scenario_defaults(self):
        """Test AttackScenario auto-generates scenario_id"""
        s = AttackScenario(name="Test")
        assert s.scenario_id != ""

    def test_simulation_run_defaults(self):
        """Test SimulationRun auto-generates sim_id"""
        s = SimulationRun()
        assert s.sim_id != ""

    def test_simulation_finding_defaults(self):
        """Test SimulationFinding auto-generates finding_id"""
        f = SimulationFinding()
        assert f.finding_id != ""

    # ========== Enum Values ==========

    def test_simulation_types(self):
        """Test SimulationType enum values"""
        assert SimulationType.RED_TEAM == "red_team"
        assert SimulationType.BLUE_TEAM == "blue_team"
        assert SimulationType.PURPLE_TEAM == "purple_team"
        assert SimulationType.STRESS_TEST == "stress_test"
        assert SimulationType.DISASTER_RECOVERY == "disaster_recovery"

    def test_finding_types(self):
        """Test FindingType enum values"""
        assert FindingType.VULNERABILITY == "vulnerability"
        assert FindingType.LATERAL_MOVEMENT == "lateral_movement"
        assert FindingType.MISSING_ENCRYPTION == "missing_encryption"

    def test_attack_types(self):
        """Test AttackType enum values"""
        assert AttackType.RANSOMWARE_PROPAGATION == "ransomware_propagation"
        assert AttackType.INSIDER_THREAT == "insider_threat"
        assert len(AttackType) == 8

    # ========== Service Port Inference ==========

    def test_port_to_service_inference(self):
        """Devices should auto-infer services from open ports"""
        created = self.service.create_twin_manual("CLIENT-001", "Net", [
            {"hostname": "test", "ip_address": "10.0.0.1", "open_ports": [80, 443, 22, 3306]},
        ])
        dev = created["devices"][0]
        assert "http" in dev["services_running"]
        assert "https" in dev["services_running"]
        assert "ssh" in dev["services_running"]
        assert "mysql" in dev["services_running"]

    # ========== Subnet Extraction ==========

    def test_subnet_extraction(self):
        """Test subnet extraction from IP"""
        assert DigitalTwinService._subnet_from_ip("192.168.1.100") == "192.168.1.0/24"
        assert DigitalTwinService._subnet_from_ip("10.0.0.50") == "10.0.0.0/24"
        assert DigitalTwinService._subnet_from_ip("invalid") == "unknown"
