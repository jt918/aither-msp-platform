"""
Tests for Synapse MSP Integration Service
AI-Powered MSP Command Center
"""

import pytest
from services.msp.synapse_msp import (
    SynapseMSPService,
    AdvisorDomain,
    RequestType,
    InsightType,
    MSPAdvisor,
    AdvisoryRequest,
    AdvisoryResponse,
    MSPInsight,
    AutomationRule,
)


@pytest.fixture
def svc():
    """Create a fresh SynapseMSPService instance (in-memory)."""
    return SynapseMSPService()


# ========== Advisor Initialization ==========

class TestAdvisorInitialization:
    """Verify pre-built advisors are seeded correctly."""

    def test_seven_builtin_advisors(self, svc):
        advisors = svc.list_advisors()
        assert len(advisors) == 7

    def test_aegis_security_advisor(self, svc):
        adv = svc.get_advisor("ADV-AEGIS")
        assert adv is not None
        assert adv["name"] == "Aegis"
        assert adv["domain"] == "security"
        assert "threat_analysis" in adv["specializations"]
        assert "MITRE ATT&CK" in adv["knowledge_base"]["frameworks"]

    def test_compliance_oracle(self, svc):
        adv = svc.get_advisor("ADV-COMPLIANCE")
        assert adv is not None
        assert adv["name"] == "Compliance Oracle"
        assert adv["domain"] == "compliance"
        assert "HIPAA" in adv["knowledge_base"]["frameworks"]

    def test_infrastructure_sage(self, svc):
        adv = svc.get_advisor("ADV-INFRA")
        assert adv is not None
        assert adv["domain"] == "infrastructure"

    def test_helpdesk_mentor(self, svc):
        adv = svc.get_advisor("ADV-HELPDESK")
        assert adv is not None
        assert adv["domain"] == "helpdesk"
        assert "P1" in adv["knowledge_base"]["sla_rules"]

    def test_executive_strategist(self, svc):
        adv = svc.get_advisor("ADV-EXEC")
        assert adv is not None
        assert adv["domain"] == "executive"

    def test_network_architect(self, svc):
        adv = svc.get_advisor("ADV-NETWORK")
        assert adv is not None
        assert adv["domain"] == "network"

    def test_cloud_navigator(self, svc):
        adv = svc.get_advisor("ADV-CLOUD")
        assert adv is not None
        assert adv["domain"] == "cloud"
        assert "AWS" in adv["knowledge_base"]["providers"]

    def test_list_by_domain(self, svc):
        security = svc.list_advisors(domain="security")
        assert len(security) == 1
        assert security[0]["name"] == "Aegis"

    def test_get_nonexistent_advisor(self, svc):
        assert svc.get_advisor("ADV-NOPE") is None


# ========== Advisor CRUD ==========

class TestAdvisorCRUD:

    def test_create_custom_advisor(self, svc):
        result = svc.create_advisor(
            name="Custom Bot",
            domain="helpdesk",
            specializations=["password_resets"],
            confidence_threshold=0.9,
        )
        assert result["name"] == "Custom Bot"
        assert result["domain"] == "helpdesk"
        assert result["confidence_threshold"] == 0.9
        assert svc.get_advisor(result["advisor_id"]) is not None

    def test_update_advisor(self, svc):
        result = svc.update_advisor("ADV-AEGIS", {"name": "Aegis v2"})
        assert result is not None
        assert result["name"] == "Aegis v2"

    def test_update_nonexistent(self, svc):
        assert svc.update_advisor("NOPE", {"name": "x"}) is None


# ========== Routing Logic ==========

class TestRoutingLogic:

    def test_ticket_routes_to_helpdesk(self, svc):
        adv = svc._route_to_advisor(RequestType.TICKET_TRIAGE.value)
        assert adv is not None
        assert adv.domain == "helpdesk"

    def test_threat_routes_to_security(self, svc):
        adv = svc._route_to_advisor(RequestType.THREAT_ANALYSIS.value)
        assert adv is not None
        assert adv.domain == "security"

    def test_compliance_routes_correctly(self, svc):
        adv = svc._route_to_advisor(RequestType.COMPLIANCE_CHECK.value)
        assert adv is not None
        assert adv.domain == "compliance"

    def test_capacity_routes_to_infra(self, svc):
        adv = svc._route_to_advisor(RequestType.CAPACITY_PLAN.value)
        assert adv is not None
        assert adv.domain == "infrastructure"

    def test_budget_routes_to_executive(self, svc):
        adv = svc._route_to_advisor(RequestType.BUDGET_FORECAST.value)
        assert adv is not None
        assert adv.domain == "executive"

    def test_unknown_type_returns_none(self, svc):
        adv = svc._route_to_advisor("unknown_type")
        assert adv is None


# ========== Ticket Triage ==========

class TestTicketTriage:

    def test_triage_network_ticket(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.TICKET_TRIAGE.value,
            context={"title": "Internet is down", "description": "Cannot connect to network"},
            urgency="high",
        )
        assert result["status"] == "completed"
        resp = result["response"]
        assert "network" in resp["recommendation"].lower()
        assert "P1" in resp["recommendation"]  # "down" triggers P1

    def test_triage_password_ticket(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.TICKET_TRIAGE.value,
            context={"title": "Password reset needed", "description": "Locked out of account"},
            urgency="medium",
        )
        resp = result["response"]
        assert "access" in resp["recommendation"].lower()
        assert resp["confidence"] > 0.5

    def test_triage_low_priority(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.TICKET_TRIAGE.value,
            context={"title": "Request for new monitor", "description": "Nice to have when possible"},
            urgency="low",
        )
        resp = result["response"]
        assert "P4" in resp["recommendation"]

    def test_triage_returns_advisor_info(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.TICKET_TRIAGE.value,
            context={"title": "Test"},
            urgency="medium",
        )
        assert "advisor" in result
        assert result["advisor"]["name"] == "Helpdesk Mentor"


# ========== Threat Analysis ==========

class TestThreatAnalysis:

    def test_ransomware_critical(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.THREAT_ANALYSIS.value,
            context={
                "threat_type": "ransomware",
                "source_ip": "10.0.0.99",
                "affected_assets": ["server-01", "server-02"],
            },
            urgency="critical",
        )
        resp = result["response"]
        assert resp["confidence"] > 0.8
        assert resp["auto_executable"] is True
        assert "ransomware" in resp["recommendation"].lower()

    def test_phishing_high(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.THREAT_ANALYSIS.value,
            context={"threat_type": "phishing", "affected_assets": ["user-john"]},
            urgency="high",
        )
        resp = result["response"]
        assert "phishing" in resp["recommendation"].lower()

    def test_unknown_threat_handled(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.THREAT_ANALYSIS.value,
            context={"threat_type": "zero_day"},
            urgency="high",
        )
        assert result["status"] == "completed"


# ========== Compliance Checks ==========

class TestComplianceChecks:

    def test_hipaa_compliance_check(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.COMPLIANCE_CHECK.value,
            context={
                "framework": "HIPAA",
                "controls_assessed": 60,
                "controls_passing": 55,
                "gaps": ["encryption_at_rest", "audit_logging"],
            },
        )
        resp = result["response"]
        assert "HIPAA" in resp["recommendation"]
        assert "91.7%" in resp["recommendation"]  # 55/60

    def test_low_compliance_critical_risk(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.COMPLIANCE_CHECK.value,
            context={
                "framework": "SOC2",
                "controls_assessed": 50,
                "controls_passing": 25,
                "gaps": [],
            },
        )
        resp = result["response"]
        assert "critical" in resp["recommendation"].lower()


# ========== Capacity Planning ==========

class TestCapacityPlanning:

    def test_healthy_capacity(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.CAPACITY_PLAN.value,
            context={"cpu_avg": 40, "memory_avg": 50, "disk_usage": 60, "growth_rate_pct": 2},
        )
        resp = result["response"]
        assert resp["confidence"] > 0.5
        assert "Warnings: 0" in resp["recommendation"]

    def test_critical_cpu(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.CAPACITY_PLAN.value,
            context={"cpu_avg": 95, "memory_avg": 50, "disk_usage": 60},
        )
        resp = result["response"]
        assert "CPU" in resp["recommendation"]


# ========== Root Cause Analysis ==========

class TestRootCauseAnalysis:

    def test_root_cause_simple(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.ROOT_CAUSE_ANALYSIS.value,
            context={
                "description": "Web app down",
                "affected_services": ["web_app", "api_gateway", "database"],
                "dependencies": {
                    "web_app": ["api_gateway"],
                    "api_gateway": ["database"],
                    "database": [],
                },
                "timeline": [{"time": "10:00", "event": "DB connection pool exhausted"}],
            },
        )
        resp = result["response"]
        assert "database" in resp["recommendation"].lower()


# ========== Remediation Planning ==========

class TestRemediationPlan:

    def test_remediation_with_vulns(self, svc):
        result = svc.request_advisory(
            request_type=RequestType.REMEDIATION_PLAN.value,
            context={
                "vulnerabilities": [
                    {"cve": "CVE-2024-001", "severity": "critical"},
                    {"cve": "CVE-2024-002", "severity": "high"},
                    {"cve": "CVE-2024-003", "severity": "medium"},
                ],
                "total_hosts": 10,
            },
        )
        resp = result["response"]
        assert "critical" in resp["recommendation"].lower()
        assert resp["confidence"] > 0.7


# ========== Insight Generation ==========

class TestInsightGeneration:

    def test_generate_insights(self, svc):
        insights = svc.generate_insights("CLIENT-001")
        assert len(insights) >= 3

    def test_insight_types_present(self, svc):
        insights = svc.generate_insights("CLIENT-002")
        types = {i["insight_type"] for i in insights}
        assert "anomaly" in types
        assert "trend" in types
        assert "opportunity" in types

    def test_insight_has_required_fields(self, svc):
        insights = svc.generate_insights("CLIENT-003")
        for ins in insights:
            assert "insight_id" in ins
            assert "title" in ins
            assert "severity" in ins
            assert "data_points" in ins


# ========== Anomaly Detection ==========

class TestAnomalyDetection:

    def test_no_anomalies_normal_data(self, svc):
        result = svc._detect_anomalies([10, 11, 10, 12, 11, 10])
        assert len(result["anomalies"]) == 0

    def test_detects_spike(self, svc):
        result = svc._detect_anomalies([10, 11, 10, 12, 11, 50])
        assert len(result["anomalies"]) > 0

    def test_insufficient_data(self, svc):
        result = svc._detect_anomalies([10])
        assert result["status"] == "insufficient_data"


# ========== Trend Prediction ==========

class TestTrendPrediction:

    def test_increasing_trend(self, svc):
        result = svc._predict_trends([10, 15, 20, 25, 30])
        assert result["direction"] == "increasing"
        assert result["projected_next"] > 30

    def test_stable_trend(self, svc):
        result = svc._predict_trends([10, 10, 10, 10])
        assert result["direction"] == "stable"

    def test_insufficient_data(self, svc):
        result = svc._predict_trends([10])
        assert result["trend"] == "insufficient_data"


# ========== Opportunity Identification ==========

class TestOpportunities:

    def test_finds_atp_opportunity(self, svc):
        opps = svc._identify_opportunities({
            "current_services": ["basic_monitoring"],
            "endpoint_count": 20,
        })
        atp = [o for o in opps if o["service"] == "Advanced Threat Protection"]
        assert len(atp) == 1
        assert atp[0]["estimated_mrr"] == 600

    def test_finds_backup_opportunity(self, svc):
        opps = svc._identify_opportunities({
            "current_services": [],
            "endpoint_count": 10,
        })
        backup = [o for o in opps if o["service"] == "Managed Backup & DR"]
        assert len(backup) == 1

    def test_compliance_for_healthcare(self, svc):
        opps = svc._identify_opportunities({
            "current_services": [],
            "endpoint_count": 5,
            "industry": "healthcare",
        })
        comp = [o for o in opps if o["service"] == "Continuous Compliance Monitoring"]
        assert len(comp) == 1


# ========== Automation Rules ==========

class TestAutomationRules:

    def test_create_rule(self, svc):
        rule = svc.create_automation_rule(
            name="Auto-triage new tickets",
            trigger_event="ticket_created",
            condition={"category": "network"},
            advisor_domain="helpdesk",
            action={"request_type": "ticket_triage", "urgency": "medium"},
        )
        assert rule["name"] == "Auto-triage new tickets"
        assert rule["is_enabled"] is True

    def test_list_rules(self, svc):
        svc.create_automation_rule("R1", "e1", {}, "helpdesk", {})
        svc.create_automation_rule("R2", "e2", {}, "security", {})
        rules = svc.list_rules()
        assert len(rules) == 2

    def test_toggle_rule(self, svc):
        rule = svc.create_automation_rule("R1", "e1", {}, "helpdesk", {})
        toggled = svc.toggle_rule(rule["rule_id"])
        assert toggled["is_enabled"] is False
        toggled2 = svc.toggle_rule(rule["rule_id"])
        assert toggled2["is_enabled"] is True

    def test_toggle_nonexistent(self, svc):
        assert svc.toggle_rule("NOPE") is None

    def test_update_rule(self, svc):
        rule = svc.create_automation_rule("R1", "e1", {}, "helpdesk", {})
        updated = svc.update_rule(rule["rule_id"], {"name": "Updated"})
        assert updated["name"] == "Updated"

    def test_process_event_triggers_rule(self, svc):
        svc.create_automation_rule(
            name="Threat auto-analyze",
            trigger_event="threat_detected",
            condition={"severity": "critical"},
            advisor_domain="security",
            action={"request_type": "threat_analysis", "urgency": "critical"},
        )
        results = svc.process_event({
            "event_type": "threat_detected",
            "data": {"severity": "critical", "threat_type": "ransomware"},
        })
        assert len(results) == 1
        assert results[0]["rule_name"] == "Threat auto-analyze"

    def test_process_event_no_match(self, svc):
        svc.create_automation_rule("R1", "ticket_created", {}, "helpdesk", {})
        results = svc.process_event({"event_type": "other_event", "data": {}})
        assert len(results) == 0

    def test_disabled_rule_not_triggered(self, svc):
        rule = svc.create_automation_rule("R1", "e1", {}, "helpdesk", {
            "request_type": "ticket_triage",
        })
        svc.toggle_rule(rule["rule_id"])  # disable
        results = svc.process_event({"event_type": "e1", "data": {}})
        assert len(results) == 0


# ========== Accuracy Tracking ==========

class TestAccuracyTracking:

    def test_rate_advisory_helpful(self, svc):
        result = svc.request_advisory(
            RequestType.TICKET_TRIAGE.value,
            {"title": "test"},
        )
        resp_id = result["response"]["response_id"]
        rating = svc.rate_advisory(resp_id, was_helpful=True, feedback="Spot on")
        assert rating["rated"] is True
        assert rating["was_helpful"] is True

    def test_accuracy_updates(self, svc):
        r1 = svc.request_advisory(RequestType.TICKET_TRIAGE.value, {"title": "a"})
        r2 = svc.request_advisory(RequestType.TICKET_TRIAGE.value, {"title": "b"})
        svc.rate_advisory(r1["response"]["response_id"], True)
        svc.rate_advisory(r2["response"]["response_id"], False)
        accuracy = svc.get_advisor_accuracy()
        helpdesk = accuracy.get("ADV-HELPDESK", {})
        assert helpdesk["rated_responses"] == 2
        assert helpdesk["accuracy_rate"] == 0.5

    def test_rate_nonexistent(self, svc):
        result = svc.rate_advisory("NOPE", True)
        assert "error" in result


# ========== Execution ==========

class TestExecution:

    def test_execute_auto_executable(self, svc):
        result = svc.request_advisory(
            RequestType.TICKET_TRIAGE.value,
            {"title": "Nice to have request when possible"},
        )
        resp_id = result["response"]["response_id"]
        exec_result = svc.execute_advisory(resp_id)
        assert exec_result["executed"] is True

    def test_execute_nonexistent(self, svc):
        result = svc.execute_advisory("NOPE")
        assert "error" in result


# ========== Advisory History ==========

class TestAdvisoryHistory:

    def test_history_returns_responses(self, svc):
        svc.request_advisory(RequestType.TICKET_TRIAGE.value, {"title": "a"})
        svc.request_advisory(RequestType.THREAT_ANALYSIS.value, {"threat_type": "malware"})
        history = svc.get_advisory_history()
        assert len(history) == 2

    def test_history_filter_by_advisor(self, svc):
        svc.request_advisory(RequestType.TICKET_TRIAGE.value, {"title": "a"})
        svc.request_advisory(RequestType.THREAT_ANALYSIS.value, {"threat_type": "x"})
        history = svc.get_advisory_history(advisor_id="ADV-HELPDESK")
        assert all(h["advisor_id"] == "ADV-HELPDESK" for h in history)

    def test_deferred_when_no_advisor(self, svc):
        result = svc.request_advisory("unknown_type_xyz", {"data": "x"})
        assert result["status"] == "deferred"


# ========== Dashboard ==========

class TestDashboard:

    def test_dashboard_structure(self, svc):
        dash = svc.get_dashboard()
        assert "advisors" in dash
        assert "advisories" in dash
        assert "accuracy" in dash
        assert "insights" in dash
        assert "automation" in dash
        assert dash["advisors"]["total"] == 7

    def test_dashboard_after_activity(self, svc):
        svc.request_advisory(RequestType.TICKET_TRIAGE.value, {"title": "test"})
        svc.generate_insights("C1")
        svc.create_automation_rule("R1", "e1", {}, "helpdesk", {})
        dash = svc.get_dashboard()
        assert dash["advisories"]["total"] >= 1
        assert dash["insights"]["total"] >= 3
        assert dash["automation"]["total_rules"] >= 1


# ========== Dataclass Defaults ==========

class TestDataclasses:

    def test_advisor_default_timestamp(self):
        a = MSPAdvisor(advisor_id="X", name="T", domain="helpdesk")
        assert a.created_at != ""

    def test_request_default_timestamp(self):
        r = AdvisoryRequest(request_id="X")
        assert r.created_at != ""

    def test_insight_default_timestamp(self):
        i = MSPInsight(insight_id="X")
        assert i.generated_at != ""

    def test_rule_defaults(self):
        r = AutomationRule(rule_id="X")
        assert r.is_enabled is True
        assert r.executions == 0
