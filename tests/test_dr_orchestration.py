"""
Tests for Disaster Recovery Orchestration Service
Full coverage: plan CRUD, steps, drills, failover, readiness, compliance,
validation, calendar, dashboard, and template.
"""

import pytest
from datetime import datetime, timezone, timedelta

import importlib, sys, os
# Direct-load the module file to avoid __init__.py re-export chain
_mod_path = os.path.join(os.path.dirname(__file__), os.pardir, "services_msp", "dr_orchestration.py")
_spec = importlib.util.spec_from_file_location("dr_orchestration", os.path.abspath(_mod_path))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

DROrchestrationService = _mod.DROrchestrationService
DRTier = _mod.DRTier
DrillType = _mod.DrillType
DrillStatus = _mod.DrillStatus
FailoverStatus = _mod.FailoverStatus
StepActionType = _mod.StepActionType
PlanStatus = _mod.PlanStatus
STANDARD_BC_TEMPLATE_STEPS = _mod.STANDARD_BC_TEMPLATE_STEPS
_plan_to_dict = _mod._plan_to_dict
_drill_to_dict = _mod._drill_to_dict
_failover_to_dict = _mod._failover_to_dict
_readiness_to_dict = _mod._readiness_to_dict
_step_to_dict = _mod._step_to_dict


@pytest.fixture
def svc():
    """Fresh DROrchestrationService instance (in-memory mode)."""
    return DROrchestrationService()


@pytest.fixture
def svc_with_plan(svc):
    """Service with one active plan."""
    plan = svc.create_plan(
        name="Production DR",
        client_id="CLIENT-001",
        description="Main production DR plan",
        tier=DRTier.TIER1_CRITICAL.value,
        rto_minutes=60,
        rpo_minutes=15,
        systems_covered=["app-server", "db-server", "file-server"],
        contacts=[{"name": "John Doe", "role": "Incident Commander", "phone": "555-0100"}],
        use_template=True,
    )
    svc.update_plan(plan.plan_id, status=PlanStatus.ACTIVE.value)
    return svc, plan


# ============================================================
# Plan CRUD
# ============================================================

class TestPlanCRUD:
    def test_create_plan(self, svc):
        plan = svc.create_plan(name="Test DR Plan", client_id="C1")
        assert plan.plan_id.startswith("DRP-")
        assert plan.name == "Test DR Plan"
        assert plan.client_id == "C1"
        assert plan.status == PlanStatus.DRAFT.value
        assert plan.tier == DRTier.TIER3_NORMAL.value

    def test_create_plan_with_template(self, svc):
        plan = svc.create_plan(name="Templated Plan", use_template=True)
        assert len(plan.runbook_steps) == 10
        assert plan.runbook_steps[0]["title"] == "Assess Situation"
        assert plan.runbook_steps[9]["title"] == "Post-Incident Review"

    def test_create_plan_without_template(self, svc):
        plan = svc.create_plan(name="Empty Plan")
        assert len(plan.runbook_steps) == 0

    def test_get_plan(self, svc):
        plan = svc.create_plan(name="Get Me")
        fetched = svc.get_plan(plan.plan_id)
        assert fetched is not None
        assert fetched.name == "Get Me"

    def test_get_plan_not_found(self, svc):
        assert svc.get_plan("DRP-NONEXIST") is None

    def test_list_plans(self, svc):
        svc.create_plan(name="P1", client_id="C1")
        svc.create_plan(name="P2", client_id="C2")
        svc.create_plan(name="P3", client_id="C1")
        assert len(svc.list_plans()) == 3
        assert len(svc.list_plans(client_id="C1")) == 2
        assert len(svc.list_plans(client_id="C2")) == 1

    def test_list_plans_by_status(self, svc):
        p1 = svc.create_plan(name="P1")
        svc.update_plan(p1.plan_id, status=PlanStatus.ACTIVE.value)
        svc.create_plan(name="P2")  # stays draft
        assert len(svc.list_plans(status=PlanStatus.ACTIVE.value)) == 1
        assert len(svc.list_plans(status=PlanStatus.DRAFT.value)) == 1

    def test_update_plan(self, svc):
        plan = svc.create_plan(name="Original")
        updated = svc.update_plan(plan.plan_id, name="Updated", rto_minutes=30)
        assert updated.name == "Updated"
        assert updated.rto_minutes == 30
        assert updated.updated_at is not None

    def test_update_plan_not_found(self, svc):
        assert svc.update_plan("DRP-NONEXIST", name="X") is None

    def test_delete_plan(self, svc):
        plan = svc.create_plan(name="Delete Me")
        assert svc.delete_plan(plan.plan_id) is True
        assert svc.get_plan(plan.plan_id) is None

    def test_delete_plan_not_found(self, svc):
        assert svc.delete_plan("DRP-NONEXIST") is False

    def test_plan_to_dict(self, svc):
        plan = svc.create_plan(name="Dict Test", client_id="C1", tier=DRTier.TIER1_CRITICAL.value)
        d = _plan_to_dict(plan)
        assert d["name"] == "Dict Test"
        assert d["client_id"] == "C1"
        assert d["tier"] == "tier1_critical"
        assert "created_at" in d


# ============================================================
# Step Management
# ============================================================

class TestStepManagement:
    def test_add_step(self, svc):
        plan = svc.create_plan(name="Steps Plan")
        result = svc.add_step(plan.plan_id, {
            "title": "Step One",
            "description": "Do the thing",
            "responsible": "Admin",
            "action_type": StepActionType.MANUAL.value,
        })
        assert result is not None
        assert len(result.runbook_steps) == 1
        assert result.runbook_steps[0]["step_number"] == 1

    def test_add_multiple_steps(self, svc):
        plan = svc.create_plan(name="Multi Steps")
        svc.add_step(plan.plan_id, {"title": "First"})
        svc.add_step(plan.plan_id, {"title": "Second"})
        svc.add_step(plan.plan_id, {"title": "Third"})
        assert len(plan.runbook_steps) == 3
        assert plan.runbook_steps[2]["step_number"] == 3

    def test_add_step_not_found(self, svc):
        assert svc.add_step("DRP-NONEXIST", {"title": "X"}) is None

    def test_reorder_steps(self, svc):
        plan = svc.create_plan(name="Reorder Plan")
        svc.add_step(plan.plan_id, {"step_number": 1, "title": "A"})
        svc.add_step(plan.plan_id, {"step_number": 2, "title": "B"})
        svc.add_step(plan.plan_id, {"step_number": 3, "title": "C"})
        result = svc.reorder_steps(plan.plan_id, [3, 1, 2])
        assert result.runbook_steps[0]["title"] == "C"
        assert result.runbook_steps[0]["step_number"] == 1
        assert result.runbook_steps[1]["title"] == "A"
        assert result.runbook_steps[2]["title"] == "B"

    def test_reorder_steps_not_found(self, svc):
        assert svc.reorder_steps("DRP-NONEXIST", [1, 2]) is None


# ============================================================
# Drill Management
# ============================================================

class TestDrillManagement:
    def test_schedule_drill(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id, DrillType.TABLETOP.value, participants=["Alice", "Bob"])
        assert drill.drill_id.startswith("DRD-")
        assert drill.status == DrillStatus.SCHEDULED.value
        assert drill.steps_total == 10  # template has 10 steps
        assert drill.participants == ["Alice", "Bob"]

    def test_schedule_drill_plan_not_found(self, svc):
        assert svc.schedule_drill("DRP-NONEXIST") is None

    def test_start_drill(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        started = svc.start_drill(drill.drill_id)
        assert started.status == DrillStatus.IN_PROGRESS.value
        assert started.started_at is not None

    def test_start_drill_not_found(self, svc):
        assert svc.start_drill("DRD-NONEXIST") is None

    def test_complete_drill_step(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        result = svc.complete_drill_step(drill.drill_id, 1, "pass")
        assert result.steps_completed == 1

    def test_complete_drill_step_fail_finding(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        svc.complete_drill_step(drill.drill_id, 1, "DNS resolution slow")
        assert len(drill.findings) == 1
        assert "DNS resolution slow" in drill.findings[0]

    def test_complete_drill_step_not_in_progress(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        # Not started yet
        assert svc.complete_drill_step(drill.drill_id, 1) is None

    def test_complete_drill(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        for i in range(1, 11):
            svc.complete_drill_step(drill.drill_id, i)
        completed = svc.complete_drill(
            drill.drill_id,
            findings=["Found issue X"],
            lessons=["Improve alerting"],
            rto_achieved_minutes=45.0,
            rpo_achieved_minutes=10.0,
        )
        assert completed.status == DrillStatus.COMPLETED.value
        assert completed.rto_met is True  # 45 <= 60
        assert completed.rpo_met is True  # 10 <= 15
        assert completed.score > 0
        assert "Found issue X" in completed.findings
        # Plan should be updated
        assert plan.last_tested_at is not None
        assert plan.test_result == "pass"

    def test_complete_drill_rto_not_met(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        completed = svc.complete_drill(
            drill.drill_id,
            rto_achieved_minutes=120.0,  # target is 60
            rpo_achieved_minutes=5.0,
        )
        assert completed.rto_met is False
        assert completed.rpo_met is True

    def test_complete_drill_not_found(self, svc):
        assert svc.complete_drill("DRD-NONEXIST") is None

    def test_get_drill(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        fetched = svc.get_drill(drill.drill_id)
        assert fetched is not None
        assert fetched.drill_id == drill.drill_id

    def test_list_drills(self, svc_with_plan):
        svc, plan = svc_with_plan
        svc.schedule_drill(plan.plan_id, DrillType.TABLETOP.value)
        svc.schedule_drill(plan.plan_id, DrillType.FULL.value)
        assert len(svc.list_drills()) == 2
        assert len(svc.list_drills(plan_id=plan.plan_id)) == 2

    def test_list_drills_by_status(self, svc_with_plan):
        svc, plan = svc_with_plan
        d1 = svc.schedule_drill(plan.plan_id)
        svc.schedule_drill(plan.plan_id)
        svc.start_drill(d1.drill_id)
        assert len(svc.list_drills(status=DrillStatus.IN_PROGRESS.value)) == 1
        assert len(svc.list_drills(status=DrillStatus.SCHEDULED.value)) == 1

    def test_drill_to_dict(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id, participants=["Alice"])
        d = _drill_to_dict(drill)
        assert d["drill_id"] == drill.drill_id
        assert d["participants"] == ["Alice"]
        assert "created_at" in d


# ============================================================
# Failover Management
# ============================================================

class TestFailoverManagement:
    def test_initiate_failover(self, svc_with_plan):
        svc, plan = svc_with_plan
        event = svc.initiate_failover(plan.plan_id, trigger="monitoring_alert")
        assert event.event_id.startswith("FO-")
        assert event.status == FailoverStatus.IN_PROGRESS.value
        assert event.started_at is not None
        assert event.trigger == "monitoring_alert"
        # Plan should be activated
        assert plan.status == PlanStatus.ACTIVATED.value

    def test_initiate_failover_plan_not_found(self, svc):
        assert svc.initiate_failover("DRP-NONEXIST") is None

    def test_initiate_failover_with_systems(self, svc_with_plan):
        svc, plan = svc_with_plan
        event = svc.initiate_failover(plan.plan_id, affected_systems=["db-server"])
        assert event.systems_failed_over == ["db-server"]

    def test_initiate_failover_default_systems(self, svc_with_plan):
        svc, plan = svc_with_plan
        event = svc.initiate_failover(plan.plan_id)
        assert event.systems_failed_over == plan.systems_covered

    def test_execute_failover_step(self, svc_with_plan):
        svc, plan = svc_with_plan
        event = svc.initiate_failover(plan.plan_id)
        result = svc.execute_failover_step(event.event_id, 1)
        assert result is not None
        assert result["step_number"] == 1
        assert result["title"] == "Assess Situation"
        assert result["status"] == "executed"

    def test_execute_failover_step_not_found(self, svc):
        assert svc.execute_failover_step("FO-NONEXIST", 1) is None

    def test_complete_failover(self, svc_with_plan):
        svc, plan = svc_with_plan
        event = svc.initiate_failover(plan.plan_id)
        completed = svc.complete_failover(event.event_id)
        assert completed.status == FailoverStatus.COMPLETED.value
        assert completed.completed_at is not None
        assert completed.rto_actual_minutes is not None
        assert completed.rto_actual_minutes >= 0

    def test_complete_failover_not_found(self, svc):
        assert svc.complete_failover("FO-NONEXIST") is None

    def test_rollback_failover(self, svc_with_plan):
        svc, plan = svc_with_plan
        event = svc.initiate_failover(plan.plan_id)
        rolled_back = svc.rollback_failover(event.event_id, reason="False alarm")
        assert rolled_back.status == FailoverStatus.ROLLED_BACK.value
        assert rolled_back.completed_at is not None
        # Plan should be reverted to active
        assert plan.status == PlanStatus.ACTIVE.value

    def test_rollback_failover_not_found(self, svc):
        assert svc.rollback_failover("FO-NONEXIST") is None

    def test_get_failover_events(self, svc_with_plan):
        svc, plan = svc_with_plan
        svc.initiate_failover(plan.plan_id)
        svc.initiate_failover(plan.plan_id)
        assert len(svc.get_failover_events()) == 2
        assert len(svc.get_failover_events(plan_id=plan.plan_id)) == 2

    def test_failover_to_dict(self, svc_with_plan):
        svc, plan = svc_with_plan
        event = svc.initiate_failover(plan.plan_id, incident_id="INC-001")
        d = _failover_to_dict(event)
        assert d["event_id"] == event.event_id
        assert d["incident_id"] == "INC-001"
        assert "created_at" in d


# ============================================================
# Readiness & Compliance
# ============================================================

class TestReadinessCompliance:
    def test_assess_readiness_no_plans(self, svc):
        readiness = svc.assess_readiness("CLIENT-EMPTY")
        assert readiness.total_plans == 0
        assert readiness.overall_readiness_score == 0
        assert "No DR plans defined" in readiness.gaps

    def test_assess_readiness_with_plans(self, svc_with_plan):
        svc, plan = svc_with_plan
        readiness = svc.assess_readiness("CLIENT-001")
        assert readiness.total_plans == 1
        assert readiness.plans_tested == 0
        assert readiness.plans_untested == 1
        assert readiness.overall_readiness_score > 0

    def test_assess_readiness_tested_plan(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        svc.complete_drill(drill.drill_id, rto_achieved_minutes=30, rpo_achieved_minutes=10)
        readiness = svc.assess_readiness("CLIENT-001")
        assert readiness.plans_tested == 1
        assert readiness.plans_untested == 0
        assert readiness.last_drill_date is not None

    def test_readiness_gaps_no_contacts(self, svc):
        plan = svc.create_plan(name="No Contacts Plan", client_id="C2")
        svc.update_plan(plan.plan_id, status=PlanStatus.ACTIVE.value)
        readiness = svc.assess_readiness("C2")
        assert any("no emergency contacts" in g for g in readiness.gaps)

    def test_readiness_gaps_no_steps(self, svc):
        plan = svc.create_plan(name="No Steps Plan", client_id="C3")
        readiness = svc.assess_readiness("C3")
        assert any("no runbook steps" in g for g in readiness.gaps)

    def test_readiness_to_dict(self, svc):
        readiness = svc.assess_readiness("CLIENT-X")
        d = _readiness_to_dict(readiness)
        assert d["client_id"] == "CLIENT-X"
        assert "gaps" in d

    def test_get_readiness_report(self, svc_with_plan):
        svc, plan = svc_with_plan
        report = svc.get_readiness_report("CLIENT-001")
        assert "readiness" in report
        assert "plans" in report
        assert "recent_drills" in report
        assert "recent_failovers" in report
        assert len(report["plans"]) == 1

    def test_rto_rpo_compliance_no_drills(self, svc_with_plan):
        svc, plan = svc_with_plan
        compliance = svc.get_rto_rpo_compliance("CLIENT-001")
        assert compliance["client_id"] == "CLIENT-001"
        assert compliance["plans_count"] == 1
        assert compliance["compliance"][0]["rto_target_minutes"] == 60
        assert compliance["compliance"][0]["rto_last_drill_minutes"] is None

    def test_rto_rpo_compliance_with_drills(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        svc.complete_drill(drill.drill_id, rto_achieved_minutes=45, rpo_achieved_minutes=10)
        compliance = svc.get_rto_rpo_compliance("CLIENT-001")
        entry = compliance["compliance"][0]
        assert entry["rto_last_drill_minutes"] == 45
        assert entry["rpo_last_drill_minutes"] == 10
        assert entry["rto_last_drill_met"] is True
        assert entry["rpo_last_drill_met"] is True

    def test_get_untested_plans(self, svc):
        svc.create_plan(name="Untested 1")
        svc.create_plan(name="Untested 2")
        untested = svc.get_untested_plans(days=90)
        assert len(untested) == 2

    def test_get_untested_plans_recently_tested(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        svc.complete_drill(drill.drill_id, rto_achieved_minutes=30, rpo_achieved_minutes=10)
        untested = svc.get_untested_plans(days=90)
        assert len(untested) == 0

    def test_drill_calendar(self, svc_with_plan):
        svc, plan = svc_with_plan
        svc.schedule_drill(plan.plan_id, DrillType.TABLETOP.value)
        svc.schedule_drill(plan.plan_id, DrillType.FULL.value)
        calendar = svc.get_drill_calendar(client_id="CLIENT-001")
        assert len(calendar) == 2
        assert calendar[0]["plan_name"] == "Production DR"

    def test_drill_calendar_no_client_filter(self, svc_with_plan):
        svc, plan = svc_with_plan
        svc.schedule_drill(plan.plan_id)
        calendar = svc.get_drill_calendar()
        assert len(calendar) == 1


# ============================================================
# Plan Validation
# ============================================================

class TestPlanValidation:
    def test_validate_complete_plan(self, svc_with_plan):
        svc, plan = svc_with_plan
        result = svc.validate_plan(plan.plan_id)
        assert result["valid"] is True
        assert len(result["errors"]) == 0
        assert result["step_count"] == 10
        assert result["contacts_count"] == 1

    def test_validate_incomplete_plan(self, svc):
        plan = svc.create_plan(name="Incomplete")
        result = svc.validate_plan(plan.plan_id)
        assert result["valid"] is False
        assert any("No systems covered" in e for e in result["errors"])
        assert any("No runbook steps" in e for e in result["errors"])
        assert any("No emergency contacts" in e for e in result["errors"])

    def test_validate_plan_not_found(self, svc):
        result = svc.validate_plan("DRP-NONEXIST")
        assert result["valid"] is False

    def test_validate_never_tested_warning(self, svc_with_plan):
        svc, plan = svc_with_plan
        result = svc.validate_plan(plan.plan_id)
        assert any("never been tested" in w for w in result["warnings"])

    def test_validate_no_responsible(self, svc):
        plan = svc.create_plan(
            name="No Responsible",
            systems_covered=["server"],
            contacts=[{"name": "Admin"}],
        )
        svc.add_step(plan.plan_id, {"title": "Do thing", "step_number": 1})
        result = svc.validate_plan(plan.plan_id)
        assert any("no responsible" in w for w in result["warnings"])


# ============================================================
# Dashboard
# ============================================================

class TestDashboard:
    def test_empty_dashboard(self, svc):
        dash = svc.get_dashboard()
        assert dash["total_plans"] == 0
        assert dash["total_drills"] == 0
        assert dash["total_failovers"] == 0
        assert dash["active_failovers"] == 0

    def test_populated_dashboard(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        svc.complete_drill(drill.drill_id, rto_achieved_minutes=30, rpo_achieved_minutes=10)
        svc.initiate_failover(plan.plan_id)
        dash = svc.get_dashboard()
        assert dash["total_plans"] == 1
        assert dash["active_plans"] == 0  # activated after failover
        assert dash["activated_plans"] == 1
        assert dash["total_drills"] == 1
        assert dash["completed_drills"] == 1
        assert dash["average_drill_score"] > 0
        assert dash["total_failovers"] == 1
        assert dash["active_failovers"] == 1
        assert len(dash["recent_drills"]) == 1
        assert len(dash["recent_failovers"]) == 1
        assert "tier_breakdown" in dash

    def test_tier_breakdown(self, svc):
        svc.create_plan(name="T1", tier=DRTier.TIER1_CRITICAL.value)
        svc.create_plan(name="T2", tier=DRTier.TIER2_IMPORTANT.value)
        svc.create_plan(name="T3a", tier=DRTier.TIER3_NORMAL.value)
        svc.create_plan(name="T3b", tier=DRTier.TIER3_NORMAL.value)
        dash = svc.get_dashboard()
        assert dash["tier_breakdown"]["tier1_critical"] == 1
        assert dash["tier_breakdown"]["tier2_important"] == 1
        assert dash["tier_breakdown"]["tier3_normal"] == 2


# ============================================================
# Template & Enums
# ============================================================

class TestTemplateAndEnums:
    def test_standard_template_has_10_steps(self):
        assert len(STANDARD_BC_TEMPLATE_STEPS) == 10

    def test_template_step_numbers_sequential(self):
        for i, step in enumerate(STANDARD_BC_TEMPLATE_STEPS, 1):
            assert step["step_number"] == i

    def test_template_covers_all_action_types(self):
        types_used = {s["action_type"] for s in STANDARD_BC_TEMPLATE_STEPS}
        assert StepActionType.MANUAL.value in types_used
        assert StepActionType.AUTOMATED.value in types_used
        assert StepActionType.VERIFICATION.value in types_used
        assert StepActionType.NOTIFICATION.value in types_used
        assert StepActionType.DECISION_POINT.value in types_used

    def test_dr_tier_values(self):
        assert DRTier.TIER1_CRITICAL.value == "tier1_critical"
        assert DRTier.TIER2_IMPORTANT.value == "tier2_important"
        assert DRTier.TIER3_NORMAL.value == "tier3_normal"

    def test_drill_type_values(self):
        assert DrillType.TABLETOP.value == "tabletop"
        assert DrillType.PARTIAL.value == "partial"
        assert DrillType.FULL.value == "full"
        assert DrillType.UNANNOUNCED.value == "unannounced"

    def test_failover_status_values(self):
        assert FailoverStatus.INITIATED.value == "initiated"
        assert FailoverStatus.COMPLETED.value == "completed"
        assert FailoverStatus.ROLLED_BACK.value == "rolled_back"

    def test_step_action_type_values(self):
        assert StepActionType.MANUAL.value == "manual"
        assert StepActionType.AUTOMATED.value == "automated"
        assert StepActionType.VERIFICATION.value == "verification"
        assert StepActionType.NOTIFICATION.value == "notification"
        assert StepActionType.DECISION_POINT.value == "decision_point"


# ============================================================
# Drill Scoring
# ============================================================

class TestDrillScoring:
    def test_perfect_drill_score(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        for i in range(1, 11):
            svc.complete_drill_step(drill.drill_id, i)
        completed = svc.complete_drill(
            drill.drill_id,
            rto_achieved_minutes=30,
            rpo_achieved_minutes=5,
            lessons=["Great teamwork", "Fast response", "Clear comms", "Good docs", "No issues"],
        )
        assert completed.score >= 90

    def test_failed_drill_low_score(self, svc_with_plan):
        svc, plan = svc_with_plan
        drill = svc.schedule_drill(plan.plan_id)
        svc.start_drill(drill.drill_id)
        # Complete only 2 of 10 steps
        svc.complete_drill_step(drill.drill_id, 1)
        svc.complete_drill_step(drill.drill_id, 2)
        completed = svc.complete_drill(
            drill.drill_id,
            rto_achieved_minutes=200,  # way over 60 target
            rpo_achieved_minutes=100,  # way over 15 target
            findings=["Major issue 1", "Major issue 2", "Major issue 3", "Major issue 4", "Major issue 5"],
        )
        assert completed.score < 50
        assert completed.rto_met is False
        assert completed.rpo_met is False
        assert plan.test_result == "fail"


# ============================================================
# Edge Cases
# ============================================================

class TestEdgeCases:
    def test_service_init_no_db(self):
        svc = DROrchestrationService()
        assert svc.use_db is False

    def test_multiple_clients(self, svc):
        svc.create_plan(name="P1", client_id="C1")
        svc.create_plan(name="P2", client_id="C2")
        assert len(svc.list_plans(client_id="C1")) == 1
        assert len(svc.list_plans(client_id="C2")) == 1

    def test_failover_with_incident_id(self, svc_with_plan):
        svc, plan = svc_with_plan
        event = svc.initiate_failover(plan.plan_id, incident_id="INC-2024-001")
        assert event.incident_id == "INC-2024-001"

    def test_step_to_dict(self):
        DRStep = _mod.DRStep
        step = DRStep(step_number=1, title="Test Step", description="Desc", responsible="Admin")
        d = _step_to_dict(step)
        assert d["step_number"] == 1
        assert d["title"] == "Test Step"

    def test_plan_with_all_fields(self, svc):
        plan = svc.create_plan(
            name="Full Plan",
            client_id="C1",
            description="Full description",
            tier=DRTier.TIER1_CRITICAL.value,
            rto_minutes=30,
            rpo_minutes=5,
            systems_covered=["web", "db", "cache"],
            dependencies=["power", "network"],
            contacts=[
                {"name": "Alice", "role": "IC", "phone": "555-0001"},
                {"name": "Bob", "role": "Eng", "phone": "555-0002"},
            ],
            use_template=True,
        )
        assert plan.tier == DRTier.TIER1_CRITICAL.value
        assert len(plan.systems_covered) == 3
        assert len(plan.dependencies) == 2
        assert len(plan.contacts) == 2
        assert len(plan.runbook_steps) == 10
