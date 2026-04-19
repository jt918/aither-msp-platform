"""
Tests for MSP Client Onboarding Workflow Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.onboarding import (
    OnboardingService,
    WorkflowStatus,
    PhaseStatus,
    TaskStatus,
    TaskType,
    OnboardingWorkflow,
    OnboardingPhase,
    OnboardingTask,
    OnboardingTemplate,
    ClientChecklist,
    ChecklistItem,
    STANDARD_MSP_TEMPLATE,
)


class TestOnboardingService:
    """Tests for OnboardingService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = OnboardingService()

    # ========== Template Tests ==========

    def test_default_template_exists(self):
        """Default standard MSP template should be auto-seeded."""
        templates = self.service.list_templates()
        assert len(templates) >= 1
        standard = [t for t in templates if t.plan_type == "standard"]
        assert len(standard) >= 1
        assert standard[0].name == "Standard MSP Onboarding"

    def test_create_template(self):
        """Test creating a custom onboarding template."""
        tpl = self.service.create_template(
            name="Express Onboarding",
            description="Expedited 3-day setup",
            plan_type="express",
            phases=[
                {"phase_number": 1, "name": "Quick Setup", "tasks": [
                    {"name": "Deploy agents", "task_type": "automated"},
                ]},
            ],
            estimated_duration_days=3,
        )
        assert tpl is not None
        assert tpl.template_id.startswith("TPL-")
        assert tpl.name == "Express Onboarding"
        assert tpl.plan_type == "express"
        assert tpl.estimated_duration_days == 3
        assert len(tpl.phases) == 1

    def test_get_template(self):
        """Test retrieving a template by ID."""
        tpl = self.service.create_template(name="Test Template", plan_type="test")
        fetched = self.service.get_template(tpl.template_id)
        assert fetched is not None
        assert fetched.template_id == tpl.template_id

    def test_get_template_not_found(self):
        """Test retrieving a non-existent template."""
        result = self.service.get_template("TPL-NONEXISTENT")
        assert result is None

    def test_list_templates(self):
        """Test listing all templates."""
        self.service.create_template(name="Template A", plan_type="a")
        self.service.create_template(name="Template B", plan_type="b")
        templates = self.service.list_templates()
        # Default + 2 custom
        assert len(templates) >= 3

    def test_update_template(self):
        """Test updating template fields."""
        tpl = self.service.create_template(name="Old Name", estimated_duration_days=7)
        updated = self.service.update_template(tpl.template_id, name="New Name", estimated_duration_days=10)
        assert updated is not None
        assert updated.name == "New Name"
        assert updated.estimated_duration_days == 10

    def test_update_template_not_found(self):
        """Test updating a non-existent template."""
        result = self.service.update_template("TPL-FAKE", name="X")
        assert result is None

    # ========== Workflow Tests ==========

    def test_start_onboarding(self):
        """Test starting a new onboarding workflow."""
        wf = self.service.start_onboarding(
            client_id="CLIENT-001",
            company_name="Acme Corp",
            primary_contact="john@acme.com",
            plan_id="PLAN-STD",
            assigned_technician="tech@msp.com",
        )
        assert wf is not None
        assert wf.workflow_id.startswith("WF-")
        assert wf.client_id == "CLIENT-001"
        assert wf.company_name == "Acme Corp"
        assert wf.status == WorkflowStatus.IN_PROGRESS
        assert wf.current_phase == 1
        assert len(wf.phases) == 6  # Standard template has 6 phases
        assert wf.target_completion is not None

    def test_start_onboarding_phases_populated(self):
        """Test that all phases and tasks are created from template."""
        wf = self.service.start_onboarding(client_id="C-002", company_name="Beta Inc")
        # Phase 1 should be in_progress, rest pending
        assert wf.phases[0].status == PhaseStatus.IN_PROGRESS
        assert wf.phases[0].started_at is not None
        for ph in wf.phases[1:]:
            assert ph.status == PhaseStatus.PENDING
            assert ph.started_at is None
        # Each phase should have tasks
        for ph in wf.phases:
            assert len(ph.tasks) > 0
            for tk in ph.tasks:
                assert tk.task_id.startswith("TK-")
                assert tk.status == TaskStatus.PENDING

    def test_start_onboarding_with_custom_template(self):
        """Test starting onboarding with a custom template."""
        tpl = self.service.create_template(
            name="Mini Onboarding",
            plan_type="mini",
            phases=[
                {"phase_number": 1, "name": "Setup", "dependencies": [], "tasks": [
                    {"name": "Create account", "task_type": "automated", "automated_action": {"action": "create_billing_account"}},
                ]},
                {"phase_number": 2, "name": "Deploy", "dependencies": [1], "tasks": [
                    {"name": "Install agents", "task_type": "manual"},
                ]},
            ],
            estimated_duration_days=5,
        )
        wf = self.service.start_onboarding(
            client_id="C-003",
            company_name="Gamma LLC",
            template_id=tpl.template_id,
        )
        assert len(wf.phases) == 2
        assert wf.phases[0].name == "Setup"
        assert wf.phases[1].name == "Deploy"

    def test_get_workflow(self):
        """Test retrieving a workflow."""
        wf = self.service.start_onboarding(client_id="C-004", company_name="Delta Co")
        fetched = self.service.get_workflow(wf.workflow_id)
        assert fetched is not None
        assert fetched.workflow_id == wf.workflow_id

    def test_get_workflow_not_found(self):
        """Test retrieving a non-existent workflow."""
        result = self.service.get_workflow("WF-NONEXISTENT")
        assert result is None

    def test_list_workflows(self):
        """Test listing all workflows."""
        self.service.start_onboarding(client_id="C-005", company_name="E Corp")
        self.service.start_onboarding(client_id="C-006", company_name="F Corp")
        workflows = self.service.list_workflows()
        assert len(workflows) >= 2

    def test_list_workflows_filter_status(self):
        """Test filtering workflows by status."""
        self.service.start_onboarding(client_id="C-007", company_name="G Corp")
        workflows = self.service.list_workflows(status=WorkflowStatus.IN_PROGRESS)
        assert all(w.status == WorkflowStatus.IN_PROGRESS for w in workflows)

    def test_list_workflows_filter_client(self):
        """Test filtering workflows by client ID."""
        self.service.start_onboarding(client_id="C-UNIQUE", company_name="Unique Corp")
        workflows = self.service.list_workflows(client_id="C-UNIQUE")
        assert len(workflows) == 1
        assert workflows[0].client_id == "C-UNIQUE"

    # ========== Phase Advancement Tests ==========

    def test_advance_phase(self):
        """Test advancing to the next phase."""
        wf = self.service.start_onboarding(client_id="C-010", company_name="Phase Corp")
        assert wf.current_phase == 1

        wf = self.service.advance_phase(wf.workflow_id)
        assert wf.current_phase == 2
        assert wf.phases[0].status == PhaseStatus.COMPLETED
        assert wf.phases[0].completed_at is not None
        assert wf.phases[1].status == PhaseStatus.IN_PROGRESS
        assert wf.phases[1].started_at is not None

    def test_advance_through_all_phases(self):
        """Test advancing through all phases completes the workflow."""
        wf = self.service.start_onboarding(client_id="C-011", company_name="Full Corp")
        for _ in range(len(wf.phases)):
            wf = self.service.advance_phase(wf.workflow_id)

        # After advancing past last phase, workflow should be completed
        assert wf.status == WorkflowStatus.COMPLETED
        assert wf.completed_at is not None

    def test_advance_completed_workflow_raises(self):
        """Test advancing a completed workflow raises an error."""
        wf = self.service.start_onboarding(client_id="C-012", company_name="Done Corp")
        for _ in range(len(wf.phases)):
            wf = self.service.advance_phase(wf.workflow_id)

        with pytest.raises(ValueError, match="cannot be advanced"):
            self.service.advance_phase(wf.workflow_id)

    def test_advance_nonexistent_workflow_raises(self):
        """Test advancing a non-existent workflow raises an error."""
        with pytest.raises(ValueError, match="not found"):
            self.service.advance_phase("WF-FAKE")

    # ========== Task Operations Tests ==========

    def test_complete_task(self):
        """Test completing a task."""
        wf = self.service.start_onboarding(client_id="C-020", company_name="Task Corp")
        task_id = wf.phases[0].tasks[0].task_id

        task = self.service.complete_task(wf.workflow_id, task_id, result={"note": "done"})
        assert task.status == TaskStatus.COMPLETED
        assert task.completed_at is not None
        assert task.result == {"note": "done"}

    def test_complete_task_not_found(self):
        """Test completing a non-existent task."""
        wf = self.service.start_onboarding(client_id="C-021", company_name="NoTask Corp")
        with pytest.raises(ValueError, match="not found"):
            self.service.complete_task(wf.workflow_id, "TK-FAKE")

    def test_skip_task(self):
        """Test skipping a task."""
        wf = self.service.start_onboarding(client_id="C-022", company_name="Skip Corp")
        task_id = wf.phases[0].tasks[0].task_id

        task = self.service.skip_task(wf.workflow_id, task_id, reason="Not applicable")
        assert task.status == TaskStatus.SKIPPED
        assert task.result == {"skipped_reason": "Not applicable"}

    def test_execute_automated_task(self):
        """Test executing an automated task."""
        wf = self.service.start_onboarding(client_id="C-023", company_name="Auto Corp")
        # Find an automated task
        auto_task = None
        for ph in wf.phases:
            for tk in ph.tasks:
                if tk.task_type == TaskType.AUTOMATED:
                    auto_task = tk
                    break
            if auto_task:
                break

        assert auto_task is not None, "Standard template should have automated tasks"
        task = self.service.execute_automated_task(wf.workflow_id, auto_task.task_id)
        assert task.status == TaskStatus.COMPLETED
        assert task.result is not None
        assert "status" in task.result

    def test_execute_manual_task_raises(self):
        """Test executing a manual task raises an error."""
        wf = self.service.start_onboarding(client_id="C-024", company_name="Manual Corp")
        manual_task = None
        for ph in wf.phases:
            for tk in ph.tasks:
                if tk.task_type == TaskType.MANUAL:
                    manual_task = tk
                    break
            if manual_task:
                break

        assert manual_task is not None
        with pytest.raises(ValueError, match="not automated"):
            self.service.execute_automated_task(wf.workflow_id, manual_task.task_id)

    # ========== Phase Blocking Tests ==========

    def test_block_phase(self):
        """Test blocking a phase."""
        wf = self.service.start_onboarding(client_id="C-030", company_name="Block Corp")
        phase_id = wf.phases[0].phase_id

        phase = self.service.block_phase(wf.workflow_id, phase_id, reason="Waiting for credentials")
        assert phase.status == PhaseStatus.BLOCKED

        # Workflow should be stalled
        wf = self.service.get_workflow(wf.workflow_id)
        assert wf.status == WorkflowStatus.STALLED
        assert "BLOCKED" in wf.notes

    def test_block_nonexistent_phase(self):
        """Test blocking a non-existent phase."""
        wf = self.service.start_onboarding(client_id="C-031", company_name="NoPhase Corp")
        with pytest.raises(ValueError, match="not found"):
            self.service.block_phase(wf.workflow_id, "PH-FAKE", reason="test")

    # ========== Progress Tests ==========

    def test_get_onboarding_progress(self):
        """Test getting onboarding progress."""
        wf = self.service.start_onboarding(client_id="C-040", company_name="Progress Corp")
        progress = self.service.get_onboarding_progress(wf.workflow_id)

        assert progress["workflow_id"] == wf.workflow_id
        assert progress["status"] == WorkflowStatus.IN_PROGRESS
        assert progress["percentage_complete"] == 0.0
        assert progress["total_tasks"] > 0
        assert progress["completed_tasks"] == 0
        assert progress["current_phase"]["number"] == 1
        assert progress["days_elapsed"] >= 0

    def test_progress_after_completing_tasks(self):
        """Test progress increases after completing tasks."""
        wf = self.service.start_onboarding(client_id="C-041", company_name="Prog2 Corp")
        # Complete first two tasks
        self.service.complete_task(wf.workflow_id, wf.phases[0].tasks[0].task_id)
        self.service.complete_task(wf.workflow_id, wf.phases[0].tasks[1].task_id)

        progress = self.service.get_onboarding_progress(wf.workflow_id)
        assert progress["completed_tasks"] == 2
        assert progress["percentage_complete"] > 0.0

    def test_progress_not_found(self):
        """Test progress for non-existent workflow."""
        with pytest.raises(ValueError, match="not found"):
            self.service.get_onboarding_progress("WF-GHOST")

    # ========== Checklist Tests ==========

    def test_checklist_created_with_workflow(self):
        """Test that a checklist is auto-created when a workflow starts."""
        wf = self.service.start_onboarding(client_id="C-050", company_name="Checklist Corp")
        cl = self.service.get_client_checklist(wf.workflow_id)
        assert cl is not None
        assert cl.workflow_id == wf.workflow_id
        assert len(cl.items) > 0
        # All items should start uncompleted
        assert all(not item.is_completed for item in cl.items)

    def test_update_checklist_item(self):
        """Test updating a checklist item."""
        wf = self.service.start_onboarding(client_id="C-051", company_name="Check2 Corp")
        cl = self.service.get_client_checklist(wf.workflow_id)
        item_id = cl.items[0].item_id

        updated = self.service.update_checklist_item(
            wf.workflow_id, item_id,
            completed=True,
            completed_by="admin@msp.com",
            notes="Verified",
        )
        assert updated is not None
        assert updated.is_completed is True
        assert updated.completed_by == "admin@msp.com"
        assert updated.completed_at is not None
        assert updated.notes == "Verified"

    def test_update_checklist_item_not_found(self):
        """Test updating a non-existent checklist item."""
        wf = self.service.start_onboarding(client_id="C-052", company_name="NoItem Corp")
        result = self.service.update_checklist_item(wf.workflow_id, "CI-FAKE", completed=True)
        assert result is None

    def test_get_checklist_not_found(self):
        """Test getting checklist for non-existent workflow."""
        result = self.service.get_client_checklist("WF-FAKE")
        assert result is None

    # ========== Lifecycle Tests ==========

    def test_stall_workflow(self):
        """Test stalling a workflow."""
        wf = self.service.start_onboarding(client_id="C-060", company_name="Stall Corp")
        wf = self.service.stall_workflow(wf.workflow_id, reason="Client unresponsive")
        assert wf.status == WorkflowStatus.STALLED
        assert "STALLED" in wf.notes
        assert "Client unresponsive" in wf.notes

    def test_cancel_workflow(self):
        """Test cancelling a workflow."""
        wf = self.service.start_onboarding(client_id="C-061", company_name="Cancel Corp")
        wf = self.service.cancel_workflow(wf.workflow_id, reason="Client withdrew")
        assert wf.status == WorkflowStatus.CANCELLED
        assert wf.completed_at is not None
        assert "CANCELLED" in wf.notes

    def test_stall_nonexistent_workflow(self):
        """Test stalling a non-existent workflow."""
        with pytest.raises(ValueError, match="not found"):
            self.service.stall_workflow("WF-GHOST")

    def test_cancel_nonexistent_workflow(self):
        """Test cancelling a non-existent workflow."""
        with pytest.raises(ValueError, match="not found"):
            self.service.cancel_workflow("WF-GHOST")

    # ========== Analytics Tests ==========

    def test_average_onboarding_time_no_data(self):
        """Test average time with no completed workflows."""
        result = self.service.get_average_onboarding_time()
        assert result["average_days"] == 0
        assert result["completed_count"] == 0

    def test_average_onboarding_time_with_data(self):
        """Test average time with completed workflows."""
        wf = self.service.start_onboarding(client_id="C-070", company_name="Avg Corp")
        # Fast-forward through all phases
        for _ in range(len(wf.phases)):
            wf = self.service.advance_phase(wf.workflow_id)

        result = self.service.get_average_onboarding_time()
        assert result["completed_count"] >= 1
        assert result["average_days"] >= 0

    def test_bottleneck_analysis(self):
        """Test bottleneck analysis returns expected structure."""
        result = self.service.get_bottleneck_analysis()
        assert "slowest_phases_hours" in result
        assert "slowest_tasks_hours" in result
        assert "most_blocked_phases" in result
        assert "most_failed_tasks" in result

    def test_dashboard(self):
        """Test dashboard returns expected structure."""
        self.service.start_onboarding(client_id="C-080", company_name="Dash Corp")
        dashboard = self.service.get_dashboard()
        assert "total_workflows" in dashboard
        assert "active" in dashboard
        assert "completed" in dashboard
        assert "stalled" in dashboard
        assert "cancelled" in dashboard
        assert "completion_rate" in dashboard
        assert "average_duration_days" in dashboard
        assert "active_workflows" in dashboard
        assert dashboard["total_workflows"] >= 1
        assert dashboard["active"] >= 1

    def test_dashboard_completion_rate(self):
        """Test dashboard completion rate calculation."""
        # Start and complete a workflow
        wf = self.service.start_onboarding(client_id="C-081", company_name="Rate Corp")
        for _ in range(len(wf.phases)):
            wf = self.service.advance_phase(wf.workflow_id)

        dashboard = self.service.get_dashboard()
        assert dashboard["completed"] >= 1
        assert dashboard["completion_rate"] > 0

    # ========== Integration Tests ==========

    def test_full_onboarding_lifecycle(self):
        """Test a complete onboarding lifecycle from start to finish."""
        # 1. Start onboarding
        wf = self.service.start_onboarding(
            client_id="C-100",
            company_name="Full Lifecycle Corp",
            primary_contact="ceo@fullcorp.com",
            plan_id="PLAN-PRO",
            assigned_technician="tech@msp.com",
            notes="Premium client",
        )
        assert wf.status == WorkflowStatus.IN_PROGRESS

        # 2. Complete some tasks in phase 1
        for tk in wf.phases[0].tasks[:3]:
            self.service.complete_task(wf.workflow_id, tk.task_id)

        # 3. Check progress
        progress = self.service.get_onboarding_progress(wf.workflow_id)
        assert progress["completed_tasks"] == 3

        # 4. Skip remaining tasks in phase 1
        for tk in wf.phases[0].tasks[3:]:
            self.service.skip_task(wf.workflow_id, tk.task_id, reason="Not needed")

        # 5. Advance to phase 2
        wf = self.service.advance_phase(wf.workflow_id)
        assert wf.current_phase == 2

        # 6. Execute automated task
        auto_tasks = [tk for tk in wf.phases[1].tasks if tk.task_type == TaskType.AUTOMATED]
        if auto_tasks:
            task = self.service.execute_automated_task(wf.workflow_id, auto_tasks[0].task_id)
            assert task.status == TaskStatus.COMPLETED

        # 7. Update checklist
        cl = self.service.get_client_checklist(wf.workflow_id)
        assert cl is not None
        self.service.update_checklist_item(
            wf.workflow_id, cl.items[0].item_id,
            completed=True, completed_by="admin",
        )

        # 8. Advance through remaining phases (2->3, 3->4, 4->5, 5->6, 6->complete)
        for _ in range(5):
            wf = self.service.advance_phase(wf.workflow_id)

        assert wf.status == WorkflowStatus.COMPLETED
        assert wf.completed_at is not None

        # 9. Verify dashboard reflects completion
        dashboard = self.service.get_dashboard()
        assert dashboard["completed"] >= 1

    def test_stall_and_resume_workflow(self):
        """Test stalling and then resuming a workflow."""
        wf = self.service.start_onboarding(client_id="C-101", company_name="Resume Corp")

        # Stall
        wf = self.service.stall_workflow(wf.workflow_id, reason="Waiting on client")
        assert wf.status == WorkflowStatus.STALLED

        # Resume by advancing (sets back to in_progress implicitly via phase update)
        wf.status = WorkflowStatus.IN_PROGRESS
        wf = self.service.advance_phase(wf.workflow_id)
        assert wf.current_phase == 2


class TestOnboardingEnums:
    """Tests for onboarding enum values"""

    def test_workflow_status_values(self):
        assert WorkflowStatus.INITIATED == "initiated"
        assert WorkflowStatus.IN_PROGRESS == "in_progress"
        assert WorkflowStatus.COMPLETED == "completed"
        assert WorkflowStatus.STALLED == "stalled"
        assert WorkflowStatus.CANCELLED == "cancelled"

    def test_phase_status_values(self):
        assert PhaseStatus.PENDING == "pending"
        assert PhaseStatus.IN_PROGRESS == "in_progress"
        assert PhaseStatus.COMPLETED == "completed"
        assert PhaseStatus.SKIPPED == "skipped"
        assert PhaseStatus.BLOCKED == "blocked"

    def test_task_status_values(self):
        assert TaskStatus.PENDING == "pending"
        assert TaskStatus.IN_PROGRESS == "in_progress"
        assert TaskStatus.COMPLETED == "completed"
        assert TaskStatus.FAILED == "failed"
        assert TaskStatus.SKIPPED == "skipped"

    def test_task_type_values(self):
        assert TaskType.MANUAL == "manual"
        assert TaskType.AUTOMATED == "automated"
        assert TaskType.APPROVAL == "approval"
        assert TaskType.DOCUMENTATION == "documentation"


class TestOnboardingDataclasses:
    """Tests for onboarding dataclass construction"""

    def test_onboarding_task_defaults(self):
        task = OnboardingTask(task_id="TK-1", phase_id="PH-1", name="Test Task")
        assert task.status == TaskStatus.PENDING
        assert task.task_type == TaskType.MANUAL
        assert task.assigned_to == ""
        assert task.automated_action is None
        assert task.result is None

    def test_onboarding_phase_defaults(self):
        phase = OnboardingPhase(phase_id="PH-1", workflow_id="WF-1", phase_number=1, name="Test Phase")
        assert phase.status == PhaseStatus.PENDING
        assert phase.tasks == []
        assert phase.dependencies == []

    def test_onboarding_workflow_defaults(self):
        wf = OnboardingWorkflow(workflow_id="WF-1", client_id="C-1", company_name="Test Corp")
        assert wf.status == WorkflowStatus.INITIATED
        assert wf.current_phase == 1
        assert wf.phases == []
        assert wf.notes == ""

    def test_onboarding_template_defaults(self):
        tpl = OnboardingTemplate(template_id="TPL-1", name="Test Template")
        assert tpl.plan_type == "standard"
        assert tpl.phases == []
        assert tpl.estimated_duration_days == 14

    def test_checklist_item_defaults(self):
        item = ChecklistItem(item_id="CI-1", category="Network", description="Test item")
        assert item.is_required is True
        assert item.is_completed is False
        assert item.completed_by == ""

    def test_client_checklist_defaults(self):
        cl = ClientChecklist(checklist_id="CL-1", workflow_id="WF-1")
        assert cl.items == []


class TestStandardMSPTemplate:
    """Tests for the pre-built standard MSP template definition"""

    def test_template_has_six_phases(self):
        assert len(STANDARD_MSP_TEMPLATE["phases"]) == 6

    def test_template_phase_names(self):
        names = [p["name"] for p in STANDARD_MSP_TEMPLATE["phases"]]
        assert "Discovery & Planning" in names
        assert "Account Setup" in names
        assert "Agent Deployment" in names
        assert "Security Baseline" in names
        assert "Service Activation" in names
        assert "Handoff & Go-Live" in names

    def test_template_phase_numbers_sequential(self):
        numbers = [p["phase_number"] for p in STANDARD_MSP_TEMPLATE["phases"]]
        assert numbers == [1, 2, 3, 4, 5, 6]

    def test_template_each_phase_has_tasks(self):
        for phase in STANDARD_MSP_TEMPLATE["phases"]:
            assert len(phase["tasks"]) >= 4, f"Phase '{phase['name']}' should have at least 4 tasks"

    def test_template_has_automated_tasks(self):
        auto_count = 0
        for phase in STANDARD_MSP_TEMPLATE["phases"]:
            for task in phase["tasks"]:
                if task.get("task_type") == "automated":
                    auto_count += 1
                    assert "automated_action" in task
        assert auto_count >= 4, "Template should have at least 4 automated tasks"

    def test_template_phase_dependencies(self):
        """Each phase after 1 should depend on the previous phase."""
        phases = STANDARD_MSP_TEMPLATE["phases"]
        assert phases[0]["dependencies"] == []
        for i in range(1, len(phases)):
            assert phases[i]["dependencies"] == [i], f"Phase {i+1} should depend on phase {i}"

    def test_template_estimated_duration(self):
        assert STANDARD_MSP_TEMPLATE["estimated_duration_days"] == 14
