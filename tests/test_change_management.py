"""
Tests for ITIL-Aligned Change Management Workflow Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.change_management import (
    ChangeManagementService,
    ChangeType,
    ChangeStatus,
    RiskLevel,
    ChangeCategory,
    ChangePriority,
    ApprovalDecision,
    ImpactScope,
    RollbackComplexity,
    TestingCoverage,
    ChangeRequest,
    ApprovalRecord,
    ChangeTemplate,
    PIR,
    BlackoutWindow,
    ChangeCalendar,
)


class TestChangeManagementService:
    """Tests for ChangeManagementService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.svc = ChangeManagementService()

    # ========== Change CRUD ==========

    def test_create_change(self):
        """Test basic change creation."""
        cr = self.svc.create_change(
            client_id="CLIENT-001",
            title="Test server patch",
            description="Apply security patches to web servers",
            change_type=ChangeType.STANDARD,
            category=ChangeCategory.SOFTWARE,
            priority=ChangePriority.MEDIUM,
            requested_by="admin@test.com",
        )
        assert cr is not None
        assert cr.change_id.startswith("CHG-")
        assert cr.title == "Test server patch"
        assert cr.status == ChangeStatus.DRAFT
        assert cr.change_type == ChangeType.STANDARD
        assert cr.category == ChangeCategory.SOFTWARE
        assert cr.client_id == "CLIENT-001"

    def test_create_change_unique_ids(self):
        """Test that each change gets a unique ID."""
        cr1 = self.svc.create_change(client_id="C1", title="Change 1", description="d1")
        cr2 = self.svc.create_change(client_id="C1", title="Change 2", description="d2")
        assert cr1.change_id != cr2.change_id

    def test_get_change(self):
        """Test retrieving a change by ID."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        fetched = self.svc.get_change(cr.change_id)
        assert fetched is not None
        assert fetched.change_id == cr.change_id

    def test_get_change_not_found(self):
        """Test retrieving a non-existent change."""
        assert self.svc.get_change("CHG-99999") is None

    def test_list_changes(self):
        """Test listing changes."""
        self.svc.create_change(client_id="C1", title="A", description="d", change_type=ChangeType.STANDARD)
        self.svc.create_change(client_id="C2", title="B", description="d", change_type=ChangeType.EMERGENCY)
        all_changes = self.svc.list_changes()
        assert len(all_changes) == 2

    def test_list_changes_filter_client(self):
        """Test filtering changes by client."""
        self.svc.create_change(client_id="C1", title="A", description="d")
        self.svc.create_change(client_id="C2", title="B", description="d")
        filtered = self.svc.list_changes(client_id="C1")
        assert len(filtered) == 1
        assert filtered[0].client_id == "C1"

    def test_list_changes_filter_status(self):
        """Test filtering changes by status."""
        self.svc.create_change(client_id="C1", title="A", description="d")
        result = self.svc.list_changes(status=ChangeStatus.DRAFT)
        assert len(result) == 1
        result2 = self.svc.list_changes(status=ChangeStatus.APPROVED)
        assert len(result2) == 0

    def test_list_changes_filter_type(self):
        """Test filtering by change type."""
        self.svc.create_change(client_id="C1", title="A", description="d", change_type=ChangeType.STANDARD)
        self.svc.create_change(client_id="C1", title="B", description="d", change_type=ChangeType.EMERGENCY)
        result = self.svc.list_changes(change_type=ChangeType.EMERGENCY)
        assert len(result) == 1

    def test_list_changes_filter_priority(self):
        """Test filtering by priority."""
        self.svc.create_change(client_id="C1", title="A", description="d", priority=ChangePriority.LOW)
        self.svc.create_change(client_id="C1", title="B", description="d", priority=ChangePriority.CRITICAL)
        result = self.svc.list_changes(priority=ChangePriority.CRITICAL)
        assert len(result) == 1

    def test_list_changes_filter_category(self):
        """Test filtering by category."""
        self.svc.create_change(client_id="C1", title="A", description="d", category=ChangeCategory.NETWORK)
        self.svc.create_change(client_id="C1", title="B", description="d", category=ChangeCategory.SECURITY)
        result = self.svc.list_changes(category=ChangeCategory.NETWORK)
        assert len(result) == 1

    def test_update_change(self):
        """Test updating a change."""
        cr = self.svc.create_change(client_id="C1", title="Original", description="d")
        updated = self.svc.update_change(cr.change_id, title="Updated Title", assigned_to="tech1")
        assert updated.title == "Updated Title"
        assert updated.assigned_to == "tech1"

    def test_update_change_not_found(self):
        """Test updating non-existent change."""
        assert self.svc.update_change("CHG-99999", title="x") is None

    # ========== Workflow ==========

    def test_submit_change(self):
        """Test submitting a draft change."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        assert cr.status == ChangeStatus.DRAFT
        submitted = self.svc.submit_change(cr.change_id)
        assert submitted.status == ChangeStatus.UNDER_REVIEW  # no approvers -> auto under_review
        assert submitted.risk_score > 0

    def test_submit_change_with_approvers(self):
        """Test submitting a change that requires approvers."""
        cr = self.svc.create_change(
            client_id="C1", title="Test", description="d",
            approvers_required=["manager1"],
        )
        submitted = self.svc.submit_change(cr.change_id)
        assert submitted.status == ChangeStatus.SUBMITTED

    def test_submit_non_draft_raises(self):
        """Test that submitting a non-draft change raises."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        self.svc.submit_change(cr.change_id)
        with pytest.raises(ValueError):
            self.svc.submit_change(cr.change_id)

    def test_approve_change(self):
        """Test approving a change."""
        cr = self.svc.create_change(
            client_id="C1", title="Test", description="d",
            approvers_required=["mgr1"],
        )
        self.svc.submit_change(cr.change_id)
        approved = self.svc.approve_change(
            cr.change_id, approver="mgr1",
            decision=ApprovalDecision.APPROVED, comments="LGTM",
        )
        assert approved.status == ChangeStatus.APPROVED
        assert "mgr1" in approved.approvals_received

    def test_approve_change_partial(self):
        """Test partial approval (multiple approvers)."""
        cr = self.svc.create_change(
            client_id="C1", title="Test", description="d",
            approvers_required=["mgr1", "mgr2"],
        )
        self.svc.submit_change(cr.change_id)
        partial = self.svc.approve_change(
            cr.change_id, approver="mgr1",
            decision=ApprovalDecision.APPROVED,
        )
        assert partial.status == ChangeStatus.UNDER_REVIEW
        full = self.svc.approve_change(
            cr.change_id, approver="mgr2",
            decision=ApprovalDecision.APPROVED,
        )
        assert full.status == ChangeStatus.APPROVED

    def test_reject_change(self):
        """Test rejecting a change."""
        cr = self.svc.create_change(
            client_id="C1", title="Test", description="d",
            approvers_required=["mgr1"],
        )
        self.svc.submit_change(cr.change_id)
        rejected = self.svc.approve_change(
            cr.change_id, approver="mgr1",
            decision=ApprovalDecision.REJECTED, comments="Too risky",
        )
        assert rejected.status == ChangeStatus.CANCELLED

    def test_defer_change(self):
        """Test deferring an approval."""
        cr = self.svc.create_change(
            client_id="C1", title="Test", description="d",
            approvers_required=["mgr1"],
        )
        self.svc.submit_change(cr.change_id)
        deferred = self.svc.approve_change(
            cr.change_id, approver="mgr1",
            decision=ApprovalDecision.DEFERRED, comments="Need more info",
        )
        assert deferred.status == ChangeStatus.UNDER_REVIEW

    def test_start_implementation(self):
        """Test starting implementation on an approved change."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        self.svc.submit_change(cr.change_id)
        # No approvers, so it goes to UNDER_REVIEW; approve it
        self.svc.approve_change(cr.change_id, approver="admin", decision=ApprovalDecision.APPROVED)
        impl = self.svc.start_implementation(cr.change_id)
        assert impl.status == ChangeStatus.IMPLEMENTING
        assert impl.actual_start is not None

    def test_start_implementation_wrong_status_raises(self):
        """Test that implementing a non-approved change raises."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        with pytest.raises(ValueError):
            self.svc.start_implementation(cr.change_id)

    def test_complete_change_success(self):
        """Test completing a change successfully."""
        cr = self._create_implementing_change()
        completed = self.svc.complete_change(cr.change_id, success=True)
        assert completed.status == ChangeStatus.COMPLETED
        assert completed.actual_end is not None

    def test_complete_change_failure(self):
        """Test completing a change as failed."""
        cr = self._create_implementing_change()
        failed = self.svc.complete_change(cr.change_id, success=False)
        assert failed.status == ChangeStatus.FAILED

    def test_complete_wrong_status_raises(self):
        """Test that completing a non-implementing change raises."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        with pytest.raises(ValueError):
            self.svc.complete_change(cr.change_id)

    def test_rollback_change(self):
        """Test rolling back a change."""
        cr = self._create_implementing_change()
        rolled = self.svc.rollback_change(cr.change_id, reason="Service degradation")
        assert rolled.status == ChangeStatus.ROLLED_BACK
        assert "Service degradation" in rolled.pir_notes

    def test_rollback_from_failed(self):
        """Test rolling back a failed change."""
        cr = self._create_implementing_change()
        self.svc.complete_change(cr.change_id, success=False)
        rolled = self.svc.rollback_change(cr.change_id, reason="Reverting")
        assert rolled.status == ChangeStatus.ROLLED_BACK

    def test_rollback_wrong_status_raises(self):
        """Test that rollback on wrong status raises."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        with pytest.raises(ValueError):
            self.svc.rollback_change(cr.change_id)

    def test_cancel_change(self):
        """Test cancelling a change."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        cancelled = self.svc.cancel_change(cr.change_id, reason="No longer needed")
        assert cancelled.status == ChangeStatus.CANCELLED

    def test_cancel_terminal_raises(self):
        """Test that cancelling an already-completed change raises."""
        cr = self._create_implementing_change()
        self.svc.complete_change(cr.change_id, success=True)
        with pytest.raises(ValueError):
            self.svc.cancel_change(cr.change_id)

    # ========== Risk ==========

    def test_calculate_risk_score_standard(self):
        """Test risk score for a standard change."""
        score = self.svc.calculate_risk_score({
            "change_type": "standard",
            "impact_scope": "single_device",
            "rollback_complexity": "simple",
            "testing_coverage": "full",
        })
        # 10 + 5 + 5 + 0 = 20
        assert score == 20

    def test_calculate_risk_score_emergency(self):
        """Test risk score for an emergency change."""
        score = self.svc.calculate_risk_score({
            "change_type": "emergency",
            "impact_scope": "organization",
            "rollback_complexity": "complex",
            "testing_coverage": "none",
        })
        # 50 + 40 + 30 + 25 = 145 -> capped at 100
        assert score == 100

    def test_calculate_risk_score_defaults(self):
        """Test risk score with defaults."""
        score = self.svc.calculate_risk_score({})
        # defaults: normal=30, department=15, moderate=15, partial=10 = 70
        assert score == 70

    def test_calculate_risk_score_blackout_penalty(self):
        """Test blackout window adds penalty."""
        now = datetime.now(timezone.utc)
        self.svc.create_blackout_window(
            client_id="C1", name="Freeze",
            start_time=now - timedelta(hours=1),
            end_time=now + timedelta(hours=1),
        )
        score = self.svc.calculate_risk_score({
            "change_type": "standard",
            "impact_scope": "single_device",
            "rollback_complexity": "simple",
            "testing_coverage": "full",
            "scheduled_start": now,
        })
        # 10 + 5 + 5 + 0 + 20 (blackout) = 40
        assert score == 40

    def test_calculate_risk_score_failure_history(self):
        """Test past failure penalty."""
        # Create a failed change in SOFTWARE category
        cr = self.svc.create_change(
            client_id="C1", title="Failed one", description="d",
            category=ChangeCategory.SOFTWARE,
        )
        self.svc.submit_change(cr.change_id)
        self.svc.approve_change(cr.change_id, "admin", ApprovalDecision.APPROVED)
        self.svc.start_implementation(cr.change_id)
        self.svc.complete_change(cr.change_id, success=False)

        # Create another SOFTWARE change and check risk
        cr2 = self.svc.create_change(
            client_id="C1", title="New one", description="d",
            category=ChangeCategory.SOFTWARE,
        )
        score = self.svc.calculate_risk_score({
            "change_type": "standard",
            "impact_scope": "single_device",
            "rollback_complexity": "simple",
            "testing_coverage": "full",
            "change_id": cr2.change_id,
        })
        # 10 + 5 + 5 + 0 + 15 (1 past failure) = 35
        assert score == 35

    def test_score_to_level(self):
        """Test risk score to level conversion."""
        assert self.svc._score_to_level(10) == RiskLevel.LOW
        assert self.svc._score_to_level(25) == RiskLevel.LOW
        assert self.svc._score_to_level(40) == RiskLevel.MEDIUM
        assert self.svc._score_to_level(60) == RiskLevel.HIGH
        assert self.svc._score_to_level(80) == RiskLevel.CRITICAL

    # ========== Approvals ==========

    def test_get_pending_approvals(self):
        """Test getting pending approvals for an approver."""
        cr = self.svc.create_change(
            client_id="C1", title="Test", description="d",
            approvers_required=["mgr1", "mgr2"],
        )
        self.svc.submit_change(cr.change_id)
        pending = self.svc.get_pending_approvals("mgr1")
        assert len(pending) == 1
        assert pending[0].change_id == cr.change_id

    def test_get_pending_approvals_after_approval(self):
        """Test that approved changes don't show as pending."""
        cr = self.svc.create_change(
            client_id="C1", title="Test", description="d",
            approvers_required=["mgr1"],
        )
        self.svc.submit_change(cr.change_id)
        self.svc.approve_change(cr.change_id, "mgr1", ApprovalDecision.APPROVED)
        pending = self.svc.get_pending_approvals("mgr1")
        assert len(pending) == 0

    def test_get_approval_history(self):
        """Test getting approval history."""
        cr = self.svc.create_change(
            client_id="C1", title="Test", description="d",
            approvers_required=["mgr1"],
        )
        self.svc.submit_change(cr.change_id)
        self.svc.approve_change(cr.change_id, "mgr1", ApprovalDecision.APPROVED, "OK")
        history = self.svc.get_approval_history(cr.change_id)
        assert len(history) == 1
        assert history[0].decision == ApprovalDecision.APPROVED
        assert history[0].comments == "OK"

    # ========== Templates ==========

    def test_default_templates_loaded(self):
        """Test that default templates are loaded."""
        templates = self.svc.list_templates()
        assert len(templates) == 5

    def test_get_template(self):
        """Test getting a specific template."""
        tpl = self.svc.get_template("TPL-001")
        assert tpl is not None
        assert tpl.name == "Server Patch Deployment"
        assert tpl.change_type == ChangeType.STANDARD

    def test_get_template_not_found(self):
        """Test getting non-existent template."""
        assert self.svc.get_template("TPL-999") is None

    def test_create_template(self):
        """Test creating a custom template."""
        tpl = self.svc.create_template(
            name="Custom Template",
            description="A custom change template",
            change_type=ChangeType.NORMAL,
            category=ChangeCategory.DATABASE,
            steps=["Step 1", "Step 2"],
        )
        assert tpl.template_id.startswith("TPL-")
        assert tpl.name == "Custom Template"
        assert len(self.svc.list_templates()) == 6

    def test_create_from_template(self):
        """Test creating a change from a template."""
        cr = self.svc.create_from_template(
            template_id="TPL-001",
            client_id="CLIENT-001",
            requested_by="admin",
        )
        assert cr is not None
        assert cr.change_type == ChangeType.STANDARD
        assert cr.title == "Server Patch Deployment"
        assert cr.status == ChangeStatus.DRAFT
        assert "Revert to pre-patch snapshot" in cr.rollback_plan

    def test_create_from_template_with_overrides(self):
        """Test template instantiation with overrides."""
        cr = self.svc.create_from_template(
            template_id="TPL-002",
            client_id="CLIENT-002",
            title="Custom Firewall Update",
            overrides={"priority": "high", "description": "Custom desc"},
        )
        assert cr.title == "Custom Firewall Update"
        assert cr.priority == ChangePriority.HIGH
        assert cr.description == "Custom desc"

    def test_create_from_template_not_found(self):
        """Test instantiating a non-existent template."""
        assert self.svc.create_from_template("TPL-999", "C1") is None

    # ========== PIR ==========

    def test_create_pir(self):
        """Test creating a Post-Implementation Review."""
        cr = self._create_implementing_change()
        self.svc.complete_change(cr.change_id, success=True)
        pir = self.svc.create_pir(cr.change_id, {
            "was_successful": True,
            "objectives_met": True,
            "issues_encountered": ["Minor delay"],
            "lessons_learned": ["Schedule more time"],
            "reviewed_by": "admin",
        })
        assert pir is not None
        assert pir.was_successful is True
        assert len(pir.issues_encountered) == 1

        # Verify change is marked as PIR completed
        updated = self.svc.get_change(cr.change_id)
        assert updated.pir_completed is True

    def test_create_pir_for_failed(self):
        """Test PIR for a failed change."""
        cr = self._create_implementing_change()
        self.svc.complete_change(cr.change_id, success=False)
        pir = self.svc.create_pir(cr.change_id, {
            "was_successful": False,
            "objectives_met": False,
            "issues_encountered": ["Service crash"],
        })
        assert pir.was_successful is False

    def test_create_pir_wrong_status_raises(self):
        """Test that PIR on a draft change raises."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        with pytest.raises(ValueError):
            self.svc.create_pir(cr.change_id, {})

    def test_get_pir(self):
        """Test retrieving a PIR."""
        cr = self._create_implementing_change()
        self.svc.complete_change(cr.change_id, success=True)
        self.svc.create_pir(cr.change_id, {"reviewed_by": "admin"})
        pir = self.svc.get_pir(cr.change_id)
        assert pir is not None
        assert pir.change_id == cr.change_id

    def test_get_pir_not_found(self):
        """Test getting PIR for a change that has none."""
        assert self.svc.get_pir("CHG-99999") is None

    # ========== Calendar ==========

    def test_get_change_calendar(self):
        """Test getting change calendar entries."""
        now = datetime.now(timezone.utc)
        self.svc.create_change(
            client_id="C1", title="Scheduled", description="d",
            scheduled_start=now + timedelta(hours=1),
            scheduled_end=now + timedelta(hours=2),
        )
        entries = self.svc.get_change_calendar()
        assert len(entries) == 1
        assert entries[0].title == "Scheduled"

    def test_get_change_calendar_filter_client(self):
        """Test calendar filtering by client."""
        now = datetime.now(timezone.utc)
        self.svc.create_change(
            client_id="C1", title="A", description="d",
            scheduled_start=now + timedelta(hours=1),
        )
        self.svc.create_change(
            client_id="C2", title="B", description="d",
            scheduled_start=now + timedelta(hours=2),
        )
        entries = self.svc.get_change_calendar(client_id="C1")
        assert len(entries) == 1

    def test_get_change_calendar_filter_date_range(self):
        """Test calendar filtering by date range."""
        now = datetime.now(timezone.utc)
        self.svc.create_change(
            client_id="C1", title="A", description="d",
            scheduled_start=now + timedelta(hours=1),
        )
        self.svc.create_change(
            client_id="C1", title="B", description="d",
            scheduled_start=now + timedelta(days=5),
        )
        entries = self.svc.get_change_calendar(
            start=now,
            end=now + timedelta(days=1),
        )
        assert len(entries) == 1

    def test_check_conflicts(self):
        """Test checking scheduling conflicts."""
        now = datetime.now(timezone.utc)
        self.svc.create_change(
            client_id="C1", title="Existing", description="d",
            scheduled_start=now + timedelta(hours=1),
            scheduled_end=now + timedelta(hours=3),
        )
        conflicts = self.svc.check_conflicts(
            now + timedelta(hours=2),
            now + timedelta(hours=4),
        )
        assert len(conflicts) == 1
        assert conflicts[0]["type"] == "change_overlap"

    def test_check_conflicts_no_overlap(self):
        """Test no conflicts when times don't overlap."""
        now = datetime.now(timezone.utc)
        self.svc.create_change(
            client_id="C1", title="Existing", description="d",
            scheduled_start=now + timedelta(hours=1),
            scheduled_end=now + timedelta(hours=2),
        )
        conflicts = self.svc.check_conflicts(
            now + timedelta(hours=3),
            now + timedelta(hours=4),
        )
        assert len(conflicts) == 0

    def test_check_conflicts_with_blackout(self):
        """Test blackout window shows as conflict."""
        now = datetime.now(timezone.utc)
        self.svc.create_blackout_window(
            client_id="C1", name="Freeze",
            start_time=now + timedelta(hours=1),
            end_time=now + timedelta(hours=5),
        )
        conflicts = self.svc.check_conflicts(
            now + timedelta(hours=2),
            now + timedelta(hours=3),
        )
        assert len(conflicts) == 1
        assert conflicts[0]["type"] == "blackout_window"

    # ========== Blackout Windows ==========

    def test_create_blackout_window(self):
        """Test creating a blackout window."""
        now = datetime.now(timezone.utc)
        bw = self.svc.create_blackout_window(
            client_id="C1",
            name="Holiday Freeze",
            start_time=now,
            end_time=now + timedelta(days=7),
            reason="End of year freeze",
        )
        assert bw.window_id.startswith("BLK-")
        assert bw.name == "Holiday Freeze"

    def test_list_blackout_windows(self):
        """Test listing blackout windows."""
        now = datetime.now(timezone.utc)
        self.svc.create_blackout_window(
            client_id="C1", name="A",
            start_time=now, end_time=now + timedelta(days=1),
        )
        self.svc.create_blackout_window(
            client_id="C2", name="B",
            start_time=now, end_time=now + timedelta(days=1),
        )
        all_bw = self.svc.list_blackout_windows()
        assert len(all_bw) == 2

    def test_list_blackout_windows_filter_client(self):
        """Test filtering blackout windows by client."""
        now = datetime.now(timezone.utc)
        self.svc.create_blackout_window(
            client_id="C1", name="A",
            start_time=now, end_time=now + timedelta(days=1),
        )
        self.svc.create_blackout_window(
            client_id="C2", name="B",
            start_time=now, end_time=now + timedelta(days=1),
        )
        filtered = self.svc.list_blackout_windows(client_id="C1")
        assert len(filtered) == 1

    def test_delete_blackout_window(self):
        """Test deleting a blackout window."""
        now = datetime.now(timezone.utc)
        bw = self.svc.create_blackout_window(
            client_id="C1", name="Delete me",
            start_time=now, end_time=now + timedelta(days=1),
        )
        assert self.svc.delete_blackout_window(bw.window_id) is True
        assert len(self.svc.list_blackout_windows()) == 0

    def test_delete_blackout_not_found(self):
        """Test deleting non-existent blackout."""
        assert self.svc.delete_blackout_window("BLK-999") is False

    def test_check_blackout(self):
        """Test checking if a time is in a blackout."""
        now = datetime.now(timezone.utc)
        self.svc.create_blackout_window(
            client_id="C1", name="Active",
            start_time=now - timedelta(hours=1),
            end_time=now + timedelta(hours=1),
        )
        assert self.svc.check_blackout(now) is True
        assert self.svc.check_blackout(now + timedelta(hours=2)) is False

    # ========== Analytics ==========

    def test_get_change_success_rate_no_changes(self):
        """Test success rate with no changes."""
        assert self.svc.get_change_success_rate() == 100.0

    def test_get_change_success_rate(self):
        """Test success rate calculation."""
        # Create 2 completed, 1 failed
        for i in range(2):
            cr = self._create_implementing_change()
            self.svc.complete_change(cr.change_id, success=True)
        cr_fail = self._create_implementing_change()
        self.svc.complete_change(cr_fail.change_id, success=False)

        rate = self.svc.get_change_success_rate()
        assert rate == pytest.approx(66.7, abs=0.1)

    def test_get_avg_implementation_time_no_data(self):
        """Test avg implementation time with no completed changes."""
        assert self.svc.get_avg_implementation_time() == 0.0

    def test_get_changes_by_category(self):
        """Test category distribution."""
        self.svc.create_change(client_id="C1", title="A", description="d", category=ChangeCategory.NETWORK)
        self.svc.create_change(client_id="C1", title="B", description="d", category=ChangeCategory.NETWORK)
        self.svc.create_change(client_id="C1", title="C", description="d", category=ChangeCategory.SECURITY)
        dist = self.svc.get_changes_by_category()
        assert dist["network"] == 2
        assert dist["security"] == 1

    def test_get_risk_distribution(self):
        """Test risk distribution."""
        self.svc.create_change(client_id="C1", title="A", description="d")
        dist = self.svc.get_risk_distribution()
        assert "medium" in dist

    # ========== Dashboard ==========

    def test_get_dashboard(self):
        """Test aggregated dashboard."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        dashboard = self.svc.get_dashboard()
        assert dashboard["total_changes"] == 1
        assert "success_rate" in dashboard
        assert "risk_distribution" in dashboard
        assert "by_status" in dashboard
        assert "by_category" in dashboard
        assert "pending_approvals" in dashboard
        assert "scheduled_changes" in dashboard
        assert "recent_pirs" in dashboard
        assert "blackout_windows_active" in dashboard

    def test_dashboard_with_pending_approvals(self):
        """Test dashboard shows pending approvals."""
        cr = self.svc.create_change(
            client_id="C1", title="Needs Approval", description="d",
            approvers_required=["mgr1"],
        )
        self.svc.submit_change(cr.change_id)
        dashboard = self.svc.get_dashboard()
        assert dashboard["pending_approvals"] == 1

    # ========== Serialization ==========

    def test_change_to_dict(self):
        """Test change serialization."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        d = self.svc.change_to_dict(cr)
        assert d["change_id"] == cr.change_id
        assert d["status"] == "draft"
        assert "created_at" in d

    def test_template_to_dict(self):
        """Test template serialization."""
        tpl = self.svc.get_template("TPL-001")
        d = self.svc.template_to_dict(tpl)
        assert d["template_id"] == "TPL-001"
        assert d["name"] == "Server Patch Deployment"

    def test_blackout_to_dict(self):
        """Test blackout serialization."""
        now = datetime.now(timezone.utc)
        bw = self.svc.create_blackout_window(
            client_id="C1", name="Test",
            start_time=now, end_time=now + timedelta(hours=1),
        )
        d = self.svc.blackout_to_dict(bw)
        assert d["window_id"] == bw.window_id
        assert "start_time" in d

    # ========== Enum Tests ==========

    def test_change_type_enum(self):
        assert ChangeType.STANDARD.value == "standard"
        assert ChangeType.NORMAL.value == "normal"
        assert ChangeType.EMERGENCY.value == "emergency"

    def test_change_status_enum(self):
        assert len(ChangeStatus) == 10

    def test_risk_level_enum(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.CRITICAL.value == "critical"

    # ========== Full Lifecycle ==========

    def test_full_lifecycle_standard_change(self):
        """Test complete lifecycle: draft -> submit -> approve -> implement -> complete -> PIR."""
        # Create
        cr = self.svc.create_change(
            client_id="ACME",
            title="Server Patch Q1",
            description="Quarterly patch deployment",
            change_type=ChangeType.STANDARD,
            category=ChangeCategory.SOFTWARE,
            priority=ChangePriority.MEDIUM,
            approvers_required=["cab_chair"],
            requested_by="sysadmin",
        )
        assert cr.status == ChangeStatus.DRAFT

        # Submit
        self.svc.submit_change(cr.change_id)
        assert cr.status == ChangeStatus.SUBMITTED

        # Approve
        self.svc.approve_change(cr.change_id, "cab_chair", ApprovalDecision.APPROVED, "Go ahead")
        assert cr.status == ChangeStatus.APPROVED

        # Implement
        self.svc.start_implementation(cr.change_id)
        assert cr.status == ChangeStatus.IMPLEMENTING

        # Complete
        self.svc.complete_change(cr.change_id, success=True)
        assert cr.status == ChangeStatus.COMPLETED

        # PIR
        pir = self.svc.create_pir(cr.change_id, {
            "was_successful": True,
            "objectives_met": True,
            "reviewed_by": "change_manager",
        })
        assert pir.was_successful is True
        assert self.svc.get_change(cr.change_id).pir_completed is True

    def test_full_lifecycle_emergency_rollback(self):
        """Test emergency change that gets rolled back."""
        cr = self.svc.create_change(
            client_id="ACME",
            title="Emergency Security Patch",
            description="Critical CVE fix",
            change_type=ChangeType.EMERGENCY,
            category=ChangeCategory.SECURITY,
            priority=ChangePriority.CRITICAL,
        )
        self.svc.submit_change(cr.change_id)
        self.svc.approve_change(cr.change_id, "security_lead", ApprovalDecision.APPROVED)
        self.svc.start_implementation(cr.change_id)
        self.svc.rollback_change(cr.change_id, reason="Broke authentication flow")
        assert cr.status == ChangeStatus.ROLLED_BACK

        pir = self.svc.create_pir(cr.change_id, {
            "was_successful": False,
            "issues_encountered": ["Auth service failed after patch"],
            "lessons_learned": ["Test auth flow before deploying"],
        })
        assert pir.was_successful is False

    # ========== Helpers ==========

    def _create_implementing_change(self) -> ChangeRequest:
        """Helper: create a change and advance it to IMPLEMENTING status."""
        cr = self.svc.create_change(client_id="C1", title="Test", description="d")
        self.svc.submit_change(cr.change_id)
        self.svc.approve_change(cr.change_id, "admin", ApprovalDecision.APPROVED)
        self.svc.start_implementation(cr.change_id)
        return cr
