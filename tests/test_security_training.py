"""
Tests for Security Awareness Training & Phishing Simulation Service.
Full coverage of courses, assignments, campaigns, risk scoring, and analytics.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.security_training import (
    SecurityTrainingService,
    CourseCategory,
    CampaignStatus,
    PhishCategory,
    AssignmentStatus,
    Difficulty,
    PhishEventType,
    TrainingCourse,
    TrainingAssignment,
    PhishingTemplate,
    PhishingCampaign,
    PhishingEvent,
    UserRiskScore,
    Module,
)


@pytest.fixture
def svc():
    """Fresh SecurityTrainingService (in-memory)."""
    return SecurityTrainingService()


# ============================================================
# Default Data Tests
# ============================================================

class TestDefaultData:
    def test_default_templates_loaded(self, svc):
        templates = svc.list_templates()
        assert len(templates) == 8
        ids = {t.template_id for t in templates}
        assert "TPL-PHISH-001" in ids
        assert "TPL-PHISH-008" in ids

    def test_default_courses_loaded(self, svc):
        courses = svc.list_courses()
        assert len(courses) == 5
        ids = {c.course_id for c in courses}
        assert "CRS-SAT-001" in ids
        assert "CRS-SAT-005" in ids

    def test_default_phishing_101_is_mandatory(self, svc):
        course = svc.get_course("CRS-SAT-001")
        assert course is not None
        assert course.is_mandatory is True
        assert course.title == "Phishing 101"
        assert course.duration_minutes == 20

    def test_template_categories(self, svc):
        cred_harvest = svc.list_templates(category="credential_harvest")
        assert len(cred_harvest) >= 3
        bec = svc.list_templates(category="bec")
        assert len(bec) == 2


# ============================================================
# Course Management Tests
# ============================================================

class TestCourseManagement:
    def test_create_course(self, svc):
        course = svc.create_course(
            title="Custom Course", description="Test description",
            category="mobile_security", difficulty="advanced",
            duration_minutes=45, passing_score=90.0, is_mandatory=True,
        )
        assert course.course_id.startswith("CRS-")
        assert course.title == "Custom Course"
        assert course.category == CourseCategory.MOBILE_SECURITY
        assert course.difficulty == Difficulty.ADVANCED
        assert course.duration_minutes == 45
        assert course.passing_score == 90.0
        assert course.is_mandatory is True

    def test_create_course_with_modules(self, svc):
        course = svc.create_course(
            title="Module Test", content_modules=[
                {"title": "Intro", "content_type": "video", "duration_minutes": 5},
                {"title": "Quiz", "content_type": "quiz", "duration_minutes": 10},
            ],
        )
        assert len(course.content_modules) == 2
        assert course.content_modules[0].title == "Intro"
        assert course.content_modules[1].content_type == "quiz"

    def test_get_course(self, svc):
        course = svc.get_course("CRS-SAT-001")
        assert course is not None
        assert course.title == "Phishing 101"

    def test_get_course_not_found(self, svc):
        assert svc.get_course("NONEXISTENT") is None

    def test_list_courses_by_category(self, svc):
        courses = svc.list_courses(category="phishing_awareness")
        assert len(courses) >= 1
        for c in courses:
            assert c.category == CourseCategory.PHISHING_AWARENESS

    def test_list_mandatory_courses(self, svc):
        mandatory = svc.list_courses(mandatory_only=True)
        assert len(mandatory) >= 1
        for c in mandatory:
            assert c.is_mandatory is True

    def test_update_course(self, svc):
        course = svc.update_course("CRS-SAT-002", title="Updated Title", duration_minutes=30)
        assert course is not None
        assert course.title == "Updated Title"
        assert course.duration_minutes == 30

    def test_update_course_not_found(self, svc):
        result = svc.update_course("NONEXISTENT", title="Nope")
        assert result is None


# ============================================================
# Assignment Tests
# ============================================================

class TestAssignments:
    def test_assign_training(self, svc):
        users = [{"email": "alice@test.com", "name": "Alice"}, {"email": "bob@test.com", "name": "Bob"}]
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001", users)
        assert len(assignments) == 2
        assert assignments[0].assignment_id.startswith("TA-")
        assert assignments[0].client_id == "CLIENT-1"
        assert assignments[0].course_id == "CRS-SAT-001"
        assert assignments[0].status == AssignmentStatus.ASSIGNED

    def test_assign_training_with_due_date(self, svc):
        due = datetime.now(timezone.utc) + timedelta(days=14)
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001",
                                          [{"email": "charlie@test.com"}], due_date=due)
        assert assignments[0].due_date == due

    def test_start_training(self, svc):
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001",
                                          [{"email": "alice@test.com"}])
        result = svc.start_training(assignments[0].assignment_id)
        assert result is not None
        assert result.status == AssignmentStatus.IN_PROGRESS
        assert result.started_at is not None
        assert result.attempts == 1

    def test_complete_training_pass(self, svc):
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001",
                                          [{"email": "alice@test.com"}])
        aid = assignments[0].assignment_id
        svc.start_training(aid)
        result = svc.complete_training(aid, score=95.0)
        assert result.status == AssignmentStatus.COMPLETED
        assert result.score == 95.0
        assert result.certificate_id is not None
        assert result.certificate_id.startswith("CERT-")

    def test_complete_training_fail(self, svc):
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001",
                                          [{"email": "alice@test.com"}])
        aid = assignments[0].assignment_id
        svc.start_training(aid)
        result = svc.complete_training(aid, score=50.0)
        assert result.status == AssignmentStatus.IN_PROGRESS  # didn't pass
        assert result.certificate_id is None

    def test_get_assignments_filters(self, svc):
        svc.assign_training("CLIENT-1", "CRS-SAT-001", [{"email": "a@test.com"}])
        svc.assign_training("CLIENT-2", "CRS-SAT-002", [{"email": "b@test.com"}])

        all_a = svc.get_assignments()
        assert len(all_a) >= 2

        c1 = svc.get_assignments(client_id="CLIENT-1")
        assert all(a.client_id == "CLIENT-1" for a in c1)

        by_email = svc.get_assignments(user_email="b@test.com")
        assert all(a.user_email == "b@test.com" for a in by_email)

    def test_overdue_assignments(self, svc):
        past = datetime.now(timezone.utc) - timedelta(days=7)
        svc.assign_training("CLIENT-1", "CRS-SAT-001",
                            [{"email": "late@test.com"}], due_date=past)
        overdue = svc.get_overdue_assignments("CLIENT-1")
        assert len(overdue) >= 1
        assert overdue[0].user_email == "late@test.com"

    def test_start_not_found(self, svc):
        assert svc.start_training("NONEXISTENT") is None

    def test_complete_not_found(self, svc):
        assert svc.complete_training("NONEXISTENT", 100.0) is None


# ============================================================
# Phishing Template Tests
# ============================================================

class TestTemplates:
    def test_create_template(self, svc):
        t = svc.create_template(
            name="Custom Template", category="attachment",
            subject="Important Doc", sender_name="HR", difficulty="high",
        )
        assert t.template_id.startswith("TPL-")
        assert t.name == "Custom Template"
        assert t.category == PhishCategory.ATTACHMENT

    def test_list_templates(self, svc):
        templates = svc.list_templates()
        assert len(templates) >= 8

    def test_list_templates_by_category(self, svc):
        ml = svc.list_templates(category="malware_link")
        assert len(ml) >= 2

    def test_get_template(self, svc):
        t = svc.get_template("TPL-PHISH-001")
        assert t is not None
        assert t.name == "Microsoft 365 Password Expiry"

    def test_get_template_not_found(self, svc):
        assert svc.get_template("NONEXISTENT") is None


# ============================================================
# Phishing Campaign Tests
# ============================================================

class TestCampaigns:
    def test_create_campaign(self, svc):
        c = svc.create_campaign(
            client_id="CLIENT-1", name="Q1 Phishing Test",
            template_id="TPL-PHISH-001",
            target_users=[{"email": "user1@test.com"}, {"email": "user2@test.com"}],
        )
        assert c.campaign_id.startswith("PC-")
        assert c.status == CampaignStatus.DRAFT
        assert len(c.target_users) == 2

    def test_schedule_campaign(self, svc):
        c = svc.create_campaign("CLIENT-1", "Scheduled Test", "TPL-PHISH-001")
        future = datetime.now(timezone.utc) + timedelta(days=7)
        result = svc.schedule_campaign(c.campaign_id, future)
        assert result.status == CampaignStatus.SCHEDULED
        assert result.scheduled_at == future

    def test_start_campaign(self, svc):
        c = svc.create_campaign(
            "CLIENT-1", "Live Test", "TPL-PHISH-002",
            target_users=[
                {"email": f"user{i}@test.com"} for i in range(10)
            ],
        )
        result = svc.start_campaign(c.campaign_id)
        assert result.status == CampaignStatus.RUNNING
        assert result.started_at is not None
        assert result.emails_sent == 10
        assert result.emails_opened >= 0
        assert result.links_clicked >= 0

    def test_list_campaigns(self, svc):
        svc.create_campaign("CLIENT-1", "Test 1", "TPL-PHISH-001")
        svc.create_campaign("CLIENT-2", "Test 2", "TPL-PHISH-002")
        all_c = svc.list_campaigns()
        assert len(all_c) >= 2

        c1 = svc.list_campaigns(client_id="CLIENT-1")
        assert all(c.client_id == "CLIENT-1" for c in c1)

    def test_get_campaign(self, svc):
        c = svc.create_campaign("CLIENT-1", "Find Me", "TPL-PHISH-001")
        found = svc.get_campaign(c.campaign_id)
        assert found is not None
        assert found.name == "Find Me"

    def test_get_campaign_not_found(self, svc):
        assert svc.get_campaign("NONEXISTENT") is None

    def test_schedule_campaign_not_found(self, svc):
        assert svc.schedule_campaign("NONEXISTENT", datetime.now(timezone.utc)) is None

    def test_start_campaign_not_found(self, svc):
        assert svc.start_campaign("NONEXISTENT") is None

    def test_record_phish_event(self, svc):
        c = svc.create_campaign("CLIENT-1", "Event Test", "TPL-PHISH-001",
                                [{"email": "target@test.com"}])
        svc.start_campaign(c.campaign_id)
        initial_opened = c.emails_opened
        event = svc.record_phish_event(c.campaign_id, "target@test.com", "opened")
        assert event is not None
        assert event.event_type == PhishEventType.OPENED
        assert c.emails_opened == initial_opened + 1

    def test_record_phish_event_not_found(self, svc):
        assert svc.record_phish_event("NONEXISTENT", "x@y.com", "opened") is None


# ============================================================
# Risk Scoring Tests
# ============================================================

class TestRiskScoring:
    def test_calculate_user_risk_baseline(self, svc):
        ur = svc.calculate_user_risk("newuser@test.com", "CLIENT-1")
        assert ur.risk_score == 50.0  # baseline with no history
        assert ur.email == "newuser@test.com"

    def test_risk_increases_with_phishing_fails(self, svc):
        c = svc.create_campaign("CLIENT-1", "Risk Test", "TPL-PHISH-001",
                                [{"email": "risky@test.com"}])
        svc.start_campaign(c.campaign_id)
        # Record extra clicks
        svc.record_phish_event(c.campaign_id, "risky@test.com", "clicked")
        svc.record_phish_event(c.campaign_id, "risky@test.com", "submitted")
        ur = svc.calculate_user_risk("risky@test.com", "CLIENT-1")
        assert ur.risk_score > 50.0
        assert ur.phishing_fail_count >= 2

    def test_risk_decreases_with_training(self, svc):
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001",
                                          [{"email": "trained@test.com"}])
        svc.start_training(assignments[0].assignment_id)
        svc.complete_training(assignments[0].assignment_id, 95.0)
        ur = svc.calculate_user_risk("trained@test.com", "CLIENT-1")
        assert ur.risk_score < 50.0
        assert ur.training_completed_count >= 1

    def test_get_user_risks(self, svc):
        svc.calculate_user_risk("a@test.com", "CLIENT-1")
        svc.calculate_user_risk("b@test.com", "CLIENT-1")
        svc.calculate_user_risk("c@test.com", "CLIENT-2")
        risks = svc.get_user_risks("CLIENT-1")
        assert len(risks) == 2

    def test_get_highest_risk_users(self, svc):
        # Create users with different risk profiles
        svc.calculate_user_risk("low@test.com", "CLIENT-1")
        c = svc.create_campaign("CLIENT-1", "HR", "TPL-PHISH-001",
                                [{"email": "high@test.com"}])
        svc.start_campaign(c.campaign_id)
        svc.record_phish_event(c.campaign_id, "high@test.com", "clicked")
        svc.record_phish_event(c.campaign_id, "high@test.com", "submitted")
        svc.calculate_user_risk("high@test.com", "CLIENT-1")

        highest = svc.get_highest_risk_users("CLIENT-1", limit=5)
        assert len(highest) >= 1
        assert highest[0].email == "high@test.com"

    def test_risk_with_reporting_lowers_score(self, svc):
        c = svc.create_campaign("CLIENT-1", "Reporter Test", "TPL-PHISH-001",
                                [{"email": "reporter@test.com"}])
        svc.start_campaign(c.campaign_id)
        svc.record_phish_event(c.campaign_id, "reporter@test.com", "reported")
        svc.record_phish_event(c.campaign_id, "reporter@test.com", "reported")
        ur = svc.calculate_user_risk("reporter@test.com", "CLIENT-1")
        assert ur.risk_score < 50.0
        assert ur.phishing_report_count >= 2


# ============================================================
# Compliance & Analytics Tests
# ============================================================

class TestComplianceAnalytics:
    def test_training_compliance(self, svc):
        users = [{"email": f"u{i}@test.com"} for i in range(4)]
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001", users)
        # Complete 2 of 4
        svc.start_training(assignments[0].assignment_id)
        svc.complete_training(assignments[0].assignment_id, 90.0)
        svc.start_training(assignments[1].assignment_id)
        svc.complete_training(assignments[1].assignment_id, 85.0)

        compliance = svc.get_training_compliance("CLIENT-1")
        assert compliance["client_id"] == "CLIENT-1"
        assert compliance["overall_completion_rate"] == 50.0
        assert len(compliance["courses"]) >= 1

    def test_training_compliance_empty(self, svc):
        compliance = svc.get_training_compliance("EMPTY-CLIENT")
        assert compliance["overall_completion_rate"] == 0.0
        assert compliance["courses"] == []

    def test_phishing_trends(self, svc):
        trends = svc.get_phishing_trends("CLIENT-1", periods=3)
        assert len(trends) == 3
        for t in trends:
            assert "period" in t
            assert "click_rate" in t
            assert "report_rate" in t

    def test_click_rate_by_template(self, svc):
        c = svc.create_campaign("CLIENT-1", "Template Stats", "TPL-PHISH-001",
                                [{"email": f"u{i}@test.com"} for i in range(5)])
        svc.start_campaign(c.campaign_id)
        rates = svc.get_click_rate_by_template()
        assert len(rates) >= 1
        assert "click_rate" in rates[0]

    def test_improvement_over_time_insufficient_data(self, svc):
        result = svc.get_improvement_over_time("CLIENT-1")
        assert result["data_points"] < 2
        assert result["improvement_pct"] == 0.0

    def test_improvement_over_time(self, svc):
        # Create two campaigns with different times
        for i in range(4):
            c = svc.create_campaign("CLIENT-1", f"Camp {i}", "TPL-PHISH-001",
                                    [{"email": f"u{j}@test.com"} for j in range(5)])
            svc.start_campaign(c.campaign_id)
            # Backdate started_at
            c.started_at = datetime.now(timezone.utc) - timedelta(days=30 * (4 - i))

        result = svc.get_improvement_over_time("CLIENT-1")
        assert result["data_points"] == 4
        assert "first_period_click_rate" in result
        assert "second_period_click_rate" in result


# ============================================================
# Dashboard Tests
# ============================================================

class TestDashboard:
    def test_dashboard_empty(self, svc):
        dash = svc.get_dashboard("EMPTY-CLIENT")
        assert dash["client_id"] == "EMPTY-CLIENT"
        assert dash["compliance_rate"] == 0.0
        assert dash["active_campaigns"] == 0
        assert dash["overdue_assignments"] == 0

    def test_dashboard_populated(self, svc):
        # Set up some data
        users = [{"email": "d1@test.com"}, {"email": "d2@test.com"}]
        past = datetime.now(timezone.utc) - timedelta(days=1)
        svc.assign_training("CLIENT-1", "CRS-SAT-001", users, due_date=past)
        c = svc.create_campaign("CLIENT-1", "Dash Campaign", "TPL-PHISH-001",
                                target_users=users)
        svc.start_campaign(c.campaign_id)
        svc.calculate_user_risk("d1@test.com", "CLIENT-1")
        svc.calculate_user_risk("d2@test.com", "CLIENT-1")

        dash = svc.get_dashboard("CLIENT-1")
        assert dash["client_id"] == "CLIENT-1"
        assert "risk_distribution" in dash
        assert "highest_risk_users" in dash
        assert dash["total_users_tracked"] >= 2


# ============================================================
# Enum Tests
# ============================================================

class TestEnums:
    def test_course_category_values(self):
        assert CourseCategory.PHISHING_AWARENESS.value == "phishing_awareness"
        assert CourseCategory.MOBILE_SECURITY.value == "mobile_security"
        assert len(CourseCategory) == 8

    def test_campaign_status_values(self):
        assert CampaignStatus.DRAFT.value == "draft"
        assert CampaignStatus.CANCELLED.value == "cancelled"
        assert len(CampaignStatus) == 5

    def test_phish_category_values(self):
        assert PhishCategory.CREDENTIAL_HARVEST.value == "credential_harvest"
        assert PhishCategory.BEC.value == "bec"
        assert len(PhishCategory) == 5

    def test_difficulty_values(self):
        assert Difficulty.BEGINNER.value == "beginner"
        assert Difficulty.ADVANCED.value == "advanced"
        assert len(Difficulty) == 3


# ============================================================
# Dataclass Tests
# ============================================================

class TestDataclasses:
    def test_module_dataclass(self):
        m = Module(module_id="M-1", title="Test", content_type="video")
        assert m.module_id == "M-1"
        assert m.duration_minutes == 5
        assert m.order == 0

    def test_training_course_dataclass(self):
        c = TrainingCourse(course_id="CRS-1", title="Test Course")
        assert c.course_id == "CRS-1"
        assert c.passing_score == 80.0
        assert c.is_mandatory is False

    def test_training_assignment_dataclass(self):
        a = TrainingAssignment(
            assignment_id="TA-1", client_id="C1",
            course_id="CRS-1", user_email="test@test.com",
        )
        assert a.status == AssignmentStatus.ASSIGNED
        assert a.attempts == 0

    def test_phishing_template_dataclass(self):
        t = PhishingTemplate(template_id="TPL-1", name="Test")
        assert t.category == PhishCategory.CREDENTIAL_HARVEST
        assert t.difficulty == "medium"

    def test_phishing_campaign_dataclass(self):
        c = PhishingCampaign(
            campaign_id="PC-1", client_id="C1",
            name="Test", template_id="TPL-1",
        )
        assert c.status == CampaignStatus.DRAFT
        assert c.emails_sent == 0

    def test_phishing_event_dataclass(self):
        e = PhishingEvent(
            event_id="EVT-1", campaign_id="PC-1",
            user_email="test@test.com", event_type=PhishEventType.CLICKED,
        )
        assert e.event_type == PhishEventType.CLICKED

    def test_user_risk_score_dataclass(self):
        ur = UserRiskScore(
            user_id="USR-1", client_id="C1", email="test@test.com",
        )
        assert ur.risk_score == 50.0
        assert ur.phishing_fail_count == 0


# ============================================================
# Edge Cases
# ============================================================

class TestEdgeCases:
    def test_simulate_campaign_no_targets(self, svc):
        c = svc.create_campaign("CLIENT-1", "Empty", "TPL-PHISH-001", target_users=[])
        svc.start_campaign(c.campaign_id)
        assert c.emails_sent == 0

    def test_multiple_attempts(self, svc):
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001",
                                          [{"email": "retry@test.com"}])
        aid = assignments[0].assignment_id
        svc.start_training(aid)
        svc.complete_training(aid, 50.0)  # fail
        # Reattempt
        svc.start_training(aid)
        assert svc._assignments[aid].attempts == 2

    def test_list_campaigns_by_status(self, svc):
        c1 = svc.create_campaign("CLIENT-1", "Draft", "TPL-PHISH-001")
        c2 = svc.create_campaign("CLIENT-1", "Running", "TPL-PHISH-001",
                                 [{"email": "u@t.com"}])
        svc.start_campaign(c2.campaign_id)
        drafts = svc.list_campaigns(status="draft")
        running = svc.list_campaigns(status="running")
        assert any(c.campaign_id == c1.campaign_id for c in drafts)
        assert any(c.campaign_id == c2.campaign_id for c in running)

    def test_record_all_event_types(self, svc):
        c = svc.create_campaign("CLIENT-1", "All Events", "TPL-PHISH-001",
                                [{"email": "target@t.com"}])
        svc.start_campaign(c.campaign_id)
        initial = {
            "opened": c.emails_opened,
            "clicked": c.links_clicked,
            "submitted": c.credentials_submitted,
            "reported": c.reported_count,
        }
        svc.record_phish_event(c.campaign_id, "target@t.com", "opened")
        assert c.emails_opened == initial["opened"] + 1
        svc.record_phish_event(c.campaign_id, "target@t.com", "clicked")
        assert c.links_clicked == initial["clicked"] + 1
        svc.record_phish_event(c.campaign_id, "target@t.com", "submitted")
        assert c.credentials_submitted == initial["submitted"] + 1
        svc.record_phish_event(c.campaign_id, "target@t.com", "reported")
        assert c.reported_count == initial["reported"] + 1

    def test_overdue_excludes_completed(self, svc):
        past = datetime.now(timezone.utc) - timedelta(days=7)
        assignments = svc.assign_training("CLIENT-1", "CRS-SAT-001",
                                          [{"email": "done@test.com"}], due_date=past)
        svc.start_training(assignments[0].assignment_id)
        svc.complete_training(assignments[0].assignment_id, 90.0)
        overdue = svc.get_overdue_assignments("CLIENT-1")
        assert not any(a.user_email == "done@test.com" for a in overdue)
