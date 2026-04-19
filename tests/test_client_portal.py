"""
Tests for MSP Client Portal Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.client_portal import (
    ClientPortalService,
    PortalClient,
    PortalUser,
    PortalReport,
    ServiceRequest,
    Announcement,
    SatisfactionSurvey,
    ReportType,
    RequestType,
    RequestStatus,
    PortalRole,
    AnnouncementSeverity,
)


class TestClientPortalService:
    """Tests for ClientPortalService class"""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = ClientPortalService()

    # ========== Client Management ==========

    def test_register_client_basic(self):
        """Test basic client registration."""
        client = self.service.register_client(
            company_name="Acme Corp",
            primary_contact_email="admin@acme.com",
            primary_contact_name="John Doe",
        )
        assert client is not None
        assert client.client_id.startswith("PC-")
        assert client.company_name == "Acme Corp"
        assert client.primary_contact_email == "admin@acme.com"
        assert client.primary_contact_name == "John Doe"
        assert client.portal_enabled is True

    def test_register_client_full(self):
        """Test client registration with all options."""
        client = self.service.register_client(
            company_name="TechCo",
            primary_contact_email="tech@techco.io",
            primary_contact_name="Jane Smith",
            plan_id="enterprise",
            endpoints_count=150,
            users_count=75,
            portal_theme="WL-BRAND01",
        )
        assert client.plan_id == "enterprise"
        assert client.endpoints_count == 150
        assert client.users_count == 75
        assert client.portal_theme == "WL-BRAND01"

    def test_get_client(self):
        """Test retrieving a client by ID."""
        client = self.service.register_client(
            company_name="GetTest",
            primary_contact_email="get@test.com",
            primary_contact_name="Get User",
        )
        retrieved = self.service.get_client(client.client_id)
        assert retrieved is not None
        assert retrieved.client_id == client.client_id

    def test_get_client_not_found(self):
        """Test retrieving a nonexistent client."""
        assert self.service.get_client("PC-NONEXIST") is None

    def test_list_clients(self):
        """Test listing all clients."""
        self.service.register_client("A", "a@a.com", "A")
        self.service.register_client("B", "b@b.com", "B")
        clients = self.service.list_clients()
        assert len(clients) == 2

    def test_list_clients_filter_enabled(self):
        """Test listing clients filtered by portal_enabled."""
        c1 = self.service.register_client("Enabled", "e@e.com", "E")
        c2 = self.service.register_client("Disabled", "d@d.com", "D")
        self.service.disable_portal(c2.client_id)
        enabled = self.service.list_clients(portal_enabled=True)
        disabled = self.service.list_clients(portal_enabled=False)
        assert len(enabled) == 1
        assert len(disabled) == 1

    def test_update_client(self):
        """Test updating client fields."""
        client = self.service.register_client("Old Name", "o@o.com", "O")
        updated = self.service.update_client(client.client_id, company_name="New Name")
        assert updated.company_name == "New Name"

    def test_update_client_not_found(self):
        """Test updating a nonexistent client."""
        assert self.service.update_client("PC-NONEXIST", company_name="X") is None

    def test_enable_portal(self):
        """Test enabling portal."""
        client = self.service.register_client("EP", "ep@ep.com", "EP")
        self.service.disable_portal(client.client_id)
        assert self.service.get_client(client.client_id).portal_enabled is False
        self.service.enable_portal(client.client_id)
        assert self.service.get_client(client.client_id).portal_enabled is True

    def test_disable_portal(self):
        """Test disabling portal."""
        client = self.service.register_client("DP", "dp@dp.com", "DP")
        self.service.disable_portal(client.client_id)
        assert self.service.get_client(client.client_id).portal_enabled is False

    # ========== User Management ==========

    def test_create_portal_user(self):
        """Test creating a portal user."""
        client = self.service.register_client("UserTest", "u@u.com", "U")
        user = self.service.create_portal_user(
            client_id=client.client_id,
            email="user@usertest.com",
            name="Portal User",
            role=PortalRole.ADMIN,
        )
        assert user is not None
        assert user.user_id.startswith("PU-")
        assert user.client_id == client.client_id
        assert user.role == PortalRole.ADMIN

    def test_create_portal_user_invalid_client(self):
        """Test creating user for nonexistent client."""
        user = self.service.create_portal_user(
            client_id="PC-NONEXIST",
            email="no@no.com",
            name="No",
        )
        assert user is None

    def test_get_user(self):
        """Test retrieving a user."""
        client = self.service.register_client("UG", "ug@ug.com", "UG")
        user = self.service.create_portal_user(client.client_id, "ug@test.com", "UG User")
        retrieved = self.service.get_user(user.user_id)
        assert retrieved is not None
        assert retrieved.email == "ug@test.com"

    def test_list_users(self):
        """Test listing users."""
        client = self.service.register_client("LU", "lu@lu.com", "LU")
        self.service.create_portal_user(client.client_id, "a@lu.com", "A")
        self.service.create_portal_user(client.client_id, "b@lu.com", "B")
        users = self.service.list_users(client_id=client.client_id)
        assert len(users) == 2

    def test_update_user(self):
        """Test updating a user."""
        client = self.service.register_client("UU", "uu@uu.com", "UU")
        user = self.service.create_portal_user(client.client_id, "uu@test.com", "Old")
        updated = self.service.update_user(user.user_id, name="New")
        assert updated.name == "New"

    def test_deactivate_user(self):
        """Test deactivating a user."""
        client = self.service.register_client("DU", "du@du.com", "DU")
        user = self.service.create_portal_user(client.client_id, "du@test.com", "DU User")
        self.service.deactivate_user(user.user_id)
        assert self.service.get_user(user.user_id).is_active is False

    def test_create_user_with_permissions(self):
        """Test creating user with specific permissions."""
        client = self.service.register_client("Perm", "p@p.com", "P")
        user = self.service.create_portal_user(
            client.client_id, "p@test.com", "Perm User",
            role=PortalRole.REQUESTER,
            permissions=["submit_tickets", "view_reports"],
            mfa_enabled=True,
        )
        assert user.permissions == ["submit_tickets", "view_reports"]
        assert user.mfa_enabled is True
        assert user.role == PortalRole.REQUESTER

    # ========== Dashboard Aggregation ==========

    def test_get_client_dashboard(self):
        """Test aggregated client dashboard."""
        client = self.service.register_client(
            "Dashboard Co", "dash@co.com", "Dash",
            endpoints_count=100,
        )
        dashboard = self.service.get_client_dashboard(client.client_id)
        assert dashboard is not None
        assert dashboard["client_id"] == client.client_id
        assert dashboard["company_name"] == "Dashboard Co"
        assert "endpoint_health" in dashboard
        assert dashboard["endpoint_health"]["total"] == 100
        assert "open_tickets" in dashboard
        assert "sla_compliance_pct" in dashboard
        assert "security_posture_score" in dashboard
        assert "compliance_score" in dashboard
        assert "health_score" in dashboard
        assert "announcements" in dashboard

    def test_get_client_dashboard_not_found(self):
        """Test dashboard for nonexistent client."""
        assert self.service.get_client_dashboard("PC-NONEXIST") is None

    def test_dashboard_with_requests(self):
        """Test dashboard reflects open requests."""
        client = self.service.register_client("Req Co", "r@co.com", "R")
        user = self.service.create_portal_user(client.client_id, "r@test.com", "R")
        self.service.submit_request(
            client.client_id, user.user_id, RequestType.SOFTWARE_INSTALL,
            "Install VS Code",
        )
        dashboard = self.service.get_client_dashboard(client.client_id)
        assert dashboard["open_tickets"] == 1

    # ========== Reports ==========

    def test_generate_monthly_summary(self):
        """Test monthly summary report generation."""
        client = self.service.register_client("Report Co", "rp@co.com", "RP")
        report = self.service.generate_report(client.client_id, ReportType.MONTHLY_SUMMARY)
        assert report is not None
        assert report.report_id.startswith("RPT-")
        assert report.report_type == ReportType.MONTHLY_SUMMARY
        assert "endpoints_monitored" in report.data

    def test_generate_security_posture(self):
        """Test security posture report."""
        client = self.service.register_client("Sec Co", "sec@co.com", "Sec")
        report = self.service.generate_report(client.client_id, ReportType.SECURITY_POSTURE)
        assert report is not None
        assert "overall_score" in report.data
        assert "vulnerability_counts" in report.data

    def test_generate_compliance_report(self):
        """Test compliance report."""
        client = self.service.register_client("Comp Co", "comp@co.com", "Comp")
        report = self.service.generate_report(client.client_id, ReportType.COMPLIANCE)
        assert "frameworks" in report.data
        assert "NIST_CSF" in report.data["frameworks"]

    def test_generate_sla_report(self):
        """Test SLA performance report."""
        client = self.service.register_client("SLA Co", "sla@co.com", "SLA")
        report = self.service.generate_report(client.client_id, ReportType.SLA_PERFORMANCE)
        assert "overall_compliance_pct" in report.data
        assert "by_priority" in report.data

    def test_generate_incident_report(self):
        """Test incident report."""
        client = self.service.register_client("Inc Co", "inc@co.com", "Inc")
        report = self.service.generate_report(client.client_id, ReportType.INCIDENT)
        assert "total_incidents" in report.data

    def test_generate_executive_briefing(self):
        """Test executive briefing."""
        client = self.service.register_client("Exec Co", "exec@co.com", "Exec")
        report = self.service.generate_report(client.client_id, ReportType.EXECUTIVE_BRIEFING)
        assert "summary" in report.data
        assert "key_metrics" in report.data

    def test_generate_asset_inventory(self):
        """Test asset inventory report."""
        client = self.service.register_client("Asset Co", "asset@co.com", "Asset", endpoints_count=50)
        report = self.service.generate_report(client.client_id, ReportType.ASSET_INVENTORY)
        assert report.data["total_endpoints"] == 50

    def test_generate_patch_status(self):
        """Test patch status report."""
        client = self.service.register_client("Patch Co", "patch@co.com", "Patch")
        report = self.service.generate_report(client.client_id, ReportType.PATCH_STATUS)
        assert "fully_patched_pct" in report.data

    def test_generate_report_invalid_client(self):
        """Test report generation for nonexistent client."""
        assert self.service.generate_report("PC-NONEXIST", ReportType.COMPLIANCE) is None

    def test_list_reports(self):
        """Test listing reports."""
        client = self.service.register_client("LR Co", "lr@co.com", "LR")
        self.service.generate_report(client.client_id, ReportType.MONTHLY_SUMMARY)
        self.service.generate_report(client.client_id, ReportType.COMPLIANCE)
        reports = self.service.list_reports(client_id=client.client_id)
        assert len(reports) == 2

    def test_publish_report(self):
        """Test publishing a report."""
        client = self.service.register_client("Pub Co", "pub@co.com", "Pub")
        report = self.service.generate_report(client.client_id, ReportType.MONTHLY_SUMMARY)
        assert report.is_published is False
        published = self.service.publish_report(report.report_id)
        assert published.is_published is True

    def test_list_reports_published_only(self):
        """Test listing only published reports."""
        client = self.service.register_client("PO Co", "po@co.com", "PO")
        r1 = self.service.generate_report(client.client_id, ReportType.MONTHLY_SUMMARY)
        self.service.generate_report(client.client_id, ReportType.COMPLIANCE)
        self.service.publish_report(r1.report_id)
        published = self.service.list_reports(client_id=client.client_id, published_only=True)
        assert len(published) == 1

    # ========== Service Requests ==========

    def test_submit_request(self):
        """Test submitting a service request."""
        client = self.service.register_client("SR Co", "sr@co.com", "SR")
        user = self.service.create_portal_user(client.client_id, "sr@test.com", "SR User")
        req = self.service.submit_request(
            client_id=client.client_id,
            user_id=user.user_id,
            request_type=RequestType.NEW_USER,
            title="New user account",
            description="Need account for new hire",
            priority="high",
        )
        assert req is not None
        assert req.request_id.startswith("SR-")
        assert req.status == RequestStatus.SUBMITTED
        assert req.request_type == RequestType.NEW_USER
        assert req.priority == "high"

    def test_submit_request_invalid_client(self):
        """Test submitting request for nonexistent client."""
        assert self.service.submit_request(
            "PC-NONEXIST", "PU-1", RequestType.OTHER, "Test"
        ) is None

    def test_approve_request(self):
        """Test approving a service request."""
        client = self.service.register_client("AR Co", "ar@co.com", "AR")
        user = self.service.create_portal_user(client.client_id, "ar@test.com", "AR")
        req = self.service.submit_request(
            client.client_id, user.user_id, RequestType.VPN_SETUP, "VPN Access",
        )
        approved = self.service.approve_request(req.request_id, "admin-01")
        assert approved.status == RequestStatus.APPROVED
        assert approved.approved_by == "admin-01"

    def test_complete_request(self):
        """Test completing a service request."""
        client = self.service.register_client("CR Co", "cr@co.com", "CR")
        user = self.service.create_portal_user(client.client_id, "cr@test.com", "CR")
        req = self.service.submit_request(
            client.client_id, user.user_id, RequestType.EMAIL_SETUP, "Email Setup",
        )
        self.service.approve_request(req.request_id, "admin")
        completed = self.service.complete_request(req.request_id)
        assert completed.status == RequestStatus.COMPLETED
        assert completed.completed_at is not None

    def test_deny_request(self):
        """Test denying a service request."""
        client = self.service.register_client("DR Co", "dr@co.com", "DR")
        user = self.service.create_portal_user(client.client_id, "dr@test.com", "DR")
        req = self.service.submit_request(
            client.client_id, user.user_id, RequestType.HARDWARE_REQUEST, "New Laptop",
        )
        denied = self.service.deny_request(req.request_id, "admin")
        assert denied.status == RequestStatus.DENIED

    def test_cannot_complete_submitted_request(self):
        """Test cannot complete a request that hasn't been approved."""
        client = self.service.register_client("NC Co", "nc@co.com", "NC")
        user = self.service.create_portal_user(client.client_id, "nc@test.com", "NC")
        req = self.service.submit_request(
            client.client_id, user.user_id, RequestType.OTHER, "Test",
        )
        assert self.service.complete_request(req.request_id) is None

    def test_list_requests(self):
        """Test listing service requests."""
        client = self.service.register_client("LR2 Co", "lr2@co.com", "LR2")
        user = self.service.create_portal_user(client.client_id, "lr2@test.com", "LR2")
        self.service.submit_request(client.client_id, user.user_id, RequestType.NEW_USER, "R1")
        self.service.submit_request(client.client_id, user.user_id, RequestType.VPN_SETUP, "R2")
        reqs = self.service.list_requests(client_id=client.client_id)
        assert len(reqs) == 2

    def test_list_requests_by_status(self):
        """Test filtering requests by status."""
        client = self.service.register_client("FS Co", "fs@co.com", "FS")
        user = self.service.create_portal_user(client.client_id, "fs@test.com", "FS")
        r1 = self.service.submit_request(client.client_id, user.user_id, RequestType.NEW_USER, "R1")
        self.service.submit_request(client.client_id, user.user_id, RequestType.VPN_SETUP, "R2")
        self.service.approve_request(r1.request_id, "admin")
        approved = self.service.list_requests(client_id=client.client_id, status=RequestStatus.APPROVED)
        assert len(approved) == 1

    def test_all_request_types(self):
        """Test all request types can be submitted."""
        client = self.service.register_client("RT Co", "rt@co.com", "RT")
        user = self.service.create_portal_user(client.client_id, "rt@test.com", "RT")
        for rtype in RequestType:
            req = self.service.submit_request(
                client.client_id, user.user_id, rtype, f"Test {rtype.value}",
            )
            assert req is not None
            assert req.request_type == rtype

    # ========== Announcements ==========

    def test_create_announcement(self):
        """Test creating an announcement."""
        ann = self.service.create_announcement(
            title="Scheduled Maintenance",
            body="We will be performing maintenance on Saturday.",
            severity=AnnouncementSeverity.WARNING,
        )
        assert ann is not None
        assert ann.announcement_id.startswith("ANN-")
        assert ann.severity == AnnouncementSeverity.WARNING
        assert ann.target_clients == ["all"]

    def test_create_announcement_targeted(self):
        """Test creating a targeted announcement."""
        c1 = self.service.register_client("T1", "t1@t.com", "T1")
        ann = self.service.create_announcement(
            title="VIP Notice",
            target_clients=[c1.client_id],
        )
        assert c1.client_id in ann.target_clients

    def test_get_announcements_all(self):
        """Test getting announcements targeting 'all'."""
        client = self.service.register_client("GA Co", "ga@co.com", "GA")
        self.service.create_announcement(title="Global Alert")
        anns = self.service.get_announcements(client.client_id)
        assert len(anns) == 1

    def test_get_announcements_targeted(self):
        """Test getting targeted announcements."""
        c1 = self.service.register_client("T1", "t1@t.com", "T1")
        c2 = self.service.register_client("T2", "t2@t.com", "T2")
        self.service.create_announcement(title="Only C1", target_clients=[c1.client_id])
        assert len(self.service.get_announcements(c1.client_id)) == 1
        assert len(self.service.get_announcements(c2.client_id)) == 0

    def test_get_announcements_expired(self):
        """Test expired announcements are filtered out."""
        client = self.service.register_client("Exp Co", "exp@co.com", "Exp")
        self.service.create_announcement(
            title="Expired",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert len(self.service.get_announcements(client.client_id)) == 0

    def test_mark_read(self):
        """Test marking an announcement as read."""
        ann = self.service.create_announcement(title="Read Test")
        result = self.service.mark_read(ann.announcement_id, "PU-USER1")
        assert "PU-USER1" in result.read_by

    def test_mark_read_idempotent(self):
        """Test marking read twice doesn't duplicate."""
        ann = self.service.create_announcement(title="Idempotent")
        self.service.mark_read(ann.announcement_id, "PU-USER1")
        self.service.mark_read(ann.announcement_id, "PU-USER1")
        result = self.service.announcements[ann.announcement_id]
        assert result.read_by.count("PU-USER1") == 1

    def test_mark_read_not_found(self):
        """Test marking nonexistent announcement."""
        assert self.service.mark_read("ANN-NONEXIST", "PU-1") is None

    # ========== Satisfaction Surveys ==========

    def test_submit_survey(self):
        """Test submitting a satisfaction survey."""
        client = self.service.register_client("Sat Co", "sat@co.com", "Sat")
        survey = self.service.submit_survey(
            client_id=client.client_id,
            ticket_id="TKT-001",
            rating=5,
            comments="Excellent support!",
        )
        assert survey is not None
        assert survey.survey_id.startswith("SAT-")
        assert survey.rating == 5

    def test_submit_survey_invalid_rating(self):
        """Test survey with invalid rating."""
        client = self.service.register_client("Bad Co", "bad@co.com", "Bad")
        assert self.service.submit_survey(client.client_id, "TKT-001", 0) is None
        assert self.service.submit_survey(client.client_id, "TKT-001", 6) is None

    def test_get_surveys(self):
        """Test retrieving surveys for a client."""
        client = self.service.register_client("GS Co", "gs@co.com", "GS")
        self.service.submit_survey(client.client_id, "TKT-001", 4)
        self.service.submit_survey(client.client_id, "TKT-002", 5)
        surveys = self.service.get_surveys(client.client_id)
        assert len(surveys) == 2

    def test_get_satisfaction_score(self):
        """Test satisfaction score calculation."""
        client = self.service.register_client("Score Co", "score@co.com", "Score")
        self.service.submit_survey(client.client_id, "TKT-001", 4)
        self.service.submit_survey(client.client_id, "TKT-002", 5)
        self.service.submit_survey(client.client_id, "TKT-003", 3)
        score = self.service.get_satisfaction_score(client.client_id)
        assert score == 4.0

    def test_get_satisfaction_score_no_surveys(self):
        """Test satisfaction score with no surveys."""
        client = self.service.register_client("Empty Co", "empty@co.com", "Empty")
        assert self.service.get_satisfaction_score(client.client_id) == 0.0

    # ========== Health Score ==========

    def test_get_client_health_score(self):
        """Test composite health score calculation."""
        client = self.service.register_client("Health Co", "h@co.com", "H")
        score = self.service.get_client_health_score(client.client_id)
        assert "overall" in score
        assert "security_score" in score
        assert "compliance_score" in score
        assert "sla_score" in score
        assert "grade" in score
        assert score["overall"] > 0

    def test_health_score_with_satisfaction(self):
        """Test health score incorporates satisfaction data."""
        client = self.service.register_client("HS Co", "hs@co.com", "HS")
        self.service.submit_survey(client.client_id, "TKT-001", 5)
        self.service.submit_survey(client.client_id, "TKT-002", 5)
        score = self.service.get_client_health_score(client.client_id)
        assert score["satisfaction_score"] == 100.0

    def test_health_score_grade(self):
        """Test health score grading."""
        client = self.service.register_client("Grade Co", "g@co.com", "G")
        score = self.service.get_client_health_score(client.client_id)
        # Default scores should yield A or B grade
        assert score["grade"] in ("A", "B")

    # ========== Portal Dashboard (Admin) ==========

    def test_get_portal_dashboard(self):
        """Test MSP admin portal overview."""
        self.service.register_client("C1", "c1@c.com", "C1")
        self.service.register_client("C2", "c2@c.com", "C2")
        dashboard = self.service.get_portal_dashboard()
        assert dashboard["total_clients"] == 2
        assert dashboard["portals_enabled"] == 2
        assert "open_service_requests" in dashboard
        assert "avg_satisfaction" in dashboard

    def test_portal_dashboard_with_data(self):
        """Test admin dashboard reflects real data."""
        c1 = self.service.register_client("D1", "d1@d.com", "D1")
        c2 = self.service.register_client("D2", "d2@d.com", "D2")
        self.service.disable_portal(c2.client_id)
        u1 = self.service.create_portal_user(c1.client_id, "u1@d.com", "U1")
        self.service.submit_request(c1.client_id, u1.user_id, RequestType.NEW_USER, "Test")
        self.service.submit_survey(c1.client_id, "TKT-001", 4)
        self.service.create_announcement(title="Test Ann")

        dashboard = self.service.get_portal_dashboard()
        assert dashboard["portals_enabled"] == 1
        assert dashboard["portals_disabled"] == 1
        assert dashboard["total_portal_users"] == 1
        assert dashboard["open_service_requests"] == 1
        assert dashboard["avg_satisfaction"] == 4.0
        assert dashboard["active_announcements"] == 1

    # ========== Enum Coverage ==========

    def test_all_report_types(self):
        """Test all report types can be generated."""
        client = self.service.register_client("AllRpt Co", "allrpt@co.com", "AllRpt")
        for rtype in ReportType:
            report = self.service.generate_report(client.client_id, rtype)
            assert report is not None, f"Failed to generate {rtype.value}"
            assert report.report_type == rtype

    def test_portal_roles(self):
        """Test all portal roles."""
        client = self.service.register_client("Role Co", "role@co.com", "Role")
        for role in PortalRole:
            user = self.service.create_portal_user(
                client.client_id, f"{role.value}@test.com", f"User {role.value}",
                role=role,
            )
            assert user.role == role

    # ========== Edge Cases ==========

    def test_deactivated_user_not_in_list(self):
        """Test deactivated users are excluded from list."""
        client = self.service.register_client("DAL Co", "dal@co.com", "DAL")
        u1 = self.service.create_portal_user(client.client_id, "a@dal.com", "A")
        u2 = self.service.create_portal_user(client.client_id, "b@dal.com", "B")
        self.service.deactivate_user(u1.user_id)
        users = self.service.list_users(client_id=client.client_id)
        assert len(users) == 1
        assert users[0].user_id == u2.user_id

    def test_publish_nonexistent_report(self):
        """Test publishing a nonexistent report."""
        assert self.service.publish_report("RPT-NONEXIST") is None

    def test_approve_already_approved(self):
        """Test approving an already-approved request returns None."""
        client = self.service.register_client("AA Co", "aa@co.com", "AA")
        user = self.service.create_portal_user(client.client_id, "aa@test.com", "AA")
        req = self.service.submit_request(
            client.client_id, user.user_id, RequestType.OTHER, "Test",
        )
        self.service.approve_request(req.request_id, "admin")
        # Second approval should fail (status is no longer SUBMITTED)
        assert self.service.approve_request(req.request_id, "admin2") is None

    def test_deny_already_approved(self):
        """Test denying an already-approved request returns None."""
        client = self.service.register_client("DA Co", "da@co.com", "DA")
        user = self.service.create_portal_user(client.client_id, "da@test.com", "DA")
        req = self.service.submit_request(
            client.client_id, user.user_id, RequestType.OTHER, "Test",
        )
        self.service.approve_request(req.request_id, "admin")
        assert self.service.deny_request(req.request_id, "admin") is None
