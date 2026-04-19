"""
Tests for ITIL Problem Management Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.problem_management import (
    ProblemManagementService,
    ProblemStatus,
    ProblemPriority,
    ProblemCategory,
    RCAMethod,
    FixStatus,
    ProblemRecord,
    KnownError,
    RootCauseAnalysis,
    ProblemTrend,
)


class TestProblemManagementService:
    """Tests for ProblemManagementService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.svc = ProblemManagementService()

    # ========== Pre-seeded KEDB ==========

    def test_seeded_known_errors(self):
        """Test that 5 known errors are pre-seeded."""
        kes = self.svc.list_known_errors()
        assert len(kes) == 5

    def test_seeded_ke_printer_spooler(self):
        """Test printer spooler known error is present."""
        ke = self.svc.get_known_error("KE-00001")
        assert ke is not None
        assert "Print Spooler" in ke.title
        assert ke.permanent_fix_status == FixStatus.IMPLEMENTED

    def test_seeded_ke_dns(self):
        """Test DNS resolution known error is present."""
        ke = self.svc.get_known_error("KE-00002")
        assert ke is not None
        assert "DNS" in ke.title

    def test_seeded_ke_vpn(self):
        """Test VPN timeout known error is present."""
        ke = self.svc.get_known_error("KE-00003")
        assert ke is not None
        assert "VPN" in ke.title
        assert ke.permanent_fix_status == FixStatus.PLANNED

    def test_seeded_ke_disk_space(self):
        """Test disk space known error is present."""
        ke = self.svc.get_known_error("KE-00004")
        assert ke is not None
        assert "Disk" in ke.title

    def test_seeded_ke_certificate(self):
        """Test certificate expiry known error is present."""
        ke = self.svc.get_known_error("KE-00005")
        assert ke is not None
        assert "Certificate" in ke.title
        assert ke.permanent_fix_status == FixStatus.IDENTIFIED

    # ========== Problem CRUD ==========

    def test_create_problem(self):
        """Test basic problem creation."""
        pr = self.svc.create_problem(
            client_id="CLIENT-001",
            title="Repeated server crashes",
            description="Web server crashes every Tuesday at 3 AM",
            priority=ProblemPriority.HIGH,
            category=ProblemCategory.SOFTWARE,
        )
        assert pr is not None
        assert pr.problem_id.startswith("PRB-")
        assert pr.title == "Repeated server crashes"
        assert pr.status == ProblemStatus.LOGGED
        assert pr.priority == ProblemPriority.HIGH
        assert pr.category == ProblemCategory.SOFTWARE
        assert pr.client_id == "CLIENT-001"

    def test_create_problem_unique_ids(self):
        """Test that each problem gets a unique ID."""
        pr1 = self.svc.create_problem(client_id="C1", title="P1", description="d1")
        pr2 = self.svc.create_problem(client_id="C1", title="P2", description="d2")
        assert pr1.problem_id != pr2.problem_id

    def test_get_problem(self):
        """Test retrieving a problem by ID."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        fetched = self.svc.get_problem(pr.problem_id)
        assert fetched is not None
        assert fetched.problem_id == pr.problem_id

    def test_get_problem_not_found(self):
        """Test retrieving a non-existent problem."""
        assert self.svc.get_problem("PRB-99999") is None

    def test_list_problems(self):
        """Test listing problems."""
        self.svc.create_problem(client_id="C1", title="A", description="d")
        self.svc.create_problem(client_id="C2", title="B", description="d")
        all_problems = self.svc.list_problems()
        assert len(all_problems) == 2

    def test_list_problems_filter_client(self):
        """Test listing problems filtered by client."""
        self.svc.create_problem(client_id="C1", title="A", description="d")
        self.svc.create_problem(client_id="C2", title="B", description="d")
        filtered = self.svc.list_problems(client_id="C1")
        assert len(filtered) == 1
        assert filtered[0].client_id == "C1"

    def test_list_problems_filter_status(self):
        """Test listing problems filtered by status."""
        pr = self.svc.create_problem(client_id="C1", title="A", description="d")
        self.svc.investigate(pr.problem_id)
        self.svc.create_problem(client_id="C1", title="B", description="d")
        logged = self.svc.list_problems(status=ProblemStatus.LOGGED)
        assert len(logged) == 1
        investigating = self.svc.list_problems(status=ProblemStatus.UNDER_INVESTIGATION)
        assert len(investigating) == 1

    def test_list_problems_filter_priority(self):
        """Test listing problems filtered by priority."""
        self.svc.create_problem(client_id="C1", title="A", description="d", priority=ProblemPriority.CRITICAL)
        self.svc.create_problem(client_id="C1", title="B", description="d", priority=ProblemPriority.LOW)
        critical = self.svc.list_problems(priority=ProblemPriority.CRITICAL)
        assert len(critical) == 1

    def test_list_problems_filter_category(self):
        """Test listing problems filtered by category."""
        self.svc.create_problem(client_id="C1", title="A", description="d", category=ProblemCategory.NETWORK)
        self.svc.create_problem(client_id="C1", title="B", description="d", category=ProblemCategory.SOFTWARE)
        network = self.svc.list_problems(category=ProblemCategory.NETWORK)
        assert len(network) == 1

    def test_update_problem(self):
        """Test updating a problem."""
        pr = self.svc.create_problem(client_id="C1", title="Original", description="d")
        updated = self.svc.update_problem(pr.problem_id, title="Updated Title", assigned_to="tech@test.com")
        assert updated is not None
        assert updated.title == "Updated Title"
        assert updated.assigned_to == "tech@test.com"

    def test_update_problem_not_found(self):
        """Test updating a non-existent problem."""
        assert self.svc.update_problem("PRB-99999", title="X") is None

    def test_delete_problem(self):
        """Test deleting a problem."""
        pr = self.svc.create_problem(client_id="C1", title="Delete me", description="d")
        assert self.svc.delete_problem(pr.problem_id) is True
        assert self.svc.get_problem(pr.problem_id) is None

    def test_delete_problem_not_found(self):
        """Test deleting a non-existent problem."""
        assert self.svc.delete_problem("PRB-99999") is False

    # ========== Investigation Workflow ==========

    def test_investigate(self):
        """Test moving a problem to under_investigation."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        result = self.svc.investigate(pr.problem_id)
        assert result is not None
        assert result.status == ProblemStatus.UNDER_INVESTIGATION

    def test_investigate_not_found(self):
        """Test investigating a non-existent problem."""
        assert self.svc.investigate("PRB-99999") is None

    def test_identify_root_cause(self):
        """Test identifying root cause for a problem."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        self.svc.investigate(pr.problem_id)
        result = self.svc.identify_root_cause(
            pr.problem_id,
            root_cause="Memory leak in application pool",
            method=RCAMethod.FIVE_WHYS,
        )
        assert result is not None
        assert result.status == ProblemStatus.ROOT_CAUSE_IDENTIFIED
        assert result.root_cause == "Memory leak in application pool"

    def test_identify_root_cause_not_found(self):
        """Test identifying root cause for non-existent problem."""
        assert self.svc.identify_root_cause("PRB-99999", "cause") is None

    def test_create_known_error_from_problem(self):
        """Test creating a Known Error from a problem."""
        pr = self.svc.create_problem(client_id="C1", title="Server OOM", description="d")
        self.svc.investigate(pr.problem_id)
        self.svc.identify_root_cause(pr.problem_id, "Memory leak in app pool")
        ke = self.svc.create_known_error(
            pr.problem_id,
            workaround="Restart app pool every 6 hours",
            symptoms=["out of memory", "server crash"],
            affected_cis=["web_server"],
        )
        assert ke is not None
        assert ke.ke_id.startswith("KE-")
        assert ke.workaround == "Restart app pool every 6 hours"
        assert ke.root_cause == "Memory leak in app pool"
        # Problem status should be KNOWN_ERROR
        updated_pr = self.svc.get_problem(pr.problem_id)
        assert updated_pr.status == ProblemStatus.KNOWN_ERROR

    def test_create_known_error_no_root_cause(self):
        """Test creating KE fails when no root cause is identified."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        ke = self.svc.create_known_error(pr.problem_id, workaround="Restart")
        assert ke is None

    def test_create_known_error_not_found(self):
        """Test creating KE for non-existent problem."""
        ke = self.svc.create_known_error("PRB-99999", workaround="Restart")
        assert ke is None

    def test_resolve_problem(self):
        """Test resolving a problem."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        result = self.svc.resolve_problem(pr.problem_id, "Upgraded application to v2.1")
        assert result is not None
        assert result.status == ProblemStatus.RESOLVED
        assert result.resolution == "Upgraded application to v2.1"
        assert result.resolved_at is not None

    def test_resolve_problem_not_found(self):
        """Test resolving non-existent problem."""
        assert self.svc.resolve_problem("PRB-99999", "fix") is None

    def test_close_problem(self):
        """Test closing a problem."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        self.svc.resolve_problem(pr.problem_id, "Fixed")
        result = self.svc.close_problem(pr.problem_id)
        assert result is not None
        assert result.status == ProblemStatus.CLOSED

    def test_close_problem_not_found(self):
        """Test closing non-existent problem."""
        assert self.svc.close_problem("PRB-99999") is None

    def test_link_incident(self):
        """Test linking an incident to a problem."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        result = self.svc.link_incident(pr.problem_id, "INC-001")
        assert result is not None
        assert "INC-001" in result.related_incidents

    def test_link_incident_duplicate(self):
        """Test linking the same incident twice does not duplicate."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        self.svc.link_incident(pr.problem_id, "INC-001")
        self.svc.link_incident(pr.problem_id, "INC-001")
        result = self.svc.get_problem(pr.problem_id)
        assert result.related_incidents.count("INC-001") == 1

    def test_link_incident_not_found(self):
        """Test linking incident to non-existent problem."""
        assert self.svc.link_incident("PRB-99999", "INC-001") is None

    # ========== Full Lifecycle ==========

    def test_full_lifecycle(self):
        """Test the complete problem lifecycle: log -> investigate -> root cause -> KE -> resolve -> close."""
        # 1. Log
        pr = self.svc.create_problem(
            client_id="CLIENT-100",
            title="Email delays",
            description="Users report 30-minute delays on outbound email",
            priority=ProblemPriority.HIGH,
            category=ProblemCategory.EMAIL,
        )
        assert pr.status == ProblemStatus.LOGGED

        # 2. Investigate
        pr = self.svc.investigate(pr.problem_id)
        assert pr.status == ProblemStatus.UNDER_INVESTIGATION

        # 3. Link incidents
        self.svc.link_incident(pr.problem_id, "INC-100")
        self.svc.link_incident(pr.problem_id, "INC-101")
        self.svc.link_incident(pr.problem_id, "INC-102")

        # 4. Root cause
        pr = self.svc.identify_root_cause(
            pr.problem_id,
            "SMTP relay queue backed up due to DNS timeout to external resolver",
        )
        assert pr.status == ProblemStatus.ROOT_CAUSE_IDENTIFIED

        # 5. Create Known Error
        ke = self.svc.create_known_error(
            pr.problem_id,
            workaround="Switch SMTP relay to use 8.8.8.8 as DNS",
            symptoms=["email delay", "outbound email slow"],
        )
        assert ke is not None
        pr = self.svc.get_problem(pr.problem_id)
        assert pr.status == ProblemStatus.KNOWN_ERROR

        # 6. Resolve
        pr = self.svc.resolve_problem(
            pr.problem_id,
            "Configured SMTP relay with redundant DNS resolvers",
        )
        assert pr.status == ProblemStatus.RESOLVED
        assert pr.resolved_at is not None

        # 7. Close
        pr = self.svc.close_problem(pr.problem_id)
        assert pr.status == ProblemStatus.CLOSED

    # ========== Root Cause Analysis ==========

    def test_perform_rca(self):
        """Test performing an RCA."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        rca = self.svc.perform_rca(
            problem_id=pr.problem_id,
            method=RCAMethod.FIVE_WHYS,
            findings=["App pool crashes under load"],
            contributing_factors=["No memory limits set"],
            recommendations=["Set memory cap at 2GB", "Enable recycling"],
            analyzed_by="admin@test.com",
        )
        assert rca is not None
        assert rca.rca_id.startswith("RCA-")
        assert rca.method == RCAMethod.FIVE_WHYS
        assert len(rca.findings) == 1
        assert len(rca.recommendations) == 2

    def test_perform_rca_not_found(self):
        """Test RCA for non-existent problem."""
        assert self.svc.perform_rca("PRB-99999") is None

    def test_get_rca(self):
        """Test retrieving an RCA by ID."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        rca = self.svc.perform_rca(pr.problem_id, findings=["Finding 1"])
        fetched = self.svc.get_rca(rca.rca_id)
        assert fetched is not None
        assert fetched.rca_id == rca.rca_id

    def test_list_rcas_for_problem(self):
        """Test listing RCAs for a problem."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        self.svc.perform_rca(pr.problem_id, method=RCAMethod.FIVE_WHYS, findings=["A"])
        self.svc.perform_rca(pr.problem_id, method=RCAMethod.FISHBONE, findings=["B"])
        rcas = self.svc.list_rcas_for_problem(pr.problem_id)
        assert len(rcas) == 2

    def test_rca_methods(self):
        """Test all RCA methods."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        for method in RCAMethod:
            rca = self.svc.perform_rca(pr.problem_id, method=method, findings=[f"Finding for {method.value}"])
            assert rca.method == method

    # ========== KEDB Search ==========

    def test_search_known_errors_by_symptom(self):
        """Test searching KEDB by symptoms."""
        matches = self.svc.search_known_errors(["printer offline"])
        assert len(matches) > 0
        assert matches[0]["ke_id"] == "KE-00001"

    def test_search_known_errors_dns(self):
        """Test searching KEDB for DNS issues."""
        matches = self.svc.search_known_errors(["DNS timeout", "name resolution failure"])
        assert len(matches) > 0
        # DNS should be top match
        assert "KE-00002" in [m["ke_id"] for m in matches]

    def test_search_known_errors_vpn(self):
        """Test searching KEDB for VPN issues."""
        matches = self.svc.search_known_errors(["VPN disconnects"])
        assert len(matches) > 0
        assert "KE-00003" in [m["ke_id"] for m in matches]

    def test_search_known_errors_empty(self):
        """Test searching KEDB with no symptoms."""
        assert self.svc.search_known_errors([]) == []

    def test_search_known_errors_no_match(self):
        """Test searching KEDB with no matching symptoms."""
        matches = self.svc.search_known_errors(["xyzzy_nonexistent_symptom_12345"])
        assert len(matches) == 0

    def test_search_returns_workaround(self):
        """Test that search results include workaround text."""
        matches = self.svc.search_known_errors(["certificate expired"])
        assert len(matches) > 0
        assert "workaround" in matches[0]
        assert len(matches[0]["workaround"]) > 0

    def test_match_incident_to_known_error(self):
        """Test matching incident data to a known error."""
        match = self.svc.match_incident_to_known_error({
            "title": "Cannot print to network printer",
            "description": "Print jobs are stuck in queue, printer shows offline",
            "symptoms": ["printer offline", "print jobs stuck"],
        })
        assert match is not None
        assert match["ke_id"] == "KE-00001"

    def test_match_incident_no_match(self):
        """Test incident matching with no results."""
        match = self.svc.match_incident_to_known_error({
            "title": "xyz",
            "description": "abc",
            "symptoms": [],
        })
        assert match is None

    def test_match_incident_by_description_only(self):
        """Test incident matching using only description."""
        match = self.svc.match_incident_to_known_error({
            "title": "",
            "description": "Users report VPN timeout and tunnel drops frequently",
        })
        assert match is not None

    # ========== Known Error CRUD ==========

    def test_list_known_errors_all(self):
        """Test listing all known errors."""
        kes = self.svc.list_known_errors()
        assert len(kes) == 5

    def test_list_known_errors_by_fix_status(self):
        """Test filtering known errors by fix status."""
        implemented = self.svc.list_known_errors(fix_status=FixStatus.IMPLEMENTED)
        assert all(ke.permanent_fix_status == FixStatus.IMPLEMENTED for ke in implemented)
        assert len(implemented) == 2  # printer spooler + DNS

    def test_get_known_error(self):
        """Test getting a specific known error."""
        ke = self.svc.get_known_error("KE-00001")
        assert ke is not None
        assert ke.title == "Print Spooler Service Crash"

    def test_get_known_error_not_found(self):
        """Test getting a non-existent known error."""
        assert self.svc.get_known_error("KE-99999") is None

    # ========== Analytics ==========

    def test_get_recurring_incidents(self):
        """Test identifying recurring incidents."""
        pr = self.svc.create_problem(client_id="C1", title="Recurring issue", description="d")
        for i in range(5):
            self.svc.link_incident(pr.problem_id, f"INC-{i:03d}")
        recurring = self.svc.get_recurring_incidents(threshold=3)
        assert len(recurring) == 1
        assert recurring[0]["incident_count"] == 5

    def test_get_recurring_incidents_below_threshold(self):
        """Test that problems below threshold are not returned."""
        pr = self.svc.create_problem(client_id="C1", title="Minor issue", description="d")
        self.svc.link_incident(pr.problem_id, "INC-001")
        recurring = self.svc.get_recurring_incidents(threshold=3)
        assert len(recurring) == 0

    def test_get_problem_trends(self):
        """Test problem trend analytics."""
        self.svc.create_problem(client_id="C1", title="Net1", description="d", category=ProblemCategory.NETWORK)
        self.svc.create_problem(client_id="C1", title="Net2", description="d", category=ProblemCategory.NETWORK)
        self.svc.create_problem(client_id="C1", title="Sw1", description="d", category=ProblemCategory.SOFTWARE)
        trends = self.svc.get_problem_trends()
        assert len(trends) >= 2
        # Network should have count 2
        net_trend = [t for t in trends if t.category == "network"]
        assert len(net_trend) == 1
        assert net_trend[0].count == 2

    def test_get_problem_trends_empty(self):
        """Test trends with no problems."""
        trends = self.svc.get_problem_trends()
        assert len(trends) == 0

    def test_get_top_root_causes(self):
        """Test top root causes."""
        pr1 = self.svc.create_problem(client_id="C1", title="A", description="d")
        pr2 = self.svc.create_problem(client_id="C1", title="B", description="d")
        pr3 = self.svc.create_problem(client_id="C1", title="C", description="d")
        self.svc.identify_root_cause(pr1.problem_id, "Memory leak")
        self.svc.identify_root_cause(pr2.problem_id, "Memory leak")
        self.svc.identify_root_cause(pr3.problem_id, "Config error")
        top = self.svc.get_top_root_causes(limit=5)
        assert len(top) == 2
        assert top[0]["root_cause"] == "Memory leak"
        assert top[0]["count"] == 2

    def test_get_top_root_causes_empty(self):
        """Test top root causes with no data."""
        top = self.svc.get_top_root_causes()
        assert len(top) == 0

    def test_get_dashboard(self):
        """Test dashboard output."""
        pr = self.svc.create_problem(
            client_id="C1",
            title="Dashboard test",
            description="d",
            priority=ProblemPriority.HIGH,
            category=ProblemCategory.NETWORK,
        )
        self.svc.link_incident(pr.problem_id, "INC-001")
        self.svc.link_incident(pr.problem_id, "INC-002")
        self.svc.link_incident(pr.problem_id, "INC-003")

        dashboard = self.svc.get_dashboard()
        assert dashboard["total_problems"] == 1
        assert dashboard["open_problems"] == 1
        assert dashboard["total_known_errors"] == 5  # pre-seeded
        assert "by_status" in dashboard
        assert "by_priority" in dashboard
        assert "by_category" in dashboard
        assert "trends" in dashboard
        assert "top_root_causes" in dashboard
        assert "recurring_incidents" in dashboard

    def test_get_dashboard_empty(self):
        """Test dashboard with no problems."""
        dashboard = self.svc.get_dashboard()
        assert dashboard["total_problems"] == 0
        assert dashboard["open_problems"] == 0
        assert dashboard["total_known_errors"] == 5

    # ========== Enum Completeness ==========

    def test_problem_status_values(self):
        """Test all ProblemStatus enum values."""
        expected = {"logged", "under_investigation", "root_cause_identified", "known_error", "resolved", "closed"}
        actual = {s.value for s in ProblemStatus}
        assert actual == expected

    def test_problem_priority_values(self):
        """Test all ProblemPriority enum values."""
        expected = {"critical", "high", "medium", "low"}
        actual = {p.value for p in ProblemPriority}
        assert actual == expected

    def test_rca_method_values(self):
        """Test all RCAMethod enum values."""
        expected = {"five_whys", "fishbone", "fault_tree", "timeline"}
        actual = {m.value for m in RCAMethod}
        assert actual == expected

    def test_fix_status_values(self):
        """Test all FixStatus enum values."""
        expected = {"identified", "planned", "in_progress", "implemented"}
        actual = {s.value for s in FixStatus}
        assert actual == expected

    # ========== Edge Cases ==========

    def test_create_problem_with_all_fields(self):
        """Test creating a problem with all optional fields populated."""
        pr = self.svc.create_problem(
            client_id="CLIENT-200",
            title="Full problem",
            description="Comprehensive test",
            priority=ProblemPriority.CRITICAL,
            category=ProblemCategory.SECURITY,
            affected_services=["web", "api", "database"],
            related_incidents=["INC-500", "INC-501"],
            assigned_to="engineer@test.com",
            impact_assessment="High impact on production services",
        )
        assert pr.priority == ProblemPriority.CRITICAL
        assert pr.category == ProblemCategory.SECURITY
        assert len(pr.affected_services) == 3
        assert len(pr.related_incidents) == 2
        assert pr.assigned_to == "engineer@test.com"
        assert pr.impact_assessment == "High impact on production services"

    def test_multiple_problems_different_categories(self):
        """Test creating problems across different categories."""
        categories = [ProblemCategory.HARDWARE, ProblemCategory.SOFTWARE, ProblemCategory.NETWORK]
        for cat in categories:
            self.svc.create_problem(client_id="C1", title=f"{cat.value} issue", description="d", category=cat)
        for cat in categories:
            filtered = self.svc.list_problems(category=cat)
            assert len(filtered) == 1

    def test_rca_with_analysis_data(self):
        """Test RCA with structured analysis data."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d")
        rca = self.svc.perform_rca(
            pr.problem_id,
            method=RCAMethod.FISHBONE,
            analysis_data={
                "categories": {
                    "People": ["Insufficient training"],
                    "Process": ["No change management"],
                    "Technology": ["Outdated firmware"],
                }
            },
            findings=["Root cause is outdated firmware"],
            contributing_factors=["No maintenance window", "Budget constraints"],
            recommendations=["Schedule firmware update", "Allocate maintenance budget"],
        )
        assert rca.analysis_data["categories"]["Technology"] == ["Outdated firmware"]
        assert len(rca.contributing_factors) == 2

    def test_problem_trend_resolution_days(self):
        """Test that trends calculate resolution days correctly."""
        pr = self.svc.create_problem(client_id="C1", title="Test", description="d", category=ProblemCategory.NETWORK)
        # Manually set created_at to 5 days ago
        pr.created_at = datetime.now(timezone.utc) - timedelta(days=5)
        self.svc.resolve_problem(pr.problem_id, "Fixed")
        trends = self.svc.get_problem_trends()
        net_trend = [t for t in trends if t.category == "network"]
        assert len(net_trend) == 1
        assert net_trend[0].avg_resolution_days >= 4.0  # approximately 5 days
