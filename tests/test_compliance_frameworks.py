"""
Tests for Compliance Framework Templates Service.
Covers framework loading, assessment lifecycle, scoring, findings, and Shield mapping.
"""

import pytest
from services.msp.compliance_frameworks import (
    ComplianceFrameworkService,
    ControlStatus,
    FindingSeverity,
    FindingStatus,
)


@pytest.fixture
def service():
    """Create a ComplianceFrameworkService with in-memory storage."""
    return ComplianceFrameworkService()


# ============================================================
# Framework Loading
# ============================================================

class TestFrameworkLoading:
    def test_all_five_frameworks_loaded(self, service):
        frameworks = service.get_frameworks()
        assert len(frameworks) == 5
        fw_ids = {fw["framework_id"] for fw in frameworks}
        assert fw_ids == {"fw-hipaa", "fw-soc2", "fw-nist-171", "fw-cmmc", "fw-pci-dss"}

    def test_hipaa_has_minimum_controls(self, service):
        fw = service.get_framework("fw-hipaa")
        assert fw is not None
        assert fw["total_controls"] >= 25

    def test_soc2_has_minimum_controls(self, service):
        fw = service.get_framework("fw-soc2")
        assert fw is not None
        assert fw["total_controls"] >= 20

    def test_nist_has_minimum_controls(self, service):
        fw = service.get_framework("fw-nist-171")
        assert fw is not None
        assert fw["total_controls"] >= 15

    def test_cmmc_has_minimum_controls(self, service):
        fw = service.get_framework("fw-cmmc")
        assert fw is not None
        assert fw["total_controls"] >= 15

    def test_pci_has_minimum_controls(self, service):
        fw = service.get_framework("fw-pci-dss")
        assert fw is not None
        assert fw["total_controls"] >= 12

    def test_framework_has_controls_by_category(self, service):
        fw = service.get_framework("fw-hipaa")
        assert "controls_by_category" in fw
        assert len(fw["controls_by_category"]) > 0

    def test_nonexistent_framework_returns_none(self, service):
        assert service.get_framework("fw-nonexistent") is None

    def test_framework_controls_have_required_fields(self, service):
        fw = service.get_framework("fw-soc2")
        for cat, controls in fw["controls_by_category"].items():
            for ctrl in controls:
                assert "control_id" in ctrl
                assert "control_number" in ctrl
                assert "title" in ctrl
                assert "description" in ctrl
                assert "evidence_types" in ctrl
                assert isinstance(ctrl["evidence_types"], list)

    def test_frameworks_list_includes_metadata(self, service):
        frameworks = service.get_frameworks()
        for fw in frameworks:
            assert "framework_id" in fw
            assert "name" in fw
            assert "version" in fw
            assert "total_controls" in fw
            assert "automated_controls" in fw
            assert "manual_controls" in fw
            assert fw["automated_controls"] + fw["manual_controls"] == fw["total_controls"]


# ============================================================
# Assessment Lifecycle
# ============================================================

class TestAssessmentLifecycle:
    def test_start_assessment(self, service):
        result = service.start_assessment("client-001", "fw-hipaa", assessed_by="auditor@test.com")
        assert result is not None
        assert result["client_id"] == "client-001"
        assert result["framework_id"] == "fw-hipaa"
        assert result["overall_score"] == 0.0
        assert result["controls_not_assessed"] > 0

    def test_start_assessment_invalid_framework(self, service):
        result = service.start_assessment("client-001", "fw-fake")
        assert result is None

    def test_update_control_status(self, service):
        result = service.start_assessment("client-002", "fw-soc2")
        assessment_id = result["assessment_id"]

        updated = service.update_control_status(
            assessment_id, "soc2-001", ControlStatus.COMPLIANT
        )
        assert updated is not None
        assert updated["control_id"] == "soc2-001"
        assert updated["status"] == ControlStatus.COMPLIANT
        assert updated["controls_compliant"] >= 1

    def test_update_control_invalid_assessment(self, service):
        result = service.update_control_status("fake-id", "soc2-001", ControlStatus.COMPLIANT)
        assert result is None

    def test_update_control_invalid_control(self, service):
        result = service.start_assessment("client-003", "fw-hipaa")
        assessment_id = result["assessment_id"]
        updated = service.update_control_status(assessment_id, "fake-control", ControlStatus.COMPLIANT)
        assert updated is None

    def test_get_assessment(self, service):
        result = service.start_assessment("client-004", "fw-pci-dss")
        assessment_id = result["assessment_id"]
        fetched = service.get_assessment(assessment_id)
        assert fetched is not None
        assert fetched["assessment_id"] == assessment_id

    def test_get_assessment_not_found(self, service):
        assert service.get_assessment("nonexistent") is None


# ============================================================
# Scoring
# ============================================================

class TestScoring:
    def test_initial_score_is_zero(self, service):
        result = service.start_assessment("client-010", "fw-cmmc")
        score = service.calculate_compliance_score(result["assessment_id"])
        assert score["overall_score"] == 0.0
        assert score["pass"] is False

    def test_full_compliance_score(self, service):
        result = service.start_assessment("client-011", "fw-nist-171")
        assessment_id = result["assessment_id"]

        fw = service.get_framework("fw-nist-171")
        for cat, controls in fw["controls_by_category"].items():
            for ctrl in controls:
                service.update_control_status(
                    assessment_id, ctrl["control_id"], ControlStatus.COMPLIANT
                )

        score = service.calculate_compliance_score(assessment_id)
        assert score["overall_score"] == 100.0
        assert score["pass"] is True

    def test_partial_compliance_score(self, service):
        result = service.start_assessment("client-012", "fw-hipaa")
        assessment_id = result["assessment_id"]

        fw = service.get_framework("fw-hipaa")
        all_controls = []
        for cat, controls in fw["controls_by_category"].items():
            all_controls.extend(controls)

        # Mark half compliant, half non-compliant
        for i, ctrl in enumerate(all_controls):
            status = ControlStatus.COMPLIANT if i % 2 == 0 else ControlStatus.NON_COMPLIANT
            service.update_control_status(assessment_id, ctrl["control_id"], status)

        score = service.calculate_compliance_score(assessment_id)
        assert 45.0 <= score["overall_score"] <= 55.0
        assert score["controls_compliant"] > 0
        assert score["controls_non_compliant"] > 0

    def test_na_controls_excluded_from_scoring(self, service):
        result = service.start_assessment("client-013", "fw-soc2")
        assessment_id = result["assessment_id"]

        fw = service.get_framework("fw-soc2")
        all_controls = []
        for cat, controls in fw["controls_by_category"].items():
            all_controls.extend(controls)

        # Mark first 5 compliant, rest N/A
        for i, ctrl in enumerate(all_controls):
            status = ControlStatus.COMPLIANT if i < 5 else ControlStatus.NOT_APPLICABLE
            service.update_control_status(assessment_id, ctrl["control_id"], status)

        score = service.calculate_compliance_score(assessment_id)
        assert score["overall_score"] == 100.0

    def test_score_not_found(self, service):
        assert service.calculate_compliance_score("nonexistent") is None


# ============================================================
# Findings
# ============================================================

class TestFindings:
    def test_add_finding(self, service):
        result = service.start_assessment("client-020", "fw-hipaa")
        assessment_id = result["assessment_id"]

        finding = service.add_finding(
            assessment_id=assessment_id,
            control_id="hipaa-001",
            severity=FindingSeverity.HIGH,
            description="No risk assessment performed in the last 12 months",
            recommendation="Conduct annual risk assessment immediately",
            due_date="2026-05-15",
        )
        assert finding is not None
        assert finding["severity"] == "high"
        assert finding["status"] == "open"
        assert finding["due_date"] == "2026-05-15"

    def test_add_finding_invalid_assessment(self, service):
        result = service.add_finding(
            assessment_id="fake-id",
            control_id="hipaa-001",
            severity=FindingSeverity.HIGH,
            description="Test",
            recommendation="Fix it",
        )
        assert result is None

    def test_update_finding_status(self, service):
        result = service.start_assessment("client-021", "fw-soc2")
        assessment_id = result["assessment_id"]

        finding = service.add_finding(
            assessment_id=assessment_id,
            control_id="soc2-001",
            severity=FindingSeverity.MEDIUM,
            description="Missing code of conduct",
            recommendation="Create and distribute code of conduct",
        )
        finding_id = finding["finding_id"]

        updated = service.update_finding(finding_id, status=FindingStatus.IN_PROGRESS)
        assert updated is not None
        assert updated["status"] == "in_progress"

        resolved = service.update_finding(finding_id, status=FindingStatus.RESOLVED)
        assert resolved["status"] == "resolved"

    def test_update_finding_not_found(self, service):
        assert service.update_finding("fake-id") is None


# ============================================================
# Reports
# ============================================================

class TestReports:
    def test_assessment_report(self, service):
        result = service.start_assessment("client-030", "fw-pci-dss")
        assessment_id = result["assessment_id"]

        # Mark some controls
        service.update_control_status(assessment_id, "pci-001", ControlStatus.COMPLIANT)
        service.update_control_status(assessment_id, "pci-002", ControlStatus.NON_COMPLIANT)

        # Add a finding
        service.add_finding(
            assessment_id=assessment_id,
            control_id="pci-002",
            severity=FindingSeverity.HIGH,
            description="Firewall misconfiguration detected",
            recommendation="Review and update firewall rules",
        )

        report = service.get_assessment_report(assessment_id)
        assert report is not None
        assert "overall_score" in report
        assert "category_scores" in report
        assert "controls" in report
        assert "findings_summary" in report
        assert "open_findings" in report
        assert len(report["controls"]) > 0
        assert report["findings_summary"]["total"] == 1

    def test_report_not_found(self, service):
        assert service.get_assessment_report("nonexistent") is None


# ============================================================
# Dashboard
# ============================================================

class TestDashboard:
    def test_empty_dashboard(self, service):
        dashboard = service.get_dashboard()
        assert dashboard["available_frameworks"] == 5
        assert dashboard["total_assessments"] == 0
        assert dashboard["findings"]["total"] == 0

    def test_dashboard_with_assessments(self, service):
        service.start_assessment("client-A", "fw-hipaa")
        service.start_assessment("client-B", "fw-soc2")

        dashboard = service.get_dashboard()
        assert dashboard["total_assessments"] == 2
        assert dashboard["active_assessments"] == 2


# ============================================================
# Shield Integration
# ============================================================

class TestShieldMapping:
    def test_map_malware_event(self, service):
        events = [
            {
                "event_type": "malware_detected",
                "event_id": "evt-001",
                "timestamp": "2026-04-19T10:00:00Z",
            }
        ]
        results = service.map_shield_events_to_controls(events)
        assert len(results) == 1
        assert results[0]["total_impacted"] > 0
        assert len(results[0]["impacted_frameworks"]) > 0

    def test_map_unknown_event(self, service):
        events = [{"event_type": "unknown_event", "event_id": "evt-999"}]
        results = service.map_shield_events_to_controls(events)
        assert len(results) == 1
        assert results[0]["total_impacted"] == 0

    def test_map_multiple_events(self, service):
        events = [
            {"event_type": "malware_detected", "event_id": "evt-001"},
            {"event_type": "unauthorized_access", "event_id": "evt-002"},
            {"event_type": "encryption_failure", "event_id": "evt-003"},
        ]
        results = service.map_shield_events_to_controls(events)
        assert len(results) == 3
        for r in results:
            assert r["total_impacted"] > 0
