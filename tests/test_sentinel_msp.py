"""
Dedicated tests for Sentinel MSP Service.
Tests provider onboarding, SLA tracking, performance evaluation, incident management,
benchmarking, contract lifecycle, escalation, and dashboard.
"""

import pytest
from datetime import datetime, timedelta
from services.operations.sentinel_msp import (
    SentinelMSP,
    ProviderStatus,
    SLAStatus,
    IncidentSeverity,
    PerformanceRating,
    ContractPhase,
    Provider,
    SLAMetric,
    ProviderIncident,
    PerformanceScorecard,
    ContractRecord,
    DEFAULT_SLA_TARGETS,
    SCORE_WEIGHTS,
)


@pytest.fixture
def msp():
    """Fresh SentinelMSP instance."""
    return SentinelMSP()


def _provider_data(**overrides):
    """Helper to build valid provider onboarding data."""
    base = {
        "name": "CloudCorp",
        "category": "cloud",
        "contract_value": 120000.0,
        "contract_start": "2025-01-01",
        "contract_end": "2026-12-31",
        "contact_info": {"email": "support@cloudcorp.com"},
        "services": ["hosting", "cdn"],
    }
    base.update(overrides)
    return base


# =============================================================================
# Initialization
# =============================================================================


class TestSentinelMSPInit:
    """Tests for SentinelMSP initialization."""

    def test_no_providers_on_init(self, msp):
        assert len(msp._providers) == 0

    def test_escalation_thresholds_set(self, msp):
        assert msp._escalation_thresholds["probation_breach_count"] == 3
        assert msp._escalation_thresholds["suspension_breach_count"] == 6

    def test_custom_config_applied(self):
        custom = SentinelMSP(config={"renewal_alert_days": 60})
        assert custom._renewal_alert_days == 60

    def test_default_renewal_alert_days(self, msp):
        assert msp._renewal_alert_days == 90


# =============================================================================
# Provider Onboarding
# =============================================================================


class TestProviderOnboarding:
    """Tests for provider registration and activation."""

    def test_onboard_creates_provider(self, msp):
        provider = msp.onboard_provider(_provider_data())
        assert provider.name == "CloudCorp"
        assert provider.status == ProviderStatus.ONBOARDING

    def test_onboard_assigns_provider_id(self, msp):
        provider = msp.onboard_provider(_provider_data())
        assert provider.provider_id.startswith("prv_")

    def test_onboard_creates_contract(self, msp):
        provider = msp.onboard_provider(_provider_data())
        assert provider.provider_id in msp._contracts
        contract = msp._contracts[provider.provider_id]
        assert contract.phase == ContractPhase.NEGOTIATION

    def test_onboard_merges_sla_targets(self, msp):
        provider = msp.onboard_provider(_provider_data(sla_targets={
            "availability": {"target_percent": 99.99},
        }))
        assert provider.sla_targets["availability"]["target_percent"] == 99.99
        # Default response_time should still be present
        assert "response_time" in provider.sla_targets

    def test_onboard_missing_required_field_raises(self, msp):
        with pytest.raises(ValueError, match="Missing required field"):
            msp.onboard_provider({"name": "Incomplete"})

    def test_onboard_end_before_start_raises(self, msp):
        with pytest.raises(ValueError, match="contract_end must be after"):
            msp.onboard_provider(_provider_data(
                contract_start="2026-01-01",
                contract_end="2025-01-01",
            ))

    def test_activate_provider(self, msp):
        provider = msp.onboard_provider(_provider_data())
        activated = msp.activate_provider(provider.provider_id)
        assert activated.status == ProviderStatus.ACTIVE

    def test_activate_non_onboarding_raises(self, msp):
        provider = msp.onboard_provider(_provider_data())
        msp.activate_provider(provider.provider_id)
        with pytest.raises(ValueError, match="not in ONBOARDING"):
            msp.activate_provider(provider.provider_id)


# =============================================================================
# SLA Tracking
# =============================================================================


class TestSLATracking:
    """Tests for SLA metric recording and compliance tracking."""

    def setup_method(self):
        self.msp = SentinelMSP()
        self.provider = self.msp.onboard_provider(_provider_data())
        self.msp.activate_provider(self.provider.provider_id)
        self.pid = self.provider.provider_id

    def test_record_compliant_availability(self):
        metric = self.msp.record_sla_metric(self.pid, "availability", 99.95)
        assert metric.status == SLAStatus.COMPLIANT

    def test_record_breached_availability(self):
        metric = self.msp.record_sla_metric(self.pid, "availability", 98.0)
        assert metric.status == SLAStatus.BREACHED

    def test_record_at_risk_availability(self):
        # Target is 99.9, at_risk threshold is ratio >= 0.995 => 99.4005
        metric = self.msp.record_sla_metric(self.pid, "availability", 99.5)
        assert metric.status == SLAStatus.AT_RISK

    def test_record_compliant_response_time(self):
        # response_time_critical target is 15 minutes, lower is better
        metric = self.msp.record_sla_metric(self.pid, "response_time_critical", 10.0)
        assert metric.status == SLAStatus.COMPLIANT

    def test_record_breached_response_time(self):
        metric = self.msp.record_sla_metric(self.pid, "response_time_critical", 25.0)
        assert metric.status == SLAStatus.BREACHED

    def test_track_sla_returns_compliance_report(self):
        self.msp.record_sla_metric(self.pid, "availability", 99.95)
        report = self.msp.track_sla(self.pid)
        assert "compliance_rate" in report
        assert "provider_name" in report
        assert report["provider_name"] == "CloudCorp"

    def test_track_sla_status_healthy_when_all_compliant(self):
        self.msp.record_sla_metric(self.pid, "availability", 99.95)
        report = self.msp.track_sla(self.pid)
        assert report["status"] == "healthy"

    def test_track_sla_status_degraded_on_breach(self):
        self.msp.record_sla_metric(self.pid, "availability", 95.0)
        report = self.msp.track_sla(self.pid)
        assert report["status"] in ("degraded", "critical")

    def test_inferred_unit_for_availability(self):
        metric = self.msp.record_sla_metric(self.pid, "availability", 99.9)
        assert metric.unit == "percent"

    def test_inferred_unit_for_response_time(self):
        metric = self.msp.record_sla_metric(self.pid, "response_time_high", 50.0)
        assert metric.unit == "minutes"


# =============================================================================
# Performance Evaluation
# =============================================================================


class TestPerformanceEvaluation:
    """Tests for provider performance scorecards."""

    def setup_method(self):
        self.msp = SentinelMSP()
        self.provider = self.msp.onboard_provider(_provider_data())
        self.msp.activate_provider(self.provider.provider_id)
        self.pid = self.provider.provider_id

    def test_evaluate_returns_scorecard(self):
        scorecard = self.msp.evaluate_performance(self.pid)
        assert isinstance(scorecard, PerformanceScorecard)

    def test_scorecard_has_all_score_dimensions(self):
        scorecard = self.msp.evaluate_performance(self.pid)
        assert scorecard.availability_score >= 0
        assert scorecard.response_time_score >= 0
        assert scorecard.quality_score >= 0
        assert scorecard.communication_score >= 0

    def test_scorecard_overall_score_range(self):
        scorecard = self.msp.evaluate_performance(self.pid)
        assert 0 <= scorecard.overall_score <= 100

    def test_scorecard_rating_assigned(self):
        scorecard = self.msp.evaluate_performance(self.pid)
        assert scorecard.rating in PerformanceRating

    def test_scorecard_stored(self):
        self.msp.evaluate_performance(self.pid)
        assert len(self.msp._scorecards[self.pid]) == 1

    def test_generate_scorecard_convenience(self):
        scorecard = self.msp.generate_scorecard(self.pid)
        assert isinstance(scorecard, PerformanceScorecard)

    def test_recommendations_generated(self):
        scorecard = self.msp.evaluate_performance(self.pid)
        assert len(scorecard.recommendations) >= 1


# =============================================================================
# Incident Management
# =============================================================================


class TestIncidentManagement:
    """Tests for provider incident creation and updates."""

    def setup_method(self):
        self.msp = SentinelMSP()
        self.provider = self.msp.onboard_provider(_provider_data())
        self.msp.activate_provider(self.provider.provider_id)
        self.pid = self.provider.provider_id

    def test_create_incident(self):
        incident = self.msp.manage_incidents(self.pid, {
            "severity": "medium",
            "title": "Slow response",
            "description": "API latency spike",
        })
        assert isinstance(incident, ProviderIncident)
        assert incident.severity == IncidentSeverity.MEDIUM

    def test_incident_increments_count(self):
        self.msp.manage_incidents(self.pid, {
            "severity": "low",
            "title": "Minor issue",
        })
        assert self.provider.incidents_count == 1

    def test_update_incident_resolution(self):
        inc = self.msp.manage_incidents(self.pid, {
            "severity": "high",
            "title": "Outage",
            "description": "Service down",
        })
        updated = self.msp.manage_incidents(self.pid, {
            "incident_id": inc.incident_id,
            "resolution": "Root cause fixed",
            "root_cause": "Config error",
        })
        assert updated.resolution == "Root cause fixed"
        assert updated.root_cause == "Config error"
        assert updated.resolved_at is not None

    def test_update_nonexistent_incident_raises(self):
        with pytest.raises(ValueError, match="not found"):
            self.msp.manage_incidents(self.pid, {
                "incident_id": "inc_NONEXIST",
                "resolution": "N/A",
            })

    def test_critical_incident_auto_escalates(self):
        self.msp.manage_incidents(self.pid, {
            "severity": "critical",
            "title": "Total outage",
            "description": "Everything is down",
        })
        assert self.provider.status == ProviderStatus.PROBATION


# =============================================================================
# Benchmarking
# =============================================================================


class TestBenchmarking:
    """Tests for provider benchmarking within a category."""

    def setup_method(self):
        self.msp = SentinelMSP()
        self.p1 = self.msp.onboard_provider(_provider_data(name="CloudA"))
        self.msp.activate_provider(self.p1.provider_id)
        self.p2 = self.msp.onboard_provider(_provider_data(name="CloudB"))
        self.msp.activate_provider(self.p2.provider_id)

    def test_benchmark_returns_list(self):
        results = self.msp.benchmark_providers("cloud")
        assert isinstance(results, list)
        assert len(results) == 2

    def test_benchmark_includes_rank(self):
        results = self.msp.benchmark_providers("cloud")
        assert results[0]["rank"] == 1
        assert results[1]["rank"] == 2

    def test_benchmark_empty_for_unknown_category(self):
        results = self.msp.benchmark_providers("nonexistent")
        assert results == []

    def test_benchmark_sorted_by_score(self):
        # Give p1 a scorecard
        self.msp.evaluate_performance(self.p1.provider_id)
        results = self.msp.benchmark_providers("cloud")
        scores = [r["overall_score"] for r in results]
        assert scores == sorted(scores, reverse=True)


# =============================================================================
# Contract Lifecycle
# =============================================================================


class TestContractLifecycle:
    """Tests for contract phase management and renewal calendar."""

    def setup_method(self):
        self.msp = SentinelMSP()

    def test_contract_lifecycle_returns_record(self):
        provider = self.msp.onboard_provider(_provider_data())
        self.msp.activate_provider(provider.provider_id)
        contract = self.msp.contract_lifecycle(provider.provider_id)
        assert isinstance(contract, ContractRecord)

    def test_expired_contract_detected(self):
        provider = self.msp.onboard_provider(_provider_data(
            contract_start="2023-01-01",
            contract_end="2024-01-01",
        ))
        self.msp.activate_provider(provider.provider_id)
        contract = self.msp._contracts[provider.provider_id]
        contract.phase = ContractPhase.ACTIVE
        result = self.msp.contract_lifecycle(provider.provider_id)
        assert result.phase == ContractPhase.EXPIRED

    def test_renewal_window_detected(self):
        now = datetime.utcnow()
        end = now + timedelta(days=30)
        provider = self.msp.onboard_provider(_provider_data(
            contract_start=(now - timedelta(days=300)).strftime("%Y-%m-%d"),
            contract_end=end.strftime("%Y-%m-%d"),
        ))
        self.msp.activate_provider(provider.provider_id)
        contract = self.msp._contracts[provider.provider_id]
        contract.phase = ContractPhase.ACTIVE
        result = self.msp.contract_lifecycle(provider.provider_id)
        assert result.phase == ContractPhase.RENEWAL

    def test_renewal_calendar_returns_upcoming(self):
        now = datetime.utcnow()
        provider = self.msp.onboard_provider(_provider_data(
            contract_start=(now - timedelta(days=300)).strftime("%Y-%m-%d"),
            contract_end=(now + timedelta(days=45)).strftime("%Y-%m-%d"),
        ))
        self.msp.activate_provider(provider.provider_id)
        contract = self.msp._contracts[provider.provider_id]
        contract.phase = ContractPhase.ACTIVE
        calendar = self.msp.get_renewal_calendar(days_ahead=90)
        assert len(calendar) >= 1
        assert calendar[0]["days_remaining"] <= 90

    def test_renewal_calendar_empty_when_none_upcoming(self):
        # Provider with far-future end date
        provider = self.msp.onboard_provider(_provider_data(
            contract_start="2025-01-01",
            contract_end="2030-12-31",
        ))
        self.msp.activate_provider(provider.provider_id)
        contract = self.msp._contracts[provider.provider_id]
        contract.phase = ContractPhase.ACTIVE
        calendar = self.msp.get_renewal_calendar(days_ahead=90)
        assert len(calendar) == 0


# =============================================================================
# Escalation & Reinstatement
# =============================================================================


class TestEscalation:
    """Tests for provider escalation and reinstatement."""

    def setup_method(self):
        self.msp = SentinelMSP()
        self.provider = self.msp.onboard_provider(_provider_data())
        self.msp.activate_provider(self.provider.provider_id)
        self.pid = self.provider.provider_id

    def test_escalate_active_to_probation(self):
        result = self.msp.escalate_provider(self.pid, reason="Poor performance")
        assert result is True
        assert self.provider.status == ProviderStatus.PROBATION

    def test_escalate_probation_to_suspended(self):
        self.msp.escalate_provider(self.pid)
        result = self.msp.escalate_provider(self.pid)
        assert result is True
        assert self.provider.status == ProviderStatus.SUSPENDED

    def test_escalate_suspended_returns_false(self):
        self.msp.escalate_provider(self.pid)
        self.msp.escalate_provider(self.pid)
        result = self.msp.escalate_provider(self.pid)
        assert result is False

    def test_reinstate_from_probation(self):
        self.msp.escalate_provider(self.pid)
        result = self.msp.reinstate_provider(self.pid)
        assert result is True
        assert self.provider.status == ProviderStatus.ACTIVE

    def test_reinstate_from_suspended(self):
        self.msp.escalate_provider(self.pid)
        self.msp.escalate_provider(self.pid)
        result = self.msp.reinstate_provider(self.pid)
        assert result is True
        assert self.provider.status == ProviderStatus.ACTIVE

    def test_reinstate_active_returns_false(self):
        result = self.msp.reinstate_provider(self.pid)
        assert result is False


# =============================================================================
# Dashboard
# =============================================================================


class TestDashboard:
    """Tests for consolidated dashboard output."""

    def test_dashboard_empty_state(self, msp):
        dashboard = msp.get_dashboard()
        assert dashboard["total_providers"] == 0

    def test_dashboard_with_providers(self, msp):
        msp.onboard_provider(_provider_data(name="ProvA"))
        msp.onboard_provider(_provider_data(name="ProvB"))
        dashboard = msp.get_dashboard()
        assert dashboard["total_providers"] == 2

    def test_dashboard_contains_required_keys(self, msp):
        msp.onboard_provider(_provider_data())
        dashboard = msp.get_dashboard()
        assert "providers_by_status" in dashboard
        assert "sla_compliance_rate" in dashboard
        assert "average_performance_score" in dashboard
        assert "incidents" in dashboard
        assert "upcoming_renewals" in dashboard
        assert "generated_at" in dashboard

    def test_dashboard_incident_breakdown(self, msp):
        provider = msp.onboard_provider(_provider_data())
        msp.activate_provider(provider.provider_id)
        msp.manage_incidents(provider.provider_id, {
            "severity": "medium",
            "title": "Issue 1",
        })
        dashboard = msp.get_dashboard()
        assert dashboard["incidents"]["total"] >= 1


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for error handling and edge cases."""

    def test_get_nonexistent_provider_raises(self, msp):
        with pytest.raises(ValueError, match="Provider not found"):
            msp.escalate_provider("prv_NONEXIST")

    def test_contract_lifecycle_nonexistent_provider_raises(self, msp):
        with pytest.raises(ValueError):
            msp.contract_lifecycle("prv_NONEXIST")

    def test_parse_date_iso_format(self, msp):
        dt = SentinelMSP._parse_date("2025-06-15T10:30:00")
        assert dt.year == 2025
        assert dt.month == 6

    def test_parse_date_invalid_raises(self, msp):
        with pytest.raises(ValueError, match="Unrecognized date"):
            SentinelMSP._parse_date("not-a-date")

    def test_parse_date_wrong_type_raises(self, msp):
        with pytest.raises(TypeError):
            SentinelMSP._parse_date(12345)
