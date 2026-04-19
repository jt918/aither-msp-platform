"""
Tests for the Dark Web Monitoring service.

Covers: identity CRUD, scanning, exposure lifecycle, risk scoring,
breach ingestion, timeline, dashboard.
"""

import pytest
from services.shield.dark_web_monitor import (
    DarkWebMonitorService,
    IdentityType,
    ExposureSeverity,
    AlertStatus,
    DataType,
    _hash_value,
    _mask_value,
)


@pytest.fixture
def svc():
    """Fresh in-memory service for each test."""
    return DarkWebMonitorService()


# ── Helpers ────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_hash_value_deterministic(self):
        h1 = _hash_value("test@example.com")
        h2 = _hash_value("test@example.com")
        assert h1 == h2
        assert len(h1) == 64

    def test_hash_value_case_insensitive(self):
        assert _hash_value("Test@Example.COM") == _hash_value("test@example.com")

    def test_mask_email(self):
        assert _mask_value("john@gmail.com", "email") == "j***@gmail.com"

    def test_mask_phone(self):
        assert _mask_value("5551234567", "phone") == "***4567"

    def test_mask_ssn(self):
        assert _mask_value("123456789", "ssn") == "***-**-6789"

    def test_mask_credit_card(self):
        assert _mask_value("4111111111111111", "credit_card") == "****-****-****-1111"

    def test_mask_domain(self):
        assert _mask_value("example.com", "domain") == "example.com"

    def test_mask_ip(self):
        assert _mask_value("192.168.1.100", "ip_address") == "192.168.*.*"

    def test_mask_username(self):
        result = _mask_value("johndoe", "username")
        assert result.startswith("j")
        assert result.endswith("e")
        assert "*" in result


# ── Identity CRUD ──────────────────────────────────────────────────────────

class TestIdentityManagement:
    def test_add_identity(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        assert ident.identity_id.startswith("DWI-")
        assert ident.user_id == "user-1"
        assert ident.identity_type == "email"
        assert ident.is_active is True
        assert "***" in ident.display_hint

    def test_list_identities(self, svc):
        svc.add_monitored_identity("user-1", "email", "a@example.com")
        svc.add_monitored_identity("user-1", "phone", "5551234567")
        svc.add_monitored_identity("user-2", "email", "b@example.com")

        user1 = svc.list_identities("user-1")
        assert len(user1) == 2

        user2 = svc.list_identities("user-2")
        assert len(user2) == 1

    def test_get_identity(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        result = svc.get_identity(ident.identity_id)
        assert result is not None
        assert result["identity_id"] == ident.identity_id

    def test_get_identity_not_found(self, svc):
        assert svc.get_identity("nonexistent") is None

    def test_remove_identity(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        assert svc.remove_identity(ident.identity_id) is True

        # Should not appear in active-only list
        assert len(svc.list_identities("user-1", active_only=True)) == 0

        # Should appear in all-identities list
        assert len(svc.list_identities("user-1", active_only=False)) == 1

    def test_remove_identity_not_found(self, svc):
        assert svc.remove_identity("nonexistent") is False

    def test_identity_value_is_hashed(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "secret@example.com")
        # The stored value should be a SHA-256 hash, not the raw email
        assert "secret@example.com" not in ident.identity_value
        assert len(ident.identity_value) == 64


# ── Scanning ───────────────────────────────────────────────────────────────

class TestScanning:
    def test_scan_identity(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        result = svc.scan_identity(ident.identity_id)

        assert result is not None
        assert result["scan_id"].startswith("SCN-")
        assert result["identity_id"] == ident.identity_id
        assert result["breaches_found"] >= 1
        assert result["scan_duration_ms"] >= 0

    def test_scan_identity_creates_exposures(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)

        exposures = svc.get_exposures("user-1")
        assert len(exposures) >= 1
        assert exposures[0]["status"] == "new"

    def test_scan_identity_not_found(self, svc):
        assert svc.scan_identity("nonexistent") is None

    def test_scan_inactive_identity(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.remove_identity(ident.identity_id)
        assert svc.scan_identity(ident.identity_id) is None

    def test_scan_idempotent(self, svc):
        """Second scan should not create duplicate exposures."""
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)
        count_first = len(svc.get_exposures("user-1"))

        svc.scan_identity(ident.identity_id)
        count_second = len(svc.get_exposures("user-1"))

        assert count_first == count_second

    def test_scan_all_identities(self, svc):
        svc.add_monitored_identity("user-1", "email", "a@example.com")
        svc.add_monitored_identity("user-2", "email", "b@example.com")

        result = svc.scan_all_identities()
        assert result["identities_scanned"] == 2
        assert result["total_breaches_found"] >= 2

    def test_scan_updates_last_checked(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        assert ident.last_checked_at is None

        svc.scan_identity(ident.identity_id)
        assert ident.last_checked_at is not None


# ── Exposure Lifecycle ─────────────────────────────────────────────────────

class TestExposureLifecycle:
    def _create_exposure(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)
        exposures = svc.get_exposures("user-1")
        return exposures[0]["alert_id"]

    def test_get_exposures_with_filters(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)

        # Filter by status
        new_only = svc.get_exposures("user-1", status="new")
        assert all(e["status"] == "new" for e in new_only)

        # No resolved yet
        resolved = svc.get_exposures("user-1", status="resolved")
        assert len(resolved) == 0

    def test_get_exposure_by_id(self, svc):
        alert_id = self._create_exposure(svc)
        result = svc.get_exposure(alert_id)
        assert result is not None
        assert result["alert_id"] == alert_id

    def test_get_exposure_not_found(self, svc):
        assert svc.get_exposure("nonexistent") is None

    def test_acknowledge_exposure(self, svc):
        alert_id = self._create_exposure(svc)
        result = svc.acknowledge_exposure(alert_id)

        assert result is not None
        assert result["status"] == "acknowledged"
        assert result["acknowledged_at"] is not None

    def test_resolve_exposure(self, svc):
        alert_id = self._create_exposure(svc)
        result = svc.resolve_exposure(alert_id)

        assert result is not None
        assert result["status"] == "resolved"
        assert result["resolved_at"] is not None

    def test_mark_false_positive(self, svc):
        alert_id = self._create_exposure(svc)
        result = svc.mark_false_positive(alert_id)

        assert result is not None
        assert result["status"] == "false_positive"
        assert result["resolved_at"] is not None

    def test_acknowledge_not_found(self, svc):
        assert svc.acknowledge_exposure("nonexistent") is None

    def test_resolve_not_found(self, svc):
        assert svc.resolve_exposure("nonexistent") is None

    def test_false_positive_not_found(self, svc):
        assert svc.mark_false_positive("nonexistent") is None

    def test_exposure_has_recommended_actions(self, svc):
        alert_id = self._create_exposure(svc)
        result = svc.get_exposure(alert_id)
        assert len(result["recommended_actions"]) > 0

    def test_pagination(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)

        all_exp = svc.get_exposures("user-1", limit=50)
        page1 = svc.get_exposures("user-1", limit=1, offset=0)
        page2 = svc.get_exposures("user-1", limit=1, offset=1)

        if len(all_exp) >= 2:
            assert len(page1) == 1
            assert len(page2) == 1
            assert page1[0]["alert_id"] != page2[0]["alert_id"]


# ── Breach Ingestion ──────────────────────────────────────────────────────

class TestBreachIngestion:
    def test_ingest_new_breach(self, svc):
        result = svc.ingest_breach_feed([
            {
                "breach_name": "TestBreach2025",
                "severity": "high",
                "breach_description": "A test breach",
                "data_types_exposed": ["email", "password"],
                "total_accounts_affected": 100000,
            },
        ])
        assert result["new_breaches"] == 1
        assert result["updated_breaches"] == 0

    def test_ingest_updates_existing(self, svc):
        svc.ingest_breach_feed([
            {"breach_name": "DuplicateTest", "severity": "low"},
        ])
        result = svc.ingest_breach_feed([
            {"breach_name": "DuplicateTest", "severity": "high"},
        ])
        assert result["new_breaches"] == 0
        assert result["updated_breaches"] == 1

    def test_ingest_skips_empty_name(self, svc):
        result = svc.ingest_breach_feed([
            {"breach_name": "", "severity": "low"},
        ])
        assert result["total_processed"] == 0

    def test_list_breaches(self, svc):
        breaches = svc.list_breaches()
        # Should include the 3 seeded mock breaches
        assert len(breaches) >= 3

    def test_get_breach(self, svc):
        breaches = svc.list_breaches()
        first = breaches[0]
        result = svc.get_breach(first["breach_id"])
        assert result is not None
        assert result["breach_name"] == first["breach_name"]

    def test_get_breach_not_found(self, svc):
        assert svc.get_breach("nonexistent") is None

    def test_breach_pagination(self, svc):
        page = svc.list_breaches(limit=1, offset=0)
        assert len(page) == 1


# ── Risk Scoring ──────────────────────────────────────────────────────────

class TestRiskScoring:
    def test_risk_score_no_exposures(self, svc):
        result = svc.get_risk_score("clean-user")
        assert result["risk_score"] == 0
        assert result["risk_level"] == "none"

    def test_risk_score_with_exposures(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)

        result = svc.get_risk_score("user-1")
        assert result["risk_score"] > 0
        assert result["unresolved_exposures"] > 0
        assert len(result["factors"]) > 0

    def test_risk_score_decreases_after_resolve(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)

        score_before = svc.get_risk_score("user-1")["risk_score"]

        # Resolve all exposures
        for exp in svc.get_exposures("user-1"):
            svc.resolve_exposure(exp["alert_id"])

        score_after = svc.get_risk_score("user-1")["risk_score"]
        assert score_after < score_before

    def test_risk_levels(self, svc):
        result = svc.get_risk_score("no-one")
        assert result["risk_level"] in ("none", "low", "medium", "high", "critical")


# ── Timeline ──────────────────────────────────────────────────────────────

class TestTimeline:
    def test_timeline_empty(self, svc):
        timeline = svc.get_exposure_timeline("user-1")
        assert timeline == []

    def test_timeline_populated(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)

        timeline = svc.get_exposure_timeline("user-1")
        assert len(timeline) >= 1
        assert "breach_name" in timeline[0]
        assert "severity" in timeline[0]
        assert "discovered_at" in timeline[0]

    def test_timeline_chronological_order(self, svc):
        ident = svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_identity(ident.identity_id)

        timeline = svc.get_exposure_timeline("user-1")
        if len(timeline) >= 2:
            assert timeline[0]["discovered_at"] <= timeline[1]["discovered_at"]


# ── Dashboard ─────────────────────────────────────────────────────────────

class TestDashboard:
    def test_dashboard_empty(self, svc):
        dash = svc.get_dashboard()
        assert dash["total_monitored_identities"] == 0
        assert dash["total_breaches_tracked"] >= 3  # mock breaches
        assert dash["total_exposures"] == 0

    def test_dashboard_with_data(self, svc):
        svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.add_monitored_identity("user-2", "phone", "5551234567")
        svc.scan_all_identities()

        dash = svc.get_dashboard()
        assert dash["total_monitored_identities"] == 2
        assert dash["total_exposures"] > 0
        assert dash["total_scans_run"] >= 2
        assert "exposure_status_breakdown" in dash
        assert "exposure_severity_breakdown" in dash

    def test_dashboard_high_risk_users(self, svc):
        svc.add_monitored_identity("user-1", "email", "test@example.com")
        svc.scan_all_identities()

        dash = svc.get_dashboard()
        assert isinstance(dash["high_risk_users"], int)


# ── Recommended Actions ──────────────────────────────────────────────────

class TestRecommendedActions:
    def test_actions_for_password_breach(self, svc):
        actions = svc.generate_recommended_actions({
            "exposed_data_types": ["password", "email"],
        })
        assert any("password" in a.lower() for a in actions)
        assert any("2fa" in a.lower() or "two-factor" in a.lower() for a in actions)

    def test_actions_for_ssn_breach(self, svc):
        actions = svc.generate_recommended_actions({
            "exposed_data_types": ["ssn"],
        })
        assert any("credit" in a.lower() for a in actions)
        assert any("ftc" in a.lower() or "identitytheft" in a.lower() for a in actions)

    def test_actions_for_credit_card_breach(self, svc):
        actions = svc.generate_recommended_actions({
            "exposed_data_types": ["credit_card"],
        })
        assert any("bank" in a.lower() for a in actions)

    def test_actions_fallback(self, svc):
        actions = svc.generate_recommended_actions({
            "exposed_data_types": [],
        })
        assert len(actions) > 0


# ── Enum Validation ──────────────────────────────────────────────────────

class TestEnums:
    def test_identity_types(self):
        assert IdentityType.EMAIL.value == "email"
        assert IdentityType.SSN.value == "ssn"
        assert IdentityType.CREDIT_CARD.value == "credit_card"
        assert IdentityType.IP_ADDRESS.value == "ip_address"

    def test_exposure_severity(self):
        assert ExposureSeverity.CRITICAL.value == "critical"
        assert ExposureSeverity.INFO.value == "info"

    def test_alert_status(self):
        assert AlertStatus.NEW.value == "new"
        assert AlertStatus.FALSE_POSITIVE.value == "false_positive"

    def test_data_types(self):
        assert DataType.PASSWORD.value == "password"
        assert DataType.MEDICAL.value == "medical"
        assert DataType.FINANCIAL.value == "financial"
