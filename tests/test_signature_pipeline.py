"""
Aither Shield - Signature Pipeline Service Tests

Full coverage for threat signature CRUD, database versioning,
delta generation, update distribution, feed sources, and stats.
"""

import pytest
from services.shield.signature_pipeline import (
    SignaturePipelineService,
    SignaturePlatform,
    UpdateStatus,
    FeedType,
    DetectionEngine,
    ThreatSeverity,
    ThreatSignature,
    SignatureDatabase,
    SignatureDelta,
    UpdateDistribution,
    FeedSource,
)


@pytest.fixture
def svc():
    """Create a fresh SignaturePipelineService (in-memory)."""
    return SignaturePipelineService()


# ── Initialization & Seeding ──────────────────────────────────────────────

class TestInitialization:
    """Verify service bootstraps correctly with seed data."""

    def test_service_creates(self, svc):
        assert svc is not None

    def test_seed_signatures_loaded(self, svc):
        assert len(svc._signatures) >= 25

    def test_seed_feeds_loaded(self, svc):
        assert len(svc._feeds) >= 3
        assert "FEED-CLAMAV" in svc._feeds
        assert "FEED-YARA" in svc._feeds
        assert "FEED-OTX" in svc._feeds

    def test_no_database_published_yet(self, svc):
        assert svc._current_version is None
        assert svc.get_database_version() is None


# ── Enums ─────────────────────────────────────────────────────────────────

class TestEnums:
    """Verify enum values are accessible."""

    def test_signature_platform(self):
        assert SignaturePlatform.WINDOWS.value == "windows"
        assert SignaturePlatform.ALL.value == "all"
        assert SignaturePlatform.IOS.value == "ios"

    def test_update_status(self):
        assert UpdateStatus.PENDING.value == "pending"
        assert UpdateStatus.INSTALLED.value == "installed"
        assert UpdateStatus.SKIPPED.value == "skipped"

    def test_feed_type(self):
        assert FeedType.CLAMAV.value == "clamav"
        assert FeedType.ALIENVAULT_OTX.value == "alienvault_otx"
        assert FeedType.VIRUSTOTAL.value == "virustotal"
        assert FeedType.ABUSE_IPDB.value == "abuse_ipdb"

    def test_detection_engine(self):
        assert DetectionEngine.SIGNATURE.value == "signature"
        assert DetectionEngine.BEHAVIORAL.value == "behavioral"

    def test_threat_severity(self):
        assert ThreatSeverity.CRITICAL.value == "critical"
        assert ThreatSeverity.LOW.value == "low"


# ── Signature CRUD ────────────────────────────────────────────────────────

class TestSignatureCRUD:
    """Tests for add, get, update, delete signatures."""

    def test_add_signature(self, svc):
        result = svc.add_signature({
            "name": "Test.Malware.NewThreat",
            "threat_type": "malware",
            "severity": "high",
            "hash_sha256": "abcd1234" * 8,
            "description": "Test malware signature",
            "platform": "windows",
        })
        assert result["status"] == "created"
        assert "signature_id" in result

    def test_add_signature_with_custom_id(self, svc):
        result = svc.add_signature({
            "signature_id": "SIG-CUSTOM-001",
            "name": "Custom.Sig",
            "threat_type": "trojan",
            "severity": "critical",
        })
        assert result["signature_id"] == "SIG-CUSTOM-001"
        assert svc.get_signature("SIG-CUSTOM-001") is not None

    def test_get_signature_exists(self, svc):
        sig = svc.get_signature("SIG-EICAR-001")
        assert sig is not None
        assert sig["name"] == "EICAR-Test-File"
        assert sig["threat_type"] == "test"
        assert sig["hash_md5"] == "44d88612fea8a8f36de82e1278abb02f"

    def test_get_signature_not_found(self, svc):
        assert svc.get_signature("SIG-NONEXISTENT") is None

    def test_update_signature(self, svc):
        result = svc.update_signature("SIG-EICAR-001", {"severity": "medium"})
        assert result["status"] == "updated"
        sig = svc.get_signature("SIG-EICAR-001")
        assert sig["severity"] == "medium"

    def test_update_signature_not_found(self, svc):
        result = svc.update_signature("SIG-NONEXISTENT", {"severity": "high"})
        assert "error" in result

    def test_delete_signature(self, svc):
        result = svc.delete_signature("SIG-EICAR-002")
        assert result["status"] == "deleted"
        sig = svc.get_signature("SIG-EICAR-002")
        assert sig["is_active"] is False

    def test_delete_signature_not_found(self, svc):
        result = svc.delete_signature("SIG-NONEXISTENT")
        assert "error" in result

    def test_add_signature_with_yara_rule(self, svc):
        result = svc.add_signature({
            "name": "Custom.YARA.Test",
            "threat_type": "malware",
            "severity": "medium",
            "yara_rule": 'rule test { condition: true }',
            "detection_engine": "signature",
        })
        assert result["status"] == "created"
        sig = svc.get_signature(result["signature_id"])
        assert sig["yara_rule"] is not None

    def test_add_signature_with_cve(self, svc):
        result = svc.add_signature({
            "name": "CVE.Test",
            "threat_type": "malware",
            "severity": "critical",
            "cve_id": "CVE-2024-12345",
        })
        sig = svc.get_signature(result["signature_id"])
        assert sig["cve_id"] == "CVE-2024-12345"


# ── Search ────────────────────────────────────────────────────────────────

class TestSearch:
    """Tests for signature search and filtering."""

    def test_search_all(self, svc):
        results = svc.search_signatures()
        assert len(results) >= 25

    def test_search_by_name(self, svc):
        results = svc.search_signatures("EICAR")
        assert len(results) >= 1
        assert all("EICAR" in r["name"] for r in results)

    def test_search_by_threat_type(self, svc):
        results = svc.search_signatures(filters={"threat_type": "ransomware"})
        assert len(results) >= 2
        assert all(r["threat_type"] == "ransomware" for r in results)

    def test_search_by_severity(self, svc):
        results = svc.search_signatures(filters={"severity": "critical"})
        assert len(results) >= 5

    def test_search_by_platform(self, svc):
        results = svc.search_signatures(filters={"platform": "linux"})
        assert len(results) >= 1

    def test_search_by_engine(self, svc):
        results = svc.search_signatures(filters={"detection_engine": "behavioral"})
        assert len(results) >= 4

    def test_search_excludes_inactive(self, svc):
        svc.delete_signature("SIG-MAL-005")
        results = svc.search_signatures("PUP")
        assert len(results) == 0

    def test_search_include_inactive(self, svc):
        svc.delete_signature("SIG-MAL-005")
        results = svc.search_signatures("PUP", {"include_inactive": True})
        assert len(results) >= 1

    def test_search_by_cve(self, svc):
        results = svc.search_signatures("CVE-2017-0144")
        assert len(results) >= 1
        assert results[0]["name"] == "Ransomware.WannaCry.A"

    def test_search_combined_filters(self, svc):
        results = svc.search_signatures(
            filters={"threat_type": "malware", "severity": "critical"}
        )
        assert all(
            r["threat_type"] == "malware" and r["severity"] == "critical"
            for r in results
        )


# ── Batch Import ──────────────────────────────────────────────────────────

class TestBatchImport:
    """Tests for bulk signature import."""

    def test_import_batch(self, svc):
        before = len([s for s in svc._signatures.values() if s.is_active])
        result = svc.import_signatures_batch([
            {"name": "Import.Test.1", "threat_type": "malware", "severity": "low"},
            {"name": "Import.Test.2", "threat_type": "trojan", "severity": "high"},
        ])
        assert result["imported"] == 2
        assert result["errors"] == 0
        assert result["total_in_db"] == before + 2

    def test_import_skips_duplicates(self, svc):
        result = svc.import_signatures_batch([
            {"signature_id": "SIG-EICAR-001", "name": "Dupe"},
        ])
        assert result["skipped"] == 1
        assert result["imported"] == 0

    def test_import_handles_errors(self, svc):
        result = svc.import_signatures_batch([
            {},  # Missing required 'name'
            {"name": "Good.Sig", "threat_type": "malware"},
        ])
        assert result["errors"] == 1
        assert result["imported"] == 1

    def test_import_empty_list(self, svc):
        result = svc.import_signatures_batch([])
        assert result["imported"] == 0


# ── Database Versioning ───────────────────────────────────────────────────

class TestDatabaseVersioning:
    """Tests for publishing and versioning signature databases."""

    def test_publish_database(self, svc):
        result = svc.publish_database("Initial release")
        assert "version" in result
        assert result["total_signatures"] >= 25
        assert result["release_notes"] == "Initial release"
        assert result["checksum_sha256"]

    def test_get_database_version(self, svc):
        svc.publish_database("v1")
        current = svc.get_database_version()
        assert current is not None
        assert current["version"] == "1.0.1"

    def test_get_database_version_none(self, svc):
        assert svc.get_database_version() is None

    def test_list_database_versions(self, svc):
        svc.publish_database("v1")
        svc.add_signature({"name": "New.Sig", "threat_type": "malware"})
        svc.publish_database("v2")
        versions = svc.list_database_versions()
        assert len(versions) == 2
        assert versions[0]["build_number"] > versions[1]["build_number"]

    def test_publish_tracks_new_and_removed(self, svc):
        svc.publish_database("v1")
        svc.add_signature({"name": "Added.Sig", "threat_type": "malware"})
        svc.delete_signature("SIG-EICAR-002")
        result = svc.publish_database("v2")
        assert result["new_in_version"] >= 1
        assert result["removed_in_version"] >= 1

    def test_publish_increments_build(self, svc):
        r1 = svc.publish_database("first")
        r2 = svc.publish_database("second")
        assert r2["build_number"] == r1["build_number"] + 1


# ── Delta Generation ─────────────────────────────────────────────────────

class TestDeltaGeneration:
    """Tests for delta update generation."""

    def test_generate_delta(self, svc):
        svc.publish_database("v1")
        svc.add_signature({"name": "Delta.New", "threat_type": "malware"})
        svc.publish_database("v2")
        delta = svc.generate_delta("1.0.1", "1.0.2")
        assert delta["added_count"] >= 1
        assert delta["checksum_sha256"]

    def test_generate_delta_invalid_version(self, svc):
        svc.publish_database("v1")
        result = svc.generate_delta("9.9.9", "1.0.1")
        assert "error" in result

    def test_get_delta_to_current(self, svc):
        svc.publish_database("v1")
        svc.add_signature({"name": "Delta.Current", "threat_type": "malware"})
        svc.publish_database("v2")
        result = svc.get_delta("1.0.1")
        assert result["from_version"] == "1.0.1"
        assert result["to_version"] == "1.0.2"

    def test_get_delta_already_current(self, svc):
        svc.publish_database("v1")
        result = svc.get_delta("1.0.1")
        assert result["status"] == "up_to_date"

    def test_get_delta_no_database(self, svc):
        result = svc.get_delta("1.0.0")
        assert "error" in result

    def test_delta_with_removals(self, svc):
        svc.publish_database("v1")
        svc.delete_signature("SIG-MAL-003")
        svc.publish_database("v2")
        delta = svc.generate_delta("1.0.1", "1.0.2")
        assert delta["removed_count"] >= 1


# ── Update Distribution ──────────────────────────────────────────────────

class TestUpdateDistribution:
    """Tests for endpoint update tracking."""

    def test_request_update_no_db(self, svc):
        result = svc.request_update("EP-001")
        assert result["status"] == "no_database"

    def test_request_update_available(self, svc):
        svc.publish_database("v1")
        result = svc.request_update("EP-001", current_version="0.9.0")
        assert result["status"] == "update_available"
        assert "distribution_id" in result
        assert result["latest_version"] == "1.0.1"

    def test_request_update_up_to_date(self, svc):
        svc.publish_database("v1")
        result = svc.request_update("EP-001", current_version="1.0.1")
        assert result["status"] == "up_to_date"

    def test_request_update_with_delta(self, svc):
        svc.publish_database("v1")
        svc.add_signature({"name": "Update.Sig", "threat_type": "malware"})
        svc.publish_database("v2")
        result = svc.request_update("EP-001", current_version="1.0.1")
        assert "delta" in result

    def test_record_update_installed(self, svc):
        svc.publish_database("v1")
        update = svc.request_update("EP-001", current_version="0.9.0")
        dist_id = update["distribution_id"]
        result = svc.record_update_result(dist_id, "installed")
        assert result["status"] == "installed"
        assert result["completed_at"] is not None

    def test_record_update_failed(self, svc):
        svc.publish_database("v1")
        update = svc.request_update("EP-001")
        dist_id = update["distribution_id"]
        result = svc.record_update_result(dist_id, "failed", error="Download timeout")
        assert result["status"] == "failed"

    def test_record_update_not_found(self, svc):
        result = svc.record_update_result("DIST-NONEXISTENT", "installed")
        assert "error" in result

    def test_request_update_with_device_id(self, svc):
        svc.publish_database("v1")
        result = svc.request_update("EP-001", device_id="DEV-ABC")
        dist = svc._distributions[result["distribution_id"]]
        assert dist.device_id == "DEV-ABC"


# ── Feed Sources ──────────────────────────────────────────────────────────

class TestFeedSources:
    """Tests for feed source management."""

    def test_list_feeds(self, svc):
        feeds = svc.list_feed_sources()
        assert len(feeds) >= 3

    def test_register_feed(self, svc):
        result = svc.register_feed_source({
            "name": "Custom Feed",
            "source_type": "custom",
            "api_url": "https://example.com/feed",
            "update_interval_hours": 12,
        })
        assert result["status"] == "registered"
        assert "source_id" in result

    def test_register_feed_with_id(self, svc):
        result = svc.register_feed_source({
            "source_id": "FEED-CUSTOM-X",
            "name": "Custom X",
            "source_type": "custom",
        })
        assert result["source_id"] == "FEED-CUSTOM-X"

    def test_update_feed(self, svc):
        result = svc.update_feed_source("FEED-CLAMAV", {
            "update_interval_hours": 2,
        })
        assert result["status"] == "updated"
        assert svc._feeds["FEED-CLAMAV"].update_interval_hours == 2

    def test_update_feed_not_found(self, svc):
        result = svc.update_feed_source("FEED-NONEXISTENT", {"name": "x"})
        assert "error" in result

    def test_delete_feed(self, svc):
        result = svc.delete_feed_source("FEED-OTX")
        assert result["status"] == "deleted"
        assert "FEED-OTX" not in svc._feeds

    def test_delete_feed_not_found(self, svc):
        result = svc.delete_feed_source("FEED-NONEXISTENT")
        assert "error" in result

    def test_pull_feed(self, svc):
        result = svc.pull_feed("FEED-CLAMAV")
        assert result["status"] == "pulled"
        assert result["imported"] >= 0
        assert svc._feeds["FEED-CLAMAV"].last_pull_at is not None

    def test_pull_disabled_feed(self, svc):
        result = svc.pull_feed("FEED-OTX")
        assert result["status"] == "disabled"
        assert result["imported"] == 0

    def test_pull_feed_not_found(self, svc):
        result = svc.pull_feed("FEED-NONEXISTENT")
        assert "error" in result

    def test_pull_all_feeds(self, svc):
        result = svc.pull_all_feeds()
        assert result["feeds_pulled"] >= 2  # CLAMAV + YARA enabled
        assert result["total_imported"] >= 0

    def test_pull_feed_increments_contributed(self, svc):
        before = svc._feeds["FEED-CLAMAV"].signatures_contributed
        svc.pull_feed("FEED-CLAMAV")
        after = svc._feeds["FEED-CLAMAV"].signatures_contributed
        assert after >= before


# ── Stats & Dashboard ────────────────────────────────────────────────────

class TestStats:
    """Tests for statistics and dashboard endpoints."""

    def test_signature_stats(self, svc):
        stats = svc.get_signature_stats()
        assert stats["total_active"] >= 25
        assert "by_threat_type" in stats
        assert "by_platform" in stats
        assert "by_detection_engine" in stats
        assert "by_severity" in stats

    def test_signature_stats_by_type(self, svc):
        stats = svc.get_signature_stats()
        types = stats["by_threat_type"]
        assert "malware" in types
        assert "ransomware" in types
        assert "network_attack" in types

    def test_signature_stats_by_platform(self, svc):
        stats = svc.get_signature_stats()
        platforms = stats["by_platform"]
        assert "windows" in platforms
        assert "all" in platforms

    def test_distribution_stats_empty(self, svc):
        stats = svc.get_distribution_stats()
        assert stats["total_distributions"] == 0
        assert stats["current_version"] is None

    def test_distribution_stats_with_updates(self, svc):
        svc.publish_database("v1")
        svc.request_update("EP-001")
        svc.request_update("EP-002")
        stats = svc.get_distribution_stats()
        assert stats["total_distributions"] == 2
        assert stats["pending"] == 2

    def test_distribution_stats_after_install(self, svc):
        svc.publish_database("v1")
        update = svc.request_update("EP-001")
        svc.record_update_result(update["distribution_id"], "installed")
        stats = svc.get_distribution_stats()
        assert stats["up_to_date"] == 1

    def test_dashboard(self, svc):
        svc.publish_database("v1")
        dashboard = svc.get_dashboard()
        assert "signatures" in dashboard
        assert "distribution" in dashboard
        assert "database" in dashboard
        assert "feeds" in dashboard
        assert "versions_published" in dashboard
        assert dashboard["versions_published"] == 1
        assert dashboard["feeds"]["total"] >= 3
        assert dashboard["feeds"]["enabled"] >= 2

    def test_dashboard_no_db(self, svc):
        dashboard = svc.get_dashboard()
        assert dashboard["database"] is None
        assert dashboard["versions_published"] == 0


# ── Dataclass Instantiation ──────────────────────────────────────────────

class TestDataclasses:
    """Verify dataclass defaults and structure."""

    def test_threat_signature_defaults(self):
        sig = ThreatSignature(
            signature_id="TEST", name="Test", threat_type="malware", severity="low"
        )
        assert sig.platform == "all"
        assert sig.detection_engine == "signature"
        assert sig.is_active is True
        assert sig.false_positive_rate == 0.0

    def test_signature_database_defaults(self):
        db = SignatureDatabase(db_id="DB-1", version="1.0.0", build_number=1)
        assert db.total_signatures == 0
        assert db.signature_ids == []

    def test_signature_delta_defaults(self):
        delta = SignatureDelta(delta_id="D-1", from_version="1.0.0", to_version="1.0.1")
        assert delta.added_signatures == []
        assert delta.removed_signature_ids == []

    def test_update_distribution_defaults(self):
        dist = UpdateDistribution(
            distribution_id="DIST-1", db_version="1.0.1", endpoint_id="EP-1"
        )
        assert dist.status == "pending"
        assert dist.completed_at is None

    def test_feed_source_defaults(self):
        feed = FeedSource(source_id="F-1", name="Test", source_type="custom")
        assert feed.update_interval_hours == 24
        assert feed.is_enabled is True
        assert feed.signatures_contributed == 0


# ── Edge Cases ────────────────────────────────────────────────────────────

class TestEdgeCases:
    """Edge case and integration-style tests."""

    def test_full_lifecycle(self, svc):
        """Add sig -> publish -> update endpoint -> record result."""
        svc.add_signature({
            "name": "Lifecycle.Test",
            "threat_type": "trojan",
            "severity": "high",
        })
        pub = svc.publish_database("lifecycle test")
        assert pub["total_signatures"] >= 26

        update = svc.request_update("EP-LIFECYCLE", current_version="0.0.0")
        assert update["status"] == "update_available"

        result = svc.record_update_result(update["distribution_id"], "installed")
        assert result["status"] == "installed"

        stats = svc.get_distribution_stats()
        assert stats["up_to_date"] >= 1

    def test_multiple_publishes_and_deltas(self, svc):
        svc.publish_database("v1")
        svc.add_signature({"name": "V2.New", "threat_type": "malware"})
        svc.publish_database("v2")
        svc.add_signature({"name": "V3.New", "threat_type": "trojan"})
        svc.publish_database("v3")

        versions = svc.list_database_versions()
        assert len(versions) == 3

        delta = svc.generate_delta("1.0.1", "1.0.3")
        assert delta["added_count"] >= 2

    def test_search_after_delete(self, svc):
        svc.add_signature({
            "signature_id": "SIG-DEL-TEST",
            "name": "DeleteMe",
            "threat_type": "malware",
        })
        svc.delete_signature("SIG-DEL-TEST")
        results = svc.search_signatures("DeleteMe")
        assert len(results) == 0
        results = svc.search_signatures("DeleteMe", {"include_inactive": True})
        assert len(results) == 1

    def test_pull_feed_adds_to_count(self, svc):
        initial = len(svc._signatures)
        svc.pull_feed("FEED-CLAMAV")
        assert len(svc._signatures) > initial

    def test_stats_reflect_delete(self, svc):
        before = svc.get_signature_stats()["total_active"]
        svc.delete_signature("SIG-MAL-001")
        after = svc.get_signature_stats()["total_active"]
        assert after == before - 1
        assert svc.get_signature_stats()["total_inactive"] >= 1
