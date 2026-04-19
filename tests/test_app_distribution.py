"""
Tests for App Distribution Service
Full coverage: app registration, release publishing, update checks,
downloads, rollback, promotion, stats, dashboard, platform coverage.
"""

import pytest
from datetime import datetime, timezone

from services.msp.app_distribution import (
    AppDistributionService,
    AppInfo,
    Release,
    DownloadRecord,
)


class TestAppDistributionService:
    """Tests for AppDistributionService class"""

    def setup_method(self):
        """Set up test fixtures — in-memory mode (no DB)."""
        self.svc = AppDistributionService()

    # ========== Default Seeding ==========

    def test_default_apps_seeded(self):
        """Default Aither apps are pre-registered on init."""
        apps = self.svc.list_apps()
        app_ids = [a.app_id for a in apps]
        assert "shield" in app_ids
        assert "synapse" in app_ids
        assert "ace" in app_ids
        assert "gigos" in app_ids
        assert "rmm_agent" in app_ids
        assert len(apps) == 5

    def test_default_app_details(self):
        """Default apps have correct metadata."""
        shield = self.svc.get_app("shield")
        assert shield is not None
        assert shield.display_name == "Aither Shield"
        assert shield.category == "security"
        assert "android" in shield.platforms
        assert "windows" in shield.platforms
        assert "ios" in shield.platforms
        assert shield.is_active is True

    # ========== App Registration ==========

    def test_register_app(self):
        """Register a new custom app."""
        app = self.svc.register_app(
            app_id="custom_tool",
            display_name="Custom Tool",
            description="A custom tool",
            category="utility",
            platforms=["windows", "linux"],
            bundle_ids={"windows": "com.aither.custom", "linux": "com.aither.custom"},
        )
        assert app.app_id == "custom_tool"
        assert app.display_name == "Custom Tool"
        assert app.is_active is True

        # Verify it appears in list
        apps = self.svc.list_apps()
        assert any(a.app_id == "custom_tool" for a in apps)

    def test_register_duplicate_app_raises(self):
        """Registering same app_id twice raises ValueError."""
        with pytest.raises(ValueError, match="already registered"):
            self.svc.register_app(app_id="shield", display_name="Duplicate Shield")

    def test_update_app(self):
        """Update app fields."""
        updated = self.svc.update_app("shield", description="Updated description", category="defense")
        assert updated is not None
        assert updated.description == "Updated description"
        assert updated.category == "defense"

    def test_update_nonexistent_app(self):
        """Updating non-existent app returns None."""
        result = self.svc.update_app("nonexistent", description="x")
        assert result is None

    def test_deactivate_app(self):
        """Deactivate an app (soft delete)."""
        ok = self.svc.deactivate_app("gigos")
        assert ok is True

        # Active-only listing should exclude it
        active = self.svc.list_apps(active_only=True)
        assert not any(a.app_id == "gigos" for a in active)

        # Full listing should include it
        all_apps = self.svc.list_apps(active_only=False)
        gigos = [a for a in all_apps if a.app_id == "gigos"]
        assert len(gigos) == 1
        assert gigos[0].is_active is False

    def test_deactivate_nonexistent(self):
        """Deactivating non-existent app returns False."""
        assert self.svc.deactivate_app("nonexistent") is False

    def test_get_app_not_found(self):
        """Get non-existent app returns None."""
        assert self.svc.get_app("nonexistent") is None

    # ========== Release Publishing ==========

    def test_publish_release(self):
        """Publish a new release."""
        release = self.svc.publish_release(
            app_id="shield",
            platform="android",
            version="1.0.0",
            version_code=100,
            channel="stable",
            release_notes="Initial release",
            file_size_bytes=50_000_000,
            file_hash_sha256="abc123",
        )
        assert release.release_id is not None
        assert release.app_id == "shield"
        assert release.platform == "android"
        assert release.version == "1.0.0"
        assert release.is_current is True
        assert release.file_name == "shield-android-1.0.0.apk"

    def test_publish_release_unknown_app(self):
        """Publishing to unknown app raises ValueError."""
        with pytest.raises(ValueError, match="not registered"):
            self.svc.publish_release(
                app_id="nonexistent", platform="android",
                version="1.0.0", version_code=1,
            )

    def test_publish_release_unsupported_platform(self):
        """Publishing to unsupported platform raises ValueError."""
        with pytest.raises(ValueError, match="not supported"):
            self.svc.publish_release(
                app_id="gigos", platform="windows",
                version="1.0.0", version_code=1,
            )

    def test_publish_replaces_current(self):
        """Publishing a new release marks the old one as non-current."""
        r1 = self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100,
        )
        assert r1.is_current is True

        r2 = self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.1.0", version_code=110,
        )
        assert r2.is_current is True

        # r1 should no longer be current
        r1_check = self.svc.get_release(r1.release_id)
        assert r1_check.is_current is False

    def test_publish_different_channels_independent(self):
        """Stable and beta channels are independent."""
        stable = self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100, channel="stable",
        )
        beta = self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.1.0-beta", version_code=110, channel="beta",
        )
        assert stable.is_current is True
        assert beta.is_current is True

    def test_publish_auto_filename(self):
        """File name is auto-generated based on platform."""
        r_win = self.svc.publish_release(
            app_id="shield", platform="windows",
            version="1.0.0", version_code=100,
        )
        assert r_win.file_name.endswith(".exe")

        r_mac = self.svc.publish_release(
            app_id="shield", platform="macos",
            version="1.0.0", version_code=100,
        )
        assert r_mac.file_name.endswith(".dmg")

        r_linux = self.svc.publish_release(
            app_id="rmm_agent", platform="linux",
            version="1.0.0", version_code=100,
        )
        assert r_linux.file_name.endswith(".deb")

    # ========== Release Retrieval ==========

    def test_get_current_release(self):
        """Get the current release for app/platform."""
        self.svc.publish_release(
            app_id="synapse", platform="windows",
            version="2.0.0", version_code=200,
        )
        current = self.svc.get_current_release("synapse", "windows")
        assert current is not None
        assert current.version == "2.0.0"

    def test_get_current_release_none(self):
        """No release returns None."""
        assert self.svc.get_current_release("synapse", "android") is None

    def test_get_release_by_id(self):
        """Retrieve a specific release."""
        r = self.svc.publish_release(
            app_id="ace", platform="android",
            version="1.0.0", version_code=100,
        )
        found = self.svc.get_release(r.release_id)
        assert found is not None
        assert found.version == "1.0.0"

    def test_get_release_not_found(self):
        """Non-existent release returns None."""
        assert self.svc.get_release("nonexistent-id") is None

    def test_list_releases(self):
        """List releases ordered by version_code descending."""
        self.svc.publish_release(app_id="shield", platform="android", version="1.0.0", version_code=100)
        self.svc.publish_release(app_id="shield", platform="android", version="1.1.0", version_code=110)
        self.svc.publish_release(app_id="shield", platform="android", version="1.2.0", version_code=120)

        releases = self.svc.list_releases("shield", platform="android")
        assert len(releases) == 3
        assert releases[0].version_code >= releases[1].version_code

    def test_list_releases_filter_platform(self):
        """Filter releases by platform."""
        self.svc.publish_release(app_id="shield", platform="android", version="1.0.0", version_code=100)
        self.svc.publish_release(app_id="shield", platform="windows", version="1.0.0", version_code=100)

        android = self.svc.list_releases("shield", platform="android")
        assert len(android) == 1
        assert android[0].platform == "android"

    def test_list_releases_filter_channel(self):
        """Filter releases by channel."""
        self.svc.publish_release(app_id="shield", platform="android", version="1.0.0", version_code=100, channel="stable")
        self.svc.publish_release(app_id="shield", platform="android", version="1.1.0-beta", version_code=110, channel="beta")

        stable = self.svc.list_releases("shield", platform="android", channel="stable")
        assert len(stable) == 1
        assert stable[0].channel == "stable"

    # ========== Update Check ==========

    def test_check_update_available(self):
        """Update available when version_code is higher."""
        self.svc.publish_release(
            app_id="shield", platform="android",
            version="2.0.0", version_code=200,
            is_mandatory=True,
        )
        result = self.svc.check_update("shield", "android", current_version_code=100)
        assert result["update_available"] is True
        assert result["latest_version"] == "2.0.0"
        assert result["is_mandatory"] is True

    def test_check_update_not_available(self):
        """No update when already on latest."""
        self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100,
        )
        result = self.svc.check_update("shield", "android", current_version_code=100)
        assert result["update_available"] is False

    def test_check_update_no_release(self):
        """No update when no releases exist."""
        result = self.svc.check_update("shield", "android", current_version_code=1)
        assert result["update_available"] is False

    # ========== Download Tracking ==========

    def test_record_download(self):
        """Record a download event."""
        r = self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100,
        )
        record = self.svc.record_download(
            release_id=r.release_id,
            user_id="user-123",
            ip_address="10.0.0.1",
            user_agent="Aither-Shield/1.0",
        )
        assert record is not None
        assert record.release_id == r.release_id
        assert record.app_id == "shield"
        assert record.user_id == "user-123"

    def test_download_increments_counter(self):
        """Download count increments on each record."""
        r = self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100,
        )
        assert r.download_count == 0

        self.svc.record_download(r.release_id)
        self.svc.record_download(r.release_id)
        self.svc.record_download(r.release_id)

        updated = self.svc.get_release(r.release_id)
        assert updated.download_count == 3

    def test_record_download_invalid_release(self):
        """Recording download for invalid release returns None."""
        assert self.svc.record_download("bad-id") is None

    # ========== Download Stats ==========

    def test_download_stats(self):
        """Get download statistics for an app."""
        r1 = self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100,
        )
        r2 = self.svc.publish_release(
            app_id="shield", platform="windows",
            version="1.0.0", version_code=100,
        )

        self.svc.record_download(r1.release_id)
        self.svc.record_download(r1.release_id)
        self.svc.record_download(r2.release_id)

        stats = self.svc.get_download_stats("shield")
        assert stats["total_downloads"] == 3
        assert stats["by_platform"]["android"] == 2
        assert stats["by_platform"]["windows"] == 1
        assert stats["release_count"] == 2

    def test_download_stats_empty(self):
        """Stats for app with no releases."""
        stats = self.svc.get_download_stats("shield")
        assert stats["total_downloads"] == 0
        assert stats["release_count"] == 0

    # ========== Rollback ==========

    def test_rollback_release(self):
        """Rollback to previous version."""
        self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100,
        )
        self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.1.0", version_code=110,
        )

        previous = self.svc.rollback_release("shield", "android")
        assert previous is not None
        assert previous.version == "1.0.0"
        assert previous.is_current is True

        # 1.1.0 should no longer be current
        current = self.svc.get_current_release("shield", "android")
        assert current.version == "1.0.0"

    def test_rollback_no_previous(self):
        """Rollback with only one release returns None."""
        self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100,
        )
        assert self.svc.rollback_release("shield", "android") is None

    def test_rollback_no_releases(self):
        """Rollback with no releases returns None."""
        assert self.svc.rollback_release("shield", "android") is None

    # ========== Promote ==========

    def test_promote_release(self):
        """Promote a release from beta to stable."""
        beta = self.svc.publish_release(
            app_id="shield", platform="android",
            version="2.0.0-beta", version_code=200, channel="beta",
        )
        promoted = self.svc.promote_release(beta.release_id, "beta", "stable")
        assert promoted is not None
        assert promoted.channel == "stable"
        assert promoted.is_current is True

        # Should be the current stable release
        current = self.svc.get_current_release("shield", "android", "stable")
        assert current is not None
        assert current.version == "2.0.0-beta"

    def test_promote_wrong_channel_raises(self):
        """Promoting from wrong source channel raises ValueError."""
        release = self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100, channel="stable",
        )
        with pytest.raises(ValueError, match="not 'beta'"):
            self.svc.promote_release(release.release_id, "beta", "stable")

    def test_promote_replaces_current_in_target(self):
        """Promoting replaces existing current in target channel."""
        self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100, channel="stable",
        )
        beta = self.svc.publish_release(
            app_id="shield", platform="android",
            version="2.0.0-beta", version_code=200, channel="beta",
        )
        self.svc.promote_release(beta.release_id, "beta", "stable")

        # Old stable should no longer be current
        releases = self.svc.list_releases("shield", platform="android", channel="stable")
        current_count = sum(1 for r in releases if r.is_current)
        assert current_count == 1

    def test_promote_nonexistent_release(self):
        """Promoting non-existent release returns None."""
        assert self.svc.promote_release("bad-id", "beta", "stable") is None

    # ========== Platform Coverage ==========

    def test_platform_coverage(self):
        """Platform coverage returns correct mapping."""
        coverage = self.svc.get_platform_coverage()
        assert "apps_by_platform" in coverage
        assert "platforms_by_app" in coverage
        assert coverage["total_apps"] == 5

        # Shield supports android, windows, macos, ios
        assert "shield" in coverage["platforms_by_app"]
        assert "android" in coverage["platforms_by_app"]["shield"]

        # Android should have multiple apps
        assert "android" in coverage["apps_by_platform"]
        assert "shield" in coverage["apps_by_platform"]["android"]

    # ========== Dashboard ==========

    def test_dashboard(self):
        """Dashboard returns comprehensive stats."""
        self.svc.publish_release(
            app_id="shield", platform="android",
            version="1.0.0", version_code=100,
        )
        r = self.svc.publish_release(
            app_id="synapse", platform="windows",
            version="1.0.0", version_code=100,
        )
        self.svc.record_download(r.release_id)

        dashboard = self.svc.get_dashboard()
        assert dashboard["total_apps"] == 5
        assert dashboard["active_apps"] == 5
        assert dashboard["total_releases"] == 2
        assert dashboard["total_downloads"] == 1
        assert "shield" in dashboard["apps"]
        assert "synapse" in dashboard["apps"]
        assert "generated_at" in dashboard

    def test_dashboard_empty(self):
        """Dashboard works with no releases."""
        dashboard = self.svc.get_dashboard()
        assert dashboard["total_apps"] == 5
        assert dashboard["total_releases"] == 0
        assert dashboard["total_downloads"] == 0

    # ========== Edge Cases ==========

    def test_multiple_platforms_same_app(self):
        """Multiple platforms for the same app are tracked independently."""
        self.svc.publish_release(app_id="shield", platform="android", version="1.0.0", version_code=100)
        self.svc.publish_release(app_id="shield", platform="windows", version="1.0.0", version_code=100)
        self.svc.publish_release(app_id="shield", platform="macos", version="1.0.0", version_code=100)

        for p in ["android", "windows", "macos"]:
            current = self.svc.get_current_release("shield", p)
            assert current is not None
            assert current.platform == p

    def test_mandatory_update_flag(self):
        """Mandatory flag is preserved through publish and check."""
        self.svc.publish_release(
            app_id="shield", platform="android",
            version="2.0.0", version_code=200,
            is_mandatory=True,
        )
        result = self.svc.check_update("shield", "android", current_version_code=100)
        assert result["update_available"] is True
        assert result["is_mandatory"] is True

    def test_rmm_agent_linux(self):
        """RMM Agent supports linux platform."""
        r = self.svc.publish_release(
            app_id="rmm_agent", platform="linux",
            version="1.0.0", version_code=100,
        )
        assert r.platform == "linux"
        current = self.svc.get_current_release("rmm_agent", "linux")
        assert current is not None

    def test_service_fresh_instance_independent(self):
        """Each service instance has independent in-memory state."""
        svc2 = AppDistributionService()
        self.svc.publish_release(app_id="shield", platform="android", version="1.0.0", version_code=100)
        assert self.svc.get_current_release("shield", "android") is not None
        assert svc2.get_current_release("shield", "android") is None
