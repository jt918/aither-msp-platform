"""
AITHER Platform - App Distribution Service
Manages app registry, releases, update channels, downloads, and analytics
for all Aither product apps (Shield, Synapse, ACE, GigOS, RMM Agent).

DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

try:
    from sqlalchemy.orm import Session
    from sqlalchemy import func as sa_func
    from models.app_distribution import (
        AppRegistration as AppRegistrationModel,
        AppRelease as AppReleaseModel,
        AppDownloadLog as AppDownloadLogModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ── Dataclasses ─────────────────────────────────────────────────────

@dataclass
class AppInfo:
    """Registered application metadata."""
    app_id: str
    display_name: str
    description: str = ""
    icon_url: str = ""
    category: str = ""              # security, ai, commerce, workforce, msp
    platforms: List[str] = field(default_factory=list)
    bundle_ids: Dict[str, str] = field(default_factory=dict)
    api_base_path: str = ""
    requires_subscription: bool = False
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class Release:
    """A published release artifact."""
    release_id: str
    app_id: str
    platform: str
    version: str
    version_code: int
    channel: str = "stable"         # stable, beta, canary
    release_notes: str = ""
    file_name: str = ""
    file_size_bytes: int = 0
    file_hash_sha256: str = ""
    download_url: str = ""
    min_os_version: str = ""
    is_current: bool = True
    is_mandatory: bool = False
    download_count: int = 0
    published_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DownloadRecord:
    """Download event log entry."""
    record_id: str
    release_id: str
    app_id: str
    platform: str
    version: str
    user_id: str = ""
    ip_address: str = ""
    user_agent: str = ""
    downloaded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── ORM conversion helpers ─────────────────────────────────────────

def _app_from_row(row) -> AppInfo:
    return AppInfo(
        app_id=row.app_id,
        display_name=row.display_name,
        description=row.description or "",
        icon_url=row.icon_url or "",
        category=row.category or "",
        platforms=row.platforms or [],
        bundle_ids=row.bundle_ids or {},
        api_base_path=row.api_base_path or "",
        requires_subscription=row.requires_subscription or False,
        is_active=row.is_active if row.is_active is not None else True,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _release_from_row(row) -> Release:
    return Release(
        release_id=row.id,
        app_id=row.app_id,
        platform=row.platform,
        version=row.version,
        version_code=row.version_code,
        channel=row.channel or "stable",
        release_notes=row.release_notes or "",
        file_name=row.file_name or "",
        file_size_bytes=row.file_size_bytes or 0,
        file_hash_sha256=row.file_hash_sha256 or "",
        download_url=row.download_url or "",
        min_os_version=row.min_os_version or "",
        is_current=row.is_current if row.is_current is not None else False,
        is_mandatory=row.is_mandatory or False,
        download_count=row.download_count or 0,
        published_at=row.published_at or datetime.now(timezone.utc),
    )


def _download_from_row(row) -> DownloadRecord:
    return DownloadRecord(
        record_id=row.id,
        release_id=row.release_id or "",
        app_id=row.app_id or "",
        platform=row.platform or "",
        version=row.version or "",
        user_id=row.user_id or "",
        ip_address=row.ip_address or "",
        user_agent=row.user_agent or "",
        downloaded_at=row.downloaded_at or datetime.now(timezone.utc),
    )


# ── Pre-registered Aither apps ─────────────────────────────────────

DEFAULT_APPS: Dict[str, Dict[str, Any]] = {
    "shield": {
        "display_name": "Aither Shield",
        "description": "AI-powered security suite — antivirus, firewall, VPN, dark web monitoring, identity protection",
        "category": "security",
        "platforms": ["android", "windows", "macos", "ios"],
        "bundle_ids": {"android": "com.aither.shield", "windows": "com.aither.shield", "macos": "com.aither.shield", "ios": "com.aither.shield"},
        "api_base_path": "/api/v1/shield",
        "icon_url": "/assets/icons/shield.png",
    },
    "synapse": {
        "display_name": "Aither Synapse",
        "description": "AI command center — LLM chat, business orchestration, memory, multi-persona intelligence",
        "category": "ai",
        "platforms": ["android", "windows", "macos"],
        "bundle_ids": {"android": "com.aither.synapse", "windows": "com.aither.synapse", "macos": "com.aither.synapse"},
        "api_base_path": "/api/synapse",
        "icon_url": "/assets/icons/synapse.png",
    },
    "ace": {
        "display_name": "Aither ACE",
        "description": "Full-stack commerce engine — POS, inventory, invoicing, customer management, analytics",
        "category": "commerce",
        "platforms": ["android", "windows"],
        "bundle_ids": {"android": "com.aither.ace", "windows": "com.aither.ace"},
        "api_base_path": "/api/ace",
        "icon_url": "/assets/icons/ace.png",
    },
    "gigos": {
        "display_name": "Aither GigOS",
        "description": "Gig workforce platform — job matching, lead claiming, commission tracking, certification",
        "category": "workforce",
        "platforms": ["android", "ios"],
        "bundle_ids": {"android": "com.aither.gigos", "ios": "com.aither.gigos"},
        "api_base_path": "/api/gigbee",
        "icon_url": "/assets/icons/gigos.png",
    },
    "rmm_agent": {
        "display_name": "Aither RMM Agent",
        "description": "Remote monitoring and management agent for MSP endpoint management",
        "category": "msp",
        "platforms": ["windows", "linux", "macos"],
        "bundle_ids": {"windows": "com.aither.rmm", "linux": "com.aither.rmm", "macos": "com.aither.rmm"},
        "api_base_path": "/api/rmm",
        "icon_url": "/assets/icons/rmm.png",
    },
}


class AppDistributionService:
    """
    App Distribution Service — manages registry, releases, downloads,
    update channels, and analytics for all Aither product apps.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: Session = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._apps: Dict[str, AppInfo] = {}
        self._releases: Dict[str, Release] = {}          # release_id -> Release
        self._downloads: List[DownloadRecord] = []

        # Seed default apps into in-memory store
        self._seed_defaults()

    # ── Bootstrap ───────────────────────────────────────────────────

    def _seed_defaults(self) -> None:
        """Pre-register Aither apps if not already present."""
        for app_id, info in DEFAULT_APPS.items():
            if app_id not in self._apps:
                self._apps[app_id] = AppInfo(
                    app_id=app_id,
                    display_name=info["display_name"],
                    description=info["description"],
                    category=info["category"],
                    platforms=info["platforms"],
                    bundle_ids=info["bundle_ids"],
                    api_base_path=info["api_base_path"],
                    icon_url=info.get("icon_url", ""),
                )

        if self._use_db:
            try:
                for app_id, info in DEFAULT_APPS.items():
                    existing = self.db.query(AppRegistrationModel).filter(
                        AppRegistrationModel.app_id == app_id
                    ).first()
                    if not existing:
                        row = AppRegistrationModel(
                            id=str(uuid.uuid4()),
                            app_id=app_id,
                            display_name=info["display_name"],
                            description=info["description"],
                            category=info["category"],
                            platforms=info["platforms"],
                            bundle_ids=info["bundle_ids"],
                            api_base_path=info["api_base_path"],
                            icon_url=info.get("icon_url", ""),
                            is_active=True,
                        )
                        self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error seeding default apps: {e}")
                self.db.rollback()

    # ── App Registry ────────────────────────────────────────────────

    def register_app(
        self,
        app_id: str,
        display_name: str,
        description: str = "",
        icon_url: str = "",
        category: str = "",
        platforms: Optional[List[str]] = None,
        bundle_ids: Optional[Dict[str, str]] = None,
        api_base_path: str = "",
        requires_subscription: bool = False,
    ) -> AppInfo:
        """Register a new app in the distribution catalog."""
        if app_id in self._apps:
            raise ValueError(f"App '{app_id}' already registered")

        app = AppInfo(
            app_id=app_id,
            display_name=display_name,
            description=description,
            icon_url=icon_url,
            category=category,
            platforms=platforms or [],
            bundle_ids=bundle_ids or {},
            api_base_path=api_base_path,
            requires_subscription=requires_subscription,
        )
        self._apps[app_id] = app

        if self._use_db:
            try:
                row = AppRegistrationModel(
                    id=str(uuid.uuid4()),
                    app_id=app_id,
                    display_name=display_name,
                    description=description,
                    icon_url=icon_url,
                    category=category,
                    platforms=platforms or [],
                    bundle_ids=bundle_ids or {},
                    api_base_path=api_base_path,
                    requires_subscription=requires_subscription,
                    is_active=True,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error registering app: {e}")
                self.db.rollback()

        return app

    def update_app(self, app_id: str, **updates) -> Optional[AppInfo]:
        """Update app registration fields."""
        app = self.get_app(app_id)
        if not app:
            return None

        for key, value in updates.items():
            if hasattr(app, key) and key != "app_id":
                setattr(app, key, value)
        app.updated_at = datetime.now(timezone.utc)
        self._apps[app_id] = app

        if self._use_db:
            try:
                row = self.db.query(AppRegistrationModel).filter(
                    AppRegistrationModel.app_id == app_id
                ).first()
                if row:
                    for key, value in updates.items():
                        if hasattr(row, key) and key != "app_id":
                            setattr(row, key, value)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating app: {e}")
                self.db.rollback()

        return app

    def get_app(self, app_id: str) -> Optional[AppInfo]:
        """Retrieve app by id."""
        if self._use_db:
            try:
                row = self.db.query(AppRegistrationModel).filter(
                    AppRegistrationModel.app_id == app_id
                ).first()
                if row:
                    return _app_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting app: {e}")

        return self._apps.get(app_id)

    def list_apps(self, active_only: bool = True) -> List[AppInfo]:
        """List all registered apps."""
        if self._use_db:
            try:
                q = self.db.query(AppRegistrationModel)
                if active_only:
                    q = q.filter(AppRegistrationModel.is_active == True)
                return [_app_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error listing apps: {e}")

        apps = list(self._apps.values())
        if active_only:
            apps = [a for a in apps if a.is_active]
        return apps

    def deactivate_app(self, app_id: str) -> bool:
        """Mark an app as inactive (soft delete)."""
        app = self.get_app(app_id)
        if not app:
            return False

        app.is_active = False
        app.updated_at = datetime.now(timezone.utc)
        self._apps[app_id] = app

        if self._use_db:
            try:
                self.db.query(AppRegistrationModel).filter(
                    AppRegistrationModel.app_id == app_id
                ).update({"is_active": False})
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error deactivating app: {e}")
                self.db.rollback()

        return True

    # ── Release Management ──────────────────────────────────────────

    def publish_release(
        self,
        app_id: str,
        platform: str,
        version: str,
        version_code: int,
        channel: str = "stable",
        release_notes: str = "",
        file_name: str = "",
        file_size_bytes: int = 0,
        file_hash_sha256: str = "",
        min_os_version: str = "",
        is_mandatory: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Release:
        """Publish a new release. Marks previous current release as non-current."""
        app = self.get_app(app_id)
        if not app:
            raise ValueError(f"App '{app_id}' not registered")
        if platform not in app.platforms:
            raise ValueError(f"Platform '{platform}' not supported for '{app_id}'")

        release_id = str(uuid.uuid4())
        if not file_name:
            ext = {"android": "apk", "ios": "ipa", "windows": "exe", "macos": "dmg", "linux": "deb"}.get(platform, "bin")
            file_name = f"{app_id}-{platform}-{version}.{ext}"

        download_url = f"/releases/{app_id}/{platform}/{file_name}"

        # Mark previous current releases as non-current (in-memory)
        for r in self._releases.values():
            if r.app_id == app_id and r.platform == platform and r.channel == channel and r.is_current:
                r.is_current = False

        release = Release(
            release_id=release_id,
            app_id=app_id,
            platform=platform,
            version=version,
            version_code=version_code,
            channel=channel,
            release_notes=release_notes,
            file_name=file_name,
            file_size_bytes=file_size_bytes,
            file_hash_sha256=file_hash_sha256,
            download_url=download_url,
            min_os_version=min_os_version,
            is_current=True,
            is_mandatory=is_mandatory,
        )
        self._releases[release_id] = release

        if self._use_db:
            try:
                # Mark previous releases as non-current
                self.db.query(AppReleaseModel).filter(
                    AppReleaseModel.app_id == app_id,
                    AppReleaseModel.platform == platform,
                    AppReleaseModel.channel == channel,
                    AppReleaseModel.is_current == True,
                ).update({"is_current": False})

                row = AppReleaseModel(
                    id=release_id,
                    app_id=app_id,
                    platform=platform,
                    version=version,
                    version_code=version_code,
                    channel=channel,
                    release_notes=release_notes,
                    file_name=file_name,
                    file_size_bytes=file_size_bytes,
                    file_hash_sha256=file_hash_sha256,
                    download_url=download_url,
                    min_os_version=min_os_version,
                    is_current=True,
                    is_mandatory=is_mandatory,
                    release_metadata=metadata or {},
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error publishing release: {e}")
                self.db.rollback()

        return release

    def get_current_release(self, app_id: str, platform: str, channel: str = "stable") -> Optional[Release]:
        """Get the latest current release for an app/platform/channel."""
        if self._use_db:
            try:
                row = self.db.query(AppReleaseModel).filter(
                    AppReleaseModel.app_id == app_id,
                    AppReleaseModel.platform == platform,
                    AppReleaseModel.channel == channel,
                    AppReleaseModel.is_current == True,
                ).first()
                if row:
                    return _release_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting current release: {e}")

        for r in self._releases.values():
            if r.app_id == app_id and r.platform == platform and r.channel == channel and r.is_current:
                return r
        return None

    def get_release(self, release_id: str) -> Optional[Release]:
        """Get a specific release by id."""
        if self._use_db:
            try:
                row = self.db.query(AppReleaseModel).filter(
                    AppReleaseModel.id == release_id
                ).first()
                if row:
                    return _release_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting release: {e}")

        return self._releases.get(release_id)

    def list_releases(
        self,
        app_id: str,
        platform: Optional[str] = None,
        channel: Optional[str] = None,
        limit: int = 50,
    ) -> List[Release]:
        """List releases for an app, newest first."""
        if self._use_db:
            try:
                q = self.db.query(AppReleaseModel).filter(AppReleaseModel.app_id == app_id)
                if platform:
                    q = q.filter(AppReleaseModel.platform == platform)
                if channel:
                    q = q.filter(AppReleaseModel.channel == channel)
                rows = q.order_by(AppReleaseModel.version_code.desc()).limit(limit).all()
                return [_release_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing releases: {e}")

        results = [r for r in self._releases.values() if r.app_id == app_id]
        if platform:
            results = [r for r in results if r.platform == platform]
        if channel:
            results = [r for r in results if r.channel == channel]
        results.sort(key=lambda r: r.version_code, reverse=True)
        return results[:limit]

    def check_update(self, app_id: str, platform: str, current_version_code: int, channel: str = "stable") -> Dict[str, Any]:
        """Check if an update is available. Returns update info or no-update."""
        latest = self.get_current_release(app_id, platform, channel)
        if not latest or latest.version_code <= current_version_code:
            return {"update_available": False}

        return {
            "update_available": True,
            "is_mandatory": latest.is_mandatory,
            "latest_version": latest.version,
            "latest_version_code": latest.version_code,
            "release_notes": latest.release_notes,
            "download_url": f"/api/app-store/download/{app_id}/{platform}/latest",
            "file_size_bytes": latest.file_size_bytes,
            "file_hash_sha256": latest.file_hash_sha256,
            "release_id": latest.release_id,
        }

    # ── Download Tracking ───────────────────────────────────────────

    def record_download(
        self,
        release_id: str,
        user_id: str = "",
        ip_address: str = "",
        user_agent: str = "",
    ) -> Optional[DownloadRecord]:
        """Record a download event and increment release counter."""
        release = self.get_release(release_id)
        if not release:
            return None

        record_id = str(uuid.uuid4())
        record = DownloadRecord(
            record_id=record_id,
            release_id=release_id,
            app_id=release.app_id,
            platform=release.platform,
            version=release.version,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self._downloads.append(record)

        # Increment counter in-memory
        if release_id in self._releases:
            self._releases[release_id].download_count += 1

        if self._use_db:
            try:
                log = AppDownloadLogModel(
                    id=record_id,
                    release_id=release_id,
                    app_id=release.app_id,
                    platform=release.platform,
                    version=release.version,
                    user_id=user_id or None,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                self.db.add(log)
                # Increment release download counter
                row = self.db.query(AppReleaseModel).filter(AppReleaseModel.id == release_id).first()
                if row:
                    row.download_count = (row.download_count or 0) + 1
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error recording download: {e}")
                self.db.rollback()

        return record

    def get_download_stats(self, app_id: str) -> Dict[str, Any]:
        """Download statistics by platform, version, and totals."""
        releases = self.list_releases(app_id, limit=500)
        total = 0
        by_platform: Dict[str, int] = {}
        by_version: Dict[str, int] = {}
        by_channel: Dict[str, int] = {}

        for r in releases:
            count = r.download_count
            total += count
            by_platform[r.platform] = by_platform.get(r.platform, 0) + count
            by_version[r.version] = by_version.get(r.version, 0) + count
            by_channel[r.channel] = by_channel.get(r.channel, 0) + count

        return {
            "app_id": app_id,
            "total_downloads": total,
            "by_platform": by_platform,
            "by_version": by_version,
            "by_channel": by_channel,
            "release_count": len(releases),
        }

    # ── Release Operations ──────────────────────────────────────────

    def rollback_release(self, app_id: str, platform: str, channel: str = "stable") -> Optional[Release]:
        """Rollback: mark current release as non-current, promote previous version."""
        releases = self.list_releases(app_id, platform=platform, channel=channel, limit=10)
        if len(releases) < 2:
            return None  # Nothing to rollback to

        current = None
        previous = None
        for r in releases:
            if r.is_current:
                current = r
            elif current and not previous:
                previous = r

        if not current or not previous:
            return None

        # Demote current
        current.is_current = False
        self._releases[current.release_id] = current

        # Promote previous
        previous.is_current = True
        self._releases[previous.release_id] = previous

        if self._use_db:
            try:
                self.db.query(AppReleaseModel).filter(
                    AppReleaseModel.id == current.release_id
                ).update({"is_current": False})
                self.db.query(AppReleaseModel).filter(
                    AppReleaseModel.id == previous.release_id
                ).update({"is_current": True})
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error during rollback: {e}")
                self.db.rollback()

        return previous

    def promote_release(self, release_id: str, from_channel: str, to_channel: str) -> Optional[Release]:
        """Promote a release from one channel to another (e.g., beta -> stable)."""
        release = self.get_release(release_id)
        if not release:
            return None
        if release.channel != from_channel:
            raise ValueError(f"Release is on '{release.channel}', not '{from_channel}'")

        # Mark existing current in target channel as non-current
        for r in self._releases.values():
            if r.app_id == release.app_id and r.platform == release.platform and r.channel == to_channel and r.is_current:
                r.is_current = False

        # Update the release
        release.channel = to_channel
        release.is_current = True
        self._releases[release_id] = release

        if self._use_db:
            try:
                # Demote existing current in target channel
                self.db.query(AppReleaseModel).filter(
                    AppReleaseModel.app_id == release.app_id,
                    AppReleaseModel.platform == release.platform,
                    AppReleaseModel.channel == to_channel,
                    AppReleaseModel.is_current == True,
                ).update({"is_current": False})
                # Move release to target channel
                self.db.query(AppReleaseModel).filter(
                    AppReleaseModel.id == release_id
                ).update({"channel": to_channel, "is_current": True})
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error promoting release: {e}")
                self.db.rollback()

        return release

    # ── Analytics / Dashboard ───────────────────────────────────────

    def get_platform_coverage(self) -> Dict[str, Any]:
        """Which apps support which platforms."""
        apps = self.list_apps(active_only=True)
        coverage: Dict[str, List[str]] = {}
        platform_apps: Dict[str, List[str]] = {}

        for app in apps:
            coverage[app.app_id] = app.platforms
            for p in app.platforms:
                platform_apps.setdefault(p, []).append(app.app_id)

        return {
            "apps_by_platform": platform_apps,
            "platforms_by_app": coverage,
            "total_apps": len(apps),
            "total_platforms": len(platform_apps),
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Admin dashboard: total apps, releases, downloads, latest versions per app."""
        apps = self.list_apps(active_only=False)
        total_downloads = 0
        total_releases = 0
        latest_versions: Dict[str, Dict[str, Any]] = {}

        for app in apps:
            releases = self.list_releases(app.app_id, limit=500)
            total_releases += len(releases)
            app_downloads = sum(r.download_count for r in releases)
            total_downloads += app_downloads

            current_map = {}
            for r in releases:
                if r.is_current:
                    current_map[r.platform] = {
                        "version": r.version,
                        "version_code": r.version_code,
                        "channel": r.channel,
                        "downloads": r.download_count,
                        "published_at": r.published_at.isoformat() if r.published_at else None,
                    }

            latest_versions[app.app_id] = {
                "display_name": app.display_name,
                "is_active": app.is_active,
                "total_releases": len(releases),
                "total_downloads": app_downloads,
                "current_versions": current_map,
            }

        return {
            "total_apps": len(apps),
            "active_apps": sum(1 for a in apps if a.is_active),
            "total_releases": total_releases,
            "total_downloads": total_downloads,
            "apps": latest_versions,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
