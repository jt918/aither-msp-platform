"""
AITHER Platform — App Distribution API
Full app store: registry, releases, update checks, downloads,
rollback, channel promotion, analytics, dashboard.
Shield, Synapse, GigOS, ACE, RMM Agent.
"""
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from middleware.auth import get_current_user, require_admin
from sqlalchemy.orm import Session
from core.database import get_sync_db
from services.msp.app_distribution import AppDistributionService
import os
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/app-store", tags=["App Distribution"])

RELEASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "releases")


def _get_service(db: Session = Depends(get_sync_db)) -> AppDistributionService:
    return AppDistributionService(db)


# ── Pydantic Request / Response Models ──────────────────────────────

class RegisterAppRequest(BaseModel):
    app_id: str = Field(..., description="Unique app identifier")
    display_name: str = Field(..., description="Human-readable app name")
    description: str = ""
    icon_url: str = ""
    category: str = Field("", description="security, ai, commerce, workforce, msp")
    platforms: List[str] = Field(default_factory=list)
    bundle_ids: Dict[str, str] = Field(default_factory=dict)
    api_base_path: str = ""
    requires_subscription: bool = False


class UpdateAppRequest(BaseModel):
    display_name: Optional[str] = None
    description: Optional[str] = None
    icon_url: Optional[str] = None
    category: Optional[str] = None
    platforms: Optional[List[str]] = None
    bundle_ids: Optional[Dict[str, str]] = None
    api_base_path: Optional[str] = None
    requires_subscription: Optional[bool] = None


class PublishReleaseRequest(BaseModel):
    platform: str = Field(..., description="Target platform: android, windows, macos, ios, linux")
    version: str = Field(..., description="Semantic version: 1.0.0")
    version_code: int = Field(..., description="Integer build number")
    channel: str = Field("stable", description="Release channel: stable, beta, canary")
    release_notes: str = ""
    file_name: str = ""
    file_size_bytes: int = 0
    file_hash_sha256: str = ""
    min_os_version: str = ""
    is_mandatory: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class UpdateCheckRequest(BaseModel):
    app_id: str
    platform: str
    current_version: str = ""
    current_version_code: int = 0
    channel: str = "stable"


class PromoteRequest(BaseModel):
    from_channel: str = Field(..., description="Source channel: canary, beta")
    to_channel: str = Field(..., description="Target channel: beta, stable")


# ── App Registry ────────────────────────────────────────────────────

@router.post("/apps/registry")
async def register_app(
    req: RegisterAppRequest,
    svc: AppDistributionService = Depends(_get_service),
    user=Depends(require_admin),
):
    """Register a new app in the distribution catalog (admin)."""
    try:
        app = svc.register_app(
            app_id=req.app_id,
            display_name=req.display_name,
            description=req.description,
            icon_url=req.icon_url,
            category=req.category,
            platforms=req.platforms,
            bundle_ids=req.bundle_ids,
            api_base_path=req.api_base_path,
            requires_subscription=req.requires_subscription,
        )
        return {"status": "registered", "app": _app_to_dict(app)}
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@router.get("/apps/registry")
async def list_apps(
    active_only: bool = Query(True),
    svc: AppDistributionService = Depends(_get_service),
):
    """List all registered apps (catalog)."""
    apps = svc.list_apps(active_only=active_only)
    return {
        "apps": [_app_to_dict(a) for a in apps],
        "total": len(apps),
    }


@router.get("/apps/registry/{app_id}")
async def get_app(
    app_id: str,
    svc: AppDistributionService = Depends(_get_service),
):
    """Get details for a specific app."""
    app = svc.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail=f"App '{app_id}' not found")
    return _app_to_dict(app)


@router.put("/apps/registry/{app_id}")
async def update_app(
    app_id: str,
    req: UpdateAppRequest,
    svc: AppDistributionService = Depends(_get_service),
    user=Depends(require_admin),
):
    """Update app registration (admin)."""
    updates = {k: v for k, v in req.dict().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    app = svc.update_app(app_id, **updates)
    if not app:
        raise HTTPException(status_code=404, detail=f"App '{app_id}' not found")
    return {"status": "updated", "app": _app_to_dict(app)}


@router.delete("/apps/registry/{app_id}")
async def deactivate_app(
    app_id: str,
    svc: AppDistributionService = Depends(_get_service),
    user=Depends(require_admin),
):
    """Deactivate an app (soft delete, admin)."""
    ok = svc.deactivate_app(app_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"App '{app_id}' not found")
    return {"status": "deactivated", "app_id": app_id}


# ── Release Management ──────────────────────────────────────────────

@router.post("/apps/{app_id}/releases")
async def publish_release(
    app_id: str,
    req: PublishReleaseRequest,
    svc: AppDistributionService = Depends(_get_service),
    user=Depends(require_admin),
):
    """Publish a new release for an app (admin)."""
    try:
        release = svc.publish_release(
            app_id=app_id,
            platform=req.platform,
            version=req.version,
            version_code=req.version_code,
            channel=req.channel,
            release_notes=req.release_notes,
            file_name=req.file_name,
            file_size_bytes=req.file_size_bytes,
            file_hash_sha256=req.file_hash_sha256,
            min_os_version=req.min_os_version,
            is_mandatory=req.is_mandatory,
            metadata=req.metadata,
        )
        return {
            "status": "published",
            "release": _release_to_dict(release),
            "download_url": f"/api/app-store/apps/{app_id}/current/{req.platform}",
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/apps/{app_id}/releases")
async def list_releases(
    app_id: str,
    platform: Optional[str] = None,
    channel: Optional[str] = None,
    limit: int = Query(20, le=100),
    svc: AppDistributionService = Depends(_get_service),
):
    """List releases for an app, newest first."""
    releases = svc.list_releases(app_id, platform=platform, channel=channel, limit=limit)
    return {
        "app_id": app_id,
        "releases": [_release_to_dict(r) for r in releases],
        "total": len(releases),
    }


# ── Current Release (public - auto-update checks) ──────────────────

@router.get("/apps/{app_id}/current/{platform}")
async def get_current_release(
    app_id: str,
    platform: str,
    channel: str = Query("stable"),
    svc: AppDistributionService = Depends(_get_service),
):
    """Get the current release for an app/platform. Public endpoint for auto-update."""
    release = svc.get_current_release(app_id, platform, channel)
    if not release:
        raise HTTPException(status_code=404, detail=f"No {channel} release for {app_id}/{platform}")
    return _release_to_dict(release)


# ── Update Check (public - agents/apps call this) ──────────────────

@router.post("/apps/check-update")
async def check_update(
    req: UpdateCheckRequest,
    svc: AppDistributionService = Depends(_get_service),
):
    """Check if an update is available. Called by client apps on startup."""
    result = svc.check_update(
        app_id=req.app_id,
        platform=req.platform,
        current_version_code=req.current_version_code,
        channel=req.channel,
    )
    return result


# ── Download ────────────────────────────────────────────────────────

@router.post("/apps/releases/{release_id}/download")
async def download_release(
    release_id: str,
    request: Request,
    svc: AppDistributionService = Depends(_get_service),
):
    """Log a download and return the download URL."""
    release = svc.get_release(release_id)
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    user_id = ""
    # Try to extract user from auth header if present
    try:
        auth = request.headers.get("authorization", "")
        if auth:
            user_id = auth.split(".")[-1][:36] if "." in auth else ""
    except Exception:
        pass

    record = svc.record_download(release_id, user_id=user_id, ip_address=ip, user_agent=ua)

    # Check if binary file exists on disk
    file_path = os.path.join(RELEASE_DIR, release.app_id, release.platform, release.file_name)
    if os.path.exists(file_path):
        media_type = {
            "android": "application/vnd.android.package-archive",
            "ios": "application/octet-stream",
            "windows": "application/x-msdownload",
            "macos": "application/x-apple-diskimage",
            "linux": "application/x-debian-package",
        }.get(release.platform, "application/octet-stream")
        return FileResponse(file_path, media_type=media_type, filename=release.file_name)

    return {
        "status": "manifest_only",
        "release_id": release_id,
        "download_url": release.download_url,
        "file_name": release.file_name,
        "file_hash_sha256": release.file_hash_sha256,
        "file_size_bytes": release.file_size_bytes,
        "message": "Binary not yet uploaded. Download URL is a placeholder.",
        "download_logged": record is not None,
    }


# ── Rollback ────────────────────────────────────────────────────────

@router.post("/apps/releases/{release_id}/rollback")
async def rollback_release(
    release_id: str,
    svc: AppDistributionService = Depends(_get_service),
    user=Depends(require_admin),
):
    """Rollback: restore previous version as current (admin)."""
    release = svc.get_release(release_id)
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")

    previous = svc.rollback_release(release.app_id, release.platform, release.channel)
    if not previous:
        raise HTTPException(status_code=400, detail="No previous release to rollback to")
    return {
        "status": "rolled_back",
        "previous_version": previous.version,
        "release": _release_to_dict(previous),
    }


# ── Promote ─────────────────────────────────────────────────────────

@router.post("/apps/releases/{release_id}/promote")
async def promote_release(
    release_id: str,
    req: PromoteRequest,
    svc: AppDistributionService = Depends(_get_service),
    user=Depends(require_admin),
):
    """Promote a release from one channel to another, e.g. beta -> stable (admin)."""
    try:
        release = svc.promote_release(release_id, req.from_channel, req.to_channel)
        if not release:
            raise HTTPException(status_code=404, detail="Release not found")
        return {
            "status": "promoted",
            "from_channel": req.from_channel,
            "to_channel": req.to_channel,
            "release": _release_to_dict(release),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Stats ───────────────────────────────────────────────────────────

@router.get("/apps/{app_id}/stats")
async def get_app_stats(
    app_id: str,
    svc: AppDistributionService = Depends(_get_service),
    user=Depends(require_admin),
):
    """Download statistics for a specific app (admin)."""
    app = svc.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail=f"App '{app_id}' not found")
    stats = svc.get_download_stats(app_id)
    return stats


# ── Dashboard ───────────────────────────────────────────────────────

@router.get("/apps/dashboard")
async def get_dashboard(
    svc: AppDistributionService = Depends(_get_service),
    user=Depends(require_admin),
):
    """Admin dashboard: totals, latest versions, download counts."""
    return svc.get_dashboard()


# ── Platform Coverage ──────────────────────────────────────────────

@router.get("/apps/platforms")
async def get_platform_coverage(
    svc: AppDistributionService = Depends(_get_service),
):
    """Which apps support which platforms."""
    return svc.get_platform_coverage()


# ── Legacy compatibility aliases ────────────────────────────────────
# Keep old routes working for any existing integrations

@router.get("/catalog")
async def legacy_catalog(svc: AppDistributionService = Depends(_get_service)):
    """Legacy catalog endpoint — redirects to /apps/registry."""
    apps = svc.list_apps(active_only=True)
    catalog = []
    for a in apps:
        catalog.append({
            "app_id": a.app_id,
            "display_name": a.display_name,
            "description": a.description,
            "category": a.category,
            "platforms": a.platforms,
            "bundle_ids": a.bundle_ids,
            "icon": a.icon_url,
            "download_links": {
                p: f"/api/app-store/apps/{a.app_id}/current/{p}"
                for p in a.platforms
            },
        })
    return {"apps": catalog, "total": len(catalog)}


@router.post("/check-update")
async def legacy_check_update(
    req: UpdateCheckRequest,
    svc: AppDistributionService = Depends(_get_service),
):
    """Legacy update check — delegates to new service."""
    return svc.check_update(
        app_id=req.app_id,
        platform=req.platform,
        current_version_code=req.current_version_code,
        channel=req.channel,
    )


# ── Serialization helpers ──────────────────────────────────────────

def _app_to_dict(app) -> dict:
    return {
        "app_id": app.app_id,
        "display_name": app.display_name,
        "description": app.description,
        "icon_url": app.icon_url,
        "category": app.category,
        "platforms": app.platforms,
        "bundle_ids": app.bundle_ids,
        "api_base_path": app.api_base_path,
        "requires_subscription": app.requires_subscription,
        "is_active": app.is_active,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "updated_at": app.updated_at.isoformat() if app.updated_at else None,
    }


def _release_to_dict(r) -> dict:
    return {
        "release_id": r.release_id,
        "app_id": r.app_id,
        "platform": r.platform,
        "version": r.version,
        "version_code": r.version_code,
        "channel": r.channel,
        "release_notes": r.release_notes,
        "file_name": r.file_name,
        "file_size_bytes": r.file_size_bytes,
        "file_hash_sha256": r.file_hash_sha256,
        "download_url": r.download_url,
        "min_os_version": r.min_os_version,
        "is_current": r.is_current,
        "is_mandatory": r.is_mandatory,
        "download_count": r.download_count,
        "published_at": r.published_at.isoformat() if r.published_at else None,
    }
