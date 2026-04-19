"""
Shield Signature Update Pipeline API

REST endpoints for managing threat signatures, versioned databases,
delta updates, feed sources, and distribution to Shield endpoints.

Created: 2026-04-19
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from sqlalchemy.orm import Session

from services.shield.signature_pipeline import SignaturePipelineService
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

router = APIRouter(prefix="/api/v1/signatures", tags=["Shield Signature Pipeline"])


def _get_service(db: Session = Depends(get_sync_db)) -> SignaturePipelineService:
    """Create a SignaturePipelineService with a live DB session per request."""
    return SignaturePipelineService(db=db)


_static_service = SignaturePipelineService()


# ==================== REQUEST MODELS ====================

class SignatureCreateRequest(BaseModel):
    signature_id: Optional[str] = None
    name: str
    threat_type: str = "malware"
    severity: str = "medium"
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    yara_rule: Optional[str] = None
    description: Optional[str] = None
    cve_id: Optional[str] = None
    platform: str = "all"
    detection_engine: str = "signature"
    false_positive_rate: float = 0.0
    is_active: bool = True


class SignatureUpdateRequest(BaseModel):
    name: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    yara_rule: Optional[str] = None
    description: Optional[str] = None
    cve_id: Optional[str] = None
    platform: Optional[str] = None
    detection_engine: Optional[str] = None
    false_positive_rate: Optional[float] = None
    is_active: Optional[bool] = None


class SignatureImportRequest(BaseModel):
    signatures: List[Dict[str, Any]]


class PublishRequest(BaseModel):
    release_notes: str = ""


class UpdateCheckRequest(BaseModel):
    endpoint_id: str
    current_version: Optional[str] = None
    device_id: Optional[str] = None


class UpdateResultRequest(BaseModel):
    distribution_id: str
    status: str
    error: Optional[str] = None


class FeedSourceCreateRequest(BaseModel):
    source_id: Optional[str] = None
    name: str
    source_type: str = "custom"
    api_url: Optional[str] = None
    api_key_ref: Optional[str] = None
    update_interval_hours: int = 24
    is_enabled: bool = True


class FeedSourceUpdateRequest(BaseModel):
    name: Optional[str] = None
    source_type: Optional[str] = None
    api_url: Optional[str] = None
    api_key_ref: Optional[str] = None
    update_interval_hours: Optional[int] = None
    is_enabled: Optional[bool] = None


# ==================== SIGNATURE CRUD ====================

@router.post("/entries")
async def create_signature(req: SignatureCreateRequest,
                           svc: SignaturePipelineService = Depends(_get_service)):
    """Add a new threat signature."""
    return svc.add_signature(req.model_dump(exclude_none=True))


@router.get("/entries/{signature_id}")
async def get_signature(signature_id: str,
                        svc: SignaturePipelineService = Depends(_get_service)):
    """Get a single signature by ID."""
    result = svc.get_signature(signature_id)
    if not result:
        raise HTTPException(status_code=404, detail="Signature not found")
    return result


@router.put("/entries/{signature_id}")
async def update_signature(signature_id: str, req: SignatureUpdateRequest,
                           svc: SignaturePipelineService = Depends(_get_service)):
    """Update an existing signature."""
    result = svc.update_signature(signature_id, req.model_dump(exclude_none=True))
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.delete("/entries/{signature_id}")
async def delete_signature(signature_id: str,
                           svc: SignaturePipelineService = Depends(_get_service)):
    """Soft-delete a signature."""
    result = svc.delete_signature(signature_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ==================== SEARCH ====================

@router.get("/search")
async def search_signatures(
    q: str = Query("", description="Search query"),
    threat_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    detection_engine: Optional[str] = Query(None),
    include_inactive: bool = Query(False),
    svc: SignaturePipelineService = Depends(_get_service),
):
    """Search signatures by name/description with filters."""
    filters = {}
    if threat_type:
        filters["threat_type"] = threat_type
    if severity:
        filters["severity"] = severity
    if platform:
        filters["platform"] = platform
    if detection_engine:
        filters["detection_engine"] = detection_engine
    if include_inactive:
        filters["include_inactive"] = True
    return svc.search_signatures(q, filters)


# ==================== IMPORT ====================

@router.post("/import")
async def import_signatures(req: SignatureImportRequest,
                            svc: SignaturePipelineService = Depends(_get_service)):
    """Bulk import signatures."""
    return svc.import_signatures_batch(req.signatures)


# ==================== DATABASE VERSIONING ====================

@router.post("/publish")
async def publish_database(req: PublishRequest,
                           svc: SignaturePipelineService = Depends(_get_service)):
    """Publish a new versioned signature database."""
    return svc.publish_database(req.release_notes)


@router.get("/database/current")
async def get_current_database(
    svc: SignaturePipelineService = Depends(_get_service),
):
    """Get current database version info."""
    result = svc.get_database_version()
    if not result:
        raise HTTPException(status_code=404, detail="No database published yet")
    return result


@router.get("/database/history")
async def list_database_history(
    svc: SignaturePipelineService = Depends(_get_service),
):
    """List all published database versions."""
    return svc.list_database_versions()


# ==================== DELTA UPDATES ====================

@router.get("/delta/{from_version}")
async def get_delta(from_version: str,
                    svc: SignaturePipelineService = Depends(_get_service)):
    """Get delta update from a version to current."""
    result = svc.get_delta(from_version)
    if result and "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ==================== UPDATE DISTRIBUTION ====================

@router.post("/update/check")
async def check_update(req: UpdateCheckRequest,
                       svc: SignaturePipelineService = Depends(_get_service)):
    """Endpoint checks for available signature updates."""
    return svc.request_update(req.endpoint_id, req.current_version, req.device_id)


@router.post("/update/result")
async def record_update_result(req: UpdateResultRequest,
                               svc: SignaturePipelineService = Depends(_get_service)):
    """Record the result of an update distribution."""
    result = svc.record_update_result(req.distribution_id, req.status, req.error)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ==================== FEED SOURCES ====================

@router.post("/feeds")
async def create_feed(req: FeedSourceCreateRequest,
                      svc: SignaturePipelineService = Depends(_get_service)):
    """Register a new feed source."""
    return svc.register_feed_source(req.model_dump(exclude_none=True))


@router.get("/feeds")
async def list_feeds(svc: SignaturePipelineService = Depends(_get_service)):
    """List all feed sources."""
    return svc.list_feed_sources()


@router.put("/feeds/{source_id}")
async def update_feed(source_id: str, req: FeedSourceUpdateRequest,
                      svc: SignaturePipelineService = Depends(_get_service)):
    """Update a feed source."""
    result = svc.update_feed_source(source_id, req.model_dump(exclude_none=True))
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.delete("/feeds/{source_id}")
async def delete_feed(source_id: str,
                      svc: SignaturePipelineService = Depends(_get_service)):
    """Delete a feed source."""
    result = svc.delete_feed_source(source_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/feeds/{source_id}/pull")
async def pull_feed(source_id: str,
                    svc: SignaturePipelineService = Depends(_get_service)):
    """Pull latest signatures from a specific feed."""
    result = svc.pull_feed(source_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/feeds/pull-all")
async def pull_all_feeds(svc: SignaturePipelineService = Depends(_get_service)):
    """Pull from all enabled feed sources."""
    return svc.pull_all_feeds()


# ==================== STATS & DASHBOARD ====================

@router.get("/stats")
async def get_signature_stats(
    svc: SignaturePipelineService = Depends(_get_service),
):
    """Get signature statistics."""
    return svc.get_signature_stats()


@router.get("/distribution")
async def get_distribution_stats(
    svc: SignaturePipelineService = Depends(_get_service),
):
    """Get update distribution statistics."""
    return svc.get_distribution_stats()


@router.get("/dashboard")
async def get_dashboard(svc: SignaturePipelineService = Depends(_get_service)):
    """Combined signature pipeline dashboard."""
    return svc.get_dashboard()
