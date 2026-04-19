"""
API Routes for IP & Entity Threat Scoring Engine
Uses ThreatScoringService for all operations
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.threat_scoring import (
    ThreatScoringService,
    EntityType,
    RiskLevel,
    AutoAction,
)

router = APIRouter(prefix="/threat-score", tags=["Threat Scoring"])


def _init_service() -> ThreatScoringService:
    """Initialize ThreatScoringService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return ThreatScoringService(db=db)
    except Exception:
        return ThreatScoringService()


service = _init_service()


# ========== Request/Response Models ==========

class ScoreEventRequest(BaseModel):
    entity_type: str = Field(..., description="ip_address|user|device|domain|email|url|hash")
    entity_value: str = Field(..., description="The entity identifier")
    event_type: str = Field(..., description="positive|negative|neutral")
    impact_points: float = Field(..., description="Score impact (positive or negative)")
    reason: str = Field("", description="Human-readable reason")
    source: str = Field("", description="Source service/system")
    raw_data: Optional[Dict[str, Any]] = None


class BatchEventsRequest(BaseModel):
    events: List[ScoreEventRequest]


class WhitelistRequest(BaseModel):
    entity_type: str
    entity_value: str
    reason: str = ""


class BlacklistRequest(BaseModel):
    entity_type: str
    entity_value: str
    reason: str = ""


class ThresholdCreateRequest(BaseModel):
    name: str
    risk_level: str
    trust_score_min: float = 0
    trust_score_max: float = 100
    threat_score_min: float = 0
    threat_score_max: float = 100
    auto_action: str = "none"
    notification_channel: str = ""


class ThresholdUpdateRequest(BaseModel):
    name: Optional[str] = None
    risk_level: Optional[str] = None
    trust_score_min: Optional[float] = None
    trust_score_max: Optional[float] = None
    threat_score_min: Optional[float] = None
    threat_score_max: Optional[float] = None
    auto_action: Optional[str] = None
    notification_channel: Optional[str] = None


class FeedCreateRequest(BaseModel):
    name: str
    feed_type: str = Field(..., description="blocklist|allowlist|reputation")
    source_url: str = ""
    format: str = "plaintext"
    update_interval_hours: int = 24


# ========== Scoring Events ==========

@router.post("/event")
async def score_event(req: ScoreEventRequest):
    """Record a scoring event and recalculate entity score."""
    result = service.score_event(
        entity_type=req.entity_type,
        entity_value=req.entity_value,
        event_type=req.event_type,
        impact_points=req.impact_points,
        reason=req.reason,
        source=req.source,
        raw_data=req.raw_data,
    )
    return result


@router.post("/events/batch")
async def score_events_batch(req: BatchEventsRequest):
    """Process multiple scoring events at once."""
    events = [e.dict() for e in req.events]
    results = service.score_batch(events)
    return {"processed": len(results), "results": results}


# ========== Entity Score Queries ==========

@router.get("/entity/{entity_type}/{entity_value:path}")
async def get_entity_score(entity_type: str, entity_value: str):
    """Get current trust/threat score for an entity."""
    result = service.get_score(entity_type, entity_value)
    if not result:
        raise HTTPException(status_code=404, detail="Entity not found")
    return result


@router.get("/entities")
async def get_entities(
    entity_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    is_blacklisted: Optional[bool] = Query(None),
    min_threat: Optional[float] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List entities with optional filters."""
    return service.get_scores(
        entity_type=entity_type,
        risk_level=risk_level,
        is_blacklisted=is_blacklisted,
        min_threat=min_threat,
        limit=limit,
        offset=offset,
    )


@router.get("/entity/{entity_type}/{entity_value:path}/history")
async def get_entity_history(
    entity_type: str,
    entity_value: str,
    period_hours: int = Query(24, ge=1, le=8760),
):
    """Get score history snapshots for an entity."""
    return service.get_score_history(entity_value, period_hours)


# ========== Whitelist / Blacklist ==========

@router.post("/whitelist")
async def whitelist_entity(req: WhitelistRequest):
    """Add entity to whitelist (boosts trust, clears block)."""
    return service.whitelist_entity(req.entity_type, req.entity_value, req.reason)


@router.post("/blacklist")
async def blacklist_entity(req: BlacklistRequest):
    """Add entity to blacklist (sets threat to maximum)."""
    return service.blacklist_entity(req.entity_type, req.entity_value, req.reason)


@router.delete("/lists/{entity_value:path}")
async def remove_from_lists(entity_value: str):
    """Remove entity from both whitelist and blacklist."""
    return service.remove_from_list(entity_value)


# ========== Threshold CRUD ==========

@router.get("/thresholds")
async def list_thresholds():
    """List all score thresholds."""
    return service.get_thresholds()


@router.post("/thresholds")
async def create_threshold(req: ThresholdCreateRequest):
    """Create a new score threshold with auto-action."""
    return service.create_threshold(
        name=req.name,
        risk_level=req.risk_level,
        trust_score_min=req.trust_score_min,
        trust_score_max=req.trust_score_max,
        threat_score_min=req.threat_score_min,
        threat_score_max=req.threat_score_max,
        auto_action=req.auto_action,
        notification_channel=req.notification_channel,
    )


@router.put("/thresholds/{threshold_id}")
async def update_threshold(threshold_id: str, req: ThresholdUpdateRequest):
    """Update an existing threshold."""
    updates = {k: v for k, v in req.dict().items() if v is not None}
    result = service.update_threshold(threshold_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Threshold not found")
    return result


@router.delete("/thresholds/{threshold_id}")
async def delete_threshold(threshold_id: str):
    """Delete a threshold."""
    service.delete_threshold(threshold_id)
    return {"status": "deleted", "threshold_id": threshold_id}


# ========== Reputation Feeds ==========

@router.get("/feeds")
async def list_feeds():
    """List all registered reputation feeds."""
    return service.list_feeds()


@router.post("/feeds")
async def register_feed(req: FeedCreateRequest):
    """Register a new reputation feed."""
    return service.register_feed(
        name=req.name,
        feed_type=req.feed_type,
        source_url=req.source_url,
        format=req.format,
        update_interval_hours=req.update_interval_hours,
    )


@router.post("/feeds/{feed_id}/pull")
async def pull_feed(feed_id: str):
    """Pull and import entries from a reputation feed."""
    result = service.pull_feed(feed_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/feeds/pull-all")
async def pull_all_feeds():
    """Pull all enabled reputation feeds."""
    return service.pull_all_feeds()


# ========== Analytics ==========

@router.get("/risk-distribution")
async def risk_distribution():
    """Count of entities per risk level."""
    return service.get_risk_distribution()


@router.get("/top-threats")
async def top_threats(limit: int = Query(10, ge=1, le=100)):
    """Top N entities by threat score."""
    return service.get_top_threats(limit)


@router.get("/trends")
async def score_trends(period_hours: int = Query(24, ge=1, le=8760)):
    """Event trends over a time period."""
    return service.get_score_trends(period_hours)


@router.get("/geo-map")
async def geographic_threat_map():
    """Geographic distribution of threats."""
    return service.get_geographic_threat_map()


@router.get("/network-posture")
async def network_posture():
    """Overall network security posture summary."""
    return service.get_network_posture()


@router.get("/dashboard")
async def dashboard():
    """Unified threat scoring dashboard."""
    return service.get_dashboard()
