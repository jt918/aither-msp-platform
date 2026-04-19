"""
API Routes for User & Entity Behavior Analytics (UEBA) Engine
Behavioral baselining, anomaly detection, and threat scoring
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.ueba_engine import (
    UEBAEngineService,
    EntityType,
    EventType,
    AnomalyType,
    RiskLevel,
    TimeWindow,
    ThreatIndicatorType,
)

router = APIRouter(prefix="/ueba", tags=["UEBA"])


def _init_ueba_service() -> UEBAEngineService:
    """Initialize UEBAEngineService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return UEBAEngineService(db=db)
    except Exception:
        return UEBAEngineService()


# Initialize service with DB persistence
ueba_service = _init_ueba_service()


# ========== Request/Response Models ==========

class ProfileCreate(BaseModel):
    entity_type: str = Field(default="user", description="Entity type: user, device, ip_address, service_account, api_key, network_segment")
    entity_id: str = Field(..., description="Unique entity identifier")
    entity_name: Optional[str] = None
    client_id: Optional[str] = ""
    tags: Optional[List[str]] = []


class EventRecord(BaseModel):
    entity_id: str = Field(..., description="Entity that performed the action")
    event_type: str = Field(..., description="Event type from EventType enum")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Event context: source_ip, geo_location, device_fingerprint, etc.")


class BatchEventRecord(BaseModel):
    events: List[EventRecord]


class AnomalyReview(BaseModel):
    reviewer: str = Field(..., description="Name or ID of the reviewer")


class ThreatCreate(BaseModel):
    indicator_type: str = Field(..., description="Threat type from ThreatIndicatorType enum")
    severity: str = Field(default="medium")
    related_profiles: Optional[List[str]] = []
    related_events: Optional[List[str]] = []
    ttps: Optional[List[str]] = []
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    description: Optional[str] = ""


class ThreatUpdate(BaseModel):
    severity: Optional[str] = None
    is_active: Optional[bool] = None
    confidence: Optional[float] = None
    description: Optional[str] = None
    ttps: Optional[List[str]] = None


# ========== Profile Endpoints ==========

@router.post("/profiles")
async def create_profile(data: ProfileCreate):
    """Create a new entity behavior profile."""
    profile = ueba_service.create_profile(
        entity_type=data.entity_type,
        entity_id=data.entity_id,
        entity_name=data.entity_name or data.entity_id,
        client_id=data.client_id or "",
        tags=data.tags,
    )
    return {"status": "created", "profile": _profile_dict(profile)}


@router.get("/profiles")
async def list_profiles(
    entity_type: Optional[str] = None,
    client_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    watchlisted: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List entity behavior profiles with filters."""
    profiles = ueba_service.list_profiles(
        entity_type=entity_type,
        client_id=client_id,
        risk_level=risk_level,
        watchlisted=watchlisted,
        limit=limit,
        offset=offset,
    )
    return {"profiles": [_profile_dict(p) for p in profiles], "count": len(profiles)}


@router.get("/profiles/{profile_id}")
async def get_profile(profile_id: str):
    """Get a single entity behavior profile."""
    profile = ueba_service.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _profile_dict(profile)


@router.post("/profiles/{profile_id}/watchlist")
async def watchlist_profile(profile_id: str):
    """Add a profile to the watchlist."""
    profile = ueba_service.watchlist_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"status": "watchlisted", "profile_id": profile_id}


@router.delete("/profiles/{profile_id}/watchlist")
async def unwatchlist_profile(profile_id: str):
    """Remove a profile from the watchlist."""
    profile = ueba_service.unwatchlist_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {"status": "unwatchlisted", "profile_id": profile_id}


# ========== Event Endpoints ==========

@router.post("/events")
async def record_event(data: EventRecord):
    """Record a behavioral event and get real-time risk assessment."""
    result = ueba_service.record_event(
        entity_id=data.entity_id,
        event_type=data.event_type,
        context=data.context,
    )
    return result


@router.post("/events/batch")
async def record_batch(data: BatchEventRecord):
    """Record multiple behavioral events in bulk."""
    events = [{"entity_id": e.entity_id, "event_type": e.event_type, "context": e.context} for e in data.events]
    result = ueba_service.record_batch(events)
    return result


# ========== Baseline Endpoints ==========

@router.post("/profiles/{profile_id}/build-baseline")
async def build_baseline(profile_id: str):
    """Build behavioral baseline from historical events."""
    profile = ueba_service.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    result = ueba_service.build_baseline(profile_id)
    return result


@router.get("/profiles/{profile_id}/baselines")
async def get_baselines(profile_id: str):
    """Get all baselines for a profile."""
    profile = ueba_service.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    baselines = ueba_service.get_baselines(profile_id)
    return {
        "profile_id": profile_id,
        "baselines": [
            {
                "baseline_id": b.baseline_id,
                "metric_name": b.metric_name,
                "expected_value": b.expected_value,
                "std_deviation": b.std_deviation,
                "sample_count": b.sample_count,
                "confidence": b.confidence,
                "time_window": b.time_window,
                "last_updated": b.last_updated.isoformat() if b.last_updated else None,
            }
            for b in baselines
        ],
    }


# ========== Anomaly Endpoints ==========

@router.get("/anomalies")
async def get_anomalies(
    profile_id: Optional[str] = None,
    anomaly_type: Optional[str] = None,
    severity: Optional[str] = None,
    confirmed: Optional[bool] = None,
    false_positive: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Get anomaly detections with filters."""
    anomalies = ueba_service.get_anomalies(
        profile_id=profile_id,
        anomaly_type=anomaly_type,
        severity=severity,
        confirmed=confirmed,
        false_positive=false_positive,
        limit=limit,
        offset=offset,
    )
    return {
        "anomalies": [_anomaly_dict(a) for a in anomalies],
        "count": len(anomalies),
    }


@router.post("/anomalies/{anomaly_id}/confirm")
async def confirm_anomaly(anomaly_id: str):
    """Confirm an anomaly as genuine."""
    anomaly = ueba_service.confirm_anomaly(anomaly_id)
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return {"status": "confirmed", "anomaly_id": anomaly_id}


@router.post("/anomalies/{anomaly_id}/false-positive")
async def mark_false_positive(anomaly_id: str):
    """Mark anomaly as false positive."""
    anomaly = ueba_service.mark_false_positive(anomaly_id)
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return {"status": "marked_false_positive", "anomaly_id": anomaly_id}


@router.post("/anomalies/{anomaly_id}/review")
async def review_anomaly(anomaly_id: str, data: AnomalyReview):
    """Mark anomaly as reviewed."""
    anomaly = ueba_service.review_anomaly(anomaly_id, reviewer=data.reviewer)
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return {"status": "reviewed", "anomaly_id": anomaly_id, "reviewed_by": data.reviewer}


# ========== Threat Endpoints ==========

@router.get("/threats")
async def get_threats(
    indicator_type: Optional[str] = None,
    severity: Optional[str] = None,
    active_only: bool = True,
    limit: int = Query(100, ge=1, le=500),
):
    """Get threat indicators."""
    threats = ueba_service.get_indicators(
        indicator_type=indicator_type,
        severity=severity,
        active_only=active_only,
        limit=limit,
    )
    return {
        "threats": [_threat_dict(t) for t in threats],
        "count": len(threats),
    }


@router.post("/correlate")
async def correlate_anomalies():
    """Run anomaly correlation to generate threat indicators."""
    indicators = ueba_service._correlate_anomalies()
    return {
        "indicators_created": len(indicators),
        "indicators": [_threat_dict(i) for i in indicators],
    }


# ========== Risk Endpoints ==========

@router.get("/risk-distribution")
async def risk_distribution():
    """Get risk score distribution across all profiles."""
    return ueba_service.get_risk_distribution()


@router.get("/high-risk")
async def get_high_risk(threshold: float = Query(60.0, ge=0, le=100)):
    """Get entities with risk score above threshold."""
    entities = ueba_service.get_high_risk_entities(threshold=threshold)
    return {"entities": entities, "count": len(entities), "threshold": threshold}


@router.get("/profiles/{profile_id}/risk-factors")
async def get_risk_factors(profile_id: str):
    """Get risk score breakdown for a profile."""
    profile = ueba_service.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    score = ueba_service.calculate_risk_score(profile_id)
    anomalies = ueba_service.get_anomalies(profile_id=profile_id)
    return {
        "profile_id": profile_id,
        "risk_score": score,
        "risk_level": profile.risk_level,
        "is_watchlisted": profile.is_watchlisted,
        "anomaly_count": len(anomalies),
        "anomaly_breakdown": _anomaly_type_breakdown(anomalies),
        "severity_breakdown": _severity_breakdown(anomalies),
    }


# ========== Peer Comparison ==========

@router.get("/profiles/{profile_id}/peer-comparison")
async def peer_comparison(profile_id: str):
    """Compare profile behavior to peers."""
    result = ueba_service.compare_to_peers(profile_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ========== Timeline ==========

@router.get("/profiles/{profile_id}/timeline")
async def anomaly_timeline(profile_id: str):
    """Get chronological anomaly timeline for a profile."""
    profile = ueba_service.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    timeline = ueba_service.get_anomaly_timeline(profile_id)
    return {"profile_id": profile_id, "timeline": timeline}


# ========== Dashboard ==========

@router.get("/dashboard")
async def dashboard():
    """Main UEBA dashboard with summary statistics."""
    return ueba_service.get_dashboard()


# ========== Helpers ==========

def _profile_dict(p) -> dict:
    return {
        "profile_id": p.profile_id,
        "entity_type": p.entity_type,
        "entity_id": p.entity_id,
        "entity_name": p.entity_name,
        "client_id": p.client_id,
        "baseline_established": p.baseline_established,
        "risk_score": p.risk_score,
        "risk_level": p.risk_level,
        "total_events": p.total_events,
        "anomaly_count": p.anomaly_count,
        "last_activity_at": p.last_activity_at.isoformat() if p.last_activity_at else None,
        "first_seen_at": p.first_seen_at.isoformat() if p.first_seen_at else None,
        "tags": p.tags,
        "is_watchlisted": p.is_watchlisted,
    }


def _anomaly_dict(a) -> dict:
    return {
        "anomaly_id": a.anomaly_id,
        "profile_id": a.profile_id,
        "event_id": a.event_id,
        "anomaly_type": a.anomaly_type,
        "severity": a.severity,
        "description": a.description,
        "deviation_score": a.deviation_score,
        "baseline_value": a.baseline_value,
        "observed_value": a.observed_value,
        "is_confirmed": a.is_confirmed,
        "is_false_positive": a.is_false_positive,
        "detected_at": a.detected_at.isoformat() if a.detected_at else None,
        "reviewed_at": a.reviewed_at.isoformat() if a.reviewed_at else None,
        "reviewed_by": a.reviewed_by,
    }


def _threat_dict(t) -> dict:
    return {
        "indicator_id": t.indicator_id,
        "indicator_type": t.indicator_type,
        "related_profiles": t.related_profiles,
        "related_events": t.related_events,
        "confidence": t.confidence,
        "severity": t.severity,
        "ttps": t.ttps,
        "is_active": t.is_active,
        "first_seen": t.first_seen.isoformat() if t.first_seen else None,
        "last_seen": t.last_seen.isoformat() if t.last_seen else None,
        "description": t.description,
    }


def _anomaly_type_breakdown(anomalies) -> dict:
    breakdown = {}
    for a in anomalies:
        breakdown[a.anomaly_type] = breakdown.get(a.anomaly_type, 0) + 1
    return breakdown


def _severity_breakdown(anomalies) -> dict:
    breakdown = {}
    for a in anomalies:
        breakdown[a.severity] = breakdown.get(a.severity, 0) + 1
    return breakdown
