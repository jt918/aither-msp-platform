"""
Dark Web Monitoring API Routes

Identity monitoring, breach scanning, exposure management, and risk scoring.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.shield.dark_web_monitor import (
    DarkWebMonitorService,
    IdentityType,
    ExposureSeverity,
    AlertStatus,
    DataType,
)

router = APIRouter(prefix="/dark-web", tags=["Dark Web Monitoring"])


def _init_dw_service() -> DarkWebMonitorService:
    """Initialize DarkWebMonitorService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return DarkWebMonitorService(db=db)
    except Exception:
        return DarkWebMonitorService()


# Global service instance
dw_service = _init_dw_service()


# ========== Request / Response Models ==========

class AddIdentityRequest(BaseModel):
    user_id: str
    identity_type: str = Field(..., description="email, phone, ssn, credit_card, username, domain, ip_address")
    identity_value: str = Field(..., description="Raw value — will be hashed before storage")


class UpdateExposureRequest(BaseModel):
    action: str = Field(..., description="acknowledge, resolve, or false_positive")


class IngestBreachRequest(BaseModel):
    breaches: List[Dict[str, Any]] = Field(
        ...,
        description="List of breach dicts with at minimum breach_name and severity",
    )


# ========== Identity Management ==========

@router.post("/identities")
async def add_identity(req: AddIdentityRequest):
    """Register an identity for dark-web monitoring."""
    # Validate identity type
    valid_types = [t.value for t in IdentityType]
    if req.identity_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid identity_type. Must be one of: {valid_types}")
    result = dw_service.add_monitored_identity(
        user_id=req.user_id,
        identity_type=req.identity_type,
        identity_value=req.identity_value,
    )
    return {"status": "ok", "identity": DarkWebMonitorService._identity_to_dict(result)}


@router.get("/identities")
async def list_identities(
    user_id: str = Query(...),
    active_only: bool = Query(True),
):
    """List monitored identities for a user."""
    return {"identities": dw_service.list_identities(user_id, active_only=active_only)}


@router.get("/identities/{identity_id}")
async def get_identity(identity_id: str):
    """Get a single monitored identity."""
    result = dw_service.get_identity(identity_id)
    if not result:
        raise HTTPException(status_code=404, detail="Identity not found")
    return result


@router.delete("/identities/{identity_id}")
async def remove_identity(identity_id: str):
    """Deactivate a monitored identity."""
    success = dw_service.remove_identity(identity_id)
    if not success:
        raise HTTPException(status_code=404, detail="Identity not found")
    return {"status": "ok", "message": "Identity deactivated"}


# ========== Scanning ==========

@router.post("/scan/{identity_id}")
async def scan_identity(identity_id: str):
    """Scan a single identity against all breach sources."""
    result = dw_service.scan_identity(identity_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Identity not found or inactive")
    return result


@router.post("/scan-all")
async def scan_all_identities():
    """Batch-scan all active monitored identities."""
    return dw_service.scan_all_identities()


# ========== Exposures ==========

@router.get("/exposures")
async def get_exposures(
    user_id: str = Query(...),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Get exposure alerts for a user."""
    exposures = dw_service.get_exposures(
        user_id=user_id,
        status=status,
        severity=severity,
        limit=limit,
        offset=offset,
    )
    return {"exposures": exposures, "count": len(exposures)}


@router.get("/exposures/{alert_id}")
async def get_exposure(alert_id: str):
    """Get a single exposure alert."""
    result = dw_service.get_exposure(alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Exposure alert not found")
    return result


@router.put("/exposures/{alert_id}")
async def update_exposure(alert_id: str, req: UpdateExposureRequest):
    """Update exposure status: acknowledge, resolve, or mark as false positive."""
    if req.action == "acknowledge":
        result = dw_service.acknowledge_exposure(alert_id)
    elif req.action == "resolve":
        result = dw_service.resolve_exposure(alert_id)
    elif req.action == "false_positive":
        result = dw_service.mark_false_positive(alert_id)
    else:
        raise HTTPException(status_code=400, detail="action must be one of: acknowledge, resolve, false_positive")

    if not result:
        raise HTTPException(status_code=404, detail="Exposure alert not found")
    return result


# ========== Breach Database ==========

@router.get("/breaches")
async def list_breaches(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List known breach records."""
    return {"breaches": dw_service.list_breaches(limit=limit, offset=offset)}


@router.post("/breaches/ingest")
async def ingest_breach_feed(req: IngestBreachRequest):
    """Import breach records from a provider feed."""
    return dw_service.ingest_breach_feed(req.breaches)


# ========== Risk & Timeline ==========

@router.get("/risk-score/{user_id}")
async def get_risk_score(user_id: str):
    """Get 0-100 risk score for a user based on their exposure profile."""
    return dw_service.get_risk_score(user_id)


@router.get("/timeline/{user_id}")
async def get_exposure_timeline(user_id: str):
    """Chronological exposure history for a user."""
    return {"timeline": dw_service.get_exposure_timeline(user_id)}


# ========== Dashboard ==========

@router.get("/dashboard")
async def get_dashboard():
    """Aggregate dark-web monitoring stats."""
    return dw_service.get_dashboard()
