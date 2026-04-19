"""
API Routes for NOC (Network Operations Center) TV-Mode Dashboard
Aggregated MSP data in a single payload for wall-mounted displays.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.noc_aggregator import NOCAggregatorService

router = APIRouter(prefix="/noc", tags=["NOC Dashboard"])


def _init_noc_service() -> NOCAggregatorService:
    """Initialize NOCAggregatorService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return NOCAggregatorService(db=db)
    except Exception:
        return NOCAggregatorService()


# Singleton instance
noc_service = _init_noc_service()


# ========== Request/Response Models ==========

class NOCConfigUpdate(BaseModel):
    rotation_interval: Optional[int] = Field(None, ge=5, le=300, description="Panel rotation interval in seconds")
    refresh_interval: Optional[int] = Field(None, ge=10, le=600, description="Data refresh interval in seconds")
    panels: Optional[List[str]] = Field(None, description="List of panels to display")
    theme: Optional[str] = Field(None, description="Display theme (dark/light)")
    show_clock: Optional[bool] = Field(None, description="Show real-time clock in header")
    alert_sound: Optional[bool] = Field(None, description="Enable alert sound notifications")
    defcon_flash: Optional[bool] = Field(None, description="Flash display on DEFCON change")


class EndpointsSummary(BaseModel):
    total: int = 0
    online: int = 0
    offline: int = 0
    warning: int = 0
    maintenance: int = 0


class AlertsSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    recent_alerts: List[Dict[str, Any]] = []


class IncidentsSummary(BaseModel):
    active: int = 0
    contained: int = 0
    resolved_today: int = 0
    defcon_level: int = 5


class TicketsSummary(BaseModel):
    open: int = 0
    sla_compliant: int = 0
    sla_breached: int = 0
    avg_resolution: float = 0


class SelfHealingSummary(BaseModel):
    total_today: int = 0
    auto_resolved: int = 0
    escalated: int = 0
    success_rate: float = 100.0


class PatchesSummary(BaseModel):
    pending: int = 0
    installed_today: int = 0
    failed: int = 0


class NetworkSummary(BaseModel):
    total_devices: int = 0
    devices_by_type: Dict[str, int] = {}
    devices_by_status: Dict[str, int] = {}


class SystemHealth(BaseModel):
    api_latency_ms: float = 0
    uptime_seconds: int = 0
    last_backup: str = ""


class NOCDashboardResponse(BaseModel):
    timestamp: str
    endpoints_summary: EndpointsSummary
    alerts_summary: AlertsSummary
    incidents_summary: IncidentsSummary
    tickets_summary: TicketsSummary
    self_healing_summary: SelfHealingSummary
    patches_summary: PatchesSummary
    network_summary: NetworkSummary
    system_health: SystemHealth


# ========== Routes ==========

@router.get("/dashboard", response_model=NOCDashboardResponse)
async def get_noc_dashboard():
    """
    Aggregated NOC dashboard data from all MSP services in one payload.
    Cached for 10 seconds to reduce service load.
    """
    try:
        data = noc_service.get_dashboard_data()
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NOC aggregation failed: {str(e)}")


@router.get("/alerts/stream")
async def get_alert_stream():
    """
    SSE (Server-Sent Events) endpoint for real-time alert push.
    Streams recent alerts as they arrive.
    """
    import asyncio
    import json

    async def event_generator():
        """Yield SSE events with latest alerts."""
        while True:
            try:
                alerts = noc_service.get_alert_stream()
                data = json.dumps({"alerts": alerts, "timestamp": str(datetime.utcnow())})
                yield f"data: {data}\n\n"
                await asyncio.sleep(5)
            except Exception as e:
                error_data = json.dumps({"error": str(e)})
                yield f"data: {error_data}\n\n"
                await asyncio.sleep(10)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/config")
async def get_noc_config():
    """Get current NOC display configuration."""
    return noc_service.get_config()


@router.put("/config")
async def update_noc_config(config: NOCConfigUpdate):
    """Update NOC display configuration."""
    updates = config.dict(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No configuration fields provided")
    return noc_service.update_config(updates)
