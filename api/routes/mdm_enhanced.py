"""
AITHER Platform - Enhanced MDM (Mobile Device Management) API Routes

Full MDM capabilities: device enrollment, BYOD policy enforcement,
app management, compliance evaluation, remote actions, and geofencing.

Persistence: DB-backed via MDMService with in-memory fallback.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from sqlalchemy.orm import Session
from core.database import get_sync_db
from services.msp.mdm_service import MDMService
from middleware.auth import get_current_user, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mdm", tags=["MDM Enhanced"])

# Singleton service (in-memory; DB session injected per request)
_service = MDMService()


def _svc(db: Session = Depends(get_sync_db)) -> MDMService:
    """Return service instance with DB session attached."""
    _service.db = db
    return _service


# ── Request Models ────────────────────────────────────────────────────

class EnrollDeviceRequest(BaseModel):
    device_name: str = Field(..., min_length=1, max_length=200)
    user_id: str = Field(default="")
    client_id: str = Field(default="")
    platform: str = Field(default="android")
    os_version: str = Field(default="")
    model: str = Field(default="")
    serial_number: str = Field(default="")
    imei: str = Field(default="")


class UpdateDeviceRequest(BaseModel):
    device_name: Optional[str] = None
    os_version: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    imei: Optional[str] = None
    battery_level: Optional[int] = None
    storage_used_pct: Optional[float] = None
    roaming: Optional[bool] = None


class CheckinRequest(BaseModel):
    battery_level: Optional[int] = None
    storage_used_pct: Optional[float] = None
    encryption_enabled: Optional[bool] = None
    passcode_set: Optional[bool] = None
    jailbroken: Optional[bool] = None
    roaming: Optional[bool] = None
    os_version: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class PolicyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")
    platform: str = Field(default="all")
    policy_type: str = Field(default="compliance")
    settings: Dict[str, Any] = Field(default_factory=dict)
    is_mandatory: bool = False
    assigned_groups: List[str] = Field(default_factory=list)


class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    platform: Optional[str] = None
    policy_type: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None
    is_mandatory: Optional[bool] = None
    assigned_groups: Optional[List[str]] = None


class AppRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    bundle_id: str = Field(default="")
    platform: str = Field(default="all")
    version: str = Field(default="1.0.0")
    is_required: bool = False
    is_blocked: bool = False
    category: str = Field(default="general")


class ComplianceRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")
    check_type: str = Field(...)
    expected_value: str = Field(default="")
    severity: str = Field(default="warning")
    auto_remediate: bool = False
    remediation_action: str = Field(default="")


class DeviceActionRequest(BaseModel):
    action_type: str = Field(...)
    params: Dict[str, Any] = Field(default_factory=dict)


class GeofenceRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    latitude: float
    longitude: float
    radius_meters: float = Field(default=500.0, ge=10.0)
    action_on_exit: str = Field(default="alert")
    assigned_devices: List[str] = Field(default_factory=list)


class GeofenceUpdateRequest(BaseModel):
    name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    radius_meters: Optional[float] = None
    action_on_exit: Optional[str] = None
    assigned_devices: Optional[List[str]] = None


class LocationCheckRequest(BaseModel):
    latitude: float
    longitude: float


# ── Device Routes ─────────────────────────────────────────────────────

@router.post("/devices")
def enroll_device(
    request: EnrollDeviceRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Enroll a new device into MDM management."""
    result = svc.enroll_device(request.model_dump())
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/devices")
def list_devices(
    platform: Optional[str] = None,
    enrollment_status: Optional[str] = None,
    compliance_status: Optional[str] = None,
    client_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """List all managed devices with optional filters."""
    return svc.list_devices(
        platform=platform,
        enrollment_status=enrollment_status,
        compliance_status=compliance_status,
        client_id=client_id,
        limit=limit,
    )


@router.get("/devices/{device_id}")
def get_device(
    device_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Get details for a specific device."""
    result = svc.get_device(device_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.put("/devices/{device_id}")
def update_device(
    device_id: str,
    request: UpdateDeviceRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Update device information."""
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    result = svc.update_device_info(device_id, updates)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.delete("/devices/{device_id}")
def unenroll_device(
    device_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Unenroll a device from MDM management."""
    result = svc.unenroll_device(device_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/devices/{device_id}/checkin")
def device_checkin(
    device_id: str,
    request: CheckinRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Process a device check-in with updated telemetry."""
    data = {k: v for k, v in request.model_dump().items() if v is not None}
    result = svc.checkin(device_id, data)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ── BYOD Routes ───────────────────────────────────────────────────────

@router.post("/devices/{device_id}/byod/separate")
def separate_work_personal(
    device_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Enable work/personal separation on a BYOD device."""
    result = svc.separate_work_personal(device_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.get("/devices/{device_id}/byod/status")
def get_work_profile_status(
    device_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Get BYOD work profile status."""
    result = svc.get_work_profile_status(device_id)
    if not result.get("success", True):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ── Policy Routes ─────────────────────────────────────────────────────

@router.post("/policies")
def create_policy(
    request: PolicyRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Create a new device policy."""
    result = svc.create_policy(request.model_dump())
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/policies")
def list_policies(
    platform: Optional[str] = None,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """List all device policies."""
    return svc.list_policies(platform=platform)


@router.put("/policies/{policy_id}")
def update_policy(
    policy_id: str,
    request: PolicyUpdateRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Update an existing policy."""
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    result = svc.update_policy(policy_id, updates)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.delete("/policies/{policy_id}")
def delete_policy(
    policy_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Delete a policy."""
    result = svc.delete_policy(policy_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/policies/{policy_id}/assign")
def assign_policy_to_group(
    policy_id: str,
    group: str = Query(...),
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Assign a policy to a device group."""
    result = svc.assign_policy_to_group(policy_id, group)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.get("/devices/{device_id}/effective-policies")
def get_effective_policies(
    device_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Get all effective policies for a device."""
    result = svc.get_effective_policies(device_id)
    if not result.get("device_id"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ── App Management Routes ─────────────────────────────────────────────

@router.post("/apps")
def register_app(
    request: AppRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Register an app in the MDM catalog."""
    result = svc.register_app(request.model_dump())
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/apps")
def list_apps(
    platform: Optional[str] = None,
    category: Optional[str] = None,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """List all managed apps."""
    return svc.list_apps(platform=platform, category=category)


@router.post("/apps/{app_id}/block")
def block_app(
    app_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Block an app from managed devices."""
    result = svc.block_app(app_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/apps/{app_id}/require")
def require_app(
    app_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Mark an app as required on all managed devices."""
    result = svc.require_app(app_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.get("/devices/{device_id}/apps")
def get_device_app_status(
    device_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Get app install status for a device."""
    result = svc.get_app_install_status(device_id)
    if not result.get("device_id"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ── Compliance Routes ─────────────────────────────────────────────────

@router.post("/compliance/rules")
def create_compliance_rule(
    request: ComplianceRuleRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Create a new compliance rule."""
    result = svc.create_compliance_rule(request.model_dump())
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/compliance/{device_id}")
def evaluate_device_compliance(
    device_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Evaluate compliance for a specific device."""
    result = svc.evaluate_compliance(device_id)
    if not result.get("device_id"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/compliance/evaluate-all")
def evaluate_all_compliance(
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Evaluate compliance for all enrolled devices."""
    return svc.evaluate_all_compliance()


@router.get("/compliance/report")
def get_compliance_report(
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Generate aggregate compliance report."""
    return svc.get_compliance_report()


# ── Device Action Routes ──────────────────────────────────────────────

@router.post("/devices/{device_id}/actions")
def send_device_action(
    device_id: str,
    request: DeviceActionRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Send a remote action to a device (lock/wipe/ring/etc)."""
    result = svc.send_action(device_id, request.action_type, request.params)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/actions")
def list_actions(
    device_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """List device actions."""
    return svc.list_actions(device_id=device_id, status=status, limit=limit)


@router.get("/actions/{action_id}")
def get_action_status(
    action_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Get status of a specific action."""
    result = svc.get_action_status(action_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ── Geofence Routes ──────────────────────────────────────────────────

@router.post("/geofences")
def create_geofence(
    request: GeofenceRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Create a geofence zone."""
    result = svc.create_zone(request.model_dump())
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/geofences")
def list_geofences(
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """List all geofence zones."""
    return svc.list_zones()


@router.put("/geofences/{zone_id}")
def update_geofence(
    zone_id: str,
    request: GeofenceUpdateRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Update a geofence zone."""
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    result = svc.update_zone(zone_id, updates)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.delete("/geofences/{zone_id}")
def delete_geofence(
    zone_id: str,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(require_admin),
):
    """Delete a geofence zone."""
    result = svc.delete_zone(zone_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/devices/{device_id}/location-check")
def check_device_location(
    device_id: str,
    request: LocationCheckRequest,
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Check if a device is within assigned geofence zones."""
    result = svc.check_device_location(device_id, request.latitude, request.longitude)
    if not result.get("device_id"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ── Dashboard ─────────────────────────────────────────────────────────

@router.get("/dashboard")
def get_mdm_dashboard(
    svc: MDMService = Depends(_svc),
    current_user: dict = Depends(get_current_user),
):
    """Get MDM dashboard overview with key metrics."""
    return svc.get_dashboard()
