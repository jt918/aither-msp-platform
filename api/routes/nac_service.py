"""
API Routes for Network Access Control (NAC) Service
Uses NACService for all operations
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

from core.database import get_sync_db

from services.msp.nac_service import (
    NACService,
    NetworkZone,
    PostureResult,
    AccessDecisionType,
    AntivirusStatus,
    GuestStatus,
    _policy_to_dict,
    _posture_to_dict,
    _guest_to_dict,
    _portal_to_dict,
    _blocked_to_dict,
)

router = APIRouter(prefix="/nac", tags=["NAC"])


def _init_nac_service() -> NACService:
    """Initialize NACService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return NACService(db=db)
    except Exception:
        return NACService()


# Initialize service with DB persistence
nac_service = _init_nac_service()


# ========== Request/Response Models ==========

class PostureRequirements(BaseModel):
    min_os_version: str = ""
    antivirus_required: bool = False
    firewall_required: bool = False
    encryption_required: bool = False
    patch_compliance_min_pct: float = 0.0
    approved_os: List[str] = []


class PolicyCreate(BaseModel):
    name: str
    client_id: str = ""
    description: str = ""
    posture_requirements: Optional[Dict[str, Any]] = None
    network_assignment: str = NetworkZone.CORPORATE.value
    vlan_id: int = 0
    priority: int = 100
    is_enabled: bool = True


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    posture_requirements: Optional[Dict[str, Any]] = None
    network_assignment: Optional[str] = None
    vlan_id: Optional[int] = None
    priority: Optional[int] = None
    is_enabled: Optional[bool] = None


class DeviceAssessRequest(BaseModel):
    device_id: Optional[str] = None
    mac_address: str = ""
    ip_address: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    antivirus_status: str = AntivirusStatus.UNKNOWN.value
    firewall_enabled: bool = False
    disk_encrypted: bool = False
    patch_compliance_pct: float = 0.0


class GuestRegisterRequest(BaseModel):
    name: str
    email: str = ""
    company: str = ""
    sponsor_email: str = ""
    mac_address: str = ""
    client_id: str = ""
    hours: int = 8


class CaptivePortalRequest(BaseModel):
    client_id: str
    branding: Optional[Dict[str, Any]] = None
    terms_of_use: str = ""
    require_registration: bool = True
    session_timeout_minutes: int = 480
    bandwidth_limit_mbps: float = 10.0


class BlockDeviceRequest(BaseModel):
    mac_address: str
    reason: str = ""
    blocked_by: str = "admin"


# ========== Policy Routes ==========

@router.post("/policies")
async def create_policy(data: PolicyCreate):
    """Create a new NAC policy."""
    kwargs = data.model_dump(exclude_none=True)
    name = kwargs.pop("name")
    client_id = kwargs.pop("client_id", "")
    policy = nac_service.create_policy(name=name, client_id=client_id, **kwargs)
    return _policy_to_dict(policy)


@router.get("/policies")
async def list_policies(
    client_id: str = Query("", description="Filter by client"),
    enabled_only: bool = Query(False, description="Only enabled policies"),
):
    """List NAC policies."""
    policies = nac_service.list_policies(client_id=client_id, enabled_only=enabled_only)
    return [_policy_to_dict(p) for p in policies]


@router.get("/policies/{policy_id}")
async def get_policy(policy_id: str):
    """Get a NAC policy by ID."""
    policy = nac_service.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _policy_to_dict(policy)


@router.put("/policies/{policy_id}")
async def update_policy(policy_id: str, data: PolicyUpdate):
    """Update a NAC policy."""
    kwargs = {k: v for k, v in data.model_dump().items() if v is not None}
    policy = nac_service.update_policy(policy_id, **kwargs)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _policy_to_dict(policy)


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str):
    """Delete a NAC policy."""
    if not nac_service.delete_policy(policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"status": "deleted", "policy_id": policy_id}


# ========== Device Posture Routes ==========

@router.post("/assess")
async def assess_device(data: DeviceAssessRequest):
    """Assess device posture and return access decision."""
    result = nac_service.assess_device_posture(data.model_dump())
    return result


@router.get("/postures")
async def list_postures(
    compliant: Optional[bool] = Query(None, description="Filter by compliance"),
    network: str = Query("", description="Filter by network zone"),
):
    """List device posture records."""
    postures = nac_service.list_postures(compliant=compliant, network=network)
    return [_posture_to_dict(p) for p in postures]


@router.get("/postures/{device_id}")
async def get_posture(device_id: str):
    """Get latest posture for a device."""
    posture = nac_service.get_posture(device_id)
    if not posture:
        raise HTTPException(status_code=404, detail="Device posture not found")
    return _posture_to_dict(posture)


@router.post("/postures/{device_id}/reassess")
async def reassess_device(device_id: str):
    """Re-assess a previously assessed device."""
    result = nac_service.reassess_device(device_id)
    if not result:
        raise HTTPException(status_code=404, detail="Device not found for reassessment")
    return result


# ========== Quarantine Routes ==========

@router.get("/quarantine")
async def get_quarantined():
    """Get all quarantined devices."""
    return nac_service.get_quarantined_devices()


@router.post("/quarantine/{device_id}/release")
async def release_quarantine(device_id: str, target_network: str = Query(NetworkZone.CORPORATE.value)):
    """Release a device from quarantine."""
    result = nac_service.release_from_quarantine(device_id, target_network=target_network)
    if not result:
        raise HTTPException(status_code=404, detail="Device not found in quarantine")
    return result


# ========== Blocked Devices Routes ==========

@router.post("/blocked")
async def block_device(data: BlockDeviceRequest):
    """Block a device by MAC address."""
    blocked = nac_service.block_device(
        mac_address=data.mac_address, reason=data.reason,
        blocked_by=data.blocked_by,
    )
    return _blocked_to_dict(blocked)


@router.get("/blocked")
async def get_blocked():
    """Get all blocked devices."""
    return nac_service.get_blocked_devices()


@router.delete("/blocked/{mac_address}")
async def unblock_device(mac_address: str):
    """Unblock a device by MAC address."""
    if not nac_service.unblock_device(mac_address):
        raise HTTPException(status_code=404, detail="Blocked device not found")
    return {"status": "unblocked", "mac_address": mac_address}


# ========== Guest Routes ==========

@router.post("/guests")
async def register_guest(data: GuestRegisterRequest):
    """Register a guest for network access."""
    guest = nac_service.register_guest(**data.model_dump())
    return _guest_to_dict(guest)


@router.get("/guests")
async def list_guests(
    client_id: str = Query("", description="Filter by client"),
    status: str = Query("", description="Filter by status"),
):
    """List guest registrations."""
    guests = nac_service.list_guests(client_id=client_id, status=status)
    return [_guest_to_dict(g) for g in guests]


@router.post("/guests/{guest_id}/approve")
async def approve_guest(guest_id: str):
    """Approve a guest registration."""
    guest = nac_service.approve_guest(guest_id)
    if not guest:
        raise HTTPException(status_code=404, detail="Guest not found")
    return _guest_to_dict(guest)


@router.post("/guests/{guest_id}/revoke")
async def revoke_guest(guest_id: str):
    """Revoke guest access."""
    guest = nac_service.revoke_guest(guest_id)
    if not guest:
        raise HTTPException(status_code=404, detail="Guest not found")
    return _guest_to_dict(guest)


# ========== Captive Portal Routes ==========

@router.post("/portal")
async def configure_portal(data: CaptivePortalRequest):
    """Configure captive portal for a client."""
    config = nac_service.configure_captive_portal(**data.model_dump())
    return _portal_to_dict(config)


@router.get("/portal/{client_id}")
async def get_portal(client_id: str):
    """Get captive portal configuration."""
    config = nac_service.get_portal_config(client_id)
    if not config:
        raise HTTPException(status_code=404, detail="Portal config not found")
    return _portal_to_dict(config)


# ========== Compliance & Dashboard Routes ==========

@router.get("/compliance")
async def compliance_report(client_id: str = Query("", description="Filter by client")):
    """Get compliance report."""
    return nac_service.get_compliance_report(client_id=client_id)


@router.get("/zones")
async def zone_distribution():
    """Get network zone distribution."""
    return nac_service.get_network_zone_distribution()


@router.get("/access-log")
async def access_log(
    device_id: str = Query("", description="Filter by device"),
    decision: str = Query("", description="Filter by decision type"),
    limit: int = Query(100, description="Max results"),
):
    """Get access decision log."""
    return nac_service.get_access_log(device_id=device_id, decision=decision, limit=limit)


@router.get("/dashboard")
async def dashboard():
    """Get NAC dashboard summary."""
    return nac_service.get_dashboard()
