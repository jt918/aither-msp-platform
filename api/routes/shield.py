"""
Aither Shield Consumer Security API

REST API for mobile and desktop apps.
Endpoints: ~50 covering devices, scanning, threats, firewall, VPN, dark web monitoring
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Header
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr
from datetime import datetime
from sqlalchemy.orm import Session

# Import the service
from services.shield import ShieldService
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

router = APIRouter(prefix="/api/v1/shield", tags=["Aither Shield"])


def _get_shield_service(db: Session = Depends(get_sync_db)) -> ShieldService:
    """Create a ShieldService with a live DB session per request."""
    return ShieldService(db=db)


# Keep a no-db fallback for the plan endpoints that don't need auth/session
_static_shield_service = ShieldService()


# ==================== REQUEST MODELS ====================

class UserCreateRequest(BaseModel):
    email: EmailStr
    password_hash: str
    name: Optional[str] = None
    plan_slug: str = "mobile-free"


class UserUpgradeRequest(BaseModel):
    plan_slug: str
    billing_cycle: str = "yearly"


class DeviceRegisterRequest(BaseModel):
    device_type: str  # 'iphone', 'android', 'windows', 'mac'
    device_name: Optional[str] = None
    device_id: str
    os_version: Optional[str] = None
    app_version: str
    push_token: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None


class ScanRequest(BaseModel):
    scan_type: str  # 'quick', 'full', 'custom'
    custom_paths: Optional[List[str]] = None


class ScanProgressRequest(BaseModel):
    files_scanned: int
    threats: Optional[List[Dict[str, Any]]] = None


class ScanCompleteRequest(BaseModel):
    files_scanned: int
    threats_found: int
    threats_resolved: int
    duration_seconds: int
    results: Optional[Dict[str, Any]] = None


class FileCheckRequest(BaseModel):
    file_hash: str
    file_path: Optional[str] = None


class URLCheckRequest(BaseModel):
    url: str


class ThreatReportRequest(BaseModel):
    threat_type: str
    threat_name: str
    severity: str
    source_type: str
    source_path: Optional[str] = None
    source_url: Optional[str] = None
    hash: Optional[str] = None
    detection_engine: str = "signature"
    action_taken: str = "quarantined"


class FirewallRuleRequest(BaseModel):
    name: str
    description: Optional[str] = None
    rule_type: str  # 'allow', 'block'
    direction: str  # 'inbound', 'outbound', 'both'
    protocol: str = "any"
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    remote_ip: Optional[str] = None
    application_path: Optional[str] = None


class FirewallRuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rule_type: Optional[str] = None
    direction: Optional[str] = None
    is_enabled: Optional[bool] = None


class FirewallEventRequest(BaseModel):
    rule_id: Optional[str] = None
    action: str  # 'allowed', 'blocked'
    threat_name: Optional[str] = None
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None


class VPNConnectRequest(BaseModel):
    server_id: str


class VPNUsageRequest(BaseModel):
    bytes_sent: int
    bytes_received: int


# ==================== SUBSCRIPTION PLANS ====================

@router.get("/plans")
async def get_plans(platform: Optional[str] = None):
    """Get available subscription plans."""
    return _static_shield_service.get_plans(platform)


@router.get("/plans/{slug}")
async def get_plan_by_slug(slug: str):
    """Get plan by slug."""
    plan = _static_shield_service.get_plan_by_slug(slug)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return plan


# ==================== USERS ====================

@router.post("/users")
async def create_user(request: UserCreateRequest, current_user: dict = Depends(require_admin),
                      shield_service: ShieldService = Depends(_get_shield_service)):
    """Create a new shield user."""
    result = shield_service.create_user(
        email=request.email,
        password_hash=request.password_hash,
        name=request.name,
        plan_slug=request.plan_slug
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/users/{user_id}")
async def get_user(user_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get user details."""
    user = shield_service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/users/{user_id}/subscription")
async def verify_subscription(user_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Verify user's subscription status."""
    return shield_service.verify_subscription(user_id)


@router.post("/users/{user_id}/upgrade")
async def upgrade_subscription(user_id: str, request: UserUpgradeRequest, current_user: dict = Depends(require_admin),
                                shield_service: ShieldService = Depends(_get_shield_service)):
    """Upgrade user subscription."""
    result = shield_service.upgrade_subscription(
        user_id=user_id,
        plan_slug=request.plan_slug,
        billing_cycle=request.billing_cycle
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/users/{user_id}/dashboard")
async def get_dashboard(user_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get dashboard statistics for user."""
    result = shield_service.get_dashboard_stats(user_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/users/{user_id}/threats/stats")
async def get_user_threat_stats(user_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get threat statistics for user."""
    return shield_service.get_user_threat_stats(user_id)


# ==================== DEVICES ====================

@router.post("/users/{user_id}/devices")
async def register_device(user_id: str, request: DeviceRegisterRequest, current_user: dict = Depends(require_admin),
                           shield_service: ShieldService = Depends(_get_shield_service)):
    """Register a new device for protection."""
    # Service expects "type" and "name" keys; translate from request schema
    info = request.dict()
    info["type"] = info.get("device_type")
    info["name"] = info.get("device_name") or "Test Device"
    result = shield_service.register_device(user_id, info)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/users/{user_id}/devices")
async def get_user_devices(user_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get all devices for a user."""
    return shield_service.get_user_devices(user_id)


@router.get("/devices/{device_id}/status")
async def get_device_status(device_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get current protection status for a device."""
    result = shield_service.get_device_status(device_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/devices/{device_id}/heartbeat")
async def device_heartbeat(device_id: str, current_user: dict = Depends(require_admin),
                            shield_service: ShieldService = Depends(_get_shield_service)):
    """Device heartbeat - update last seen."""
    result = shield_service.device_heartbeat(device_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.delete("/devices/{device_id}")
async def remove_device(device_id: str, current_user: dict = Depends(require_admin),
                         shield_service: ShieldService = Depends(_get_shield_service)):
    """Remove a device from protection."""
    result = shield_service.remove_device(device_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ==================== SCANNING ====================

@router.post("/devices/{device_id}/scan")
async def start_scan(device_id: str, request: ScanRequest, current_user: dict = Depends(require_admin),
                      shield_service: ShieldService = Depends(_get_shield_service)):
    """Start a security scan."""
    result = shield_service.start_scan(
        device_id=device_id,
        scan_type=request.scan_type,
        custom_paths=request.custom_paths
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/scans/{scan_id}/progress")
async def report_scan_progress(scan_id: str, request: ScanProgressRequest, current_user: dict = Depends(require_admin),
                                shield_service: ShieldService = Depends(_get_shield_service)):
    """Report scan progress from device."""
    result = shield_service.report_scan_progress(scan_id, request.dict())
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/scans/{scan_id}/complete")
async def complete_scan(scan_id: str, request: ScanCompleteRequest, current_user: dict = Depends(require_admin),
                         shield_service: ShieldService = Depends(_get_shield_service)):
    """Mark scan as complete."""
    result = shield_service.complete_scan(scan_id, request.dict())
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.get("/devices/{device_id}/scans")
async def get_scan_history(device_id: str, limit: int = Query(default=10, le=100),
                            shield_service: ShieldService = Depends(_get_shield_service)):
    """Get scan history for device."""
    return shield_service.get_scan_history(device_id, limit)


# ==================== REAL-TIME PROTECTION ====================

@router.post("/devices/{device_id}/check/file")
async def check_file(device_id: str, request: FileCheckRequest, current_user: dict = Depends(require_admin),
                      shield_service: ShieldService = Depends(_get_shield_service)):
    """Real-time file check against threat database."""
    return shield_service.check_file(
        device_id=device_id,
        file_hash=request.file_hash,
        file_path=request.file_path
    )


@router.post("/devices/{device_id}/check/url")
async def check_url(device_id: str, request: URLCheckRequest, current_user: dict = Depends(require_admin),
                     shield_service: ShieldService = Depends(_get_shield_service)):
    """Check if URL is safe."""
    return shield_service.check_url(device_id, request.url)


@router.post("/devices/{device_id}/threat")
async def report_threat(device_id: str, request: ThreatReportRequest, current_user: dict = Depends(require_admin),
                         shield_service: ShieldService = Depends(_get_shield_service)):
    """Report a detected threat from device."""
    result = shield_service.report_threat(device_id, request.dict())
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/devices/{device_id}/threats")
async def get_threat_history(device_id: str, limit: int = Query(default=50, le=200),
                              shield_service: ShieldService = Depends(_get_shield_service)):
    """Get threat history for device."""
    return shield_service.get_threat_history(device_id, limit)


# ==================== FIREWALL (Desktop) ====================

@router.get("/devices/{device_id}/firewall/rules")
async def get_firewall_rules(device_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get firewall rules for device."""
    return shield_service.get_firewall_rules(device_id)


@router.post("/devices/{device_id}/firewall/rules")
async def create_firewall_rule(device_id: str, request: FirewallRuleRequest, current_user: dict = Depends(require_admin),
                                shield_service: ShieldService = Depends(_get_shield_service)):
    """Create new firewall rule."""
    result = shield_service.create_firewall_rule(device_id, request.dict())
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.put("/firewall/rules/{rule_id}")
async def update_firewall_rule(rule_id: str, request: FirewallRuleUpdateRequest, current_user: dict = Depends(require_admin),
                                shield_service: ShieldService = Depends(_get_shield_service)):
    """Update a firewall rule."""
    result = shield_service.update_firewall_rule(rule_id, request.dict(exclude_none=True))
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.put("/firewall/rules/{rule_id}/toggle")
async def toggle_firewall_rule(rule_id: str, enabled: bool = Query(...), current_user: dict = Depends(require_admin),
                                shield_service: ShieldService = Depends(_get_shield_service)):
    """Enable/disable firewall rule."""
    result = shield_service.toggle_firewall_rule(rule_id, enabled)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.delete("/firewall/rules/{rule_id}")
async def delete_firewall_rule(rule_id: str, current_user: dict = Depends(require_admin),
                                shield_service: ShieldService = Depends(_get_shield_service)):
    """Delete a firewall rule."""
    result = shield_service.delete_firewall_rule(rule_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/devices/{device_id}/firewall/event")
async def log_firewall_event(device_id: str, request: FirewallEventRequest, current_user: dict = Depends(require_admin),
                              shield_service: ShieldService = Depends(_get_shield_service)):
    """Log firewall event from device."""
    return shield_service.log_firewall_event(device_id, request.dict())


# ==================== VPN ====================

@router.get("/users/{user_id}/vpn/servers")
async def get_vpn_servers(user_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get available VPN servers."""
    result = shield_service.get_vpn_servers(user_id)
    if "error" in result and not result.get("servers"):
        raise HTTPException(status_code=403, detail=result["error"])
    return result


@router.post("/devices/{device_id}/vpn/connect")
async def connect_vpn(device_id: str, request: VPNConnectRequest, current_user: dict = Depends(require_admin),
                       shield_service: ShieldService = Depends(_get_shield_service)):
    """Connect to VPN server."""
    result = shield_service.connect_vpn(device_id, request.server_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/devices/{device_id}/vpn/disconnect")
async def disconnect_vpn(device_id: str, current_user: dict = Depends(require_admin),
                          shield_service: ShieldService = Depends(_get_shield_service)):
    """Disconnect VPN."""
    result = shield_service.disconnect_vpn(device_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/devices/{device_id}/vpn/status")
async def get_vpn_status(device_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get current VPN status for device."""
    return shield_service.get_vpn_status(device_id)


@router.post("/vpn/sessions/{session_id}/usage")
async def report_vpn_usage(session_id: str, request: VPNUsageRequest, current_user: dict = Depends(require_admin),
                            shield_service: ShieldService = Depends(_get_shield_service)):
    """Report VPN bandwidth usage."""
    result = shield_service.report_vpn_usage(
        session_id=session_id,
        bytes_sent=request.bytes_sent,
        bytes_received=request.bytes_received
    )
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ==================== DARK WEB MONITORING ====================

@router.get("/users/{user_id}/darkweb/scan")
async def check_dark_web(user_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Check for dark web exposure."""
    result = shield_service.check_dark_web(user_id)
    if "error" in result:
        raise HTTPException(status_code=403, detail=result["error"])
    return result


@router.get("/users/{user_id}/darkweb/alerts")
async def get_dark_web_alerts(user_id: str, shield_service: ShieldService = Depends(_get_shield_service)):
    """Get dark web alerts for user."""
    return shield_service.get_dark_web_alerts(user_id)


@router.post("/darkweb/alerts/{alert_id}/acknowledge")
async def acknowledge_dark_web_alert(alert_id: str, current_user: dict = Depends(require_admin),
                                      shield_service: ShieldService = Depends(_get_shield_service)):
    """Acknowledge a dark web alert."""
    result = shield_service.acknowledge_dark_web_alert(alert_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@router.post("/darkweb/alerts/{alert_id}/resolve")
async def resolve_dark_web_alert(alert_id: str, current_user: dict = Depends(require_admin),
                                  shield_service: ShieldService = Depends(_get_shield_service)):
    """Mark a dark web alert as resolved."""
    result = shield_service.resolve_dark_web_alert(alert_id)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


# ==================== SIGNATURES ====================

@router.get("/signatures/version")
async def get_signature_version():
    """Get latest threat signature version."""
    return _static_shield_service.get_signature_version()


@router.get("/signatures/update")
async def get_signature_update(current_version: str = Query(...)):
    """Get signature updates since version."""
    return _static_shield_service.get_signature_updates(current_version)
