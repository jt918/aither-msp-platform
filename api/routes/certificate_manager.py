"""
API Routes for Certificate Lifecycle Management
Tracks SSL/TLS certificates, alerts on expiration, manages renewal workflows.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.certificate_manager import (
    CertificateManagerService,
    CertType,
    CertStatus,
    AlertType,
    AlertSeverity,
    ScanGrade,
    RenewalStatus,
)

router = APIRouter(prefix="/certificate-manager", tags=["Certificate Manager"])


def _init_service() -> CertificateManagerService:
    """Initialize CertificateManagerService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return CertificateManagerService(db=db)
    except Exception:
        return CertificateManagerService()


service = _init_service()


# ========== Request/Response Models ==========

class CertificateCreate(BaseModel):
    common_name: str
    client_id: str = ""
    san_names: List[str] = []
    issuer: str = ""
    serial_number: str = ""
    fingerprint_sha256: str = ""
    key_algorithm: str = "RSA"
    key_size: int = 2048
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    cert_type: str = "dv"
    installed_on: List[str] = []
    auto_renew: bool = False
    renewal_provider: str = "manual"


class CertificateUpdate(BaseModel):
    common_name: Optional[str] = None
    client_id: Optional[str] = None
    san_names: Optional[List[str]] = None
    issuer: Optional[str] = None
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    cert_type: Optional[str] = None
    installed_on: Optional[List[str]] = None
    auto_renew: Optional[bool] = None
    renewal_provider: Optional[str] = None


class ScanRequest(BaseModel):
    host: str
    port: int = 443


class NetworkScanRequest(BaseModel):
    client_id: str
    hosts: List[str]
    port: int = 443


class RenewalRequestCreate(BaseModel):
    cert_id: str
    requested_by: str = "api"


class RenewalComplete(BaseModel):
    common_name: str
    client_id: str = ""
    san_names: List[str] = []
    issuer: str = ""
    key_algorithm: str = "RSA"
    key_size: int = 2048
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    cert_type: str = "dv"
    installed_on: List[str] = []
    auto_renew: bool = False
    renewal_provider: str = "manual"


# ========== Helper converters ==========

def _parse_dt(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val)
    except Exception:
        return None


def cert_to_dict(c) -> dict:
    return {
        "cert_id": c.cert_id,
        "client_id": c.client_id,
        "common_name": c.common_name,
        "san_names": c.san_names,
        "issuer": c.issuer,
        "serial_number": c.serial_number,
        "fingerprint_sha256": c.fingerprint_sha256,
        "key_algorithm": c.key_algorithm,
        "key_size": c.key_size,
        "valid_from": c.valid_from.isoformat() if c.valid_from else None,
        "valid_to": c.valid_to.isoformat() if c.valid_to else None,
        "days_until_expiry": c.days_until_expiry,
        "status": c.status.value if hasattr(c.status, "value") else c.status,
        "cert_type": c.cert_type.value if hasattr(c.cert_type, "value") else c.cert_type,
        "installed_on": c.installed_on,
        "auto_renew": c.auto_renew,
        "renewal_provider": c.renewal_provider,
        "last_checked_at": c.last_checked_at.isoformat() if c.last_checked_at else None,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def alert_to_dict(a) -> dict:
    return {
        "alert_id": a.alert_id,
        "cert_id": a.cert_id,
        "alert_type": a.alert_type.value if hasattr(a.alert_type, "value") else a.alert_type,
        "severity": a.severity.value if hasattr(a.severity, "value") else a.severity,
        "message": a.message,
        "is_acknowledged": a.is_acknowledged,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def renewal_to_dict(r) -> dict:
    return {
        "renewal_id": r.renewal_id,
        "cert_id": r.cert_id,
        "status": r.status.value if hasattr(r.status, "value") else r.status,
        "requested_by": r.requested_by,
        "requested_at": r.requested_at.isoformat() if r.requested_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "new_cert_id": r.new_cert_id,
        "error_message": r.error_message,
    }


def scan_to_dict(s) -> dict:
    return {
        "scan_id": s.scan_id,
        "target_host": s.target_host,
        "port": s.port,
        "scanned_at": s.scanned_at.isoformat() if s.scanned_at else None,
        "cert_found": s.cert_found,
        "cert_id": s.cert_id,
        "chain_valid": s.chain_valid,
        "protocol_version": s.protocol_version,
        "cipher_suite": s.cipher_suite,
        "grade": s.grade,
        "issues": s.issues,
    }


# ========== Certificate CRUD ==========

@router.get("/certificates")
async def list_certificates(
    client_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    cert_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    """List all tracked certificates with optional filters."""
    certs = service.list_certificates(
        client_id=client_id, status=status, cert_type=cert_type,
        limit=limit, offset=offset,
    )
    return {"certificates": [cert_to_dict(c) for c in certs], "count": len(certs)}


@router.get("/certificates/{cert_id}")
async def get_certificate(cert_id: str, current_user: dict = Depends(get_current_user)):
    """Get a single certificate by ID."""
    cert = service.get_certificate(cert_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert_to_dict(cert)


@router.post("/certificates", status_code=201)
async def add_certificate(data: CertificateCreate, current_user: dict = Depends(require_admin)):
    """Add a certificate to lifecycle tracking."""
    cert = service.add_certificate(
        common_name=data.common_name,
        client_id=data.client_id,
        san_names=data.san_names,
        issuer=data.issuer,
        serial_number=data.serial_number,
        fingerprint_sha256=data.fingerprint_sha256,
        key_algorithm=data.key_algorithm,
        key_size=data.key_size,
        valid_from=_parse_dt(data.valid_from),
        valid_to=_parse_dt(data.valid_to),
        cert_type=data.cert_type,
        installed_on=data.installed_on,
        auto_renew=data.auto_renew,
        renewal_provider=data.renewal_provider,
    )
    return cert_to_dict(cert)


@router.put("/certificates/{cert_id}")
async def update_certificate(
    cert_id: str, data: CertificateUpdate, current_user: dict = Depends(require_admin),
):
    """Update certificate tracking data."""
    updates = {k: v for k, v in data.dict(exclude_unset=True).items() if v is not None}
    cert = service.update_certificate(cert_id, updates)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert_to_dict(cert)


@router.delete("/certificates/{cert_id}")
async def delete_certificate(cert_id: str, current_user: dict = Depends(require_admin)):
    """Remove a certificate from tracking."""
    deleted = service.delete_certificate(cert_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {"deleted": True, "cert_id": cert_id}


# ========== Discovery / Scanning ==========

@router.post("/scan")
async def scan_host(data: ScanRequest, current_user: dict = Depends(require_admin)):
    """Scan a single host for SSL/TLS certificate info and grade the config."""
    scan = service.scan_host(data.host, data.port)
    return scan_to_dict(scan)


@router.post("/scan/network")
async def scan_network(data: NetworkScanRequest, current_user: dict = Depends(require_admin)):
    """Bulk scan multiple hosts for a given client."""
    scans = service.scan_network(data.client_id, data.hosts, data.port)
    return {"scans": [scan_to_dict(s) for s in scans], "count": len(scans)}


@router.get("/scans")
async def list_scans(
    host: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
):
    """List scan results."""
    scans = service.get_scans(host=host, limit=limit)
    return {"scans": [scan_to_dict(s) for s in scans], "count": len(scans)}


# ========== Expiration Tracking ==========

@router.post("/check-expirations")
async def check_expirations(current_user: dict = Depends(require_admin)):
    """Run expiration check across all certificates and create alerts."""
    alerts = service.check_expirations()
    return {"alerts_created": len(alerts), "alerts": [alert_to_dict(a) for a in alerts]}


@router.get("/expiring")
async def get_expiring_certificates(
    days: int = Query(30, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
):
    """Get certificates expiring within the specified number of days."""
    certs = service.get_expiring_certificates(days_ahead=days)
    return {"certificates": [cert_to_dict(c) for c in certs], "count": len(certs)}


# ========== Renewal ==========

@router.post("/renewals")
async def request_renewal(data: RenewalRequestCreate, current_user: dict = Depends(require_admin)):
    """Request renewal of a certificate."""
    renewal = service.request_renewal(data.cert_id, requested_by=data.requested_by)
    if not renewal:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return renewal_to_dict(renewal)


@router.post("/renewals/{renewal_id}/complete")
async def complete_renewal(
    renewal_id: str, data: RenewalComplete, current_user: dict = Depends(require_admin),
):
    """Complete a renewal request with new certificate data."""
    new_cert_data = {
        "common_name": data.common_name,
        "client_id": data.client_id,
        "san_names": data.san_names,
        "issuer": data.issuer,
        "key_algorithm": data.key_algorithm,
        "key_size": data.key_size,
        "valid_from": _parse_dt(data.valid_from),
        "valid_to": _parse_dt(data.valid_to),
        "cert_type": data.cert_type,
        "installed_on": data.installed_on,
        "auto_renew": data.auto_renew,
        "renewal_provider": data.renewal_provider,
    }
    renewal = service.complete_renewal(renewal_id, new_cert_data)
    if not renewal:
        raise HTTPException(status_code=404, detail="Renewal request not found")
    return renewal_to_dict(renewal)


@router.get("/renewals")
async def list_renewals(
    cert_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
):
    """List renewal requests."""
    renewals = service.get_renewals(cert_id=cert_id, status=status, limit=limit)
    return {"renewals": [renewal_to_dict(r) for r in renewals], "count": len(renewals)}


# ========== Alerts ==========

@router.get("/alerts")
async def list_alerts(
    cert_id: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
):
    """List certificate alerts."""
    alerts = service.get_alerts(
        cert_id=cert_id, alert_type=alert_type,
        acknowledged=acknowledged, limit=limit,
    )
    return {"alerts": [alert_to_dict(a) for a in alerts], "count": len(alerts)}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, current_user: dict = Depends(require_admin)):
    """Acknowledge a certificate alert."""
    alert = service.acknowledge_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert)


# ========== Analytics & Dashboard ==========

@router.get("/analytics/timeline")
async def expiration_timeline(
    months: int = Query(12, ge=1, le=36),
    current_user: dict = Depends(get_current_user),
):
    """Get certificate expiration timeline (certs per month)."""
    timeline = service.get_expiration_timeline(months=months)
    return {"timeline": timeline}


@router.get("/analytics/inventory")
async def cert_inventory(
    client_id: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    """Get certificate inventory breakdown."""
    inventory = service.get_cert_inventory(client_id=client_id)
    return inventory


@router.get("/analytics/weak")
async def weak_certificates(current_user: dict = Depends(get_current_user)):
    """Find certificates with weak keys, SHA1, or self-signed in production."""
    weak = service.get_weak_certificates()
    return {"weak_certificates": weak, "count": len(weak)}


@router.get("/analytics/compliance")
async def compliance_status(current_user: dict = Depends(get_current_user)):
    """Check PCI-DSS and HIPAA certificate compliance."""
    return service.get_compliance_status()


@router.get("/dashboard")
async def dashboard(current_user: dict = Depends(get_current_user)):
    """Certificate management dashboard summary."""
    return service.get_dashboard()
