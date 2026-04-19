"""
API Routes for IT Asset Lifecycle Management
Uses AssetLifecycleService for all operations with DB persistence
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.asset_lifecycle import (
    AssetLifecycleService,
    AssetCategory,
    LifecycleStatus,
    LicenseType,
    DepreciationMethod,
    DisposalMethod,
    _asset_to_dict,
    _license_to_dict,
    _maintenance_to_dict,
    _depreciation_to_dict,
    _request_to_dict,
    _disposal_to_dict,
)

router = APIRouter(prefix="/asset-lifecycle", tags=["Asset Lifecycle"])


def _init_service() -> AssetLifecycleService:
    """Initialize AssetLifecycleService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return AssetLifecycleService(db=db)
    except Exception:
        return AssetLifecycleService()


# Initialize service with DB persistence
_service = _init_service()


# ========== Request/Response Models ==========

class AssetCreate(BaseModel):
    name: str
    category: str = "hardware"
    asset_type: str = "laptop"
    client_id: str = ""
    asset_tag: str = ""
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    purchase_date: Optional[str] = None
    purchase_price: float = 0.0
    vendor: str = ""
    warranty_expires: Optional[str] = None
    assigned_to: Optional[str] = None
    location: str = ""
    department: str = ""
    notes: str = ""
    custom_fields: Dict[str, Any] = {}


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    asset_type: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    purchase_price: Optional[float] = None
    vendor: Optional[str] = None
    assigned_to: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None
    notes: Optional[str] = None
    custom_fields: Optional[Dict[str, Any]] = None


class DeployRequest(BaseModel):
    assigned_to: str = ""
    location: str = ""
    department: str = ""


class StoreRequest(BaseModel):
    location: str = ""


class MaintainRequest(BaseModel):
    notes: str = ""


class LicenseCreate(BaseModel):
    software_name: str
    asset_id: Optional[str] = None
    license_key: str = ""
    license_type: str = "per_seat"
    seats_purchased: int = 1
    renewal_date: Optional[str] = None
    annual_cost: float = 0.0
    vendor: str = ""


class MaintenanceCreate(BaseModel):
    maintenance_type: str = "repair"
    description: str = ""
    cost: float = 0.0
    performed_by: str = ""
    scheduled_date: Optional[str] = None
    next_maintenance: Optional[str] = None


class MaintenanceComplete(BaseModel):
    cost: Optional[float] = None


class DepreciationCreate(BaseModel):
    method: str = "straight_line"
    useful_life_years: int = 5
    salvage_value: float = 0.0


class RequestCreate(BaseModel):
    requester_name: str
    asset_type: str
    client_id: str = ""
    justification: str = ""
    quantity: int = 1
    estimated_cost: float = 0.0


class RequestApprove(BaseModel):
    approved_by: str = ""


class DisposalCreate(BaseModel):
    disposal_method: str = "recycle"
    disposal_date: Optional[str] = None
    certificate_of_destruction: str = ""
    data_wiped: bool = False
    wiped_method: str = ""
    proceeds: float = 0.0


# ========== Helper ==========

def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    """Parse ISO date string to datetime."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


# ========== Asset CRUD + Search ==========

@router.post("/assets")
def create_asset(data: AssetCreate, db: Session = Depends(get_sync_db)):
    """Create a new IT asset."""
    asset = _service.create_asset(
        name=data.name,
        category=data.category,
        asset_type=data.asset_type,
        client_id=data.client_id,
        asset_tag=data.asset_tag,
        manufacturer=data.manufacturer,
        model=data.model,
        serial_number=data.serial_number,
        purchase_date=_parse_dt(data.purchase_date),
        purchase_price=data.purchase_price,
        vendor=data.vendor,
        warranty_expires=_parse_dt(data.warranty_expires),
        assigned_to=data.assigned_to,
        location=data.location,
        department=data.department,
        notes=data.notes,
        custom_fields=data.custom_fields,
    )
    return _asset_to_dict(asset)


@router.get("/assets")
def list_assets(
    client_id: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    department: Optional[str] = None,
    db: Session = Depends(get_sync_db),
):
    """List all assets with optional filters."""
    assets = _service.list_assets(
        client_id=client_id,
        category=category,
        status=status,
        department=department,
    )
    return {"assets": [_asset_to_dict(a) for a in assets], "total": len(assets)}


@router.get("/assets/search")
def search_assets(q: str = Query(..., min_length=1), db: Session = Depends(get_sync_db)):
    """Search assets by name, serial number, asset tag, or manufacturer."""
    results = _service.search_assets(q)
    return {"assets": [_asset_to_dict(a) for a in results], "total": len(results)}


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str, db: Session = Depends(get_sync_db)):
    """Get a specific asset."""
    asset = _service.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@router.put("/assets/{asset_id}")
def update_asset(asset_id: str, data: AssetUpdate, db: Session = Depends(get_sync_db)):
    """Update an asset."""
    updates = {k: v for k, v in data.dict().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    asset = _service.update_asset(asset_id, **updates)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: str, db: Session = Depends(get_sync_db)):
    """Delete (dispose) an asset."""
    asset = _service.dispose_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"status": "disposed", "asset_id": asset_id}


# ========== Lifecycle Transitions ==========

@router.post("/assets/{asset_id}/receive")
def receive_asset(asset_id: str, location: str = "", db: Session = Depends(get_sync_db)):
    """Mark asset as received."""
    asset = _service.receive_asset(asset_id, location=location)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@router.post("/assets/{asset_id}/deploy")
def deploy_asset(asset_id: str, data: DeployRequest, db: Session = Depends(get_sync_db)):
    """Deploy asset to user/location."""
    asset = _service.deploy_asset(
        asset_id,
        assigned_to=data.assigned_to,
        location=data.location,
        department=data.department,
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@router.post("/assets/{asset_id}/store")
def store_asset(asset_id: str, data: StoreRequest = StoreRequest(), db: Session = Depends(get_sync_db)):
    """Move asset to storage."""
    asset = _service.store_asset(asset_id, location=data.location)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@router.post("/assets/{asset_id}/maintain")
def maintain_asset(asset_id: str, data: MaintainRequest = MaintainRequest(), db: Session = Depends(get_sync_db)):
    """Send asset to maintenance."""
    asset = _service.send_to_maintenance(asset_id, notes=data.notes)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@router.post("/assets/{asset_id}/retire")
def retire_asset(asset_id: str, db: Session = Depends(get_sync_db)):
    """Retire an asset."""
    asset = _service.retire_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_to_dict(asset)


@router.post("/assets/{asset_id}/dispose")
def dispose_asset(asset_id: str, data: DisposalCreate, db: Session = Depends(get_sync_db)):
    """Dispose an asset with full disposal record."""
    rec = _service.create_disposal_record(
        asset_id=asset_id,
        disposal_method=data.disposal_method,
        disposal_date=_parse_dt(data.disposal_date),
        certificate_of_destruction=data.certificate_of_destruction,
        data_wiped=data.data_wiped,
        wiped_method=data.wiped_method,
        proceeds=data.proceeds,
    )
    if not rec:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _disposal_to_dict(rec)


# ========== Software Licenses ==========

@router.post("/assets/licenses")
def create_license(data: LicenseCreate, db: Session = Depends(get_sync_db)):
    """Create a software license."""
    lic = _service.create_license(
        software_name=data.software_name,
        asset_id=data.asset_id,
        license_key=data.license_key,
        license_type=data.license_type,
        seats_purchased=data.seats_purchased,
        renewal_date=_parse_dt(data.renewal_date),
        annual_cost=data.annual_cost,
        vendor=data.vendor,
    )
    return _license_to_dict(lic)


@router.get("/assets/licenses")
def list_licenses(asset_id: Optional[str] = None, db: Session = Depends(get_sync_db)):
    """List software licenses."""
    lics = _service.list_licenses(asset_id=asset_id)
    return {"licenses": [_license_to_dict(l) for l in lics], "total": len(lics)}


@router.get("/assets/licenses/{license_id}")
def get_license(license_id: str, db: Session = Depends(get_sync_db)):
    """Get a specific license."""
    lic = _service.get_license(license_id)
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    return _license_to_dict(lic)


@router.post("/assets/licenses/{license_id}/assign")
def assign_seat(license_id: str, db: Session = Depends(get_sync_db)):
    """Assign a seat on a license."""
    lic = _service.assign_seat(license_id)
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    return _license_to_dict(lic)


@router.post("/assets/licenses/{license_id}/release")
def release_seat(license_id: str, db: Session = Depends(get_sync_db)):
    """Release a seat on a license."""
    lic = _service.release_seat(license_id)
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    return _license_to_dict(lic)


# ========== Maintenance ==========

@router.post("/assets/{asset_id}/maintenance")
def schedule_maintenance(asset_id: str, data: MaintenanceCreate, db: Session = Depends(get_sync_db)):
    """Schedule maintenance for an asset."""
    rec = _service.schedule_maintenance(
        asset_id=asset_id,
        maintenance_type=data.maintenance_type,
        description=data.description,
        cost=data.cost,
        performed_by=data.performed_by,
        scheduled_date=_parse_dt(data.scheduled_date),
        next_maintenance=_parse_dt(data.next_maintenance),
    )
    return _maintenance_to_dict(rec)


@router.get("/assets/{asset_id}/maintenance")
def get_maintenance_history(asset_id: str, db: Session = Depends(get_sync_db)):
    """Get maintenance history for an asset."""
    records = _service.get_maintenance_history(asset_id)
    return {"records": [_maintenance_to_dict(r) for r in records], "total": len(records)}


@router.post("/assets/maintenance/{record_id}/complete")
def complete_maintenance(record_id: str, data: MaintenanceComplete = MaintenanceComplete(), db: Session = Depends(get_sync_db)):
    """Complete a maintenance record."""
    rec = _service.complete_maintenance(record_id, cost=data.cost)
    if not rec:
        raise HTTPException(status_code=404, detail="Maintenance record not found")
    return _maintenance_to_dict(rec)


@router.get("/assets/maintenance/upcoming")
def get_upcoming_maintenance(days: int = 30, db: Session = Depends(get_sync_db)):
    """Get upcoming maintenance events."""
    records = _service.get_upcoming_maintenance(days_ahead=days)
    return {"records": [_maintenance_to_dict(r) for r in records], "total": len(records)}


# ========== Depreciation ==========

@router.post("/assets/{asset_id}/depreciation")
def create_depreciation(asset_id: str, data: DepreciationCreate, db: Session = Depends(get_sync_db)):
    """Create a depreciation schedule for an asset."""
    sched = _service.create_depreciation_schedule(
        asset_id=asset_id,
        method=data.method,
        useful_life_years=data.useful_life_years,
        salvage_value=data.salvage_value,
    )
    if not sched:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _depreciation_to_dict(sched)


@router.get("/assets/{asset_id}/depreciation")
def get_depreciation(asset_id: str, db: Session = Depends(get_sync_db)):
    """Get depreciation report for an asset."""
    report = _service.get_depreciation_report(asset_id)
    if not report:
        raise HTTPException(status_code=404, detail="No depreciation schedule found")
    return report


# ========== Asset Requests ==========

@router.post("/assets/requests")
def submit_request(data: RequestCreate, db: Session = Depends(get_sync_db)):
    """Submit an asset procurement request."""
    req = _service.submit_request(
        requester_name=data.requester_name,
        asset_type=data.asset_type,
        client_id=data.client_id,
        justification=data.justification,
        quantity=data.quantity,
        estimated_cost=data.estimated_cost,
    )
    return _request_to_dict(req)


@router.get("/assets/requests")
def list_requests(
    client_id: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_sync_db),
):
    """List asset requests."""
    reqs = _service.list_requests(client_id=client_id, status=status)
    return {"requests": [_request_to_dict(r) for r in reqs], "total": len(reqs)}


@router.put("/assets/requests/{request_id}/approve")
def approve_request(request_id: str, data: RequestApprove = RequestApprove(), db: Session = Depends(get_sync_db)):
    """Approve an asset request."""
    req = _service.approve_request(request_id, approved_by=data.approved_by)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    return _request_to_dict(req)


@router.put("/assets/requests/{request_id}/deny")
def deny_request(request_id: str, data: RequestApprove = RequestApprove(), db: Session = Depends(get_sync_db)):
    """Deny an asset request."""
    req = _service.deny_request(request_id, denied_by=data.approved_by)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    return _request_to_dict(req)


# ========== Warranties ==========

@router.get("/assets/warranties/expiring")
def get_expiring_warranties(days: int = 90, db: Session = Depends(get_sync_db)):
    """Get assets with warranties expiring soon."""
    results = _service.get_expiring_warranties(days_ahead=days)
    return {"assets": results, "count": len(results)}


@router.get("/assets/{asset_id}/warranty")
def get_warranty_status(asset_id: str, db: Session = Depends(get_sync_db)):
    """Get warranty status for an asset."""
    status = _service.get_warranty_status(asset_id)
    if not status:
        raise HTTPException(status_code=404, detail="Asset not found")
    return status


# ========== Reports ==========

@router.get("/assets/reports/inventory")
def get_inventory_report(client_id: Optional[str] = None, db: Session = Depends(get_sync_db)):
    """Get asset inventory report."""
    return _service.get_asset_inventory(client_id=client_id)


@router.get("/assets/reports/value")
def get_value_report(client_id: Optional[str] = None, db: Session = Depends(get_sync_db)):
    """Get total asset value report."""
    return _service.get_total_asset_value(client_id=client_id)


@router.get("/assets/reports/license-compliance")
def get_compliance_report(db: Session = Depends(get_sync_db)):
    """Get license compliance report."""
    return _service.get_license_compliance_report()


@router.get("/assets/reports/lifecycle")
def get_lifecycle_report(db: Session = Depends(get_sync_db)):
    """Get lifecycle summary report."""
    return _service.get_lifecycle_summary()


# ========== Dashboard ==========

@router.get("/assets/dashboard")
def get_dashboard(db: Session = Depends(get_sync_db)):
    """Get asset lifecycle management dashboard."""
    return _service.get_dashboard()
