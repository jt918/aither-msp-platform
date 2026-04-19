"""
API Routes for Vendor Management Portal
Uses VendorManagementService for all operations
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from core.database import get_sync_db

from services.msp.vendor_management import (
    VendorManagementService,
    VendorCategory,
    VendorStatus,
    ContractType,
    ContractStatus,
    RiskType,
    RiskSeverity,
    RiskStatus,
    ProcurementStatus,
    _vendor_to_dict,
    _contract_to_dict,
    _review_to_dict,
    _procurement_to_dict,
    _risk_to_dict,
)

router = APIRouter(prefix="/vendor-management", tags=["Vendor Management"])


def _init_service() -> VendorManagementService:
    """Initialize VendorManagementService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return VendorManagementService(db=db)
    except Exception:
        return VendorManagementService()


svc = _init_service()


# ========== Request/Response Models ==========

class VendorCreate(BaseModel):
    name: str
    category: str = "software"
    contact_name: str = ""
    contact_email: str = ""
    contact_phone: str = ""
    website: str = ""
    account_number: str = ""
    account_rep: str = ""
    status: str = "active"
    risk_tier: str = "low"
    payment_terms: str = "net30"
    notes: str = ""


class VendorUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    website: Optional[str] = None
    account_number: Optional[str] = None
    account_rep: Optional[str] = None
    status: Optional[str] = None
    risk_tier: Optional[str] = None
    payment_terms: Optional[str] = None
    notes: Optional[str] = None
    total_spend_ytd: Optional[float] = None


class ContractCreate(BaseModel):
    vendor_id: str
    title: str
    contract_type: str = "subscription"
    client_id: str = ""
    value_monthly: float = 0.0
    value_annual: float = 0.0
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    auto_renew: bool = False
    cancellation_notice_days: int = 30
    sla_terms: Dict[str, Any] = {}
    deliverables: List[str] = []
    status: str = "active"


class ContractUpdate(BaseModel):
    title: Optional[str] = None
    contract_type: Optional[str] = None
    value_monthly: Optional[float] = None
    value_annual: Optional[float] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    auto_renew: Optional[bool] = None
    cancellation_notice_days: Optional[int] = None
    sla_terms: Optional[Dict[str, Any]] = None
    deliverables: Optional[List[str]] = None
    status: Optional[str] = None


class ReviewCreate(BaseModel):
    vendor_id: str
    review_period: str = ""
    quality_score: float = 0.0
    delivery_score: float = 0.0
    communication_score: float = 0.0
    value_score: float = 0.0
    strengths: List[str] = []
    weaknesses: List[str] = []
    recommendation: str = ""
    reviewed_by: str = ""


class ProcurementCreate(BaseModel):
    vendor_id: str
    title: str
    client_id: str = ""
    description: str = ""
    items: List[Dict[str, Any]] = []
    estimated_cost: float = 0.0
    requested_by: str = ""


class ProcurementApprove(BaseModel):
    approved_by: str = ""


class ProcurementOrder(BaseModel):
    po_number: str = ""


class RiskCreate(BaseModel):
    vendor_id: str
    risk_type: str
    severity: str
    description: str
    mitigation: str = ""


class RiskUpdate(BaseModel):
    severity: Optional[str] = None
    description: Optional[str] = None
    mitigation: Optional[str] = None
    status: Optional[str] = None


class VendorCompare(BaseModel):
    vendor_ids: List[str]


# ========== Vendor CRUD ==========

@router.post("/vendors")
async def create_vendor(data: VendorCreate):
    vendor = svc.create_vendor(
        name=data.name, category=data.category,
        contact_name=data.contact_name, contact_email=data.contact_email,
        contact_phone=data.contact_phone, website=data.website,
        account_number=data.account_number, account_rep=data.account_rep,
        status=data.status, risk_tier=data.risk_tier,
        payment_terms=data.payment_terms, notes=data.notes,
    )
    return {"status": "created", "vendor": _vendor_to_dict(vendor)}


@router.get("/vendors")
async def list_vendors(
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    vendors = svc.list_vendors(category=category, status=status)
    return {"vendors": [_vendor_to_dict(v) for v in vendors], "count": len(vendors)}


@router.get("/vendors/search")
async def search_vendors(q: str = Query(...)):
    vendors = svc.search_vendors(q)
    return {"vendors": [_vendor_to_dict(v) for v in vendors], "count": len(vendors)}


@router.get("/vendors/high-risk")
async def get_high_risk_vendors():
    vendors = svc.get_high_risk_vendors()
    return {"vendors": [_vendor_to_dict(v) for v in vendors], "count": len(vendors)}


@router.get("/vendors/{vendor_id}")
async def get_vendor(vendor_id: str):
    vendor = svc.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return {"vendor": _vendor_to_dict(vendor)}


@router.put("/vendors/{vendor_id}")
async def update_vendor(vendor_id: str, data: VendorUpdate):
    updates = {k: v for k, v in data.dict().items() if v is not None}
    vendor = svc.update_vendor(vendor_id, **updates)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return {"status": "updated", "vendor": _vendor_to_dict(vendor)}


@router.delete("/vendors/{vendor_id}")
async def delete_vendor(vendor_id: str):
    if not svc.delete_vendor(vendor_id):
        raise HTTPException(status_code=404, detail="Vendor not found")
    return {"status": "deleted", "vendor_id": vendor_id}


@router.post("/vendors/compare")
async def compare_vendors(data: VendorCompare):
    results = svc.compare_vendors(data.vendor_ids)
    return {"comparison": results, "count": len(results)}


# ========== Contract CRUD ==========

@router.post("/contracts")
async def create_contract(data: ContractCreate):
    kwargs = data.dict()
    vendor_id = kwargs.pop("vendor_id")
    title = kwargs.pop("title")
    contract_type = kwargs.pop("contract_type")
    # Parse date strings
    for date_field in ("start_date", "end_date"):
        val = kwargs.get(date_field)
        if val:
            try:
                kwargs[date_field] = datetime.fromisoformat(val)
            except (ValueError, TypeError):
                kwargs[date_field] = None
    contract = svc.create_contract(vendor_id, title, contract_type, **kwargs)
    return {"status": "created", "contract": _contract_to_dict(contract)}


@router.get("/contracts")
async def list_contracts(
    vendor_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    contracts = svc.list_contracts(vendor_id=vendor_id, status=status)
    return {"contracts": [_contract_to_dict(c) for c in contracts], "count": len(contracts)}


@router.get("/contracts/expiring")
async def get_expiring_contracts(days: int = Query(30)):
    contracts = svc.get_expiring_contracts(days)
    return {"contracts": [_contract_to_dict(c) for c in contracts], "count": len(contracts)}


@router.get("/contracts/{contract_id}")
async def get_contract(contract_id: str):
    contract = svc.get_contract(contract_id)
    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")
    return {"contract": _contract_to_dict(contract)}


@router.put("/contracts/{contract_id}")
async def update_contract(contract_id: str, data: ContractUpdate):
    updates = {k: v for k, v in data.dict().items() if v is not None}
    for date_field in ("start_date", "end_date"):
        val = updates.get(date_field)
        if val and isinstance(val, str):
            try:
                updates[date_field] = datetime.fromisoformat(val)
            except (ValueError, TypeError):
                updates.pop(date_field, None)
    contract = svc.update_contract(contract_id, **updates)
    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")
    return {"status": "updated", "contract": _contract_to_dict(contract)}


@router.delete("/contracts/{contract_id}")
async def delete_contract(contract_id: str):
    if not svc.delete_contract(contract_id):
        raise HTTPException(status_code=404, detail="Contract not found")
    return {"status": "deleted", "contract_id": contract_id}


# ========== Reviews ==========

@router.post("/reviews")
async def create_review(data: ReviewCreate):
    review = svc.create_review(
        vendor_id=data.vendor_id,
        review_period=data.review_period,
        quality_score=data.quality_score,
        delivery_score=data.delivery_score,
        communication_score=data.communication_score,
        value_score=data.value_score,
        strengths=data.strengths,
        weaknesses=data.weaknesses,
        recommendation=data.recommendation,
        reviewed_by=data.reviewed_by,
    )
    return {"status": "created", "review": _review_to_dict(review)}


@router.get("/reviews/{vendor_id}")
async def get_reviews(vendor_id: str):
    reviews = svc.get_reviews(vendor_id)
    return {"reviews": [_review_to_dict(r) for r in reviews], "count": len(reviews)}


@router.get("/reviews/{vendor_id}/score")
async def get_vendor_score(vendor_id: str):
    score = svc.calculate_vendor_score(vendor_id)
    return {"vendor_id": vendor_id, "performance_score": score}


# ========== Procurement ==========

@router.post("/procurement")
async def submit_procurement(data: ProcurementCreate):
    req = svc.submit_request(
        vendor_id=data.vendor_id, title=data.title,
        client_id=data.client_id, description=data.description,
        items=data.items, estimated_cost=data.estimated_cost,
        requested_by=data.requested_by,
    )
    return {"status": "submitted", "request": _procurement_to_dict(req)}


@router.get("/procurement")
async def list_procurement(
    vendor_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    client_id: Optional[str] = Query(None),
):
    reqs = svc.get_requests(vendor_id=vendor_id, status=status, client_id=client_id)
    return {"requests": [_procurement_to_dict(r) for r in reqs], "count": len(reqs)}


@router.get("/procurement/{request_id}")
async def get_procurement(request_id: str):
    req = svc.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Procurement request not found")
    return {"request": _procurement_to_dict(req)}


@router.post("/procurement/{request_id}/approve")
async def approve_procurement(request_id: str, data: ProcurementApprove):
    req = svc.approve_request(request_id, approved_by=data.approved_by)
    if not req:
        raise HTTPException(status_code=404, detail="Procurement request not found")
    return {"status": "approved", "request": _procurement_to_dict(req)}


@router.post("/procurement/{request_id}/order")
async def order_procurement(request_id: str, data: ProcurementOrder):
    req = svc.mark_ordered(request_id, po_number=data.po_number)
    if not req:
        raise HTTPException(status_code=404, detail="Procurement request not found")
    return {"status": "ordered", "request": _procurement_to_dict(req)}


@router.post("/procurement/{request_id}/receive")
async def receive_procurement(request_id: str):
    req = svc.mark_received(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Procurement request not found")
    return {"status": "received", "request": _procurement_to_dict(req)}


# ========== Risk Management ==========

@router.post("/risks")
async def add_risk(data: RiskCreate):
    risk = svc.add_risk(
        vendor_id=data.vendor_id, risk_type=data.risk_type,
        severity=data.severity, description=data.description,
        mitigation=data.mitigation,
    )
    return {"status": "created", "risk": _risk_to_dict(risk)}


@router.get("/risks/{vendor_id}")
async def get_risks(vendor_id: str):
    risks = svc.get_risks(vendor_id)
    return {"risks": [_risk_to_dict(r) for r in risks], "count": len(risks)}


@router.put("/risks/{risk_id}")
async def update_risk(risk_id: str, data: RiskUpdate):
    updates = {k: v for k, v in data.dict().items() if v is not None}
    risk = svc.update_risk(risk_id, **updates)
    if not risk:
        raise HTTPException(status_code=404, detail="Risk not found")
    return {"status": "updated", "risk": _risk_to_dict(risk)}


# ========== Analytics ==========

@router.get("/analytics/spend")
async def get_spend_report():
    return svc.get_vendor_spend_report()


@router.get("/analytics/categories")
async def get_category_breakdown():
    return svc.get_category_breakdown()


@router.get("/analytics/renewal-calendar")
async def get_renewal_calendar(months: int = Query(6)):
    return {"calendar": svc.get_renewal_calendar(months)}


@router.get("/analytics/concentration-risk/{client_id}")
async def get_concentration_risk(client_id: str):
    return svc.get_concentration_risk(client_id)


@router.get("/dashboard")
async def get_dashboard():
    return svc.get_dashboard()
