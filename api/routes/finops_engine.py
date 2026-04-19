"""
AITHER Platform - FinOps / IT Cost Optimization Engine API Routes
Full CRUD for cost centers, entries, contracts, opportunities,
forecasts, alerts, analytics, and dashboard.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

from core.database import get_sync_db
from services.msp.finops_engine import (
    FinOpsEngineService,
    center_to_dict,
    entry_to_dict,
    opportunity_to_dict,
    forecast_to_dict,
    contract_to_dict,
    alert_to_dict,
)

router = APIRouter(prefix="/finops-engine", tags=["FinOps Engine"])


def _svc():
    """Get FinOpsEngineService with optional DB session."""
    try:
        db = next(get_sync_db())
        return FinOpsEngineService(db=db)
    except Exception:
        return FinOpsEngineService()


# ============================================================
# Pydantic Schemas
# ============================================================

class CostCenterCreate(BaseModel):
    client_id: str
    name: str
    category: str = "other"
    budget_monthly: float = 0.0
    owner: str = ""
    department: str = ""


class CostCenterUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    budget_monthly: Optional[float] = None
    owner: Optional[str] = None
    department: Optional[str] = None


class CostEntryCreate(BaseModel):
    center_id: str
    client_id: str
    description: str = ""
    vendor: str = ""
    amount: float = 0.0
    currency: str = "USD"
    period: str = ""
    entry_type: str = "recurring"
    is_committed: bool = False
    contract_end_date: Optional[str] = None


class VendorContractCreate(BaseModel):
    client_id: str
    vendor_name: str
    service_description: str = ""
    monthly_cost: float = 0.0
    annual_cost: float = 0.0
    contract_start: Optional[str] = None
    contract_end: Optional[str] = None
    auto_renew: bool = False
    notice_period_days: int = 30
    seats_purchased: int = 0
    seats_used: int = 0


class VendorContractUpdate(BaseModel):
    vendor_name: Optional[str] = None
    service_description: Optional[str] = None
    monthly_cost: Optional[float] = None
    annual_cost: Optional[float] = None
    contract_end: Optional[str] = None
    auto_renew: Optional[bool] = None
    notice_period_days: Optional[int] = None
    seats_purchased: Optional[int] = None
    seats_used: Optional[int] = None


class ForecastCreate(BaseModel):
    client_id: str
    period: str
    category: str = ""
    forecasted_amount: float = 0.0


class OpportunityStatusUpdate(BaseModel):
    status: str


# ============================================================
# Cost Center Endpoints
# ============================================================

@router.post("/cost-centers")
def create_cost_center(body: CostCenterCreate):
    svc = _svc()
    center = svc.create_center(
        client_id=body.client_id,
        name=body.name,
        category=body.category,
        budget_monthly=body.budget_monthly,
        owner=body.owner,
        department=body.department,
    )
    return center_to_dict(center)


@router.get("/cost-centers")
def list_cost_centers(
    client_id: Optional[str] = None,
    category: Optional[str] = None,
):
    svc = _svc()
    centers = svc.list_centers(client_id=client_id, category=category)
    return [center_to_dict(c) for c in centers]


@router.get("/cost-centers/{center_id}")
def get_cost_center(center_id: str):
    svc = _svc()
    center = svc.get_center(center_id)
    if not center:
        raise HTTPException(status_code=404, detail="Cost center not found")
    return center_to_dict(center)


@router.put("/cost-centers/{center_id}")
def update_cost_center(center_id: str, body: CostCenterUpdate):
    svc = _svc()
    updates = {k: v for k, v in body.dict().items() if v is not None}
    center = svc.update_center(center_id, **updates)
    if not center:
        raise HTTPException(status_code=404, detail="Cost center not found")
    return center_to_dict(center)


# ============================================================
# Cost Entry Endpoints
# ============================================================

@router.post("/costs")
def record_cost(body: CostEntryCreate):
    svc = _svc()
    contract_end = None
    if body.contract_end_date:
        try:
            contract_end = datetime.fromisoformat(body.contract_end_date)
        except ValueError:
            pass
    entry = svc.record_cost(
        center_id=body.center_id,
        client_id=body.client_id,
        description=body.description,
        vendor=body.vendor,
        amount=body.amount,
        currency=body.currency,
        period=body.period,
        entry_type=body.entry_type,
        is_committed=body.is_committed,
        contract_end_date=contract_end,
    )
    return entry_to_dict(entry)


@router.get("/costs")
def get_costs(
    client_id: Optional[str] = None,
    center_id: Optional[str] = None,
    vendor: Optional[str] = None,
    period: Optional[str] = None,
    entry_type: Optional[str] = None,
):
    svc = _svc()
    entries = svc.get_costs(
        client_id=client_id,
        center_id=center_id,
        vendor=vendor,
        period=period,
        entry_type=entry_type,
    )
    return [entry_to_dict(e) for e in entries]


@router.get("/costs/breakdown/{client_id}")
def get_cost_breakdown(client_id: str, period: Optional[str] = None):
    svc = _svc()
    return svc.get_cost_breakdown(client_id, period=period)


# ============================================================
# Vendor Contract Endpoints
# ============================================================

@router.post("/contracts")
def add_contract(body: VendorContractCreate):
    svc = _svc()
    start_dt = None
    end_dt = None
    if body.contract_start:
        try:
            start_dt = datetime.fromisoformat(body.contract_start)
        except ValueError:
            pass
    if body.contract_end:
        try:
            end_dt = datetime.fromisoformat(body.contract_end)
        except ValueError:
            pass

    contract = svc.add_contract(
        client_id=body.client_id,
        vendor_name=body.vendor_name,
        service_description=body.service_description,
        monthly_cost=body.monthly_cost,
        annual_cost=body.annual_cost,
        contract_start=start_dt,
        contract_end=end_dt,
        auto_renew=body.auto_renew,
        notice_period_days=body.notice_period_days,
        seats_purchased=body.seats_purchased,
        seats_used=body.seats_used,
    )
    return contract_to_dict(contract)


@router.get("/contracts")
def list_contracts(client_id: Optional[str] = None):
    svc = _svc()
    contracts = svc.get_contracts(client_id=client_id)
    return [contract_to_dict(c) for c in contracts]


@router.put("/contracts/{contract_id}")
def update_contract(contract_id: str, body: VendorContractUpdate):
    svc = _svc()
    updates = {k: v for k, v in body.dict().items() if v is not None}
    # Parse date strings
    if "contract_end" in updates and isinstance(updates["contract_end"], str):
        try:
            updates["contract_end"] = datetime.fromisoformat(updates["contract_end"])
        except ValueError:
            del updates["contract_end"]
    contract = svc.update_contract(contract_id, **updates)
    if not contract:
        raise HTTPException(status_code=404, detail="Contract not found")
    return contract_to_dict(contract)


@router.get("/contracts/expiring")
def get_expiring_contracts(days: int = Query(90, ge=1, le=365)):
    svc = _svc()
    contracts = svc.get_expiring_contracts(days=days)
    return [contract_to_dict(c) for c in contracts]


# ============================================================
# Savings Opportunity Endpoints
# ============================================================

@router.post("/opportunities/identify/{client_id}")
def identify_savings(client_id: str):
    svc = _svc()
    opps = svc.identify_savings_opportunities(client_id)
    return {
        "client_id": client_id,
        "opportunities_found": len(opps),
        "opportunities": [opportunity_to_dict(o) for o in opps],
    }


@router.get("/opportunities")
def list_opportunities(
    client_id: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
):
    svc = _svc()
    opps = svc.get_opportunities(client_id=client_id, status=status, category=category)
    return [opportunity_to_dict(o) for o in opps]


@router.put("/opportunities/{opportunity_id}/status")
def update_opportunity_status(opportunity_id: str, body: OpportunityStatusUpdate):
    svc = _svc()
    opp = svc.update_opportunity_status(opportunity_id, body.status)
    if not opp:
        raise HTTPException(status_code=404, detail="Opportunity not found")
    return opportunity_to_dict(opp)


@router.post("/opportunities/{opportunity_id}/implement")
def implement_opportunity(opportunity_id: str):
    svc = _svc()
    opp = svc.implement_opportunity(opportunity_id)
    if not opp:
        raise HTTPException(status_code=404, detail="Opportunity not found")
    return opportunity_to_dict(opp)


# ============================================================
# Budget Forecast Endpoints
# ============================================================

@router.post("/forecasts")
def create_forecast(body: ForecastCreate):
    svc = _svc()
    forecast = svc.create_forecast(
        client_id=body.client_id,
        period=body.period,
        category=body.category,
        forecasted_amount=body.forecasted_amount,
    )
    return forecast_to_dict(forecast)


@router.get("/forecasts")
def list_forecasts(
    client_id: Optional[str] = None,
    period: Optional[str] = None,
):
    svc = _svc()
    forecasts = svc.get_forecasts(client_id=client_id, period=period)
    return [forecast_to_dict(f) for f in forecasts]


@router.get("/budget-vs-actual/{client_id}")
def compare_budget_to_actual(client_id: str):
    svc = _svc()
    return svc.compare_budget_to_actual(client_id)


# ============================================================
# Alert Endpoints
# ============================================================

@router.post("/alerts/check-budgets")
def check_budgets():
    svc = _svc()
    alerts = svc.check_budgets()
    return {
        "alerts_generated": len(alerts),
        "alerts": [alert_to_dict(a) for a in alerts],
    }


@router.post("/alerts/generate/{client_id}")
def generate_alerts(client_id: str):
    svc = _svc()
    alerts = svc.generate_alerts(client_id)
    return {
        "client_id": client_id,
        "alerts_generated": len(alerts),
        "alerts": [alert_to_dict(a) for a in alerts],
    }


@router.get("/alerts")
def list_alerts(
    client_id: Optional[str] = None,
    alert_type: Optional[str] = None,
    acknowledged: Optional[bool] = None,
):
    svc = _svc()
    alerts = svc.get_alerts(
        client_id=client_id,
        alert_type=alert_type,
        acknowledged=acknowledged,
    )
    return [alert_to_dict(a) for a in alerts]


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    svc = _svc()
    alert = svc.acknowledge_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert)


# ============================================================
# Analytics Endpoints
# ============================================================

@router.get("/analytics/trend/{client_id}")
def get_cost_trend(client_id: str, months: int = Query(6, ge=1, le=24)):
    svc = _svc()
    return svc.get_cost_trend(client_id, months=months)


@router.get("/analytics/per-endpoint/{client_id}")
def get_cost_per_endpoint(client_id: str):
    svc = _svc()
    return svc.get_cost_per_endpoint(client_id)


@router.get("/analytics/vendor-spend")
def get_vendor_spend(client_id: Optional[str] = None):
    svc = _svc()
    return svc.get_vendor_spend_analysis(client_id=client_id)


@router.get("/analytics/category-breakdown/{client_id}")
def get_category_breakdown(client_id: str):
    svc = _svc()
    return svc.get_category_breakdown(client_id)


@router.get("/analytics/yoy/{client_id}")
def get_yoy_comparison(client_id: str):
    svc = _svc()
    return svc.get_yoy_comparison(client_id)


# ============================================================
# Savings Totals
# ============================================================

@router.get("/savings/implemented")
def get_savings_implemented(client_id: Optional[str] = None):
    svc = _svc()
    return svc.get_total_savings_implemented(client_id)


@router.get("/savings/available")
def get_savings_available(client_id: Optional[str] = None):
    svc = _svc()
    return svc.get_total_savings_available(client_id)


# ============================================================
# Dashboard
# ============================================================

@router.get("/dashboard")
def get_dashboard(client_id: Optional[str] = None):
    svc = _svc()
    return svc.get_dashboard(client_id=client_id)
