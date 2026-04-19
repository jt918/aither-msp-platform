"""
API Routes for MSP Billing Engine
Multi-tenant billing aggregation for per-seat/per-endpoint MSP clients
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.billing_engine import (
    BillingEngineService,
    BillingModel,
    BillingCycle,
    AccountStatus,
    InvoiceStatus,
    plan_to_dict,
    account_to_dict,
    invoice_to_dict,
    usage_to_dict,
    payment_to_dict,
)

router = APIRouter(prefix="/billing", tags=["Billing Engine"])


def _init_billing_service() -> BillingEngineService:
    """Initialize BillingEngineService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return BillingEngineService(db=db)
    except Exception:
        return BillingEngineService()


# Initialize service with DB persistence
billing_service = _init_billing_service()


# ========== Request/Response Models ==========

class PlanCreate(BaseModel):
    name: str
    description: str = ""
    billing_model: str = "per_endpoint"
    base_price: float = 0.0
    per_unit_price: float = 0.0
    included_units: int = 0
    overage_price: float = 0.0
    billing_cycle: str = "monthly"
    features: List[str] = []
    is_active: bool = True


class PlanUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    billing_model: Optional[str] = None
    base_price: Optional[float] = None
    per_unit_price: Optional[float] = None
    included_units: Optional[int] = None
    overage_price: Optional[float] = None
    billing_cycle: Optional[str] = None
    features: Optional[List[str]] = None
    is_active: Optional[bool] = None


class AccountCreate(BaseModel):
    tenant_id: str
    company_name: str
    plan_id: str
    billing_email: str = ""
    billing_address: str = ""
    payment_method_id: str = ""


class AccountUpdate(BaseModel):
    company_name: Optional[str] = None
    plan_id: Optional[str] = None
    billing_email: Optional[str] = None
    billing_address: Optional[str] = None
    payment_method_id: Optional[str] = None


class UsageInput(BaseModel):
    metric: str  # endpoints, users, scans, incidents
    count: int


class PaymentInput(BaseModel):
    invoice_id: str
    amount: float
    method: str = "card"


class DiscountInput(BaseModel):
    percentage: float
    reason: str = ""
    expires_at: Optional[str] = None  # ISO datetime string


# ========== Plan Routes ==========

@router.get("/plans")
async def list_plans(
    active_only: bool = Query(False),
    user=Depends(get_current_user),
):
    """List all billing plans."""
    plans = billing_service.list_plans(active_only=active_only)
    return {"plans": [plan_to_dict(p) for p in plans], "count": len(plans)}


@router.get("/plans/{plan_id}")
async def get_plan(plan_id: str, user=Depends(get_current_user)):
    """Get a specific billing plan."""
    plan = billing_service.get_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return plan_to_dict(plan)


@router.post("/plans")
async def create_plan(data: PlanCreate, user=Depends(require_admin)):
    """Create a new billing plan."""
    plan = billing_service.create_plan(
        name=data.name,
        description=data.description,
        billing_model=data.billing_model,
        base_price=data.base_price,
        per_unit_price=data.per_unit_price,
        included_units=data.included_units,
        overage_price=data.overage_price,
        billing_cycle=data.billing_cycle,
        features=data.features,
        is_active=data.is_active,
    )
    return plan_to_dict(plan)


@router.put("/plans/{plan_id}")
async def update_plan(plan_id: str, data: PlanUpdate, user=Depends(require_admin)):
    """Update an existing billing plan."""
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    plan = billing_service.update_plan(plan_id, **updates)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return plan_to_dict(plan)


# ========== Account Routes ==========

@router.get("/accounts")
async def list_accounts(
    status: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """List all billing accounts."""
    accounts = billing_service.list_accounts(status=status)
    return {"accounts": [account_to_dict(a) for a in accounts], "count": len(accounts)}


@router.get("/accounts/{account_id}")
async def get_account(account_id: str, user=Depends(get_current_user)):
    """Get a specific billing account."""
    acct = billing_service.get_account(account_id)
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")
    return account_to_dict(acct)


@router.post("/accounts")
async def create_account(data: AccountCreate, user=Depends(require_admin)):
    """Create a new billing account."""
    acct = billing_service.create_account(
        tenant_id=data.tenant_id,
        company_name=data.company_name,
        plan_id=data.plan_id,
        billing_email=data.billing_email,
        billing_address=data.billing_address,
        payment_method_id=data.payment_method_id,
    )
    return account_to_dict(acct)


@router.put("/accounts/{account_id}")
async def update_account(account_id: str, data: AccountUpdate, user=Depends(require_admin)):
    """Update an existing billing account."""
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    acct = billing_service.update_account(account_id, **updates)
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")
    return account_to_dict(acct)


@router.post("/accounts/{account_id}/suspend")
async def suspend_account(account_id: str, user=Depends(require_admin)):
    """Suspend a billing account."""
    acct = billing_service.suspend_account(account_id)
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")
    return account_to_dict(acct)


@router.post("/accounts/{account_id}/reactivate")
async def reactivate_account(account_id: str, user=Depends(require_admin)):
    """Reactivate a suspended billing account."""
    acct = billing_service.reactivate_account(account_id)
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")
    return account_to_dict(acct)


@router.post("/accounts/{account_id}/usage")
async def record_usage(account_id: str, data: UsageInput, user=Depends(get_current_user)):
    """Record usage data for an account."""
    rec = billing_service.record_usage(
        account_id=account_id,
        metric=data.metric,
        count=data.count,
    )
    return usage_to_dict(rec)


@router.get("/accounts/{account_id}/usage")
async def get_usage(
    account_id: str,
    metric: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """Get usage records for an account."""
    records = billing_service.get_usage(account_id, metric=metric)
    return {"records": [usage_to_dict(r) for r in records], "count": len(records)}


@router.post("/accounts/{account_id}/generate-invoice")
async def generate_invoice(account_id: str, user=Depends(require_admin)):
    """Generate an invoice for an account based on current usage."""
    inv = billing_service.generate_invoice(account_id)
    if not inv:
        raise HTTPException(status_code=400, detail="Could not generate invoice. Check account and plan exist.")
    return invoice_to_dict(inv)


@router.post("/accounts/{account_id}/discount")
async def apply_discount(account_id: str, data: DiscountInput, user=Depends(require_admin)):
    """Apply a discount to an account."""
    expires_at = None
    if data.expires_at:
        try:
            expires_at = datetime.fromisoformat(data.expires_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid expires_at format. Use ISO datetime.")

    acct = billing_service.apply_discount(
        account_id=account_id,
        percentage=data.percentage,
        reason=data.reason,
        expires_at=expires_at,
    )
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")
    return account_to_dict(acct)


# ========== Invoice Routes ==========

@router.get("/invoices")
async def list_invoices(
    account_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """List invoices with optional filters."""
    invoices = billing_service.list_invoices(account_id=account_id, status=status)
    return {"invoices": [invoice_to_dict(i) for i in invoices], "count": len(invoices)}


@router.get("/invoices/{invoice_id}")
async def get_invoice(invoice_id: str, user=Depends(get_current_user)):
    """Get a specific invoice."""
    inv = billing_service.get_invoice(invoice_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice_to_dict(inv)


@router.post("/invoices/{invoice_id}/void")
async def void_invoice(invoice_id: str, user=Depends(require_admin)):
    """Void an invoice."""
    inv = billing_service.void_invoice(invoice_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice_to_dict(inv)


@router.post("/invoices/{invoice_id}/pay")
async def pay_invoice(invoice_id: str, data: PaymentInput, user=Depends(require_admin)):
    """Record a payment for an invoice."""
    inv = billing_service.get_invoice(invoice_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")

    payment = billing_service.record_payment(
        account_id=inv.account_id,
        invoice_id=invoice_id,
        amount=data.amount,
        method=data.method,
    )
    return payment_to_dict(payment)


# ========== Metrics & Dashboard Routes ==========

@router.get("/metrics/mrr")
async def get_mrr(user=Depends(get_current_user)):
    """Get Monthly Recurring Revenue."""
    return {"mrr": billing_service.calculate_mrr()}


@router.get("/metrics/arr")
async def get_arr(user=Depends(get_current_user)):
    """Get Annual Recurring Revenue."""
    return {"arr": billing_service.calculate_arr()}


@router.get("/metrics/churn")
async def get_churn(user=Depends(get_current_user)):
    """Get account churn rate."""
    return {"churn_rate": billing_service.get_churn_rate()}


@router.get("/metrics/arpa")
async def get_arpa(user=Depends(get_current_user)):
    """Get Average Revenue Per Account."""
    return {"arpa": billing_service.get_arpa()}


@router.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    """Get comprehensive billing dashboard."""
    return billing_service.get_billing_dashboard()


@router.get("/revenue-forecast")
async def get_revenue_forecast(
    months: int = Query(12, ge=1, le=60),
    user=Depends(get_current_user),
):
    """Get revenue forecast for the next N months."""
    forecast = billing_service.get_revenue_forecast(months=months)
    return {"forecast": forecast, "months": months}


@router.post("/check-overdue")
async def check_overdue(user=Depends(require_admin)):
    """Check and flag overdue invoices."""
    overdue = billing_service.check_overdue_invoices()
    return {
        "overdue_count": len(overdue),
        "invoices": [invoice_to_dict(i) for i in overdue],
    }
