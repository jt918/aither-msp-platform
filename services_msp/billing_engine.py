"""
AITHER Platform - MSP Billing Engine Service
Multi-tenant billing aggregation for per-seat/per-endpoint MSP clients

Provides:
- Billing plan management (CRUD)
- Tenant billing account lifecycle
- Usage tracking (endpoints, users, scans, incidents)
- Automated invoice generation from usage + plan
- Payment recording
- Revenue analytics (MRR, ARR, churn, ARPA, forecasting)
- Overdue detection and account suspension
- Discount management

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.msp_billing import (
        BillingPlanModel,
        BillingAccountModel,
        InvoiceModel,
        InvoiceLineItemModel,
        UsageRecordModel,
        PaymentRecordModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class BillingModel(str, Enum):
    """Billing model type"""
    PER_ENDPOINT = "per_endpoint"
    PER_USER = "per_user"
    PER_DEVICE = "per_device"
    FLAT = "flat"


class BillingCycle(str, Enum):
    """Billing cycle"""
    MONTHLY = "monthly"
    ANNUAL = "annual"


class AccountStatus(str, Enum):
    """Account status"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"
    PAST_DUE = "past_due"


class InvoiceStatus(str, Enum):
    """Invoice status"""
    DRAFT = "draft"
    SENT = "sent"
    PAID = "paid"
    OVERDUE = "overdue"
    VOID = "void"


class LineItemType(str, Enum):
    """Line item type"""
    BASE = "base"
    ENDPOINT = "endpoint"
    USER = "user"
    OVERAGE = "overage"
    ADDON = "addon"


class PaymentStatus(str, Enum):
    """Payment status"""
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class BillingPlan:
    """Billing plan definition"""
    plan_id: str
    name: str
    description: str = ""
    billing_model: str = "per_endpoint"
    base_price: float = 0.0
    per_unit_price: float = 0.0
    included_units: int = 0
    overage_price: float = 0.0
    billing_cycle: str = "monthly"
    features: List[str] = field(default_factory=list)
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class BillingAccount:
    """Tenant billing account"""
    account_id: str
    tenant_id: str
    company_name: str
    plan_id: str
    billing_email: str = ""
    billing_address: str = ""
    payment_method_id: str = ""
    current_endpoints: int = 0
    current_users: int = 0
    status: str = "active"
    discount_percentage: float = 0.0
    discount_reason: str = ""
    discount_expires_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    next_billing_date: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class LineItem:
    """Invoice line item"""
    description: str
    quantity: float
    unit_price: float
    total: float
    item_type: str = "base"


@dataclass
class Invoice:
    """Billing invoice"""
    invoice_id: str
    account_id: str
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    line_items: List[Dict[str, Any]] = field(default_factory=list)
    subtotal: float = 0.0
    tax: float = 0.0
    discount: float = 0.0
    total: float = 0.0
    status: str = "draft"
    due_date: Optional[datetime] = None
    paid_at: Optional[datetime] = None
    payment_reference: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class UsageRecord:
    """Usage tracking record"""
    record_id: str
    account_id: str
    metric: str  # endpoints, users, scans, incidents
    count: int = 0
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PaymentRecord:
    """Payment record"""
    payment_id: str
    account_id: str
    invoice_id: str
    amount: float = 0.0
    method: str = ""
    status: str = "pending"
    processed_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _plan_from_row(row) -> BillingPlan:
    """Convert BillingPlanModel row to BillingPlan dataclass."""
    return BillingPlan(
        plan_id=row.plan_id,
        name=row.name,
        description=row.description or "",
        billing_model=row.billing_model or "per_endpoint",
        base_price=row.base_price or 0.0,
        per_unit_price=row.per_unit_price or 0.0,
        included_units=row.included_units or 0,
        overage_price=row.overage_price or 0.0,
        billing_cycle=row.billing_cycle or "monthly",
        features=row.features or [],
        is_active=row.is_active if row.is_active is not None else True,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _account_from_row(row) -> BillingAccount:
    """Convert BillingAccountModel row to BillingAccount dataclass."""
    return BillingAccount(
        account_id=row.account_id,
        tenant_id=row.tenant_id,
        company_name=row.company_name,
        plan_id=row.plan_id,
        billing_email=row.billing_email or "",
        billing_address=row.billing_address or "",
        payment_method_id=row.payment_method_id or "",
        current_endpoints=row.current_endpoints or 0,
        current_users=row.current_users or 0,
        status=row.status or "active",
        discount_percentage=row.discount_percentage or 0.0,
        discount_reason=row.discount_reason or "",
        discount_expires_at=row.discount_expires_at,
        created_at=row.created_at or datetime.now(timezone.utc),
        next_billing_date=row.next_billing_date,
        updated_at=row.updated_at,
    )


def _invoice_from_row(row) -> Invoice:
    """Convert InvoiceModel row to Invoice dataclass."""
    return Invoice(
        invoice_id=row.invoice_id,
        account_id=row.account_id,
        period_start=row.period_start,
        period_end=row.period_end,
        line_items=row.line_items or [],
        subtotal=row.subtotal or 0.0,
        tax=row.tax or 0.0,
        discount=getattr(row, "discount", 0.0) or 0.0,
        total=row.total or 0.0,
        status=row.status or "draft",
        due_date=row.due_date,
        paid_at=row.paid_at,
        payment_reference=row.payment_reference or "",
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _usage_from_row(row) -> UsageRecord:
    """Convert UsageRecordModel row to UsageRecord dataclass."""
    return UsageRecord(
        record_id=row.record_id,
        account_id=row.account_id,
        metric=row.metric,
        count=row.count or 0,
        recorded_at=row.recorded_at or datetime.now(timezone.utc),
    )


def _payment_from_row(row) -> PaymentRecord:
    """Convert PaymentRecordModel row to PaymentRecord dataclass."""
    return PaymentRecord(
        payment_id=row.payment_id,
        account_id=row.account_id,
        invoice_id=row.invoice_id,
        amount=row.amount or 0.0,
        method=row.method or "",
        status=row.status or "pending",
        processed_at=row.processed_at,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


# ============================================================
# Serialization helpers
# ============================================================

def plan_to_dict(plan: BillingPlan) -> dict:
    """Convert BillingPlan dataclass to dict."""
    return {
        "plan_id": plan.plan_id,
        "name": plan.name,
        "description": plan.description,
        "billing_model": plan.billing_model,
        "base_price": plan.base_price,
        "per_unit_price": plan.per_unit_price,
        "included_units": plan.included_units,
        "overage_price": plan.overage_price,
        "billing_cycle": plan.billing_cycle,
        "features": plan.features,
        "is_active": plan.is_active,
        "created_at": plan.created_at.isoformat() if plan.created_at else None,
        "updated_at": plan.updated_at.isoformat() if plan.updated_at else None,
    }


def account_to_dict(acct: BillingAccount) -> dict:
    """Convert BillingAccount dataclass to dict."""
    return {
        "account_id": acct.account_id,
        "tenant_id": acct.tenant_id,
        "company_name": acct.company_name,
        "plan_id": acct.plan_id,
        "billing_email": acct.billing_email,
        "billing_address": acct.billing_address,
        "payment_method_id": acct.payment_method_id,
        "current_endpoints": acct.current_endpoints,
        "current_users": acct.current_users,
        "status": acct.status,
        "discount_percentage": acct.discount_percentage,
        "discount_reason": acct.discount_reason,
        "discount_expires_at": acct.discount_expires_at.isoformat() if acct.discount_expires_at else None,
        "created_at": acct.created_at.isoformat() if acct.created_at else None,
        "next_billing_date": acct.next_billing_date.isoformat() if acct.next_billing_date else None,
        "updated_at": acct.updated_at.isoformat() if acct.updated_at else None,
    }


def invoice_to_dict(inv: Invoice) -> dict:
    """Convert Invoice dataclass to dict."""
    return {
        "invoice_id": inv.invoice_id,
        "account_id": inv.account_id,
        "period_start": inv.period_start.isoformat() if inv.period_start else None,
        "period_end": inv.period_end.isoformat() if inv.period_end else None,
        "line_items": inv.line_items,
        "subtotal": inv.subtotal,
        "tax": inv.tax,
        "discount": inv.discount,
        "total": inv.total,
        "status": inv.status,
        "due_date": inv.due_date.isoformat() if inv.due_date else None,
        "paid_at": inv.paid_at.isoformat() if inv.paid_at else None,
        "payment_reference": inv.payment_reference,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
    }


def usage_to_dict(rec: UsageRecord) -> dict:
    """Convert UsageRecord dataclass to dict."""
    return {
        "record_id": rec.record_id,
        "account_id": rec.account_id,
        "metric": rec.metric,
        "count": rec.count,
        "recorded_at": rec.recorded_at.isoformat() if rec.recorded_at else None,
    }


def payment_to_dict(pay: PaymentRecord) -> dict:
    """Convert PaymentRecord dataclass to dict."""
    return {
        "payment_id": pay.payment_id,
        "account_id": pay.account_id,
        "invoice_id": pay.invoice_id,
        "amount": pay.amount,
        "method": pay.method,
        "status": pay.status,
        "processed_at": pay.processed_at.isoformat() if pay.processed_at else None,
        "created_at": pay.created_at.isoformat() if pay.created_at else None,
    }


# ============================================================
# Default pricing tiers
# ============================================================

DEFAULT_PLANS = [
    {
        "name": "Starter",
        "description": "Entry-level MSP plan with 100 included endpoints",
        "billing_model": "per_endpoint",
        "base_price": 0.0,
        "per_unit_price": 2.50,
        "included_units": 100,
        "overage_price": 3.00,
        "billing_cycle": "monthly",
        "features": ["basic_monitoring", "patch_management", "remote_access", "alerting"],
    },
    {
        "name": "Professional",
        "description": "Professional MSP plan with 500 included endpoints",
        "billing_model": "per_endpoint",
        "base_price": 0.0,
        "per_unit_price": 4.00,
        "included_units": 500,
        "overage_price": 4.50,
        "billing_cycle": "monthly",
        "features": ["basic_monitoring", "patch_management", "remote_access", "alerting",
                      "automation", "reporting", "psa_integration", "sla_management"],
    },
    {
        "name": "Enterprise",
        "description": "Enterprise MSP plan with unlimited endpoints",
        "billing_model": "per_endpoint",
        "base_price": 0.0,
        "per_unit_price": 6.00,
        "included_units": 999999,
        "overage_price": 0.0,
        "billing_cycle": "monthly",
        "features": ["basic_monitoring", "patch_management", "remote_access", "alerting",
                      "automation", "reporting", "psa_integration", "sla_management",
                      "custom_integrations", "dedicated_support", "white_label", "api_access"],
    },
    {
        "name": "Shield Consumer - Personal",
        "description": "Personal cybersecurity protection",
        "billing_model": "per_user",
        "base_price": 4.99,
        "per_unit_price": 4.99,
        "included_units": 1,
        "overage_price": 4.99,
        "billing_cycle": "monthly",
        "features": ["endpoint_protection", "web_filtering", "password_manager"],
    },
    {
        "name": "Shield Consumer - Family",
        "description": "Family cybersecurity protection for up to 5 users",
        "billing_model": "per_user",
        "base_price": 9.99,
        "per_unit_price": 9.99,
        "included_units": 5,
        "overage_price": 4.99,
        "billing_cycle": "monthly",
        "features": ["endpoint_protection", "web_filtering", "password_manager",
                      "parental_controls", "family_dashboard"],
    },
    {
        "name": "Shield Consumer - Pro",
        "description": "Professional individual cybersecurity",
        "billing_model": "per_user",
        "base_price": 14.99,
        "per_unit_price": 14.99,
        "included_units": 1,
        "overage_price": 14.99,
        "billing_cycle": "monthly",
        "features": ["endpoint_protection", "web_filtering", "password_manager",
                      "vpn", "dark_web_monitoring", "identity_protection", "priority_support"],
    },
]


# ============================================================
# BillingEngineService
# ============================================================

class BillingEngineService:
    """
    Multi-tenant MSP Billing Engine

    Manages plans, accounts, usage tracking, invoice generation,
    payments, and revenue analytics for MSP clients.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._plans: Dict[str, BillingPlan] = {}
        self._accounts: Dict[str, BillingAccount] = {}
        self._invoices: Dict[str, Invoice] = {}
        self._usage_records: List[UsageRecord] = []
        self._payments: List[PaymentRecord] = []

        # Initialize default plans
        self._init_default_plans()

    def _init_default_plans(self) -> None:
        """Seed default pricing tiers if none exist."""
        existing = self.list_plans()
        if existing:
            return
        for plan_data in DEFAULT_PLANS:
            self.create_plan(**plan_data)
        logger.info("Seeded %d default billing plans", len(DEFAULT_PLANS))

    # ========== Plan Management ==========

    def create_plan(
        self,
        name: str,
        description: str = "",
        billing_model: str = "per_endpoint",
        base_price: float = 0.0,
        per_unit_price: float = 0.0,
        included_units: int = 0,
        overage_price: float = 0.0,
        billing_cycle: str = "monthly",
        features: Optional[List[str]] = None,
        is_active: bool = True,
    ) -> BillingPlan:
        """Create a new billing plan."""
        plan_id = f"PLN-{uuid.uuid4().hex[:8].upper()}"
        plan = BillingPlan(
            plan_id=plan_id,
            name=name,
            description=description,
            billing_model=billing_model,
            base_price=base_price,
            per_unit_price=per_unit_price,
            included_units=included_units,
            overage_price=overage_price,
            billing_cycle=billing_cycle,
            features=features or [],
            is_active=is_active,
        )

        if self._use_db:
            try:
                row = BillingPlanModel(
                    plan_id=plan_id,
                    name=name,
                    description=description,
                    billing_model=billing_model,
                    base_price=base_price,
                    per_unit_price=per_unit_price,
                    included_units=included_units,
                    overage_price=overage_price,
                    billing_cycle=billing_cycle,
                    features=features or [],
                    is_active=is_active,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Created billing plan %s in DB", plan_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for plan %s, using memory: %s", plan_id, exc)
                self._plans[plan_id] = plan
        else:
            self._plans[plan_id] = plan

        return plan

    def update_plan(self, plan_id: str, **kwargs) -> Optional[BillingPlan]:
        """Update an existing billing plan."""
        if self._use_db:
            try:
                row = self.db.query(BillingPlanModel).filter(
                    BillingPlanModel.plan_id == plan_id
                ).first()
                if not row:
                    return None
                for key, value in kwargs.items():
                    if hasattr(row, key) and key not in ("plan_id", "id"):
                        setattr(row, key, value)
                self.db.commit()
                return _plan_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for plan %s: %s", plan_id, exc)

        plan = self._plans.get(plan_id)
        if not plan:
            return None
        for key, value in kwargs.items():
            if hasattr(plan, key) and key not in ("plan_id",):
                setattr(plan, key, value)
        plan.updated_at = datetime.now(timezone.utc)
        return plan

    def get_plan(self, plan_id: str) -> Optional[BillingPlan]:
        """Retrieve a billing plan by ID."""
        if self._use_db:
            try:
                row = self.db.query(BillingPlanModel).filter(
                    BillingPlanModel.plan_id == plan_id
                ).first()
                if row:
                    return _plan_from_row(row)
            except Exception as exc:
                logger.warning("DB read failed for plan %s: %s", plan_id, exc)

        return self._plans.get(plan_id)

    def list_plans(self, active_only: bool = False) -> List[BillingPlan]:
        """List all billing plans."""
        if self._use_db:
            try:
                q = self.db.query(BillingPlanModel)
                if active_only:
                    q = q.filter(BillingPlanModel.is_active == True)
                rows = q.all()
                return [_plan_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB list plans failed: %s", exc)

        plans = list(self._plans.values())
        if active_only:
            plans = [p for p in plans if p.is_active]
        return plans

    # ========== Account Management ==========

    def create_account(
        self,
        tenant_id: str,
        company_name: str,
        plan_id: str,
        billing_email: str = "",
        billing_address: str = "",
        payment_method_id: str = "",
    ) -> BillingAccount:
        """Create a new billing account for a tenant."""
        account_id = f"ACCT-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        next_billing = now + timedelta(days=30)

        acct = BillingAccount(
            account_id=account_id,
            tenant_id=tenant_id,
            company_name=company_name,
            plan_id=plan_id,
            billing_email=billing_email,
            billing_address=billing_address,
            payment_method_id=payment_method_id,
            status="active",
            created_at=now,
            next_billing_date=next_billing,
        )

        if self._use_db:
            try:
                row = BillingAccountModel(
                    account_id=account_id,
                    tenant_id=tenant_id,
                    company_name=company_name,
                    plan_id=plan_id,
                    billing_email=billing_email,
                    billing_address=billing_address,
                    payment_method_id=payment_method_id,
                    status="active",
                    next_billing_date=next_billing,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Created billing account %s in DB", account_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for account %s: %s", account_id, exc)
                self._accounts[account_id] = acct
        else:
            self._accounts[account_id] = acct

        return acct

    def update_account(self, account_id: str, **kwargs) -> Optional[BillingAccount]:
        """Update an existing billing account."""
        if self._use_db:
            try:
                row = self.db.query(BillingAccountModel).filter(
                    BillingAccountModel.account_id == account_id
                ).first()
                if not row:
                    return None
                for key, value in kwargs.items():
                    if hasattr(row, key) and key not in ("account_id", "id"):
                        setattr(row, key, value)
                self.db.commit()
                return _account_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for account %s: %s", account_id, exc)

        acct = self._accounts.get(account_id)
        if not acct:
            return None
        for key, value in kwargs.items():
            if hasattr(acct, key) and key not in ("account_id",):
                setattr(acct, key, value)
        acct.updated_at = datetime.now(timezone.utc)
        return acct

    def get_account(self, account_id: str) -> Optional[BillingAccount]:
        """Retrieve a billing account by ID."""
        if self._use_db:
            try:
                row = self.db.query(BillingAccountModel).filter(
                    BillingAccountModel.account_id == account_id
                ).first()
                if row:
                    return _account_from_row(row)
            except Exception as exc:
                logger.warning("DB read failed for account %s: %s", account_id, exc)

        return self._accounts.get(account_id)

    def list_accounts(self, status: Optional[str] = None) -> List[BillingAccount]:
        """List all billing accounts, optionally filtered by status."""
        if self._use_db:
            try:
                q = self.db.query(BillingAccountModel)
                if status:
                    q = q.filter(BillingAccountModel.status == status)
                rows = q.all()
                return [_account_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB list accounts failed: %s", exc)

        accts = list(self._accounts.values())
        if status:
            accts = [a for a in accts if a.status == status]
        return accts

    def suspend_account(self, account_id: str, reason: str = "") -> Optional[BillingAccount]:
        """Suspend a billing account."""
        return self.update_account(account_id, status="suspended")

    def reactivate_account(self, account_id: str) -> Optional[BillingAccount]:
        """Reactivate a suspended billing account."""
        return self.update_account(account_id, status="active")

    # ========== Usage Tracking ==========

    def record_usage(self, account_id: str, metric: str, count: int) -> UsageRecord:
        """Record a usage data point for billing calculations."""
        record_id = f"USG-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        rec = UsageRecord(
            record_id=record_id,
            account_id=account_id,
            metric=metric,
            count=count,
            recorded_at=now,
        )

        # Also update account current counts
        if metric == "endpoints":
            self.update_account(account_id, current_endpoints=count)
        elif metric == "users":
            self.update_account(account_id, current_users=count)

        if self._use_db:
            try:
                row = UsageRecordModel(
                    record_id=record_id,
                    account_id=account_id,
                    metric=metric,
                    count=count,
                    recorded_at=now,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Recorded usage %s for account %s", record_id, account_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for usage %s: %s", record_id, exc)
                self._usage_records.append(rec)
        else:
            self._usage_records.append(rec)

        return rec

    def get_usage(self, account_id: str, metric: Optional[str] = None) -> List[UsageRecord]:
        """Get usage records for an account."""
        if self._use_db:
            try:
                q = self.db.query(UsageRecordModel).filter(
                    UsageRecordModel.account_id == account_id
                )
                if metric:
                    q = q.filter(UsageRecordModel.metric == metric)
                rows = q.order_by(UsageRecordModel.recorded_at.desc()).all()
                return [_usage_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB read usage failed for %s: %s", account_id, exc)

        records = [r for r in self._usage_records if r.account_id == account_id]
        if metric:
            records = [r for r in records if r.metric == metric]
        return records

    # ========== Invoice Management ==========

    def generate_invoice(self, account_id: str) -> Optional[Invoice]:
        """Auto-generate an invoice based on current usage and plan."""
        acct = self.get_account(account_id)
        if not acct:
            logger.warning("Cannot generate invoice: account %s not found", account_id)
            return None

        plan = self.get_plan(acct.plan_id)
        if not plan:
            logger.warning("Cannot generate invoice: plan %s not found", acct.plan_id)
            return None

        invoice_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(days=30)
        period_end = now
        due_date = now + timedelta(days=30)

        line_items = []
        subtotal = 0.0

        # Base fee line item
        if plan.base_price > 0:
            base_item = {
                "description": f"{plan.name} - Base Fee",
                "quantity": 1,
                "unit_price": plan.base_price,
                "total": plan.base_price,
                "item_type": "base",
            }
            line_items.append(base_item)
            subtotal += plan.base_price

        # Usage-based line items
        if plan.billing_model in ("per_endpoint", "per_device"):
            unit_count = acct.current_endpoints
            unit_label = "endpoint"
        elif plan.billing_model == "per_user":
            unit_count = acct.current_users
            unit_label = "user"
        else:
            unit_count = 0
            unit_label = "unit"

        if unit_count > 0:
            included = min(unit_count, plan.included_units)
            included_total = included * plan.per_unit_price

            included_item = {
                "description": f"{plan.name} - {included} {unit_label}(s) @ ${plan.per_unit_price:.2f}",
                "quantity": included,
                "unit_price": plan.per_unit_price,
                "total": included_total,
                "item_type": unit_label,
            }
            line_items.append(included_item)
            subtotal += included_total

            # Overage
            overage_count = max(0, unit_count - plan.included_units)
            if overage_count > 0 and plan.overage_price > 0:
                overage_total = overage_count * plan.overage_price
                overage_item = {
                    "description": f"Overage - {overage_count} {unit_label}(s) @ ${plan.overage_price:.2f}",
                    "quantity": overage_count,
                    "unit_price": plan.overage_price,
                    "total": overage_total,
                    "item_type": "overage",
                }
                line_items.append(overage_item)
                subtotal += overage_total

        # Apply discount
        discount_amount = 0.0
        if acct.discount_percentage > 0:
            if acct.discount_expires_at is None or acct.discount_expires_at > now:
                discount_amount = subtotal * (acct.discount_percentage / 100.0)

        total = subtotal - discount_amount

        invoice = Invoice(
            invoice_id=invoice_id,
            account_id=account_id,
            period_start=period_start,
            period_end=period_end,
            line_items=line_items,
            subtotal=subtotal,
            tax=0.0,
            discount=discount_amount,
            total=round(total, 2),
            status="draft",
            due_date=due_date,
            created_at=now,
        )

        if self._use_db:
            try:
                row = InvoiceModel(
                    invoice_id=invoice_id,
                    account_id=account_id,
                    period_start=period_start,
                    period_end=period_end,
                    line_items=line_items,
                    subtotal=subtotal,
                    tax=0.0,
                    discount=discount_amount,
                    total=round(total, 2),
                    status="draft",
                    due_date=due_date,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Generated invoice %s for account %s", invoice_id, account_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for invoice %s: %s", invoice_id, exc)
                self._invoices[invoice_id] = invoice
        else:
            self._invoices[invoice_id] = invoice

        # Update next billing date
        if plan.billing_cycle == "annual":
            next_date = now + timedelta(days=365)
        else:
            next_date = now + timedelta(days=30)
        self.update_account(account_id, next_billing_date=next_date)

        return invoice

    def get_invoice(self, invoice_id: str) -> Optional[Invoice]:
        """Get a specific invoice."""
        if self._use_db:
            try:
                row = self.db.query(InvoiceModel).filter(
                    InvoiceModel.invoice_id == invoice_id
                ).first()
                if row:
                    return _invoice_from_row(row)
            except Exception as exc:
                logger.warning("DB read failed for invoice %s: %s", invoice_id, exc)

        return self._invoices.get(invoice_id)

    def list_invoices(
        self,
        account_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Invoice]:
        """List invoices, optionally filtered by account or status."""
        if self._use_db:
            try:
                q = self.db.query(InvoiceModel)
                if account_id:
                    q = q.filter(InvoiceModel.account_id == account_id)
                if status:
                    q = q.filter(InvoiceModel.status == status)
                rows = q.order_by(InvoiceModel.created_at.desc()).all()
                return [_invoice_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB list invoices failed: %s", exc)

        invoices = list(self._invoices.values())
        if account_id:
            invoices = [i for i in invoices if i.account_id == account_id]
        if status:
            invoices = [i for i in invoices if i.status == status]
        return invoices

    def void_invoice(self, invoice_id: str) -> Optional[Invoice]:
        """Void an invoice."""
        if self._use_db:
            try:
                row = self.db.query(InvoiceModel).filter(
                    InvoiceModel.invoice_id == invoice_id
                ).first()
                if row:
                    row.status = "void"
                    self.db.commit()
                    return _invoice_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB void invoice failed for %s: %s", invoice_id, exc)

        inv = self._invoices.get(invoice_id)
        if inv:
            inv.status = "void"
        return inv

    def mark_paid(
        self,
        invoice_id: str,
        payment_reference: str = "",
    ) -> Optional[Invoice]:
        """Mark an invoice as paid."""
        now = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(InvoiceModel).filter(
                    InvoiceModel.invoice_id == invoice_id
                ).first()
                if row:
                    row.status = "paid"
                    row.paid_at = now
                    row.payment_reference = payment_reference
                    self.db.commit()
                    return _invoice_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB mark_paid failed for %s: %s", invoice_id, exc)

        inv = self._invoices.get(invoice_id)
        if inv:
            inv.status = "paid"
            inv.paid_at = now
            inv.payment_reference = payment_reference
        return inv

    # ========== Payment Management ==========

    def record_payment(
        self,
        account_id: str,
        invoice_id: str,
        amount: float,
        method: str = "card",
    ) -> PaymentRecord:
        """Record a payment against an invoice."""
        payment_id = f"PAY-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        pay = PaymentRecord(
            payment_id=payment_id,
            account_id=account_id,
            invoice_id=invoice_id,
            amount=amount,
            method=method,
            status="completed",
            processed_at=now,
            created_at=now,
        )

        if self._use_db:
            try:
                row = PaymentRecordModel(
                    payment_id=payment_id,
                    account_id=account_id,
                    invoice_id=invoice_id,
                    amount=amount,
                    method=method,
                    status="completed",
                    processed_at=now,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Recorded payment %s for invoice %s", payment_id, invoice_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for payment %s: %s", payment_id, exc)
                self._payments.append(pay)
        else:
            self._payments.append(pay)

        # Mark the invoice as paid
        self.mark_paid(invoice_id, payment_reference=payment_id)

        # If account was past_due, reactivate
        acct = self.get_account(account_id)
        if acct and acct.status == "past_due":
            self.reactivate_account(account_id)

        return pay

    # ========== Revenue Analytics ==========

    def calculate_mrr(self) -> float:
        """Calculate Monthly Recurring Revenue across all active accounts."""
        active_accounts = self.list_accounts(status="active")
        mrr = 0.0

        for acct in active_accounts:
            plan = self.get_plan(acct.plan_id)
            if not plan:
                continue

            if plan.billing_model in ("per_endpoint", "per_device"):
                units = acct.current_endpoints
            elif plan.billing_model == "per_user":
                units = acct.current_users
            else:
                units = 0

            # Base price
            monthly_revenue = plan.base_price

            # Unit pricing
            included = min(units, plan.included_units)
            monthly_revenue += included * plan.per_unit_price

            # Overage
            overage = max(0, units - plan.included_units)
            if overage > 0:
                monthly_revenue += overage * plan.overage_price

            # Apply discount
            if acct.discount_percentage > 0:
                now = datetime.now(timezone.utc)
                if acct.discount_expires_at is None or acct.discount_expires_at > now:
                    monthly_revenue *= (1 - acct.discount_percentage / 100.0)

            # If annual, divide by 12
            if plan.billing_cycle == "annual":
                monthly_revenue /= 12.0

            mrr += monthly_revenue

        return round(mrr, 2)

    def calculate_arr(self) -> float:
        """Calculate Annual Recurring Revenue."""
        return round(self.calculate_mrr() * 12, 2)

    def get_revenue_forecast(self, months: int = 12) -> List[Dict[str, Any]]:
        """Forecast revenue for the next N months based on current MRR."""
        mrr = self.calculate_mrr()
        forecast = []
        now = datetime.now(timezone.utc)

        for i in range(1, months + 1):
            future_date = now + timedelta(days=30 * i)
            forecast.append({
                "month": i,
                "date": future_date.strftime("%Y-%m"),
                "projected_mrr": round(mrr, 2),
                "projected_arr": round(mrr * 12, 2),
                "cumulative_revenue": round(mrr * i, 2),
            })

        return forecast

    def get_churn_rate(self) -> float:
        """Calculate account churn rate (cancelled / total)."""
        all_accounts = self.list_accounts()
        if not all_accounts:
            return 0.0

        cancelled = len([a for a in all_accounts if a.status == "cancelled"])
        return round((cancelled / len(all_accounts)) * 100, 2)

    def get_arpa(self) -> float:
        """Calculate Average Revenue Per Account."""
        active_accounts = self.list_accounts(status="active")
        if not active_accounts:
            return 0.0

        mrr = self.calculate_mrr()
        return round(mrr / len(active_accounts), 2)

    def get_billing_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive billing dashboard data."""
        all_accounts = self.list_accounts()
        active_accounts = [a for a in all_accounts if a.status == "active"]
        overdue_invoices = self.list_invoices(status="overdue")
        paid_invoices = self.list_invoices(status="paid")

        # Revenue by plan
        revenue_by_plan: Dict[str, float] = {}
        for acct in active_accounts:
            plan = self.get_plan(acct.plan_id)
            if not plan:
                continue
            plan_name = plan.name
            if plan.billing_model in ("per_endpoint", "per_device"):
                units = acct.current_endpoints
            elif plan.billing_model == "per_user":
                units = acct.current_users
            else:
                units = 0

            rev = plan.base_price
            included = min(units, plan.included_units)
            rev += included * plan.per_unit_price
            overage = max(0, units - plan.included_units)
            if overage > 0:
                rev += overage * plan.overage_price

            revenue_by_plan[plan_name] = revenue_by_plan.get(plan_name, 0.0) + rev

        mrr = self.calculate_mrr()

        return {
            "mrr": mrr,
            "arr": round(mrr * 12, 2),
            "churn_rate": self.get_churn_rate(),
            "arpa": self.get_arpa(),
            "total_accounts": len(all_accounts),
            "active_accounts": len(active_accounts),
            "suspended_accounts": len([a for a in all_accounts if a.status == "suspended"]),
            "past_due_accounts": len([a for a in all_accounts if a.status == "past_due"]),
            "cancelled_accounts": len([a for a in all_accounts if a.status == "cancelled"]),
            "total_endpoints": sum(a.current_endpoints for a in active_accounts),
            "total_users": sum(a.current_users for a in active_accounts),
            "overdue_invoices": len(overdue_invoices),
            "overdue_amount": sum(i.total for i in overdue_invoices),
            "total_paid": sum(i.total for i in paid_invoices),
            "revenue_by_plan": revenue_by_plan,
        }

    def check_overdue_invoices(self) -> List[Invoice]:
        """Check and flag overdue invoices, updating account status."""
        now = datetime.now(timezone.utc)
        overdue = []

        all_invoices = self.list_invoices()
        for inv in all_invoices:
            if inv.status in ("draft", "sent") and inv.due_date and inv.due_date < now:
                # Mark invoice as overdue
                if self._use_db:
                    try:
                        row = self.db.query(InvoiceModel).filter(
                            InvoiceModel.invoice_id == inv.invoice_id
                        ).first()
                        if row:
                            row.status = "overdue"
                            self.db.commit()
                    except Exception as exc:
                        self.db.rollback()
                        logger.warning("DB overdue update failed: %s", exc)
                else:
                    inv.status = "overdue"

                # Flag account as past_due
                self.update_account(inv.account_id, status="past_due")
                inv.status = "overdue"
                overdue.append(inv)

        if overdue:
            logger.warning("Found %d overdue invoices", len(overdue))

        return overdue

    def apply_discount(
        self,
        account_id: str,
        percentage: float,
        reason: str = "",
        expires_at: Optional[datetime] = None,
    ) -> Optional[BillingAccount]:
        """Apply a discount to an account."""
        return self.update_account(
            account_id,
            discount_percentage=percentage,
            discount_reason=reason,
            discount_expires_at=expires_at,
        )
