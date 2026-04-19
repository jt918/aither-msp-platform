"""
AITHER Platform - MSP Billing Engine Persistence Models (G-46)

Tables for billing plans, accounts, invoices, usage records,
and payment records for multi-tenant MSP billing.
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON,
    Index,
)
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


# ============================================================
# Billing Plans
# ============================================================

class BillingPlanModel(Base):
    """MSP billing plan definition."""
    __tablename__ = "msp_billing_plans"

    id = Column(String(36), primary_key=True, default=_uuid)
    plan_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    billing_model = Column(String(30), nullable=False, index=True)
    # per_endpoint, per_user, per_device, flat
    base_price = Column(Float, default=0.0)
    per_unit_price = Column(Float, default=0.0)
    included_units = Column(Integer, default=0)
    overage_price = Column(Float, default=0.0)
    billing_cycle = Column(String(20), default="monthly")  # monthly, annual
    features = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_msp_bp_model_active", "billing_model", "is_active"),
    )


# ============================================================
# Billing Accounts
# ============================================================

class BillingAccountModel(Base):
    """MSP tenant billing account."""
    __tablename__ = "msp_billing_accounts"

    id = Column(String(36), primary_key=True, default=_uuid)
    account_id = Column(String(30), unique=True, nullable=False, index=True)
    tenant_id = Column(String(100), nullable=False, index=True)
    company_name = Column(String(300), nullable=False)
    plan_id = Column(String(30), nullable=False, index=True)
    billing_email = Column(String(300), default="")
    billing_address = Column(Text, default="")
    payment_method_id = Column(String(100), default="")
    current_endpoints = Column(Integer, default=0)
    current_users = Column(Integer, default=0)
    status = Column(String(20), default="active", index=True)
    # active, suspended, cancelled, past_due
    discount_percentage = Column(Float, default=0.0)
    discount_reason = Column(Text, default="")
    discount_expires_at = Column(DateTime, nullable=True)

    next_billing_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_msp_ba_tenant_status", "tenant_id", "status"),
    )


# ============================================================
# Invoices
# ============================================================

class InvoiceModel(Base):
    """MSP billing invoice."""
    __tablename__ = "msp_billing_invoices"

    id = Column(String(36), primary_key=True, default=_uuid)
    invoice_id = Column(String(30), unique=True, nullable=False, index=True)
    account_id = Column(String(30), nullable=False, index=True)
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)
    line_items = Column(JSON, default=list)
    subtotal = Column(Float, default=0.0)
    tax = Column(Float, default=0.0)
    discount = Column(Float, default=0.0)
    total = Column(Float, default=0.0)
    status = Column(String(20), default="draft", index=True)
    # draft, sent, paid, overdue, void
    due_date = Column(DateTime, nullable=True)
    paid_at = Column(DateTime, nullable=True)
    payment_reference = Column(String(200), default="")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_msp_inv_account_status", "account_id", "status"),
    )


# ============================================================
# Invoice Line Items
# ============================================================

class InvoiceLineItemModel(Base):
    """Individual line item on an invoice."""
    __tablename__ = "msp_billing_line_items"

    id = Column(String(36), primary_key=True, default=_uuid)
    invoice_id = Column(String(30), nullable=False, index=True)
    description = Column(Text, default="")
    quantity = Column(Float, default=0.0)
    unit_price = Column(Float, default=0.0)
    total = Column(Float, default=0.0)
    item_type = Column(String(30), default="base")
    # base, endpoint, user, overage, addon

    created_at = Column(DateTime, default=func.now())


# ============================================================
# Usage Records
# ============================================================

class UsageRecordModel(Base):
    """Usage tracking record for billing."""
    __tablename__ = "msp_billing_usage"

    id = Column(String(36), primary_key=True, default=_uuid)
    record_id = Column(String(30), unique=True, nullable=False, index=True)
    account_id = Column(String(30), nullable=False, index=True)
    metric = Column(String(50), nullable=False)
    # endpoints, users, scans, incidents
    count = Column(Integer, default=0)
    recorded_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_msp_usage_account_metric", "account_id", "metric"),
    )


# ============================================================
# Payment Records
# ============================================================

class PaymentRecordModel(Base):
    """Payment record for an invoice."""
    __tablename__ = "msp_billing_payments"

    id = Column(String(36), primary_key=True, default=_uuid)
    payment_id = Column(String(30), unique=True, nullable=False, index=True)
    account_id = Column(String(30), nullable=False, index=True)
    invoice_id = Column(String(30), nullable=False, index=True)
    amount = Column(Float, default=0.0)
    method = Column(String(50), default="")
    status = Column(String(20), default="pending")
    # pending, completed, failed, refunded
    processed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_msp_pay_account_invoice", "account_id", "invoice_id"),
    )
