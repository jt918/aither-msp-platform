"""
AITHER Platform - FinOps / IT Cost Optimization Engine Models

Tables for cost centers, cost entries, savings opportunities,
budget forecasts, vendor contracts, and cost alerts.
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
# Cost Centers
# ============================================================

class CostCenterModel(Base):
    """IT cost center tracking."""
    __tablename__ = "finops_cost_centers"

    id = Column(String(36), primary_key=True, default=_uuid)
    center_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    name = Column(String(300), nullable=False)
    category = Column(String(50), nullable=False, index=True)
    budget_monthly = Column(Float, default=0.0)
    actual_monthly = Column(Float, default=0.0)
    variance = Column(Float, default=0.0)
    owner = Column(String(200), default="")
    department = Column(String(200), default="")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_finops_cc_client_cat", "client_id", "category"),
    )


# ============================================================
# Cost Entries
# ============================================================

class CostEntryModel(Base):
    """Individual cost line items."""
    __tablename__ = "finops_cost_entries"

    id = Column(String(36), primary_key=True, default=_uuid)
    entry_id = Column(String(30), unique=True, nullable=False, index=True)
    center_id = Column(String(30), nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    description = Column(Text, default="")
    vendor = Column(String(300), default="")
    amount = Column(Float, default=0.0)
    currency = Column(String(10), default="USD")
    period = Column(String(20), default="")
    entry_type = Column(String(30), default="recurring")
    is_committed = Column(Boolean, default=False)
    contract_end_date = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_finops_ce_client_period", "client_id", "period"),
        Index("ix_finops_ce_vendor", "vendor"),
    )


# ============================================================
# Savings Opportunities
# ============================================================

class SavingsOpportunityModel(Base):
    """Identified cost optimization opportunities."""
    __tablename__ = "finops_savings_opportunities"

    id = Column(String(36), primary_key=True, default=_uuid)
    opportunity_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    category = Column(String(50), nullable=False, index=True)
    estimated_monthly_savings = Column(Float, default=0.0)
    estimated_annual_savings = Column(Float, default=0.0)
    effort_level = Column(String(20), default="medium")
    confidence = Column(Float, default=0.5)
    status = Column(String(30), default="identified", index=True)
    identified_at = Column(DateTime, default=func.now())
    implemented_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_finops_so_client_status", "client_id", "status"),
    )


# ============================================================
# Budget Forecasts
# ============================================================

class BudgetForecastModel(Base):
    """Budget vs actual tracking and forecasting."""
    __tablename__ = "finops_budget_forecasts"

    id = Column(String(36), primary_key=True, default=_uuid)
    forecast_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    period = Column(String(20), nullable=False)
    category = Column(String(50), default="")
    forecasted_amount = Column(Float, default=0.0)
    actual_amount = Column(Float, default=0.0)
    variance = Column(Float, default=0.0)
    trend = Column(String(20), default="stable")
    confidence = Column(Float, default=0.5)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_finops_bf_client_period", "client_id", "period"),
    )


# ============================================================
# Vendor Contracts
# ============================================================

class VendorContractModel(Base):
    """Vendor contract tracking for cost optimization."""
    __tablename__ = "finops_vendor_contracts"

    id = Column(String(36), primary_key=True, default=_uuid)
    contract_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    vendor_name = Column(String(300), nullable=False)
    service_description = Column(Text, default="")
    monthly_cost = Column(Float, default=0.0)
    annual_cost = Column(Float, default=0.0)
    contract_start = Column(DateTime, nullable=True)
    contract_end = Column(DateTime, nullable=True)
    auto_renew = Column(Boolean, default=False)
    notice_period_days = Column(Integer, default=30)
    seats_purchased = Column(Integer, default=0)
    seats_used = Column(Integer, default=0)
    utilization_pct = Column(Float, default=0.0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_finops_vc_client", "client_id"),
        Index("ix_finops_vc_end", "contract_end"),
    )


# ============================================================
# Cost Alerts
# ============================================================

class CostAlertModel(Base):
    """Cost-related alerts and notifications."""
    __tablename__ = "finops_cost_alerts"

    id = Column(String(36), primary_key=True, default=_uuid)
    alert_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    alert_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="medium")
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    amount = Column(Float, default=0.0)
    threshold = Column(Float, default=0.0)
    is_acknowledged = Column(Boolean, default=False)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_finops_ca_client_type", "client_id", "alert_type"),
    )
