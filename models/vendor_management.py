"""
AITHER Platform - Vendor Management Persistence Models

Tables for vendors, vendor contracts, vendor reviews,
procurement requests, and vendor risk assessments.

Provides MSP-grade vendor lifecycle management with full audit trail.
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
# Vendor
# ============================================================

class VendorModel(Base):
    """Technology vendor record."""
    __tablename__ = "vendors"

    id = Column(String(36), primary_key=True, default=_uuid)
    vendor_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(300), nullable=False, index=True)
    category = Column(String(30), nullable=False, index=True)
    contact_name = Column(String(200), default="")
    contact_email = Column(String(200), default="")
    contact_phone = Column(String(50), default="")
    website = Column(String(500), default="")
    account_number = Column(String(100), default="")
    account_rep = Column(String(200), default="")
    status = Column(String(20), default="active", index=True)
    risk_tier = Column(String(20), default="low", index=True)
    performance_score = Column(Float, default=0.0)
    total_spend_ytd = Column(Float, default=0.0)
    payment_terms = Column(String(100), default="net30")
    notes = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_vendor_category_status", "category", "status"),
    )


# ============================================================
# Vendor Contract
# ============================================================

class VendorContractModel(Base):
    """Vendor contract record."""
    __tablename__ = "vendor_contracts"

    id = Column(String(36), primary_key=True, default=_uuid)
    contract_id = Column(String(30), unique=True, nullable=False, index=True)
    vendor_id = Column(String(30), nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    title = Column(String(300), nullable=False)
    contract_type = Column(String(30), nullable=False)
    value_monthly = Column(Float, default=0.0)
    value_annual = Column(Float, default=0.0)
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    auto_renew = Column(Boolean, default=False)
    cancellation_notice_days = Column(Integer, default=30)
    sla_terms = Column(JSON, default=dict)
    deliverables = Column(JSON, default=list)
    status = Column(String(20), default="draft", index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_vcontract_vendor_status", "vendor_id", "status"),
    )


# ============================================================
# Vendor Review
# ============================================================

class VendorReviewModel(Base):
    """Vendor performance review."""
    __tablename__ = "vendor_reviews"

    id = Column(String(36), primary_key=True, default=_uuid)
    review_id = Column(String(30), unique=True, nullable=False, index=True)
    vendor_id = Column(String(30), nullable=False, index=True)
    review_period = Column(String(50), default="")
    quality_score = Column(Float, default=0.0)
    delivery_score = Column(Float, default=0.0)
    communication_score = Column(Float, default=0.0)
    value_score = Column(Float, default=0.0)
    overall_score = Column(Float, default=0.0)
    strengths = Column(JSON, default=list)
    weaknesses = Column(JSON, default=list)
    recommendation = Column(Text, default="")
    reviewed_by = Column(String(200), default="")
    reviewed_at = Column(DateTime, default=func.now())

    created_at = Column(DateTime, default=func.now())


# ============================================================
# Procurement Request
# ============================================================

class ProcurementRequestModel(Base):
    """Procurement request record."""
    __tablename__ = "procurement_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    request_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    vendor_id = Column(String(30), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    items = Column(JSON, default=list)
    estimated_cost = Column(Float, default=0.0)
    status = Column(String(20), default="draft", index=True)
    requested_by = Column(String(200), default="")
    approved_by = Column(String(200), default="")
    po_number = Column(String(100), default="")
    ordered_at = Column(DateTime, nullable=True)
    received_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_procurement_vendor_status", "vendor_id", "status"),
    )


# ============================================================
# Vendor Risk
# ============================================================

class VendorRiskModel(Base):
    """Vendor risk assessment."""
    __tablename__ = "vendor_risks"

    id = Column(String(36), primary_key=True, default=_uuid)
    risk_id = Column(String(30), unique=True, nullable=False, index=True)
    vendor_id = Column(String(30), nullable=False, index=True)
    risk_type = Column(String(30), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    description = Column(Text, default="")
    mitigation = Column(Text, default="")
    status = Column(String(20), default="identified", index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_vrisk_vendor_type", "vendor_id", "risk_type"),
    )
