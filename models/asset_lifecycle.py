"""
AITHER Platform - IT Asset Lifecycle Management Persistence Models

Tables for IT assets, software licenses, maintenance records,
depreciation schedules, asset requests, and disposal records.
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


class ITAssetModel(Base):
    """IT Asset tracked through full lifecycle."""
    __tablename__ = "it_assets"

    id = Column(String(36), primary_key=True, default=_uuid)
    asset_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    asset_tag = Column(String(100), default="", index=True)
    name = Column(String(300), nullable=False)
    category = Column(String(30), nullable=False, index=True)
    asset_type = Column(String(30), nullable=False, index=True)
    manufacturer = Column(String(200), default="")
    model = Column(String(200), default="")
    serial_number = Column(String(200), default="", index=True)
    purchase_date = Column(DateTime, nullable=True)
    purchase_price = Column(Float, default=0.0)
    vendor = Column(String(200), default="")
    warranty_expires = Column(DateTime, nullable=True)
    lifecycle_status = Column(String(20), default="ordered", index=True)
    assigned_to = Column(String(200), nullable=True)
    location = Column(String(300), default="")
    department = Column(String(200), default="")
    notes = Column(Text, default="")
    custom_fields = Column(JSON, default=dict)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_it_asset_client_status", "client_id", "lifecycle_status"),
        Index("ix_it_asset_category_type", "category", "asset_type"),
    )


class SoftwareLicenseModel(Base):
    """Software license linked to an IT asset."""
    __tablename__ = "software_licenses"

    id = Column(String(36), primary_key=True, default=_uuid)
    license_id = Column(String(30), unique=True, nullable=False, index=True)
    asset_id = Column(String(30), nullable=True, index=True)
    software_name = Column(String(300), nullable=False)
    license_key = Column(String(500), default="")
    license_type = Column(String(30), default="per_seat")
    seats_purchased = Column(Integer, default=1)
    seats_used = Column(Integer, default=0)
    renewal_date = Column(DateTime, nullable=True)
    annual_cost = Column(Float, default=0.0)
    vendor = Column(String(200), default="")
    is_compliant = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class MaintenanceRecordModel(Base):
    """Maintenance record for an IT asset."""
    __tablename__ = "maintenance_records"

    id = Column(String(36), primary_key=True, default=_uuid)
    record_id = Column(String(30), unique=True, nullable=False, index=True)
    asset_id = Column(String(30), nullable=False, index=True)
    maintenance_type = Column(String(30), nullable=False)
    description = Column(Text, default="")
    cost = Column(Float, default=0.0)
    performed_by = Column(String(200), default="")
    scheduled_date = Column(DateTime, nullable=True)
    completed_date = Column(DateTime, nullable=True)
    next_maintenance = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())


class DepreciationScheduleModel(Base):
    """Depreciation schedule for an IT asset."""
    __tablename__ = "depreciation_schedules"

    id = Column(String(36), primary_key=True, default=_uuid)
    schedule_id = Column(String(30), unique=True, nullable=False, index=True)
    asset_id = Column(String(30), nullable=False, index=True)
    method = Column(String(30), default="straight_line")
    useful_life_years = Column(Integer, default=5)
    salvage_value = Column(Float, default=0.0)
    current_book_value = Column(Float, default=0.0)
    depreciation_per_period = Column(Float, default=0.0)
    periods_remaining = Column(Integer, default=0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class AssetRequestModel(Base):
    """Asset procurement request."""
    __tablename__ = "asset_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    request_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    requester_name = Column(String(200), nullable=False)
    asset_type = Column(String(30), nullable=False)
    justification = Column(Text, default="")
    quantity = Column(Integer, default=1)
    estimated_cost = Column(Float, default=0.0)
    status = Column(String(20), default="submitted", index=True)
    approved_by = Column(String(200), nullable=True)
    approved_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class DisposalRecordModel(Base):
    """Disposal record for a retired IT asset."""
    __tablename__ = "disposal_records"

    id = Column(String(36), primary_key=True, default=_uuid)
    disposal_id = Column(String(30), unique=True, nullable=False, index=True)
    asset_id = Column(String(30), nullable=False, index=True)
    disposal_method = Column(String(30), nullable=False)
    disposal_date = Column(DateTime, nullable=True)
    certificate_of_destruction = Column(String(500), default="")
    data_wiped = Column(Boolean, default=False)
    wiped_method = Column(String(200), default="")
    proceeds = Column(Float, default=0.0)

    created_at = Column(DateTime, default=func.now())
