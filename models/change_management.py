"""
AITHER Platform - Change Management Persistence Models

Tables for ITIL-aligned change management: change requests, approvals,
templates, post-implementation reviews, and blackout windows.
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
# Change Request
# ============================================================

class ChangeRequestModel(Base):
    """ITIL change request record."""
    __tablename__ = "cm_change_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    change_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    change_type = Column(String(20), default="normal", index=True)
    category = Column(String(30), default="other", index=True)
    priority = Column(String(20), default="medium", index=True)
    status = Column(String(20), default="draft", index=True)
    risk_level = Column(String(20), default="medium", index=True)
    risk_score = Column(Integer, default=0)
    impact_assessment = Column(Text, default="")
    rollback_plan = Column(Text, default="")
    implementation_plan = Column(Text, default="")
    testing_plan = Column(Text, default="")

    scheduled_start = Column(DateTime, nullable=True)
    scheduled_end = Column(DateTime, nullable=True)
    actual_start = Column(DateTime, nullable=True)
    actual_end = Column(DateTime, nullable=True)

    requested_by = Column(String(200), default="")
    assigned_to = Column(String(200), nullable=True)
    approved_by = Column(String(200), nullable=True)

    approvers_required = Column(JSON, default=list)
    approvals_received = Column(JSON, default=list)
    affected_cis = Column(JSON, default=list)
    related_tickets = Column(JSON, default=list)

    pir_completed = Column(Boolean, default=False)
    pir_notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_cm_cr_client_status", "client_id", "status"),
        Index("ix_cm_cr_type_priority", "change_type", "priority"),
    )


# ============================================================
# Approval Record
# ============================================================

class ApprovalRecordModel(Base):
    """Approval decision for a change request."""
    __tablename__ = "cm_approval_records"

    id = Column(String(36), primary_key=True, default=_uuid)
    approval_id = Column(String(30), unique=True, nullable=False, index=True)
    change_id = Column(String(30), nullable=False, index=True)
    approver = Column(String(200), nullable=False)
    decision = Column(String(20), default="deferred")
    comments = Column(Text, default="")
    decided_at = Column(DateTime, default=func.now())


# ============================================================
# Change Template
# ============================================================

class ChangeTemplateModel(Base):
    """Pre-built change template."""
    __tablename__ = "cm_change_templates"

    id = Column(String(36), primary_key=True, default=_uuid)
    template_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(300), nullable=False)
    description = Column(Text, default="")
    change_type = Column(String(20), default="standard")
    category = Column(String(30), default="other")
    default_risk_level = Column(String(20), default="low")
    steps = Column(JSON, default=list)
    approvers_required = Column(JSON, default=list)
    estimated_duration_minutes = Column(Integer, default=30)
    rollback_steps = Column(JSON, default=list)


# ============================================================
# Post-Implementation Review
# ============================================================

class PIRModel(Base):
    """Post-implementation review record."""
    __tablename__ = "cm_pirs"

    id = Column(String(36), primary_key=True, default=_uuid)
    pir_id = Column(String(30), unique=True, nullable=False, index=True)
    change_id = Column(String(30), nullable=False, index=True)
    was_successful = Column(Boolean, default=True)
    objectives_met = Column(Boolean, default=True)
    issues_encountered = Column(JSON, default=list)
    lessons_learned = Column(JSON, default=list)
    follow_up_actions = Column(JSON, default=list)
    reviewed_by = Column(String(200), default="")
    reviewed_at = Column(DateTime, default=func.now())


# ============================================================
# Blackout Window
# ============================================================

class BlackoutWindowModel(Base):
    """Maintenance blackout window."""
    __tablename__ = "cm_blackout_windows"

    id = Column(String(36), primary_key=True, default=_uuid)
    window_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    name = Column(String(300), default="")
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    reason = Column(Text, default="")
    is_recurring = Column(Boolean, default=False)
    recurrence_pattern = Column(String(100), nullable=True)
