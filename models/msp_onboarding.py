"""
AITHER Platform - MSP Client Onboarding Persistence Models

Tables for onboarding templates, workflows, phases, tasks,
and client pre-flight checklists.
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
# Onboarding Templates
# ============================================================

class OnboardingTemplateModel(Base):
    """Reusable onboarding template definition."""
    __tablename__ = "msp_onboarding_templates"

    id = Column(String(36), primary_key=True, default=_uuid)
    template_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    plan_type = Column(String(30), default="standard", index=True)
    phases = Column(JSON, default=list)
    estimated_duration_days = Column(Integer, default=14)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Onboarding Workflows
# ============================================================

class OnboardingWorkflowModel(Base):
    """Client onboarding workflow instance."""
    __tablename__ = "msp_onboarding_workflows"

    id = Column(String(36), primary_key=True, default=_uuid)
    workflow_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    company_name = Column(String(300), nullable=False)
    primary_contact = Column(String(200), default="")
    plan_id = Column(String(30), default="", index=True)
    status = Column(String(20), default="initiated", index=True)
    current_phase = Column(Integer, default=1)
    assigned_technician = Column(String(200), default="")

    started_at = Column(DateTime, default=func.now())
    target_completion = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_msp_ob_wf_client_status", "client_id", "status"),
    )


# ============================================================
# Onboarding Phases
# ============================================================

class OnboardingPhaseModel(Base):
    """Phase within an onboarding workflow."""
    __tablename__ = "msp_onboarding_phases"

    id = Column(String(36), primary_key=True, default=_uuid)
    phase_id = Column(String(30), unique=True, nullable=False, index=True)
    workflow_id = Column(String(30), nullable=False, index=True)
    phase_number = Column(Integer, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    status = Column(String(20), default="pending", index=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    dependencies = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_msp_ob_ph_wf_num", "workflow_id", "phase_number"),
    )


# ============================================================
# Onboarding Tasks
# ============================================================

class OnboardingTaskModel(Base):
    """Task within an onboarding phase."""
    __tablename__ = "msp_onboarding_tasks"

    id = Column(String(36), primary_key=True, default=_uuid)
    task_id = Column(String(30), unique=True, nullable=False, index=True)
    phase_id = Column(String(30), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    task_type = Column(String(20), default="manual")
    status = Column(String(20), default="pending", index=True)
    assigned_to = Column(String(200), default="")
    automated_action = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Client Checklists
# ============================================================

class ClientChecklistModel(Base):
    """Pre-flight checklist tied to an onboarding workflow."""
    __tablename__ = "msp_onboarding_checklists"

    id = Column(String(36), primary_key=True, default=_uuid)
    checklist_id = Column(String(30), unique=True, nullable=False, index=True)
    workflow_id = Column(String(30), nullable=False, index=True)
    items = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
