"""
AITHER Platform - Disaster Recovery Orchestration Persistence Models

Tables for DR plans, DR drills, and failover events.

Provides MSP-grade DR orchestration with full audit trail.
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
# DR Plan
# ============================================================

class DRPlanModel(Base):
    """Disaster Recovery plan definition."""
    __tablename__ = "dr_plans"

    id = Column(String(36), primary_key=True, default=_uuid)
    plan_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    tier = Column(String(30), default="tier3_normal")  # tier1_critical/tier2_important/tier3_normal
    rto_minutes = Column(Integer, default=240)
    rpo_minutes = Column(Integer, default=60)
    systems_covered = Column(JSON, default=list)
    runbook_steps = Column(JSON, default=list)
    dependencies = Column(JSON, default=list)
    contacts = Column(JSON, default=list)
    last_tested_at = Column(DateTime, nullable=True)
    test_result = Column(String(30), default="")
    status = Column(String(20), default="draft")  # draft/active/testing/activated/suspended

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_dr_plan_client_tier", "client_id", "tier"),
        Index("ix_dr_plan_status", "status"),
    )


# ============================================================
# DR Drill
# ============================================================

class DRDrillModel(Base):
    """DR drill / exercise record."""
    __tablename__ = "dr_drills"

    id = Column(String(36), primary_key=True, default=_uuid)
    drill_id = Column(String(30), unique=True, nullable=False, index=True)
    plan_id = Column(String(30), nullable=False, index=True)
    drill_type = Column(String(20), default="tabletop")  # tabletop/partial/full/unannounced
    status = Column(String(20), default="scheduled")  # scheduled/in_progress/completed/failed/cancelled
    scheduled_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    participants = Column(JSON, default=list)
    steps_completed = Column(Integer, default=0)
    steps_total = Column(Integer, default=0)
    rto_achieved_minutes = Column(Float, nullable=True)
    rpo_achieved_minutes = Column(Float, nullable=True)
    rto_met = Column(Boolean, nullable=True)
    rpo_met = Column(Boolean, nullable=True)
    findings = Column(JSON, default=list)
    lessons_learned = Column(JSON, default=list)
    score = Column(Integer, default=0)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_dr_drill_plan_status", "plan_id", "status"),
    )


# ============================================================
# Failover Event
# ============================================================

class FailoverEventModel(Base):
    """Failover event record."""
    __tablename__ = "dr_failover_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    event_id = Column(String(30), unique=True, nullable=False, index=True)
    plan_id = Column(String(30), nullable=False, index=True)
    trigger = Column(String(30), default="manual")  # manual/automated/monitoring_alert
    status = Column(String(20), default="initiated")  # initiated/in_progress/completed/failed/rolled_back
    systems_failed_over = Column(JSON, default=list)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    rto_actual_minutes = Column(Float, nullable=True)
    data_loss_minutes = Column(Float, nullable=True)
    incident_id = Column(String(100), default="")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_dr_failover_plan_status", "plan_id", "status"),
    )
