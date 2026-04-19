"""
AITHER Platform - Problem Management Persistence Models

Tables for ITIL problem management: problem records, known errors,
and root cause analyses.
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
# Problem Record
# ============================================================

class ProblemRecordModel(Base):
    """ITIL problem record."""
    __tablename__ = "pm_problem_records"

    id = Column(String(36), primary_key=True, default=_uuid)
    problem_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    status = Column(String(30), default="logged", index=True)
    priority = Column(String(20), default="medium", index=True)
    category = Column(String(30), default="other", index=True)
    root_cause = Column(Text, default="")
    workaround = Column(Text, default="")
    resolution = Column(Text, default="")
    affected_services = Column(JSON, default=list)
    related_incidents = Column(JSON, default=list)
    assigned_to = Column(String(200), nullable=True)
    impact_assessment = Column(Text, default="")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
    resolved_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_pm_pr_client_status", "client_id", "status"),
        Index("ix_pm_pr_priority_category", "priority", "category"),
    )


# ============================================================
# Known Error
# ============================================================

class KnownErrorModel(Base):
    """Known Error Database entry."""
    __tablename__ = "pm_known_errors"

    id = Column(String(36), primary_key=True, default=_uuid)
    ke_id = Column(String(30), unique=True, nullable=False, index=True)
    problem_id = Column(String(30), default="", index=True)
    title = Column(String(500), nullable=False)
    error_description = Column(Text, default="")
    root_cause = Column(Text, default="")
    workaround = Column(Text, default="")
    permanent_fix_status = Column(String(20), default="identified", index=True)
    symptoms = Column(JSON, default=list)
    affected_cis = Column(JSON, default=list)
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_pm_ke_fix_status", "permanent_fix_status"),
    )


# ============================================================
# Root Cause Analysis
# ============================================================

class RootCauseAnalysisModel(Base):
    """Root cause analysis record."""
    __tablename__ = "pm_root_cause_analyses"

    id = Column(String(36), primary_key=True, default=_uuid)
    rca_id = Column(String(30), unique=True, nullable=False, index=True)
    problem_id = Column(String(30), default="", index=True)
    method = Column(String(20), default="five_whys")
    analysis_data = Column(JSON, default=dict)
    findings = Column(JSON, default=list)
    contributing_factors = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)
    analyzed_by = Column(String(200), default="")
    analyzed_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_pm_rca_problem", "problem_id"),
    )
