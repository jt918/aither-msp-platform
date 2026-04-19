"""
AITHER Platform - Compliance Framework Persistence Models (G-47)

Tables for compliance framework templates, controls, assessments,
and findings used by the MSP compliance framework service.
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
# Compliance Framework Templates
# ============================================================

class ComplianceFrameworkTemplateModel(Base):
    """Pre-built compliance framework template (HIPAA, SOC2, etc.)."""
    __tablename__ = "compliance_framework_templates"

    id = Column(String(36), primary_key=True, default=_uuid)
    framework_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    version = Column(String(50), default="")
    description = Column(Text, default="")
    total_controls = Column(Integer, default=0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class ComplianceControlTemplateModel(Base):
    """Individual control within a compliance framework template."""
    __tablename__ = "compliance_control_templates"

    id = Column(String(36), primary_key=True, default=_uuid)
    control_id = Column(String(30), unique=True, nullable=False, index=True)
    framework_id = Column(String(30), nullable=False, index=True)
    control_number = Column(String(50), nullable=False)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    category = Column(String(100), default="", index=True)
    requirement_text = Column(Text, default="")
    evidence_types = Column(JSON, default=list)
    automated_check = Column(Boolean, default=False)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_ctrl_tmpl_fw_cat", "framework_id", "category"),
    )


# ============================================================
# Compliance Assessments
# ============================================================

class ComplianceAssessmentModel(Base):
    """Client compliance assessment against a framework."""
    __tablename__ = "compliance_assessments"

    id = Column(String(36), primary_key=True, default=_uuid)
    assessment_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    framework_id = Column(String(30), nullable=False, index=True)
    assessed_by = Column(String(200), default="")
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)

    overall_score = Column(Float, default=0.0)
    controls_compliant = Column(Integer, default=0)
    controls_non_compliant = Column(Integer, default=0)
    controls_partial = Column(Integer, default=0)
    controls_na = Column(Integer, default=0)
    controls_not_assessed = Column(Integer, default=0)

    # Full map of control_id -> status
    control_statuses = Column(JSON, default=dict)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_ca_client_fw", "client_id", "framework_id"),
    )


# ============================================================
# Compliance Findings
# ============================================================

class ComplianceFindingModel(Base):
    """Finding from a compliance assessment."""
    __tablename__ = "compliance_assessment_findings"

    id = Column(String(36), primary_key=True, default=_uuid)
    finding_id = Column(String(30), unique=True, nullable=False, index=True)
    assessment_id = Column(String(30), nullable=False, index=True)
    control_id = Column(String(30), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    description = Column(Text, default="")
    recommendation = Column(Text, default="")
    due_date = Column(DateTime, nullable=True)
    status = Column(String(20), default="open", index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_cf_assess_status", "assessment_id", "status"),
    )
