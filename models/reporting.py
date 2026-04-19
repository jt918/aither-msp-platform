"""
AITHER Platform - MSP Reporting Engine Persistence Models (G-46)

Tables for report templates, sections, generated reports,
KPI snapshots, and business intelligence insights.
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
# Report Templates
# ============================================================

class ReportTemplateModel(Base):
    """MSP report template definition."""
    __tablename__ = "msp_report_templates"

    id = Column(String(36), primary_key=True, default=_uuid)
    template_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    report_type = Column(String(50), nullable=False, index=True)
    description = Column(Text, default="")
    sections = Column(JSON, default=list)
    schedule_cron = Column(String(100), nullable=True)
    recipients = Column(JSON, default=list)
    format = Column(String(20), default="pdf")
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_msp_rt_type_active", "report_type", "is_active"),
    )


# ============================================================
# Report Sections
# ============================================================

class ReportSectionModel(Base):
    """Individual section within a report template."""
    __tablename__ = "msp_report_sections"

    id = Column(String(36), primary_key=True, default=_uuid)
    section_id = Column(String(30), unique=True, nullable=False, index=True)
    template_id = Column(String(30), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    data_source = Column(String(100), nullable=False)
    query_type = Column(String(30), default="summary")
    filters = Column(JSON, default=dict)
    sort_by = Column(String(100), nullable=True)
    limit = Column(Integer, nullable=True)
    order_index = Column(Integer, default=0)

    created_at = Column(DateTime, default=func.now())


# ============================================================
# Generated Reports
# ============================================================

class GeneratedReportModel(Base):
    """A report that has been generated from a template."""
    __tablename__ = "msp_generated_reports"

    id = Column(String(36), primary_key=True, default=_uuid)
    report_id = Column(String(30), unique=True, nullable=False, index=True)
    template_id = Column(String(30), nullable=False, index=True)
    client_id = Column(String(100), nullable=True, index=True)
    title = Column(String(300), nullable=False)
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)
    generated_at = Column(DateTime, default=func.now())
    format = Column(String(20), default="pdf")
    data = Column(JSON, default=dict)
    file_path = Column(Text, nullable=True)
    status = Column(String(20), default="generating", index=True)
    sent_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_msp_gr_status_date", "status", "generated_at"),
        Index("ix_msp_gr_client_date", "client_id", "generated_at"),
    )


# ============================================================
# KPI Snapshots
# ============================================================

class KPISnapshotModel(Base):
    """Point-in-time KPI measurement."""
    __tablename__ = "msp_kpi_snapshots"

    id = Column(String(36), primary_key=True, default=_uuid)
    metric_id = Column(String(30), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    category = Column(String(30), nullable=False, index=True)
    current_value = Column(Float, default=0.0)
    previous_value = Column(Float, default=0.0)
    target_value = Column(Float, default=0.0)
    trend = Column(String(10), default="flat")
    unit = Column(String(20), default="count")
    snapshot_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_msp_kpi_cat_date", "category", "snapshot_at"),
    )


# ============================================================
# Business Intelligence Insights
# ============================================================

class BusinessIntelligenceModel(Base):
    """AI-generated business intelligence insight."""
    __tablename__ = "msp_business_intelligence"

    id = Column(String(36), primary_key=True, default=_uuid)
    bi_id = Column(String(30), unique=True, nullable=False, index=True)
    insight_type = Column(String(50), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    impact_value = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    affected_clients = Column(JSON, default=list)
    recommended_action = Column(Text, default="")
    generated_at = Column(DateTime, default=func.now())
    is_resolved = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_msp_bi_type_resolved", "insight_type", "is_resolved"),
    )
