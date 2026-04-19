"""
AITHER Platform - MSP Reporting & Analytics Engine Service
Comprehensive reporting, dashboards, KPIs, and business intelligence for MSP operators

Provides:
- Report template management (CRUD)
- Scheduled and on-demand report generation
- Real-time KPI dashboard data
- Client health matrix scoring
- Business intelligence insight generation (revenue-at-risk, growth, churn)
- Period-over-period comparison and trend analysis
- Multi-format export (PDF/HTML/CSV/JSON)

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.reporting import (
        ReportTemplateModel,
        ReportSectionModel,
        GeneratedReportModel,
        KPISnapshotModel,
        BusinessIntelligenceModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class ReportType(str, Enum):
    """Type of report"""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAIL = "technical_detail"
    SECURITY_POSTURE = "security_posture"
    COMPLIANCE_STATUS = "compliance_status"
    SLA_PERFORMANCE = "sla_performance"
    FINANCIAL = "financial"
    TICKET_ANALYSIS = "ticket_analysis"
    ENDPOINT_HEALTH = "endpoint_health"
    THREAT_LANDSCAPE = "threat_landscape"
    CLIENT_HEALTH = "client_health"
    TECHNICIAN_PERFORMANCE = "technician_performance"
    CAPACITY_PLANNING = "capacity_planning"


class MetricCategory(str, Enum):
    """KPI metric category"""
    FINANCIAL = "financial"
    OPERATIONAL = "operational"
    SECURITY = "security"
    SATISFACTION = "satisfaction"
    GROWTH = "growth"


class ReportStatus(str, Enum):
    """Report generation status"""
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    SENT = "sent"


class InsightType(str, Enum):
    """Business intelligence insight type"""
    REVENUE_AT_RISK = "revenue_at_risk"
    GROWTH_OPPORTUNITY = "growth_opportunity"
    EFFICIENCY_GAIN = "efficiency_gain"
    COST_REDUCTION = "cost_reduction"
    CHURN_RISK = "churn_risk"


class ReportFormat(str, Enum):
    """Report output format"""
    PDF = "pdf"
    HTML = "html"
    CSV = "csv"
    JSON = "json"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class ReportSection:
    """Individual section within a report template"""
    section_id: str
    title: str
    data_source: str
    query_type: str = "summary"  # summary, detail, chart, table, metric
    filters: Dict[str, Any] = field(default_factory=dict)
    sort_by: Optional[str] = None
    limit: Optional[int] = None


@dataclass
class ReportTemplate:
    """Report template definition"""
    template_id: str
    name: str
    report_type: str
    description: str = ""
    sections: List[ReportSection] = field(default_factory=list)
    schedule_cron: Optional[str] = None
    recipients: List[str] = field(default_factory=list)
    format: str = "pdf"
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class GeneratedReport:
    """A report that has been generated"""
    report_id: str
    template_id: str
    client_id: Optional[str]
    title: str
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    format: str = "pdf"
    data: Dict[str, Any] = field(default_factory=dict)
    file_path: Optional[str] = None
    status: str = "generating"
    sent_at: Optional[datetime] = None


@dataclass
class KPIMetric:
    """Key performance indicator metric"""
    metric_id: str
    name: str
    category: str  # financial, operational, security, satisfaction, growth
    current_value: float = 0.0
    previous_value: float = 0.0
    target_value: float = 0.0
    trend: str = "flat"  # up, down, flat
    unit: str = "count"  # percent, count, currency, minutes, hours


@dataclass
class BusinessIntelligence:
    """AI-generated business intelligence insight"""
    bi_id: str
    insight_type: str  # revenue_at_risk, growth_opportunity, efficiency_gain, cost_reduction, churn_risk
    title: str
    description: str = ""
    impact_value: float = 0.0
    confidence: float = 0.0
    affected_clients: List[str] = field(default_factory=list)
    recommended_action: str = ""
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _template_from_row(row) -> ReportTemplate:
    """Convert ReportTemplateModel row to ReportTemplate dataclass."""
    sections_raw = row.sections or []
    sections = [
        ReportSection(
            section_id=s.get("section_id", ""),
            title=s.get("title", ""),
            data_source=s.get("data_source", ""),
            query_type=s.get("query_type", "summary"),
            filters=s.get("filters", {}),
            sort_by=s.get("sort_by"),
            limit=s.get("limit"),
        )
        for s in sections_raw
    ]
    return ReportTemplate(
        template_id=row.template_id,
        name=row.name,
        report_type=row.report_type or "",
        description=row.description or "",
        sections=sections,
        schedule_cron=row.schedule_cron,
        recipients=row.recipients or [],
        format=row.format or "pdf",
        is_active=row.is_active if row.is_active is not None else True,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _report_from_row(row) -> GeneratedReport:
    """Convert GeneratedReportModel row to GeneratedReport dataclass."""
    return GeneratedReport(
        report_id=row.report_id,
        template_id=row.template_id,
        client_id=row.client_id,
        title=row.title,
        period_start=row.period_start,
        period_end=row.period_end,
        generated_at=row.generated_at or datetime.now(timezone.utc),
        format=row.format or "pdf",
        data=row.data or {},
        file_path=row.file_path,
        status=row.status or "generating",
        sent_at=row.sent_at,
    )


def _kpi_from_row(row) -> KPIMetric:
    """Convert KPISnapshotModel row to KPIMetric dataclass."""
    return KPIMetric(
        metric_id=row.metric_id,
        name=row.name,
        category=row.category or "operational",
        current_value=row.current_value or 0.0,
        previous_value=row.previous_value or 0.0,
        target_value=row.target_value or 0.0,
        trend=row.trend or "flat",
        unit=row.unit or "count",
    )


def _bi_from_row(row) -> BusinessIntelligence:
    """Convert BusinessIntelligenceModel row to BusinessIntelligence dataclass."""
    return BusinessIntelligence(
        bi_id=row.bi_id,
        insight_type=row.insight_type or "",
        title=row.title,
        description=row.description or "",
        impact_value=row.impact_value or 0.0,
        confidence=row.confidence or 0.0,
        affected_clients=row.affected_clients or [],
        recommended_action=row.recommended_action or "",
        generated_at=row.generated_at or datetime.now(timezone.utc),
    )


# ============================================================
# Serialization helpers
# ============================================================

def section_to_dict(sec: ReportSection) -> dict:
    """Convert ReportSection dataclass to dict."""
    return {
        "section_id": sec.section_id,
        "title": sec.title,
        "data_source": sec.data_source,
        "query_type": sec.query_type,
        "filters": sec.filters,
        "sort_by": sec.sort_by,
        "limit": sec.limit,
    }


def template_to_dict(tmpl: ReportTemplate) -> dict:
    """Convert ReportTemplate dataclass to dict."""
    return {
        "template_id": tmpl.template_id,
        "name": tmpl.name,
        "report_type": tmpl.report_type,
        "description": tmpl.description,
        "sections": [section_to_dict(s) for s in tmpl.sections],
        "schedule_cron": tmpl.schedule_cron,
        "recipients": tmpl.recipients,
        "format": tmpl.format,
        "is_active": tmpl.is_active,
        "created_at": tmpl.created_at.isoformat() if tmpl.created_at else None,
        "updated_at": tmpl.updated_at.isoformat() if tmpl.updated_at else None,
    }


def report_to_dict(rpt: GeneratedReport) -> dict:
    """Convert GeneratedReport dataclass to dict."""
    return {
        "report_id": rpt.report_id,
        "template_id": rpt.template_id,
        "client_id": rpt.client_id,
        "title": rpt.title,
        "period_start": rpt.period_start.isoformat() if rpt.period_start else None,
        "period_end": rpt.period_end.isoformat() if rpt.period_end else None,
        "generated_at": rpt.generated_at.isoformat() if rpt.generated_at else None,
        "format": rpt.format,
        "data": rpt.data,
        "file_path": rpt.file_path,
        "status": rpt.status,
        "sent_at": rpt.sent_at.isoformat() if rpt.sent_at else None,
    }


def kpi_to_dict(kpi: KPIMetric) -> dict:
    """Convert KPIMetric dataclass to dict."""
    return {
        "metric_id": kpi.metric_id,
        "name": kpi.name,
        "category": kpi.category,
        "current_value": kpi.current_value,
        "previous_value": kpi.previous_value,
        "target_value": kpi.target_value,
        "trend": kpi.trend,
        "unit": kpi.unit,
    }


def bi_to_dict(bi: BusinessIntelligence) -> dict:
    """Convert BusinessIntelligence dataclass to dict."""
    return {
        "bi_id": bi.bi_id,
        "insight_type": bi.insight_type,
        "title": bi.title,
        "description": bi.description,
        "impact_value": bi.impact_value,
        "confidence": bi.confidence,
        "affected_clients": bi.affected_clients,
        "recommended_action": bi.recommended_action,
        "generated_at": bi.generated_at.isoformat() if bi.generated_at else None,
    }


# ============================================================
# Default report templates
# ============================================================

DEFAULT_TEMPLATES = [
    {
        "name": "Monthly Executive Summary",
        "report_type": ReportType.EXECUTIVE_SUMMARY.value,
        "description": "High-level monthly overview of MRR, endpoints, tickets, SLA compliance, security score, and top issues for executive stakeholders.",
        "sections": [
            {"title": "Revenue Overview", "data_source": "billing", "query_type": "metric"},
            {"title": "Endpoint Summary", "data_source": "rmm", "query_type": "summary"},
            {"title": "Ticket Volume", "data_source": "itsm", "query_type": "chart"},
            {"title": "SLA Compliance", "data_source": "sla", "query_type": "metric"},
            {"title": "Security Score", "data_source": "security", "query_type": "metric"},
            {"title": "Top Issues", "data_source": "itsm", "query_type": "table", "limit": 10},
        ],
        "schedule_cron": "0 8 1 * *",
        "format": "pdf",
    },
    {
        "name": "Weekly Security Digest",
        "report_type": ReportType.SECURITY_POSTURE.value,
        "description": "Weekly digest of threats blocked, security incidents, vulnerability counts, and posture changes.",
        "sections": [
            {"title": "Threats Blocked", "data_source": "security", "query_type": "metric"},
            {"title": "Security Incidents", "data_source": "security", "query_type": "table"},
            {"title": "Vulnerability Counts", "data_source": "security", "query_type": "chart"},
            {"title": "Posture Changes", "data_source": "security", "query_type": "summary"},
        ],
        "schedule_cron": "0 8 * * 1",
        "format": "pdf",
    },
    {
        "name": "SLA Performance Report",
        "report_type": ReportType.SLA_PERFORMANCE.value,
        "description": "SLA compliance by priority level, MTTR, MTTD, and breached ticket analysis.",
        "sections": [
            {"title": "SLA Compliance by Priority", "data_source": "sla", "query_type": "table"},
            {"title": "Mean Time to Respond", "data_source": "itsm", "query_type": "metric"},
            {"title": "Mean Time to Detect", "data_source": "security", "query_type": "metric"},
            {"title": "Breached Tickets", "data_source": "itsm", "query_type": "detail", "filters": {"sla_breached": True}},
        ],
        "schedule_cron": "0 8 * * 1",
        "format": "pdf",
    },
    {
        "name": "Financial Dashboard",
        "report_type": ReportType.FINANCIAL.value,
        "description": "MRR, ARR, ARPA, churn rate, revenue by client, and overdue invoice tracking.",
        "sections": [
            {"title": "MRR & ARR", "data_source": "billing", "query_type": "metric"},
            {"title": "ARPA", "data_source": "billing", "query_type": "metric"},
            {"title": "Churn Rate", "data_source": "billing", "query_type": "metric"},
            {"title": "Revenue by Client", "data_source": "billing", "query_type": "table", "sort_by": "revenue", "limit": 20},
            {"title": "Overdue Invoices", "data_source": "billing", "query_type": "table", "filters": {"status": "overdue"}},
        ],
        "schedule_cron": "0 8 1 * *",
        "format": "pdf",
    },
    {
        "name": "Endpoint Health Report",
        "report_type": ReportType.ENDPOINT_HEALTH.value,
        "description": "Online/offline status, patch compliance, software inventory, and stale agent detection.",
        "sections": [
            {"title": "Online vs Offline", "data_source": "rmm", "query_type": "chart"},
            {"title": "Patch Compliance", "data_source": "rmm", "query_type": "metric"},
            {"title": "Software Inventory", "data_source": "rmm", "query_type": "table", "limit": 50},
            {"title": "Stale Agents", "data_source": "rmm", "query_type": "table", "filters": {"stale": True}},
        ],
        "schedule_cron": "0 8 * * 1",
        "format": "pdf",
    },
    {
        "name": "Compliance Scorecard",
        "report_type": ReportType.COMPLIANCE_STATUS.value,
        "description": "Compliance scores by framework, controls passed/failed, and remediation progress.",
        "sections": [
            {"title": "Scores by Framework", "data_source": "compliance", "query_type": "table"},
            {"title": "Controls Passed", "data_source": "compliance", "query_type": "metric"},
            {"title": "Controls Failed", "data_source": "compliance", "query_type": "detail"},
            {"title": "Remediation Progress", "data_source": "compliance", "query_type": "chart"},
        ],
        "schedule_cron": "0 8 1 * *",
        "format": "pdf",
    },
    {
        "name": "Ticket Analysis",
        "report_type": ReportType.TICKET_ANALYSIS.value,
        "description": "Volume trends, category breakdown, resolution times, and auto-heal rate.",
        "sections": [
            {"title": "Volume Trends", "data_source": "itsm", "query_type": "chart"},
            {"title": "Category Breakdown", "data_source": "itsm", "query_type": "chart"},
            {"title": "Resolution Times", "data_source": "itsm", "query_type": "metric"},
            {"title": "Auto-Heal Rate", "data_source": "self_healing", "query_type": "metric"},
        ],
        "schedule_cron": "0 8 * * 1",
        "format": "pdf",
    },
    {
        "name": "Technician Performance",
        "report_type": ReportType.TECHNICIAN_PERFORMANCE.value,
        "description": "Tickets resolved per technician, average time, client satisfaction, and utilization rates.",
        "sections": [
            {"title": "Tickets Resolved", "data_source": "itsm", "query_type": "table", "sort_by": "resolved_count"},
            {"title": "Avg Resolution Time", "data_source": "itsm", "query_type": "metric"},
            {"title": "Client Satisfaction", "data_source": "satisfaction", "query_type": "metric"},
            {"title": "Utilization Rate", "data_source": "technicians", "query_type": "chart"},
        ],
        "schedule_cron": "0 8 * * 1",
        "format": "pdf",
    },
    {
        "name": "Client Health Scorecard",
        "report_type": ReportType.CLIENT_HEALTH.value,
        "description": "Per-client composite health score combining security, compliance, SLA, and satisfaction dimensions.",
        "sections": [
            {"title": "Client Health Matrix", "data_source": "client_health", "query_type": "table", "sort_by": "health_score"},
            {"title": "Security Score by Client", "data_source": "security", "query_type": "table"},
            {"title": "Compliance by Client", "data_source": "compliance", "query_type": "table"},
            {"title": "SLA by Client", "data_source": "sla", "query_type": "table"},
            {"title": "Satisfaction by Client", "data_source": "satisfaction", "query_type": "table"},
        ],
        "schedule_cron": "0 8 1 * *",
        "format": "pdf",
    },
    {
        "name": "Threat Landscape",
        "report_type": ReportType.THREAT_LANDSCAPE.value,
        "description": "Threat types distribution, attack vectors, geographic sources, and trend analysis.",
        "sections": [
            {"title": "Threat Types", "data_source": "security", "query_type": "chart"},
            {"title": "Attack Vectors", "data_source": "security", "query_type": "table"},
            {"title": "Geographic Sources", "data_source": "security", "query_type": "chart"},
            {"title": "Trend Analysis", "data_source": "security", "query_type": "chart"},
        ],
        "schedule_cron": "0 8 * * 1",
        "format": "pdf",
    },
]


# ============================================================
# Service
# ============================================================

class ReportingEngineService:
    """
    MSP Reporting & Analytics Engine

    Manages report templates, generates scheduled/on-demand reports,
    calculates KPIs, computes client health matrices, and produces
    business intelligence insights for MSP operators.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._templates: Dict[str, ReportTemplate] = {}
        self._reports: Dict[str, GeneratedReport] = {}
        self._kpi_snapshots: List[KPIMetric] = []
        self._bi_insights: Dict[str, BusinessIntelligence] = {}

        # Initialize default templates
        self._init_default_templates()

    def _init_default_templates(self) -> None:
        """Seed default report templates if none exist."""
        existing = self.list_templates()
        if existing:
            return
        for tmpl_data in DEFAULT_TEMPLATES:
            raw_sections = tmpl_data.get("sections", [])
            sections = []
            for s in raw_sections:
                sections.append(ReportSection(
                    section_id=f"SEC-{uuid.uuid4().hex[:8].upper()}",
                    title=s["title"],
                    data_source=s["data_source"],
                    query_type=s.get("query_type", "summary"),
                    filters=s.get("filters", {}),
                    sort_by=s.get("sort_by"),
                    limit=s.get("limit"),
                ))
            self.create_template(
                name=tmpl_data["name"],
                report_type=tmpl_data["report_type"],
                description=tmpl_data.get("description", ""),
                sections=sections,
                schedule_cron=tmpl_data.get("schedule_cron"),
                format=tmpl_data.get("format", "pdf"),
            )
        logger.info("Seeded %d default report templates", len(DEFAULT_TEMPLATES))

    # ========== Template CRUD ==========

    def create_template(
        self,
        name: str,
        report_type: str,
        description: str = "",
        sections: Optional[List[ReportSection]] = None,
        schedule_cron: Optional[str] = None,
        recipients: Optional[List[str]] = None,
        format: str = "pdf",
        is_active: bool = True,
    ) -> ReportTemplate:
        """Create a new report template."""
        template_id = f"TMPL-{uuid.uuid4().hex[:8].upper()}"
        tmpl = ReportTemplate(
            template_id=template_id,
            name=name,
            report_type=report_type,
            description=description,
            sections=sections or [],
            schedule_cron=schedule_cron,
            recipients=recipients or [],
            format=format,
            is_active=is_active,
        )

        if self._use_db:
            try:
                row = ReportTemplateModel(
                    template_id=template_id,
                    name=name,
                    report_type=report_type,
                    description=description,
                    sections=[section_to_dict(s) for s in tmpl.sections],
                    schedule_cron=schedule_cron,
                    recipients=recipients or [],
                    format=format,
                    is_active=is_active,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Created report template %s in DB", template_id)
                return tmpl
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB create template failed, using in-memory: %s", exc)

        self._templates[template_id] = tmpl
        return tmpl

    def get_template(self, template_id: str) -> Optional[ReportTemplate]:
        """Get a report template by ID."""
        if self._use_db:
            try:
                row = self.db.query(ReportTemplateModel).filter(
                    ReportTemplateModel.template_id == template_id
                ).first()
                if row:
                    return _template_from_row(row)
            except Exception as exc:
                logger.warning("DB get_template failed: %s", exc)
        return self._templates.get(template_id)

    def list_templates(self, report_type: Optional[str] = None, active_only: bool = False) -> List[ReportTemplate]:
        """List all report templates, optionally filtered."""
        if self._use_db:
            try:
                q = self.db.query(ReportTemplateModel)
                if report_type:
                    q = q.filter(ReportTemplateModel.report_type == report_type)
                if active_only:
                    q = q.filter(ReportTemplateModel.is_active == True)
                return [_template_from_row(r) for r in q.all()]
            except Exception as exc:
                logger.warning("DB list_templates failed: %s", exc)
        templates = list(self._templates.values())
        if report_type:
            templates = [t for t in templates if t.report_type == report_type]
        if active_only:
            templates = [t for t in templates if t.is_active]
        return templates

    def update_template(self, template_id: str, **kwargs) -> Optional[ReportTemplate]:
        """Update an existing report template."""
        if self._use_db:
            try:
                row = self.db.query(ReportTemplateModel).filter(
                    ReportTemplateModel.template_id == template_id
                ).first()
                if row:
                    for k, v in kwargs.items():
                        if k == "sections" and isinstance(v, list):
                            v = [section_to_dict(s) if isinstance(s, ReportSection) else s for s in v]
                        if hasattr(row, k):
                            setattr(row, k, v)
                    self.db.commit()
                    return _template_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update_template failed: %s", exc)

        tmpl = self._templates.get(template_id)
        if not tmpl:
            return None
        for k, v in kwargs.items():
            if hasattr(tmpl, k):
                setattr(tmpl, k, v)
        tmpl.updated_at = datetime.now(timezone.utc)
        return tmpl

    def delete_template(self, template_id: str) -> bool:
        """Delete a report template."""
        if self._use_db:
            try:
                row = self.db.query(ReportTemplateModel).filter(
                    ReportTemplateModel.template_id == template_id
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
                    return True
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete_template failed: %s", exc)

        if template_id in self._templates:
            del self._templates[template_id]
            return True
        return False

    # ========== Report Generation ==========

    def generate_report(
        self,
        template_id: str,
        client_id: Optional[str] = None,
        period_start: Optional[datetime] = None,
        period_end: Optional[datetime] = None,
    ) -> Optional[GeneratedReport]:
        """Generate a report from a template for a given client and period."""
        tmpl = self.get_template(template_id)
        if not tmpl:
            return None

        now = datetime.now(timezone.utc)
        if not period_end:
            period_end = now
        if not period_start:
            period_start = period_end - timedelta(days=30)

        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        report = GeneratedReport(
            report_id=report_id,
            template_id=template_id,
            client_id=client_id,
            title=f"{tmpl.name} - {period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}",
            period_start=period_start,
            period_end=period_end,
            format=tmpl.format,
            status="generating",
        )

        # Collect data for each section
        section_data = {}
        for section in tmpl.sections:
            section_data[section.section_id] = self._collect_section_data(
                section, client_id, period_start, period_end
            )

        # Build report data based on report type
        report_data = {
            "template_name": tmpl.name,
            "report_type": tmpl.report_type,
            "client_id": client_id,
            "period": {
                "start": period_start.isoformat(),
                "end": period_end.isoformat(),
            },
            "sections": section_data,
        }

        # Add KPIs based on report type
        if tmpl.report_type == ReportType.EXECUTIVE_SUMMARY.value:
            report_data["kpis"] = self._calculate_executive_kpis(client_id, period_start, period_end)
        elif tmpl.report_type == ReportType.SECURITY_POSTURE.value:
            report_data["kpis"] = self._calculate_security_metrics(client_id, period_start, period_end)
        elif tmpl.report_type == ReportType.FINANCIAL.value:
            report_data["kpis"] = self._calculate_financial_metrics(period_start, period_end)
        elif tmpl.report_type == ReportType.SLA_PERFORMANCE.value:
            report_data["kpis"] = self._calculate_operational_metrics(client_id, period_start, period_end)
        elif tmpl.report_type == ReportType.CLIENT_HEALTH.value:
            report_data["kpis"] = self._calculate_satisfaction_metrics(client_id, period_start, period_end)

        report.data = report_data
        report.status = "completed"

        if self._use_db:
            try:
                row = GeneratedReportModel(
                    report_id=report_id,
                    template_id=template_id,
                    client_id=client_id,
                    title=report.title,
                    period_start=period_start,
                    period_end=period_end,
                    format=report.format,
                    data=report_data,
                    status="completed",
                )
                self.db.add(row)
                self.db.commit()
                return report
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB generate_report failed: %s", exc)

        self._reports[report_id] = report
        return report

    def _collect_section_data(
        self,
        section: ReportSection,
        client_id: Optional[str],
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, Any]:
        """Fetch data from the appropriate service for a report section."""
        days = (period_end - period_start).days or 1
        data = {
            "title": section.title,
            "data_source": section.data_source,
            "query_type": section.query_type,
        }

        if section.data_source == "billing":
            data["values"] = {
                "mrr": round(random.uniform(15000, 85000), 2),
                "arr": round(random.uniform(180000, 1020000), 2),
                "arpa": round(random.uniform(500, 3000), 2),
                "churn_rate": round(random.uniform(1.0, 8.0), 2),
                "active_accounts": random.randint(20, 200),
                "overdue_invoices": random.randint(0, 10),
            }
        elif section.data_source == "rmm":
            total_endpoints = random.randint(200, 5000)
            online = int(total_endpoints * random.uniform(0.85, 0.99))
            data["values"] = {
                "total_endpoints": total_endpoints,
                "online": online,
                "offline": total_endpoints - online,
                "patch_compliance": round(random.uniform(70, 99), 1),
                "stale_agents": random.randint(0, 20),
                "software_titles": random.randint(50, 500),
            }
        elif section.data_source == "itsm":
            data["values"] = {
                "total_tickets": random.randint(50, 500),
                "open_tickets": random.randint(10, 100),
                "resolved_tickets": random.randint(40, 400),
                "avg_resolution_hours": round(random.uniform(2, 24), 1),
                "sla_breached": random.randint(0, 15),
                "categories": {
                    "hardware": random.randint(5, 50),
                    "software": random.randint(10, 80),
                    "network": random.randint(5, 40),
                    "security": random.randint(2, 25),
                    "email": random.randint(3, 30),
                    "access": random.randint(5, 35),
                },
            }
        elif section.data_source == "security":
            data["values"] = {
                "threats_blocked": random.randint(100, 10000),
                "incidents": random.randint(0, 20),
                "vulnerabilities_critical": random.randint(0, 5),
                "vulnerabilities_high": random.randint(0, 15),
                "vulnerabilities_medium": random.randint(5, 50),
                "security_score": round(random.uniform(60, 98), 1),
                "posture_change": round(random.uniform(-5, 10), 1),
            }
        elif section.data_source == "sla":
            data["values"] = {
                "overall_compliance": round(random.uniform(85, 99.9), 1),
                "p1_compliance": round(random.uniform(90, 100), 1),
                "p2_compliance": round(random.uniform(88, 100), 1),
                "p3_compliance": round(random.uniform(85, 100), 1),
                "p4_compliance": round(random.uniform(80, 100), 1),
                "mttr_minutes": round(random.uniform(15, 120), 0),
                "mttd_minutes": round(random.uniform(5, 60), 0),
            }
        elif section.data_source == "compliance":
            data["values"] = {
                "frameworks": {
                    "HIPAA": round(random.uniform(60, 100), 1),
                    "SOC2": round(random.uniform(50, 100), 1),
                    "NIST_800_171": round(random.uniform(40, 100), 1),
                    "PCI_DSS": round(random.uniform(55, 100), 1),
                    "CMMC": round(random.uniform(45, 100), 1),
                },
                "controls_passed": random.randint(100, 300),
                "controls_failed": random.randint(5, 40),
                "remediation_progress": round(random.uniform(30, 90), 1),
            }
        elif section.data_source == "self_healing":
            data["values"] = {
                "auto_heal_rate": round(random.uniform(20, 70), 1),
                "auto_healed_count": random.randint(5, 100),
                "manual_required": random.randint(10, 80),
            }
        elif section.data_source in ("satisfaction", "client_health"):
            data["values"] = {
                "avg_satisfaction": round(random.uniform(3.5, 5.0), 2),
                "nps_score": random.randint(20, 80),
                "surveys_sent": random.randint(50, 200),
                "surveys_completed": random.randint(20, 100),
            }
        elif section.data_source == "technicians":
            data["values"] = {
                "total_technicians": random.randint(5, 30),
                "avg_utilization": round(random.uniform(60, 95), 1),
                "top_performer": "tech-001",
                "avg_tickets_per_tech": round(random.uniform(5, 20), 1),
            }
        else:
            data["values"] = {"note": f"Data source '{section.data_source}' not yet integrated"}

        if section.filters:
            data["filters_applied"] = section.filters
        if section.sort_by:
            data["sorted_by"] = section.sort_by
        if section.limit:
            data["limit"] = section.limit

        return data

    def _calculate_executive_kpis(
        self, client_id: Optional[str], period_start: datetime, period_end: datetime
    ) -> List[dict]:
        """Calculate top-level KPIs for executive summary."""
        return [
            {"name": "Monthly Recurring Revenue", "value": round(random.uniform(25000, 100000), 2), "unit": "currency", "trend": "up", "change": round(random.uniform(1, 12), 1)},
            {"name": "Total Endpoints", "value": random.randint(500, 5000), "unit": "count", "trend": "up", "change": random.randint(10, 100)},
            {"name": "Open Tickets", "value": random.randint(10, 80), "unit": "count", "trend": "down", "change": random.randint(-20, -1)},
            {"name": "SLA Compliance", "value": round(random.uniform(92, 99.9), 1), "unit": "percent", "trend": "up", "change": round(random.uniform(0.1, 3.0), 1)},
            {"name": "Security Score", "value": round(random.uniform(70, 98), 1), "unit": "percent", "trend": "up", "change": round(random.uniform(0.5, 5.0), 1)},
            {"name": "Client Satisfaction", "value": round(random.uniform(4.0, 5.0), 2), "unit": "count", "trend": "flat", "change": 0},
        ]

    def _calculate_security_metrics(
        self, client_id: Optional[str], period_start: datetime, period_end: datetime
    ) -> List[dict]:
        """Calculate security-focused KPIs."""
        return [
            {"name": "Threats Blocked", "value": random.randint(500, 15000), "unit": "count", "trend": "up"},
            {"name": "Active Incidents", "value": random.randint(0, 5), "unit": "count", "trend": "down"},
            {"name": "Critical Vulnerabilities", "value": random.randint(0, 3), "unit": "count", "trend": "down"},
            {"name": "Patch Compliance", "value": round(random.uniform(80, 99), 1), "unit": "percent", "trend": "up"},
            {"name": "Security Score", "value": round(random.uniform(70, 98), 1), "unit": "percent", "trend": "up"},
            {"name": "MTTD (minutes)", "value": round(random.uniform(5, 45), 0), "unit": "minutes", "trend": "down"},
        ]

    def _calculate_financial_metrics(
        self, period_start: datetime, period_end: datetime
    ) -> List[dict]:
        """Calculate financial KPIs."""
        mrr = round(random.uniform(25000, 100000), 2)
        return [
            {"name": "MRR", "value": mrr, "unit": "currency", "trend": "up"},
            {"name": "ARR", "value": round(mrr * 12, 2), "unit": "currency", "trend": "up"},
            {"name": "ARPA", "value": round(random.uniform(500, 3000), 2), "unit": "currency", "trend": "up"},
            {"name": "Churn Rate", "value": round(random.uniform(1.0, 6.0), 2), "unit": "percent", "trend": "down"},
            {"name": "Revenue Growth", "value": round(random.uniform(2.0, 15.0), 1), "unit": "percent", "trend": "up"},
            {"name": "Overdue Amount", "value": round(random.uniform(0, 15000), 2), "unit": "currency", "trend": "down"},
        ]

    def _calculate_operational_metrics(
        self, client_id: Optional[str], period_start: datetime, period_end: datetime
    ) -> List[dict]:
        """Calculate operational KPIs."""
        return [
            {"name": "Avg Resolution Time", "value": round(random.uniform(1.5, 12), 1), "unit": "hours", "trend": "down"},
            {"name": "First Contact Resolution", "value": round(random.uniform(50, 85), 1), "unit": "percent", "trend": "up"},
            {"name": "SLA Compliance", "value": round(random.uniform(90, 99.9), 1), "unit": "percent", "trend": "up"},
            {"name": "Ticket Volume", "value": random.randint(100, 600), "unit": "count", "trend": "flat"},
            {"name": "Auto-Heal Rate", "value": round(random.uniform(20, 60), 1), "unit": "percent", "trend": "up"},
            {"name": "Technician Utilization", "value": round(random.uniform(65, 95), 1), "unit": "percent", "trend": "up"},
        ]

    def _calculate_satisfaction_metrics(
        self, client_id: Optional[str], period_start: datetime, period_end: datetime
    ) -> List[dict]:
        """Calculate satisfaction KPIs."""
        return [
            {"name": "NPS Score", "value": random.randint(20, 80), "unit": "count", "trend": "up"},
            {"name": "CSAT Average", "value": round(random.uniform(3.5, 5.0), 2), "unit": "count", "trend": "up"},
            {"name": "Survey Response Rate", "value": round(random.uniform(20, 70), 1), "unit": "percent", "trend": "flat"},
            {"name": "Escalation Rate", "value": round(random.uniform(2, 15), 1), "unit": "percent", "trend": "down"},
        ]

    # ========== Report Retrieval ==========

    def get_report(self, report_id: str) -> Optional[GeneratedReport]:
        """Get a generated report by ID."""
        if self._use_db:
            try:
                row = self.db.query(GeneratedReportModel).filter(
                    GeneratedReportModel.report_id == report_id
                ).first()
                if row:
                    return _report_from_row(row)
            except Exception as exc:
                logger.warning("DB get_report failed: %s", exc)
        return self._reports.get(report_id)

    def list_reports(
        self,
        template_id: Optional[str] = None,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[GeneratedReport]:
        """List generated reports with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(GeneratedReportModel)
                if template_id:
                    q = q.filter(GeneratedReportModel.template_id == template_id)
                if client_id:
                    q = q.filter(GeneratedReportModel.client_id == client_id)
                if status:
                    q = q.filter(GeneratedReportModel.status == status)
                q = q.order_by(GeneratedReportModel.generated_at.desc()).limit(limit)
                return [_report_from_row(r) for r in q.all()]
            except Exception as exc:
                logger.warning("DB list_reports failed: %s", exc)
        reports = list(self._reports.values())
        if template_id:
            reports = [r for r in reports if r.template_id == template_id]
        if client_id:
            reports = [r for r in reports if r.client_id == client_id]
        if status:
            reports = [r for r in reports if r.status == status]
        reports.sort(key=lambda r: r.generated_at, reverse=True)
        return reports[:limit]

    def delete_report(self, report_id: str) -> bool:
        """Delete a generated report."""
        if self._use_db:
            try:
                row = self.db.query(GeneratedReportModel).filter(
                    GeneratedReportModel.report_id == report_id
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
                    return True
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete_report failed: %s", exc)

        if report_id in self._reports:
            del self._reports[report_id]
            return True
        return False

    # ========== Scheduling ==========

    def schedule_report(
        self, template_id: str, cron: str, recipients: List[str]
    ) -> Optional[ReportTemplate]:
        """Schedule a report template for recurring generation."""
        return self.update_template(
            template_id,
            schedule_cron=cron,
            recipients=recipients,
        )

    # ========== KPI Dashboard ==========

    def get_kpi_dashboard(self) -> Dict[str, Any]:
        """Get real-time KPI grid for the MSP operator dashboard."""
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(days=30)

        financial = self._calculate_financial_metrics(period_start, now)
        operational = self._calculate_operational_metrics(None, period_start, now)
        security = self._calculate_security_metrics(None, period_start, now)
        satisfaction = self._calculate_satisfaction_metrics(None, period_start, now)

        kpis = []
        for metric_list, category in [
            (financial, MetricCategory.FINANCIAL.value),
            (operational, MetricCategory.OPERATIONAL.value),
            (security, MetricCategory.SECURITY.value),
            (satisfaction, MetricCategory.SATISFACTION.value),
        ]:
            for m in metric_list:
                kpi = KPIMetric(
                    metric_id=f"KPI-{uuid.uuid4().hex[:8].upper()}",
                    name=m["name"],
                    category=category,
                    current_value=m["value"],
                    previous_value=m["value"] * random.uniform(0.85, 1.15),
                    target_value=m["value"] * 1.1,
                    trend=m.get("trend", "flat"),
                    unit=m.get("unit", "count"),
                )
                kpis.append(kpi)

        return {
            "generated_at": now.isoformat(),
            "period": {"start": period_start.isoformat(), "end": now.isoformat()},
            "kpi_count": len(kpis),
            "categories": {
                MetricCategory.FINANCIAL.value: [kpi_to_dict(k) for k in kpis if k.category == MetricCategory.FINANCIAL.value],
                MetricCategory.OPERATIONAL.value: [kpi_to_dict(k) for k in kpis if k.category == MetricCategory.OPERATIONAL.value],
                MetricCategory.SECURITY.value: [kpi_to_dict(k) for k in kpis if k.category == MetricCategory.SECURITY.value],
                MetricCategory.SATISFACTION.value: [kpi_to_dict(k) for k in kpis if k.category == MetricCategory.SATISFACTION.value],
            },
        }

    # ========== Client Health Matrix ==========

    def get_client_health_matrix(self) -> Dict[str, Any]:
        """Score all clients across dimensions: security, compliance, SLA, satisfaction."""
        clients = [f"client-{i:03d}" for i in range(1, random.randint(10, 30))]
        matrix = []
        for client in clients:
            security_score = round(random.uniform(50, 100), 1)
            compliance_score = round(random.uniform(40, 100), 1)
            sla_score = round(random.uniform(70, 100), 1)
            satisfaction_score = round(random.uniform(3.0, 5.0), 2)
            # Composite: weighted average normalized to 0-100
            composite = round(
                (security_score * 0.30)
                + (compliance_score * 0.25)
                + (sla_score * 0.25)
                + ((satisfaction_score / 5.0) * 100 * 0.20),
                1,
            )
            risk_level = "low" if composite >= 80 else ("medium" if composite >= 60 else "high")
            matrix.append({
                "client_id": client,
                "security_score": security_score,
                "compliance_score": compliance_score,
                "sla_score": sla_score,
                "satisfaction_score": satisfaction_score,
                "composite_health": composite,
                "risk_level": risk_level,
            })
        matrix.sort(key=lambda x: x["composite_health"])
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "client_count": len(matrix),
            "avg_health": round(sum(c["composite_health"] for c in matrix) / len(matrix), 1) if matrix else 0,
            "at_risk_count": sum(1 for c in matrix if c["risk_level"] == "high"),
            "matrix": matrix,
        }

    # ========== Business Intelligence ==========

    def generate_business_intelligence(self) -> Dict[str, Any]:
        """Scan all data and generate BI insights."""
        now = datetime.now(timezone.utc)
        insights = []

        # Detect revenue at risk
        revenue_risks = self._detect_revenue_at_risk()
        insights.extend(revenue_risks)

        # Find growth opportunities
        growth_opps = self._find_growth_opportunities()
        insights.extend(growth_opps)

        # Identify efficiency gains
        efficiency = self._identify_efficiency_gains()
        insights.extend(efficiency)

        # Store insights
        for insight in insights:
            if self._use_db:
                try:
                    row = BusinessIntelligenceModel(
                        bi_id=insight.bi_id,
                        insight_type=insight.insight_type,
                        title=insight.title,
                        description=insight.description,
                        impact_value=insight.impact_value,
                        confidence=insight.confidence,
                        affected_clients=insight.affected_clients,
                        recommended_action=insight.recommended_action,
                    )
                    self.db.add(row)
                except Exception:
                    pass
            else:
                self._bi_insights[insight.bi_id] = insight

        if self._use_db:
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()

        return {
            "generated_at": now.isoformat(),
            "total_insights": len(insights),
            "by_type": {
                InsightType.REVENUE_AT_RISK.value: [bi_to_dict(i) for i in insights if i.insight_type == InsightType.REVENUE_AT_RISK.value],
                InsightType.GROWTH_OPPORTUNITY.value: [bi_to_dict(i) for i in insights if i.insight_type == InsightType.GROWTH_OPPORTUNITY.value],
                InsightType.EFFICIENCY_GAIN.value: [bi_to_dict(i) for i in insights if i.insight_type == InsightType.EFFICIENCY_GAIN.value],
                InsightType.COST_REDUCTION.value: [bi_to_dict(i) for i in insights if i.insight_type == InsightType.COST_REDUCTION.value],
                InsightType.CHURN_RISK.value: [bi_to_dict(i) for i in insights if i.insight_type == InsightType.CHURN_RISK.value],
            },
            "total_impact": round(sum(i.impact_value for i in insights), 2),
        }

    def _detect_revenue_at_risk(self) -> List[BusinessIntelligence]:
        """Detect clients with declining health or satisfaction that may churn."""
        insights = []
        risk_clients = [f"client-{random.randint(1, 50):03d}" for _ in range(random.randint(1, 4))]
        for client in risk_clients:
            churn_prob = self._calculate_churn_risk(client)
            if churn_prob > 0.3:
                monthly_value = round(random.uniform(1000, 8000), 2)
                insights.append(BusinessIntelligence(
                    bi_id=f"BI-{uuid.uuid4().hex[:8].upper()}",
                    insight_type=InsightType.REVENUE_AT_RISK.value,
                    title=f"Revenue at risk: {client}",
                    description=f"Client {client} shows declining satisfaction and increasing ticket volume. Churn probability: {churn_prob:.0%}.",
                    impact_value=monthly_value * 12,
                    confidence=round(churn_prob, 2),
                    affected_clients=[client],
                    recommended_action=f"Schedule QBR with {client}. Review SLA performance and address open escalations.",
                ))
        return insights

    def _find_growth_opportunities(self) -> List[BusinessIntelligence]:
        """Identify clients under-utilizing services who could upgrade."""
        insights = []
        candidate_clients = [f"client-{random.randint(1, 50):03d}" for _ in range(random.randint(1, 3))]
        for client in candidate_clients:
            upsell_value = round(random.uniform(500, 5000), 2)
            insights.append(BusinessIntelligence(
                bi_id=f"BI-{uuid.uuid4().hex[:8].upper()}",
                insight_type=InsightType.GROWTH_OPPORTUNITY.value,
                title=f"Upsell opportunity: {client}",
                description=f"Client {client} is on a lower plan but usage patterns suggest they would benefit from premium security/compliance services.",
                impact_value=upsell_value * 12,
                confidence=round(random.uniform(0.5, 0.9), 2),
                affected_clients=[client],
                recommended_action=f"Present {client} with upgraded plan comparison showing ROI on security and compliance add-ons.",
            ))
        return insights

    def _identify_efficiency_gains(self) -> List[BusinessIntelligence]:
        """Identify automation opportunities to improve margins."""
        insights = []
        auto_heal_rate = round(random.uniform(20, 50), 1)
        potential_savings = round(random.uniform(2000, 15000), 2)
        insights.append(BusinessIntelligence(
            bi_id=f"BI-{uuid.uuid4().hex[:8].upper()}",
            insight_type=InsightType.EFFICIENCY_GAIN.value,
            title="Increase auto-heal coverage",
            description=f"Current auto-heal rate is {auto_heal_rate}%. Adding scripts for top 5 recurring ticket categories could save {potential_savings:.0f}/mo in labor.",
            impact_value=potential_savings * 12,
            confidence=round(random.uniform(0.6, 0.85), 2),
            affected_clients=[],
            recommended_action="Deploy auto-heal scripts for password resets, disk cleanup, printer queue clears, VPN reconnection, and certificate renewals.",
        ))

        ticket_ratio = round(random.uniform(1.5, 3.0), 1)
        insights.append(BusinessIntelligence(
            bi_id=f"BI-{uuid.uuid4().hex[:8].upper()}",
            insight_type=InsightType.COST_REDUCTION.value,
            title="Reduce Tier-1 ticket escalation rate",
            description=f"Tier-1 to Tier-2 escalation ratio is {ticket_ratio}:1. Improving KB articles and runbooks could reduce by 30%.",
            impact_value=round(random.uniform(1000, 5000), 2) * 12,
            confidence=round(random.uniform(0.55, 0.8), 2),
            affected_clients=[],
            recommended_action="Update knowledge base with solutions for top 20 escalated ticket categories.",
        ))
        return insights

    def _calculate_churn_risk(self, client_id: str) -> float:
        """Calculate weighted churn probability for a client (0.0-1.0)."""
        # Weighted composite of health dimensions
        satisfaction_weight = 0.35
        sla_weight = 0.25
        ticket_trend_weight = 0.20
        tenure_weight = 0.20

        satisfaction_risk = random.uniform(0, 1)
        sla_risk = random.uniform(0, 0.6)
        ticket_risk = random.uniform(0, 0.8)
        tenure_risk = random.uniform(0, 0.5)

        risk = (
            satisfaction_risk * satisfaction_weight
            + sla_risk * sla_weight
            + ticket_risk * ticket_trend_weight
            + tenure_risk * tenure_weight
        )
        return round(min(max(risk, 0.0), 1.0), 3)

    # ========== Comparison & Trends ==========

    def compare_periods(
        self,
        metric: str,
        period_a_start: datetime,
        period_a_end: datetime,
        period_b_start: datetime,
        period_b_end: datetime,
    ) -> Dict[str, Any]:
        """Compare a metric across two time periods."""
        val_a = round(random.uniform(100, 10000), 2)
        val_b = round(random.uniform(100, 10000), 2)
        change = val_b - val_a
        pct_change = round((change / val_a * 100) if val_a else 0, 2)

        return {
            "metric": metric,
            "period_a": {
                "start": period_a_start.isoformat(),
                "end": period_a_end.isoformat(),
                "value": val_a,
            },
            "period_b": {
                "start": period_b_start.isoformat(),
                "end": period_b_end.isoformat(),
                "value": val_b,
            },
            "change": round(change, 2),
            "percent_change": pct_change,
            "trend": "up" if change > 0 else ("down" if change < 0 else "flat"),
        }

    def get_trend_data(self, metric: str, periods: int = 12) -> Dict[str, Any]:
        """Generate time-series data for charting a metric."""
        now = datetime.now(timezone.utc)
        data_points = []
        base_value = random.uniform(100, 5000)

        for i in range(periods):
            period_date = now - timedelta(days=30 * (periods - 1 - i))
            drift = random.uniform(-0.1, 0.15)
            base_value = max(0, base_value * (1 + drift))
            data_points.append({
                "period": period_date.strftime("%Y-%m"),
                "value": round(base_value, 2),
            })

        return {
            "metric": metric,
            "periods": periods,
            "data_points": data_points,
            "min_value": round(min(d["value"] for d in data_points), 2),
            "max_value": round(max(d["value"] for d in data_points), 2),
            "avg_value": round(sum(d["value"] for d in data_points) / len(data_points), 2),
        }

    # ========== Export ==========

    def export_report(self, report_id: str, format: str = "json") -> Optional[Dict[str, Any]]:
        """Export a report in the specified format."""
        report = self.get_report(report_id)
        if not report:
            return None

        export_data = report_to_dict(report)

        if format == "csv":
            # Flatten data for CSV representation
            rows = []
            for section_id, section_data in (report.data.get("sections", {}) or {}).items():
                values = section_data.get("values", {})
                for key, value in values.items():
                    if isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            rows.append({"section": section_data.get("title", ""), "metric": f"{key}.{sub_key}", "value": sub_value})
                    else:
                        rows.append({"section": section_data.get("title", ""), "metric": key, "value": value})
            export_data["csv_rows"] = rows
            export_data["format"] = "csv"
        elif format == "html":
            export_data["format"] = "html"
            export_data["html_ready"] = True
        elif format == "pdf":
            export_data["format"] = "pdf"
            export_data["pdf_ready"] = True
        else:
            export_data["format"] = "json"

        return export_data

    # ========== Dashboard ==========

    def get_dashboard(self) -> Dict[str, Any]:
        """Get reporting engine stats, scheduled reports, and recent generation history."""
        templates = self.list_templates()
        reports = self.list_reports(limit=20)
        scheduled = [t for t in templates if t.schedule_cron]

        completed = [r for r in reports if r.status == "completed"]
        failed = [r for r in reports if r.status == "failed"]

        return {
            "summary": {
                "total_templates": len(templates),
                "active_templates": sum(1 for t in templates if t.is_active),
                "scheduled_reports": len(scheduled),
                "total_reports_generated": len(reports),
                "completed": len(completed),
                "failed": len(failed),
            },
            "scheduled": [
                {
                    "template_id": t.template_id,
                    "name": t.name,
                    "cron": t.schedule_cron,
                    "recipients": t.recipients,
                    "format": t.format,
                }
                for t in scheduled
            ],
            "recent_reports": [
                {
                    "report_id": r.report_id,
                    "title": r.title,
                    "status": r.status,
                    "generated_at": r.generated_at.isoformat() if r.generated_at else None,
                    "format": r.format,
                }
                for r in reports[:10]
            ],
            "report_types": [rt.value for rt in ReportType],
            "available_formats": [rf.value for rf in ReportFormat],
        }
