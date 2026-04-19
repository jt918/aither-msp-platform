"""
API Routes for MSP Reporting & Analytics Engine
Scheduled reports, real-time dashboards, KPIs, and business intelligence
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.reporting_engine import (
    ReportingEngineService,
    ReportType,
    MetricCategory,
    ReportFormat,
    ReportStatus,
    InsightType,
    template_to_dict,
    report_to_dict,
    kpi_to_dict,
    bi_to_dict,
)

router = APIRouter(prefix="/reports", tags=["Reporting Engine"])


def _init_reporting_service() -> ReportingEngineService:
    """Initialize ReportingEngineService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return ReportingEngineService(db=db)
    except Exception:
        return ReportingEngineService()


# Initialize service with DB persistence
reporting_service = _init_reporting_service()


# ========== Request/Response Models ==========

class SectionInput(BaseModel):
    title: str
    data_source: str
    query_type: str = "summary"
    filters: Dict[str, Any] = {}
    sort_by: Optional[str] = None
    limit: Optional[int] = None


class TemplateCreate(BaseModel):
    name: str
    report_type: str = "executive_summary"
    description: str = ""
    sections: List[SectionInput] = []
    schedule_cron: Optional[str] = None
    recipients: List[str] = []
    format: str = "pdf"
    is_active: bool = True


class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    report_type: Optional[str] = None
    description: Optional[str] = None
    schedule_cron: Optional[str] = None
    recipients: Optional[List[str]] = None
    format: Optional[str] = None
    is_active: Optional[bool] = None


class GenerateRequest(BaseModel):
    template_id: str
    client_id: Optional[str] = None
    period_start: Optional[str] = None
    period_end: Optional[str] = None


class ScheduleRequest(BaseModel):
    cron: str
    recipients: List[str] = []


# ========== Template Routes ==========

@router.get("/templates")
async def list_templates(
    report_type: Optional[str] = Query(None),
    active_only: bool = Query(False),
    user=Depends(get_current_user),
):
    """List all report templates."""
    templates = reporting_service.list_templates(
        report_type=report_type, active_only=active_only
    )
    return {"templates": [template_to_dict(t) for t in templates], "count": len(templates)}


@router.get("/templates/{template_id}")
async def get_template(template_id: str, user=Depends(get_current_user)):
    """Get a specific report template."""
    tmpl = reporting_service.get_template(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return template_to_dict(tmpl)


@router.post("/templates")
async def create_template(data: TemplateCreate, user=Depends(require_admin)):
    """Create a new report template."""
    from services.msp.reporting_engine import ReportSection
    import uuid as _uuid

    sections = [
        ReportSection(
            section_id=f"SEC-{_uuid.uuid4().hex[:8].upper()}",
            title=s.title,
            data_source=s.data_source,
            query_type=s.query_type,
            filters=s.filters,
            sort_by=s.sort_by,
            limit=s.limit,
        )
        for s in data.sections
    ]
    tmpl = reporting_service.create_template(
        name=data.name,
        report_type=data.report_type,
        description=data.description,
        sections=sections,
        schedule_cron=data.schedule_cron,
        recipients=data.recipients,
        format=data.format,
        is_active=data.is_active,
    )
    return template_to_dict(tmpl)


@router.put("/templates/{template_id}")
async def update_template(template_id: str, data: TemplateUpdate, user=Depends(require_admin)):
    """Update an existing report template."""
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    tmpl = reporting_service.update_template(template_id, **updates)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return template_to_dict(tmpl)


@router.delete("/templates/{template_id}")
async def delete_template(template_id: str, user=Depends(require_admin)):
    """Delete a report template."""
    ok = reporting_service.delete_template(template_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"deleted": True, "template_id": template_id}


# ========== Report Generation Routes ==========

@router.post("/generate")
async def generate_report(data: GenerateRequest, user=Depends(get_current_user)):
    """Generate a report from a template."""
    period_start = None
    period_end = None
    if data.period_start:
        period_start = datetime.fromisoformat(data.period_start)
    if data.period_end:
        period_end = datetime.fromisoformat(data.period_end)

    report = reporting_service.generate_report(
        template_id=data.template_id,
        client_id=data.client_id,
        period_start=period_start,
        period_end=period_end,
    )
    if not report:
        raise HTTPException(status_code=404, detail="Template not found")
    return report_to_dict(report)


@router.get("/list")
async def list_reports(
    template_id: Optional[str] = Query(None),
    client_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user=Depends(get_current_user),
):
    """List generated reports."""
    reports = reporting_service.list_reports(
        template_id=template_id,
        client_id=client_id,
        status=status,
        limit=limit,
    )
    return {"reports": [report_to_dict(r) for r in reports], "count": len(reports)}


@router.get("/detail/{report_id}")
async def get_report(report_id: str, user=Depends(get_current_user)):
    """Get a specific generated report."""
    report = reporting_service.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_to_dict(report)


@router.delete("/detail/{report_id}")
async def delete_report(report_id: str, user=Depends(require_admin)):
    """Delete a generated report."""
    ok = reporting_service.delete_report(report_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"deleted": True, "report_id": report_id}


# ========== Export Routes ==========

@router.get("/detail/{report_id}/export")
async def export_report(
    report_id: str,
    format: str = Query("json"),
    user=Depends(get_current_user),
):
    """Export a report in the specified format (pdf, csv, json, html)."""
    result = reporting_service.export_report(report_id, format=format)
    if not result:
        raise HTTPException(status_code=404, detail="Report not found")
    return result


# ========== Schedule Routes ==========

@router.post("/templates/{template_id}/schedule")
async def schedule_report(
    template_id: str, data: ScheduleRequest, user=Depends(require_admin)
):
    """Schedule a report template for recurring generation."""
    tmpl = reporting_service.schedule_report(
        template_id=template_id,
        cron=data.cron,
        recipients=data.recipients,
    )
    if not tmpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return template_to_dict(tmpl)


# ========== KPI Dashboard ==========

@router.get("/kpis")
async def get_kpi_dashboard(user=Depends(get_current_user)):
    """Get real-time KPI dashboard for the MSP operator."""
    return reporting_service.get_kpi_dashboard()


# ========== Client Health Matrix ==========

@router.get("/client-health-matrix")
async def get_client_health_matrix(user=Depends(get_current_user)):
    """Get all clients scored across security, compliance, SLA, and satisfaction."""
    return reporting_service.get_client_health_matrix()


# ========== Business Intelligence ==========

@router.get("/business-intelligence")
async def get_business_intelligence(user=Depends(get_current_user)):
    """Generate and return business intelligence insights."""
    return reporting_service.generate_business_intelligence()


# ========== Trends ==========

@router.get("/trends/{metric}")
async def get_trends(
    metric: str,
    periods: int = Query(12, ge=1, le=60),
    user=Depends(get_current_user),
):
    """Get time-series trend data for a metric."""
    return reporting_service.get_trend_data(metric, periods=periods)


# ========== Compare ==========

@router.get("/compare")
async def compare_periods(
    metric: str = Query(...),
    period_a_start: str = Query(...),
    period_a_end: str = Query(...),
    period_b_start: str = Query(...),
    period_b_end: str = Query(...),
    user=Depends(get_current_user),
):
    """Compare a metric across two time periods."""
    try:
        pa_start = datetime.fromisoformat(period_a_start)
        pa_end = datetime.fromisoformat(period_a_end)
        pb_start = datetime.fromisoformat(period_b_start)
        pb_end = datetime.fromisoformat(period_b_end)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use ISO format.")

    return reporting_service.compare_periods(
        metric=metric,
        period_a_start=pa_start,
        period_a_end=pa_end,
        period_b_start=pb_start,
        period_b_end=pb_end,
    )


# ========== Dashboard ==========

@router.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    """Get reporting engine stats, scheduled reports, and recent generation history."""
    return reporting_service.get_dashboard()
