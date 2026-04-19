"""
API Routes for Compliance Framework Templates
Pre-built HIPAA, SOC2, NIST 800-171, CMMC, PCI-DSS checklists for MSP clients.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.compliance_frameworks import (
    ComplianceFrameworkService,
    ControlStatus,
    FindingSeverity,
    FindingStatus,
)

router = APIRouter(prefix="/compliance-frameworks", tags=["Compliance Frameworks"])


def _init_service() -> ComplianceFrameworkService:
    """Initialize ComplianceFrameworkService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return ComplianceFrameworkService(db=db)
    except Exception:
        return ComplianceFrameworkService()


# Initialize service with DB persistence
_service = _init_service()


# ========== Request/Response Models ==========

class StartAssessmentRequest(BaseModel):
    client_id: str
    framework_id: str
    assessed_by: str = ""


class UpdateControlStatusRequest(BaseModel):
    status: str = Field(..., description="One of: not_assessed, compliant, non_compliant, partially_compliant, not_applicable")
    notes: str = ""
    assessed_by: str = ""


class AddFindingRequest(BaseModel):
    control_id: str
    severity: str = Field(..., description="One of: critical, high, medium, low, info")
    description: str
    recommendation: str = ""
    due_date: Optional[str] = Field(None, description="YYYY-MM-DD format")


class UpdateFindingRequest(BaseModel):
    status: Optional[str] = Field(None, description="One of: open, in_progress, resolved, accepted_risk")
    recommendation: Optional[str] = None


class ShieldEventsRequest(BaseModel):
    events: List[Dict[str, Any]]


# ========== Framework Routes ==========

@router.get("/frameworks")
def list_frameworks():
    """List all available compliance frameworks (HIPAA, SOC2, NIST 800-171, CMMC, PCI-DSS)."""
    frameworks = _service.get_frameworks()
    return {"frameworks": frameworks, "total": len(frameworks)}


@router.get("/frameworks/{framework_id}")
def get_framework(framework_id: str):
    """Get a specific framework with all controls grouped by category."""
    result = _service.get_framework(framework_id)
    if not result:
        raise HTTPException(status_code=404, detail="Framework not found")
    return result


# ========== Assessment Routes ==========

@router.post("/assessments")
def start_assessment(data: StartAssessmentRequest):
    """Start a new compliance assessment for a client against a framework."""
    result = _service.start_assessment(
        client_id=data.client_id,
        framework_id=data.framework_id,
        assessed_by=data.assessed_by,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Framework not found")
    return result


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str):
    """Get assessment details and current scores."""
    result = _service.get_assessment(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.put("/assessments/{assessment_id}/controls/{control_id}")
def update_control_status(assessment_id: str, control_id: str, data: UpdateControlStatusRequest):
    """Update the status of a control within an assessment."""
    # Validate status
    valid_statuses = [s.value for s in ControlStatus]
    if data.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )

    result = _service.update_control_status(
        assessment_id=assessment_id,
        control_id=control_id,
        status=data.status,
        notes=data.notes,
        assessed_by=data.assessed_by,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Assessment or control not found")
    return result


@router.get("/assessments/{assessment_id}/report")
def get_assessment_report(assessment_id: str):
    """Generate a full compliance report for an assessment."""
    result = _service.get_assessment_report(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.get("/assessments/{assessment_id}/score")
def get_compliance_score(assessment_id: str):
    """Calculate and return detailed compliance scoring for an assessment."""
    result = _service.calculate_compliance_score(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


# ========== Finding Routes ==========

@router.post("/assessments/{assessment_id}/findings")
def add_finding(assessment_id: str, data: AddFindingRequest):
    """Add a finding to an assessment."""
    # Validate severity
    valid_severities = [s.value for s in FindingSeverity]
    if data.severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    result = _service.add_finding(
        assessment_id=assessment_id,
        control_id=data.control_id,
        severity=data.severity,
        description=data.description,
        recommendation=data.recommendation,
        due_date=data.due_date,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return result


@router.put("/findings/{finding_id}")
def update_finding(finding_id: str, data: UpdateFindingRequest):
    """Update a finding's status or recommendation."""
    if data.status:
        valid_statuses = [s.value for s in FindingStatus]
        if data.status not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )

    result = _service.update_finding(
        finding_id=finding_id,
        status=data.status,
        recommendation=data.recommendation,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


# ========== Dashboard & Integration ==========

@router.get("/dashboard")
def get_dashboard():
    """Get compliance dashboard stats across all clients and frameworks."""
    return _service.get_dashboard()


@router.post("/shield-mapping")
def map_shield_events(data: ShieldEventsRequest):
    """Map Aither Shield security events to compliance controls.
    Helps MSPs understand which compliance areas are impacted by security incidents."""
    results = _service.map_shield_events_to_controls(data.events)
    return {"mappings": results, "total_events": len(results)}
