"""
API Routes for ITIL Problem Management
Root cause tracking, Known Error Database (KEDB), and recurring incident prevention.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.problem_management import (
    ProblemManagementService,
    ProblemStatus,
    ProblemPriority,
    ProblemCategory,
    RCAMethod,
    FixStatus,
)

router = APIRouter(prefix="/problem-management", tags=["Problem Management"])

# Singleton instance
_pm_instance: Optional[ProblemManagementService] = None


def get_pm() -> ProblemManagementService:
    """Get or create ProblemManagementService instance with DB persistence."""
    global _pm_instance
    if _pm_instance is None:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            _pm_instance = ProblemManagementService(db=db)
        except Exception:
            _pm_instance = ProblemManagementService()
    return _pm_instance


# ========== Pydantic Models ==========

class ProblemCreate(BaseModel):
    """Create a problem record."""
    client_id: str
    title: str
    description: str
    priority: str = "medium"
    category: str = "other"
    affected_services: List[str] = []
    related_incidents: List[str] = []
    assigned_to: Optional[str] = None
    impact_assessment: str = ""


class ProblemUpdate(BaseModel):
    """Update a problem record."""
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    category: Optional[str] = None
    assigned_to: Optional[str] = None
    impact_assessment: Optional[str] = None
    affected_services: Optional[List[str]] = None


class RootCausePayload(BaseModel):
    """Identify root cause payload."""
    root_cause: str
    method: str = "five_whys"


class KnownErrorCreate(BaseModel):
    """Create a known error from a problem."""
    workaround: str
    symptoms: List[str] = []
    affected_cis: List[str] = []


class ResolvePayload(BaseModel):
    """Resolve a problem."""
    resolution: str


class LinkIncidentPayload(BaseModel):
    """Link an incident to a problem."""
    incident_id: str


class RCAPayload(BaseModel):
    """Perform root cause analysis."""
    method: str = "five_whys"
    analysis_data: Dict[str, Any] = {}
    findings: List[str] = []
    contributing_factors: List[str] = []
    recommendations: List[str] = []
    analyzed_by: str = ""


class SymptomSearch(BaseModel):
    """Search known errors by symptoms."""
    symptoms: List[str]


class IncidentMatch(BaseModel):
    """Match incident data to known errors."""
    title: str = ""
    description: str = ""
    symptoms: List[str] = []


# ========== Helper ==========

def _problem_to_dict(pr) -> Dict[str, Any]:
    return {
        "problem_id": pr.problem_id,
        "client_id": pr.client_id,
        "title": pr.title,
        "description": pr.description,
        "status": pr.status.value,
        "priority": pr.priority.value,
        "category": pr.category.value,
        "root_cause": pr.root_cause,
        "workaround": pr.workaround,
        "resolution": pr.resolution,
        "affected_services": pr.affected_services,
        "related_incidents": pr.related_incidents,
        "assigned_to": pr.assigned_to,
        "impact_assessment": pr.impact_assessment,
        "created_at": pr.created_at.isoformat() if pr.created_at else None,
        "updated_at": pr.updated_at.isoformat() if pr.updated_at else None,
        "resolved_at": pr.resolved_at.isoformat() if pr.resolved_at else None,
    }


def _ke_to_dict(ke) -> Dict[str, Any]:
    return {
        "ke_id": ke.ke_id,
        "problem_id": ke.problem_id,
        "title": ke.title,
        "error_description": ke.error_description,
        "root_cause": ke.root_cause,
        "workaround": ke.workaround,
        "permanent_fix_status": ke.permanent_fix_status.value,
        "symptoms": ke.symptoms,
        "affected_cis": ke.affected_cis,
        "created_at": ke.created_at.isoformat() if ke.created_at else None,
    }


def _rca_to_dict(rca) -> Dict[str, Any]:
    return {
        "rca_id": rca.rca_id,
        "problem_id": rca.problem_id,
        "method": rca.method.value,
        "analysis_data": rca.analysis_data,
        "findings": rca.findings,
        "contributing_factors": rca.contributing_factors,
        "recommendations": rca.recommendations,
        "analyzed_by": rca.analyzed_by,
        "analyzed_at": rca.analyzed_at.isoformat() if rca.analyzed_at else None,
    }


# ========== Problem CRUD ==========

@router.get("/list")
def list_problems(
    client_id: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    category: Optional[str] = None,
):
    """List problem records with optional filters."""
    svc = get_pm()
    st = ProblemStatus(status) if status else None
    pr = ProblemPriority(priority) if priority else None
    cat = ProblemCategory(category) if category else None
    problems = svc.list_problems(client_id=client_id, status=st, priority=pr, category=cat)
    return {"problems": [_problem_to_dict(p) for p in problems], "total": len(problems)}


@router.get("/dashboard")
def get_dashboard():
    """Get the problem management dashboard."""
    svc = get_pm()
    return svc.get_dashboard()


@router.get("/trends")
def get_trends():
    """Get problem trend analytics."""
    svc = get_pm()
    trends = svc.get_problem_trends()
    return {
        "trends": [
            {
                "category": t.category,
                "count": t.count,
                "trend_direction": t.trend_direction,
                "avg_resolution_days": t.avg_resolution_days,
            }
            for t in trends
        ]
    }


@router.get("/top-root-causes")
def get_top_root_causes(limit: int = Query(10, ge=1, le=50)):
    """Get the most common root causes."""
    svc = get_pm()
    return {"root_causes": svc.get_top_root_causes(limit)}


@router.get("/recurring-incidents")
def get_recurring_incidents(threshold: int = Query(3, ge=1)):
    """Get problems linked to many incidents (recurring patterns)."""
    svc = get_pm()
    return {"recurring": svc.get_recurring_incidents(threshold)}


@router.post("/create")
def create_problem(data: ProblemCreate):
    """Create a new problem record."""
    svc = get_pm()
    pr = svc.create_problem(
        client_id=data.client_id,
        title=data.title,
        description=data.description,
        priority=ProblemPriority(data.priority),
        category=ProblemCategory(data.category),
        affected_services=data.affected_services,
        related_incidents=data.related_incidents,
        assigned_to=data.assigned_to,
        impact_assessment=data.impact_assessment,
    )
    return _problem_to_dict(pr)


@router.get("/{problem_id}")
def get_problem(problem_id: str):
    """Get a specific problem record."""
    svc = get_pm()
    pr = svc.get_problem(problem_id)
    if not pr:
        raise HTTPException(status_code=404, detail="Problem not found")
    return _problem_to_dict(pr)


@router.put("/{problem_id}")
def update_problem(problem_id: str, data: ProblemUpdate):
    """Update a problem record."""
    svc = get_pm()
    updates = {}
    if data.title is not None:
        updates["title"] = data.title
    if data.description is not None:
        updates["description"] = data.description
    if data.priority is not None:
        updates["priority"] = ProblemPriority(data.priority)
    if data.category is not None:
        updates["category"] = ProblemCategory(data.category)
    if data.assigned_to is not None:
        updates["assigned_to"] = data.assigned_to
    if data.impact_assessment is not None:
        updates["impact_assessment"] = data.impact_assessment
    if data.affected_services is not None:
        updates["affected_services"] = data.affected_services

    pr = svc.update_problem(problem_id, **updates)
    if not pr:
        raise HTTPException(status_code=404, detail="Problem not found")
    return _problem_to_dict(pr)


@router.delete("/{problem_id}")
def delete_problem(problem_id: str):
    """Delete a problem record."""
    svc = get_pm()
    if not svc.delete_problem(problem_id):
        raise HTTPException(status_code=404, detail="Problem not found")
    return {"deleted": True, "problem_id": problem_id}


# ========== Investigation Workflow ==========

@router.post("/{problem_id}/investigate")
def investigate_problem(problem_id: str):
    """Move a problem to under_investigation status."""
    svc = get_pm()
    pr = svc.investigate(problem_id)
    if not pr:
        raise HTTPException(status_code=404, detail="Problem not found")
    return _problem_to_dict(pr)


@router.post("/{problem_id}/root-cause")
def identify_root_cause(problem_id: str, data: RootCausePayload):
    """Identify the root cause for a problem."""
    svc = get_pm()
    pr = svc.identify_root_cause(
        problem_id=problem_id,
        root_cause=data.root_cause,
        method=RCAMethod(data.method),
    )
    if not pr:
        raise HTTPException(status_code=404, detail="Problem not found")
    return _problem_to_dict(pr)


@router.post("/{problem_id}/known-error")
def create_known_error(problem_id: str, data: KnownErrorCreate):
    """Create a Known Error entry from a problem."""
    svc = get_pm()
    ke = svc.create_known_error(
        problem_id=problem_id,
        workaround=data.workaround,
        symptoms=data.symptoms,
        affected_cis=data.affected_cis,
    )
    if not ke:
        raise HTTPException(status_code=400, detail="Cannot create known error. Problem not found or no root cause identified.")
    return _ke_to_dict(ke)


@router.post("/{problem_id}/resolve")
def resolve_problem(problem_id: str, data: ResolvePayload):
    """Resolve a problem with a permanent fix."""
    svc = get_pm()
    pr = svc.resolve_problem(problem_id=problem_id, resolution=data.resolution)
    if not pr:
        raise HTTPException(status_code=404, detail="Problem not found")
    return _problem_to_dict(pr)


@router.post("/{problem_id}/close")
def close_problem(problem_id: str):
    """Close a resolved problem."""
    svc = get_pm()
    pr = svc.close_problem(problem_id)
    if not pr:
        raise HTTPException(status_code=404, detail="Problem not found")
    return _problem_to_dict(pr)


@router.post("/{problem_id}/link-incident")
def link_incident(problem_id: str, data: LinkIncidentPayload):
    """Link an incident to a problem."""
    svc = get_pm()
    pr = svc.link_incident(problem_id=problem_id, incident_id=data.incident_id)
    if not pr:
        raise HTTPException(status_code=404, detail="Problem not found")
    return _problem_to_dict(pr)


# ========== Root Cause Analysis ==========

@router.post("/{problem_id}/rca")
def perform_rca(problem_id: str, data: RCAPayload):
    """Perform root cause analysis on a problem."""
    svc = get_pm()
    rca = svc.perform_rca(
        problem_id=problem_id,
        method=RCAMethod(data.method),
        analysis_data=data.analysis_data,
        findings=data.findings,
        contributing_factors=data.contributing_factors,
        recommendations=data.recommendations,
        analyzed_by=data.analyzed_by,
    )
    if not rca:
        raise HTTPException(status_code=404, detail="Problem not found")
    return _rca_to_dict(rca)


@router.get("/{problem_id}/rcas")
def list_rcas(problem_id: str):
    """List all RCAs for a problem."""
    svc = get_pm()
    rcas = svc.list_rcas_for_problem(problem_id)
    return {"rcas": [_rca_to_dict(r) for r in rcas], "total": len(rcas)}


# ========== Known Error Database (KEDB) ==========

@router.get("/kedb/list")
def list_known_errors(fix_status: Optional[str] = None):
    """List all known errors."""
    svc = get_pm()
    fs = FixStatus(fix_status) if fix_status else None
    kes = svc.list_known_errors(fix_status=fs)
    return {"known_errors": [_ke_to_dict(ke) for ke in kes], "total": len(kes)}


@router.get("/kedb/{ke_id}")
def get_known_error(ke_id: str):
    """Get a specific known error."""
    svc = get_pm()
    ke = svc.get_known_error(ke_id)
    if not ke:
        raise HTTPException(status_code=404, detail="Known error not found")
    return _ke_to_dict(ke)


@router.post("/kedb/search")
def search_known_errors(data: SymptomSearch):
    """Search the KEDB by symptoms."""
    svc = get_pm()
    matches = svc.search_known_errors(data.symptoms)
    return {"matches": matches, "total": len(matches)}


@router.post("/kedb/match-incident")
def match_incident(data: IncidentMatch):
    """Match incident data to a known error."""
    svc = get_pm()
    incident_data = {
        "title": data.title,
        "description": data.description,
        "symptoms": data.symptoms,
    }
    match = svc.match_incident_to_known_error(incident_data)
    if not match:
        return {"matched": False, "known_error": None}
    return {"matched": True, "known_error": match}
