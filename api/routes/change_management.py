"""
API Routes for ITIL-Aligned Change Management Workflow
Full lifecycle: request -> risk assessment -> approval -> implementation -> PIR
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.change_management import (
    ChangeManagementService,
    ChangeType,
    ChangeStatus,
    RiskLevel,
    ChangeCategory,
    ChangePriority,
    ApprovalDecision,
)

router = APIRouter(prefix="/change-management", tags=["Change Management Workflow"])

# Singleton instance
_cm_instance: Optional[ChangeManagementService] = None


def get_cm() -> ChangeManagementService:
    """Get or create ChangeManagementService instance with DB persistence."""
    global _cm_instance
    if _cm_instance is None:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            _cm_instance = ChangeManagementService(db=db)
        except Exception:
            _cm_instance = ChangeManagementService()
    return _cm_instance


# ========== Pydantic Models ==========

class ChangeCreate(BaseModel):
    """Create a change request."""
    client_id: str
    title: str
    description: str
    change_type: str = "normal"
    category: str = "other"
    priority: str = "medium"
    impact_assessment: str = ""
    rollback_plan: str = ""
    implementation_plan: str = ""
    testing_plan: str = ""
    scheduled_start: Optional[str] = None
    scheduled_end: Optional[str] = None
    requested_by: str = ""
    assigned_to: Optional[str] = None
    approvers_required: List[str] = []
    affected_cis: List[str] = []
    related_tickets: List[str] = []


class ChangeUpdate(BaseModel):
    """Update a change request."""
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    impact_assessment: Optional[str] = None
    rollback_plan: Optional[str] = None
    implementation_plan: Optional[str] = None
    testing_plan: Optional[str] = None
    scheduled_start: Optional[str] = None
    scheduled_end: Optional[str] = None
    affected_cis: Optional[List[str]] = None
    related_tickets: Optional[List[str]] = None


class ApprovalAction(BaseModel):
    """Approval decision payload."""
    approver: str
    decision: str  # approved / rejected / deferred
    comments: str = ""


class RiskCalculation(BaseModel):
    """Risk calculation input."""
    change_type: str = "normal"
    impact_scope: str = "department"
    rollback_complexity: str = "moderate"
    testing_coverage: str = "partial"
    scheduled_start: Optional[str] = None
    scheduled_end: Optional[str] = None
    change_id: Optional[str] = None


class TemplateCreate(BaseModel):
    """Create a change template."""
    name: str
    description: str
    change_type: str = "standard"
    category: str = "other"
    default_risk_level: str = "low"
    steps: List[str] = []
    approvers_required: List[str] = []
    estimated_duration_minutes: int = 30
    rollback_steps: List[str] = []


class TemplateInstantiate(BaseModel):
    """Create a change from a template."""
    client_id: str
    title: str = ""
    requested_by: str = ""
    overrides: Dict[str, Any] = {}


class PIRCreate(BaseModel):
    """Post-Implementation Review input."""
    was_successful: bool = True
    objectives_met: bool = True
    issues_encountered: List[str] = []
    lessons_learned: List[str] = []
    follow_up_actions: List[str] = []
    reviewed_by: str = ""
    notes: str = ""


class BlackoutCreate(BaseModel):
    """Create a blackout window."""
    client_id: str
    name: str
    start_time: str
    end_time: str
    reason: str = ""
    is_recurring: bool = False
    recurrence_pattern: Optional[str] = None


class ConflictCheck(BaseModel):
    """Check for scheduling conflicts."""
    scheduled_start: str
    scheduled_end: str


class CompletePayload(BaseModel):
    """Complete change payload."""
    success: bool = True


class ReasonPayload(BaseModel):
    """Payload with a reason string."""
    reason: str = ""


# ========== Helper ==========

def _parse_dt(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None


# ========== Change CRUD ==========

@router.get("/list")
def list_changes(
    client_id: Optional[str] = None,
    status: Optional[str] = None,
    change_type: Optional[str] = None,
    priority: Optional[str] = None,
    category: Optional[str] = None,
):
    """List change requests with optional filters."""
    svc = get_cm()
    st = ChangeStatus(status) if status else None
    ct = ChangeType(change_type) if change_type else None
    pr = ChangePriority(priority) if priority else None
    cat = ChangeCategory(category) if category else None
    changes = svc.list_changes(client_id=client_id, status=st, change_type=ct, priority=pr, category=cat)
    return {"changes": [svc.change_to_dict(c) for c in changes], "total": len(changes)}


@router.get("/{change_id}")
def get_change(change_id: str):
    """Get a specific change request."""
    svc = get_cm()
    cr = svc.get_change(change_id)
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.change_to_dict(cr)


@router.post("/create")
def create_change(data: ChangeCreate):
    """Create a new change request."""
    svc = get_cm()
    cr = svc.create_change(
        client_id=data.client_id,
        title=data.title,
        description=data.description,
        change_type=ChangeType(data.change_type),
        category=ChangeCategory(data.category),
        priority=ChangePriority(data.priority),
        impact_assessment=data.impact_assessment,
        rollback_plan=data.rollback_plan,
        implementation_plan=data.implementation_plan,
        testing_plan=data.testing_plan,
        scheduled_start=_parse_dt(data.scheduled_start),
        scheduled_end=_parse_dt(data.scheduled_end),
        requested_by=data.requested_by,
        assigned_to=data.assigned_to,
        approvers_required=data.approvers_required,
        affected_cis=data.affected_cis,
        related_tickets=data.related_tickets,
    )
    return svc.change_to_dict(cr)


@router.put("/{change_id}")
def update_change(change_id: str, data: ChangeUpdate):
    """Update a change request."""
    svc = get_cm()
    updates = {}
    if data.title is not None:
        updates["title"] = data.title
    if data.description is not None:
        updates["description"] = data.description
    if data.priority is not None:
        updates["priority"] = ChangePriority(data.priority)
    if data.assigned_to is not None:
        updates["assigned_to"] = data.assigned_to
    if data.impact_assessment is not None:
        updates["impact_assessment"] = data.impact_assessment
    if data.rollback_plan is not None:
        updates["rollback_plan"] = data.rollback_plan
    if data.implementation_plan is not None:
        updates["implementation_plan"] = data.implementation_plan
    if data.testing_plan is not None:
        updates["testing_plan"] = data.testing_plan
    if data.scheduled_start is not None:
        updates["scheduled_start"] = _parse_dt(data.scheduled_start)
    if data.scheduled_end is not None:
        updates["scheduled_end"] = _parse_dt(data.scheduled_end)
    if data.affected_cis is not None:
        updates["affected_cis"] = data.affected_cis
    if data.related_tickets is not None:
        updates["related_tickets"] = data.related_tickets

    cr = svc.update_change(change_id, **updates)
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.change_to_dict(cr)


# ========== Workflow ==========

@router.post("/{change_id}/submit")
def submit_change(change_id: str):
    """Submit a draft change for review."""
    svc = get_cm()
    try:
        cr = svc.submit_change(change_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.change_to_dict(cr)


@router.post("/{change_id}/approve")
def approve_change(change_id: str, data: ApprovalAction):
    """Record an approval decision."""
    svc = get_cm()
    try:
        cr = svc.approve_change(
            change_id=change_id,
            approver=data.approver,
            decision=ApprovalDecision(data.decision),
            comments=data.comments,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.change_to_dict(cr)


@router.post("/{change_id}/implement")
def start_implementation(change_id: str):
    """Start implementing a change."""
    svc = get_cm()
    try:
        cr = svc.start_implementation(change_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.change_to_dict(cr)


@router.post("/{change_id}/complete")
def complete_change(change_id: str, data: CompletePayload = CompletePayload()):
    """Mark a change as completed or failed."""
    svc = get_cm()
    try:
        cr = svc.complete_change(change_id, success=data.success)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.change_to_dict(cr)


@router.post("/{change_id}/rollback")
def rollback_change(change_id: str, data: ReasonPayload = ReasonPayload()):
    """Roll back a change."""
    svc = get_cm()
    try:
        cr = svc.rollback_change(change_id, reason=data.reason)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.change_to_dict(cr)


@router.post("/{change_id}/cancel")
def cancel_change(change_id: str, data: ReasonPayload = ReasonPayload()):
    """Cancel a change request."""
    svc = get_cm()
    try:
        cr = svc.cancel_change(change_id, reason=data.reason)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.change_to_dict(cr)


# ========== Risk ==========

@router.post("/risk/calculate")
def calculate_risk(data: RiskCalculation):
    """Calculate risk score from weighted factors."""
    svc = get_cm()
    change_data = {
        "change_type": data.change_type,
        "impact_scope": data.impact_scope,
        "rollback_complexity": data.rollback_complexity,
        "testing_coverage": data.testing_coverage,
        "change_id": data.change_id,
    }
    if data.scheduled_start:
        change_data["scheduled_start"] = _parse_dt(data.scheduled_start)
    if data.scheduled_end:
        change_data["scheduled_end"] = _parse_dt(data.scheduled_end)

    score = svc.calculate_risk_score(change_data)
    level = svc._score_to_level(score)
    return {"risk_score": score, "risk_level": level.value}


# ========== Approvals ==========

@router.get("/approvals/pending/{approver}")
def get_pending_approvals(approver: str):
    """Get changes awaiting approval from a specific approver."""
    svc = get_cm()
    pending = svc.get_pending_approvals(approver)
    return {"pending": [svc.change_to_dict(c) for c in pending], "total": len(pending)}


@router.get("/{change_id}/approvals")
def get_approval_history(change_id: str):
    """Get approval history for a change."""
    svc = get_cm()
    history = svc.get_approval_history(change_id)
    return {"approvals": [svc.approval_to_dict(a) for a in history], "total": len(history)}


# ========== Templates ==========

@router.get("/templates/list")
def list_templates():
    """List all change templates."""
    svc = get_cm()
    templates = svc.list_templates()
    return {"templates": [svc.template_to_dict(t) for t in templates], "total": len(templates)}


@router.get("/templates/{template_id}")
def get_template(template_id: str):
    """Get a specific template."""
    svc = get_cm()
    tpl = svc.get_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return svc.template_to_dict(tpl)


@router.post("/templates/create")
def create_template(data: TemplateCreate):
    """Create a new change template."""
    svc = get_cm()
    tpl = svc.create_template(
        name=data.name,
        description=data.description,
        change_type=ChangeType(data.change_type),
        category=ChangeCategory(data.category),
        default_risk_level=RiskLevel(data.default_risk_level),
        steps=data.steps,
        approvers_required=data.approvers_required,
        estimated_duration_minutes=data.estimated_duration_minutes,
        rollback_steps=data.rollback_steps,
    )
    return svc.template_to_dict(tpl)


@router.post("/templates/{template_id}/instantiate")
def instantiate_template(template_id: str, data: TemplateInstantiate):
    """Create a change request from a template."""
    svc = get_cm()
    cr = svc.create_from_template(
        template_id=template_id,
        client_id=data.client_id,
        title=data.title,
        requested_by=data.requested_by,
        overrides=data.overrides,
    )
    if not cr:
        raise HTTPException(status_code=404, detail="Template not found")
    return svc.change_to_dict(cr)


# ========== PIR ==========

@router.post("/{change_id}/pir")
def create_pir(change_id: str, data: PIRCreate):
    """Create a Post-Implementation Review."""
    svc = get_cm()
    try:
        pir = svc.create_pir(change_id, {
            "was_successful": data.was_successful,
            "objectives_met": data.objectives_met,
            "issues_encountered": data.issues_encountered,
            "lessons_learned": data.lessons_learned,
            "follow_up_actions": data.follow_up_actions,
            "reviewed_by": data.reviewed_by,
            "notes": data.notes,
        })
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not pir:
        raise HTTPException(status_code=404, detail="Change request not found")
    return svc.pir_to_dict(pir)


@router.get("/{change_id}/pir")
def get_pir(change_id: str):
    """Get PIR for a change."""
    svc = get_cm()
    pir = svc.get_pir(change_id)
    if not pir:
        raise HTTPException(status_code=404, detail="PIR not found")
    return svc.pir_to_dict(pir)


# ========== Calendar ==========

@router.get("/calendar/view")
def get_change_calendar(
    client_id: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    """Get change calendar entries."""
    svc = get_cm()
    entries = svc.get_change_calendar(
        client_id=client_id,
        start=_parse_dt(start),
        end=_parse_dt(end),
    )
    return {"entries": [svc.calendar_to_dict(e) for e in entries], "total": len(entries)}


@router.post("/calendar/conflicts")
def check_conflicts(data: ConflictCheck):
    """Check for scheduling conflicts."""
    svc = get_cm()
    s = _parse_dt(data.scheduled_start)
    e = _parse_dt(data.scheduled_end)
    if not s or not e:
        raise HTTPException(status_code=400, detail="Invalid date format")
    conflicts = svc.check_conflicts(s, e)
    return {"conflicts": conflicts, "has_conflicts": len(conflicts) > 0, "total": len(conflicts)}


# ========== Blackout Windows ==========

@router.post("/blackout/create")
def create_blackout(data: BlackoutCreate):
    """Create a blackout window."""
    svc = get_cm()
    s = _parse_dt(data.start_time)
    e = _parse_dt(data.end_time)
    if not s or not e:
        raise HTTPException(status_code=400, detail="Invalid date format")
    bw = svc.create_blackout_window(
        client_id=data.client_id,
        name=data.name,
        start_time=s,
        end_time=e,
        reason=data.reason,
        is_recurring=data.is_recurring,
        recurrence_pattern=data.recurrence_pattern,
    )
    return svc.blackout_to_dict(bw)


@router.get("/blackout/list")
def list_blackouts(client_id: Optional[str] = None):
    """List blackout windows."""
    svc = get_cm()
    windows = svc.list_blackout_windows(client_id=client_id)
    return {"blackout_windows": [svc.blackout_to_dict(bw) for bw in windows], "total": len(windows)}


@router.delete("/blackout/{window_id}")
def delete_blackout(window_id: str):
    """Delete a blackout window."""
    svc = get_cm()
    if not svc.delete_blackout_window(window_id):
        raise HTTPException(status_code=404, detail="Blackout window not found")
    return {"status": "deleted", "window_id": window_id}


@router.get("/blackout/check")
def check_blackout(dt: str):
    """Check if a datetime falls within a blackout window."""
    svc = get_cm()
    parsed = _parse_dt(dt)
    if not parsed:
        raise HTTPException(status_code=400, detail="Invalid date format")
    in_blackout = svc.check_blackout(parsed)
    return {"datetime": dt, "in_blackout": in_blackout}


# ========== Analytics ==========

@router.get("/analytics/success-rate")
def get_success_rate():
    """Get change success rate."""
    svc = get_cm()
    return {"success_rate": svc.get_change_success_rate()}


@router.get("/analytics/avg-implementation-time")
def get_avg_implementation_time():
    """Get average implementation time in minutes."""
    svc = get_cm()
    return {"avg_minutes": svc.get_avg_implementation_time()}


@router.get("/analytics/by-category")
def get_by_category():
    """Get changes grouped by category."""
    svc = get_cm()
    return {"by_category": svc.get_changes_by_category()}


@router.get("/analytics/risk-distribution")
def get_risk_distribution():
    """Get risk level distribution."""
    svc = get_cm()
    return {"risk_distribution": svc.get_risk_distribution()}


# ========== Dashboard ==========

@router.get("/dashboard")
def get_dashboard():
    """Get aggregated change management dashboard."""
    svc = get_cm()
    return svc.get_dashboard()
