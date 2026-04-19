"""
API Routes for MSP Client Onboarding Workflow
Automates the process of bringing new MSP clients onto the platform.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.onboarding import (
    OnboardingService,
    WorkflowStatus,
    PhaseStatus,
    TaskStatus,
    TaskType,
)

router = APIRouter(prefix="/msp-onboarding", tags=["MSP Client Onboarding"])


def _init_onboarding_service() -> OnboardingService:
    """Initialize OnboardingService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return OnboardingService(db=db)
    except Exception:
        return OnboardingService()


# Initialize service with DB persistence
onboarding_service = _init_onboarding_service()


# ========== Request/Response Models ==========

class TemplateCreate(BaseModel):
    name: str
    description: str = ""
    plan_type: str = "standard"
    phases: List[Dict[str, Any]] = []
    estimated_duration_days: int = 14


class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    plan_type: Optional[str] = None
    phases: Optional[List[Dict[str, Any]]] = None
    estimated_duration_days: Optional[int] = None


class WorkflowStart(BaseModel):
    client_id: str
    company_name: str
    template_id: Optional[str] = None
    primary_contact: str = ""
    plan_id: str = ""
    assigned_technician: str = ""
    notes: str = ""


class TaskComplete(BaseModel):
    result: Optional[Dict[str, Any]] = None


class TaskSkip(BaseModel):
    reason: str = ""


class PhaseBlock(BaseModel):
    phase_id: str
    reason: str = ""


class WorkflowStall(BaseModel):
    reason: str = ""


class WorkflowCancel(BaseModel):
    reason: str = ""


class ChecklistItemUpdate(BaseModel):
    completed: bool
    completed_by: str = ""
    notes: str = ""


# ========== Helpers ==========

def _workflow_to_dict(wf) -> Dict[str, Any]:
    """Serialize a workflow dataclass to dict."""
    return {
        "workflow_id": wf.workflow_id,
        "client_id": wf.client_id,
        "company_name": wf.company_name,
        "primary_contact": wf.primary_contact,
        "plan_id": wf.plan_id,
        "status": wf.status,
        "current_phase": wf.current_phase,
        "assigned_technician": wf.assigned_technician,
        "started_at": wf.started_at.isoformat() if wf.started_at else None,
        "target_completion": wf.target_completion.isoformat() if wf.target_completion else None,
        "completed_at": wf.completed_at.isoformat() if wf.completed_at else None,
        "notes": wf.notes,
        "phases": [_phase_to_dict(ph) for ph in wf.phases],
    }


def _phase_to_dict(ph) -> Dict[str, Any]:
    return {
        "phase_id": ph.phase_id,
        "phase_number": ph.phase_number,
        "name": ph.name,
        "description": ph.description,
        "status": ph.status,
        "started_at": ph.started_at.isoformat() if ph.started_at else None,
        "completed_at": ph.completed_at.isoformat() if ph.completed_at else None,
        "dependencies": ph.dependencies,
        "tasks": [_task_to_dict(tk) for tk in ph.tasks],
    }


def _task_to_dict(tk) -> Dict[str, Any]:
    return {
        "task_id": tk.task_id,
        "phase_id": tk.phase_id,
        "name": tk.name,
        "description": tk.description,
        "task_type": tk.task_type,
        "status": tk.status,
        "assigned_to": tk.assigned_to,
        "automated_action": tk.automated_action,
        "result": tk.result,
        "started_at": tk.started_at.isoformat() if tk.started_at else None,
        "completed_at": tk.completed_at.isoformat() if tk.completed_at else None,
    }


def _template_to_dict(tpl) -> Dict[str, Any]:
    return {
        "template_id": tpl.template_id,
        "name": tpl.name,
        "description": tpl.description,
        "plan_type": tpl.plan_type,
        "phases": tpl.phases,
        "estimated_duration_days": tpl.estimated_duration_days,
        "created_at": tpl.created_at.isoformat() if tpl.created_at else None,
    }


def _checklist_to_dict(cl) -> Dict[str, Any]:
    return {
        "checklist_id": cl.checklist_id,
        "workflow_id": cl.workflow_id,
        "items": [
            {
                "item_id": i.item_id,
                "category": i.category,
                "description": i.description,
                "is_required": i.is_required,
                "is_completed": i.is_completed,
                "completed_by": i.completed_by,
                "completed_at": i.completed_at.isoformat() if i.completed_at else None,
                "notes": i.notes,
            }
            for i in cl.items
        ],
    }


# ========== Template Routes ==========

@router.post("/templates", tags=["MSP Client Onboarding"])
async def create_template(data: TemplateCreate):
    """Create a new onboarding template."""
    tpl = onboarding_service.create_template(
        name=data.name,
        description=data.description,
        plan_type=data.plan_type,
        phases=data.phases,
        estimated_duration_days=data.estimated_duration_days,
    )
    return _template_to_dict(tpl)


@router.get("/templates", tags=["MSP Client Onboarding"])
async def list_templates():
    """List all onboarding templates."""
    templates = onboarding_service.list_templates()
    return [_template_to_dict(t) for t in templates]


@router.get("/templates/{template_id}", tags=["MSP Client Onboarding"])
async def get_template(template_id: str):
    """Get a specific onboarding template."""
    tpl = onboarding_service.get_template(template_id)
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return _template_to_dict(tpl)


@router.put("/templates/{template_id}", tags=["MSP Client Onboarding"])
async def update_template(template_id: str, data: TemplateUpdate):
    """Update an onboarding template."""
    updates = data.dict(exclude_none=True)
    tpl = onboarding_service.update_template(template_id, **updates)
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return _template_to_dict(tpl)


# ========== Workflow Routes ==========

@router.post("/start", tags=["MSP Client Onboarding"])
async def start_onboarding(data: WorkflowStart):
    """Start a new client onboarding workflow."""
    try:
        wf = onboarding_service.start_onboarding(
            client_id=data.client_id,
            company_name=data.company_name,
            template_id=data.template_id,
            primary_contact=data.primary_contact,
            plan_id=data.plan_id,
            assigned_technician=data.assigned_technician,
            notes=data.notes,
        )
        return _workflow_to_dict(wf)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/workflows", tags=["MSP Client Onboarding"])
async def list_workflows(
    status: Optional[str] = Query(None, description="Filter by status"),
    client_id: Optional[str] = Query(None, description="Filter by client ID"),
):
    """List onboarding workflows with optional filters."""
    workflows = onboarding_service.list_workflows(status=status, client_id=client_id)
    return [_workflow_to_dict(w) for w in workflows]


@router.get("/workflows/{workflow_id}", tags=["MSP Client Onboarding"])
async def get_workflow(workflow_id: str):
    """Get a specific onboarding workflow with all phases and tasks."""
    wf = onboarding_service.get_workflow(workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return _workflow_to_dict(wf)


@router.get("/workflows/{workflow_id}/progress", tags=["MSP Client Onboarding"])
async def get_progress(workflow_id: str):
    """Get onboarding progress: percentage, current phase, blockers."""
    try:
        return onboarding_service.get_onboarding_progress(workflow_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ========== Task Routes ==========

@router.post("/workflows/{workflow_id}/tasks/{task_id}/complete", tags=["MSP Client Onboarding"])
async def complete_task(workflow_id: str, task_id: str, data: TaskComplete):
    """Mark a task as completed."""
    try:
        task = onboarding_service.complete_task(workflow_id, task_id, result=data.result)
        return _task_to_dict(task)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/workflows/{workflow_id}/tasks/{task_id}/skip", tags=["MSP Client Onboarding"])
async def skip_task(workflow_id: str, task_id: str, data: TaskSkip):
    """Skip a task."""
    try:
        task = onboarding_service.skip_task(workflow_id, task_id, reason=data.reason)
        return _task_to_dict(task)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/workflows/{workflow_id}/tasks/{task_id}/execute", tags=["MSP Client Onboarding"])
async def execute_automated_task(workflow_id: str, task_id: str):
    """Execute an automated task."""
    try:
        task = onboarding_service.execute_automated_task(workflow_id, task_id)
        return _task_to_dict(task)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ========== Phase Routes ==========

@router.post("/workflows/{workflow_id}/advance", tags=["MSP Client Onboarding"])
async def advance_phase(workflow_id: str):
    """Advance the workflow to the next phase."""
    try:
        wf = onboarding_service.advance_phase(workflow_id)
        return _workflow_to_dict(wf)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/workflows/{workflow_id}/block", tags=["MSP Client Onboarding"])
async def block_phase(workflow_id: str, data: PhaseBlock):
    """Block a phase."""
    try:
        phase = onboarding_service.block_phase(workflow_id, data.phase_id, reason=data.reason)
        return _phase_to_dict(phase)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ========== Checklist Routes ==========

@router.get("/workflows/{workflow_id}/checklist", tags=["MSP Client Onboarding"])
async def get_checklist(workflow_id: str):
    """Get the pre-flight checklist for a workflow."""
    cl = onboarding_service.get_client_checklist(workflow_id)
    if not cl:
        raise HTTPException(status_code=404, detail="Checklist not found")
    return _checklist_to_dict(cl)


@router.put("/workflows/{workflow_id}/checklist/{item_id}", tags=["MSP Client Onboarding"])
async def update_checklist_item(workflow_id: str, item_id: str, data: ChecklistItemUpdate):
    """Update a checklist item."""
    item = onboarding_service.update_checklist_item(
        workflow_id, item_id,
        completed=data.completed,
        completed_by=data.completed_by,
        notes=data.notes,
    )
    if not item:
        raise HTTPException(status_code=404, detail="Checklist item not found")
    return {
        "item_id": item.item_id,
        "category": item.category,
        "description": item.description,
        "is_required": item.is_required,
        "is_completed": item.is_completed,
        "completed_by": item.completed_by,
        "completed_at": item.completed_at.isoformat() if item.completed_at else None,
        "notes": item.notes,
    }


# ========== Lifecycle Routes ==========

@router.post("/workflows/{workflow_id}/stall", tags=["MSP Client Onboarding"])
async def stall_workflow(workflow_id: str, data: WorkflowStall):
    """Mark a workflow as stalled."""
    try:
        wf = onboarding_service.stall_workflow(workflow_id, reason=data.reason)
        return _workflow_to_dict(wf)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/workflows/{workflow_id}/cancel", tags=["MSP Client Onboarding"])
async def cancel_workflow(workflow_id: str, data: WorkflowCancel):
    """Cancel an onboarding workflow."""
    try:
        wf = onboarding_service.cancel_workflow(workflow_id, reason=data.reason)
        return _workflow_to_dict(wf)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ========== Analytics Routes ==========

@router.get("/analytics/duration", tags=["MSP Client Onboarding"])
async def get_average_duration():
    """Get average onboarding duration analytics."""
    return onboarding_service.get_average_onboarding_time()


@router.get("/analytics/bottlenecks", tags=["MSP Client Onboarding"])
async def get_bottlenecks():
    """Get bottleneck analysis across all onboarding workflows."""
    return onboarding_service.get_bottleneck_analysis()


# ========== Dashboard Route ==========

@router.get("/dashboard", tags=["MSP Client Onboarding"])
async def get_dashboard():
    """Get onboarding dashboard: active workflows, completion rate, avg duration, stalled count."""
    return onboarding_service.get_dashboard()
