"""
API Routes for SOAR Playbook Engine
Extends Cyber-911 with configurable incident response playbooks.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.soar_playbook import (
    SOARPlaybookService,
    ActionType,
    ExecutionStatus,
    TriggerType,
)

router = APIRouter(prefix="/soar", tags=["SOAR - Playbook Engine"])

# Singleton instance
_soar_instance: Optional[SOARPlaybookService] = None


def get_soar() -> SOARPlaybookService:
    """Get or create SOAR Playbook instance with DB persistence"""
    global _soar_instance
    if _soar_instance is None:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            _soar_instance = SOARPlaybookService(db=db)
        except Exception:
            _soar_instance = SOARPlaybookService()
    return _soar_instance


# ========== Pydantic Models ==========

class PlaybookStepCreate(BaseModel):
    """Playbook step creation model"""
    step_id: Optional[str] = None
    step_number: Optional[int] = None
    name: str
    action_type: str
    parameters: Dict[str, Any] = {}
    timeout_seconds: int = 300
    on_failure: str = "abort"
    condition: Optional[str] = None
    wait_for_approval: bool = False
    assigned_to: Optional[str] = None


class PlaybookCreate(BaseModel):
    """Playbook creation model"""
    playbook_id: Optional[str] = None
    name: str
    description: str = ""
    trigger_type: str = "manual"
    trigger_conditions: Dict[str, Any] = {}
    steps: List[PlaybookStepCreate] = []
    tags: List[str] = []
    is_enabled: bool = True
    created_by: str = "user"


class PlaybookUpdate(BaseModel):
    """Playbook update model"""
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_conditions: Optional[Dict[str, Any]] = None
    steps: Optional[List[PlaybookStepCreate]] = None
    tags: Optional[List[str]] = None
    is_enabled: Optional[bool] = None


class PlaybookClone(BaseModel):
    """Playbook clone request"""
    new_name: Optional[str] = None


class ExecuteRequest(BaseModel):
    """Playbook execution request"""
    incident_id: str
    context: Dict[str, Any] = {}
    triggered_by: str = "manual"


class EvaluateRequest(BaseModel):
    """Trigger evaluation request"""
    incident_id: Optional[str] = None
    threat_type: str = ""
    severity: int = 0
    source: str = ""
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None


class ApproveRequest(BaseModel):
    """Step approval request"""
    approved_by: str = "admin"


# ========== Playbook CRUD ==========

@router.post("/playbooks")
async def create_playbook(data: PlaybookCreate):
    """Create a new SOAR playbook"""
    svc = get_soar()
    pb = svc.create_playbook(data.model_dump())
    result = svc.get_playbook(pb.playbook_id)
    return {"status": "created", "playbook": result}


@router.get("/playbooks")
async def list_playbooks(
    enabled_only: bool = Query(False),
    tag: Optional[str] = Query(None),
):
    """List all SOAR playbooks"""
    svc = get_soar()
    return {"playbooks": svc.list_playbooks(enabled_only=enabled_only, tag=tag)}


@router.get("/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str):
    """Get a single playbook by ID"""
    svc = get_soar()
    result = svc.get_playbook(playbook_id)
    if not result:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return result


@router.put("/playbooks/{playbook_id}")
async def update_playbook(playbook_id: str, data: PlaybookUpdate):
    """Update an existing playbook"""
    svc = get_soar()
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    if "steps" in update_data:
        update_data["steps"] = [s.model_dump() if hasattr(s, "model_dump") else s for s in update_data["steps"]]
    pb = svc.update_playbook(playbook_id, update_data)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"status": "updated", "playbook": svc.get_playbook(playbook_id)}


@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str):
    """Delete a playbook"""
    svc = get_soar()
    if not svc.delete_playbook(playbook_id):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"status": "deleted", "playbook_id": playbook_id}


@router.post("/playbooks/{playbook_id}/clone")
async def clone_playbook(playbook_id: str, data: PlaybookClone = PlaybookClone()):
    """Clone an existing playbook"""
    svc = get_soar()
    pb = svc.clone_playbook(playbook_id, new_name=data.new_name)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"status": "cloned", "playbook": svc.get_playbook(pb.playbook_id)}


# ========== Execution ==========

@router.post("/playbooks/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, data: ExecuteRequest):
    """Manually trigger a playbook execution"""
    svc = get_soar()
    execution = await svc.execute_playbook(
        playbook_id, data.incident_id,
        context=data.context, triggered_by=data.triggered_by,
    )
    if not execution:
        raise HTTPException(status_code=404, detail="Playbook not found or disabled")
    return {"status": "executed", "execution": svc.get_execution(execution.execution_id)}


@router.get("/executions")
async def list_executions(
    playbook_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    """List playbook executions"""
    svc = get_soar()
    return {"executions": svc.list_executions(playbook_id=playbook_id, status=status, limit=limit)}


@router.get("/executions/{execution_id}")
async def get_execution(execution_id: str):
    """Get execution details"""
    svc = get_soar()
    result = svc.get_execution(execution_id)
    if not result:
        raise HTTPException(status_code=404, detail="Execution not found")
    return result


@router.post("/executions/{execution_id}/abort")
async def abort_execution(execution_id: str):
    """Abort a running execution"""
    svc = get_soar()
    result = await svc.abort_execution(execution_id)
    if not result:
        raise HTTPException(status_code=404, detail="Execution not found")
    return {"status": "aborted", "execution": result}


@router.post("/executions/{execution_id}/steps/{step_id}/approve")
async def approve_step(execution_id: str, step_id: str, data: ApproveRequest = ApproveRequest()):
    """Approve a pending approval gate step"""
    svc = get_soar()
    result = await svc.approve_step(execution_id, step_id)
    if not result:
        raise HTTPException(status_code=404, detail="Execution or step not found, or not awaiting approval")
    return {"status": "approved", "execution": result}


# ========== Trigger Evaluation ==========

@router.post("/evaluate")
async def evaluate_triggers(data: EvaluateRequest):
    """Evaluate all automatic playbook triggers for an incident"""
    svc = get_soar()
    incident = data.model_dump()
    executions = await svc.evaluate_triggers(incident)
    return {
        "triggered_count": len(executions),
        "executions": [svc.get_execution(ex.execution_id) for ex in executions],
    }


# ========== Analytics & Dashboard ==========

@router.get("/analytics")
async def get_analytics():
    """Get SOAR analytics"""
    svc = get_soar()
    return {
        "stats": svc.get_playbook_stats(),
        "most_triggered": svc.get_most_triggered(),
        "avg_resolution_time_seconds": svc.get_average_resolution_time(),
    }


@router.get("/dashboard")
async def get_dashboard():
    """Get SOAR dashboard data"""
    svc = get_soar()
    return svc.get_dashboard()
