"""
API Routes for Disaster Recovery Orchestration
Uses DROrchestrationService for all operations.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

from services.msp.dr_orchestration import (
    DROrchestrationService,
    DRTier,
    DrillType,
    DrillStatus,
    FailoverStatus,
    StepActionType,
    PlanStatus,
    _plan_to_dict,
    _drill_to_dict,
    _failover_to_dict,
    _readiness_to_dict,
)

try:
    from core.database import get_sync_db
except Exception:
    get_sync_db = None

router = APIRouter(prefix="/dr-orchestration", tags=["DR Orchestration"])


def _init_service() -> DROrchestrationService:
    """Initialize service with DB if available."""
    try:
        if get_sync_db:
            db_gen = get_sync_db()
            db = next(db_gen)
            return DROrchestrationService(db=db)
    except Exception:
        pass
    return DROrchestrationService()


service = _init_service()


# ========== Request/Response Models ==========

class PlanCreate(BaseModel):
    name: str
    client_id: str = ""
    description: str = ""
    tier: str = DRTier.TIER3_NORMAL.value
    rto_minutes: int = 240
    rpo_minutes: int = 60
    systems_covered: List[str] = []
    dependencies: List[str] = []
    contacts: List[Dict[str, str]] = []
    use_template: bool = False


class PlanUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tier: Optional[str] = None
    rto_minutes: Optional[int] = None
    rpo_minutes: Optional[int] = None
    systems_covered: Optional[List[str]] = None
    dependencies: Optional[List[str]] = None
    contacts: Optional[List[Dict[str, str]]] = None
    status: Optional[str] = None


class StepCreate(BaseModel):
    step_number: Optional[int] = None
    title: str
    description: str = ""
    responsible: str = ""
    action_type: str = StepActionType.MANUAL.value
    automation_script: str = ""
    estimated_duration_minutes: int = 15
    dependencies: List[int] = []
    rollback_instructions: str = ""


class ReorderSteps(BaseModel):
    step_order: List[int]


class DrillSchedule(BaseModel):
    plan_id: str
    drill_type: str = DrillType.TABLETOP.value
    scheduled_at: Optional[str] = None
    participants: List[str] = []


class DrillStepComplete(BaseModel):
    step_number: int
    result: str = "pass"


class DrillComplete(BaseModel):
    findings: List[str] = []
    lessons: List[str] = []
    rto_achieved_minutes: Optional[float] = None
    rpo_achieved_minutes: Optional[float] = None


class FailoverInitiate(BaseModel):
    plan_id: str
    trigger: str = "manual"
    affected_systems: List[str] = []
    incident_id: str = ""


class FailoverRollback(BaseModel):
    reason: str = ""


# ========== Plan Routes ==========

@router.post("/plans")
async def create_plan(data: PlanCreate):
    plan = service.create_plan(
        name=data.name,
        client_id=data.client_id,
        description=data.description,
        tier=data.tier,
        rto_minutes=data.rto_minutes,
        rpo_minutes=data.rpo_minutes,
        systems_covered=data.systems_covered,
        dependencies=data.dependencies,
        contacts=data.contacts,
        use_template=data.use_template,
    )
    return _plan_to_dict(plan)


@router.get("/plans")
async def list_plans(
    client_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    plans = service.list_plans(client_id=client_id, status=status)
    return [_plan_to_dict(p) for p in plans]


@router.get("/plans/{plan_id}")
async def get_plan(plan_id: str):
    plan = service.get_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return _plan_to_dict(plan)


@router.put("/plans/{plan_id}")
async def update_plan(plan_id: str, data: PlanUpdate):
    updates = data.dict(exclude_none=True)
    plan = service.update_plan(plan_id, **updates)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return _plan_to_dict(plan)


@router.delete("/plans/{plan_id}")
async def delete_plan(plan_id: str):
    if not service.delete_plan(plan_id):
        raise HTTPException(status_code=404, detail="Plan not found")
    return {"deleted": True, "plan_id": plan_id}


@router.post("/plans/{plan_id}/steps")
async def add_step(plan_id: str, data: StepCreate):
    step_dict = data.dict()
    if step_dict.get("step_number") is None:
        del step_dict["step_number"]
    plan = service.add_step(plan_id, step_dict)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return _plan_to_dict(plan)


@router.put("/plans/{plan_id}/steps/reorder")
async def reorder_steps(plan_id: str, data: ReorderSteps):
    plan = service.reorder_steps(plan_id, data.step_order)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    return _plan_to_dict(plan)


@router.get("/plans/{plan_id}/validate")
async def validate_plan(plan_id: str):
    result = service.validate_plan(plan_id)
    if "Plan not found" in result.get("errors", []):
        raise HTTPException(status_code=404, detail="Plan not found")
    return result


# ========== Drill Routes ==========

@router.post("/drills")
async def schedule_drill(data: DrillSchedule):
    scheduled_at = None
    if data.scheduled_at:
        try:
            scheduled_at = datetime.fromisoformat(data.scheduled_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scheduled_at datetime format")
    drill = service.schedule_drill(
        plan_id=data.plan_id,
        drill_type=data.drill_type,
        scheduled_at=scheduled_at,
        participants=data.participants,
    )
    if not drill:
        raise HTTPException(status_code=404, detail="Plan not found")
    return _drill_to_dict(drill)


@router.get("/drills")
async def list_drills(
    plan_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    drills = service.list_drills(plan_id=plan_id, status=status)
    return [_drill_to_dict(d) for d in drills]


@router.get("/drills/{drill_id}")
async def get_drill(drill_id: str):
    drill = service.get_drill(drill_id)
    if not drill:
        raise HTTPException(status_code=404, detail="Drill not found")
    return _drill_to_dict(drill)


@router.post("/drills/{drill_id}/start")
async def start_drill(drill_id: str):
    drill = service.start_drill(drill_id)
    if not drill:
        raise HTTPException(status_code=404, detail="Drill not found")
    return _drill_to_dict(drill)


@router.post("/drills/{drill_id}/step")
async def complete_drill_step(drill_id: str, data: DrillStepComplete):
    drill = service.complete_drill_step(drill_id, data.step_number, data.result)
    if not drill:
        raise HTTPException(status_code=404, detail="Drill not found or not in progress")
    return _drill_to_dict(drill)


@router.post("/drills/{drill_id}/complete")
async def complete_drill(drill_id: str, data: DrillComplete):
    drill = service.complete_drill(
        drill_id,
        findings=data.findings,
        lessons=data.lessons,
        rto_achieved_minutes=data.rto_achieved_minutes,
        rpo_achieved_minutes=data.rpo_achieved_minutes,
    )
    if not drill:
        raise HTTPException(status_code=404, detail="Drill not found")
    return _drill_to_dict(drill)


# ========== Failover Routes ==========

@router.post("/failovers")
async def initiate_failover(data: FailoverInitiate):
    event = service.initiate_failover(
        plan_id=data.plan_id,
        trigger=data.trigger,
        affected_systems=data.affected_systems or None,
        incident_id=data.incident_id,
    )
    if not event:
        raise HTTPException(status_code=404, detail="Plan not found")
    return _failover_to_dict(event)


@router.get("/failovers")
async def list_failovers(plan_id: Optional[str] = Query(None)):
    events = service.get_failover_events(plan_id=plan_id)
    return [_failover_to_dict(e) for e in events]


@router.post("/failovers/{event_id}/step/{step_number}")
async def execute_failover_step(event_id: str, step_number: int):
    result = service.execute_failover_step(event_id, step_number)
    if not result:
        raise HTTPException(status_code=404, detail="Failover event or step not found")
    return result


@router.post("/failovers/{event_id}/complete")
async def complete_failover(event_id: str):
    event = service.complete_failover(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Failover event not found")
    return _failover_to_dict(event)


@router.post("/failovers/{event_id}/rollback")
async def rollback_failover(event_id: str, data: FailoverRollback):
    event = service.rollback_failover(event_id, reason=data.reason)
    if not event:
        raise HTTPException(status_code=404, detail="Failover event not found")
    return _failover_to_dict(event)


# ========== Readiness & Compliance Routes ==========

@router.get("/readiness/{client_id}")
async def assess_readiness(client_id: str):
    readiness = service.assess_readiness(client_id)
    return _readiness_to_dict(readiness)


@router.get("/readiness/{client_id}/report")
async def readiness_report(client_id: str):
    return service.get_readiness_report(client_id)


@router.get("/compliance/{client_id}")
async def rto_rpo_compliance(client_id: str):
    return service.get_rto_rpo_compliance(client_id)


@router.get("/untested-plans")
async def untested_plans(days: int = Query(90)):
    plans = service.get_untested_plans(days=days)
    return [_plan_to_dict(p) for p in plans]


@router.get("/drill-calendar")
async def drill_calendar(
    client_id: Optional[str] = Query(None),
    period_days: int = Query(90),
):
    return service.get_drill_calendar(client_id=client_id, period_days=period_days)


# ========== Dashboard ==========

@router.get("/dashboard")
async def dashboard():
    return service.get_dashboard()
