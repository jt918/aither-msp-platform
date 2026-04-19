"""
AITHER Platform - Disaster Recovery Orchestration Service
Comprehensive DR runbook management, failover automation, RTO/RPO compliance,
and DR drill exercises for MSP operations.

Provides:
- DR plan CRUD with tiered classification
- Runbook step management (manual/automated/verification/notification/decision)
- DR drill scheduling, execution, and scoring
- Failover initiation, execution, and rollback
- RTO/RPO compliance tracking and reporting
- Readiness assessment and gap analysis
- Pre-built DR plan templates
- Dashboard: real-time DR health overview

G-46 pattern: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.dr_orchestration import (
        DRPlanModel,
        DRDrillModel,
        FailoverEventModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class DRTier(str, Enum):
    """DR plan tier classification"""
    TIER1_CRITICAL = "tier1_critical"
    TIER2_IMPORTANT = "tier2_important"
    TIER3_NORMAL = "tier3_normal"


class DrillType(str, Enum):
    """DR drill types"""
    TABLETOP = "tabletop"
    PARTIAL = "partial"
    FULL = "full"
    UNANNOUNCED = "unannounced"


class DrillStatus(str, Enum):
    """DR drill status"""
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FailoverStatus(str, Enum):
    """Failover event status"""
    INITIATED = "initiated"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class StepActionType(str, Enum):
    """DR step action types"""
    MANUAL = "manual"
    AUTOMATED = "automated"
    VERIFICATION = "verification"
    NOTIFICATION = "notification"
    DECISION_POINT = "decision_point"


class PlanStatus(str, Enum):
    """DR plan status"""
    DRAFT = "draft"
    ACTIVE = "active"
    TESTING = "testing"
    ACTIVATED = "activated"
    SUSPENDED = "suspended"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class DRStep:
    """Single step in a DR runbook"""
    step_number: int
    title: str
    description: str = ""
    responsible: str = ""
    action_type: str = StepActionType.MANUAL.value
    automation_script: str = ""
    estimated_duration_minutes: int = 15
    dependencies: List[int] = field(default_factory=list)
    rollback_instructions: str = ""


@dataclass
class DRPlan:
    """Disaster Recovery plan definition"""
    plan_id: str
    client_id: str = ""
    name: str = ""
    description: str = ""
    tier: str = DRTier.TIER3_NORMAL.value
    rto_minutes: int = 240
    rpo_minutes: int = 60
    systems_covered: List[str] = field(default_factory=list)
    runbook_steps: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    contacts: List[Dict[str, str]] = field(default_factory=list)
    last_tested_at: Optional[datetime] = None
    test_result: str = ""
    status: str = PlanStatus.DRAFT.value
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class DRDrill:
    """DR drill/exercise record"""
    drill_id: str
    plan_id: str
    drill_type: str = DrillType.TABLETOP.value
    status: str = DrillStatus.SCHEDULED.value
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    participants: List[str] = field(default_factory=list)
    steps_completed: int = 0
    steps_total: int = 0
    rto_achieved_minutes: Optional[float] = None
    rpo_achieved_minutes: Optional[float] = None
    rto_met: Optional[bool] = None
    rpo_met: Optional[bool] = None
    findings: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    score: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class FailoverEvent:
    """Failover event record"""
    event_id: str
    plan_id: str
    trigger: str = "manual"
    status: str = FailoverStatus.INITIATED.value
    systems_failed_over: List[str] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    rto_actual_minutes: Optional[float] = None
    data_loss_minutes: Optional[float] = None
    incident_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DRReadiness:
    """DR readiness assessment for a client"""
    client_id: str
    total_plans: int = 0
    plans_tested: int = 0
    plans_untested: int = 0
    avg_rto_target: float = 0.0
    avg_rpo_target: float = 0.0
    last_drill_date: Optional[datetime] = None
    overall_readiness_score: int = 0
    gaps: List[str] = field(default_factory=list)


# ============================================================
# Helpers
# ============================================================

def _step_to_dict(s: DRStep) -> dict:
    return {
        "step_number": s.step_number,
        "title": s.title,
        "description": s.description,
        "responsible": s.responsible,
        "action_type": s.action_type,
        "automation_script": s.automation_script,
        "estimated_duration_minutes": s.estimated_duration_minutes,
        "dependencies": s.dependencies,
        "rollback_instructions": s.rollback_instructions,
    }


def _plan_to_dict(p: DRPlan) -> dict:
    return {
        "plan_id": p.plan_id,
        "client_id": p.client_id,
        "name": p.name,
        "description": p.description,
        "tier": p.tier,
        "rto_minutes": p.rto_minutes,
        "rpo_minutes": p.rpo_minutes,
        "systems_covered": p.systems_covered,
        "runbook_steps": p.runbook_steps,
        "dependencies": p.dependencies,
        "contacts": p.contacts,
        "last_tested_at": p.last_tested_at.isoformat() if p.last_tested_at else None,
        "test_result": p.test_result,
        "status": p.status,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _drill_to_dict(d: DRDrill) -> dict:
    return {
        "drill_id": d.drill_id,
        "plan_id": d.plan_id,
        "drill_type": d.drill_type,
        "status": d.status,
        "scheduled_at": d.scheduled_at.isoformat() if d.scheduled_at else None,
        "started_at": d.started_at.isoformat() if d.started_at else None,
        "completed_at": d.completed_at.isoformat() if d.completed_at else None,
        "participants": d.participants,
        "steps_completed": d.steps_completed,
        "steps_total": d.steps_total,
        "rto_achieved_minutes": d.rto_achieved_minutes,
        "rpo_achieved_minutes": d.rpo_achieved_minutes,
        "rto_met": d.rto_met,
        "rpo_met": d.rpo_met,
        "findings": d.findings,
        "lessons_learned": d.lessons_learned,
        "score": d.score,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def _failover_to_dict(f: FailoverEvent) -> dict:
    return {
        "event_id": f.event_id,
        "plan_id": f.plan_id,
        "trigger": f.trigger,
        "status": f.status,
        "systems_failed_over": f.systems_failed_over,
        "started_at": f.started_at.isoformat() if f.started_at else None,
        "completed_at": f.completed_at.isoformat() if f.completed_at else None,
        "rto_actual_minutes": f.rto_actual_minutes,
        "data_loss_minutes": f.data_loss_minutes,
        "incident_id": f.incident_id,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def _readiness_to_dict(r: DRReadiness) -> dict:
    return {
        "client_id": r.client_id,
        "total_plans": r.total_plans,
        "plans_tested": r.plans_tested,
        "plans_untested": r.plans_untested,
        "avg_rto_target": r.avg_rto_target,
        "avg_rpo_target": r.avg_rpo_target,
        "last_drill_date": r.last_drill_date.isoformat() if r.last_drill_date else None,
        "overall_readiness_score": r.overall_readiness_score,
        "gaps": r.gaps,
    }


# ============================================================
# Standard Business Continuity Template
# ============================================================

STANDARD_BC_TEMPLATE_STEPS = [
    {
        "step_number": 1,
        "title": "Assess Situation",
        "description": "Evaluate the scope and severity of the incident. Identify affected systems, estimated impact, and initial root cause.",
        "responsible": "Incident Commander",
        "action_type": StepActionType.DECISION_POINT.value,
        "automation_script": "",
        "estimated_duration_minutes": 15,
        "dependencies": [],
        "rollback_instructions": "",
    },
    {
        "step_number": 2,
        "title": "Activate DR Team",
        "description": "Notify and assemble the disaster recovery team. Assign roles per DR plan.",
        "responsible": "DR Coordinator",
        "action_type": StepActionType.NOTIFICATION.value,
        "automation_script": "",
        "estimated_duration_minutes": 10,
        "dependencies": [1],
        "rollback_instructions": "Stand down DR team if false alarm confirmed.",
    },
    {
        "step_number": 3,
        "title": "Notify Stakeholders",
        "description": "Send initial notifications to management, affected clients, and vendors.",
        "responsible": "Communications Lead",
        "action_type": StepActionType.NOTIFICATION.value,
        "automation_script": "",
        "estimated_duration_minutes": 10,
        "dependencies": [1],
        "rollback_instructions": "Send all-clear notification.",
    },
    {
        "step_number": 4,
        "title": "Failover Primary Systems",
        "description": "Execute failover for Tier 1 critical systems to secondary infrastructure.",
        "responsible": "Infrastructure Lead",
        "action_type": StepActionType.AUTOMATED.value,
        "automation_script": "scripts/failover_primary.sh",
        "estimated_duration_minutes": 30,
        "dependencies": [1, 2],
        "rollback_instructions": "Execute failback script: scripts/failback_primary.sh",
    },
    {
        "step_number": 5,
        "title": "Verify Services",
        "description": "Run service health checks to confirm all failed-over services are operational.",
        "responsible": "QA / Operations",
        "action_type": StepActionType.VERIFICATION.value,
        "automation_script": "scripts/verify_services.sh",
        "estimated_duration_minutes": 20,
        "dependencies": [4],
        "rollback_instructions": "Re-attempt failover or escalate to manual intervention.",
    },
    {
        "step_number": 6,
        "title": "Redirect Traffic",
        "description": "Update DNS, load balancer, and routing rules to direct traffic to failover systems.",
        "responsible": "Network Engineer",
        "action_type": StepActionType.AUTOMATED.value,
        "automation_script": "scripts/redirect_traffic.sh",
        "estimated_duration_minutes": 15,
        "dependencies": [5],
        "rollback_instructions": "Revert DNS and routing to original configuration.",
    },
    {
        "step_number": 7,
        "title": "Monitor Failover Systems",
        "description": "Continuously monitor failed-over systems for stability, performance, and data integrity.",
        "responsible": "NOC Team",
        "action_type": StepActionType.MANUAL.value,
        "automation_script": "",
        "estimated_duration_minutes": 60,
        "dependencies": [6],
        "rollback_instructions": "",
    },
    {
        "step_number": 8,
        "title": "Communicate Status",
        "description": "Provide regular status updates to stakeholders on recovery progress.",
        "responsible": "Communications Lead",
        "action_type": StepActionType.NOTIFICATION.value,
        "automation_script": "",
        "estimated_duration_minutes": 10,
        "dependencies": [6],
        "rollback_instructions": "",
    },
    {
        "step_number": 9,
        "title": "Plan Recovery / Failback",
        "description": "Develop and schedule plan to restore original production systems and fail back.",
        "responsible": "DR Coordinator",
        "action_type": StepActionType.DECISION_POINT.value,
        "automation_script": "",
        "estimated_duration_minutes": 30,
        "dependencies": [7],
        "rollback_instructions": "",
    },
    {
        "step_number": 10,
        "title": "Post-Incident Review",
        "description": "Conduct post-incident review. Document findings, update DR plan, and identify improvements.",
        "responsible": "Incident Commander",
        "action_type": StepActionType.MANUAL.value,
        "automation_script": "",
        "estimated_duration_minutes": 60,
        "dependencies": [9],
        "rollback_instructions": "",
    },
]


# ============================================================
# DROrchestrationService
# ============================================================

class DROrchestrationService:
    """
    Disaster Recovery Orchestration Service.
    Manages DR plans, drills, failover events, and readiness assessments.
    G-46 pattern: DB persistence with in-memory fallback.
    """

    def __init__(self, db: "Session | None" = None):
        self.db = db
        self.use_db = db is not None and ORM_AVAILABLE
        # In-memory stores
        self._plans: Dict[str, DRPlan] = {}
        self._drills: Dict[str, DRDrill] = {}
        self._failovers: Dict[str, FailoverEvent] = {}
        logger.info("DROrchestrationService initialized (db=%s)", self.use_db)

    # ----------------------------------------------------------
    # Plan CRUD
    # ----------------------------------------------------------

    def create_plan(
        self,
        name: str,
        client_id: str = "",
        description: str = "",
        tier: str = DRTier.TIER3_NORMAL.value,
        rto_minutes: int = 240,
        rpo_minutes: int = 60,
        systems_covered: Optional[List[str]] = None,
        dependencies: Optional[List[str]] = None,
        contacts: Optional[List[Dict[str, str]]] = None,
        use_template: bool = False,
    ) -> DRPlan:
        """Create a new DR plan. Optionally pre-populate with standard BC template."""
        plan_id = f"DRP-{uuid.uuid4().hex[:8].upper()}"
        steps = list(STANDARD_BC_TEMPLATE_STEPS) if use_template else []
        plan = DRPlan(
            plan_id=plan_id,
            client_id=client_id,
            name=name,
            description=description,
            tier=tier,
            rto_minutes=rto_minutes,
            rpo_minutes=rpo_minutes,
            systems_covered=systems_covered or [],
            runbook_steps=steps,
            dependencies=dependencies or [],
            contacts=contacts or [],
        )
        if self.use_db:
            try:
                row = DRPlanModel(
                    plan_id=plan.plan_id,
                    client_id=plan.client_id,
                    name=plan.name,
                    description=plan.description,
                    tier=plan.tier,
                    rto_minutes=plan.rto_minutes,
                    rpo_minutes=plan.rpo_minutes,
                    systems_covered=plan.systems_covered,
                    runbook_steps=plan.runbook_steps,
                    dependencies=plan.dependencies,
                    contacts=plan.contacts,
                    status=plan.status,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB create_plan failed: %s", exc)
        self._plans[plan_id] = plan
        return plan

    def get_plan(self, plan_id: str) -> Optional[DRPlan]:
        """Get a DR plan by ID."""
        return self._plans.get(plan_id)

    def list_plans(self, client_id: Optional[str] = None, status: Optional[str] = None) -> List[DRPlan]:
        """List DR plans, optionally filtered by client_id and/or status."""
        plans = list(self._plans.values())
        if client_id:
            plans = [p for p in plans if p.client_id == client_id]
        if status:
            plans = [p for p in plans if p.status == status]
        return plans

    def update_plan(self, plan_id: str, **kwargs) -> Optional[DRPlan]:
        """Update DR plan fields."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None
        for k, v in kwargs.items():
            if v is not None and hasattr(plan, k):
                setattr(plan, k, v)
        plan.updated_at = datetime.now(timezone.utc)
        if self.use_db:
            try:
                row = self.db.query(DRPlanModel).filter_by(plan_id=plan_id).first()
                if row:
                    for k, v in kwargs.items():
                        if v is not None and hasattr(row, k):
                            setattr(row, k, v)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB update_plan failed: %s", exc)
        return plan

    def delete_plan(self, plan_id: str) -> bool:
        """Delete a DR plan."""
        if plan_id not in self._plans:
            return False
        del self._plans[plan_id]
        if self.use_db:
            try:
                self.db.query(DRPlanModel).filter_by(plan_id=plan_id).delete()
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB delete_plan failed: %s", exc)
        return True

    # ----------------------------------------------------------
    # Runbook Step Management
    # ----------------------------------------------------------

    def add_step(self, plan_id: str, step: Dict[str, Any]) -> Optional[DRPlan]:
        """Add a step to a DR plan's runbook."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None
        # Auto-assign step_number if not provided
        if "step_number" not in step:
            existing = [s.get("step_number", 0) for s in plan.runbook_steps]
            step["step_number"] = max(existing, default=0) + 1
        plan.runbook_steps.append(step)
        plan.updated_at = datetime.now(timezone.utc)
        if self.use_db:
            try:
                row = self.db.query(DRPlanModel).filter_by(plan_id=plan_id).first()
                if row:
                    row.runbook_steps = list(plan.runbook_steps)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB add_step failed: %s", exc)
        return plan

    def reorder_steps(self, plan_id: str, step_order: List[int]) -> Optional[DRPlan]:
        """Reorder steps in a DR plan. step_order is a list of step_numbers in desired order."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None
        step_map = {s.get("step_number"): s for s in plan.runbook_steps}
        reordered = []
        for i, num in enumerate(step_order, 1):
            if num in step_map:
                s = dict(step_map[num])
                s["step_number"] = i
                reordered.append(s)
        plan.runbook_steps = reordered
        plan.updated_at = datetime.now(timezone.utc)
        if self.use_db:
            try:
                row = self.db.query(DRPlanModel).filter_by(plan_id=plan_id).first()
                if row:
                    row.runbook_steps = list(plan.runbook_steps)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB reorder_steps failed: %s", exc)
        return plan

    # ----------------------------------------------------------
    # Drill Management
    # ----------------------------------------------------------

    def schedule_drill(
        self,
        plan_id: str,
        drill_type: str = DrillType.TABLETOP.value,
        scheduled_at: Optional[datetime] = None,
        participants: Optional[List[str]] = None,
    ) -> Optional[DRDrill]:
        """Schedule a new DR drill."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None
        drill_id = f"DRD-{uuid.uuid4().hex[:8].upper()}"
        drill = DRDrill(
            drill_id=drill_id,
            plan_id=plan_id,
            drill_type=drill_type,
            scheduled_at=scheduled_at or datetime.now(timezone.utc),
            participants=participants or [],
            steps_total=len(plan.runbook_steps),
        )
        if self.use_db:
            try:
                row = DRDrillModel(
                    drill_id=drill.drill_id,
                    plan_id=drill.plan_id,
                    drill_type=drill.drill_type,
                    status=drill.status,
                    scheduled_at=drill.scheduled_at,
                    participants=drill.participants,
                    steps_total=drill.steps_total,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB schedule_drill failed: %s", exc)
        self._drills[drill_id] = drill
        return drill

    def start_drill(self, drill_id: str) -> Optional[DRDrill]:
        """Start a scheduled drill."""
        drill = self._drills.get(drill_id)
        if not drill:
            return None
        drill.status = DrillStatus.IN_PROGRESS.value
        drill.started_at = datetime.now(timezone.utc)
        if self.use_db:
            try:
                row = self.db.query(DRDrillModel).filter_by(drill_id=drill_id).first()
                if row:
                    row.status = drill.status
                    row.started_at = drill.started_at
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB start_drill failed: %s", exc)
        return drill

    def complete_drill_step(self, drill_id: str, step_number: int, result: str = "pass") -> Optional[DRDrill]:
        """Mark a drill step as completed."""
        drill = self._drills.get(drill_id)
        if not drill:
            return None
        if drill.status != DrillStatus.IN_PROGRESS.value:
            return None
        drill.steps_completed = min(drill.steps_completed + 1, drill.steps_total)
        if result != "pass":
            drill.findings.append(f"Step {step_number}: {result}")
        return drill

    def complete_drill(
        self,
        drill_id: str,
        findings: Optional[List[str]] = None,
        lessons: Optional[List[str]] = None,
        rto_achieved_minutes: Optional[float] = None,
        rpo_achieved_minutes: Optional[float] = None,
    ) -> Optional[DRDrill]:
        """Complete a drill with results."""
        drill = self._drills.get(drill_id)
        if not drill:
            return None
        plan = self._plans.get(drill.plan_id)

        drill.status = DrillStatus.COMPLETED.value
        drill.completed_at = datetime.now(timezone.utc)
        if findings:
            drill.findings.extend(findings)
        if lessons:
            drill.lessons_learned.extend(lessons)
        drill.rto_achieved_minutes = rto_achieved_minutes
        drill.rpo_achieved_minutes = rpo_achieved_minutes

        # Evaluate RTO/RPO compliance
        if plan and rto_achieved_minutes is not None:
            drill.rto_met = rto_achieved_minutes <= plan.rto_minutes
        if plan and rpo_achieved_minutes is not None:
            drill.rpo_met = rpo_achieved_minutes <= plan.rpo_minutes

        # Calculate score (0-100)
        drill.score = self._calculate_drill_score(drill)

        # Update plan's last test info
        if plan:
            plan.last_tested_at = drill.completed_at
            plan.test_result = "pass" if drill.score >= 70 else "fail"
            plan.updated_at = datetime.now(timezone.utc)

        if self.use_db:
            try:
                row = self.db.query(DRDrillModel).filter_by(drill_id=drill_id).first()
                if row:
                    row.status = drill.status
                    row.completed_at = drill.completed_at
                    row.findings = drill.findings
                    row.lessons_learned = drill.lessons_learned
                    row.rto_achieved_minutes = drill.rto_achieved_minutes
                    row.rpo_achieved_minutes = drill.rpo_achieved_minutes
                    row.rto_met = drill.rto_met
                    row.rpo_met = drill.rpo_met
                    row.score = drill.score
                    row.steps_completed = drill.steps_completed
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB complete_drill failed: %s", exc)
        return drill

    def _calculate_drill_score(self, drill: DRDrill) -> int:
        """Calculate drill score 0-100 based on completion, RTO/RPO, and findings."""
        score = 0
        # Step completion (40 points)
        if drill.steps_total > 0:
            score += int(40 * drill.steps_completed / drill.steps_total)
        # RTO compliance (25 points)
        if drill.rto_met is True:
            score += 25
        elif drill.rto_met is False:
            score += 10  # partial credit
        else:
            score += 15  # not measured
        # RPO compliance (25 points)
        if drill.rpo_met is True:
            score += 25
        elif drill.rpo_met is False:
            score += 10
        else:
            score += 15
        # Findings penalty (up to -10)
        findings_penalty = min(len(drill.findings) * 2, 10)
        score -= findings_penalty
        # Lessons bonus (up to +10)
        lessons_bonus = min(len(drill.lessons_learned) * 2, 10)
        score += lessons_bonus
        return max(0, min(100, score))

    def get_drill(self, drill_id: str) -> Optional[DRDrill]:
        """Get a drill by ID."""
        return self._drills.get(drill_id)

    def list_drills(self, plan_id: Optional[str] = None, status: Optional[str] = None) -> List[DRDrill]:
        """List drills, optionally filtered."""
        drills = list(self._drills.values())
        if plan_id:
            drills = [d for d in drills if d.plan_id == plan_id]
        if status:
            drills = [d for d in drills if d.status == status]
        return drills

    # ----------------------------------------------------------
    # Failover Management
    # ----------------------------------------------------------

    def initiate_failover(
        self,
        plan_id: str,
        trigger: str = "manual",
        affected_systems: Optional[List[str]] = None,
        incident_id: str = "",
    ) -> Optional[FailoverEvent]:
        """Initiate a failover event."""
        plan = self._plans.get(plan_id)
        if not plan:
            return None
        event_id = f"FO-{uuid.uuid4().hex[:8].upper()}"
        event = FailoverEvent(
            event_id=event_id,
            plan_id=plan_id,
            trigger=trigger,
            status=FailoverStatus.IN_PROGRESS.value,
            systems_failed_over=affected_systems or list(plan.systems_covered),
            started_at=datetime.now(timezone.utc),
            incident_id=incident_id,
        )
        # Mark plan as activated
        plan.status = PlanStatus.ACTIVATED.value
        plan.updated_at = datetime.now(timezone.utc)

        if self.use_db:
            try:
                row = FailoverEventModel(
                    event_id=event.event_id,
                    plan_id=event.plan_id,
                    trigger=event.trigger,
                    status=event.status,
                    systems_failed_over=event.systems_failed_over,
                    started_at=event.started_at,
                    incident_id=event.incident_id,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB initiate_failover failed: %s", exc)
        self._failovers[event_id] = event
        return event

    def execute_failover_step(self, event_id: str, step_number: int) -> Optional[Dict[str, Any]]:
        """Execute a single failover step."""
        event = self._failovers.get(event_id)
        if not event or event.status != FailoverStatus.IN_PROGRESS.value:
            return None
        plan = self._plans.get(event.plan_id)
        if not plan:
            return None
        step = None
        for s in plan.runbook_steps:
            if s.get("step_number") == step_number:
                step = s
                break
        if not step:
            return None
        return {
            "event_id": event_id,
            "step_number": step_number,
            "title": step.get("title", ""),
            "action_type": step.get("action_type", "manual"),
            "status": "executed",
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }

    def complete_failover(self, event_id: str) -> Optional[FailoverEvent]:
        """Mark a failover event as completed."""
        event = self._failovers.get(event_id)
        if not event:
            return None
        event.status = FailoverStatus.COMPLETED.value
        event.completed_at = datetime.now(timezone.utc)
        # Calculate actual RTO
        if event.started_at:
            delta = event.completed_at - event.started_at
            event.rto_actual_minutes = round(delta.total_seconds() / 60, 2)
        if self.use_db:
            try:
                row = self.db.query(FailoverEventModel).filter_by(event_id=event_id).first()
                if row:
                    row.status = event.status
                    row.completed_at = event.completed_at
                    row.rto_actual_minutes = event.rto_actual_minutes
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB complete_failover failed: %s", exc)
        return event

    def rollback_failover(self, event_id: str, reason: str = "") -> Optional[FailoverEvent]:
        """Rollback a failover event."""
        event = self._failovers.get(event_id)
        if not event:
            return None
        event.status = FailoverStatus.ROLLED_BACK.value
        event.completed_at = datetime.now(timezone.utc)
        if event.started_at:
            delta = event.completed_at - event.started_at
            event.rto_actual_minutes = round(delta.total_seconds() / 60, 2)
        # Restore plan status
        plan = self._plans.get(event.plan_id)
        if plan:
            plan.status = PlanStatus.ACTIVE.value
            plan.updated_at = datetime.now(timezone.utc)
        if self.use_db:
            try:
                row = self.db.query(FailoverEventModel).filter_by(event_id=event_id).first()
                if row:
                    row.status = event.status
                    row.completed_at = event.completed_at
                    row.rto_actual_minutes = event.rto_actual_minutes
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB rollback_failover failed: %s", exc)
        return event

    def get_failover_events(self, plan_id: Optional[str] = None) -> List[FailoverEvent]:
        """List failover events, optionally filtered by plan."""
        events = list(self._failovers.values())
        if plan_id:
            events = [e for e in events if e.plan_id == plan_id]
        return events

    # ----------------------------------------------------------
    # Readiness & Compliance
    # ----------------------------------------------------------

    def assess_readiness(self, client_id: str) -> DRReadiness:
        """Assess DR readiness for a client."""
        plans = [p for p in self._plans.values() if p.client_id == client_id]
        total = len(plans)
        tested = [p for p in plans if p.last_tested_at is not None]
        untested = total - len(tested)
        gaps: List[str] = []

        avg_rto = sum(p.rto_minutes for p in plans) / total if total else 0.0
        avg_rpo = sum(p.rpo_minutes for p in plans) / total if total else 0.0

        # Find last drill date
        client_drills = [
            d for d in self._drills.values()
            if d.plan_id in {p.plan_id for p in plans} and d.completed_at
        ]
        last_drill_date = max((d.completed_at for d in client_drills), default=None)

        # Gap analysis
        if total == 0:
            gaps.append("No DR plans defined")
        if untested > 0:
            gaps.append(f"{untested} plan(s) never tested")
        for p in plans:
            if not p.contacts:
                gaps.append(f"Plan '{p.name}' has no emergency contacts")
            if not p.runbook_steps:
                gaps.append(f"Plan '{p.name}' has no runbook steps")
            if p.status == PlanStatus.DRAFT.value:
                gaps.append(f"Plan '{p.name}' is still in draft status")
        stale = [
            p for p in tested
            if p.last_tested_at and p.last_tested_at < datetime.now(timezone.utc) - timedelta(days=90)
        ]
        if stale:
            gaps.append(f"{len(stale)} plan(s) not tested in 90+ days")

        # Score calculation
        score = 0
        if total > 0:
            # Plans exist (20 points)
            score += 20
            # Tested ratio (30 points)
            score += int(30 * len(tested) / total)
            # Active status ratio (20 points)
            active = [p for p in plans if p.status == PlanStatus.ACTIVE.value]
            score += int(20 * len(active) / total)
            # No stale plans (15 points)
            if not stale:
                score += 15
            # Contacts defined (15 points)
            with_contacts = [p for p in plans if p.contacts]
            score += int(15 * len(with_contacts) / total)

        readiness = DRReadiness(
            client_id=client_id,
            total_plans=total,
            plans_tested=len(tested),
            plans_untested=untested,
            avg_rto_target=round(avg_rto, 1),
            avg_rpo_target=round(avg_rpo, 1),
            last_drill_date=last_drill_date,
            overall_readiness_score=min(100, max(0, score)),
            gaps=gaps,
        )
        return readiness

    def get_readiness_report(self, client_id: str) -> Dict[str, Any]:
        """Get a comprehensive readiness report for a client."""
        readiness = self.assess_readiness(client_id)
        plans = [_plan_to_dict(p) for p in self.list_plans(client_id=client_id)]
        recent_drills = [
            _drill_to_dict(d) for d in self._drills.values()
            if d.plan_id in {p["plan_id"] for p in plans}
        ]
        recent_failovers = [
            _failover_to_dict(f) for f in self._failovers.values()
            if f.plan_id in {p["plan_id"] for p in plans}
        ]
        return {
            "readiness": _readiness_to_dict(readiness),
            "plans": plans,
            "recent_drills": sorted(recent_drills, key=lambda x: x.get("created_at", ""), reverse=True)[:10],
            "recent_failovers": sorted(recent_failovers, key=lambda x: x.get("created_at", ""), reverse=True)[:10],
        }

    def get_rto_rpo_compliance(self, client_id: str) -> Dict[str, Any]:
        """Get RTO/RPO compliance data: actual vs target for a client."""
        plans = [p for p in self._plans.values() if p.client_id == client_id]
        compliance_data = []
        for plan in plans:
            plan_drills = sorted(
                [d for d in self._drills.values() if d.plan_id == plan.plan_id and d.status == DrillStatus.COMPLETED.value],
                key=lambda x: x.completed_at or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            latest = plan_drills[0] if plan_drills else None
            plan_failovers = sorted(
                [f for f in self._failovers.values() if f.plan_id == plan.plan_id and f.status == FailoverStatus.COMPLETED.value],
                key=lambda x: x.completed_at or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )
            latest_fo = plan_failovers[0] if plan_failovers else None
            compliance_data.append({
                "plan_id": plan.plan_id,
                "plan_name": plan.name,
                "tier": plan.tier,
                "rto_target_minutes": plan.rto_minutes,
                "rpo_target_minutes": plan.rpo_minutes,
                "rto_last_drill_minutes": latest.rto_achieved_minutes if latest else None,
                "rpo_last_drill_minutes": latest.rpo_achieved_minutes if latest else None,
                "rto_last_drill_met": latest.rto_met if latest else None,
                "rpo_last_drill_met": latest.rpo_met if latest else None,
                "rto_last_failover_minutes": latest_fo.rto_actual_minutes if latest_fo else None,
                "last_tested_at": plan.last_tested_at.isoformat() if plan.last_tested_at else None,
            })
        return {
            "client_id": client_id,
            "plans_count": len(plans),
            "compliance": compliance_data,
        }

    def get_untested_plans(self, days: int = 90) -> List[DRPlan]:
        """Get plans not tested within N days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        result = []
        for p in self._plans.values():
            if p.last_tested_at is None or p.last_tested_at < cutoff:
                result.append(p)
        return result

    def get_drill_calendar(self, client_id: Optional[str] = None, period_days: int = 90) -> List[Dict[str, Any]]:
        """Get upcoming and recent drill schedule."""
        now = datetime.now(timezone.utc)
        cutoff_past = now - timedelta(days=period_days)
        cutoff_future = now + timedelta(days=period_days)

        plan_ids = None
        if client_id:
            plan_ids = {p.plan_id for p in self._plans.values() if p.client_id == client_id}

        calendar = []
        for d in self._drills.values():
            if plan_ids is not None and d.plan_id not in plan_ids:
                continue
            sched = d.scheduled_at or d.created_at
            if cutoff_past <= sched <= cutoff_future:
                plan = self._plans.get(d.plan_id)
                calendar.append({
                    "drill_id": d.drill_id,
                    "plan_id": d.plan_id,
                    "plan_name": plan.name if plan else "",
                    "drill_type": d.drill_type,
                    "status": d.status,
                    "scheduled_at": sched.isoformat() if sched else None,
                    "score": d.score,
                })
        return sorted(calendar, key=lambda x: x.get("scheduled_at", ""))

    def validate_plan(self, plan_id: str) -> Dict[str, Any]:
        """Validate a DR plan for completeness and gaps."""
        plan = self._plans.get(plan_id)
        if not plan:
            return {"valid": False, "errors": ["Plan not found"]}
        errors: List[str] = []
        warnings: List[str] = []

        # Required fields
        if not plan.name:
            errors.append("Plan name is required")
        if not plan.client_id:
            warnings.append("No client_id assigned")
        if not plan.systems_covered:
            errors.append("No systems covered defined")
        if not plan.runbook_steps:
            errors.append("No runbook steps defined")
        if not plan.contacts:
            errors.append("No emergency contacts defined")
        if plan.rto_minutes <= 0:
            errors.append("RTO must be > 0")
        if plan.rpo_minutes <= 0:
            errors.append("RPO must be > 0")

        # Step validation
        if plan.runbook_steps:
            step_numbers = [s.get("step_number") for s in plan.runbook_steps]
            if len(step_numbers) != len(set(step_numbers)):
                errors.append("Duplicate step numbers found")
            for step in plan.runbook_steps:
                if not step.get("title"):
                    errors.append(f"Step {step.get('step_number')}: missing title")
                if not step.get("responsible"):
                    warnings.append(f"Step {step.get('step_number')}: no responsible person assigned")
                if step.get("action_type") == StepActionType.AUTOMATED.value and not step.get("automation_script"):
                    warnings.append(f"Step {step.get('step_number')}: automated step has no script")

        # Testing staleness
        if plan.last_tested_at:
            age = (datetime.now(timezone.utc) - plan.last_tested_at).days
            if age > 180:
                warnings.append(f"Plan last tested {age} days ago (>180 days)")
            elif age > 90:
                warnings.append(f"Plan last tested {age} days ago (>90 days)")
        else:
            warnings.append("Plan has never been tested")

        valid = len(errors) == 0
        return {
            "valid": valid,
            "plan_id": plan_id,
            "plan_name": plan.name,
            "errors": errors,
            "warnings": warnings,
            "step_count": len(plan.runbook_steps),
            "contacts_count": len(plan.contacts),
            "systems_count": len(plan.systems_covered),
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Get DR orchestration dashboard overview."""
        plans = list(self._plans.values())
        drills = list(self._drills.values())
        failovers = list(self._failovers.values())

        active_plans = [p for p in plans if p.status == PlanStatus.ACTIVE.value]
        draft_plans = [p for p in plans if p.status == PlanStatus.DRAFT.value]
        activated_plans = [p for p in plans if p.status == PlanStatus.ACTIVATED.value]
        untested = [p for p in plans if p.last_tested_at is None]

        completed_drills = [d for d in drills if d.status == DrillStatus.COMPLETED.value]
        avg_score = (
            round(sum(d.score for d in completed_drills) / len(completed_drills), 1)
            if completed_drills else 0
        )

        active_failovers = [f for f in failovers if f.status == FailoverStatus.IN_PROGRESS.value]

        # Tier breakdown
        tier_counts = {}
        for t in DRTier:
            tier_counts[t.value] = len([p for p in plans if p.tier == t.value])

        return {
            "total_plans": len(plans),
            "active_plans": len(active_plans),
            "draft_plans": len(draft_plans),
            "activated_plans": len(activated_plans),
            "untested_plans": len(untested),
            "tier_breakdown": tier_counts,
            "total_drills": len(drills),
            "completed_drills": len(completed_drills),
            "average_drill_score": avg_score,
            "total_failovers": len(failovers),
            "active_failovers": len(active_failovers),
            "recent_drills": [
                _drill_to_dict(d) for d in sorted(
                    drills, key=lambda x: x.created_at, reverse=True
                )[:5]
            ],
            "recent_failovers": [
                _failover_to_dict(f) for f in sorted(
                    failovers, key=lambda x: x.created_at, reverse=True
                )[:5]
            ],
        }
