"""
AITHER Platform - MSP Client Onboarding Workflow Service
Automates the process of bringing new MSP clients onto the platform --
from initial discovery through full deployment and go-live.

Provides:
- Onboarding template management (reusable phase/task blueprints)
- Workflow lifecycle (initiate → in_progress → completed/stalled/cancelled)
- Phase-gated progression with dependency tracking
- Automated task execution (billing setup, agent deployment, discovery scans)
- Pre-flight checklists per workflow
- Analytics: average onboarding time, bottleneck analysis, dashboard

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
    from models.msp_onboarding import (
        OnboardingTemplateModel,
        OnboardingWorkflowModel,
        OnboardingPhaseModel,
        OnboardingTaskModel,
        ClientChecklistModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class WorkflowStatus(str, Enum):
    """Onboarding workflow status"""
    INITIATED = "initiated"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    STALLED = "stalled"
    CANCELLED = "cancelled"


class PhaseStatus(str, Enum):
    """Phase status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class TaskStatus(str, Enum):
    """Task status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class TaskType(str, Enum):
    """Task type"""
    MANUAL = "manual"
    AUTOMATED = "automated"
    APPROVAL = "approval"
    DOCUMENTATION = "documentation"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class OnboardingTask:
    """A single task within an onboarding phase."""
    task_id: str
    phase_id: str
    name: str
    description: str = ""
    task_type: str = TaskType.MANUAL
    status: str = TaskStatus.PENDING
    assigned_to: str = ""
    automated_action: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class OnboardingPhase:
    """A phase within an onboarding workflow."""
    phase_id: str
    workflow_id: str
    phase_number: int
    name: str
    description: str = ""
    status: str = PhaseStatus.PENDING
    tasks: List[OnboardingTask] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    dependencies: List[str] = field(default_factory=list)


@dataclass
class OnboardingWorkflow:
    """A client onboarding workflow instance."""
    workflow_id: str
    client_id: str
    company_name: str
    primary_contact: str = ""
    plan_id: str = ""
    status: str = WorkflowStatus.INITIATED
    current_phase: int = 1
    phases: List[OnboardingPhase] = field(default_factory=list)
    assigned_technician: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    target_completion: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    notes: str = ""


@dataclass
class OnboardingTemplate:
    """Reusable onboarding template with phase/task definitions."""
    template_id: str
    name: str
    description: str = ""
    plan_type: str = "standard"
    phases: List[Dict[str, Any]] = field(default_factory=list)
    estimated_duration_days: int = 14
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ChecklistItem:
    """Single item in a client pre-flight checklist."""
    item_id: str
    category: str
    description: str
    is_required: bool = True
    is_completed: bool = False
    completed_by: str = ""
    completed_at: Optional[datetime] = None
    notes: str = ""


@dataclass
class ClientChecklist:
    """Pre-flight checklist tied to an onboarding workflow."""
    checklist_id: str
    workflow_id: str
    items: List[ChecklistItem] = field(default_factory=list)


# ============================================================
# Standard MSP Onboarding Template
# ============================================================

STANDARD_MSP_TEMPLATE: Dict[str, Any] = {
    "name": "Standard MSP Onboarding",
    "description": "Full-service MSP client onboarding from discovery through go-live (14 days).",
    "plan_type": "standard",
    "estimated_duration_days": 14,
    "phases": [
        {
            "phase_number": 1,
            "name": "Discovery & Planning",
            "description": "Day 1-2: Gather client info and assess current environment.",
            "dependencies": [],
            "tasks": [
                {"name": "Gather client info", "description": "Company size, locations, existing tools", "task_type": "manual"},
                {"name": "Network assessment", "description": "Run discovery scan on client network", "task_type": "automated", "automated_action": {"action": "run_discovery"}},
                {"name": "Document current infrastructure", "description": "Catalog servers, workstations, network devices", "task_type": "documentation"},
                {"name": "Define SLA requirements", "description": "Agree on response times, uptime guarantees", "task_type": "approval"},
                {"name": "Select billing plan", "description": "Choose per-endpoint/per-user/flat pricing", "task_type": "manual"},
            ],
        },
        {
            "phase_number": 2,
            "name": "Account Setup",
            "description": "Day 2-3: Provision accounts, billing, and portal access.",
            "dependencies": [1],
            "tasks": [
                {"name": "Create billing account", "description": "Auto-create client in billing engine", "task_type": "automated", "automated_action": {"action": "create_billing_account"}},
                {"name": "Create portal user accounts", "description": "Auto-provision portal logins for client contacts", "task_type": "automated", "automated_action": {"action": "create_portal_users"}},
                {"name": "Configure white-label branding", "description": "Apply client branding if applicable", "task_type": "manual"},
                {"name": "Set up billing agreement", "description": "Finalize contract terms and payment method", "task_type": "approval"},
                {"name": "Configure compliance frameworks", "description": "Enable HIPAA/SOC2/NIST as required", "task_type": "manual"},
            ],
        },
        {
            "phase_number": 3,
            "name": "Agent Deployment",
            "description": "Day 3-5: Deploy monitoring agents and configure backup policies.",
            "dependencies": [2],
            "tasks": [
                {"name": "Deploy RMM agents", "description": "Push agents to all client endpoints", "task_type": "automated", "automated_action": {"action": "deploy_agents"}},
                {"name": "Install Shield on endpoints", "description": "Deploy Aither Shield security suite", "task_type": "automated", "automated_action": {"action": "deploy_agents"}},
                {"name": "Configure backup policies", "description": "Set up BDR schedules and retention", "task_type": "manual"},
                {"name": "Set up monitoring thresholds", "description": "CPU, memory, disk alerts", "task_type": "manual"},
                {"name": "Verify agent connectivity", "description": "Confirm all agents reporting", "task_type": "manual"},
            ],
        },
        {
            "phase_number": 4,
            "name": "Security Baseline",
            "description": "Day 5-7: Establish security posture and run initial assessments.",
            "dependencies": [3],
            "tasks": [
                {"name": "Run initial vulnerability scan", "description": "Full network vulnerability assessment", "task_type": "automated", "automated_action": {"action": "run_discovery"}},
                {"name": "Configure firewall rules", "description": "Set up perimeter and host-based rules", "task_type": "manual"},
                {"name": "Set up SIEM log collection", "description": "Configure log forwarding from all sources", "task_type": "manual"},
                {"name": "Create digital twin of network", "description": "Build network topology model", "task_type": "automated", "automated_action": {"action": "run_discovery"}},
                {"name": "Run initial red team simulation", "description": "Automated penetration test", "task_type": "automated", "automated_action": {"action": "run_discovery"}},
                {"name": "Configure SOAR playbooks", "description": "Set up automated incident response", "task_type": "manual"},
            ],
        },
        {
            "phase_number": 5,
            "name": "Service Activation",
            "description": "Day 7-10: Enable self-healing, notifications, and reporting.",
            "dependencies": [4],
            "tasks": [
                {"name": "Enable self-healing", "description": "Activate automated remediation policies", "task_type": "manual"},
                {"name": "Configure notification channels", "description": "Email, SMS, Slack/Teams alerts", "task_type": "manual"},
                {"name": "Set up scheduled reports", "description": "Weekly/monthly executive summaries", "task_type": "manual"},
                {"name": "Create knowledge base articles", "description": "Client-specific KB for common issues", "task_type": "documentation"},
                {"name": "Train client portal users", "description": "Walkthrough of portal features", "task_type": "manual"},
                {"name": "Perform SLA verification test", "description": "Validate SLA monitoring is active", "task_type": "approval"},
            ],
        },
        {
            "phase_number": 6,
            "name": "Handoff & Go-Live",
            "description": "Day 10-14: Final sign-off and transition to BAU support.",
            "dependencies": [5],
            "tasks": [
                {"name": "Executive briefing", "description": "Present security posture and service overview", "task_type": "manual"},
                {"name": "Sign-off documentation", "description": "Client acknowledges deployment is complete", "task_type": "approval"},
                {"name": "Activate billing", "description": "Start billing cycle", "task_type": "automated", "automated_action": {"action": "create_billing_account"}},
                {"name": "Transition to BAU support", "description": "Hand off to support team", "task_type": "manual"},
                {"name": "Schedule 30-day review", "description": "Book post-onboarding check-in", "task_type": "manual"},
            ],
        },
    ],
}

DEFAULT_CHECKLIST_ITEMS: List[Dict[str, Any]] = [
    {"category": "Network", "description": "IP address ranges documented", "is_required": True},
    {"category": "Network", "description": "Firewall access provided", "is_required": True},
    {"category": "Network", "description": "VPN credentials received", "is_required": False},
    {"category": "Credentials", "description": "Domain admin credentials secured", "is_required": True},
    {"category": "Credentials", "description": "Cloud admin access provided", "is_required": False},
    {"category": "Contacts", "description": "Primary technical contact confirmed", "is_required": True},
    {"category": "Contacts", "description": "Emergency escalation path defined", "is_required": True},
    {"category": "Billing", "description": "Billing contact confirmed", "is_required": True},
    {"category": "Billing", "description": "Payment method on file", "is_required": True},
    {"category": "Compliance", "description": "Compliance requirements identified", "is_required": False},
    {"category": "Documentation", "description": "Existing documentation received", "is_required": False},
    {"category": "Documentation", "description": "NDA/MSA signed", "is_required": True},
]


# ============================================================
# Service
# ============================================================

class OnboardingService:
    """
    MSP Client Onboarding Workflow Service.

    Manages the full lifecycle of bringing a new MSP client onto the
    Aither platform: template management, workflow creation, phase
    advancement, automated task execution, checklists, and analytics.
    """

    def __init__(self, db: "Session | None" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE
        # In-memory stores (fallback)
        self._templates: Dict[str, OnboardingTemplate] = {}
        self._workflows: Dict[str, OnboardingWorkflow] = {}
        self._checklists: Dict[str, ClientChecklist] = {}
        logger.info("OnboardingService initialized (db=%s)", "yes" if self._use_db else "no")
        # Seed the default template
        self._ensure_default_template()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _uid(self, prefix: str = "OB") -> str:
        return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"

    def _ensure_default_template(self):
        """Seed the standard MSP template if not present."""
        existing = self.list_templates()
        for t in existing:
            if t.plan_type == "standard":
                return
        self.create_template(
            name=STANDARD_MSP_TEMPLATE["name"],
            description=STANDARD_MSP_TEMPLATE["description"],
            plan_type=STANDARD_MSP_TEMPLATE["plan_type"],
            phases=STANDARD_MSP_TEMPLATE["phases"],
            estimated_duration_days=STANDARD_MSP_TEMPLATE["estimated_duration_days"],
        )

    # ------------------------------------------------------------------
    # Template CRUD
    # ------------------------------------------------------------------

    def create_template(
        self,
        name: str,
        description: str = "",
        plan_type: str = "standard",
        phases: Optional[List[Dict]] = None,
        estimated_duration_days: int = 14,
    ) -> OnboardingTemplate:
        """Create a reusable onboarding template."""
        tid = self._uid("TPL")
        tpl = OnboardingTemplate(
            template_id=tid,
            name=name,
            description=description,
            plan_type=plan_type,
            phases=phases or [],
            estimated_duration_days=estimated_duration_days,
        )
        if self._use_db:
            try:
                row = OnboardingTemplateModel(
                    id=str(uuid.uuid4()),
                    template_id=tid,
                    name=name,
                    description=description,
                    plan_type=plan_type,
                    phases=phases or [],
                    estimated_duration_days=estimated_duration_days,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Template %s persisted to DB", tid)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB persist failed for template %s: %s", tid, exc)
        self._templates[tid] = tpl
        return tpl

    def get_template(self, template_id: str) -> Optional[OnboardingTemplate]:
        """Retrieve a template by ID."""
        if self._use_db:
            try:
                row = self.db.query(OnboardingTemplateModel).filter_by(template_id=template_id).first()
                if row:
                    return OnboardingTemplate(
                        template_id=row.template_id,
                        name=row.name,
                        description=row.description or "",
                        plan_type=row.plan_type or "standard",
                        phases=row.phases or [],
                        estimated_duration_days=row.estimated_duration_days or 14,
                        created_at=row.created_at or self._now(),
                    )
            except Exception as exc:
                logger.warning("DB read failed for template %s: %s", template_id, exc)
        return self._templates.get(template_id)

    def list_templates(self) -> List[OnboardingTemplate]:
        """List all onboarding templates."""
        if self._use_db:
            try:
                rows = self.db.query(OnboardingTemplateModel).all()
                return [
                    OnboardingTemplate(
                        template_id=r.template_id,
                        name=r.name,
                        description=r.description or "",
                        plan_type=r.plan_type or "standard",
                        phases=r.phases or [],
                        estimated_duration_days=r.estimated_duration_days or 14,
                        created_at=r.created_at or self._now(),
                    )
                    for r in rows
                ]
            except Exception as exc:
                logger.warning("DB list templates failed: %s", exc)
        return list(self._templates.values())

    def update_template(self, template_id: str, **kwargs) -> Optional[OnboardingTemplate]:
        """Update template fields."""
        tpl = self.get_template(template_id)
        if not tpl:
            return None
        for k, v in kwargs.items():
            if hasattr(tpl, k) and v is not None:
                setattr(tpl, k, v)
        if self._use_db:
            try:
                row = self.db.query(OnboardingTemplateModel).filter_by(template_id=template_id).first()
                if row:
                    for k, v in kwargs.items():
                        if hasattr(row, k) and v is not None:
                            setattr(row, k, v)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update template %s failed: %s", template_id, exc)
        self._templates[template_id] = tpl
        return tpl

    # ------------------------------------------------------------------
    # Workflow management
    # ------------------------------------------------------------------

    def start_onboarding(
        self,
        client_id: str,
        company_name: str,
        template_id: Optional[str] = None,
        primary_contact: str = "",
        plan_id: str = "",
        assigned_technician: str = "",
        notes: str = "",
    ) -> OnboardingWorkflow:
        """
        Start a new client onboarding workflow from a template.
        If no template_id is given, uses the first standard template.
        """
        # Resolve template
        tpl = None
        if template_id:
            tpl = self.get_template(template_id)
        if not tpl:
            templates = self.list_templates()
            for t in templates:
                if t.plan_type == "standard":
                    tpl = t
                    break
        if not tpl:
            raise ValueError("No onboarding template available. Create one first.")

        wf_id = self._uid("WF")
        now = self._now()
        target = now + timedelta(days=tpl.estimated_duration_days)

        # Build phases and tasks from template
        phases: List[OnboardingPhase] = []
        for pdef in tpl.phases:
            ph_id = self._uid("PH")
            tasks: List[OnboardingTask] = []
            for tdef in pdef.get("tasks", []):
                t_id = self._uid("TK")
                tasks.append(OnboardingTask(
                    task_id=t_id,
                    phase_id=ph_id,
                    name=tdef.get("name", ""),
                    description=tdef.get("description", ""),
                    task_type=tdef.get("task_type", TaskType.MANUAL),
                    automated_action=tdef.get("automated_action"),
                ))
            ph_status = PhaseStatus.IN_PROGRESS if pdef.get("phase_number", 1) == 1 else PhaseStatus.PENDING
            phases.append(OnboardingPhase(
                phase_id=ph_id,
                workflow_id=wf_id,
                phase_number=pdef.get("phase_number", 1),
                name=pdef.get("name", ""),
                description=pdef.get("description", ""),
                status=ph_status,
                tasks=tasks,
                started_at=now if ph_status == PhaseStatus.IN_PROGRESS else None,
                dependencies=[str(d) for d in pdef.get("dependencies", [])],
            ))

        wf = OnboardingWorkflow(
            workflow_id=wf_id,
            client_id=client_id,
            company_name=company_name,
            primary_contact=primary_contact,
            plan_id=plan_id,
            status=WorkflowStatus.IN_PROGRESS,
            current_phase=1,
            phases=phases,
            assigned_technician=assigned_technician,
            started_at=now,
            target_completion=target,
            notes=notes,
        )

        # Persist
        if self._use_db:
            try:
                self._persist_workflow(wf)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB persist workflow %s failed: %s", wf_id, exc)

        self._workflows[wf_id] = wf

        # Create default checklist
        self._create_default_checklist(wf_id)

        logger.info("Onboarding workflow %s started for client %s (%s)", wf_id, client_id, company_name)
        return wf

    def _persist_workflow(self, wf: OnboardingWorkflow):
        """Write workflow + phases + tasks to DB."""
        wf_row = OnboardingWorkflowModel(
            id=str(uuid.uuid4()),
            workflow_id=wf.workflow_id,
            client_id=wf.client_id,
            company_name=wf.company_name,
            primary_contact=wf.primary_contact,
            plan_id=wf.plan_id,
            status=wf.status,
            current_phase=wf.current_phase,
            assigned_technician=wf.assigned_technician,
            started_at=wf.started_at,
            target_completion=wf.target_completion,
            notes=wf.notes,
        )
        self.db.add(wf_row)

        for ph in wf.phases:
            ph_row = OnboardingPhaseModel(
                id=str(uuid.uuid4()),
                phase_id=ph.phase_id,
                workflow_id=wf.workflow_id,
                phase_number=ph.phase_number,
                name=ph.name,
                description=ph.description,
                status=ph.status,
                started_at=ph.started_at,
                dependencies=ph.dependencies,
            )
            self.db.add(ph_row)

            for tk in ph.tasks:
                tk_row = OnboardingTaskModel(
                    id=str(uuid.uuid4()),
                    task_id=tk.task_id,
                    phase_id=ph.phase_id,
                    name=tk.name,
                    description=tk.description,
                    task_type=tk.task_type,
                    status=tk.status,
                    assigned_to=tk.assigned_to,
                    automated_action=tk.automated_action,
                )
                self.db.add(tk_row)

        self.db.commit()

    def get_workflow(self, workflow_id: str) -> Optional[OnboardingWorkflow]:
        """Retrieve a workflow by ID."""
        return self._workflows.get(workflow_id)

    def list_workflows(self, status: Optional[str] = None, client_id: Optional[str] = None) -> List[OnboardingWorkflow]:
        """List workflows with optional filters."""
        results = list(self._workflows.values())
        if status:
            results = [w for w in results if w.status == status]
        if client_id:
            results = [w for w in results if w.client_id == client_id]
        return results

    # ------------------------------------------------------------------
    # Phase / Task operations
    # ------------------------------------------------------------------

    def advance_phase(self, workflow_id: str) -> OnboardingWorkflow:
        """Advance workflow to the next phase."""
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")

        if wf.status in (WorkflowStatus.COMPLETED, WorkflowStatus.CANCELLED):
            raise ValueError(f"Workflow {workflow_id} is {wf.status} and cannot be advanced")

        current = self._get_current_phase(wf)
        if current:
            # Mark current phase complete
            current.status = PhaseStatus.COMPLETED
            current.completed_at = self._now()

        # Find next phase
        next_phase_num = wf.current_phase + 1
        next_phase = None
        for ph in wf.phases:
            if ph.phase_number == next_phase_num:
                next_phase = ph
                break

        if next_phase:
            next_phase.status = PhaseStatus.IN_PROGRESS
            next_phase.started_at = self._now()
            wf.current_phase = next_phase_num
        else:
            # No more phases - workflow complete
            wf.status = WorkflowStatus.COMPLETED
            wf.completed_at = self._now()
            logger.info("Workflow %s completed", workflow_id)

        self._sync_workflow_db(wf)
        return wf

    def complete_task(self, workflow_id: str, task_id: str, result: Optional[Dict] = None) -> OnboardingTask:
        """Mark a task as completed."""
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")

        task = self._find_task(wf, task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found in workflow {workflow_id}")

        task.status = TaskStatus.COMPLETED
        task.completed_at = self._now()
        task.result = result
        if not task.started_at:
            task.started_at = task.completed_at

        self._sync_workflow_db(wf)
        return task

    def skip_task(self, workflow_id: str, task_id: str, reason: str = "") -> OnboardingTask:
        """Skip a task with optional reason."""
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")

        task = self._find_task(wf, task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        task.status = TaskStatus.SKIPPED
        task.completed_at = self._now()
        task.result = {"skipped_reason": reason}

        self._sync_workflow_db(wf)
        return task

    def block_phase(self, workflow_id: str, phase_id: str, reason: str = "") -> OnboardingPhase:
        """Mark a phase as blocked."""
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")

        phase = self._find_phase(wf, phase_id)
        if not phase:
            raise ValueError(f"Phase {phase_id} not found")

        phase.status = PhaseStatus.BLOCKED
        wf.status = WorkflowStatus.STALLED
        wf.notes = (wf.notes + f"\n[BLOCKED] Phase '{phase.name}': {reason}").strip()

        self._sync_workflow_db(wf)
        return phase

    def execute_automated_task(self, workflow_id: str, task_id: str) -> OnboardingTask:
        """Execute an automated task by dispatching to the appropriate handler."""
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")

        task = self._find_task(wf, task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        if task.task_type != TaskType.AUTOMATED:
            raise ValueError(f"Task {task_id} is not automated (type={task.task_type})")

        task.status = TaskStatus.IN_PROGRESS
        task.started_at = self._now()

        action = (task.automated_action or {}).get("action", "")
        client_data = {
            "client_id": wf.client_id,
            "company_name": wf.company_name,
            "plan_id": wf.plan_id,
            "primary_contact": wf.primary_contact,
        }

        result = {}
        try:
            if action == "create_billing_account":
                result = self._auto_create_billing_account(client_data)
            elif action == "create_portal_users":
                result = self._auto_create_portal_users(client_data)
            elif action == "deploy_agents":
                result = self._auto_deploy_agents(client_data)
            elif action == "run_discovery":
                result = self._auto_run_discovery(client_data)
            else:
                result = {"status": "skipped", "reason": f"Unknown action: {action}"}

            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = self._now()
        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.result = {"error": str(exc)}
            logger.error("Automated task %s failed: %s", task_id, exc)

        self._sync_workflow_db(wf)
        return task

    # ------------------------------------------------------------------
    # Automated action stubs
    # ------------------------------------------------------------------

    def _auto_create_billing_account(self, client_data: Dict) -> Dict:
        """Create a billing account via BillingEngine (stub integration)."""
        logger.info("AUTO: Creating billing account for %s", client_data.get("company_name"))
        return {
            "status": "created",
            "account_id": f"BA-{uuid.uuid4().hex[:8].upper()}",
            "client_id": client_data.get("client_id"),
            "plan_id": client_data.get("plan_id"),
            "message": "Billing account created successfully",
        }

    def _auto_create_portal_users(self, client_data: Dict) -> Dict:
        """Provision portal user accounts (stub integration)."""
        logger.info("AUTO: Creating portal users for %s", client_data.get("company_name"))
        return {
            "status": "created",
            "users_created": 1,
            "primary_user": client_data.get("primary_contact"),
            "message": "Portal user accounts provisioned",
        }

    def _auto_deploy_agents(self, client_data: Dict) -> Dict:
        """Queue RMM agent deployment commands (stub integration)."""
        logger.info("AUTO: Queueing agent deployment for %s", client_data.get("company_name"))
        return {
            "status": "queued",
            "deployment_id": f"DEP-{uuid.uuid4().hex[:8].upper()}",
            "message": "Agent deployment commands queued",
        }

    def _auto_run_discovery(self, client_data: Dict) -> Dict:
        """Trigger network discovery scan (stub integration)."""
        logger.info("AUTO: Running network discovery for %s", client_data.get("company_name"))
        return {
            "status": "initiated",
            "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}",
            "message": "Network discovery scan initiated",
        }

    # ------------------------------------------------------------------
    # Progress & Checklist
    # ------------------------------------------------------------------

    def get_onboarding_progress(self, workflow_id: str) -> Dict[str, Any]:
        """Get onboarding progress: percentage, current phase, blockers."""
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")

        total_tasks = 0
        completed_tasks = 0
        blockers: List[str] = []

        for ph in wf.phases:
            for tk in ph.tasks:
                total_tasks += 1
                if tk.status in (TaskStatus.COMPLETED, TaskStatus.SKIPPED):
                    completed_tasks += 1
            if ph.status == PhaseStatus.BLOCKED:
                blockers.append(f"Phase {ph.phase_number}: {ph.name}")

        pct = round((completed_tasks / total_tasks * 100), 1) if total_tasks > 0 else 0.0
        current_ph = self._get_current_phase(wf)

        return {
            "workflow_id": workflow_id,
            "status": wf.status,
            "percentage_complete": pct,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "current_phase": {
                "number": current_ph.phase_number if current_ph else None,
                "name": current_ph.name if current_ph else None,
                "status": current_ph.status if current_ph else None,
            },
            "blockers": blockers,
            "started_at": wf.started_at.isoformat() if wf.started_at else None,
            "target_completion": wf.target_completion.isoformat() if wf.target_completion else None,
            "days_elapsed": (self._now() - wf.started_at).days if wf.started_at else 0,
        }

    def _create_default_checklist(self, workflow_id: str):
        """Create a default pre-flight checklist for a workflow."""
        cl_id = self._uid("CL")
        items = []
        for item_def in DEFAULT_CHECKLIST_ITEMS:
            items.append(ChecklistItem(
                item_id=self._uid("CI"),
                category=item_def["category"],
                description=item_def["description"],
                is_required=item_def.get("is_required", True),
            ))
        cl = ClientChecklist(checklist_id=cl_id, workflow_id=workflow_id, items=items)
        self._checklists[workflow_id] = cl

        if self._use_db:
            try:
                row = ClientChecklistModel(
                    id=str(uuid.uuid4()),
                    checklist_id=cl_id,
                    workflow_id=workflow_id,
                    items=[
                        {
                            "item_id": i.item_id,
                            "category": i.category,
                            "description": i.description,
                            "is_required": i.is_required,
                            "is_completed": False,
                            "completed_by": "",
                            "completed_at": None,
                            "notes": "",
                        }
                        for i in items
                    ],
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB persist checklist failed: %s", exc)

        return cl

    def get_client_checklist(self, workflow_id: str) -> Optional[ClientChecklist]:
        """Get the pre-flight checklist for a workflow."""
        return self._checklists.get(workflow_id)

    def update_checklist_item(self, workflow_id: str, item_id: str, completed: bool, completed_by: str = "", notes: str = "") -> Optional[ChecklistItem]:
        """Update a single checklist item."""
        cl = self.get_client_checklist(workflow_id)
        if not cl:
            return None

        for item in cl.items:
            if item.item_id == item_id:
                item.is_completed = completed
                item.completed_by = completed_by
                item.completed_at = self._now() if completed else None
                item.notes = notes
                return item
        return None

    # ------------------------------------------------------------------
    # Workflow lifecycle
    # ------------------------------------------------------------------

    def stall_workflow(self, workflow_id: str, reason: str = "") -> OnboardingWorkflow:
        """Mark a workflow as stalled."""
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")
        wf.status = WorkflowStatus.STALLED
        wf.notes = (wf.notes + f"\n[STALLED] {reason}").strip()
        self._sync_workflow_db(wf)
        return wf

    def cancel_workflow(self, workflow_id: str, reason: str = "") -> OnboardingWorkflow:
        """Cancel an onboarding workflow."""
        wf = self.get_workflow(workflow_id)
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")
        wf.status = WorkflowStatus.CANCELLED
        wf.completed_at = self._now()
        wf.notes = (wf.notes + f"\n[CANCELLED] {reason}").strip()
        self._sync_workflow_db(wf)
        logger.info("Workflow %s cancelled: %s", workflow_id, reason)
        return wf

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_average_onboarding_time(self) -> Dict[str, Any]:
        """Calculate average onboarding duration for completed workflows."""
        completed = [w for w in self._workflows.values() if w.status == WorkflowStatus.COMPLETED and w.completed_at and w.started_at]
        if not completed:
            return {"average_days": 0, "completed_count": 0, "min_days": 0, "max_days": 0}

        durations = [(w.completed_at - w.started_at).total_seconds() / 86400 for w in completed]
        return {
            "average_days": round(sum(durations) / len(durations), 1),
            "completed_count": len(completed),
            "min_days": round(min(durations), 1),
            "max_days": round(max(durations), 1),
        }

    def get_bottleneck_analysis(self) -> Dict[str, Any]:
        """Analyse which phases/tasks take longest across all workflows."""
        phase_durations: Dict[str, List[float]] = {}
        task_durations: Dict[str, List[float]] = {}
        blocked_phases: Dict[str, int] = {}
        failed_tasks: Dict[str, int] = {}

        for wf in self._workflows.values():
            for ph in wf.phases:
                if ph.started_at and ph.completed_at:
                    dur = (ph.completed_at - ph.started_at).total_seconds() / 3600
                    phase_durations.setdefault(ph.name, []).append(dur)
                if ph.status == PhaseStatus.BLOCKED:
                    blocked_phases[ph.name] = blocked_phases.get(ph.name, 0) + 1
                for tk in ph.tasks:
                    if tk.started_at and tk.completed_at:
                        dur = (tk.completed_at - tk.started_at).total_seconds() / 3600
                        task_durations.setdefault(tk.name, []).append(dur)
                    if tk.status == TaskStatus.FAILED:
                        failed_tasks[tk.name] = failed_tasks.get(tk.name, 0) + 1

        avg_phase = {
            name: round(sum(durs) / len(durs), 2) for name, durs in phase_durations.items()
        }
        avg_task = {
            name: round(sum(durs) / len(durs), 2) for name, durs in task_durations.items()
        }

        # Sort by duration desc
        slowest_phases = sorted(avg_phase.items(), key=lambda x: x[1], reverse=True)[:5]
        slowest_tasks = sorted(avg_task.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "slowest_phases_hours": dict(slowest_phases),
            "slowest_tasks_hours": dict(slowest_tasks),
            "most_blocked_phases": blocked_phases,
            "most_failed_tasks": failed_tasks,
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Overview dashboard: active onboardings, completion rate, avg duration, stalled."""
        all_wfs = list(self._workflows.values())
        total = len(all_wfs)
        active = len([w for w in all_wfs if w.status == WorkflowStatus.IN_PROGRESS])
        completed = len([w for w in all_wfs if w.status == WorkflowStatus.COMPLETED])
        stalled = len([w for w in all_wfs if w.status == WorkflowStatus.STALLED])
        cancelled = len([w for w in all_wfs if w.status == WorkflowStatus.CANCELLED])
        initiated = len([w for w in all_wfs if w.status == WorkflowStatus.INITIATED])

        avg = self.get_average_onboarding_time()

        return {
            "total_workflows": total,
            "active": active,
            "completed": completed,
            "stalled": stalled,
            "cancelled": cancelled,
            "initiated": initiated,
            "completion_rate": round(completed / total * 100, 1) if total > 0 else 0.0,
            "average_duration_days": avg.get("average_days", 0),
            "active_workflows": [
                {
                    "workflow_id": w.workflow_id,
                    "company_name": w.company_name,
                    "current_phase": w.current_phase,
                    "status": w.status,
                    "started_at": w.started_at.isoformat() if w.started_at else None,
                }
                for w in all_wfs
                if w.status in (WorkflowStatus.IN_PROGRESS, WorkflowStatus.STALLED)
            ],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_current_phase(self, wf: OnboardingWorkflow) -> Optional[OnboardingPhase]:
        for ph in wf.phases:
            if ph.phase_number == wf.current_phase:
                return ph
        return None

    def _find_task(self, wf: OnboardingWorkflow, task_id: str) -> Optional[OnboardingTask]:
        for ph in wf.phases:
            for tk in ph.tasks:
                if tk.task_id == task_id:
                    return tk
        return None

    def _find_phase(self, wf: OnboardingWorkflow, phase_id: str) -> Optional[OnboardingPhase]:
        for ph in wf.phases:
            if ph.phase_id == phase_id:
                return ph
        return None

    def _sync_workflow_db(self, wf: OnboardingWorkflow):
        """Sync in-memory workflow state to DB."""
        if not self._use_db:
            return
        try:
            row = self.db.query(OnboardingWorkflowModel).filter_by(workflow_id=wf.workflow_id).first()
            if row:
                row.status = wf.status
                row.current_phase = wf.current_phase
                row.completed_at = wf.completed_at
                row.notes = wf.notes
                self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.warning("DB sync workflow %s failed: %s", wf.workflow_id, exc)
