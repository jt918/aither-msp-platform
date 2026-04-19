"""
AITHER Platform - SOAR Playbook Engine
Logic Card: LC-014b

Security Orchestration, Automation, and Response playbook engine.
Extends Cyber-911 with configurable, reusable incident response playbooks.

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import asyncio
from enum import Enum
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    from sqlalchemy.orm import Session
    from models.soar import (
        SOARPlaybook as SOARPlaybookModel,
        SOARPlaybookStep as SOARPlaybookStepModel,
        SOARPlaybookExecution as SOARPlaybookExecutionModel,
        SOARStepResult as SOARStepResultModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None


# ============================================================
# Enums
# ============================================================

class ActionType(str, Enum):
    """SOAR action types for playbook steps"""
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    SEND_NOTIFICATION = "send_notification"
    CREATE_TICKET = "create_ticket"
    RUN_SCAN = "run_scan"
    COLLECT_FORENSICS = "collect_forensics"
    ENRICH_IOC = "enrich_ioc"
    LOOKUP_REPUTATION = "lookup_reputation"
    UPDATE_FIREWALL_RULE = "update_firewall_rule"
    RESTART_SERVICE = "restart_service"
    SNAPSHOT_VM = "snapshot_vm"
    ESCALATE = "escalate"
    CUSTOM_SCRIPT = "custom_script"
    WAIT = "wait"
    APPROVAL_GATE = "approval_gate"
    ADD_TO_WATCHLIST = "add_to_watchlist"
    REVOKE_SESSIONS = "revoke_sessions"
    FORCE_PASSWORD_RESET = "force_password_reset"


class ExecutionStatus(str, Enum):
    """Playbook execution statuses"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"
    AWAITING_APPROVAL = "awaiting_approval"


class TriggerType(str, Enum):
    """Playbook trigger types"""
    MANUAL = "manual"
    AUTOMATIC = "automatic"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class PlaybookStep:
    """Single step in a SOAR playbook"""
    step_id: str
    step_number: int
    name: str
    action_type: ActionType
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 300
    on_failure: str = "abort"  # continue / abort / skip_to
    condition: Optional[str] = None
    wait_for_approval: bool = False
    assigned_to: Optional[str] = None


@dataclass
class Playbook:
    """SOAR playbook definition"""
    playbook_id: str
    name: str
    description: str = ""
    trigger_type: TriggerType = TriggerType.MANUAL
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    steps: List[PlaybookStep] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    is_enabled: bool = True
    version: int = 1
    created_by: str = "system"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    execution_count: int = 0
    avg_execution_time_seconds: float = 0.0


@dataclass
class StepResult:
    """Result of executing a single playbook step"""
    step_id: str
    step_number: int
    action_type: str
    status: str = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class PlaybookExecution:
    """Record of a playbook execution"""
    execution_id: str
    playbook_id: str
    incident_id: str
    triggered_by: str = "manual"
    status: ExecutionStatus = ExecutionStatus.PENDING
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    current_step: int = 0
    step_results: List[StepResult] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# Helpers
# ============================================================

def _step_to_dict(step: PlaybookStep) -> Dict[str, Any]:
    return {
        "step_id": step.step_id,
        "step_number": step.step_number,
        "name": step.name,
        "action_type": step.action_type.value if isinstance(step.action_type, ActionType) else step.action_type,
        "parameters": step.parameters,
        "timeout_seconds": step.timeout_seconds,
        "on_failure": step.on_failure,
        "condition": step.condition,
        "wait_for_approval": step.wait_for_approval,
        "assigned_to": step.assigned_to,
    }


def _step_from_dict(d: Dict[str, Any]) -> PlaybookStep:
    at = d.get("action_type", "custom_script")
    try:
        at = ActionType(at)
    except ValueError:
        at = ActionType.CUSTOM_SCRIPT
    return PlaybookStep(
        step_id=d.get("step_id", str(uuid.uuid4())[:8]),
        step_number=d.get("step_number", 0),
        name=d.get("name", ""),
        action_type=at,
        parameters=d.get("parameters", {}),
        timeout_seconds=d.get("timeout_seconds", 300),
        on_failure=d.get("on_failure", "abort"),
        condition=d.get("condition"),
        wait_for_approval=d.get("wait_for_approval", False),
        assigned_to=d.get("assigned_to"),
    )


def _result_to_dict(r: StepResult) -> Dict[str, Any]:
    return {
        "step_id": r.step_id,
        "step_number": r.step_number,
        "action_type": r.action_type,
        "status": r.status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "output": r.output,
        "error": r.error,
    }


def _playbook_to_dict(pb: Playbook) -> Dict[str, Any]:
    return {
        "playbook_id": pb.playbook_id,
        "name": pb.name,
        "description": pb.description,
        "trigger_type": pb.trigger_type.value if isinstance(pb.trigger_type, TriggerType) else pb.trigger_type,
        "trigger_conditions": pb.trigger_conditions,
        "steps": [_step_to_dict(s) for s in pb.steps],
        "tags": pb.tags,
        "is_enabled": pb.is_enabled,
        "version": pb.version,
        "created_by": pb.created_by,
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
        "updated_at": pb.updated_at.isoformat() if pb.updated_at else None,
        "execution_count": pb.execution_count,
        "avg_execution_time_seconds": pb.avg_execution_time_seconds,
    }


def _execution_to_dict(ex: PlaybookExecution) -> Dict[str, Any]:
    return {
        "execution_id": ex.execution_id,
        "playbook_id": ex.playbook_id,
        "incident_id": ex.incident_id,
        "triggered_by": ex.triggered_by,
        "status": ex.status.value if isinstance(ex.status, ExecutionStatus) else ex.status,
        "started_at": ex.started_at.isoformat() if ex.started_at else None,
        "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
        "current_step": ex.current_step,
        "step_results": [_result_to_dict(r) for r in ex.step_results],
        "context": ex.context,
    }


# ============================================================
# Pre-built Playbooks
# ============================================================

def _build_prebuilt_playbooks() -> List[Playbook]:
    """Return the five pre-built SOAR playbooks."""
    playbooks: List[Playbook] = []

    # 1. Ransomware Response
    playbooks.append(Playbook(
        playbook_id="PB-RANSOM-001",
        name="Ransomware Response",
        description="Automated response to ransomware incidents: isolate, disable, forensics, ticket, notify, block, verify backups.",
        trigger_type=TriggerType.AUTOMATIC,
        trigger_conditions={"threat_type": "ransomware", "severity_min": 8},
        tags=["ransomware", "critical", "auto"],
        steps=[
            PlaybookStep(step_id="RS-01", step_number=1, name="Isolate affected host",
                         action_type=ActionType.ISOLATE_HOST, parameters={"source": "incident"}),
            PlaybookStep(step_id="RS-02", step_number=2, name="Disable compromised user account",
                         action_type=ActionType.DISABLE_ACCOUNT, parameters={"source": "incident"}),
            PlaybookStep(step_id="RS-03", step_number=3, name="Capture forensic snapshot",
                         action_type=ActionType.COLLECT_FORENSICS, parameters={"full_memory": True}),
            PlaybookStep(step_id="RS-04", step_number=4, name="Create P1 incident ticket",
                         action_type=ActionType.CREATE_TICKET, parameters={"priority": "P1", "category": "ransomware"}),
            PlaybookStep(step_id="RS-05", step_number=5, name="Notify security team",
                         action_type=ActionType.SEND_NOTIFICATION, parameters={"channel": "security", "urgency": "critical"}),
            PlaybookStep(step_id="RS-06", step_number=6, name="Block source IP at firewall",
                         action_type=ActionType.BLOCK_IP, parameters={"source": "incident"}),
            PlaybookStep(step_id="RS-07", step_number=7, name="Initiate backup verification",
                         action_type=ActionType.RUN_SCAN, parameters={"scan_type": "backup_integrity"}),
        ],
    ))

    # 2. Brute Force Response
    playbooks.append(Playbook(
        playbook_id="PB-BRUTE-001",
        name="Brute Force Response",
        description="Respond to brute force login attempts: reputation check, block, password reset, MFA, ticket.",
        trigger_type=TriggerType.AUTOMATIC,
        trigger_conditions={"threat_type": "credential_compromise", "severity_min": 5},
        tags=["brute-force", "authentication", "auto"],
        steps=[
            PlaybookStep(step_id="BF-01", step_number=1, name="Lookup source IP reputation",
                         action_type=ActionType.LOOKUP_REPUTATION, parameters={"target": "source_ip"}),
            PlaybookStep(step_id="BF-02", step_number=2, name="Block malicious IP",
                         action_type=ActionType.BLOCK_IP, parameters={"source": "incident"},
                         condition="reputation_score < 30"),
            PlaybookStep(step_id="BF-03", step_number=3, name="Force password reset for affected user",
                         action_type=ActionType.FORCE_PASSWORD_RESET, parameters={"source": "incident"}),
            PlaybookStep(step_id="BF-04", step_number=4, name="Enable MFA on account",
                         action_type=ActionType.CUSTOM_SCRIPT, parameters={"script": "enable_mfa", "source": "incident"}),
            PlaybookStep(step_id="BF-05", step_number=5, name="Create incident ticket",
                         action_type=ActionType.CREATE_TICKET, parameters={"priority": "P2", "category": "brute_force"}),
            PlaybookStep(step_id="BF-06", step_number=6, name="Send notification",
                         action_type=ActionType.SEND_NOTIFICATION, parameters={"channel": "security"}),
        ],
    ))

    # 3. Phishing Response
    playbooks.append(Playbook(
        playbook_id="PB-PHISH-001",
        name="Phishing Response",
        description="Respond to phishing attacks: quarantine, scan, credential check, password reset, filter update.",
        trigger_type=TriggerType.AUTOMATIC,
        trigger_conditions={"threat_type": "phishing", "severity_min": 5},
        tags=["phishing", "email", "auto"],
        steps=[
            PlaybookStep(step_id="PH-01", step_number=1, name="Quarantine phishing email",
                         action_type=ActionType.QUARANTINE_FILE, parameters={"type": "email", "source": "incident"}),
            PlaybookStep(step_id="PH-02", step_number=2, name="Scan recipient devices",
                         action_type=ActionType.RUN_SCAN, parameters={"scan_type": "endpoint", "source": "incident"}),
            PlaybookStep(step_id="PH-03", step_number=3, name="Check for credential compromise",
                         action_type=ActionType.ENRICH_IOC, parameters={"check_type": "credential_leak"}),
            PlaybookStep(step_id="PH-04", step_number=4, name="Force password reset",
                         action_type=ActionType.FORCE_PASSWORD_RESET, parameters={"source": "incident"}),
            PlaybookStep(step_id="PH-05", step_number=5, name="Update email filters",
                         action_type=ActionType.UPDATE_FIREWALL_RULE, parameters={"type": "email_filter", "source": "incident"}),
            PlaybookStep(step_id="PH-06", step_number=6, name="Create incident ticket",
                         action_type=ActionType.CREATE_TICKET, parameters={"priority": "P2", "category": "phishing"}),
        ],
    ))

    # 4. Data Exfiltration Response
    playbooks.append(Playbook(
        playbook_id="PB-EXFIL-001",
        name="Data Exfiltration Response",
        description="Respond to data exfiltration: isolate, revoke, forensics, block, ticket, escalate, preserve.",
        trigger_type=TriggerType.AUTOMATIC,
        trigger_conditions={"threat_type": "data_exfiltration", "severity_min": 8},
        tags=["exfiltration", "data-loss", "critical", "auto"],
        steps=[
            PlaybookStep(step_id="EX-01", step_number=1, name="Isolate compromised host",
                         action_type=ActionType.ISOLATE_HOST, parameters={"source": "incident"}),
            PlaybookStep(step_id="EX-02", step_number=2, name="Revoke all active sessions",
                         action_type=ActionType.REVOKE_SESSIONS, parameters={"source": "incident"}),
            PlaybookStep(step_id="EX-03", step_number=3, name="Capture forensic evidence",
                         action_type=ActionType.COLLECT_FORENSICS, parameters={"full_memory": True, "disk_image": True}),
            PlaybookStep(step_id="EX-04", step_number=4, name="Block destination IP",
                         action_type=ActionType.BLOCK_IP, parameters={"target": "destination_ip", "source": "incident"}),
            PlaybookStep(step_id="EX-05", step_number=5, name="Create P1 incident ticket",
                         action_type=ActionType.CREATE_TICKET, parameters={"priority": "P1", "category": "data_exfiltration"}),
            PlaybookStep(step_id="EX-06", step_number=6, name="Escalate to CISO",
                         action_type=ActionType.ESCALATE, parameters={"target": "CISO", "urgency": "critical"},
                         wait_for_approval=True),
            PlaybookStep(step_id="EX-07", step_number=7, name="Preserve evidence chain",
                         action_type=ActionType.SNAPSHOT_VM, parameters={"source": "incident"}),
        ],
    ))

    # 5. Malware Detection Response
    playbooks.append(Playbook(
        playbook_id="PB-MALWR-001",
        name="Malware Detection Response",
        description="Respond to malware detection: quarantine, scan, IOC check, signatures, ticket, notify.",
        trigger_type=TriggerType.AUTOMATIC,
        trigger_conditions={"threat_type": "malware", "severity_min": 5},
        tags=["malware", "endpoint", "auto"],
        steps=[
            PlaybookStep(step_id="MW-01", step_number=1, name="Quarantine malicious file",
                         action_type=ActionType.QUARANTINE_FILE, parameters={"source": "incident"}),
            PlaybookStep(step_id="MW-02", step_number=2, name="Run full endpoint scan",
                         action_type=ActionType.RUN_SCAN, parameters={"scan_type": "full", "source": "incident"}),
            PlaybookStep(step_id="MW-03", step_number=3, name="Check other endpoints for IOC",
                         action_type=ActionType.ENRICH_IOC, parameters={"scope": "all_endpoints"}),
            PlaybookStep(step_id="MW-04", step_number=4, name="Update AV signatures",
                         action_type=ActionType.UPDATE_FIREWALL_RULE, parameters={"type": "av_signature"}),
            PlaybookStep(step_id="MW-05", step_number=5, name="Create incident ticket",
                         action_type=ActionType.CREATE_TICKET, parameters={"priority": "P2", "category": "malware"}),
            PlaybookStep(step_id="MW-06", step_number=6, name="Notify administrator",
                         action_type=ActionType.SEND_NOTIFICATION, parameters={"channel": "admin"}),
        ],
    ))

    return playbooks


# ============================================================
# Service
# ============================================================

class SOARPlaybookService:
    """
    SOAR Playbook Engine

    TRIGGER: Security incident from Cyber-911 or manual invocation
    INPUT: Incident data, playbook definitions, step parameters
    PROCESS:
        1. Match incident to playbook via trigger conditions
        2. Execute playbook steps sequentially
        3. Route each step to the appropriate action handler
        4. Track execution state, handle failures and approvals
        5. Record analytics and update playbook stats
    OUTPUT: Execution records, step results, analytics
    STORAGE: soar_playbooks / soar_playbook_executions tables

    Accepts optional db: Session for persistence.
    """

    def __init__(self, db: Optional[Any] = None):
        self.db = db
        self._use_db = ORM_AVAILABLE and db is not None
        # In-memory stores
        self._playbooks: Dict[str, Playbook] = {}
        self._executions: Dict[str, PlaybookExecution] = {}
        # Load pre-built playbooks
        self._load_prebuilt()
        # Load from DB if available
        if self._use_db:
            self._load_from_db()
        logger.info("SOARPlaybookService initialized (db=%s)", self._use_db)

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _load_prebuilt(self):
        """Load pre-built playbooks into memory."""
        for pb in _build_prebuilt_playbooks():
            self._playbooks[pb.playbook_id] = pb

    def _load_from_db(self):
        """Load playbooks from database, merging with pre-built."""
        try:
            rows = self.db.query(SOARPlaybookModel).all()
            for row in rows:
                steps = [_step_from_dict(s) for s in (row.steps or [])]
                pb = Playbook(
                    playbook_id=row.playbook_id,
                    name=row.name,
                    description=row.description or "",
                    trigger_type=TriggerType(row.trigger_type) if row.trigger_type else TriggerType.MANUAL,
                    trigger_conditions=row.trigger_conditions or {},
                    steps=steps,
                    tags=row.tags or [],
                    is_enabled=row.is_enabled,
                    version=row.version or 1,
                    created_by=row.created_by or "system",
                    created_at=row.created_at or datetime.utcnow(),
                    updated_at=row.updated_at,
                    execution_count=row.execution_count or 0,
                    avg_execution_time_seconds=row.avg_execution_time_seconds or 0.0,
                )
                self._playbooks[pb.playbook_id] = pb
        except Exception as exc:
            logger.warning("SOAR: failed to load playbooks from DB: %s", exc)

    def _persist_playbook(self, pb: Playbook):
        """Persist a playbook to DB."""
        if not self._use_db:
            return
        try:
            existing = self.db.query(SOARPlaybookModel).filter_by(playbook_id=pb.playbook_id).first()
            data = {
                "name": pb.name,
                "description": pb.description,
                "trigger_type": pb.trigger_type.value if isinstance(pb.trigger_type, TriggerType) else pb.trigger_type,
                "trigger_conditions": pb.trigger_conditions,
                "steps": [_step_to_dict(s) for s in pb.steps],
                "tags": pb.tags,
                "is_enabled": pb.is_enabled,
                "version": pb.version,
                "created_by": pb.created_by,
                "execution_count": pb.execution_count,
                "avg_execution_time_seconds": pb.avg_execution_time_seconds,
            }
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
            else:
                row = SOARPlaybookModel(playbook_id=pb.playbook_id, **data)
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.warning("SOAR: persist playbook failed: %s", exc)
            try:
                self.db.rollback()
            except Exception:
                pass

    def _persist_execution(self, ex: PlaybookExecution):
        """Persist an execution to DB."""
        if not self._use_db:
            return
        try:
            existing = self.db.query(SOARPlaybookExecutionModel).filter_by(execution_id=ex.execution_id).first()
            data = {
                "playbook_id": ex.playbook_id,
                "incident_id": ex.incident_id,
                "triggered_by": ex.triggered_by,
                "status": ex.status.value if isinstance(ex.status, ExecutionStatus) else ex.status,
                "current_step": ex.current_step,
                "step_results": [_result_to_dict(r) for r in ex.step_results],
                "context": ex.context,
                "completed_at": ex.completed_at,
            }
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
            else:
                row = SOARPlaybookExecutionModel(execution_id=ex.execution_id, **data)
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.warning("SOAR: persist execution failed: %s", exc)
            try:
                self.db.rollback()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Playbook CRUD
    # ------------------------------------------------------------------

    def create_playbook(self, data: Dict[str, Any]) -> Playbook:
        """Create a new playbook from a dict specification."""
        pb_id = data.get("playbook_id", f"PB-{uuid.uuid4().hex[:8].upper()}")
        steps = []
        for i, s in enumerate(data.get("steps", [])):
            s.setdefault("step_id", f"S-{uuid.uuid4().hex[:6].upper()}")
            s.setdefault("step_number", i + 1)
            steps.append(_step_from_dict(s))

        tt = data.get("trigger_type", "manual")
        try:
            tt = TriggerType(tt)
        except ValueError:
            tt = TriggerType.MANUAL

        pb = Playbook(
            playbook_id=pb_id,
            name=data.get("name", "Unnamed Playbook"),
            description=data.get("description", ""),
            trigger_type=tt,
            trigger_conditions=data.get("trigger_conditions", {}),
            steps=steps,
            tags=data.get("tags", []),
            is_enabled=data.get("is_enabled", True),
            version=1,
            created_by=data.get("created_by", "user"),
        )
        self._playbooks[pb.playbook_id] = pb
        self._persist_playbook(pb)
        logger.info("SOAR: created playbook %s (%s)", pb.playbook_id, pb.name)
        return pb

    def update_playbook(self, playbook_id: str, data: Dict[str, Any]) -> Optional[Playbook]:
        """Update an existing playbook."""
        pb = self._playbooks.get(playbook_id)
        if not pb:
            return None

        if "name" in data:
            pb.name = data["name"]
        if "description" in data:
            pb.description = data["description"]
        if "trigger_type" in data:
            try:
                pb.trigger_type = TriggerType(data["trigger_type"])
            except ValueError:
                pass
        if "trigger_conditions" in data:
            pb.trigger_conditions = data["trigger_conditions"]
        if "steps" in data:
            steps = []
            for i, s in enumerate(data["steps"]):
                s.setdefault("step_id", f"S-{uuid.uuid4().hex[:6].upper()}")
                s.setdefault("step_number", i + 1)
                steps.append(_step_from_dict(s))
            pb.steps = steps
        if "tags" in data:
            pb.tags = data["tags"]
        if "is_enabled" in data:
            pb.is_enabled = data["is_enabled"]

        pb.version += 1
        pb.updated_at = datetime.utcnow()
        self._persist_playbook(pb)
        logger.info("SOAR: updated playbook %s v%d", playbook_id, pb.version)
        return pb

    def delete_playbook(self, playbook_id: str) -> bool:
        """Delete a playbook."""
        if playbook_id not in self._playbooks:
            return False
        del self._playbooks[playbook_id]
        if self._use_db:
            try:
                self.db.query(SOARPlaybookModel).filter_by(playbook_id=playbook_id).delete()
                self.db.commit()
            except Exception:
                try:
                    self.db.rollback()
                except Exception:
                    pass
        logger.info("SOAR: deleted playbook %s", playbook_id)
        return True

    def list_playbooks(self, enabled_only: bool = False, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all playbooks with optional filters."""
        results = []
        for pb in self._playbooks.values():
            if enabled_only and not pb.is_enabled:
                continue
            if tag and tag not in pb.tags:
                continue
            results.append(_playbook_to_dict(pb))
        return sorted(results, key=lambda x: x["name"])

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get a single playbook by ID."""
        pb = self._playbooks.get(playbook_id)
        return _playbook_to_dict(pb) if pb else None

    def clone_playbook(self, playbook_id: str, new_name: Optional[str] = None) -> Optional[Playbook]:
        """Clone an existing playbook with a new ID."""
        original = self._playbooks.get(playbook_id)
        if not original:
            return None
        data = _playbook_to_dict(original)
        data["playbook_id"] = f"PB-{uuid.uuid4().hex[:8].upper()}"
        data["name"] = new_name or f"{original.name} (Copy)"
        data["created_by"] = "user"
        data["execution_count"] = 0
        data["avg_execution_time_seconds"] = 0.0
        return self.create_playbook(data)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute_playbook(self, playbook_id: str, incident_id: str,
                               context: Optional[Dict[str, Any]] = None,
                               triggered_by: str = "manual") -> Optional[PlaybookExecution]:
        """Execute a playbook for a given incident."""
        pb = self._playbooks.get(playbook_id)
        if not pb or not pb.is_enabled:
            logger.warning("SOAR: playbook %s not found or disabled", playbook_id)
            return None

        exec_id = f"EX-{uuid.uuid4().hex[:8].upper()}"
        execution = PlaybookExecution(
            execution_id=exec_id,
            playbook_id=playbook_id,
            incident_id=incident_id,
            triggered_by=triggered_by,
            status=ExecutionStatus.RUNNING,
            context=context or {},
        )
        self._executions[exec_id] = execution
        self._persist_execution(execution)

        logger.info("SOAR: executing playbook %s for incident %s (exec=%s)",
                     playbook_id, incident_id, exec_id)

        start_time = datetime.utcnow()

        for step in pb.steps:
            execution.current_step = step.step_number

            # Evaluate condition
            if step.condition and not self._evaluate_condition(step.condition, execution.context):
                sr = StepResult(
                    step_id=step.step_id, step_number=step.step_number,
                    action_type=step.action_type.value, status="skipped",
                    started_at=datetime.utcnow(), completed_at=datetime.utcnow(),
                    output={"reason": "condition not met"},
                )
                execution.step_results.append(sr)
                continue

            # Approval gate
            if step.wait_for_approval:
                sr = StepResult(
                    step_id=step.step_id, step_number=step.step_number,
                    action_type=step.action_type.value, status="awaiting_approval",
                    started_at=datetime.utcnow(),
                )
                execution.step_results.append(sr)
                execution.status = ExecutionStatus.AWAITING_APPROVAL
                self._persist_execution(execution)
                logger.info("SOAR: execution %s awaiting approval at step %s",
                            exec_id, step.step_id)
                return execution

            # Execute step
            sr = await self._execute_step(step, execution.context)
            execution.step_results.append(sr)

            if sr.status == "failed":
                if step.on_failure == "abort":
                    execution.status = ExecutionStatus.FAILED
                    execution.completed_at = datetime.utcnow()
                    self._persist_execution(execution)
                    self._update_playbook_stats(pb, start_time)
                    return execution
                elif step.on_failure == "continue":
                    continue
                # skip_to not implemented yet, treat as continue
                continue

            # Merge step output into context
            if sr.output:
                execution.context.update(sr.output)

        execution.status = ExecutionStatus.COMPLETED
        execution.completed_at = datetime.utcnow()
        self._persist_execution(execution)
        self._update_playbook_stats(pb, start_time)
        logger.info("SOAR: execution %s completed", exec_id)
        return execution

    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution details."""
        ex = self._executions.get(execution_id)
        return _execution_to_dict(ex) if ex else None

    def list_executions(self, playbook_id: Optional[str] = None,
                        status: Optional[str] = None,
                        limit: int = 50) -> List[Dict[str, Any]]:
        """List executions with optional filters."""
        results = []
        for ex in self._executions.values():
            if playbook_id and ex.playbook_id != playbook_id:
                continue
            if status:
                ex_status = ex.status.value if isinstance(ex.status, ExecutionStatus) else ex.status
                if ex_status != status:
                    continue
            results.append(_execution_to_dict(ex))
        results.sort(key=lambda x: x["started_at"] or "", reverse=True)
        return results[:limit]

    async def abort_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Abort a running execution."""
        ex = self._executions.get(execution_id)
        if not ex:
            return None
        if ex.status not in (ExecutionStatus.RUNNING, ExecutionStatus.AWAITING_APPROVAL, ExecutionStatus.PENDING):
            return _execution_to_dict(ex)
        ex.status = ExecutionStatus.ABORTED
        ex.completed_at = datetime.utcnow()
        self._persist_execution(ex)
        logger.info("SOAR: execution %s aborted", execution_id)
        return _execution_to_dict(ex)

    async def approve_step(self, execution_id: str, step_id: str) -> Optional[Dict[str, Any]]:
        """Approve a pending approval gate and resume execution."""
        ex = self._executions.get(execution_id)
        if not ex or ex.status != ExecutionStatus.AWAITING_APPROVAL:
            return None

        # Find the awaiting step result and mark approved
        for sr in ex.step_results:
            if sr.step_id == step_id and sr.status == "awaiting_approval":
                sr.status = "completed"
                sr.completed_at = datetime.utcnow()
                sr.output = {"approved": True, "approved_at": datetime.utcnow().isoformat()}
                break
        else:
            return None

        # Resume execution from next step
        pb = self._playbooks.get(ex.playbook_id)
        if not pb:
            return _execution_to_dict(ex)

        ex.status = ExecutionStatus.RUNNING
        start_time = datetime.utcnow()

        # Find approved step number and continue from next
        approved_step_num = None
        for sr in ex.step_results:
            if sr.step_id == step_id:
                approved_step_num = sr.step_number
                break

        remaining_steps = [s for s in pb.steps if s.step_number > (approved_step_num or 0)]

        for step in remaining_steps:
            ex.current_step = step.step_number

            if step.condition and not self._evaluate_condition(step.condition, ex.context):
                sr = StepResult(
                    step_id=step.step_id, step_number=step.step_number,
                    action_type=step.action_type.value, status="skipped",
                    started_at=datetime.utcnow(), completed_at=datetime.utcnow(),
                    output={"reason": "condition not met"},
                )
                ex.step_results.append(sr)
                continue

            if step.wait_for_approval:
                sr = StepResult(
                    step_id=step.step_id, step_number=step.step_number,
                    action_type=step.action_type.value, status="awaiting_approval",
                    started_at=datetime.utcnow(),
                )
                ex.step_results.append(sr)
                ex.status = ExecutionStatus.AWAITING_APPROVAL
                self._persist_execution(ex)
                return _execution_to_dict(ex)

            sr = await self._execute_step(step, ex.context)
            ex.step_results.append(sr)

            if sr.status == "failed" and step.on_failure == "abort":
                ex.status = ExecutionStatus.FAILED
                ex.completed_at = datetime.utcnow()
                self._persist_execution(ex)
                return _execution_to_dict(ex)

            if sr.output:
                ex.context.update(sr.output)

        ex.status = ExecutionStatus.COMPLETED
        ex.completed_at = datetime.utcnow()
        self._persist_execution(ex)
        self._update_playbook_stats(pb, start_time)
        return _execution_to_dict(ex)

    # ------------------------------------------------------------------
    # Auto-trigger
    # ------------------------------------------------------------------

    async def evaluate_triggers(self, incident: Dict[str, Any]) -> List[PlaybookExecution]:
        """Evaluate all automatic playbooks to see if any should fire for the incident."""
        triggered: List[PlaybookExecution] = []
        threat_type = incident.get("threat_type", "").lower()
        severity = incident.get("severity", 0)
        source = incident.get("source", "")
        incident_id = incident.get("incident_id", f"INC-{uuid.uuid4().hex[:6].upper()}")

        for pb in self._playbooks.values():
            if not pb.is_enabled:
                continue
            if pb.trigger_type != TriggerType.AUTOMATIC:
                continue

            conds = pb.trigger_conditions
            if not conds:
                continue

            # Check threat type match
            if "threat_type" in conds:
                if conds["threat_type"].lower() != threat_type:
                    continue

            # Check severity minimum
            if "severity_min" in conds:
                if severity < conds["severity_min"]:
                    continue

            # Check source match
            if "source" in conds:
                if conds["source"].lower() != source.lower():
                    continue

            # All conditions matched - fire playbook
            execution = await self.execute_playbook(
                pb.playbook_id, incident_id,
                context=incident, triggered_by="auto",
            )
            if execution:
                triggered.append(execution)

        return triggered

    # ------------------------------------------------------------------
    # Step dispatch
    # ------------------------------------------------------------------

    async def _execute_step(self, step: PlaybookStep, context: Dict[str, Any]) -> StepResult:
        """Route step to appropriate action handler."""
        sr = StepResult(
            step_id=step.step_id,
            step_number=step.step_number,
            action_type=step.action_type.value,
            status="running",
            started_at=datetime.utcnow(),
        )

        handler_map = {
            ActionType.BLOCK_IP: self._action_block_ip,
            ActionType.ISOLATE_HOST: self._action_isolate_host,
            ActionType.DISABLE_ACCOUNT: self._action_disable_account,
            ActionType.QUARANTINE_FILE: self._action_quarantine_file,
            ActionType.SEND_NOTIFICATION: self._action_send_notification,
            ActionType.CREATE_TICKET: self._action_create_ticket,
            ActionType.RUN_SCAN: self._action_run_scan,
            ActionType.COLLECT_FORENSICS: self._action_collect_forensics,
            ActionType.ENRICH_IOC: self._action_enrich_ioc,
            ActionType.LOOKUP_REPUTATION: self._action_lookup_reputation,
            ActionType.UPDATE_FIREWALL_RULE: self._action_update_firewall_rule,
            ActionType.RESTART_SERVICE: self._action_restart_service,
            ActionType.SNAPSHOT_VM: self._action_snapshot_vm,
            ActionType.ESCALATE: self._action_escalate,
            ActionType.CUSTOM_SCRIPT: self._action_custom_script,
            ActionType.WAIT: self._action_wait,
            ActionType.APPROVAL_GATE: self._action_approval_gate,
            ActionType.ADD_TO_WATCHLIST: self._action_add_to_watchlist,
            ActionType.REVOKE_SESSIONS: self._action_revoke_sessions,
            ActionType.FORCE_PASSWORD_RESET: self._action_force_password_reset,
        }

        handler = handler_map.get(step.action_type, self._action_custom_script)
        try:
            output = await handler(step.parameters, context)
            sr.status = "completed"
            sr.output = output or {}
        except Exception as exc:
            sr.status = "failed"
            sr.error = str(exc)
            logger.error("SOAR: step %s failed: %s", step.step_id, exc)

        sr.completed_at = datetime.utcnow()
        return sr

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate a simple condition against the execution context."""
        try:
            # Support simple conditions like "reputation_score < 30"
            parts = condition.split()
            if len(parts) == 3:
                key, op, value = parts
                ctx_val = context.get(key)
                if ctx_val is None:
                    return True  # If no data, execute anyway
                ctx_val = float(ctx_val) if isinstance(ctx_val, (int, float, str)) else 0
                threshold = float(value)
                if op == "<":
                    return ctx_val < threshold
                elif op == ">":
                    return ctx_val > threshold
                elif op == "==":
                    return ctx_val == threshold
                elif op == ">=":
                    return ctx_val >= threshold
                elif op == "<=":
                    return ctx_val <= threshold
                elif op == "!=":
                    return ctx_val != threshold
            return True  # Default: execute
        except Exception:
            return True

    def _update_playbook_stats(self, pb: Playbook, start_time: datetime):
        """Update execution count and average execution time."""
        elapsed = (datetime.utcnow() - start_time).total_seconds()
        total = pb.avg_execution_time_seconds * pb.execution_count
        pb.execution_count += 1
        pb.avg_execution_time_seconds = (total + elapsed) / pb.execution_count
        self._persist_playbook(pb)

    # ------------------------------------------------------------------
    # Action handlers (each wraps a simulated service call)
    # ------------------------------------------------------------------

    async def _action_block_ip(self, params: Dict, context: Dict) -> Dict:
        ip = params.get("ip") or context.get("source_ip", "unknown")
        logger.info("SOAR ACTION: Blocking IP %s", ip)
        return {"action": "block_ip", "ip": ip, "blocked": True}

    async def _action_isolate_host(self, params: Dict, context: Dict) -> Dict:
        host = params.get("hostname") or context.get("hostname", "unknown")
        logger.info("SOAR ACTION: Isolating host %s", host)
        return {"action": "isolate_host", "hostname": host, "isolated": True}

    async def _action_disable_account(self, params: Dict, context: Dict) -> Dict:
        user = params.get("username") or context.get("user", "unknown")
        logger.info("SOAR ACTION: Disabling account %s", user)
        return {"action": "disable_account", "username": user, "disabled": True}

    async def _action_quarantine_file(self, params: Dict, context: Dict) -> Dict:
        file_path = params.get("file_path") or context.get("file_path", "unknown")
        logger.info("SOAR ACTION: Quarantining file %s", file_path)
        return {"action": "quarantine_file", "file": file_path, "quarantined": True}

    async def _action_send_notification(self, params: Dict, context: Dict) -> Dict:
        channel = params.get("channel", "default")
        urgency = params.get("urgency", "normal")
        logger.info("SOAR ACTION: Sending notification to %s (urgency=%s)", channel, urgency)
        return {"action": "send_notification", "channel": channel, "sent": True}

    async def _action_create_ticket(self, params: Dict, context: Dict) -> Dict:
        priority = params.get("priority", "P3")
        category = params.get("category", "security")
        ticket_id = f"TKT-{uuid.uuid4().hex[:6].upper()}"
        logger.info("SOAR ACTION: Creating %s ticket %s (%s)", priority, ticket_id, category)
        return {"action": "create_ticket", "ticket_id": ticket_id, "priority": priority, "category": category}

    async def _action_run_scan(self, params: Dict, context: Dict) -> Dict:
        scan_type = params.get("scan_type", "quick")
        logger.info("SOAR ACTION: Running %s scan", scan_type)
        return {"action": "run_scan", "scan_type": scan_type, "completed": True, "findings": 0}

    async def _action_collect_forensics(self, params: Dict, context: Dict) -> Dict:
        full_memory = params.get("full_memory", False)
        logger.info("SOAR ACTION: Collecting forensics (memory=%s)", full_memory)
        return {"action": "collect_forensics", "collected": True, "full_memory": full_memory}

    async def _action_enrich_ioc(self, params: Dict, context: Dict) -> Dict:
        check_type = params.get("check_type", "general")
        logger.info("SOAR ACTION: Enriching IOC (%s)", check_type)
        return {"action": "enrich_ioc", "check_type": check_type, "enriched": True, "matches": 0}

    async def _action_lookup_reputation(self, params: Dict, context: Dict) -> Dict:
        target = params.get("target", "source_ip")
        ip = context.get(target, context.get("source_ip", "unknown"))
        logger.info("SOAR ACTION: Looking up reputation for %s", ip)
        return {"action": "lookup_reputation", "target": ip, "reputation_score": 25, "category": "suspicious"}

    async def _action_update_firewall_rule(self, params: Dict, context: Dict) -> Dict:
        rule_type = params.get("type", "block")
        logger.info("SOAR ACTION: Updating firewall rule (%s)", rule_type)
        return {"action": "update_firewall_rule", "type": rule_type, "updated": True}

    async def _action_restart_service(self, params: Dict, context: Dict) -> Dict:
        service = params.get("service_name", "unknown")
        logger.info("SOAR ACTION: Restarting service %s", service)
        return {"action": "restart_service", "service": service, "restarted": True}

    async def _action_snapshot_vm(self, params: Dict, context: Dict) -> Dict:
        vm = params.get("vm_name") or context.get("hostname", "unknown")
        snapshot_id = f"SNAP-{uuid.uuid4().hex[:6].upper()}"
        logger.info("SOAR ACTION: Snapshotting VM %s -> %s", vm, snapshot_id)
        return {"action": "snapshot_vm", "vm": vm, "snapshot_id": snapshot_id}

    async def _action_escalate(self, params: Dict, context: Dict) -> Dict:
        target = params.get("target", "manager")
        urgency = params.get("urgency", "high")
        logger.info("SOAR ACTION: Escalating to %s (urgency=%s)", target, urgency)
        return {"action": "escalate", "target": target, "urgency": urgency, "escalated": True}

    async def _action_custom_script(self, params: Dict, context: Dict) -> Dict:
        script = params.get("script", "noop")
        logger.info("SOAR ACTION: Running custom script '%s'", script)
        return {"action": "custom_script", "script": script, "executed": True}

    async def _action_wait(self, params: Dict, context: Dict) -> Dict:
        duration = params.get("duration_seconds", 0)
        logger.info("SOAR ACTION: Waiting %s seconds", duration)
        # In production, this would actually wait; for now, just log
        return {"action": "wait", "duration_seconds": duration, "waited": True}

    async def _action_approval_gate(self, params: Dict, context: Dict) -> Dict:
        logger.info("SOAR ACTION: Approval gate reached")
        return {"action": "approval_gate", "status": "approved"}

    async def _action_add_to_watchlist(self, params: Dict, context: Dict) -> Dict:
        entity = params.get("entity") or context.get("source_ip", "unknown")
        logger.info("SOAR ACTION: Adding %s to watchlist", entity)
        return {"action": "add_to_watchlist", "entity": entity, "added": True}

    async def _action_revoke_sessions(self, params: Dict, context: Dict) -> Dict:
        user = params.get("username") or context.get("user", "unknown")
        logger.info("SOAR ACTION: Revoking sessions for %s", user)
        return {"action": "revoke_sessions", "username": user, "revoked": True}

    async def _action_force_password_reset(self, params: Dict, context: Dict) -> Dict:
        user = params.get("username") or context.get("user", "unknown")
        logger.info("SOAR ACTION: Forcing password reset for %s", user)
        return {"action": "force_password_reset", "username": user, "reset": True}

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_playbook_stats(self) -> Dict[str, Any]:
        """Return aggregate stats across all playbooks."""
        total = len(self._playbooks)
        enabled = sum(1 for p in self._playbooks.values() if p.is_enabled)
        total_executions = sum(p.execution_count for p in self._playbooks.values())
        return {
            "total_playbooks": total,
            "enabled_playbooks": enabled,
            "disabled_playbooks": total - enabled,
            "total_executions": total_executions,
        }

    def get_most_triggered(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Return the most frequently triggered playbooks."""
        pbs = sorted(self._playbooks.values(), key=lambda p: p.execution_count, reverse=True)
        return [
            {
                "playbook_id": p.playbook_id,
                "name": p.name,
                "execution_count": p.execution_count,
                "avg_execution_time_seconds": p.avg_execution_time_seconds,
            }
            for p in pbs[:limit]
        ]

    def get_average_resolution_time(self) -> float:
        """Return the average resolution time across all completed executions."""
        completed = [
            ex for ex in self._executions.values()
            if ex.status == ExecutionStatus.COMPLETED and ex.completed_at and ex.started_at
        ]
        if not completed:
            return 0.0
        total = sum((ex.completed_at - ex.started_at).total_seconds() for ex in completed)
        return total / len(completed)

    def get_dashboard(self) -> Dict[str, Any]:
        """Return dashboard data for the SOAR module."""
        active = [
            _execution_to_dict(ex) for ex in self._executions.values()
            if ex.status in (ExecutionStatus.RUNNING, ExecutionStatus.AWAITING_APPROVAL)
        ]
        recent = self.list_executions(limit=10)
        return {
            "active_executions": active,
            "active_count": len(active),
            "playbook_library_size": len(self._playbooks),
            "top_playbooks": self.get_most_triggered(5),
            "recent_executions": recent,
            "stats": self.get_playbook_stats(),
            "avg_resolution_time_seconds": self.get_average_resolution_time(),
        }
