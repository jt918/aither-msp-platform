"""
AITHER Platform - ITIL-Aligned Change Management Workflow Service
Manages IT change lifecycle: request -> risk assessment -> approval -> implementation -> PIR

Provides:
- Change request CRUD with full lifecycle workflow
- Risk scoring with configurable factors
- Multi-stage approval workflows
- Pre-built change templates (ITIL standard/normal/emergency)
- Post-Implementation Review (PIR)
- Change calendar with blackout windows
- Analytics and dashboard

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.change_management import (
        ChangeRequestModel,
        ApprovalRecordModel,
        ChangeTemplateModel,
        PIRModel,
        BlackoutWindowModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class ChangeType(str, Enum):
    STANDARD = "standard"
    NORMAL = "normal"
    EMERGENCY = "emergency"


class ChangeStatus(str, Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    IMPLEMENTING = "implementing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ChangeCategory(str, Enum):
    HARDWARE = "hardware"
    SOFTWARE = "software"
    NETWORK = "network"
    SECURITY = "security"
    DATABASE = "database"
    CLOUD = "cloud"
    OTHER = "other"


class ChangePriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    DEFERRED = "deferred"


class ImpactScope(str, Enum):
    SINGLE_DEVICE = "single_device"
    DEPARTMENT = "department"
    SITE = "site"
    ORGANIZATION = "organization"


class RollbackComplexity(str, Enum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"


class TestingCoverage(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class ChangeRequest:
    """ITIL change request."""
    change_id: str
    client_id: str
    title: str
    description: str
    change_type: ChangeType = ChangeType.NORMAL
    category: ChangeCategory = ChangeCategory.OTHER
    priority: ChangePriority = ChangePriority.MEDIUM
    status: ChangeStatus = ChangeStatus.DRAFT
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_score: int = 0
    impact_assessment: str = ""
    rollback_plan: str = ""
    implementation_plan: str = ""
    testing_plan: str = ""
    scheduled_start: Optional[datetime] = None
    scheduled_end: Optional[datetime] = None
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None
    requested_by: str = ""
    assigned_to: Optional[str] = None
    approved_by: Optional[str] = None
    approvers_required: List[str] = field(default_factory=list)
    approvals_received: List[str] = field(default_factory=list)
    affected_cis: List[str] = field(default_factory=list)
    related_tickets: List[str] = field(default_factory=list)
    pir_completed: bool = False
    pir_notes: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ApprovalRecord:
    """Record of an approval decision."""
    approval_id: str
    change_id: str
    approver: str
    decision: ApprovalDecision = ApprovalDecision.DEFERRED
    comments: str = ""
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ChangeTemplate:
    """Pre-built change template for common changes."""
    template_id: str
    name: str
    description: str
    change_type: ChangeType = ChangeType.STANDARD
    category: ChangeCategory = ChangeCategory.OTHER
    default_risk_level: RiskLevel = RiskLevel.LOW
    steps: List[str] = field(default_factory=list)
    approvers_required: List[str] = field(default_factory=list)
    estimated_duration_minutes: int = 30
    rollback_steps: List[str] = field(default_factory=list)


@dataclass
class PIR:
    """Post-Implementation Review."""
    pir_id: str
    change_id: str
    was_successful: bool = True
    objectives_met: bool = True
    issues_encountered: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    follow_up_actions: List[str] = field(default_factory=list)
    reviewed_by: str = ""
    reviewed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ChangeCalendar:
    """Calendar entry for a scheduled change."""
    entry_id: str
    change_id: str
    title: str
    scheduled_start: datetime
    scheduled_end: datetime
    status: ChangeStatus = ChangeStatus.SCHEDULED
    risk_level: RiskLevel = RiskLevel.LOW
    client_id: str = ""


@dataclass
class BlackoutWindow:
    """Maintenance blackout window -- no changes allowed."""
    window_id: str
    client_id: str
    name: str
    start_time: datetime
    end_time: datetime
    reason: str = ""
    is_recurring: bool = False
    recurrence_pattern: Optional[str] = None


# ============================================================
# Row-to-dataclass converters
# ============================================================

def _change_from_row(row) -> ChangeRequest:
    return ChangeRequest(
        change_id=row.change_id,
        client_id=row.client_id or "",
        title=row.title,
        description=row.description or "",
        change_type=ChangeType(row.change_type) if row.change_type else ChangeType.NORMAL,
        category=ChangeCategory(row.category) if row.category else ChangeCategory.OTHER,
        priority=ChangePriority(row.priority) if row.priority else ChangePriority.MEDIUM,
        status=ChangeStatus(row.status) if row.status else ChangeStatus.DRAFT,
        risk_level=RiskLevel(row.risk_level) if row.risk_level else RiskLevel.MEDIUM,
        risk_score=row.risk_score or 0,
        impact_assessment=row.impact_assessment or "",
        rollback_plan=row.rollback_plan or "",
        implementation_plan=row.implementation_plan or "",
        testing_plan=row.testing_plan or "",
        scheduled_start=row.scheduled_start,
        scheduled_end=row.scheduled_end,
        actual_start=row.actual_start,
        actual_end=row.actual_end,
        requested_by=row.requested_by or "",
        assigned_to=row.assigned_to,
        approved_by=row.approved_by,
        approvers_required=row.approvers_required or [],
        approvals_received=row.approvals_received or [],
        affected_cis=row.affected_cis or [],
        related_tickets=row.related_tickets or [],
        pir_completed=row.pir_completed or False,
        pir_notes=row.pir_notes,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at or datetime.now(timezone.utc),
    )


def _approval_from_row(row) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=row.approval_id,
        change_id=row.change_id,
        approver=row.approver or "",
        decision=ApprovalDecision(row.decision) if row.decision else ApprovalDecision.DEFERRED,
        comments=row.comments or "",
        decided_at=row.decided_at or datetime.now(timezone.utc),
    )


def _template_from_row(row) -> ChangeTemplate:
    return ChangeTemplate(
        template_id=row.template_id,
        name=row.name,
        description=row.description or "",
        change_type=ChangeType(row.change_type) if row.change_type else ChangeType.STANDARD,
        category=ChangeCategory(row.category) if row.category else ChangeCategory.OTHER,
        default_risk_level=RiskLevel(row.default_risk_level) if row.default_risk_level else RiskLevel.LOW,
        steps=row.steps or [],
        approvers_required=row.approvers_required or [],
        estimated_duration_minutes=row.estimated_duration_minutes or 30,
        rollback_steps=row.rollback_steps or [],
    )


def _pir_from_row(row) -> PIR:
    return PIR(
        pir_id=row.pir_id,
        change_id=row.change_id,
        was_successful=row.was_successful if row.was_successful is not None else True,
        objectives_met=row.objectives_met if row.objectives_met is not None else True,
        issues_encountered=row.issues_encountered or [],
        lessons_learned=row.lessons_learned or [],
        follow_up_actions=row.follow_up_actions or [],
        reviewed_by=row.reviewed_by or "",
        reviewed_at=row.reviewed_at or datetime.now(timezone.utc),
    )


def _blackout_from_row(row) -> BlackoutWindow:
    return BlackoutWindow(
        window_id=row.window_id,
        client_id=row.client_id or "",
        name=row.name or "",
        start_time=row.start_time,
        end_time=row.end_time,
        reason=row.reason or "",
        is_recurring=row.is_recurring or False,
        recurrence_pattern=row.recurrence_pattern,
    )


# ============================================================
# Pre-built Change Templates
# ============================================================

DEFAULT_TEMPLATES: List[Dict[str, Any]] = [
    {
        "template_id": "TPL-001",
        "name": "Server Patch Deployment",
        "description": "Standard operating-system and security patch deployment to servers.",
        "change_type": "standard",
        "category": "software",
        "default_risk_level": "low",
        "steps": [
            "Identify target servers and applicable patches",
            "Download and stage patches",
            "Create pre-patch snapshot/backup",
            "Apply patches in maintenance window",
            "Verify services restart successfully",
            "Run automated smoke tests",
        ],
        "approvers_required": [],
        "estimated_duration_minutes": 30,
        "rollback_steps": [
            "Revert to pre-patch snapshot",
            "Verify services restored",
        ],
    },
    {
        "template_id": "TPL-002",
        "name": "Firewall Rule Change",
        "description": "Add, modify, or remove firewall rules. Requires security team approval.",
        "change_type": "normal",
        "category": "security",
        "default_risk_level": "medium",
        "steps": [
            "Document current rule set",
            "Define new/modified rules with justification",
            "Peer review by security team",
            "Apply rules in staging environment",
            "Validate traffic flows",
            "Apply to production firewall",
            "Monitor for anomalies",
        ],
        "approvers_required": ["security_lead"],
        "estimated_duration_minutes": 45,
        "rollback_steps": [
            "Revert to documented previous rule set",
            "Verify connectivity restored",
        ],
    },
    {
        "template_id": "TPL-003",
        "name": "Network Switch Replacement",
        "description": "Physical replacement of a network switch. Requires CAB approval due to high impact.",
        "change_type": "normal",
        "category": "network",
        "default_risk_level": "high",
        "steps": [
            "Identify affected ports and VLANs",
            "Pre-configure replacement switch",
            "Notify affected users/departments",
            "Schedule maintenance window",
            "Physically swap switch hardware",
            "Verify port connectivity and VLAN tagging",
            "Run network diagnostics",
        ],
        "approvers_required": ["network_lead", "cab_chair"],
        "estimated_duration_minutes": 120,
        "rollback_steps": [
            "Reinstall original switch",
            "Verify port mappings restored",
            "Confirm VLAN connectivity",
        ],
    },
    {
        "template_id": "TPL-004",
        "name": "Emergency Security Patch",
        "description": "Expedited deployment of a critical security patch. Emergency change with expedited approval.",
        "change_type": "emergency",
        "category": "security",
        "default_risk_level": "critical",
        "steps": [
            "Assess CVE severity and exposure",
            "Obtain emergency approval from security lead",
            "Stage patch on test system",
            "Quick-validate critical services",
            "Deploy to production immediately",
            "Monitor for service impact",
            "Complete full PIR within 48 hours",
        ],
        "approvers_required": ["security_lead"],
        "estimated_duration_minutes": 60,
        "rollback_steps": [
            "Revert patch via package manager rollback",
            "Restore from snapshot if necessary",
            "Implement compensating controls if rollback fails",
        ],
    },
    {
        "template_id": "TPL-005",
        "name": "Cloud Service Migration",
        "description": "Multi-stage migration of services to cloud infrastructure. High risk with comprehensive rollback.",
        "change_type": "normal",
        "category": "cloud",
        "default_risk_level": "high",
        "steps": [
            "Inventory services and dependencies",
            "Design target cloud architecture",
            "Provision cloud infrastructure",
            "Configure networking and security groups",
            "Migrate data with validation checksums",
            "Deploy application tier",
            "Run parallel operation period",
            "DNS cutover to cloud endpoints",
            "Decommission on-prem resources after soak period",
        ],
        "approvers_required": ["infrastructure_lead", "application_lead", "cab_chair"],
        "estimated_duration_minutes": 480,
        "rollback_steps": [
            "Revert DNS to on-prem endpoints",
            "Restore on-prem services from backup",
            "Validate data consistency",
            "Notify stakeholders of rollback",
        ],
    },
]


# ============================================================
# Risk Scoring Weights
# ============================================================

CHANGE_TYPE_WEIGHT = {
    ChangeType.STANDARD: 10,
    ChangeType.NORMAL: 30,
    ChangeType.EMERGENCY: 50,
}

IMPACT_SCOPE_WEIGHT = {
    ImpactScope.SINGLE_DEVICE: 5,
    ImpactScope.DEPARTMENT: 15,
    ImpactScope.SITE: 25,
    ImpactScope.ORGANIZATION: 40,
}

ROLLBACK_COMPLEXITY_WEIGHT = {
    RollbackComplexity.SIMPLE: 5,
    RollbackComplexity.MODERATE: 15,
    RollbackComplexity.COMPLEX: 30,
}

TESTING_COVERAGE_WEIGHT = {
    TestingCoverage.FULL: 0,
    TestingCoverage.PARTIAL: 10,
    TestingCoverage.NONE: 25,
}

BLACKOUT_CONFLICT_PENALTY = 20
PAST_FAILURE_PENALTY = 15


# ============================================================
# Service
# ============================================================

class ChangeManagementService:
    """
    ITIL-aligned Change Management Workflow Service.

    Manages the full lifecycle of IT changes from request through
    implementation with risk assessment, approval workflows, and
    post-implementation review.

    Accepts optional db: Session for PostgreSQL persistence.
    Falls back to in-memory storage when DB is unavailable.
    """

    def __init__(self, db=None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE
        self.changes: Dict[str, ChangeRequest] = {}
        self.approvals: Dict[str, List[ApprovalRecord]] = {}
        self.templates: Dict[str, ChangeTemplate] = {}
        self.pirs: Dict[str, PIR] = {}
        self.blackout_windows: Dict[str, BlackoutWindow] = {}
        self._next_change_num = 1

        # Hydrate from DB
        if self._use_db:
            self._hydrate_from_db()
        else:
            # Seed default templates in-memory
            self._seed_default_templates()

    # ----------------------------------------------------------
    # Hydration & persistence helpers
    # ----------------------------------------------------------

    def _hydrate_from_db(self):
        """Load all data from DB into memory."""
        try:
            for row in self.db.query(ChangeRequestModel).all():
                cr = _change_from_row(row)
                self.changes[cr.change_id] = cr
                num = self._extract_num(cr.change_id)
                if num >= self._next_change_num:
                    self._next_change_num = num + 1

            for row in self.db.query(ApprovalRecordModel).all():
                ar = _approval_from_row(row)
                self.approvals.setdefault(ar.change_id, []).append(ar)

            for row in self.db.query(ChangeTemplateModel).all():
                tpl = _template_from_row(row)
                self.templates[tpl.template_id] = tpl

            for row in self.db.query(PIRModel).all():
                p = _pir_from_row(row)
                self.pirs[p.change_id] = p

            for row in self.db.query(BlackoutWindowModel).all():
                bw = _blackout_from_row(row)
                self.blackout_windows[bw.window_id] = bw

            # Seed default templates if none exist
            if not self.templates:
                self._seed_default_templates()
        except Exception as e:
            logger.error(f"DB hydration error: {e}")
            self._seed_default_templates()

    def _seed_default_templates(self):
        """Load the 5 pre-built ITIL templates."""
        for tdata in DEFAULT_TEMPLATES:
            tpl = ChangeTemplate(
                template_id=tdata["template_id"],
                name=tdata["name"],
                description=tdata["description"],
                change_type=ChangeType(tdata["change_type"]),
                category=ChangeCategory(tdata["category"]),
                default_risk_level=RiskLevel(tdata["default_risk_level"]),
                steps=tdata["steps"],
                approvers_required=tdata["approvers_required"],
                estimated_duration_minutes=tdata["estimated_duration_minutes"],
                rollback_steps=tdata["rollback_steps"],
            )
            self.templates[tpl.template_id] = tpl
            self._persist_template(tpl)

    @staticmethod
    def _extract_num(change_id: str) -> int:
        try:
            return int(change_id.split("-")[1])
        except (IndexError, ValueError):
            return 0

    def _gen_change_id(self) -> str:
        cid = f"CHG-{str(self._next_change_num).zfill(5)}"
        self._next_change_num += 1
        return cid

    # --- DB persist helpers ---

    def _persist_change(self, cr: ChangeRequest):
        if not self._use_db:
            return
        try:
            existing = self.db.query(ChangeRequestModel).filter(
                ChangeRequestModel.change_id == cr.change_id
            ).first()
            data = {
                "change_id": cr.change_id,
                "client_id": cr.client_id,
                "title": cr.title,
                "description": cr.description,
                "change_type": cr.change_type.value,
                "category": cr.category.value,
                "priority": cr.priority.value,
                "status": cr.status.value,
                "risk_level": cr.risk_level.value,
                "risk_score": cr.risk_score,
                "impact_assessment": cr.impact_assessment,
                "rollback_plan": cr.rollback_plan,
                "implementation_plan": cr.implementation_plan,
                "testing_plan": cr.testing_plan,
                "scheduled_start": cr.scheduled_start,
                "scheduled_end": cr.scheduled_end,
                "actual_start": cr.actual_start,
                "actual_end": cr.actual_end,
                "requested_by": cr.requested_by,
                "assigned_to": cr.assigned_to,
                "approved_by": cr.approved_by,
                "approvers_required": cr.approvers_required,
                "approvals_received": cr.approvals_received,
                "affected_cis": cr.affected_cis,
                "related_tickets": cr.related_tickets,
                "pir_completed": cr.pir_completed,
                "pir_notes": cr.pir_notes,
            }
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
            else:
                self.db.add(ChangeRequestModel(**data))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist change error: {e}")
            self.db.rollback()

    def _persist_approval(self, ar: ApprovalRecord):
        if not self._use_db:
            return
        try:
            self.db.add(ApprovalRecordModel(
                approval_id=ar.approval_id,
                change_id=ar.change_id,
                approver=ar.approver,
                decision=ar.decision.value,
                comments=ar.comments,
                decided_at=ar.decided_at,
            ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist approval error: {e}")
            self.db.rollback()

    def _persist_template(self, tpl: ChangeTemplate):
        if not self._use_db:
            return
        try:
            existing = self.db.query(ChangeTemplateModel).filter(
                ChangeTemplateModel.template_id == tpl.template_id
            ).first()
            if not existing:
                self.db.add(ChangeTemplateModel(
                    template_id=tpl.template_id,
                    name=tpl.name,
                    description=tpl.description,
                    change_type=tpl.change_type.value,
                    category=tpl.category.value,
                    default_risk_level=tpl.default_risk_level.value,
                    steps=tpl.steps,
                    approvers_required=tpl.approvers_required,
                    estimated_duration_minutes=tpl.estimated_duration_minutes,
                    rollback_steps=tpl.rollback_steps,
                ))
                self.db.commit()
        except Exception as e:
            logger.error(f"DB persist template error: {e}")
            self.db.rollback()

    def _persist_pir(self, pir: PIR):
        if not self._use_db:
            return
        try:
            self.db.add(PIRModel(
                pir_id=pir.pir_id,
                change_id=pir.change_id,
                was_successful=pir.was_successful,
                objectives_met=pir.objectives_met,
                issues_encountered=pir.issues_encountered,
                lessons_learned=pir.lessons_learned,
                follow_up_actions=pir.follow_up_actions,
                reviewed_by=pir.reviewed_by,
                reviewed_at=pir.reviewed_at,
            ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist PIR error: {e}")
            self.db.rollback()

    def _persist_blackout(self, bw: BlackoutWindow):
        if not self._use_db:
            return
        try:
            existing = self.db.query(BlackoutWindowModel).filter(
                BlackoutWindowModel.window_id == bw.window_id
            ).first()
            if not existing:
                self.db.add(BlackoutWindowModel(
                    window_id=bw.window_id,
                    client_id=bw.client_id,
                    name=bw.name,
                    start_time=bw.start_time,
                    end_time=bw.end_time,
                    reason=bw.reason,
                    is_recurring=bw.is_recurring,
                    recurrence_pattern=bw.recurrence_pattern,
                ))
                self.db.commit()
        except Exception as e:
            logger.error(f"DB persist blackout error: {e}")
            self.db.rollback()

    def _delete_blackout_db(self, window_id: str):
        if not self._use_db:
            return
        try:
            self.db.query(BlackoutWindowModel).filter(
                BlackoutWindowModel.window_id == window_id
            ).delete()
            self.db.commit()
        except Exception as e:
            logger.error(f"DB delete blackout error: {e}")
            self.db.rollback()

    # ----------------------------------------------------------
    # Change CRUD
    # ----------------------------------------------------------

    def create_change(
        self,
        client_id: str,
        title: str,
        description: str,
        change_type: ChangeType = ChangeType.NORMAL,
        category: ChangeCategory = ChangeCategory.OTHER,
        priority: ChangePriority = ChangePriority.MEDIUM,
        impact_assessment: str = "",
        rollback_plan: str = "",
        implementation_plan: str = "",
        testing_plan: str = "",
        scheduled_start: Optional[datetime] = None,
        scheduled_end: Optional[datetime] = None,
        requested_by: str = "",
        assigned_to: Optional[str] = None,
        approvers_required: Optional[List[str]] = None,
        affected_cis: Optional[List[str]] = None,
        related_tickets: Optional[List[str]] = None,
    ) -> ChangeRequest:
        """Create a new change request in DRAFT status."""
        change_id = self._gen_change_id()
        now = datetime.now(timezone.utc)

        cr = ChangeRequest(
            change_id=change_id,
            client_id=client_id,
            title=title,
            description=description,
            change_type=change_type,
            category=category,
            priority=priority,
            status=ChangeStatus.DRAFT,
            impact_assessment=impact_assessment,
            rollback_plan=rollback_plan,
            implementation_plan=implementation_plan,
            testing_plan=testing_plan,
            scheduled_start=scheduled_start,
            scheduled_end=scheduled_end,
            requested_by=requested_by,
            assigned_to=assigned_to,
            approvers_required=approvers_required or [],
            affected_cis=affected_cis or [],
            related_tickets=related_tickets or [],
            created_at=now,
            updated_at=now,
        )
        self.changes[change_id] = cr
        self._persist_change(cr)
        logger.info(f"Change {change_id} created: {title}")
        return cr

    def get_change(self, change_id: str) -> Optional[ChangeRequest]:
        """Retrieve a change request by ID."""
        return self.changes.get(change_id)

    def list_changes(
        self,
        client_id: Optional[str] = None,
        status: Optional[ChangeStatus] = None,
        change_type: Optional[ChangeType] = None,
        priority: Optional[ChangePriority] = None,
        category: Optional[ChangeCategory] = None,
    ) -> List[ChangeRequest]:
        """List change requests with optional filters."""
        result = list(self.changes.values())
        if client_id:
            result = [c for c in result if c.client_id == client_id]
        if status:
            result = [c for c in result if c.status == status]
        if change_type:
            result = [c for c in result if c.change_type == change_type]
        if priority:
            result = [c for c in result if c.priority == priority]
        if category:
            result = [c for c in result if c.category == category]
        result.sort(key=lambda c: c.created_at, reverse=True)
        return result

    def update_change(self, change_id: str, **kwargs) -> Optional[ChangeRequest]:
        """Update fields on a change request."""
        cr = self.changes.get(change_id)
        if not cr:
            return None

        for key, value in kwargs.items():
            if hasattr(cr, key) and key not in ("change_id", "created_at"):
                setattr(cr, key, value)

        cr.updated_at = datetime.now(timezone.utc)
        self._persist_change(cr)
        return cr

    # ----------------------------------------------------------
    # Workflow transitions
    # ----------------------------------------------------------

    def submit_change(self, change_id: str) -> Optional[ChangeRequest]:
        """Submit a draft change for review."""
        cr = self.changes.get(change_id)
        if not cr:
            return None
        if cr.status != ChangeStatus.DRAFT:
            raise ValueError(f"Change {change_id} is not in DRAFT status (current: {cr.status.value})")

        cr.status = ChangeStatus.SUBMITTED
        cr.updated_at = datetime.now(timezone.utc)

        # Auto-calculate risk score on submission
        cr.risk_score = self.calculate_risk_score({
            "change_type": cr.change_type.value,
        })
        cr.risk_level = self._score_to_level(cr.risk_score)

        # If no approvers required, auto-advance to under_review
        if not cr.approvers_required:
            cr.status = ChangeStatus.UNDER_REVIEW

        self._persist_change(cr)
        logger.info(f"Change {change_id} submitted (risk_score={cr.risk_score})")
        return cr

    def approve_change(
        self,
        change_id: str,
        approver: str,
        decision: ApprovalDecision,
        comments: str = "",
    ) -> Optional[ChangeRequest]:
        """Record an approval decision on a change request."""
        cr = self.changes.get(change_id)
        if not cr:
            return None
        if cr.status not in (ChangeStatus.SUBMITTED, ChangeStatus.UNDER_REVIEW):
            raise ValueError(f"Change {change_id} is not awaiting approval (current: {cr.status.value})")

        ar = ApprovalRecord(
            approval_id=str(uuid.uuid4())[:12],
            change_id=change_id,
            approver=approver,
            decision=decision,
            comments=comments,
            decided_at=datetime.now(timezone.utc),
        )
        self.approvals.setdefault(change_id, []).append(ar)
        self._persist_approval(ar)

        if decision == ApprovalDecision.APPROVED:
            if approver not in cr.approvals_received:
                cr.approvals_received.append(approver)
            cr.approved_by = approver

            # Check if all required approvers have approved
            if cr.approvers_required:
                all_approved = all(
                    req in cr.approvals_received for req in cr.approvers_required
                )
                if all_approved:
                    cr.status = ChangeStatus.APPROVED
                else:
                    cr.status = ChangeStatus.UNDER_REVIEW
            else:
                cr.status = ChangeStatus.APPROVED

        elif decision == ApprovalDecision.REJECTED:
            cr.status = ChangeStatus.CANCELLED

        elif decision == ApprovalDecision.DEFERRED:
            cr.status = ChangeStatus.UNDER_REVIEW

        cr.updated_at = datetime.now(timezone.utc)
        self._persist_change(cr)
        logger.info(f"Change {change_id} {decision.value} by {approver}")
        return cr

    def start_implementation(self, change_id: str) -> Optional[ChangeRequest]:
        """Transition change to IMPLEMENTING."""
        cr = self.changes.get(change_id)
        if not cr:
            return None
        if cr.status not in (ChangeStatus.APPROVED, ChangeStatus.SCHEDULED):
            raise ValueError(f"Change {change_id} must be APPROVED or SCHEDULED to implement (current: {cr.status.value})")

        cr.status = ChangeStatus.IMPLEMENTING
        cr.actual_start = datetime.now(timezone.utc)
        cr.updated_at = datetime.now(timezone.utc)
        self._persist_change(cr)
        logger.info(f"Change {change_id} implementation started")
        return cr

    def complete_change(self, change_id: str, success: bool = True) -> Optional[ChangeRequest]:
        """Mark change as COMPLETED or FAILED."""
        cr = self.changes.get(change_id)
        if not cr:
            return None
        if cr.status != ChangeStatus.IMPLEMENTING:
            raise ValueError(f"Change {change_id} must be IMPLEMENTING to complete (current: {cr.status.value})")

        cr.status = ChangeStatus.COMPLETED if success else ChangeStatus.FAILED
        cr.actual_end = datetime.now(timezone.utc)
        cr.updated_at = datetime.now(timezone.utc)
        self._persist_change(cr)
        logger.info(f"Change {change_id} {'completed' if success else 'failed'}")
        return cr

    def rollback_change(self, change_id: str, reason: str = "") -> Optional[ChangeRequest]:
        """Roll back a change that is implementing or failed."""
        cr = self.changes.get(change_id)
        if not cr:
            return None
        if cr.status not in (ChangeStatus.IMPLEMENTING, ChangeStatus.FAILED):
            raise ValueError(f"Change {change_id} must be IMPLEMENTING or FAILED to rollback (current: {cr.status.value})")

        cr.status = ChangeStatus.ROLLED_BACK
        cr.actual_end = datetime.now(timezone.utc)
        cr.updated_at = datetime.now(timezone.utc)
        if reason:
            cr.pir_notes = (cr.pir_notes or "") + f"\nRollback reason: {reason}"
        self._persist_change(cr)
        logger.info(f"Change {change_id} rolled back: {reason}")
        return cr

    def cancel_change(self, change_id: str, reason: str = "") -> Optional[ChangeRequest]:
        """Cancel a change request."""
        cr = self.changes.get(change_id)
        if not cr:
            return None
        terminal = (ChangeStatus.COMPLETED, ChangeStatus.FAILED, ChangeStatus.ROLLED_BACK, ChangeStatus.CANCELLED)
        if cr.status in terminal:
            raise ValueError(f"Change {change_id} is already in terminal status ({cr.status.value})")

        cr.status = ChangeStatus.CANCELLED
        cr.updated_at = datetime.now(timezone.utc)
        if reason:
            cr.pir_notes = (cr.pir_notes or "") + f"\nCancellation reason: {reason}"
        self._persist_change(cr)
        logger.info(f"Change {change_id} cancelled: {reason}")
        return cr

    # ----------------------------------------------------------
    # Risk Assessment
    # ----------------------------------------------------------

    def calculate_risk_score(
        self,
        change_data: Dict[str, Any],
    ) -> int:
        """
        Calculate risk score (0-100) from weighted factors.

        Expected keys in change_data:
        - change_type: str (standard/normal/emergency)
        - impact_scope: str (single_device/department/site/organization)
        - rollback_complexity: str (simple/moderate/complex)
        - testing_coverage: str (full/partial/none)
        - scheduled_start: datetime (optional, for blackout check)
        - scheduled_end: datetime (optional)
        - change_id: str (optional, for failure history lookup)
        """
        score = 0

        # Change type weight
        ct = change_data.get("change_type", "normal")
        try:
            score += CHANGE_TYPE_WEIGHT.get(ChangeType(ct), 30)
        except ValueError:
            score += 30

        # Impact scope
        scope = change_data.get("impact_scope", "department")
        try:
            score += IMPACT_SCOPE_WEIGHT.get(ImpactScope(scope), 15)
        except ValueError:
            score += 15

        # Rollback complexity
        rb = change_data.get("rollback_complexity", "moderate")
        try:
            score += ROLLBACK_COMPLEXITY_WEIGHT.get(RollbackComplexity(rb), 15)
        except ValueError:
            score += 15

        # Testing coverage
        tc = change_data.get("testing_coverage", "partial")
        try:
            score += TESTING_COVERAGE_WEIGHT.get(TestingCoverage(tc), 10)
        except ValueError:
            score += 10

        # Blackout conflict check
        sched_start = change_data.get("scheduled_start")
        sched_end = change_data.get("scheduled_end")
        if sched_start:
            if self.check_blackout(sched_start):
                score += BLACKOUT_CONFLICT_PENALTY

        # Previous failure history
        change_id = change_data.get("change_id")
        if change_id:
            cr = self.changes.get(change_id)
            if cr:
                # Count past failures for same category
                past_failures = sum(
                    1 for c in self.changes.values()
                    if c.status == ChangeStatus.FAILED
                    and c.category == cr.category
                    and c.change_id != change_id
                )
                score += past_failures * PAST_FAILURE_PENALTY

        return min(score, 100)

    @staticmethod
    def _score_to_level(score: int) -> RiskLevel:
        """Convert numeric risk score to risk level."""
        if score <= 25:
            return RiskLevel.LOW
        elif score <= 50:
            return RiskLevel.MEDIUM
        elif score <= 75:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    # ----------------------------------------------------------
    # Approvals
    # ----------------------------------------------------------

    def get_pending_approvals(self, approver: str) -> List[ChangeRequest]:
        """Get changes awaiting approval from a specific approver."""
        pending = []
        for cr in self.changes.values():
            if cr.status in (ChangeStatus.SUBMITTED, ChangeStatus.UNDER_REVIEW):
                if approver in cr.approvers_required and approver not in cr.approvals_received:
                    pending.append(cr)
        return pending

    def get_approval_history(self, change_id: str) -> List[ApprovalRecord]:
        """Get all approval records for a change."""
        return self.approvals.get(change_id, [])

    # ----------------------------------------------------------
    # Templates
    # ----------------------------------------------------------

    def create_template(
        self,
        name: str,
        description: str,
        change_type: ChangeType = ChangeType.STANDARD,
        category: ChangeCategory = ChangeCategory.OTHER,
        default_risk_level: RiskLevel = RiskLevel.LOW,
        steps: Optional[List[str]] = None,
        approvers_required: Optional[List[str]] = None,
        estimated_duration_minutes: int = 30,
        rollback_steps: Optional[List[str]] = None,
    ) -> ChangeTemplate:
        """Create a new change template."""
        tid = f"TPL-{str(uuid.uuid4())[:8].upper()}"
        tpl = ChangeTemplate(
            template_id=tid,
            name=name,
            description=description,
            change_type=change_type,
            category=category,
            default_risk_level=default_risk_level,
            steps=steps or [],
            approvers_required=approvers_required or [],
            estimated_duration_minutes=estimated_duration_minutes,
            rollback_steps=rollback_steps or [],
        )
        self.templates[tid] = tpl
        self._persist_template(tpl)
        return tpl

    def list_templates(self) -> List[ChangeTemplate]:
        """List all change templates."""
        return list(self.templates.values())

    def get_template(self, template_id: str) -> Optional[ChangeTemplate]:
        """Get a specific template by ID."""
        return self.templates.get(template_id)

    def create_from_template(
        self,
        template_id: str,
        client_id: str,
        title: str = "",
        requested_by: str = "",
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Optional[ChangeRequest]:
        """Create a change request from a template with optional overrides."""
        tpl = self.templates.get(template_id)
        if not tpl:
            return None

        overrides = overrides or {}
        return self.create_change(
            client_id=client_id,
            title=title or tpl.name,
            description=overrides.get("description", tpl.description),
            change_type=ChangeType(overrides["change_type"]) if "change_type" in overrides else tpl.change_type,
            category=ChangeCategory(overrides["category"]) if "category" in overrides else tpl.category,
            priority=ChangePriority(overrides.get("priority", "medium")),
            rollback_plan=overrides.get("rollback_plan", "\n".join(tpl.rollback_steps)),
            implementation_plan=overrides.get("implementation_plan", "\n".join(tpl.steps)),
            requested_by=requested_by,
            approvers_required=overrides.get("approvers_required", tpl.approvers_required),
            affected_cis=overrides.get("affected_cis", []),
            related_tickets=overrides.get("related_tickets", []),
        )

    # ----------------------------------------------------------
    # Post-Implementation Review
    # ----------------------------------------------------------

    def create_pir(self, change_id: str, pir_data: Dict[str, Any]) -> Optional[PIR]:
        """Create a Post-Implementation Review for a completed/failed/rolled-back change."""
        cr = self.changes.get(change_id)
        if not cr:
            return None
        terminal = (ChangeStatus.COMPLETED, ChangeStatus.FAILED, ChangeStatus.ROLLED_BACK)
        if cr.status not in terminal:
            raise ValueError(f"PIR can only be created for completed/failed/rolled-back changes (current: {cr.status.value})")

        pir = PIR(
            pir_id=f"PIR-{str(uuid.uuid4())[:8].upper()}",
            change_id=change_id,
            was_successful=pir_data.get("was_successful", cr.status == ChangeStatus.COMPLETED),
            objectives_met=pir_data.get("objectives_met", cr.status == ChangeStatus.COMPLETED),
            issues_encountered=pir_data.get("issues_encountered", []),
            lessons_learned=pir_data.get("lessons_learned", []),
            follow_up_actions=pir_data.get("follow_up_actions", []),
            reviewed_by=pir_data.get("reviewed_by", ""),
            reviewed_at=datetime.now(timezone.utc),
        )
        self.pirs[change_id] = pir
        cr.pir_completed = True
        cr.pir_notes = pir_data.get("notes", "")
        cr.updated_at = datetime.now(timezone.utc)
        self._persist_pir(pir)
        self._persist_change(cr)
        return pir

    def get_pir(self, change_id: str) -> Optional[PIR]:
        """Get PIR for a change."""
        return self.pirs.get(change_id)

    # ----------------------------------------------------------
    # Calendar & Blackout
    # ----------------------------------------------------------

    def get_change_calendar(
        self,
        client_id: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[ChangeCalendar]:
        """Get scheduled changes as calendar entries."""
        entries = []
        for cr in self.changes.values():
            if cr.scheduled_start is None:
                continue
            if client_id and cr.client_id != client_id:
                continue
            if start and cr.scheduled_start < start:
                continue
            if end and cr.scheduled_start > end:
                continue
            entries.append(ChangeCalendar(
                entry_id=f"CAL-{cr.change_id}",
                change_id=cr.change_id,
                title=cr.title,
                scheduled_start=cr.scheduled_start,
                scheduled_end=cr.scheduled_end or (cr.scheduled_start + timedelta(hours=1)),
                status=cr.status,
                risk_level=cr.risk_level,
                client_id=cr.client_id,
            ))
        entries.sort(key=lambda e: e.scheduled_start)
        return entries

    def check_conflicts(
        self,
        scheduled_start: datetime,
        scheduled_end: datetime,
    ) -> List[Dict[str, Any]]:
        """Check for scheduling conflicts with existing changes and blackout windows."""
        conflicts = []

        # Check against existing scheduled changes
        for cr in self.changes.values():
            if cr.scheduled_start is None:
                continue
            if cr.status in (ChangeStatus.CANCELLED, ChangeStatus.COMPLETED, ChangeStatus.FAILED, ChangeStatus.ROLLED_BACK):
                continue
            cr_end = cr.scheduled_end or (cr.scheduled_start + timedelta(hours=1))
            if scheduled_start < cr_end and scheduled_end > cr.scheduled_start:
                conflicts.append({
                    "type": "change_overlap",
                    "change_id": cr.change_id,
                    "title": cr.title,
                    "start": cr.scheduled_start.isoformat(),
                    "end": cr_end.isoformat(),
                })

        # Check against blackout windows
        for bw in self.blackout_windows.values():
            if scheduled_start < bw.end_time and scheduled_end > bw.start_time:
                conflicts.append({
                    "type": "blackout_window",
                    "window_id": bw.window_id,
                    "name": bw.name,
                    "start": bw.start_time.isoformat(),
                    "end": bw.end_time.isoformat(),
                    "reason": bw.reason,
                })

        return conflicts

    def create_blackout_window(
        self,
        client_id: str,
        name: str,
        start_time: datetime,
        end_time: datetime,
        reason: str = "",
        is_recurring: bool = False,
        recurrence_pattern: Optional[str] = None,
    ) -> BlackoutWindow:
        """Create a maintenance blackout window."""
        wid = f"BLK-{str(uuid.uuid4())[:8].upper()}"
        bw = BlackoutWindow(
            window_id=wid,
            client_id=client_id,
            name=name,
            start_time=start_time,
            end_time=end_time,
            reason=reason,
            is_recurring=is_recurring,
            recurrence_pattern=recurrence_pattern,
        )
        self.blackout_windows[wid] = bw
        self._persist_blackout(bw)
        return bw

    def list_blackout_windows(self, client_id: Optional[str] = None) -> List[BlackoutWindow]:
        """List blackout windows, optionally filtered by client."""
        result = list(self.blackout_windows.values())
        if client_id:
            result = [bw for bw in result if bw.client_id == client_id]
        result.sort(key=lambda bw: bw.start_time)
        return result

    def delete_blackout_window(self, window_id: str) -> bool:
        """Delete a blackout window."""
        if window_id in self.blackout_windows:
            del self.blackout_windows[window_id]
            self._delete_blackout_db(window_id)
            return True
        return False

    def check_blackout(self, dt: datetime) -> bool:
        """Check if a datetime falls within any blackout window."""
        for bw in self.blackout_windows.values():
            if bw.start_time <= dt <= bw.end_time:
                return True
        return False

    # ----------------------------------------------------------
    # Analytics
    # ----------------------------------------------------------

    def get_change_success_rate(self) -> float:
        """Calculate success rate of completed changes (percentage)."""
        completed = sum(1 for c in self.changes.values() if c.status == ChangeStatus.COMPLETED)
        failed = sum(1 for c in self.changes.values() if c.status in (ChangeStatus.FAILED, ChangeStatus.ROLLED_BACK))
        total = completed + failed
        if total == 0:
            return 100.0
        return round((completed / total) * 100, 1)

    def get_avg_implementation_time(self) -> float:
        """Average implementation time in minutes for completed changes."""
        durations = []
        for c in self.changes.values():
            if c.actual_start and c.actual_end:
                delta = (c.actual_end - c.actual_start).total_seconds() / 60
                durations.append(delta)
        if not durations:
            return 0.0
        return round(sum(durations) / len(durations), 1)

    def get_changes_by_category(self) -> Dict[str, int]:
        """Count changes grouped by category."""
        counts: Dict[str, int] = {}
        for c in self.changes.values():
            cat = c.category.value
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def get_risk_distribution(self) -> Dict[str, int]:
        """Count changes grouped by risk level."""
        dist: Dict[str, int] = {}
        for c in self.changes.values():
            rl = c.risk_level.value
            dist[rl] = dist.get(rl, 0) + 1
        return dist

    def get_dashboard(self) -> Dict[str, Any]:
        """Aggregated dashboard for change management."""
        now = datetime.now(timezone.utc)

        # Pending approvals
        pending = [c for c in self.changes.values() if c.status in (ChangeStatus.SUBMITTED, ChangeStatus.UNDER_REVIEW)]

        # Scheduled changes (next 14 days)
        upcoming = []
        for c in self.changes.values():
            if c.scheduled_start and c.status in (ChangeStatus.APPROVED, ChangeStatus.SCHEDULED):
                if 0 <= (c.scheduled_start - now).days <= 14:
                    upcoming.append(c)
        upcoming.sort(key=lambda c: c.scheduled_start)

        # Recent PIRs
        recent_pirs = sorted(self.pirs.values(), key=lambda p: p.reviewed_at, reverse=True)[:5]

        # Counts by status
        by_status: Dict[str, int] = {}
        for c in self.changes.values():
            by_status[c.status.value] = by_status.get(c.status.value, 0) + 1

        return {
            "total_changes": len(self.changes),
            "pending_approvals": len(pending),
            "pending_approval_changes": [
                {"change_id": c.change_id, "title": c.title, "priority": c.priority.value, "risk_level": c.risk_level.value}
                for c in pending
            ],
            "scheduled_changes": [
                {
                    "change_id": c.change_id,
                    "title": c.title,
                    "scheduled_start": c.scheduled_start.isoformat() if c.scheduled_start else None,
                    "risk_level": c.risk_level.value,
                }
                for c in upcoming
            ],
            "success_rate": self.get_change_success_rate(),
            "avg_implementation_time_minutes": self.get_avg_implementation_time(),
            "risk_distribution": self.get_risk_distribution(),
            "by_status": by_status,
            "by_category": self.get_changes_by_category(),
            "recent_pirs": [
                {
                    "pir_id": p.pir_id,
                    "change_id": p.change_id,
                    "was_successful": p.was_successful,
                    "reviewed_at": p.reviewed_at.isoformat(),
                }
                for p in recent_pirs
            ],
            "blackout_windows_active": sum(
                1 for bw in self.blackout_windows.values()
                if bw.start_time <= now <= bw.end_time
            ),
        }

    # ----------------------------------------------------------
    # Serialization helpers
    # ----------------------------------------------------------

    @staticmethod
    def change_to_dict(cr: ChangeRequest) -> Dict[str, Any]:
        """Serialize a ChangeRequest to a dict."""
        return {
            "change_id": cr.change_id,
            "client_id": cr.client_id,
            "title": cr.title,
            "description": cr.description,
            "change_type": cr.change_type.value,
            "category": cr.category.value,
            "priority": cr.priority.value,
            "status": cr.status.value,
            "risk_level": cr.risk_level.value,
            "risk_score": cr.risk_score,
            "impact_assessment": cr.impact_assessment,
            "rollback_plan": cr.rollback_plan,
            "implementation_plan": cr.implementation_plan,
            "testing_plan": cr.testing_plan,
            "scheduled_start": cr.scheduled_start.isoformat() if cr.scheduled_start else None,
            "scheduled_end": cr.scheduled_end.isoformat() if cr.scheduled_end else None,
            "actual_start": cr.actual_start.isoformat() if cr.actual_start else None,
            "actual_end": cr.actual_end.isoformat() if cr.actual_end else None,
            "requested_by": cr.requested_by,
            "assigned_to": cr.assigned_to,
            "approved_by": cr.approved_by,
            "approvers_required": cr.approvers_required,
            "approvals_received": cr.approvals_received,
            "affected_cis": cr.affected_cis,
            "related_tickets": cr.related_tickets,
            "pir_completed": cr.pir_completed,
            "pir_notes": cr.pir_notes,
            "created_at": cr.created_at.isoformat(),
            "updated_at": cr.updated_at.isoformat(),
        }

    @staticmethod
    def approval_to_dict(ar: ApprovalRecord) -> Dict[str, Any]:
        return {
            "approval_id": ar.approval_id,
            "change_id": ar.change_id,
            "approver": ar.approver,
            "decision": ar.decision.value,
            "comments": ar.comments,
            "decided_at": ar.decided_at.isoformat(),
        }

    @staticmethod
    def template_to_dict(tpl: ChangeTemplate) -> Dict[str, Any]:
        return {
            "template_id": tpl.template_id,
            "name": tpl.name,
            "description": tpl.description,
            "change_type": tpl.change_type.value,
            "category": tpl.category.value,
            "default_risk_level": tpl.default_risk_level.value,
            "steps": tpl.steps,
            "approvers_required": tpl.approvers_required,
            "estimated_duration_minutes": tpl.estimated_duration_minutes,
            "rollback_steps": tpl.rollback_steps,
        }

    @staticmethod
    def pir_to_dict(pir: PIR) -> Dict[str, Any]:
        return {
            "pir_id": pir.pir_id,
            "change_id": pir.change_id,
            "was_successful": pir.was_successful,
            "objectives_met": pir.objectives_met,
            "issues_encountered": pir.issues_encountered,
            "lessons_learned": pir.lessons_learned,
            "follow_up_actions": pir.follow_up_actions,
            "reviewed_by": pir.reviewed_by,
            "reviewed_at": pir.reviewed_at.isoformat(),
        }

    @staticmethod
    def blackout_to_dict(bw: BlackoutWindow) -> Dict[str, Any]:
        return {
            "window_id": bw.window_id,
            "client_id": bw.client_id,
            "name": bw.name,
            "start_time": bw.start_time.isoformat(),
            "end_time": bw.end_time.isoformat(),
            "reason": bw.reason,
            "is_recurring": bw.is_recurring,
            "recurrence_pattern": bw.recurrence_pattern,
        }

    @staticmethod
    def calendar_to_dict(entry: ChangeCalendar) -> Dict[str, Any]:
        return {
            "entry_id": entry.entry_id,
            "change_id": entry.change_id,
            "title": entry.title,
            "scheduled_start": entry.scheduled_start.isoformat(),
            "scheduled_end": entry.scheduled_end.isoformat(),
            "status": entry.status.value,
            "risk_level": entry.risk_level.value,
            "client_id": entry.client_id,
        }
