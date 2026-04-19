"""
AITHER Platform - Security Awareness Training & Phishing Simulation Service

Manages employee security training programs, runs phishing simulations,
tracks compliance, and calculates per-user risk scores.

Provides:
- Training course management and assignment
- Phishing campaign creation and simulation
- Phishing template library (8 pre-built)
- Per-user risk scoring (0-100)
- Compliance dashboards and trend analytics
- DB persistence with in-memory fallback
"""

import uuid
import random
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.security_training import (
        TrainingCourseModel,
        TrainingAssignmentModel,
        PhishingCampaignModel,
        PhishingTemplateModel,
        PhishingEventModel,
        UserRiskScoreModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class CourseCategory(str, Enum):
    PHISHING_AWARENESS = "phishing_awareness"
    PASSWORD_SECURITY = "password_security"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_HANDLING = "data_handling"
    COMPLIANCE = "compliance"
    INCIDENT_REPORTING = "incident_reporting"
    PHYSICAL_SECURITY = "physical_security"
    MOBILE_SECURITY = "mobile_security"


class AssignmentStatus(str, Enum):
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    OVERDUE = "overdue"
    EXEMPTED = "exempted"


class CampaignStatus(str, Enum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class PhishCategory(str, Enum):
    CREDENTIAL_HARVEST = "credential_harvest"
    MALWARE_LINK = "malware_link"
    ATTACHMENT = "attachment"
    BEC = "bec"
    SPEAR_PHISH = "spear_phish"


class PhishEventType(str, Enum):
    SENT = "sent"
    OPENED = "opened"
    CLICKED = "clicked"
    SUBMITTED = "submitted"
    REPORTED = "reported"


class Difficulty(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class Module:
    """Single content module within a training course."""
    module_id: str
    title: str
    content_type: str  # video/article/quiz/interactive
    content_url: str = ""
    duration_minutes: int = 5
    order: int = 0


@dataclass
class TrainingCourse:
    """Security awareness training course."""
    course_id: str
    title: str
    description: str = ""
    category: CourseCategory = CourseCategory.PHISHING_AWARENESS
    difficulty: Difficulty = Difficulty.BEGINNER
    duration_minutes: int = 15
    content_modules: List[Module] = field(default_factory=list)
    passing_score: float = 80.0
    is_mandatory: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class TrainingAssignment:
    """Links a user to a course with tracking."""
    assignment_id: str
    client_id: str
    course_id: str
    user_email: str
    user_name: str = ""
    status: AssignmentStatus = AssignmentStatus.ASSIGNED
    assigned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    due_date: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    score: Optional[float] = None
    attempts: int = 0
    certificate_id: Optional[str] = None


@dataclass
class PhishingTemplate:
    """Phishing email template."""
    template_id: str
    name: str
    category: PhishCategory = PhishCategory.CREDENTIAL_HARVEST
    subject: str = ""
    sender_name: str = ""
    sender_email: str = ""
    body_html: str = ""
    landing_page_html: str = ""
    difficulty: str = "medium"
    brand_impersonated: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PhishingCampaign:
    """Phishing simulation campaign."""
    campaign_id: str
    client_id: str
    name: str
    template_id: str
    status: CampaignStatus = CampaignStatus.DRAFT
    target_users: List[Dict[str, str]] = field(default_factory=list)
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_submitted: int = 0
    reported_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PhishingEvent:
    """Individual phishing event."""
    event_id: str
    campaign_id: str
    user_email: str
    event_type: PhishEventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UserRiskScore:
    """Aggregated security risk per user."""
    user_id: str
    client_id: str
    email: str
    name: str = ""
    phishing_fail_count: int = 0
    phishing_report_count: int = 0
    training_completed_count: int = 0
    training_overdue_count: int = 0
    risk_score: float = 50.0
    last_phish_test: Optional[datetime] = None
    last_training: Optional[datetime] = None


# ============================================================
# Service
# ============================================================

class SecurityTrainingService:
    """
    Security Awareness Training & Phishing Simulation Service.

    Manages training courses, phishing campaigns, user risk scoring,
    and compliance analytics for MSP clients.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback
        self._courses: Dict[str, TrainingCourse] = {}
        self._assignments: Dict[str, TrainingAssignment] = {}
        self._campaigns: Dict[str, PhishingCampaign] = {}
        self._templates: Dict[str, PhishingTemplate] = {}
        self._events: List[PhishingEvent] = []
        self._user_risks: Dict[str, UserRiskScore] = {}

        self._init_default_templates()
        self._init_default_courses()

    # ------------------------------------------------------------------
    # Default data
    # ------------------------------------------------------------------

    def _init_default_templates(self) -> None:
        """Seed 8 pre-built phishing templates."""
        defaults = [
            PhishingTemplate(
                template_id="TPL-PHISH-001", name="Microsoft 365 Password Expiry",
                category=PhishCategory.CREDENTIAL_HARVEST, difficulty="medium",
                subject="Action Required: Your Microsoft 365 password expires in 24 hours",
                sender_name="Microsoft 365 Admin", sender_email="admin@microsoft365-security.com",
                body_html="<p>Your password will expire soon. Click <a href='#'>here</a> to reset.</p>",
                landing_page_html="<h2>Microsoft 365 Sign In</h2><form><input placeholder='Email'/><input type='password' placeholder='Password'/><button>Sign In</button></form>",
                brand_impersonated="Microsoft",
            ),
            PhishingTemplate(
                template_id="TPL-PHISH-002", name="IT Department System Update Required",
                category=PhishCategory.MALWARE_LINK, difficulty="low",
                subject="Required: System Security Update Available",
                sender_name="IT Department", sender_email="it-support@company-updates.com",
                body_html="<p>A critical security update is available. <a href='#'>Download now</a>.</p>",
                landing_page_html="<h2>Download Update</h2><p>Click to install security patch.</p>",
                brand_impersonated="Internal IT",
            ),
            PhishingTemplate(
                template_id="TPL-PHISH-003", name="CEO Wire Transfer Request",
                category=PhishCategory.BEC, difficulty="high",
                subject="Urgent: Wire Transfer Needed Today",
                sender_name="CEO Office", sender_email="ceo@company-executive.com",
                body_html="<p>I need you to process an urgent wire transfer. Please reply with confirmation ASAP.</p>",
                landing_page_html="",
                brand_impersonated="Internal Executive",
            ),
            PhishingTemplate(
                template_id="TPL-PHISH-004", name="Shared Document Notification",
                category=PhishCategory.CREDENTIAL_HARVEST, difficulty="medium",
                subject="Document shared with you: Q4 Financial Report.xlsx",
                sender_name="SharePoint Online", sender_email="noreply@sharepoint-docs.com",
                body_html="<p>A document has been shared with you. <a href='#'>View Document</a></p>",
                landing_page_html="<h2>Sign in to view document</h2><form><input placeholder='Email'/><input type='password' placeholder='Password'/><button>Sign In</button></form>",
                brand_impersonated="Microsoft SharePoint",
            ),
            PhishingTemplate(
                template_id="TPL-PHISH-005", name="HR Benefits Enrollment",
                category=PhishCategory.SPEAR_PHISH, difficulty="medium",
                subject="Open Enrollment: Update Your Benefits Before Friday",
                sender_name="HR Benefits Team", sender_email="benefits@hr-portal-enrollment.com",
                body_html="<p>Open enrollment closes Friday. <a href='#'>Update your benefits</a> now.</p>",
                landing_page_html="<h2>Benefits Portal Login</h2><form><input placeholder='Employee ID'/><input type='password' placeholder='Password'/><button>Login</button></form>",
                brand_impersonated="HR Department",
            ),
            PhishingTemplate(
                template_id="TPL-PHISH-006", name="Package Delivery Failed",
                category=PhishCategory.MALWARE_LINK, difficulty="low",
                subject="Delivery Failed: Package #PKG-29481 Could Not Be Delivered",
                sender_name="FedEx Delivery", sender_email="tracking@fedex-notifications.com",
                body_html="<p>Your package could not be delivered. <a href='#'>Reschedule delivery</a> or <a href='#'>download shipping label</a>.</p>",
                landing_page_html="<h2>FedEx Tracking</h2><p>Click to reschedule your delivery.</p>",
                brand_impersonated="FedEx",
            ),
            PhishingTemplate(
                template_id="TPL-PHISH-007", name="Zoom Meeting Invitation",
                category=PhishCategory.CREDENTIAL_HARVEST, difficulty="low",
                subject="You have been invited to a Zoom meeting",
                sender_name="Zoom Meetings", sender_email="no-reply@zoom-meetings-invite.com",
                body_html="<p>You have a scheduled meeting. <a href='#'>Join Meeting</a></p>",
                landing_page_html="<h2>Zoom - Sign In</h2><form><input placeholder='Email'/><input type='password' placeholder='Password'/><button>Sign In</button></form>",
                brand_impersonated="Zoom",
            ),
            PhishingTemplate(
                template_id="TPL-PHISH-008", name="Payroll Direct Deposit Change",
                category=PhishCategory.BEC, difficulty="high",
                subject="Payroll: Direct Deposit Update Required",
                sender_name="Payroll Department", sender_email="payroll@company-payroll.com",
                body_html="<p>We need to verify your direct deposit information before the next pay cycle. <a href='#'>Verify now</a>.</p>",
                landing_page_html="<h2>Payroll Portal</h2><form><input placeholder='Employee ID'/><input placeholder='Bank Routing #'/><input placeholder='Account #'/><button>Submit</button></form>",
                brand_impersonated="Internal Payroll",
            ),
        ]
        for t in defaults:
            if self._use_db:
                existing = self.db.query(PhishingTemplateModel).filter_by(
                    template_id=t.template_id
                ).first()
                if not existing:
                    self.db.add(PhishingTemplateModel(
                        template_id=t.template_id, name=t.name, category=t.category.value if isinstance(t.category, Enum) else t.category,
                        subject=t.subject, sender_name=t.sender_name, sender_email=t.sender_email,
                        body_html=t.body_html, landing_page_html=t.landing_page_html,
                        difficulty=t.difficulty, brand_impersonated=t.brand_impersonated,
                    ))
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
            self._templates[t.template_id] = t

    def _init_default_courses(self) -> None:
        """Seed 5 pre-built training courses."""
        defaults = [
            TrainingCourse(
                course_id="CRS-SAT-001", title="Phishing 101",
                description="Learn to identify and report phishing emails, links, and social engineering attacks.",
                category=CourseCategory.PHISHING_AWARENESS, difficulty=Difficulty.BEGINNER,
                duration_minutes=20, passing_score=80.0, is_mandatory=True,
                content_modules=[
                    Module(module_id="M-001-1", title="What is Phishing?", content_type="video", duration_minutes=5, order=1),
                    Module(module_id="M-001-2", title="Common Phishing Tactics", content_type="article", duration_minutes=5, order=2),
                    Module(module_id="M-001-3", title="How to Report Phishing", content_type="article", duration_minutes=3, order=3),
                    Module(module_id="M-001-4", title="Phishing Identification Quiz", content_type="quiz", duration_minutes=7, order=4),
                ],
            ),
            TrainingCourse(
                course_id="CRS-SAT-002", title="Password Best Practices",
                description="Understand strong password creation, multi-factor authentication, and credential management.",
                category=CourseCategory.PASSWORD_SECURITY, difficulty=Difficulty.BEGINNER,
                duration_minutes=15, passing_score=80.0, is_mandatory=False,
                content_modules=[
                    Module(module_id="M-002-1", title="Password Strength Fundamentals", content_type="video", duration_minutes=5, order=1),
                    Module(module_id="M-002-2", title="Multi-Factor Authentication", content_type="article", duration_minutes=4, order=2),
                    Module(module_id="M-002-3", title="Password Manager Setup", content_type="interactive", duration_minutes=3, order=3),
                    Module(module_id="M-002-4", title="Knowledge Check", content_type="quiz", duration_minutes=3, order=4),
                ],
            ),
            TrainingCourse(
                course_id="CRS-SAT-003", title="Social Engineering Defense",
                description="Recognize and defend against social engineering attacks including pretexting, baiting, and tailgating.",
                category=CourseCategory.SOCIAL_ENGINEERING, difficulty=Difficulty.INTERMEDIATE,
                duration_minutes=30, passing_score=75.0, is_mandatory=False,
                content_modules=[
                    Module(module_id="M-003-1", title="Types of Social Engineering", content_type="video", duration_minutes=8, order=1),
                    Module(module_id="M-003-2", title="Real-World Case Studies", content_type="article", duration_minutes=7, order=2),
                    Module(module_id="M-003-3", title="Interactive Scenario Training", content_type="interactive", duration_minutes=10, order=3),
                    Module(module_id="M-003-4", title="Assessment", content_type="quiz", duration_minutes=5, order=4),
                ],
            ),
            TrainingCourse(
                course_id="CRS-SAT-004", title="Data Handling & Classification",
                description="Learn proper data handling procedures including classification, storage, and disposal of sensitive information.",
                category=CourseCategory.DATA_HANDLING, difficulty=Difficulty.INTERMEDIATE,
                duration_minutes=25, passing_score=80.0, is_mandatory=False,
                content_modules=[
                    Module(module_id="M-004-1", title="Data Classification Levels", content_type="article", duration_minutes=5, order=1),
                    Module(module_id="M-004-2", title="Handling Sensitive Data", content_type="video", duration_minutes=8, order=2),
                    Module(module_id="M-004-3", title="Secure Disposal Methods", content_type="article", duration_minutes=5, order=3),
                    Module(module_id="M-004-4", title="Classification Exercise", content_type="interactive", duration_minutes=7, order=4),
                ],
            ),
            TrainingCourse(
                course_id="CRS-SAT-005", title="Incident Reporting Procedures",
                description="Understand when and how to report security incidents, suspicious activity, and policy violations.",
                category=CourseCategory.INCIDENT_REPORTING, difficulty=Difficulty.BEGINNER,
                duration_minutes=10, passing_score=85.0, is_mandatory=False,
                content_modules=[
                    Module(module_id="M-005-1", title="What Counts as an Incident?", content_type="video", duration_minutes=3, order=1),
                    Module(module_id="M-005-2", title="Reporting Steps", content_type="article", duration_minutes=3, order=2),
                    Module(module_id="M-005-3", title="Practice Scenarios", content_type="quiz", duration_minutes=4, order=3),
                ],
            ),
        ]
        for c in defaults:
            if self._use_db:
                existing = self.db.query(TrainingCourseModel).filter_by(
                    course_id=c.course_id
                ).first()
                if not existing:
                    self.db.add(TrainingCourseModel(
                        course_id=c.course_id, title=c.title, description=c.description,
                        category=c.category.value if isinstance(c.category, Enum) else c.category,
                        difficulty=c.difficulty.value if isinstance(c.difficulty, Enum) else c.difficulty,
                        duration_minutes=c.duration_minutes,
                        content_modules=[{"module_id": m.module_id, "title": m.title, "content_type": m.content_type,
                                          "content_url": m.content_url, "duration_minutes": m.duration_minutes,
                                          "order": m.order} for m in c.content_modules],
                        passing_score=c.passing_score, is_mandatory=c.is_mandatory,
                    ))
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
            self._courses[c.course_id] = c

    # ------------------------------------------------------------------
    # Course Management
    # ------------------------------------------------------------------

    def create_course(
        self, title: str, description: str = "", category: str = "phishing_awareness",
        difficulty: str = "beginner", duration_minutes: int = 15,
        content_modules: Optional[List[Dict]] = None, passing_score: float = 80.0,
        is_mandatory: bool = False,
    ) -> TrainingCourse:
        """Create a new training course."""
        course_id = f"CRS-{uuid.uuid4().hex[:8].upper()}"
        modules = []
        for i, m in enumerate(content_modules or []):
            modules.append(Module(
                module_id=m.get("module_id", f"M-{uuid.uuid4().hex[:6]}"),
                title=m.get("title", ""), content_type=m.get("content_type", "article"),
                content_url=m.get("content_url", ""), duration_minutes=m.get("duration_minutes", 5),
                order=m.get("order", i + 1),
            ))
        course = TrainingCourse(
            course_id=course_id, title=title, description=description,
            category=CourseCategory(category), difficulty=Difficulty(difficulty),
            duration_minutes=duration_minutes, content_modules=modules,
            passing_score=passing_score, is_mandatory=is_mandatory,
        )
        if self._use_db:
            self.db.add(TrainingCourseModel(
                course_id=course_id, title=title, description=description,
                category=category, difficulty=difficulty, duration_minutes=duration_minutes,
                content_modules=[{"module_id": m.module_id, "title": m.title, "content_type": m.content_type,
                                  "content_url": m.content_url, "duration_minutes": m.duration_minutes,
                                  "order": m.order} for m in modules],
                passing_score=passing_score, is_mandatory=is_mandatory,
            ))
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()
        self._courses[course_id] = course
        logger.info("Created training course %s: %s", course_id, title)
        return course

    def get_course(self, course_id: str) -> Optional[TrainingCourse]:
        """Retrieve a course by ID."""
        if course_id in self._courses:
            return self._courses[course_id]
        if self._use_db:
            row = self.db.query(TrainingCourseModel).filter_by(course_id=course_id).first()
            if row:
                return self._row_to_course(row)
        return None

    def list_courses(self, category: Optional[str] = None, mandatory_only: bool = False) -> List[TrainingCourse]:
        """List courses with optional filters."""
        courses = list(self._courses.values())
        if category:
            courses = [c for c in courses if (c.category.value if isinstance(c.category, Enum) else c.category) == category]
        if mandatory_only:
            courses = [c for c in courses if c.is_mandatory]
        return courses

    def update_course(self, course_id: str, **kwargs) -> Optional[TrainingCourse]:
        """Update course fields."""
        course = self.get_course(course_id)
        if not course:
            return None
        for key, value in kwargs.items():
            if hasattr(course, key) and value is not None:
                setattr(course, key, value)
        course.updated_at = datetime.now(timezone.utc)
        self._courses[course_id] = course
        if self._use_db:
            row = self.db.query(TrainingCourseModel).filter_by(course_id=course_id).first()
            if row:
                for key, value in kwargs.items():
                    if hasattr(row, key) and value is not None:
                        val = value.value if isinstance(value, Enum) else value
                        setattr(row, key, val)
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
        return course

    # ------------------------------------------------------------------
    # Assignment Management
    # ------------------------------------------------------------------

    def assign_training(
        self, client_id: str, course_id: str,
        users: List[Dict[str, str]], due_date: Optional[datetime] = None,
    ) -> List[TrainingAssignment]:
        """Assign a training course to a list of users."""
        assignments = []
        for user in users:
            assignment_id = f"TA-{uuid.uuid4().hex[:8].upper()}"
            a = TrainingAssignment(
                assignment_id=assignment_id, client_id=client_id, course_id=course_id,
                user_email=user.get("email", ""), user_name=user.get("name", ""),
                due_date=due_date,
            )
            if self._use_db:
                self.db.add(TrainingAssignmentModel(
                    assignment_id=assignment_id, client_id=client_id, course_id=course_id,
                    user_email=a.user_email, user_name=a.user_name,
                    due_date=due_date,
                ))
            self._assignments[assignment_id] = a
            assignments.append(a)
        if self._use_db:
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()
        logger.info("Assigned course %s to %d users for client %s", course_id, len(users), client_id)
        return assignments

    def start_training(self, assignment_id: str) -> Optional[TrainingAssignment]:
        """Mark training as in-progress."""
        a = self._assignments.get(assignment_id)
        if not a:
            return None
        a.status = AssignmentStatus.IN_PROGRESS
        a.started_at = datetime.now(timezone.utc)
        a.attempts += 1
        if self._use_db:
            row = self.db.query(TrainingAssignmentModel).filter_by(assignment_id=assignment_id).first()
            if row:
                row.status = "in_progress"
                row.started_at = a.started_at
                row.attempts = a.attempts
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
        return a

    def complete_training(self, assignment_id: str, score: float) -> Optional[TrainingAssignment]:
        """Complete a training assignment with a score."""
        a = self._assignments.get(assignment_id)
        if not a:
            return None
        course = self.get_course(a.course_id)
        a.score = score
        a.completed_at = datetime.now(timezone.utc)
        a.status = AssignmentStatus.COMPLETED if (course and score >= course.passing_score) else AssignmentStatus.IN_PROGRESS
        if a.status == AssignmentStatus.COMPLETED:
            a.certificate_id = f"CERT-{uuid.uuid4().hex[:8].upper()}"
        if self._use_db:
            row = self.db.query(TrainingAssignmentModel).filter_by(assignment_id=assignment_id).first()
            if row:
                row.status = a.status.value
                row.score = score
                row.completed_at = a.completed_at
                row.certificate_id = a.certificate_id
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
        return a

    def get_assignments(
        self, client_id: Optional[str] = None, course_id: Optional[str] = None,
        user_email: Optional[str] = None, status: Optional[str] = None,
    ) -> List[TrainingAssignment]:
        """Get assignments with optional filters."""
        result = list(self._assignments.values())
        if client_id:
            result = [a for a in result if a.client_id == client_id]
        if course_id:
            result = [a for a in result if a.course_id == course_id]
        if user_email:
            result = [a for a in result if a.user_email == user_email]
        if status:
            result = [a for a in result if (a.status.value if isinstance(a.status, Enum) else a.status) == status]
        return result

    def get_overdue_assignments(self, client_id: Optional[str] = None) -> List[TrainingAssignment]:
        """Get all overdue assignments (past due_date and not completed)."""
        now = datetime.now(timezone.utc)
        result = []
        for a in self._assignments.values():
            if a.due_date and a.due_date < now and a.status not in (AssignmentStatus.COMPLETED, AssignmentStatus.EXEMPTED):
                if client_id and a.client_id != client_id:
                    continue
                a.status = AssignmentStatus.OVERDUE
                result.append(a)
        return result

    # ------------------------------------------------------------------
    # Phishing Template Management
    # ------------------------------------------------------------------

    def create_template(
        self, name: str, category: str = "credential_harvest", subject: str = "",
        sender_name: str = "", sender_email: str = "", body_html: str = "",
        landing_page_html: str = "", difficulty: str = "medium", brand_impersonated: str = "",
    ) -> PhishingTemplate:
        """Create a custom phishing template."""
        template_id = f"TPL-{uuid.uuid4().hex[:8].upper()}"
        t = PhishingTemplate(
            template_id=template_id, name=name, category=PhishCategory(category),
            subject=subject, sender_name=sender_name, sender_email=sender_email,
            body_html=body_html, landing_page_html=landing_page_html,
            difficulty=difficulty, brand_impersonated=brand_impersonated,
        )
        if self._use_db:
            self.db.add(PhishingTemplateModel(
                template_id=template_id, name=name, category=category,
                subject=subject, sender_name=sender_name, sender_email=sender_email,
                body_html=body_html, landing_page_html=landing_page_html,
                difficulty=difficulty, brand_impersonated=brand_impersonated,
            ))
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()
        self._templates[template_id] = t
        logger.info("Created phishing template %s: %s", template_id, name)
        return t

    def list_templates(self, category: Optional[str] = None) -> List[PhishingTemplate]:
        """List phishing templates."""
        templates = list(self._templates.values())
        if category:
            templates = [t for t in templates if (t.category.value if isinstance(t.category, Enum) else t.category) == category]
        return templates

    def get_template(self, template_id: str) -> Optional[PhishingTemplate]:
        """Get a template by ID."""
        return self._templates.get(template_id)

    # ------------------------------------------------------------------
    # Phishing Campaign Management
    # ------------------------------------------------------------------

    def create_campaign(
        self, client_id: str, name: str, template_id: str,
        target_users: Optional[List[Dict[str, str]]] = None,
    ) -> PhishingCampaign:
        """Create a new phishing campaign."""
        campaign_id = f"PC-{uuid.uuid4().hex[:8].upper()}"
        c = PhishingCampaign(
            campaign_id=campaign_id, client_id=client_id, name=name,
            template_id=template_id, target_users=target_users or [],
        )
        if self._use_db:
            self.db.add(PhishingCampaignModel(
                campaign_id=campaign_id, client_id=client_id, name=name,
                template_id=template_id, target_users=target_users or [],
            ))
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()
        self._campaigns[campaign_id] = c
        logger.info("Created phishing campaign %s: %s", campaign_id, name)
        return c

    def schedule_campaign(self, campaign_id: str, scheduled_at: datetime) -> Optional[PhishingCampaign]:
        """Schedule a campaign for future launch."""
        c = self._campaigns.get(campaign_id)
        if not c:
            return None
        c.status = CampaignStatus.SCHEDULED
        c.scheduled_at = scheduled_at
        if self._use_db:
            row = self.db.query(PhishingCampaignModel).filter_by(campaign_id=campaign_id).first()
            if row:
                row.status = "scheduled"
                row.scheduled_at = scheduled_at
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
        return c

    def start_campaign(self, campaign_id: str) -> Optional[PhishingCampaign]:
        """Start a campaign and simulate sending."""
        c = self._campaigns.get(campaign_id)
        if not c:
            return None
        c.status = CampaignStatus.RUNNING
        c.started_at = datetime.now(timezone.utc)
        self._simulate_campaign(campaign_id)
        if self._use_db:
            row = self.db.query(PhishingCampaignModel).filter_by(campaign_id=campaign_id).first()
            if row:
                row.status = "running"
                row.started_at = c.started_at
                row.emails_sent = c.emails_sent
                row.emails_opened = c.emails_opened
                row.links_clicked = c.links_clicked
                row.credentials_submitted = c.credentials_submitted
                row.reported_count = c.reported_count
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()
        return c

    def get_campaign(self, campaign_id: str) -> Optional[PhishingCampaign]:
        """Get campaign by ID."""
        return self._campaigns.get(campaign_id)

    def list_campaigns(self, client_id: Optional[str] = None, status: Optional[str] = None) -> List[PhishingCampaign]:
        """List campaigns with optional filters."""
        result = list(self._campaigns.values())
        if client_id:
            result = [c for c in result if c.client_id == client_id]
        if status:
            result = [c for c in result if (c.status.value if isinstance(c.status, Enum) else c.status) == status]
        return result

    def _simulate_campaign(self, campaign_id: str) -> None:
        """Simulate email sends and user interactions for a campaign."""
        c = self._campaigns.get(campaign_id)
        if not c or not c.target_users:
            return
        template = self.get_template(c.template_id)
        diff_factor = {"low": 0.6, "medium": 0.4, "high": 0.25}.get(
            template.difficulty if template else "medium", 0.4
        )
        for user in c.target_users:
            email = user.get("email", "")
            # Every target gets sent
            self._record_event(campaign_id, email, PhishEventType.SENT)
            c.emails_sent += 1
            # Simulate open (70-90% open rate)
            if random.random() < random.uniform(0.7, 0.9):
                self._record_event(campaign_id, email, PhishEventType.OPENED)
                c.emails_opened += 1
                # Simulate click based on difficulty
                if random.random() < diff_factor:
                    self._record_event(campaign_id, email, PhishEventType.CLICKED)
                    c.links_clicked += 1
                    # Simulate credential submission (subset of clickers)
                    if random.random() < 0.5:
                        self._record_event(campaign_id, email, PhishEventType.SUBMITTED)
                        c.credentials_submitted += 1
                # Simulate report (good security awareness)
                if random.random() < 0.15:
                    self._record_event(campaign_id, email, PhishEventType.REPORTED)
                    c.reported_count += 1

    def _record_event(self, campaign_id: str, user_email: str, event_type: PhishEventType) -> PhishingEvent:
        """Internal event recording."""
        event = PhishingEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
            campaign_id=campaign_id, user_email=user_email, event_type=event_type,
        )
        self._events.append(event)
        if self._use_db:
            self.db.add(PhishingEventModel(
                event_id=event.event_id, campaign_id=campaign_id,
                user_email=user_email, event_type=event_type.value,
            ))
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()
        return event

    def record_phish_event(
        self, campaign_id: str, user_email: str, event_type: str,
    ) -> Optional[PhishingEvent]:
        """Public method to record a phishing event (open/click/submit/report)."""
        c = self._campaigns.get(campaign_id)
        if not c:
            return None
        et = PhishEventType(event_type)
        event = self._record_event(campaign_id, user_email, et)
        if et == PhishEventType.OPENED:
            c.emails_opened += 1
        elif et == PhishEventType.CLICKED:
            c.links_clicked += 1
        elif et == PhishEventType.SUBMITTED:
            c.credentials_submitted += 1
        elif et == PhishEventType.REPORTED:
            c.reported_count += 1
        return event

    # ------------------------------------------------------------------
    # User Risk Scoring
    # ------------------------------------------------------------------

    def calculate_user_risk(self, email: str, client_id: str = "") -> UserRiskScore:
        """Calculate a user's security risk score based on phishing and training history."""
        # Count phishing failures / reports
        phish_fails = sum(
            1 for e in self._events
            if e.user_email == email and e.event_type in (PhishEventType.CLICKED, PhishEventType.SUBMITTED)
        )
        phish_reports = sum(
            1 for e in self._events
            if e.user_email == email and e.event_type == PhishEventType.REPORTED
        )
        # Count training stats
        user_assignments = [a for a in self._assignments.values() if a.user_email == email]
        training_completed = sum(1 for a in user_assignments if a.status == AssignmentStatus.COMPLETED)
        training_overdue = sum(1 for a in user_assignments if a.status == AssignmentStatus.OVERDUE or
                               (a.due_date and a.due_date < datetime.now(timezone.utc) and
                                a.status not in (AssignmentStatus.COMPLETED, AssignmentStatus.EXEMPTED)))

        # Risk formula: base 50, +15 per fail, -10 per report, -5 per completed, +10 per overdue
        risk = 50 + (phish_fails * 15) - (phish_reports * 10) - (training_completed * 5) + (training_overdue * 10)
        risk = max(0, min(100, risk))

        last_phish = None
        phish_events_for_user = [e for e in self._events if e.user_email == email]
        if phish_events_for_user:
            last_phish = max(e.timestamp for e in phish_events_for_user)
        last_train = None
        completed_assigns = [a for a in user_assignments if a.completed_at]
        if completed_assigns:
            last_train = max(a.completed_at for a in completed_assigns)

        user_id = f"USR-{uuid.uuid4().hex[:8].upper()}" if email not in self._user_risks else self._user_risks[email].user_id
        ur = UserRiskScore(
            user_id=user_id, client_id=client_id, email=email,
            phishing_fail_count=phish_fails, phishing_report_count=phish_reports,
            training_completed_count=training_completed, training_overdue_count=training_overdue,
            risk_score=risk, last_phish_test=last_phish, last_training=last_train,
        )
        self._user_risks[email] = ur

        if self._use_db:
            row = self.db.query(UserRiskScoreModel).filter_by(email=email).first()
            if row:
                row.phishing_fail_count = phish_fails
                row.phishing_report_count = phish_reports
                row.training_completed_count = training_completed
                row.training_overdue_count = training_overdue
                row.risk_score = risk
                row.last_phish_test = last_phish
                row.last_training = last_train
            else:
                self.db.add(UserRiskScoreModel(
                    user_id=ur.user_id, client_id=client_id, email=email,
                    phishing_fail_count=phish_fails, phishing_report_count=phish_reports,
                    training_completed_count=training_completed, training_overdue_count=training_overdue,
                    risk_score=risk, last_phish_test=last_phish, last_training=last_train,
                ))
            try:
                self.db.commit()
            except Exception:
                self.db.rollback()
        return ur

    def get_user_risks(self, client_id: str) -> List[UserRiskScore]:
        """Get all user risk scores for a client."""
        return [ur for ur in self._user_risks.values() if ur.client_id == client_id]

    def get_highest_risk_users(self, client_id: str, limit: int = 10) -> List[UserRiskScore]:
        """Get users with the highest risk scores."""
        users = self.get_user_risks(client_id)
        users.sort(key=lambda u: u.risk_score, reverse=True)
        return users[:limit]

    # ------------------------------------------------------------------
    # Compliance & Analytics
    # ------------------------------------------------------------------

    def get_training_compliance(self, client_id: str) -> Dict[str, Any]:
        """Get training compliance percentages by course."""
        client_assignments = [a for a in self._assignments.values() if a.client_id == client_id]
        if not client_assignments:
            return {"client_id": client_id, "courses": [], "overall_completion_rate": 0.0}

        courses_data = {}
        for a in client_assignments:
            if a.course_id not in courses_data:
                course = self.get_course(a.course_id)
                courses_data[a.course_id] = {
                    "course_id": a.course_id,
                    "title": course.title if course else a.course_id,
                    "total": 0, "completed": 0, "in_progress": 0, "overdue": 0,
                }
            courses_data[a.course_id]["total"] += 1
            if a.status == AssignmentStatus.COMPLETED:
                courses_data[a.course_id]["completed"] += 1
            elif a.status == AssignmentStatus.IN_PROGRESS:
                courses_data[a.course_id]["in_progress"] += 1
            elif a.status == AssignmentStatus.OVERDUE or (a.due_date and a.due_date < datetime.now(timezone.utc) and a.status != AssignmentStatus.COMPLETED):
                courses_data[a.course_id]["overdue"] += 1

        for cd in courses_data.values():
            cd["completion_rate"] = round((cd["completed"] / cd["total"]) * 100, 1) if cd["total"] else 0.0

        total = len(client_assignments)
        completed = sum(1 for a in client_assignments if a.status == AssignmentStatus.COMPLETED)
        return {
            "client_id": client_id,
            "courses": list(courses_data.values()),
            "overall_completion_rate": round((completed / total) * 100, 1) if total else 0.0,
        }

    def get_phishing_trends(self, client_id: str, periods: int = 6) -> List[Dict[str, Any]]:
        """Get phishing simulation trends over recent periods (months)."""
        now = datetime.now(timezone.utc)
        trends = []
        for i in range(periods):
            period_start = now - timedelta(days=30 * (i + 1))
            period_end = now - timedelta(days=30 * i)
            client_campaigns = [c for c in self._campaigns.values() if c.client_id == client_id]
            period_campaigns = [
                c for c in client_campaigns
                if c.started_at and period_start <= c.started_at < period_end
            ]
            sent = sum(c.emails_sent for c in period_campaigns)
            clicked = sum(c.links_clicked for c in period_campaigns)
            reported = sum(c.reported_count for c in period_campaigns)
            trends.append({
                "period": period_end.strftime("%Y-%m"),
                "campaigns": len(period_campaigns),
                "emails_sent": sent,
                "click_rate": round((clicked / sent) * 100, 1) if sent else 0.0,
                "report_rate": round((reported / sent) * 100, 1) if sent else 0.0,
            })
        trends.reverse()
        return trends

    def get_click_rate_by_template(self) -> List[Dict[str, Any]]:
        """Get click rates grouped by phishing template."""
        template_stats: Dict[str, Dict[str, int]] = {}
        for c in self._campaigns.values():
            if c.template_id not in template_stats:
                tpl = self.get_template(c.template_id)
                template_stats[c.template_id] = {
                    "template_id": c.template_id,
                    "name": tpl.name if tpl else c.template_id,
                    "sent": 0, "clicked": 0,
                }
            template_stats[c.template_id]["sent"] += c.emails_sent
            template_stats[c.template_id]["clicked"] += c.links_clicked
        result = []
        for ts in template_stats.values():
            ts["click_rate"] = round((ts["clicked"] / ts["sent"]) * 100, 1) if ts["sent"] else 0.0
            result.append(ts)
        result.sort(key=lambda x: x["click_rate"], reverse=True)
        return result

    def get_improvement_over_time(self, client_id: str) -> Dict[str, Any]:
        """Measure improvement: compare first-half vs second-half campaign click rates."""
        client_campaigns = sorted(
            [c for c in self._campaigns.values() if c.client_id == client_id and c.started_at],
            key=lambda c: c.started_at,
        )
        if len(client_campaigns) < 2:
            return {"client_id": client_id, "improvement_pct": 0.0, "data_points": len(client_campaigns)}

        mid = len(client_campaigns) // 2
        first_half = client_campaigns[:mid]
        second_half = client_campaigns[mid:]

        def _click_rate(campaigns):
            sent = sum(c.emails_sent for c in campaigns)
            clicked = sum(c.links_clicked for c in campaigns)
            return (clicked / sent) * 100 if sent else 0.0

        first_rate = _click_rate(first_half)
        second_rate = _click_rate(second_half)
        improvement = first_rate - second_rate  # positive = improvement (fewer clicks)

        return {
            "client_id": client_id,
            "first_period_click_rate": round(first_rate, 1),
            "second_period_click_rate": round(second_rate, 1),
            "improvement_pct": round(improvement, 1),
            "data_points": len(client_campaigns),
        }

    def get_dashboard(self, client_id: str) -> Dict[str, Any]:
        """Get a consolidated dashboard for a client."""
        compliance = self.get_training_compliance(client_id)
        active_campaigns = [c for c in self._campaigns.values()
                           if c.client_id == client_id and c.status in (CampaignStatus.RUNNING, CampaignStatus.SCHEDULED)]
        overdue = self.get_overdue_assignments(client_id)
        risks = self.get_user_risks(client_id)

        # Risk distribution
        risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for ur in risks:
            if ur.risk_score < 30:
                risk_dist["low"] += 1
            elif ur.risk_score < 60:
                risk_dist["medium"] += 1
            elif ur.risk_score < 80:
                risk_dist["high"] += 1
            else:
                risk_dist["critical"] += 1

        return {
            "client_id": client_id,
            "compliance_rate": compliance.get("overall_completion_rate", 0.0),
            "active_campaigns": len(active_campaigns),
            "overdue_assignments": len(overdue),
            "total_users_tracked": len(risks),
            "risk_distribution": risk_dist,
            "highest_risk_users": [
                {"email": u.email, "risk_score": u.risk_score}
                for u in self.get_highest_risk_users(client_id, 5)
            ],
            "course_compliance": compliance.get("courses", []),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_course(row) -> TrainingCourse:
        """Convert DB row to TrainingCourse dataclass."""
        modules = []
        for m in (row.content_modules or []):
            modules.append(Module(
                module_id=m.get("module_id", ""), title=m.get("title", ""),
                content_type=m.get("content_type", "article"),
                content_url=m.get("content_url", ""),
                duration_minutes=m.get("duration_minutes", 5),
                order=m.get("order", 0),
            ))
        return TrainingCourse(
            course_id=row.course_id, title=row.title, description=row.description or "",
            category=CourseCategory(row.category) if row.category else CourseCategory.PHISHING_AWARENESS,
            difficulty=Difficulty(row.difficulty) if row.difficulty else Difficulty.BEGINNER,
            duration_minutes=row.duration_minutes or 15,
            content_modules=modules, passing_score=row.passing_score or 80.0,
            is_mandatory=row.is_mandatory or False,
            created_at=row.created_at or datetime.now(timezone.utc),
        )
