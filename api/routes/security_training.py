"""
API Routes for Security Awareness Training & Phishing Simulation
Uses SecurityTrainingService for all operations
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

from core.database import get_sync_db
from services.msp.security_training import (
    SecurityTrainingService,
    CourseCategory,
    CampaignStatus,
    PhishCategory,
    AssignmentStatus,
    Difficulty,
    PhishEventType,
)

router = APIRouter(prefix="/security-training", tags=["Security Training"])


def _init_service() -> SecurityTrainingService:
    """Initialize SecurityTrainingService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return SecurityTrainingService(db=db)
    except Exception:
        return SecurityTrainingService()


service = _init_service()


# ========== Request/Response Models ==========

class ModuleModel(BaseModel):
    module_id: Optional[str] = None
    title: str = ""
    content_type: str = "article"
    content_url: str = ""
    duration_minutes: int = 5
    order: int = 0


class CourseCreate(BaseModel):
    title: str
    description: str = ""
    category: str = "phishing_awareness"
    difficulty: str = "beginner"
    duration_minutes: int = 15
    content_modules: List[ModuleModel] = []
    passing_score: float = 80.0
    is_mandatory: bool = False


class CourseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    duration_minutes: Optional[int] = None
    passing_score: Optional[float] = None
    is_mandatory: Optional[bool] = None


class UserRef(BaseModel):
    email: str
    name: str = ""


class AssignTrainingRequest(BaseModel):
    client_id: str
    course_id: str
    users: List[UserRef]
    due_date: Optional[datetime] = None


class CompleteTrainingRequest(BaseModel):
    score: float


class TemplateCreate(BaseModel):
    name: str
    category: str = "credential_harvest"
    subject: str = ""
    sender_name: str = ""
    sender_email: str = ""
    body_html: str = ""
    landing_page_html: str = ""
    difficulty: str = "medium"
    brand_impersonated: str = ""


class CampaignCreate(BaseModel):
    client_id: str
    name: str
    template_id: str
    target_users: List[UserRef] = []


class ScheduleCampaignRequest(BaseModel):
    scheduled_at: datetime


class PhishEventRequest(BaseModel):
    user_email: str
    event_type: str  # opened/clicked/submitted/reported


# ========== Course Endpoints ==========

@router.post("/courses")
async def create_course(data: CourseCreate):
    """Create a new training course."""
    course = service.create_course(
        title=data.title, description=data.description, category=data.category,
        difficulty=data.difficulty, duration_minutes=data.duration_minutes,
        content_modules=[m.dict() for m in data.content_modules],
        passing_score=data.passing_score, is_mandatory=data.is_mandatory,
    )
    return _serialize_course(course)


@router.get("/courses")
async def list_courses(
    category: Optional[str] = Query(None),
    mandatory_only: bool = Query(False),
):
    """List training courses with optional filters."""
    courses = service.list_courses(category=category, mandatory_only=mandatory_only)
    return [_serialize_course(c) for c in courses]


@router.get("/courses/{course_id}")
async def get_course(course_id: str):
    """Get a course by ID."""
    course = service.get_course(course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return _serialize_course(course)


@router.put("/courses/{course_id}")
async def update_course(course_id: str, data: CourseUpdate):
    """Update a training course."""
    updates = {k: v for k, v in data.dict().items() if v is not None}
    course = service.update_course(course_id, **updates)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return _serialize_course(course)


# ========== Assignment Endpoints ==========

@router.post("/assignments")
async def assign_training(data: AssignTrainingRequest):
    """Assign a training course to users."""
    assignments = service.assign_training(
        client_id=data.client_id, course_id=data.course_id,
        users=[u.dict() for u in data.users], due_date=data.due_date,
    )
    return [_serialize_assignment(a) for a in assignments]


@router.post("/assignments/{assignment_id}/start")
async def start_training(assignment_id: str):
    """Mark training assignment as in-progress."""
    a = service.start_training(assignment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assignment not found")
    return _serialize_assignment(a)


@router.post("/assignments/{assignment_id}/complete")
async def complete_training(assignment_id: str, data: CompleteTrainingRequest):
    """Complete a training assignment with score."""
    a = service.complete_training(assignment_id, data.score)
    if not a:
        raise HTTPException(status_code=404, detail="Assignment not found")
    return _serialize_assignment(a)


@router.get("/assignments")
async def get_assignments(
    client_id: Optional[str] = Query(None),
    course_id: Optional[str] = Query(None),
    user_email: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List training assignments with filters."""
    assignments = service.get_assignments(
        client_id=client_id, course_id=course_id,
        user_email=user_email, status=status,
    )
    return [_serialize_assignment(a) for a in assignments]


@router.get("/assignments/overdue")
async def get_overdue_assignments(client_id: Optional[str] = Query(None)):
    """Get all overdue training assignments."""
    assignments = service.get_overdue_assignments(client_id=client_id)
    return [_serialize_assignment(a) for a in assignments]


# ========== Template Endpoints ==========

@router.post("/templates")
async def create_template(data: TemplateCreate):
    """Create a custom phishing template."""
    t = service.create_template(
        name=data.name, category=data.category, subject=data.subject,
        sender_name=data.sender_name, sender_email=data.sender_email,
        body_html=data.body_html, landing_page_html=data.landing_page_html,
        difficulty=data.difficulty, brand_impersonated=data.brand_impersonated,
    )
    return _serialize_template(t)


@router.get("/templates")
async def list_templates(category: Optional[str] = Query(None)):
    """List phishing templates."""
    templates = service.list_templates(category=category)
    return [_serialize_template(t) for t in templates]


@router.get("/templates/{template_id}")
async def get_template(template_id: str):
    """Get a phishing template by ID."""
    t = service.get_template(template_id)
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    return _serialize_template(t)


# ========== Campaign Endpoints ==========

@router.post("/campaigns")
async def create_campaign(data: CampaignCreate):
    """Create a new phishing campaign."""
    c = service.create_campaign(
        client_id=data.client_id, name=data.name, template_id=data.template_id,
        target_users=[u.dict() for u in data.target_users],
    )
    return _serialize_campaign(c)


@router.post("/campaigns/{campaign_id}/schedule")
async def schedule_campaign(campaign_id: str, data: ScheduleCampaignRequest):
    """Schedule a campaign for future execution."""
    c = service.schedule_campaign(campaign_id, data.scheduled_at)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return _serialize_campaign(c)


@router.post("/campaigns/{campaign_id}/start")
async def start_campaign(campaign_id: str):
    """Start a phishing campaign (simulates sends)."""
    c = service.start_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return _serialize_campaign(c)


@router.get("/campaigns")
async def list_campaigns(
    client_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List phishing campaigns."""
    campaigns = service.list_campaigns(client_id=client_id, status=status)
    return [_serialize_campaign(c) for c in campaigns]


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Get campaign details."""
    c = service.get_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return _serialize_campaign(c)


@router.post("/campaigns/{campaign_id}/events")
async def record_phish_event(campaign_id: str, data: PhishEventRequest):
    """Record a phishing event (open/click/submit/report)."""
    event = service.record_phish_event(campaign_id, data.user_email, data.event_type)
    if not event:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {
        "event_id": event.event_id, "campaign_id": event.campaign_id,
        "user_email": event.user_email, "event_type": event.event_type.value if hasattr(event.event_type, 'value') else event.event_type,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
    }


# ========== Risk Endpoints ==========

@router.get("/risk/{email}")
async def calculate_user_risk(email: str, client_id: str = Query("")):
    """Calculate and return a user's risk score."""
    ur = service.calculate_user_risk(email, client_id)
    return _serialize_risk(ur)


@router.get("/risk")
async def get_user_risks(client_id: str = Query(...)):
    """Get all user risk scores for a client."""
    risks = service.get_user_risks(client_id)
    return [_serialize_risk(r) for r in risks]


@router.get("/risk/highest/{client_id}")
async def get_highest_risk_users(client_id: str, limit: int = Query(10)):
    """Get users with the highest risk scores."""
    risks = service.get_highest_risk_users(client_id, limit)
    return [_serialize_risk(r) for r in risks]


# ========== Compliance & Analytics Endpoints ==========

@router.get("/compliance/{client_id}")
async def get_training_compliance(client_id: str):
    """Get training compliance report for a client."""
    return service.get_training_compliance(client_id)


@router.get("/analytics/phishing-trends/{client_id}")
async def get_phishing_trends(client_id: str, periods: int = Query(6)):
    """Get phishing simulation trends over time."""
    return service.get_phishing_trends(client_id, periods)


@router.get("/analytics/click-rate-by-template")
async def get_click_rate_by_template():
    """Get click rates grouped by phishing template."""
    return service.get_click_rate_by_template()


@router.get("/analytics/improvement/{client_id}")
async def get_improvement_over_time(client_id: str):
    """Measure click-rate improvement over time."""
    return service.get_improvement_over_time(client_id)


@router.get("/dashboard/{client_id}")
async def get_dashboard(client_id: str):
    """Get consolidated security training dashboard."""
    return service.get_dashboard(client_id)


# ========== Serializers ==========

def _serialize_course(c) -> dict:
    from enum import Enum
    return {
        "course_id": c.course_id,
        "title": c.title,
        "description": c.description,
        "category": c.category.value if isinstance(c.category, Enum) else c.category,
        "difficulty": c.difficulty.value if isinstance(c.difficulty, Enum) else c.difficulty,
        "duration_minutes": c.duration_minutes,
        "content_modules": [
            {"module_id": m.module_id, "title": m.title, "content_type": m.content_type,
             "content_url": m.content_url, "duration_minutes": m.duration_minutes, "order": m.order}
            for m in (c.content_modules or [])
        ],
        "passing_score": c.passing_score,
        "is_mandatory": c.is_mandatory,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


def _serialize_assignment(a) -> dict:
    from enum import Enum
    return {
        "assignment_id": a.assignment_id,
        "client_id": a.client_id,
        "course_id": a.course_id,
        "user_email": a.user_email,
        "user_name": a.user_name,
        "status": a.status.value if isinstance(a.status, Enum) else a.status,
        "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
        "due_date": a.due_date.isoformat() if a.due_date else None,
        "started_at": a.started_at.isoformat() if a.started_at else None,
        "completed_at": a.completed_at.isoformat() if a.completed_at else None,
        "score": a.score,
        "attempts": a.attempts,
        "certificate_id": a.certificate_id,
    }


def _serialize_template(t) -> dict:
    from enum import Enum
    return {
        "template_id": t.template_id,
        "name": t.name,
        "category": t.category.value if isinstance(t.category, Enum) else t.category,
        "subject": t.subject,
        "sender_name": t.sender_name,
        "sender_email": t.sender_email,
        "body_html": t.body_html,
        "landing_page_html": t.landing_page_html,
        "difficulty": t.difficulty,
        "brand_impersonated": t.brand_impersonated,
    }


def _serialize_campaign(c) -> dict:
    from enum import Enum
    return {
        "campaign_id": c.campaign_id,
        "client_id": c.client_id,
        "name": c.name,
        "template_id": c.template_id,
        "status": c.status.value if isinstance(c.status, Enum) else c.status,
        "target_users": c.target_users,
        "scheduled_at": c.scheduled_at.isoformat() if c.scheduled_at else None,
        "started_at": c.started_at.isoformat() if c.started_at else None,
        "completed_at": c.completed_at.isoformat() if c.completed_at else None,
        "emails_sent": c.emails_sent,
        "emails_opened": c.emails_opened,
        "links_clicked": c.links_clicked,
        "credentials_submitted": c.credentials_submitted,
        "reported_count": c.reported_count,
    }


def _serialize_risk(r) -> dict:
    return {
        "user_id": r.user_id,
        "client_id": r.client_id,
        "email": r.email,
        "name": r.name,
        "phishing_fail_count": r.phishing_fail_count,
        "phishing_report_count": r.phishing_report_count,
        "training_completed_count": r.training_completed_count,
        "training_overdue_count": r.training_overdue_count,
        "risk_score": r.risk_score,
        "last_phish_test": r.last_phish_test.isoformat() if r.last_phish_test else None,
        "last_training": r.last_training.isoformat() if r.last_training else None,
    }
