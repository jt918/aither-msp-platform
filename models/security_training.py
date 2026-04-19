"""
AITHER Platform - Security Awareness Training & Phishing Simulation Models

Tables for training courses, assignments, phishing campaigns/templates/events,
and user risk scores.
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON,
    Index,
)
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


# ============================================================
# Training Courses
# ============================================================

class TrainingCourseModel(Base):
    """Security awareness training course."""
    __tablename__ = "training_courses"

    id = Column(String(36), primary_key=True, default=_uuid)
    course_id = Column(String(30), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    category = Column(String(50), nullable=False, index=True)
    difficulty = Column(String(20), default="beginner")
    duration_minutes = Column(Integer, default=15)
    content_modules = Column(JSON, default=list)
    passing_score = Column(Float, default=80.0)
    is_mandatory = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Training Assignments
# ============================================================

class TrainingAssignmentModel(Base):
    """Training assignment linking user to course."""
    __tablename__ = "training_assignments"

    id = Column(String(36), primary_key=True, default=_uuid)
    assignment_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    course_id = Column(String(30), nullable=False, index=True)
    user_email = Column(String(300), nullable=False, index=True)
    user_name = Column(String(300), default="")
    status = Column(String(20), default="assigned", index=True)
    assigned_at = Column(DateTime, default=func.now())
    due_date = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    score = Column(Float, nullable=True)
    attempts = Column(Integer, default=0)
    certificate_id = Column(String(50), nullable=True)

    __table_args__ = (
        Index("ix_ta_client_status", "client_id", "status"),
        Index("ix_ta_course_status", "course_id", "status"),
    )


# ============================================================
# Phishing Campaigns
# ============================================================

class PhishingCampaignModel(Base):
    """Phishing simulation campaign."""
    __tablename__ = "phishing_campaigns"

    id = Column(String(36), primary_key=True, default=_uuid)
    campaign_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    name = Column(String(300), nullable=False)
    template_id = Column(String(30), nullable=False)
    status = Column(String(20), default="draft", index=True)
    target_users = Column(JSON, default=list)
    scheduled_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    emails_sent = Column(Integer, default=0)
    emails_opened = Column(Integer, default=0)
    links_clicked = Column(Integer, default=0)
    credentials_submitted = Column(Integer, default=0)
    reported_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())


# ============================================================
# Phishing Templates
# ============================================================

class PhishingTemplateModel(Base):
    """Pre-built or custom phishing email template."""
    __tablename__ = "phishing_templates"

    id = Column(String(36), primary_key=True, default=_uuid)
    template_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(300), nullable=False)
    category = Column(String(30), nullable=False, index=True)
    subject = Column(String(500), default="")
    sender_name = Column(String(200), default="")
    sender_email = Column(String(300), default="")
    body_html = Column(Text, default="")
    landing_page_html = Column(Text, default="")
    difficulty = Column(String(20), default="medium")
    brand_impersonated = Column(String(200), default="")
    created_at = Column(DateTime, default=func.now())


# ============================================================
# Phishing Events (tracking individual interactions)
# ============================================================

class PhishingEventModel(Base):
    """Individual phishing simulation event (open/click/submit/report)."""
    __tablename__ = "phishing_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    event_id = Column(String(30), unique=True, nullable=False, index=True)
    campaign_id = Column(String(30), nullable=False, index=True)
    user_email = Column(String(300), nullable=False, index=True)
    event_type = Column(String(30), nullable=False)  # sent/opened/clicked/submitted/reported
    timestamp = Column(DateTime, default=func.now())
    metadata = Column(JSON, default=dict)

    __table_args__ = (
        Index("ix_pe_campaign_type", "campaign_id", "event_type"),
    )


# ============================================================
# User Risk Scores
# ============================================================

class UserRiskScoreModel(Base):
    """Aggregated security risk score per user."""
    __tablename__ = "user_risk_scores"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(50), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    email = Column(String(300), nullable=False, index=True)
    name = Column(String(300), default="")
    phishing_fail_count = Column(Integer, default=0)
    phishing_report_count = Column(Integer, default=0)
    training_completed_count = Column(Integer, default=0)
    training_overdue_count = Column(Integer, default=0)
    risk_score = Column(Float, default=50.0)
    last_phish_test = Column(DateTime, nullable=True)
    last_training = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
