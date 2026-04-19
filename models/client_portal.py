"""
AITHER Platform - Client Portal Persistence Models

Tables for MSP client portal: portal clients, portal users,
reports, service requests, announcements, and satisfaction surveys.
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
# Portal Client
# ============================================================

class PortalClientModel(Base):
    """MSP client registered for portal access."""
    __tablename__ = "portal_clients"

    id = Column(String(36), primary_key=True, default=_uuid)
    client_id = Column(String(30), unique=True, nullable=False, index=True)
    company_name = Column(String(300), nullable=False, index=True)
    primary_contact_email = Column(String(200), nullable=False)
    primary_contact_name = Column(String(200), nullable=False)
    plan_id = Column(String(50), default="", index=True)
    endpoints_count = Column(Integer, default=0)
    users_count = Column(Integer, default=0)
    portal_enabled = Column(Boolean, default=True, index=True)
    portal_theme = Column(String(30), default="")  # brand_id reference
    is_active = Column(Boolean, default=True, index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Portal User
# ============================================================

class PortalUserModel(Base):
    """User with access to the client portal."""
    __tablename__ = "portal_users"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(30), nullable=False, index=True)
    email = Column(String(200), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    role = Column(String(20), default="viewer", index=True)  # admin, viewer, requester
    permissions = Column(JSON, default=list)
    last_login = Column(DateTime, nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True, index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Portal Report
# ============================================================

class PortalReportModel(Base):
    """Generated report for a client."""
    __tablename__ = "portal_reports"

    id = Column(String(36), primary_key=True, default=_uuid)
    report_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(30), nullable=False, index=True)
    report_type = Column(String(30), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    generated_at = Column(DateTime, default=func.now())
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)
    data = Column(JSON, default=dict)
    is_published = Column(Boolean, default=False, index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Service Request
# ============================================================

class ServiceRequestModel(Base):
    """Service request from a portal client."""
    __tablename__ = "portal_service_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    request_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(30), nullable=False, index=True)
    user_id = Column(String(30), nullable=False, index=True)
    request_type = Column(String(30), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(String(20), default="medium", index=True)
    status = Column(String(20), default="submitted", index=True)
    submitted_at = Column(DateTime, default=func.now())
    approved_by = Column(String(200), nullable=True)
    completed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Announcement
# ============================================================

class AnnouncementModel(Base):
    """Announcement pushed to portal clients."""
    __tablename__ = "portal_announcements"

    id = Column(String(36), primary_key=True, default=_uuid)
    announcement_id = Column(String(30), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    body = Column(Text, nullable=True)
    severity = Column(String(20), default="info", index=True)
    target_clients = Column(JSON, default=list)  # list of client_ids or ["all"]
    published_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)
    read_by = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Satisfaction Survey
# ============================================================

class SatisfactionSurveyModel(Base):
    """Post-ticket satisfaction survey."""
    __tablename__ = "portal_satisfaction_surveys"

    id = Column(String(36), primary_key=True, default=_uuid)
    survey_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(30), nullable=False, index=True)
    ticket_id = Column(String(30), nullable=False, index=True)
    rating = Column(Integer, nullable=False)  # 1-5
    comments = Column(Text, nullable=True)
    submitted_at = Column(DateTime, default=func.now())

    created_at = Column(DateTime, default=func.now())
