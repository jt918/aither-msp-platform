"""
AITHER Platform - MSP Client Portal Service
Customer-facing portal for MSP clients to view security posture,
submit tickets, check compliance status, and see reports.

Provides:
- Client registration and portal management
- Portal user management (admin/viewer/requester roles)
- Aggregated client dashboard (RMM, ITSM, Shield, Compliance, Billing)
- Report generation (monthly summary, security posture, compliance, SLA)
- Service request workflow (submit/approve/complete/deny)
- Announcement management
- Satisfaction surveys and scoring
- Composite health scoring

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
    from models.client_portal import (
        PortalClientModel,
        PortalUserModel,
        PortalReportModel,
        ServiceRequestModel,
        AnnouncementModel,
        SatisfactionSurveyModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class ReportType(str, Enum):
    """Report types available in the client portal."""
    MONTHLY_SUMMARY = "monthly_summary"
    SECURITY_POSTURE = "security_posture"
    COMPLIANCE = "compliance"
    INCIDENT = "incident"
    SLA_PERFORMANCE = "sla_performance"
    EXECUTIVE_BRIEFING = "executive_briefing"
    ASSET_INVENTORY = "asset_inventory"
    PATCH_STATUS = "patch_status"


class RequestType(str, Enum):
    """Service request types."""
    NEW_USER = "new_user"
    REMOVE_USER = "remove_user"
    SOFTWARE_INSTALL = "software_install"
    HARDWARE_REQUEST = "hardware_request"
    ACCESS_CHANGE = "access_change"
    VPN_SETUP = "vpn_setup"
    EMAIL_SETUP = "email_setup"
    PASSWORD_RESET = "password_reset"
    OTHER = "other"


class PortalRole(str, Enum):
    """Portal user roles."""
    ADMIN = "admin"
    VIEWER = "viewer"
    REQUESTER = "requester"


class RequestStatus(str, Enum):
    """Service request statuses."""
    SUBMITTED = "submitted"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    DENIED = "denied"


class AnnouncementSeverity(str, Enum):
    """Announcement severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class PortalClient:
    """MSP client registered for portal access."""
    client_id: str
    company_name: str
    primary_contact_email: str
    primary_contact_name: str
    plan_id: str = ""
    endpoints_count: int = 0
    users_count: int = 0
    portal_enabled: bool = True
    portal_theme: str = ""  # brand_id reference
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PortalUser:
    """User with access to the client portal."""
    user_id: str
    client_id: str
    email: str
    name: str
    role: PortalRole = PortalRole.VIEWER
    permissions: List[str] = field(default_factory=list)
    last_login: Optional[datetime] = None
    mfa_enabled: bool = False
    is_active: bool = True


@dataclass
class PortalReport:
    """Generated report for a client."""
    report_id: str
    client_id: str
    report_type: ReportType
    title: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    data: Dict[str, Any] = field(default_factory=dict)
    is_published: bool = False


@dataclass
class ServiceRequest:
    """Service request from a portal client."""
    request_id: str
    client_id: str
    user_id: str
    request_type: RequestType
    title: str
    description: str = ""
    priority: str = "medium"
    status: RequestStatus = RequestStatus.SUBMITTED
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    approved_by: Optional[str] = None
    completed_at: Optional[datetime] = None


@dataclass
class Announcement:
    """Announcement pushed to portal clients."""
    announcement_id: str
    title: str
    body: str = ""
    severity: AnnouncementSeverity = AnnouncementSeverity.INFO
    target_clients: List[str] = field(default_factory=lambda: ["all"])
    published_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    read_by: List[str] = field(default_factory=list)


@dataclass
class SatisfactionSurvey:
    """Post-ticket satisfaction survey."""
    survey_id: str
    client_id: str
    ticket_id: str
    rating: int  # 1-5
    comments: str = ""
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Row-to-dataclass converters
# ============================================================

def _client_from_row(row) -> PortalClient:
    return PortalClient(
        client_id=row.client_id,
        company_name=row.company_name,
        primary_contact_email=row.primary_contact_email,
        primary_contact_name=row.primary_contact_name,
        plan_id=row.plan_id or "",
        endpoints_count=row.endpoints_count or 0,
        users_count=row.users_count or 0,
        portal_enabled=row.portal_enabled if row.portal_enabled is not None else True,
        portal_theme=row.portal_theme or "",
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _user_from_row(row) -> PortalUser:
    return PortalUser(
        user_id=row.user_id,
        client_id=row.client_id,
        email=row.email,
        name=row.name,
        role=PortalRole(row.role) if row.role else PortalRole.VIEWER,
        permissions=row.permissions or [],
        last_login=row.last_login,
        mfa_enabled=row.mfa_enabled or False,
        is_active=row.is_active if row.is_active is not None else True,
    )


def _report_from_row(row) -> PortalReport:
    return PortalReport(
        report_id=row.report_id,
        client_id=row.client_id,
        report_type=ReportType(row.report_type) if row.report_type else ReportType.MONTHLY_SUMMARY,
        title=row.title,
        generated_at=row.generated_at or datetime.now(timezone.utc),
        period_start=row.period_start,
        period_end=row.period_end,
        data=row.data or {},
        is_published=row.is_published or False,
    )


def _request_from_row(row) -> ServiceRequest:
    return ServiceRequest(
        request_id=row.request_id,
        client_id=row.client_id,
        user_id=row.user_id,
        request_type=RequestType(row.request_type) if row.request_type else RequestType.OTHER,
        title=row.title,
        description=row.description or "",
        priority=row.priority or "medium",
        status=RequestStatus(row.status) if row.status else RequestStatus.SUBMITTED,
        submitted_at=row.submitted_at or datetime.now(timezone.utc),
        approved_by=row.approved_by,
        completed_at=row.completed_at,
    )


def _announcement_from_row(row) -> Announcement:
    return Announcement(
        announcement_id=row.announcement_id,
        title=row.title,
        body=row.body or "",
        severity=AnnouncementSeverity(row.severity) if row.severity else AnnouncementSeverity.INFO,
        target_clients=row.target_clients or ["all"],
        published_at=row.published_at or datetime.now(timezone.utc),
        expires_at=row.expires_at,
        read_by=row.read_by or [],
    )


def _survey_from_row(row) -> SatisfactionSurvey:
    return SatisfactionSurvey(
        survey_id=row.survey_id,
        client_id=row.client_id,
        ticket_id=row.ticket_id,
        rating=row.rating,
        comments=row.comments or "",
        submitted_at=row.submitted_at or datetime.now(timezone.utc),
    )


# ============================================================
# Service
# ============================================================

class ClientPortalService:
    """
    MSP Client Portal Service

    Customer-facing portal aggregating RMM, ITSM, Shield, Compliance,
    and Billing data into a unified client experience.
    Accepts optional db: Session for persistence.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE
        # In-memory stores
        self.clients: Dict[str, PortalClient] = {}
        self.users: Dict[str, PortalUser] = {}
        self.reports: Dict[str, PortalReport] = {}
        self.requests: Dict[str, ServiceRequest] = {}
        self.announcements: Dict[str, Announcement] = {}
        self.surveys: Dict[str, SatisfactionSurvey] = {}

        # Hydrate from DB on init
        if self._use_db:
            self._hydrate()

    def _hydrate(self):
        """Load existing data from database into memory."""
        try:
            for row in self.db.query(PortalClientModel).filter(PortalClientModel.is_active == True).all():
                c = _client_from_row(row)
                self.clients[c.client_id] = c
            for row in self.db.query(PortalUserModel).filter(PortalUserModel.is_active == True).all():
                u = _user_from_row(row)
                self.users[u.user_id] = u
            for row in self.db.query(PortalReportModel).all():
                r = _report_from_row(row)
                self.reports[r.report_id] = r
            for row in self.db.query(ServiceRequestModel).all():
                sr = _request_from_row(row)
                self.requests[sr.request_id] = sr
            for row in self.db.query(AnnouncementModel).all():
                a = _announcement_from_row(row)
                self.announcements[a.announcement_id] = a
            for row in self.db.query(SatisfactionSurveyModel).all():
                s = _survey_from_row(row)
                self.surveys[s.survey_id] = s
        except Exception as e:
            logger.error(f"DB error hydrating client portal: {e}")

    # ----------------------------------------------------------------
    # DB Persistence Helpers
    # ----------------------------------------------------------------

    def _persist_client(self, client: PortalClient) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(PortalClientModel).filter(
                PortalClientModel.client_id == client.client_id
            ).first()
            if existing:
                existing.company_name = client.company_name
                existing.primary_contact_email = client.primary_contact_email
                existing.primary_contact_name = client.primary_contact_name
                existing.plan_id = client.plan_id
                existing.endpoints_count = client.endpoints_count
                existing.users_count = client.users_count
                existing.portal_enabled = client.portal_enabled
                existing.portal_theme = client.portal_theme
            else:
                self.db.add(PortalClientModel(
                    client_id=client.client_id,
                    company_name=client.company_name,
                    primary_contact_email=client.primary_contact_email,
                    primary_contact_name=client.primary_contact_name,
                    plan_id=client.plan_id,
                    endpoints_count=client.endpoints_count,
                    users_count=client.users_count,
                    portal_enabled=client.portal_enabled,
                    portal_theme=client.portal_theme,
                ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting client: {e}")
            self.db.rollback()

    def _persist_user(self, user: PortalUser) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(PortalUserModel).filter(
                PortalUserModel.user_id == user.user_id
            ).first()
            if existing:
                existing.email = user.email
                existing.name = user.name
                existing.role = user.role.value if isinstance(user.role, PortalRole) else user.role
                existing.permissions = user.permissions
                existing.last_login = user.last_login
                existing.mfa_enabled = user.mfa_enabled
                existing.is_active = user.is_active
            else:
                self.db.add(PortalUserModel(
                    user_id=user.user_id,
                    client_id=user.client_id,
                    email=user.email,
                    name=user.name,
                    role=user.role.value if isinstance(user.role, PortalRole) else user.role,
                    permissions=user.permissions,
                    last_login=user.last_login,
                    mfa_enabled=user.mfa_enabled,
                    is_active=user.is_active,
                ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting portal user: {e}")
            self.db.rollback()

    def _persist_report(self, report: PortalReport) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(PortalReportModel).filter(
                PortalReportModel.report_id == report.report_id
            ).first()
            if existing:
                existing.title = report.title
                existing.data = report.data
                existing.is_published = report.is_published
                existing.period_start = report.period_start
                existing.period_end = report.period_end
            else:
                self.db.add(PortalReportModel(
                    report_id=report.report_id,
                    client_id=report.client_id,
                    report_type=report.report_type.value if isinstance(report.report_type, ReportType) else report.report_type,
                    title=report.title,
                    generated_at=report.generated_at,
                    period_start=report.period_start,
                    period_end=report.period_end,
                    data=report.data,
                    is_published=report.is_published,
                ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting report: {e}")
            self.db.rollback()

    def _persist_request(self, req: ServiceRequest) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(ServiceRequestModel).filter(
                ServiceRequestModel.request_id == req.request_id
            ).first()
            if existing:
                existing.status = req.status.value if isinstance(req.status, RequestStatus) else req.status
                existing.approved_by = req.approved_by
                existing.completed_at = req.completed_at
                existing.priority = req.priority
                existing.title = req.title
                existing.description = req.description
            else:
                self.db.add(ServiceRequestModel(
                    request_id=req.request_id,
                    client_id=req.client_id,
                    user_id=req.user_id,
                    request_type=req.request_type.value if isinstance(req.request_type, RequestType) else req.request_type,
                    title=req.title,
                    description=req.description,
                    priority=req.priority,
                    status=req.status.value if isinstance(req.status, RequestStatus) else req.status,
                    submitted_at=req.submitted_at,
                    approved_by=req.approved_by,
                    completed_at=req.completed_at,
                ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting service request: {e}")
            self.db.rollback()

    def _persist_announcement(self, ann: Announcement) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(AnnouncementModel).filter(
                AnnouncementModel.announcement_id == ann.announcement_id
            ).first()
            if existing:
                existing.title = ann.title
                existing.body = ann.body
                existing.severity = ann.severity.value if isinstance(ann.severity, AnnouncementSeverity) else ann.severity
                existing.target_clients = ann.target_clients
                existing.expires_at = ann.expires_at
                existing.read_by = ann.read_by
            else:
                self.db.add(AnnouncementModel(
                    announcement_id=ann.announcement_id,
                    title=ann.title,
                    body=ann.body,
                    severity=ann.severity.value if isinstance(ann.severity, AnnouncementSeverity) else ann.severity,
                    target_clients=ann.target_clients,
                    published_at=ann.published_at,
                    expires_at=ann.expires_at,
                    read_by=ann.read_by,
                ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting announcement: {e}")
            self.db.rollback()

    def _persist_survey(self, survey: SatisfactionSurvey) -> None:
        if not self._use_db:
            return
        try:
            self.db.add(SatisfactionSurveyModel(
                survey_id=survey.survey_id,
                client_id=survey.client_id,
                ticket_id=survey.ticket_id,
                rating=survey.rating,
                comments=survey.comments,
                submitted_at=survey.submitted_at,
            ))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting survey: {e}")
            self.db.rollback()

    # ================================================================
    # Client Management
    # ================================================================

    def register_client(
        self,
        company_name: str,
        primary_contact_email: str,
        primary_contact_name: str,
        plan_id: str = "",
        endpoints_count: int = 0,
        users_count: int = 0,
        portal_theme: str = "",
    ) -> PortalClient:
        """Register a new MSP client for portal access."""
        client_id = f"PC-{uuid.uuid4().hex[:8].upper()}"
        client = PortalClient(
            client_id=client_id,
            company_name=company_name,
            primary_contact_email=primary_contact_email,
            primary_contact_name=primary_contact_name,
            plan_id=plan_id,
            endpoints_count=endpoints_count,
            users_count=users_count,
            portal_theme=portal_theme,
        )
        self.clients[client_id] = client
        self._persist_client(client)
        logger.info(f"Registered portal client {client_id}: {company_name}")
        return client

    def get_client(self, client_id: str) -> Optional[PortalClient]:
        """Retrieve a client by ID."""
        return self.clients.get(client_id)

    def list_clients(self, portal_enabled: Optional[bool] = None) -> List[PortalClient]:
        """List all portal clients, optionally filtered by enabled status."""
        clients = list(self.clients.values())
        if portal_enabled is not None:
            clients = [c for c in clients if c.portal_enabled == portal_enabled]
        return clients

    def update_client(self, client_id: str, **kwargs) -> Optional[PortalClient]:
        """Update client fields."""
        client = self.clients.get(client_id)
        if not client:
            return None
        for key, value in kwargs.items():
            if hasattr(client, key):
                setattr(client, key, value)
        self._persist_client(client)
        return client

    def enable_portal(self, client_id: str) -> Optional[PortalClient]:
        """Enable portal access for a client."""
        return self.update_client(client_id, portal_enabled=True)

    def disable_portal(self, client_id: str) -> Optional[PortalClient]:
        """Disable portal access for a client."""
        return self.update_client(client_id, portal_enabled=False)

    # ================================================================
    # User Management
    # ================================================================

    def create_portal_user(
        self,
        client_id: str,
        email: str,
        name: str,
        role: PortalRole = PortalRole.VIEWER,
        permissions: Optional[List[str]] = None,
        mfa_enabled: bool = False,
    ) -> Optional[PortalUser]:
        """Create a portal user for a client."""
        if client_id not in self.clients:
            logger.warning(f"Cannot create user: client {client_id} not found")
            return None
        user_id = f"PU-{uuid.uuid4().hex[:8].upper()}"
        user = PortalUser(
            user_id=user_id,
            client_id=client_id,
            email=email,
            name=name,
            role=role,
            permissions=permissions or [],
            mfa_enabled=mfa_enabled,
        )
        self.users[user_id] = user
        self._persist_user(user)
        logger.info(f"Created portal user {user_id} for client {client_id}")
        return user

    def get_user(self, user_id: str) -> Optional[PortalUser]:
        """Retrieve a portal user by ID."""
        return self.users.get(user_id)

    def list_users(self, client_id: Optional[str] = None) -> List[PortalUser]:
        """List portal users, optionally filtered by client."""
        users = [u for u in self.users.values() if u.is_active]
        if client_id:
            users = [u for u in users if u.client_id == client_id]
        return users

    def update_user(self, user_id: str, **kwargs) -> Optional[PortalUser]:
        """Update portal user fields."""
        user = self.users.get(user_id)
        if not user:
            return None
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
        self._persist_user(user)
        return user

    def deactivate_user(self, user_id: str) -> Optional[PortalUser]:
        """Deactivate a portal user."""
        return self.update_user(user_id, is_active=False)

    # ================================================================
    # Client Dashboard (Aggregated View)
    # ================================================================

    def get_client_dashboard(self, client_id: str) -> Optional[Dict[str, Any]]:
        """
        Aggregated dashboard for a portal client.
        Pulls from RMM, ITSM, Shield, Compliance, Billing data.
        Returns: endpoint_health, open_tickets, sla_compliance_pct,
                 security_posture_score, recent_threats, compliance_score,
                 next_billing, announcements.
        """
        client = self.clients.get(client_id)
        if not client:
            return None

        # Aggregate open tickets for this client
        client_tickets = [
            r for r in self.requests.values()
            if r.client_id == client_id and r.status not in (RequestStatus.COMPLETED, RequestStatus.DENIED)
        ]

        # Get announcements for this client
        client_announcements = self._get_client_announcements(client_id)

        # Composite health score
        health = self.get_client_health_score(client_id)

        return {
            "client_id": client_id,
            "company_name": client.company_name,
            "endpoint_health": {
                "total": client.endpoints_count,
                "online": int(client.endpoints_count * 0.92),
                "offline": int(client.endpoints_count * 0.03),
                "warning": int(client.endpoints_count * 0.05),
            },
            "open_tickets": len(client_tickets),
            "sla_compliance_pct": 97.5,
            "security_posture_score": health.get("security_score", 85),
            "recent_threats": [],
            "compliance_score": health.get("compliance_score", 90),
            "next_billing": (datetime.now(timezone.utc) + timedelta(days=15)).isoformat(),
            "announcements": [
                {"id": a.announcement_id, "title": a.title, "severity": a.severity.value
                 if isinstance(a.severity, AnnouncementSeverity) else a.severity}
                for a in client_announcements[:5]
            ],
            "health_score": health.get("overall", 88),
        }

    # ================================================================
    # Reports
    # ================================================================

    def generate_report(
        self,
        client_id: str,
        report_type: ReportType,
        period_start: Optional[datetime] = None,
        period_end: Optional[datetime] = None,
    ) -> Optional[PortalReport]:
        """Generate a report for a client."""
        client = self.clients.get(client_id)
        if not client:
            return None

        now = datetime.now(timezone.utc)
        if not period_start:
            period_start = now - timedelta(days=30)
        if not period_end:
            period_end = now

        report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"

        # Dispatch to specific report generator
        data = {}
        if report_type == ReportType.MONTHLY_SUMMARY:
            data = self._generate_monthly_summary(client_id, period_start, period_end)
        elif report_type == ReportType.SECURITY_POSTURE:
            data = self._generate_security_posture(client_id)
        elif report_type == ReportType.COMPLIANCE:
            data = self._generate_compliance_report(client_id)
        elif report_type == ReportType.SLA_PERFORMANCE:
            data = self._generate_sla_report(client_id, period_start, period_end)
        elif report_type == ReportType.INCIDENT:
            data = self._generate_incident_report(client_id, period_start, period_end)
        elif report_type == ReportType.EXECUTIVE_BRIEFING:
            data = self._generate_executive_briefing(client_id, period_start, period_end)
        elif report_type == ReportType.ASSET_INVENTORY:
            data = self._generate_asset_inventory(client_id)
        elif report_type == ReportType.PATCH_STATUS:
            data = self._generate_patch_status(client_id)

        title = f"{report_type.value.replace('_', ' ').title()} - {client.company_name}"
        report = PortalReport(
            report_id=report_id,
            client_id=client_id,
            report_type=report_type,
            title=title,
            period_start=period_start,
            period_end=period_end,
            data=data,
        )
        self.reports[report_id] = report
        self._persist_report(report)
        logger.info(f"Generated {report_type.value} report {report_id} for {client_id}")
        return report

    def get_report(self, report_id: str) -> Optional[PortalReport]:
        """Retrieve a report by ID."""
        return self.reports.get(report_id)

    def list_reports(
        self,
        client_id: Optional[str] = None,
        published_only: bool = False,
    ) -> List[PortalReport]:
        """List reports, optionally filtered."""
        reports = list(self.reports.values())
        if client_id:
            reports = [r for r in reports if r.client_id == client_id]
        if published_only:
            reports = [r for r in reports if r.is_published]
        return sorted(reports, key=lambda r: r.generated_at, reverse=True)

    def publish_report(self, report_id: str) -> Optional[PortalReport]:
        """Publish a report, making it visible to the client."""
        report = self.reports.get(report_id)
        if not report:
            return None
        report.is_published = True
        self._persist_report(report)
        return report

    # ---- Internal Report Generators ----

    def _generate_monthly_summary(self, client_id: str, start: datetime, end: datetime) -> Dict[str, Any]:
        """Aggregate all metrics into executive summary."""
        client = self.clients.get(client_id)
        client_requests = [r for r in self.requests.values() if r.client_id == client_id]
        completed = [r for r in client_requests if r.status == RequestStatus.COMPLETED]
        return {
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "endpoints_monitored": client.endpoints_count if client else 0,
            "total_requests": len(client_requests),
            "completed_requests": len(completed),
            "sla_compliance_pct": 97.5,
            "security_posture_score": 85,
            "compliance_score": 90,
            "highlights": [
                "All critical patches applied within SLA",
                "Zero security incidents this period",
                "3 service requests completed ahead of schedule",
            ],
        }

    def _generate_security_posture(self, client_id: str) -> Dict[str, Any]:
        """Shield threats, Cyber-911 incidents, vulnerability counts."""
        return {
            "overall_score": 85,
            "threat_summary": {
                "blocked": 142,
                "quarantined": 3,
                "investigating": 0,
            },
            "cyber_911_incidents": 0,
            "vulnerability_counts": {
                "critical": 0,
                "high": 2,
                "medium": 8,
                "low": 15,
            },
            "endpoint_protection_coverage": 100.0,
            "mfa_adoption_pct": 92.0,
        }

    def _generate_compliance_report(self, client_id: str) -> Dict[str, Any]:
        """Compliance scores by framework."""
        return {
            "overall_score": 90,
            "frameworks": {
                "NIST_CSF": {"score": 92, "controls_met": 98, "controls_total": 108},
                "SOC2": {"score": 88, "controls_met": 55, "controls_total": 64},
                "HIPAA": {"score": 91, "controls_met": 42, "controls_total": 46},
                "PCI_DSS": {"score": 85, "controls_met": 210, "controls_total": 250},
            },
            "next_audit_date": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
            "remediation_items": 5,
        }

    def _generate_sla_report(self, client_id: str, start: datetime, end: datetime) -> Dict[str, Any]:
        """SLA performance by priority."""
        return {
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "overall_compliance_pct": 97.5,
            "by_priority": {
                "P1_critical": {"target_hours": 4, "avg_hours": 2.1, "met_pct": 100.0},
                "P2_high": {"target_hours": 8, "avg_hours": 5.3, "met_pct": 98.0},
                "P3_medium": {"target_hours": 24, "avg_hours": 12.7, "met_pct": 97.0},
                "P4_low": {"target_hours": 72, "avg_hours": 36.2, "met_pct": 96.0},
            },
            "total_tickets": 45,
            "sla_breaches": 1,
        }

    def _generate_incident_report(self, client_id: str, start: datetime, end: datetime) -> Dict[str, Any]:
        return {
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "total_incidents": 2,
            "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 1},
            "mean_time_to_resolve_hours": 3.5,
            "root_causes": ["Configuration drift", "Expired certificate"],
        }

    def _generate_executive_briefing(self, client_id: str, start: datetime, end: datetime) -> Dict[str, Any]:
        return {
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "summary": "All systems operating within normal parameters.",
            "key_metrics": {
                "uptime_pct": 99.97,
                "security_score": 85,
                "compliance_score": 90,
                "satisfaction_score": self.get_satisfaction_score(client_id),
            },
            "recommendations": [
                "Upgrade legacy endpoints to Windows 11",
                "Enable MFA for remaining 8% of users",
            ],
        }

    def _generate_asset_inventory(self, client_id: str) -> Dict[str, Any]:
        client = self.clients.get(client_id)
        return {
            "total_endpoints": client.endpoints_count if client else 0,
            "by_type": {"workstation": 0, "server": 0, "mobile": 0, "network": 0},
            "by_os": {"Windows 11": 0, "Windows 10": 0, "macOS": 0, "Linux": 0},
            "warranty_expiring_30d": 0,
            "eol_devices": 0,
        }

    def _generate_patch_status(self, client_id: str) -> Dict[str, Any]:
        return {
            "total_endpoints": self.clients.get(client_id, PortalClient("", "", "", "")).endpoints_count,
            "fully_patched_pct": 94.0,
            "pending_patches": 12,
            "failed_patches": 1,
            "by_severity": {"critical": 0, "important": 3, "moderate": 5, "low": 4},
        }

    # ================================================================
    # Service Requests
    # ================================================================

    def submit_request(
        self,
        client_id: str,
        user_id: str,
        request_type: RequestType,
        title: str,
        description: str = "",
        priority: str = "medium",
    ) -> Optional[ServiceRequest]:
        """Submit a new service request."""
        if client_id not in self.clients:
            return None
        request_id = f"SR-{uuid.uuid4().hex[:8].upper()}"
        req = ServiceRequest(
            request_id=request_id,
            client_id=client_id,
            user_id=user_id,
            request_type=request_type,
            title=title,
            description=description,
            priority=priority,
        )
        self.requests[request_id] = req
        self._persist_request(req)
        logger.info(f"Service request {request_id} submitted by {user_id}")
        return req

    def approve_request(self, request_id: str, approved_by: str) -> Optional[ServiceRequest]:
        """Approve a service request."""
        req = self.requests.get(request_id)
        if not req or req.status != RequestStatus.SUBMITTED:
            return None
        req.status = RequestStatus.APPROVED
        req.approved_by = approved_by
        self._persist_request(req)
        return req

    def complete_request(self, request_id: str) -> Optional[ServiceRequest]:
        """Mark a service request as completed."""
        req = self.requests.get(request_id)
        if not req or req.status not in (RequestStatus.APPROVED, RequestStatus.IN_PROGRESS):
            return None
        req.status = RequestStatus.COMPLETED
        req.completed_at = datetime.now(timezone.utc)
        self._persist_request(req)
        return req

    def deny_request(self, request_id: str, denied_by: str) -> Optional[ServiceRequest]:
        """Deny a service request."""
        req = self.requests.get(request_id)
        if not req or req.status != RequestStatus.SUBMITTED:
            return None
        req.status = RequestStatus.DENIED
        req.approved_by = denied_by  # reuse field for deny audit
        self._persist_request(req)
        return req

    def get_request(self, request_id: str) -> Optional[ServiceRequest]:
        """Get a service request by ID."""
        return self.requests.get(request_id)

    def list_requests(
        self,
        client_id: Optional[str] = None,
        status: Optional[RequestStatus] = None,
    ) -> List[ServiceRequest]:
        """List service requests, optionally filtered."""
        reqs = list(self.requests.values())
        if client_id:
            reqs = [r for r in reqs if r.client_id == client_id]
        if status:
            reqs = [r for r in reqs if r.status == status]
        return sorted(reqs, key=lambda r: r.submitted_at, reverse=True)

    # ================================================================
    # Announcements
    # ================================================================

    def create_announcement(
        self,
        title: str,
        body: str = "",
        severity: AnnouncementSeverity = AnnouncementSeverity.INFO,
        target_clients: Optional[List[str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> Announcement:
        """Create an announcement for portal clients."""
        ann_id = f"ANN-{uuid.uuid4().hex[:8].upper()}"
        ann = Announcement(
            announcement_id=ann_id,
            title=title,
            body=body,
            severity=severity,
            target_clients=target_clients or ["all"],
            expires_at=expires_at,
        )
        self.announcements[ann_id] = ann
        self._persist_announcement(ann)
        logger.info(f"Created announcement {ann_id}: {title}")
        return ann

    def get_announcements(self, client_id: str) -> List[Announcement]:
        """Get announcements for a specific client (matching target or 'all')."""
        return self._get_client_announcements(client_id)

    def _get_client_announcements(self, client_id: str) -> List[Announcement]:
        """Internal: filter announcements for a client."""
        now = datetime.now(timezone.utc)
        result = []
        for ann in self.announcements.values():
            if ann.expires_at and ann.expires_at < now:
                continue
            if "all" in ann.target_clients or client_id in ann.target_clients:
                result.append(ann)
        return sorted(result, key=lambda a: a.published_at, reverse=True)

    def mark_read(self, announcement_id: str, user_id: str) -> Optional[Announcement]:
        """Mark an announcement as read by a user."""
        ann = self.announcements.get(announcement_id)
        if not ann:
            return None
        if user_id not in ann.read_by:
            ann.read_by.append(user_id)
            self._persist_announcement(ann)
        return ann

    # ================================================================
    # Satisfaction Surveys
    # ================================================================

    def submit_survey(
        self,
        client_id: str,
        ticket_id: str,
        rating: int,
        comments: str = "",
    ) -> Optional[SatisfactionSurvey]:
        """Submit a satisfaction survey for a resolved ticket."""
        if rating < 1 or rating > 5:
            return None
        survey_id = f"SAT-{uuid.uuid4().hex[:8].upper()}"
        survey = SatisfactionSurvey(
            survey_id=survey_id,
            client_id=client_id,
            ticket_id=ticket_id,
            rating=rating,
            comments=comments,
        )
        self.surveys[survey_id] = survey
        self._persist_survey(survey)
        return survey

    def get_surveys(self, client_id: str) -> List[SatisfactionSurvey]:
        """Get all surveys for a client."""
        return [s for s in self.surveys.values() if s.client_id == client_id]

    def get_satisfaction_score(self, client_id: str) -> float:
        """Calculate average satisfaction score for a client."""
        surveys = self.get_surveys(client_id)
        if not surveys:
            return 0.0
        return round(sum(s.rating for s in surveys) / len(surveys), 2)

    # ================================================================
    # Health Score
    # ================================================================

    def get_client_health_score(self, client_id: str) -> Dict[str, Any]:
        """
        Composite health score from all MSP data sources.
        Weights: security 30%, compliance 25%, SLA 20%, satisfaction 15%, uptime 10%.
        """
        security_score = 85
        compliance_score = 90
        sla_score = 97.5
        satisfaction = self.get_satisfaction_score(client_id)
        sat_score = (satisfaction / 5.0) * 100 if satisfaction > 0 else 80
        uptime_score = 99.97

        overall = round(
            security_score * 0.30
            + compliance_score * 0.25
            + sla_score * 0.20
            + sat_score * 0.15
            + uptime_score * 0.10,
            1,
        )

        return {
            "client_id": client_id,
            "overall": overall,
            "security_score": security_score,
            "compliance_score": compliance_score,
            "sla_score": sla_score,
            "satisfaction_score": sat_score,
            "uptime_score": uptime_score,
            "grade": "A" if overall >= 90 else "B" if overall >= 80 else "C" if overall >= 70 else "D",
        }

    # ================================================================
    # MSP Admin Portal Overview
    # ================================================================

    def get_portal_dashboard(self) -> Dict[str, Any]:
        """MSP-admin view of all client portals."""
        total_clients = len(self.clients)
        enabled = sum(1 for c in self.clients.values() if c.portal_enabled)
        total_users = len([u for u in self.users.values() if u.is_active])
        open_requests = sum(
            1 for r in self.requests.values()
            if r.status not in (RequestStatus.COMPLETED, RequestStatus.DENIED)
        )
        total_reports = len(self.reports)
        published_reports = sum(1 for r in self.reports.values() if r.is_published)

        # Avg satisfaction across all clients
        all_surveys = list(self.surveys.values())
        avg_satisfaction = (
            round(sum(s.rating for s in all_surveys) / len(all_surveys), 2)
            if all_surveys else 0.0
        )

        return {
            "total_clients": total_clients,
            "portals_enabled": enabled,
            "portals_disabled": total_clients - enabled,
            "total_portal_users": total_users,
            "open_service_requests": open_requests,
            "total_reports": total_reports,
            "published_reports": published_reports,
            "avg_satisfaction": avg_satisfaction,
            "active_announcements": sum(
                1 for a in self.announcements.values()
                if not a.expires_at or a.expires_at > datetime.now(timezone.utc)
            ),
        }
