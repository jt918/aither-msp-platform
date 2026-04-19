"""
API Routes for MSP Client Portal Service
Customer-facing portal + MSP admin endpoints.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.client_portal import (
    ClientPortalService,
    ReportType,
    RequestType,
    RequestStatus,
    PortalRole,
    AnnouncementSeverity,
)

router = APIRouter(prefix="/client-portal", tags=["Client Portal"])

# Singleton instance
_portal_instance: Optional[ClientPortalService] = None


def get_portal() -> ClientPortalService:
    """Get or create ClientPortalService instance with DB persistence."""
    global _portal_instance
    if _portal_instance is None:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            _portal_instance = ClientPortalService(db=db)
        except Exception:
            _portal_instance = ClientPortalService()
    return _portal_instance


# ========== Pydantic Models ==========

class ClientCreate(BaseModel):
    company_name: str
    primary_contact_email: str
    primary_contact_name: str
    plan_id: Optional[str] = ""
    endpoints_count: Optional[int] = 0
    users_count: Optional[int] = 0
    portal_theme: Optional[str] = ""


class ClientUpdate(BaseModel):
    company_name: Optional[str] = None
    primary_contact_email: Optional[str] = None
    primary_contact_name: Optional[str] = None
    plan_id: Optional[str] = None
    endpoints_count: Optional[int] = None
    users_count: Optional[int] = None
    portal_theme: Optional[str] = None


class UserCreate(BaseModel):
    client_id: str
    email: str
    name: str
    role: Optional[str] = "viewer"
    permissions: Optional[List[str]] = []
    mfa_enabled: Optional[bool] = False


class UserUpdate(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None
    role: Optional[str] = None
    permissions: Optional[List[str]] = None
    mfa_enabled: Optional[bool] = None


class TicketCreate(BaseModel):
    title: str
    description: str
    category: Optional[str] = "other"
    priority: Optional[str] = "medium"


class ReportGenerate(BaseModel):
    client_id: str
    report_type: str
    period_start: Optional[str] = None
    period_end: Optional[str] = None


class RequestCreate(BaseModel):
    client_id: str
    user_id: str
    request_type: str
    title: str
    description: Optional[str] = ""
    priority: Optional[str] = "medium"


class RequestAction(BaseModel):
    action_by: str


class AnnouncementCreate(BaseModel):
    title: str
    body: Optional[str] = ""
    severity: Optional[str] = "info"
    target_clients: Optional[List[str]] = None
    expires_at: Optional[str] = None


class SurveyCreate(BaseModel):
    client_id: str
    ticket_id: str
    rating: int = Field(ge=1, le=5)
    comments: Optional[str] = ""


# ========== Helper ==========

def _serialize_dataclass(obj) -> Dict[str, Any]:
    """Convert a dataclass to dict, handling datetime and enum."""
    result = {}
    for key, val in obj.__dict__.items():
        if isinstance(val, datetime):
            result[key] = val.isoformat()
        elif hasattr(val, 'value'):
            result[key] = val.value
        else:
            result[key] = val
    return result


# ======================================================================
# CLIENT-FACING ROUTES (authenticated as portal user)
# ======================================================================

@router.get("/portal/dashboard")
async def portal_dashboard(
    client_id: str = Query(..., description="Client ID"),
    _user=Depends(get_current_user),
):
    """Client dashboard - aggregated view of all MSP data."""
    svc = get_portal()
    data = svc.get_client_dashboard(client_id)
    if not data:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"status": "success", "data": data}


@router.get("/portal/endpoints")
async def portal_endpoints(
    client_id: str = Query(...),
    _user=Depends(get_current_user),
):
    """Endpoint health view for a client."""
    svc = get_portal()
    client = svc.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    total = client.endpoints_count
    return {
        "status": "success",
        "data": {
            "total": total,
            "online": int(total * 0.92),
            "offline": int(total * 0.03),
            "warning": int(total * 0.05),
            "endpoints": [],
        },
    }


@router.get("/portal/tickets")
async def portal_tickets(
    client_id: str = Query(...),
    _user=Depends(get_current_user),
):
    """Open tickets for a client."""
    svc = get_portal()
    reqs = svc.list_requests(client_id=client_id)
    return {
        "status": "success",
        "data": [_serialize_dataclass(r) for r in reqs],
        "total": len(reqs),
    }


@router.post("/portal/tickets")
async def portal_create_ticket(
    body: TicketCreate,
    client_id: str = Query(...),
    user_id: str = Query(...),
    _user=Depends(get_current_user),
):
    """Submit a new ticket (creates as service request)."""
    svc = get_portal()
    req = svc.submit_request(
        client_id=client_id,
        user_id=user_id,
        request_type=RequestType.OTHER,
        title=body.title,
        description=body.description,
        priority=body.priority or "medium",
    )
    if not req:
        raise HTTPException(status_code=400, detail="Could not create ticket")
    return {"status": "success", "data": _serialize_dataclass(req)}


@router.get("/portal/reports")
async def portal_reports(
    client_id: str = Query(...),
    _user=Depends(get_current_user),
):
    """Published reports for a client."""
    svc = get_portal()
    reports = svc.list_reports(client_id=client_id, published_only=True)
    return {
        "status": "success",
        "data": [_serialize_dataclass(r) for r in reports],
        "total": len(reports),
    }


@router.get("/portal/reports/{report_id}")
async def portal_report_detail(
    report_id: str,
    _user=Depends(get_current_user),
):
    """View a specific report."""
    svc = get_portal()
    report = svc.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "success", "data": _serialize_dataclass(report)}


@router.post("/portal/requests")
async def portal_submit_request(
    body: RequestCreate,
    _user=Depends(get_current_user),
):
    """Submit a service request."""
    svc = get_portal()
    try:
        rtype = RequestType(body.request_type)
    except ValueError:
        rtype = RequestType.OTHER
    req = svc.submit_request(
        client_id=body.client_id,
        user_id=body.user_id,
        request_type=rtype,
        title=body.title,
        description=body.description or "",
        priority=body.priority or "medium",
    )
    if not req:
        raise HTTPException(status_code=400, detail="Could not submit request")
    return {"status": "success", "data": _serialize_dataclass(req)}


@router.get("/portal/requests")
async def portal_list_requests(
    client_id: str = Query(...),
    status: Optional[str] = None,
    _user=Depends(get_current_user),
):
    """List service requests for a client."""
    svc = get_portal()
    req_status = None
    if status:
        try:
            req_status = RequestStatus(status)
        except ValueError:
            pass
    reqs = svc.list_requests(client_id=client_id, status=req_status)
    return {
        "status": "success",
        "data": [_serialize_dataclass(r) for r in reqs],
        "total": len(reqs),
    }


@router.get("/portal/announcements")
async def portal_announcements(
    client_id: str = Query(...),
    _user=Depends(get_current_user),
):
    """Announcements for this client."""
    svc = get_portal()
    anns = svc.get_announcements(client_id)
    return {
        "status": "success",
        "data": [_serialize_dataclass(a) for a in anns],
        "total": len(anns),
    }


@router.post("/portal/announcements/{announcement_id}/read")
async def portal_mark_announcement_read(
    announcement_id: str,
    user_id: str = Query(...),
    _user=Depends(get_current_user),
):
    """Mark an announcement as read."""
    svc = get_portal()
    ann = svc.mark_read(announcement_id, user_id)
    if not ann:
        raise HTTPException(status_code=404, detail="Announcement not found")
    return {"status": "success", "data": _serialize_dataclass(ann)}


@router.post("/portal/surveys")
async def portal_submit_survey(
    body: SurveyCreate,
    _user=Depends(get_current_user),
):
    """Submit a satisfaction survey."""
    svc = get_portal()
    survey = svc.submit_survey(
        client_id=body.client_id,
        ticket_id=body.ticket_id,
        rating=body.rating,
        comments=body.comments or "",
    )
    if not survey:
        raise HTTPException(status_code=400, detail="Invalid survey data")
    return {"status": "success", "data": _serialize_dataclass(survey)}


@router.get("/portal/security-posture")
async def portal_security_posture(
    client_id: str = Query(...),
    _user=Depends(get_current_user),
):
    """Security overview for a client."""
    svc = get_portal()
    report = svc.generate_report(client_id, ReportType.SECURITY_POSTURE)
    if not report:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"status": "success", "data": report.data}


@router.get("/portal/compliance")
async def portal_compliance(
    client_id: str = Query(...),
    _user=Depends(get_current_user),
):
    """Compliance status for a client."""
    svc = get_portal()
    report = svc.generate_report(client_id, ReportType.COMPLIANCE)
    if not report:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"status": "success", "data": report.data}


# ======================================================================
# MSP ADMIN ROUTES
# ======================================================================

@router.post("/portal/admin/clients")
async def admin_create_client(
    body: ClientCreate,
    _user=Depends(get_current_user),
):
    """Register a new portal client."""
    svc = get_portal()
    client = svc.register_client(
        company_name=body.company_name,
        primary_contact_email=body.primary_contact_email,
        primary_contact_name=body.primary_contact_name,
        plan_id=body.plan_id or "",
        endpoints_count=body.endpoints_count or 0,
        users_count=body.users_count or 0,
        portal_theme=body.portal_theme or "",
    )
    return {"status": "success", "data": _serialize_dataclass(client)}


@router.get("/portal/admin/clients")
async def admin_list_clients(
    portal_enabled: Optional[bool] = None,
    _user=Depends(get_current_user),
):
    """List all portal clients."""
    svc = get_portal()
    clients = svc.list_clients(portal_enabled=portal_enabled)
    return {
        "status": "success",
        "data": [_serialize_dataclass(c) for c in clients],
        "total": len(clients),
    }


@router.put("/portal/admin/clients/{client_id}")
async def admin_update_client(
    client_id: str,
    body: ClientUpdate,
    _user=Depends(get_current_user),
):
    """Update a portal client."""
    svc = get_portal()
    updates = {k: v for k, v in body.dict().items() if v is not None}
    client = svc.update_client(client_id, **updates)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"status": "success", "data": _serialize_dataclass(client)}


@router.post("/portal/admin/users")
async def admin_create_user(
    body: UserCreate,
    _user=Depends(get_current_user),
):
    """Create a portal user."""
    svc = get_portal()
    try:
        role = PortalRole(body.role)
    except ValueError:
        role = PortalRole.VIEWER
    user = svc.create_portal_user(
        client_id=body.client_id,
        email=body.email,
        name=body.name,
        role=role,
        permissions=body.permissions or [],
        mfa_enabled=body.mfa_enabled or False,
    )
    if not user:
        raise HTTPException(status_code=400, detail="Could not create user (client not found?)")
    return {"status": "success", "data": _serialize_dataclass(user)}


@router.get("/portal/admin/users")
async def admin_list_users(
    client_id: Optional[str] = None,
    _user=Depends(get_current_user),
):
    """List portal users."""
    svc = get_portal()
    users = svc.list_users(client_id=client_id)
    return {
        "status": "success",
        "data": [_serialize_dataclass(u) for u in users],
        "total": len(users),
    }


@router.post("/portal/admin/reports/generate")
async def admin_generate_report(
    body: ReportGenerate,
    _user=Depends(get_current_user),
):
    """Generate a report for a client."""
    svc = get_portal()
    try:
        rtype = ReportType(body.report_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid report type: {body.report_type}")

    period_start = None
    period_end = None
    if body.period_start:
        try:
            period_start = datetime.fromisoformat(body.period_start)
        except ValueError:
            pass
    if body.period_end:
        try:
            period_end = datetime.fromisoformat(body.period_end)
        except ValueError:
            pass

    report = svc.generate_report(body.client_id, rtype, period_start, period_end)
    if not report:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"status": "success", "data": _serialize_dataclass(report)}


@router.post("/portal/admin/reports/{report_id}/publish")
async def admin_publish_report(
    report_id: str,
    _user=Depends(get_current_user),
):
    """Publish a report."""
    svc = get_portal()
    report = svc.publish_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "success", "data": _serialize_dataclass(report)}


@router.post("/portal/admin/requests/{request_id}")
async def admin_action_request(
    request_id: str,
    action: str = Query(..., description="approve, complete, or deny"),
    action_by: str = Query("admin"),
    _user=Depends(get_current_user),
):
    """Approve, complete, or deny a service request."""
    svc = get_portal()
    if action == "approve":
        req = svc.approve_request(request_id, action_by)
    elif action == "complete":
        req = svc.complete_request(request_id)
    elif action == "deny":
        req = svc.deny_request(request_id, action_by)
    else:
        raise HTTPException(status_code=400, detail=f"Invalid action: {action}")
    if not req:
        raise HTTPException(status_code=404, detail="Request not found or invalid state")
    return {"status": "success", "data": _serialize_dataclass(req)}


@router.put("/portal/admin/requests/{request_id}")
async def admin_update_request(
    request_id: str,
    action: str = Query(..., description="approve, complete, or deny"),
    action_by: str = Query("admin"),
    _user=Depends(get_current_user),
):
    """Update a service request (same as POST action)."""
    svc = get_portal()
    if action == "approve":
        req = svc.approve_request(request_id, action_by)
    elif action == "complete":
        req = svc.complete_request(request_id)
    elif action == "deny":
        req = svc.deny_request(request_id, action_by)
    else:
        raise HTTPException(status_code=400, detail=f"Invalid action: {action}")
    if not req:
        raise HTTPException(status_code=404, detail="Request not found or invalid state")
    return {"status": "success", "data": _serialize_dataclass(req)}


@router.post("/portal/admin/announcements")
async def admin_create_announcement(
    body: AnnouncementCreate,
    _user=Depends(get_current_user),
):
    """Create an announcement."""
    svc = get_portal()
    try:
        severity = AnnouncementSeverity(body.severity)
    except ValueError:
        severity = AnnouncementSeverity.INFO
    expires = None
    if body.expires_at:
        try:
            expires = datetime.fromisoformat(body.expires_at)
        except ValueError:
            pass
    ann = svc.create_announcement(
        title=body.title,
        body=body.body or "",
        severity=severity,
        target_clients=body.target_clients,
        expires_at=expires,
    )
    return {"status": "success", "data": _serialize_dataclass(ann)}


@router.get("/portal/admin/satisfaction")
async def admin_satisfaction(
    client_id: Optional[str] = None,
    _user=Depends(get_current_user),
):
    """Satisfaction metrics."""
    svc = get_portal()
    if client_id:
        surveys = svc.get_surveys(client_id)
        score = svc.get_satisfaction_score(client_id)
    else:
        surveys = list(svc.surveys.values())
        score = round(sum(s.rating for s in surveys) / len(surveys), 2) if surveys else 0.0
    return {
        "status": "success",
        "data": {
            "total_surveys": len(surveys),
            "average_rating": score,
            "surveys": [_serialize_dataclass(s) for s in surveys[-20:]],
        },
    }


@router.get("/portal/admin/dashboard")
async def admin_portal_dashboard(
    _user=Depends(get_current_user),
):
    """MSP admin overview of all client portals."""
    svc = get_portal()
    return {"status": "success", "data": svc.get_portal_dashboard()}
