"""
API Routes for Email Security Gateway
Anti-phishing, anti-spam, attachment sandboxing, and email DLP for MSP clients.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.email_security import (
    EmailSecurityService,
    Verdict,
    Direction,
    PolicyType,
    DLPPatternType,
    DLPAction,
)

router = APIRouter(prefix="/email-security", tags=["Email Security Gateway"])


def _init_email_security_service() -> EmailSecurityService:
    """Initialize EmailSecurityService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return EmailSecurityService(db=db)
    except Exception:
        return EmailSecurityService()


# Initialize service with DB persistence
email_security_service = _init_email_security_service()


# ========== Request/Response Models ==========

class ScanEmailRequest(BaseModel):
    """Email scan request."""
    client_id: str
    sender: str
    recipient: str
    subject: str = ""
    direction: str = "inbound"
    headers: Dict[str, Any] = {}
    body_preview: str = ""
    body: str = ""
    attachment_names: List[str] = []
    attachment_hashes: List[str] = []
    message_id: Optional[str] = None


class QuarantineReleaseRequest(BaseModel):
    """Release quarantined message."""
    released_by: str


class PolicyCreateRequest(BaseModel):
    """Create email policy."""
    client_id: str
    name: str
    policy_type: str = "spam_filter"
    config: Dict[str, Any] = {}
    priority: int = 100
    actions: List[str] = ["quarantine"]


class PolicyUpdateRequest(BaseModel):
    """Update email policy."""
    name: Optional[str] = None
    policy_type: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None
    priority: Optional[int] = None
    actions: Optional[List[str]] = None


class DLPRuleCreateRequest(BaseModel):
    """Create DLP rule."""
    policy_id: str
    name: str
    pattern_type: str = "regex"
    pattern: str = ""
    action: str = "alert"
    severity: str = "medium"


class DLPTestRequest(BaseModel):
    """Test DLP rules against text."""
    text: str


class FeedUpdateRequest(BaseModel):
    """Update threat feed."""
    name: Optional[str] = None
    entries: Optional[List[str]] = None


class FalseReportRequest(BaseModel):
    """Report false positive/negative."""
    message_id: str


# ========== Email Scanning ==========

@router.post("/scan")
async def scan_email(data: ScanEmailRequest):
    """Scan an email through the full analysis pipeline."""
    result = email_security_service.scan_email(data.dict())
    return result


@router.get("/messages")
async def list_messages(
    client_id: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    direction: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List scanned email messages with filters."""
    return email_security_service.list_messages(
        client_id=client_id, verdict=verdict,
        direction=direction, limit=limit, offset=offset,
    )


@router.get("/messages/{message_id}")
async def get_message(message_id: str):
    """Get a single scanned message by ID."""
    result = email_security_service.get_message(message_id)
    if not result:
        raise HTTPException(status_code=404, detail="Message not found")
    return result


# ========== Quarantine Management ==========

@router.get("/quarantine")
async def list_quarantine(
    client_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List quarantined messages."""
    return email_security_service.get_quarantine(
        client_id=client_id, status=status, limit=limit, offset=offset,
    )


@router.get("/quarantine/stats")
async def quarantine_stats():
    """Get quarantine statistics."""
    return email_security_service.get_quarantine_stats()


@router.post("/quarantine/{message_id}")
async def quarantine_message(message_id: str, reason: str = Query("Manual quarantine")):
    """Manually quarantine a message."""
    entry = email_security_service.quarantine_message(message_id, reason)
    if not entry:
        raise HTTPException(status_code=404, detail="Message not found")
    return {"entry_id": entry.entry_id, "status": "quarantined"}


@router.post("/quarantine/{entry_id}/release")
async def release_quarantine(entry_id: str, data: QuarantineReleaseRequest):
    """Release a message from quarantine."""
    entry = email_security_service.release_message(entry_id, data.released_by)
    if not entry:
        raise HTTPException(status_code=404, detail="Quarantine entry not found")
    return {"entry_id": entry.entry_id, "status": "released"}


@router.delete("/quarantine/{entry_id}")
async def delete_quarantine(entry_id: str):
    """Permanently delete a quarantined message."""
    ok = email_security_service.delete_quarantined(entry_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Quarantine entry not found")
    return {"entry_id": entry_id, "status": "deleted"}


# ========== Policy Management ==========

@router.post("/policies")
async def create_policy(data: PolicyCreateRequest):
    """Create an email security policy."""
    policy = email_security_service.create_policy(
        client_id=data.client_id,
        name=data.name,
        policy_type=data.policy_type,
        config=data.config,
        priority=data.priority,
        actions=data.actions,
    )
    return email_security_service._policy_to_dict(policy)


@router.get("/policies")
async def list_policies(client_id: Optional[str] = Query(None)):
    """List email security policies."""
    return email_security_service.list_policies(client_id=client_id)


@router.put("/policies/{policy_id}")
async def update_policy(policy_id: str, data: PolicyUpdateRequest):
    """Update an email security policy."""
    updates = {k: v for k, v in data.dict().items() if v is not None}
    policy = email_security_service.update_policy(policy_id, **updates)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return email_security_service._policy_to_dict(policy)


@router.post("/policies/{policy_id}/toggle")
async def toggle_policy(policy_id: str):
    """Toggle a policy enabled/disabled."""
    result = email_security_service.toggle_policy(policy_id)
    if not result:
        raise HTTPException(status_code=404, detail="Policy not found")
    return result


# ========== DLP Rules ==========

@router.post("/dlp-rules")
async def create_dlp_rule(data: DLPRuleCreateRequest):
    """Create a DLP rule."""
    rule = email_security_service.create_dlp_rule(
        policy_id=data.policy_id,
        name=data.name,
        pattern_type=data.pattern_type,
        pattern=data.pattern,
        action=data.action,
        severity=data.severity,
    )
    return email_security_service._dlp_to_dict(rule)


@router.get("/dlp-rules")
async def list_dlp_rules(policy_id: Optional[str] = Query(None)):
    """List DLP rules."""
    return email_security_service.list_dlp_rules(policy_id=policy_id)


@router.post("/dlp-rules/test")
async def test_dlp_rules(data: DLPTestRequest):
    """Test DLP rules against sample text."""
    return email_security_service.test_dlp_rule(data.text)


# ========== Threat Feeds ==========

@router.get("/feeds")
async def list_feeds():
    """List threat intelligence feeds."""
    return email_security_service.list_feeds()


@router.put("/feeds/{feed_id}")
async def update_feed(feed_id: str, data: FeedUpdateRequest):
    """Update a threat feed."""
    updates = {k: v for k, v in data.dict().items() if v is not None and k != "entries"}
    result = email_security_service.update_feed(feed_id, entries=data.entries, **updates)
    if not result:
        raise HTTPException(status_code=404, detail="Feed not found")
    return result


# ========== False Positive / Negative Reporting ==========

@router.post("/report/false-positive")
async def report_false_positive(data: FalseReportRequest):
    """Report a message as false positive."""
    return email_security_service.report_false_positive(data.message_id)


@router.post("/report/false-negative")
async def report_false_negative(data: FalseReportRequest):
    """Report a message as false negative."""
    return email_security_service.report_false_negative(data.message_id)


# ========== Statistics & Dashboard ==========

@router.get("/stats")
async def get_email_stats(
    client_id: Optional[str] = Query(None),
    period: str = Query("24h"),
):
    """Get email security statistics."""
    return email_security_service.get_email_stats(client_id=client_id, period=period)


@router.get("/stats/targeted-users")
async def get_targeted_users(
    client_id: str = Query(...),
    limit: int = Query(10, ge=1, le=50),
):
    """Get most targeted (phished) users for a client."""
    return email_security_service.get_top_targeted_users(client_id, limit=limit)


@router.get("/dashboard")
async def get_dashboard():
    """Get email security dashboard overview."""
    return email_security_service.get_dashboard()
