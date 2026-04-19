"""
Notification Connector API Routes

External alerting for the Aither MSP platform.
- Channel CRUD (email, Slack, PagerDuty, MS Teams, webhook, SMS)
- Rule CRUD (event-type routing with severity filters and cooldowns)
- Test channel connectivity
- Manual notification send
- Delivery log and dashboard stats
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

from middleware.auth import get_current_user, require_admin
from sqlalchemy.orm import Session
from core.database import get_sync_db
from services.integrations.notification_connector import (
    get_notification_connector,
    NotificationConnectorService,
    ChannelType,
    EventType,
    SeverityLevel,
)

router = APIRouter(prefix="/api/v1/notifications", tags=["Notification Connector"])


# ==================== REQUEST MODELS ====================

class ChannelCreate(BaseModel):
    """Create a notification channel"""
    channel_type: str = Field(..., description="email, slack, pagerduty, msteams, webhook, sms")
    name: str = Field(..., description="Human-readable channel name")
    config: Dict[str, Any] = Field(default_factory=dict, description="Channel-specific configuration")
    is_enabled: bool = True


class ChannelUpdate(BaseModel):
    """Update a notification channel"""
    name: Optional[str] = None
    channel_type: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None


class RuleCreate(BaseModel):
    """Create a notification rule"""
    name: str = Field(..., description="Rule name")
    event_types: List[str] = Field(..., description="Event types to match")
    channels: List[str] = Field(..., description="Channel IDs to route to")
    severity_filter: str = Field(default="all", description="Severity filter (critical, high, medium, low, info, all)")
    is_enabled: bool = True
    cooldown_minutes: int = Field(default=5, ge=0, description="Minutes between re-triggers")


class RuleUpdate(BaseModel):
    """Update a notification rule"""
    name: Optional[str] = None
    event_types: Optional[List[str]] = None
    channels: Optional[List[str]] = None
    severity_filter: Optional[str] = None
    is_enabled: Optional[bool] = None
    cooldown_minutes: Optional[int] = None


class ManualNotification(BaseModel):
    """Send a manual notification"""
    event_type: str = Field(..., description="Event type")
    severity: str = Field(default="info", description="Severity level")
    subject: str = Field(..., description="Notification subject")
    body: str = Field(..., description="Notification body")
    metadata: Optional[Dict[str, Any]] = None


# ==================== CHANNEL ENDPOINTS ====================

@router.post("/channels")
def create_channel(request: ChannelCreate, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """
    Create a new notification channel.

    Supported types: email, slack, pagerduty, msteams, webhook, sms.
    Each type requires specific config keys (see channel type docs).
    """
    try:
        ChannelType(request.channel_type)
    except ValueError:
        valid = [t.value for t in ChannelType]
        raise HTTPException(status_code=400, detail=f"Invalid channel_type. Valid: {valid}")

    svc = get_notification_connector()
    result = svc.create_channel(
        channel_type=request.channel_type,
        name=request.name,
        config=request.config,
        is_enabled=request.is_enabled,
    )
    return result


@router.get("/channels")
def list_channels(
    channel_type: Optional[str] = Query(None, description="Filter by type"),
    enabled_only: bool = Query(False, description="Only enabled channels"),
    db: Session = Depends(get_sync_db),
):
    """List all notification channels with optional filters."""
    svc = get_notification_connector()
    channels = svc.list_channels(channel_type=channel_type, enabled_only=enabled_only)
    return {"channels": channels, "count": len(channels)}


@router.get("/channels/{channel_id}")
def get_channel(channel_id: str, db: Session = Depends(get_sync_db)):
    """Get a single notification channel by ID."""
    svc = get_notification_connector()
    channel = svc.get_channel(channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    return channel


@router.put("/channels/{channel_id}")
def update_channel(channel_id: str, request: ChannelUpdate, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Update a notification channel."""
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    if "channel_type" in updates:
        try:
            ChannelType(updates["channel_type"])
        except ValueError:
            valid = [t.value for t in ChannelType]
            raise HTTPException(status_code=400, detail=f"Invalid channel_type. Valid: {valid}")

    svc = get_notification_connector()
    result = svc.update_channel(channel_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Channel not found")
    return result


@router.delete("/channels/{channel_id}")
def delete_channel(channel_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Delete a notification channel."""
    svc = get_notification_connector()
    success = svc.delete_channel(channel_id)
    if not success:
        raise HTTPException(status_code=404, detail="Channel not found")
    return {"success": True, "channel_id": channel_id, "deleted_at": datetime.utcnow().isoformat()}


@router.post("/test/{channel_id}")
def test_channel(channel_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """
    Send a test notification through a channel.

    Verifies connectivity without creating a rule or log entry.
    """
    svc = get_notification_connector()
    result = svc.test_channel(channel_id)
    if not result.get("success"):
        raise HTTPException(status_code=502, detail=result.get("error", "Test failed"))
    return result


# ==================== RULE ENDPOINTS ====================

@router.post("/rules")
def create_rule(request: RuleCreate, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """
    Create a notification routing rule.

    Maps event types and severity filters to one or more channels.
    Cooldown prevents repeated triggers within the configured window.
    """
    svc = get_notification_connector()
    result = svc.create_rule(
        name=request.name,
        event_types=request.event_types,
        channels=request.channels,
        severity_filter=request.severity_filter,
        is_enabled=request.is_enabled,
        cooldown_minutes=request.cooldown_minutes,
    )
    return result


@router.get("/rules")
def list_rules(
    enabled_only: bool = Query(False, description="Only enabled rules"),
    db: Session = Depends(get_sync_db),
):
    """List all notification rules."""
    svc = get_notification_connector()
    rules = svc.list_rules(enabled_only=enabled_only)
    return {"rules": rules, "count": len(rules)}


@router.put("/rules/{rule_id}")
def update_rule(rule_id: str, request: RuleUpdate, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Update a notification rule."""
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    svc = get_notification_connector()
    result = svc.update_rule(rule_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Delete a notification rule."""
    svc = get_notification_connector()
    success = svc.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"success": True, "rule_id": rule_id, "deleted_at": datetime.utcnow().isoformat()}


# ==================== NOTIFICATION SEND ====================

@router.post("/send")
def send_notification(request: ManualNotification, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """
    Manually send a notification through all matching rules.

    The event is routed through the same rule-matching and throttling
    logic as automatic platform events.
    """
    svc = get_notification_connector()
    result = svc.send_notification(
        event_type=request.event_type,
        severity=request.severity,
        subject=request.subject,
        body=request.body,
        metadata=request.metadata,
    )
    return result


# ==================== LOG & DASHBOARD ====================

@router.get("/log")
def get_notification_log(
    rule_id: Optional[str] = Query(None),
    channel_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_sync_db),
):
    """
    Query notification delivery history.

    Supports filtering by rule, channel, event type, and delivery status.
    """
    svc = get_notification_connector()
    logs = svc.get_notification_log(
        rule_id=rule_id,
        channel_id=channel_id,
        event_type=event_type,
        status=status,
        limit=limit,
    )
    return {"logs": logs, "count": len(logs)}


@router.get("/dashboard")
def get_dashboard(db: Session = Depends(get_sync_db)):
    """
    Notification dashboard with aggregate statistics.

    Returns channel counts, rule counts, delivery stats, and
    breakdowns by channel type and event type.
    """
    svc = get_notification_connector()
    return svc.get_dashboard()


# ==================== REFERENCE ENDPOINTS ====================

@router.get("/channel-types")
def list_channel_types(db: Session = Depends(get_sync_db)):
    """List supported notification channel types."""
    descriptions = {
        ChannelType.EMAIL: "Email via SMTP (config: smtp_host, smtp_port, smtp_user, smtp_password, from_address, to_addresses)",
        ChannelType.SLACK: "Slack incoming webhook (config: webhook_url, channel, username)",
        ChannelType.PAGERDUTY: "PagerDuty Events API v2 (config: routing_key, severity)",
        ChannelType.MSTEAMS: "Microsoft Teams incoming webhook (config: webhook_url)",
        ChannelType.WEBHOOK: "Generic HTTP webhook (config: url, method, headers, secret)",
        ChannelType.SMS: "SMS via Twilio (config: account_sid, auth_token, from_number, to_numbers)",
    }
    return {
        "channel_types": [
            {"value": t.value, "name": t.name, "description": descriptions.get(t, "")}
            for t in ChannelType
        ]
    }


@router.get("/event-types")
def list_event_types(db: Session = Depends(get_sync_db)):
    """List MSP event types that can trigger notifications."""
    descriptions = {
        EventType.THREAT_DETECTED: "Security threat detected by Cyber-911 or Shield",
        EventType.INCIDENT_CREATED: "New security or service incident created",
        EventType.ENDPOINT_OFFLINE: "Monitored endpoint went offline",
        EventType.SLA_BREACH: "Service level agreement deadline breached",
        EventType.PATCH_FAILED: "Patch deployment failed on endpoint",
        EventType.SELF_HEAL_FAILED: "Self-healing remediation attempt failed",
        EventType.BACKUP_FAILED: "Scheduled backup job failed",
        EventType.COMPLIANCE_VIOLATION: "Compliance policy violation detected",
    }
    return {
        "event_types": [
            {"value": t.value, "name": t.name, "description": descriptions.get(t, "")}
            for t in EventType
        ]
    }


@router.get("/health")
def health_check(db: Session = Depends(get_sync_db)):
    """Health check for the Notification Connector service."""
    svc = get_notification_connector()
    dashboard = svc.get_dashboard()
    return {
        "status": "healthy",
        "total_channels": dashboard["total_channels"],
        "enabled_channels": dashboard["enabled_channels"],
        "total_rules": dashboard["total_rules"],
        "checked_at": datetime.utcnow().isoformat(),
    }
