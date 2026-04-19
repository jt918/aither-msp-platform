"""
AITHER Platform - Notification Connector Persistence Models

Tables for notification channels, rules, and delivery logs.
Supports email, Slack, PagerDuty, MS Teams, webhooks, and SMS.
"""

from sqlalchemy import (
    Column, String, Integer, Boolean, Text, DateTime, JSON,
    Index,
)
from sqlalchemy.sql import func
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


class NotificationChannelModel(Base):
    """Configured notification channel (email, Slack, webhook, etc.)."""
    __tablename__ = "notification_channels"

    id = Column(String(36), primary_key=True, default=_uuid)
    channel_id = Column(String(50), unique=True, nullable=False, index=True)
    channel_type = Column(String(20), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    config = Column(JSON, default=dict)
    is_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class NotificationRuleModel(Base):
    """Notification routing rule mapping events to channels."""
    __tablename__ = "notification_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    rule_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    event_types = Column(JSON, default=list)
    severity_filter = Column(String(20), default="all", index=True)
    channels = Column(JSON, default=list)
    is_enabled = Column(Boolean, default=True)
    cooldown_minutes = Column(Integer, default=5)
    last_triggered = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class NotificationLogModel(Base):
    """Delivery log for sent/failed/throttled notifications."""
    __tablename__ = "notification_logs"

    id = Column(String(36), primary_key=True, default=_uuid)
    log_id = Column(String(50), unique=True, nullable=False, index=True)
    rule_id = Column(String(50), nullable=False, index=True)
    channel_id = Column(String(50), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="info")
    subject = Column(String(300), default="")
    body = Column(Text, default="")
    status = Column(String(20), default="sent", index=True)
    error = Column(Text, default="")

    sent_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_notif_log_rule_status", "rule_id", "status"),
    )
