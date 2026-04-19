"""
AITHER Platform - Email Security Gateway Persistence Models

Tables for email messages, phishing indicators, quarantine entries,
email policies, and DLP rules.

G-46 pattern: DB persistence with in-memory fallback.
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
# Email Security - Email Messages
# ============================================================

class EmailMessageModel(Base):
    """Scanned email message record."""
    __tablename__ = "email_messages"

    id = Column(String(36), primary_key=True, default=_uuid)
    message_id = Column(String(64), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    direction = Column(String(20), nullable=False, default="inbound")
    sender = Column(String(300), nullable=False)
    recipient = Column(String(300), nullable=False)
    subject = Column(String(500), default="")
    has_attachments = Column(Boolean, default=False)
    attachment_names = Column(JSON, default=list)
    attachment_hashes = Column(JSON, default=list)
    headers = Column(JSON, default=dict)
    body_preview = Column(Text, default="")

    verdict = Column(String(30), default="clean", index=True)
    confidence = Column(Float, default=0.0)
    processing_time_ms = Column(Integer, default=0)
    rules_matched = Column(JSON, default=list)
    indicators = Column(JSON, default=list)

    received_at = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_email_msg_client_verdict", "client_id", "verdict"),
        Index("ix_email_msg_direction", "direction"),
        Index("ix_email_msg_received", "received_at"),
    )


# ============================================================
# Email Security - Phishing Indicators
# ============================================================

class PhishingIndicatorModel(Base):
    """Phishing indicator detected in a message."""
    __tablename__ = "email_phishing_indicators"

    id = Column(String(36), primary_key=True, default=_uuid)
    indicator_id = Column(String(64), unique=True, nullable=False, index=True)
    message_id = Column(String(64), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(20), default="medium")
    confidence = Column(Float, default=0.0)

    created_at = Column(DateTime, default=func.now())


# ============================================================
# Email Security - Quarantine Entries
# ============================================================

class QuarantineEntryModel(Base):
    """Quarantined email entry."""
    __tablename__ = "email_quarantine"

    id = Column(String(36), primary_key=True, default=_uuid)
    entry_id = Column(String(64), unique=True, nullable=False, index=True)
    message_id = Column(String(64), nullable=False, index=True)
    reason = Column(String(200), nullable=False)
    original_recipient = Column(String(300), default="")
    status = Column(String(30), default="quarantined", index=True)
    quarantined_at = Column(DateTime, default=func.now())
    released_by = Column(String(200), nullable=True)
    released_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_quarantine_status", "status"),
    )


# ============================================================
# Email Security - Email Policies
# ============================================================

class EmailPolicyModel(Base):
    """Email security policy."""
    __tablename__ = "email_policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(String(64), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    policy_type = Column(String(50), nullable=False)
    config = Column(JSON, default=dict)
    is_enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=100)
    actions = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_email_policy_client_type", "client_id", "policy_type"),
    )


# ============================================================
# Email Security - DLP Rules
# ============================================================

class DLPRuleModel(Base):
    """Data Loss Prevention rule."""
    __tablename__ = "email_dlp_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    rule_id = Column(String(64), unique=True, nullable=False, index=True)
    policy_id = Column(String(64), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    pattern_type = Column(String(30), nullable=False)
    pattern = Column(Text, default="")
    action = Column(String(30), default="alert")
    severity = Column(String(20), default="medium")
    is_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
