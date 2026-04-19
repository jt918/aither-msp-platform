"""
AITHER Platform - DNS Filtering Persistence Models

Tables for DNS policies, query logs, domain categories, and blocklist entries.
Provides DNS-level security and content filtering for MSP clients.
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


class DNSPolicyModel(Base):
    """DNS filtering policy for a client."""
    __tablename__ = "dns_policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    blocked_categories = Column(JSON, default=list)
    allowed_overrides = Column(JSON, default=list)
    custom_blocklist = Column(JSON, default=list)
    custom_allowlist = Column(JSON, default=list)
    safe_search_enforced = Column(Boolean, default=False)
    logging_enabled = Column(Boolean, default=True)
    block_page_url = Column(String(500), default="")
    is_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_dns_policy_client_enabled", "client_id", "is_enabled"),
    )


class DNSQueryLogModel(Base):
    """DNS query log entry."""
    __tablename__ = "dns_query_logs"

    id = Column(String(36), primary_key=True, default=_uuid)
    log_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    source_ip = Column(String(50), nullable=False)
    device_id = Column(String(100), default="")
    query_domain = Column(String(500), nullable=False, index=True)
    query_type = Column(String(10), default="A")
    category = Column(String(50), default="unknown")
    action = Column(String(20), nullable=False, index=True)
    policy_id = Column(String(30), default="")
    response_time_ms = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=func.now(), index=True)

    __table_args__ = (
        Index("ix_dns_qlog_client_ts", "client_id", "timestamp"),
        Index("ix_dns_qlog_action_ts", "action", "timestamp"),
    )


class DomainCategoryModel(Base):
    """Domain categorization record."""
    __tablename__ = "dns_domain_categories"

    id = Column(String(36), primary_key=True, default=_uuid)
    domain = Column(String(500), unique=True, nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    subcategory = Column(String(50), default="")
    confidence = Column(Float, default=1.0)
    source = Column(String(50), default="manual")
    last_verified = Column(DateTime, default=func.now())

    created_at = Column(DateTime, default=func.now())


class BlocklistEntryModel(Base):
    """Blocklist / allowlist entry."""
    __tablename__ = "dns_blocklist_entries"

    id = Column(String(36), primary_key=True, default=_uuid)
    entry_id = Column(String(30), unique=True, nullable=False, index=True)
    domain_pattern = Column(String(500), nullable=False, index=True)
    list_type = Column(String(20), nullable=False, index=True)  # blocklist / allowlist
    reason = Column(Text, default="")
    source = Column(String(30), default="manual")  # manual / feed / threat_intel
    added_by = Column(String(200), default="system")
    added_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_dns_bl_type_domain", "list_type", "domain_pattern"),
    )
