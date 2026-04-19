"""
AITHER Platform - SIEM Ingest Persistence Models

Tables for SIEM sources, raw events, parse rules, and correlation rules.
Feeds normalized events into the Cyber-911 incident response pipeline.

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
# SIEM Sources
# ============================================================

class SIEMSource(Base):
    """Registered SIEM event source."""
    __tablename__ = "siem_sources"

    id = Column(String(36), primary_key=True, default=_uuid)
    source_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    source_type = Column(String(30), nullable=False, index=True)
    config = Column(JSON, default=dict)
    is_enabled = Column(Boolean, default=True)
    events_received = Column(Integer, default=0)
    events_processed = Column(Integer, default=0)
    last_event_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Raw Events
# ============================================================

class RawEvent(Base):
    """Ingested raw security event."""
    __tablename__ = "siem_raw_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    event_id = Column(String(50), unique=True, nullable=False, index=True)
    source_id = Column(String(50), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    raw_data = Column(JSON, default=dict)
    parsed = Column(Boolean, default=False, index=True)
    event_type = Column(String(100), default="")
    severity_raw = Column(String(50), default="")
    severity_normalized = Column(String(20), default="")
    source_ip = Column(String(50), default="")
    dest_ip = Column(String(50), default="")
    hostname = Column(String(200), default="")
    user = Column(String(200), default="")
    message = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_siem_event_ts_source", "timestamp", "source_id"),
        Index("ix_siem_event_type_sev", "event_type", "severity_normalized"),
    )


# ============================================================
# Parse Rules
# ============================================================

class ParseRule(Base):
    """Event parsing / normalization rule for a source type."""
    __tablename__ = "siem_parse_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    rule_id = Column(String(50), unique=True, nullable=False, index=True)
    source_type = Column(String(30), nullable=False, index=True)
    field_mappings = Column(JSON, default=dict)
    severity_mapping = Column(JSON, default=dict)
    event_type_mapping = Column(JSON, default=dict)
    is_default = Column(Boolean, default=False)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Correlation Rules
# ============================================================

class CorrelationRule(Base):
    """Event correlation rule that can trigger Cyber-911 incidents."""
    __tablename__ = "siem_correlation_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    rule_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    conditions = Column(JSON, default=list)
    time_window_seconds = Column(Integer, default=300)
    min_events = Column(Integer, default=1)
    action = Column(String(30), default="create_incident")
    severity = Column(String(20), default="HIGH")
    threat_type = Column(String(50), default="")
    is_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
