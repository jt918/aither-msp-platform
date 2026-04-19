"""
AITHER Platform - Threat Scoring Persistence Models

Tables for entity scores, score events, thresholds, reputation feeds,
and score history snapshots.
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


class EntityScoreModel(Base):
    """Tracked entity with trust/threat scores."""
    __tablename__ = "threat_entity_scores"

    id = Column(String(36), primary_key=True, default=_uuid)
    score_id = Column(String(36), unique=True, nullable=False, index=True)
    entity_type = Column(String(30), nullable=False, index=True)
    entity_value = Column(String(500), nullable=False, index=True)
    trust_score = Column(Float, default=50.0)
    threat_score = Column(Float, default=50.0)
    risk_level = Column(String(20), default="medium", index=True)
    score_factors = Column(JSON, default=list)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now())
    total_events = Column(Integer, default=0)
    positive_events = Column(Integer, default=0)
    negative_events = Column(Integer, default=0)
    is_whitelisted = Column(Boolean, default=False)
    is_blacklisted = Column(Boolean, default=False)
    auto_block_triggered = Column(Boolean, default=False)
    geo_data = Column(JSON, default=dict)
    decay_rate = Column(Float, default=1.0)

    __table_args__ = (
        Index("ix_threat_entity_type_value", "entity_type", "entity_value"),
        Index("ix_threat_entity_risk", "risk_level", "threat_score"),
    )


class ScoreEventModel(Base):
    """Individual scoring event."""
    __tablename__ = "threat_score_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    event_id = Column(String(36), unique=True, nullable=False, index=True)
    entity_value = Column(String(500), nullable=False, index=True)
    entity_type = Column(String(30), nullable=False)
    event_type = Column(String(20), nullable=False, index=True)
    impact_points = Column(Float, default=0.0)
    reason = Column(String(500), default="")
    source_service = Column(String(200), default="")
    raw_data = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=func.now(), index=True)

    __table_args__ = (
        Index("ix_threat_event_entity", "entity_value", "timestamp"),
    )


class ScoreThresholdModel(Base):
    """Threshold configuration for auto-actions."""
    __tablename__ = "threat_score_thresholds"

    id = Column(String(36), primary_key=True, default=_uuid)
    threshold_id = Column(String(36), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    risk_level = Column(String(20), nullable=False)
    trust_score_min = Column(Float, default=0.0)
    trust_score_max = Column(Float, default=100.0)
    threat_score_min = Column(Float, default=0.0)
    threat_score_max = Column(Float, default=100.0)
    auto_action = Column(String(30), default="none")
    notification_channel = Column(String(200), default="")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class ReputationFeedModel(Base):
    """External reputation / blocklist feed."""
    __tablename__ = "threat_reputation_feeds"

    id = Column(String(36), primary_key=True, default=_uuid)
    feed_id = Column(String(36), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    feed_type = Column(String(30), nullable=False)
    source_url = Column(String(1000), default="")
    format = Column(String(50), default="plaintext")
    last_updated = Column(DateTime, nullable=True)
    entries_count = Column(Integer, default=0)
    is_enabled = Column(Boolean, default=True)
    update_interval_hours = Column(Integer, default=24)
    created_at = Column(DateTime, default=func.now())


class ScoreHistoryModel(Base):
    """Point-in-time score snapshot."""
    __tablename__ = "threat_score_history"

    id = Column(String(36), primary_key=True, default=_uuid)
    history_id = Column(String(36), unique=True, nullable=False, index=True)
    entity_value = Column(String(500), nullable=False, index=True)
    trust_score = Column(Float, default=50.0)
    threat_score = Column(Float, default=50.0)
    risk_level = Column(String(20), default="medium")
    snapshot_at = Column(DateTime, default=func.now(), index=True)

    __table_args__ = (
        Index("ix_threat_history_entity_time", "entity_value", "snapshot_at"),
    )
