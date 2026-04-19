"""
AITHER Platform - UEBA Persistence Models

Tables for User & Entity Behavior Analytics:
- UserBehaviorProfile: entity profiles with risk scores and baselines
- BehaviorEvent: recorded actions/events per entity
- BehavioralBaseline: statistical baselines per metric
- AnomalyDetection: detected anomalies with severity
- ThreatIndicator: correlated threat indicators (MITRE-mapped)
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


class UserBehaviorProfileModel(Base):
    """Entity behavior profile for UEBA analytics."""
    __tablename__ = "ueba_profiles"

    id = Column(String(36), primary_key=True, default=_uuid)
    profile_id = Column(String(30), unique=True, nullable=False, index=True)
    entity_type = Column(String(30), nullable=False, index=True)
    entity_id = Column(String(200), nullable=False, index=True)
    entity_name = Column(String(300), default="")
    client_id = Column(String(100), default="", index=True)
    baseline_established = Column(Boolean, default=False)
    baseline_data = Column(JSON, default=dict)
    risk_score = Column(Float, default=0.0, index=True)
    risk_level = Column(String(20), default="low", index=True)
    total_events = Column(Integer, default=0)
    anomaly_count = Column(Integer, default=0)
    last_activity_at = Column(DateTime, nullable=True)
    first_seen_at = Column(DateTime, default=func.now())
    tags = Column(JSON, default=list)
    is_watchlisted = Column(Boolean, default=False, index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_ueba_prof_entity", "entity_type", "entity_id"),
        Index("ix_ueba_prof_risk", "risk_level", "risk_score"),
    )


class BehaviorEventModel(Base):
    """Recorded behavior event for UEBA analysis."""
    __tablename__ = "ueba_events"

    id = Column(String(36), primary_key=True, default=_uuid)
    event_id = Column(String(30), unique=True, nullable=False, index=True)
    profile_id = Column(String(30), nullable=False, index=True)
    entity_id = Column(String(200), nullable=False)
    event_type = Column(String(50), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=func.now())
    source_ip = Column(String(50), default="")
    destination_ip = Column(String(50), default="")
    user_agent = Column(Text, default="")
    geo_location = Column(JSON, default=dict)
    device_fingerprint = Column(String(200), default="")
    session_id = Column(String(100), default="")
    resource_accessed = Column(String(500), default="")
    action_performed = Column(String(200), default="")
    outcome = Column(String(20), default="success")
    metadata = Column(JSON, default=dict)
    risk_contribution = Column(Float, default=0.0)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_ueba_evt_entity_ts", "entity_id", "timestamp"),
        Index("ix_ueba_evt_srcip_ts", "source_ip", "timestamp"),
        Index("ix_ueba_evt_profile_type", "profile_id", "event_type"),
    )


class BehavioralBaselineModel(Base):
    """Statistical baseline for a profile metric."""
    __tablename__ = "ueba_baselines"

    id = Column(String(36), primary_key=True, default=_uuid)
    baseline_id = Column(String(30), unique=True, nullable=False, index=True)
    profile_id = Column(String(30), nullable=False, index=True)
    metric_name = Column(String(100), nullable=False)
    expected_value = Column(Float, default=0.0)
    std_deviation = Column(Float, default=0.0)
    sample_count = Column(Integer, default=0)
    confidence = Column(Float, default=0.0)
    last_updated = Column(DateTime, default=func.now())
    time_window = Column(String(20), default="daily")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_ueba_bl_profile_metric", "profile_id", "metric_name"),
    )


class AnomalyDetectionModel(Base):
    """Detected behavioral anomaly."""
    __tablename__ = "ueba_anomalies"

    id = Column(String(36), primary_key=True, default=_uuid)
    anomaly_id = Column(String(30), unique=True, nullable=False, index=True)
    profile_id = Column(String(30), nullable=False, index=True)
    event_id = Column(String(30), default="", index=True)
    anomaly_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    description = Column(Text, default="")
    deviation_score = Column(Float, default=0.0)
    baseline_value = Column(Float, default=0.0)
    observed_value = Column(Float, default=0.0)
    is_confirmed = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    auto_response_taken = Column(JSON, default=list)
    detected_at = Column(DateTime, default=func.now())
    reviewed_at = Column(DateTime, nullable=True)
    reviewed_by = Column(String(200), default="")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_ueba_anom_profile_sev", "profile_id", "severity"),
        Index("ix_ueba_anom_type_detected", "anomaly_type", "detected_at"),
    )


class ThreatIndicatorModel(Base):
    """Correlated threat indicator with MITRE ATT&CK mapping."""
    __tablename__ = "ueba_threats"

    id = Column(String(36), primary_key=True, default=_uuid)
    indicator_id = Column(String(30), unique=True, nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False, index=True)
    related_profiles = Column(JSON, default=list)
    related_events = Column(JSON, default=list)
    confidence = Column(Float, default=0.0)
    severity = Column(String(20), nullable=False, index=True)
    ttps = Column(JSON, default=list)
    is_active = Column(Boolean, default=True, index=True)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())
    description = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_ueba_threat_type_active", "indicator_type", "is_active"),
    )
