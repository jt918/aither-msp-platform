"""
dynamic_deception.py — Dynamic Honeypot & Canary Deployment persistence models

Tables for deception assets, honeypot services, canary tokens, deception rules,
interaction logs, and intelligence reports.

Created: 2026-04-19 (Dynamic Deception module)
Purpose: DB persistence for the Dynamic Deception Engine (MSP defense layer).
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, Index, JSON,
)
from core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc)


class DeceptionAssetModel(Base):
    """A deception asset (honeypot, canary token, honeyfile, etc.)."""
    __tablename__ = "deception_assets"

    id = Column(String(36), primary_key=True, default=_uuid)
    asset_id = Column(String(100), unique=True, nullable=False, index=True)
    asset_type = Column(String(30), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    deployment_target = Column(String(500), default="")
    config = Column(JSON, default=dict)
    status = Column(String(20), default="staged", index=True)
    interaction_count = Column(Integer, default=0)
    last_interaction_at = Column(DateTime, nullable=True)
    intelligence_gathered = Column(JSON, default=list)
    deployed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now)

    __table_args__ = (
        Index("ix_deception_type_status", "asset_type", "status"),
    )


class HoneypotServiceModel(Base):
    """A honeypot service bound to a deception asset."""
    __tablename__ = "honeypot_services"

    id = Column(String(36), primary_key=True, default=_uuid)
    honeypot_id = Column(String(100), unique=True, nullable=False, index=True)
    asset_id = Column(String(100), nullable=False, index=True)
    service_type = Column(String(30), nullable=False, index=True)
    listen_port = Column(Integer, nullable=False)
    listen_ip = Column(String(50), default="0.0.0.0")
    banner = Column(Text, default="")
    credentials = Column(JSON, default=list)
    response_templates = Column(JSON, default=dict)
    capture_level = Column(String(30), default="auth_capture")
    max_sessions = Column(Integer, default=10)
    created_at = Column(DateTime, default=_now)


class CanaryTokenModel(Base):
    """A canary token planted for detection."""
    __tablename__ = "canary_tokens"

    id = Column(String(36), primary_key=True, default=_uuid)
    token_id = Column(String(100), unique=True, nullable=False, index=True)
    asset_id = Column(String(100), nullable=False, index=True)
    token_type = Column(String(30), nullable=False, index=True)
    token_value = Column(String(500), nullable=False, index=True)
    deployment_location = Column(String(500), default="")
    trigger_webhook = Column(String(500), default="")
    triggered_count = Column(Integer, default=0)
    last_triggered_at = Column(DateTime, nullable=True)
    triggered_by = Column(JSON, default=list)
    created_at = Column(DateTime, default=_now)


class DeceptionRuleModel(Base):
    """Automated deception deployment rule."""
    __tablename__ = "deception_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    rule_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    trigger_condition = Column(JSON, default=dict)
    risk_threshold = Column(Float, default=7.0)
    target_entity_type = Column(String(30), default="ip")
    action = Column(String(50), default="deploy_honeypot")
    deception_asset_id = Column(String(100), nullable=True)
    cooldown_minutes = Column(Integer, default=60)
    is_enabled = Column(Boolean, default=True)
    executions = Column(Integer, default=0)
    last_executed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now)


class InteractionLogModel(Base):
    """Log of attacker interaction with a deception asset."""
    __tablename__ = "deception_interaction_logs"

    id = Column(String(36), primary_key=True, default=_uuid)
    log_id = Column(String(100), unique=True, nullable=False, index=True)
    asset_id = Column(String(100), nullable=False, index=True)
    source_ip = Column(String(50), nullable=True, index=True)
    source_user = Column(String(255), nullable=True)
    interaction_type = Column(String(30), nullable=False, index=True)
    raw_data = Column(JSON, default=dict)
    credentials_used = Column(String(500), nullable=True)
    commands_executed = Column(JSON, default=list)
    files_accessed = Column(JSON, default=list)
    duration_seconds = Column(Float, default=0.0)
    intelligence_value = Column(String(20), default="low")
    timestamp = Column(DateTime, default=_now, index=True)


class IntelligenceReportModel(Base):
    """Intelligence report generated from deception interactions."""
    __tablename__ = "deception_intelligence_reports"

    id = Column(String(36), primary_key=True, default=_uuid)
    report_id = Column(String(100), unique=True, nullable=False, index=True)
    asset_id = Column(String(100), nullable=False, index=True)
    report_type = Column(String(30), nullable=False)
    title = Column(String(500), nullable=False)
    findings = Column(JSON, default=dict)
    iocs_extracted = Column(JSON, default=list)
    ttps_observed = Column(JSON, default=list)
    attacker_profile = Column(JSON, default=dict)
    generated_at = Column(DateTime, default=_now)
