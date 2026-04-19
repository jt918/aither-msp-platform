"""
AITHER Platform - Cloud Infrastructure Monitoring Persistence Models

Tables for cloud accounts, resources, cost entries, security findings, and alerts.
Supports AWS/Azure/GCP multi-cloud monitoring for MSP clients.
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


class CloudAccountModel(Base):
    """Cloud provider account linked to an MSP client."""
    __tablename__ = "cloud_accounts"

    id = Column(String(36), primary_key=True, default=_uuid)
    account_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    provider = Column(String(20), nullable=False, index=True)  # aws/azure/gcp
    account_name = Column(String(200), nullable=False)
    account_identifier = Column(String(200), nullable=False)  # AWS account ID, Azure sub, GCP project
    region = Column(String(50), default="us-east-1")
    credentials_ref = Column(String(200), default="")  # encrypted vault ref
    status = Column(String(20), default="disconnected", index=True)
    last_sync_at = Column(DateTime, nullable=True)
    resources_count = Column(Integer, default=0)
    monthly_cost = Column(Float, default=0.0)
    cost_trend = Column(Float, default=0.0)  # % change vs prior month

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_cloud_acct_client_provider", "client_id", "provider"),
    )


class CloudResourceModel(Base):
    """Individual cloud resource (VM, DB, bucket, etc.)."""
    __tablename__ = "cloud_resources"

    id = Column(String(36), primary_key=True, default=_uuid)
    resource_id = Column(String(30), unique=True, nullable=False, index=True)
    account_id = Column(String(30), nullable=False, index=True)
    provider = Column(String(20), nullable=False)
    resource_type = Column(String(50), nullable=False, index=True)
    resource_name = Column(String(300), nullable=False)
    resource_identifier = Column(String(500), nullable=False)  # ARN / resource URI
    region = Column(String(50), default="")
    status = Column(String(20), default="running", index=True)
    tags = Column(JSON, default=dict)
    monthly_cost = Column(Float, default=0.0)
    metrics = Column(JSON, default=dict)  # cpu, memory, network, disk
    security_findings = Column(JSON, default=list)
    compliance_status = Column(String(30), default="unknown")

    created_at = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_cloud_res_acct_type", "account_id", "resource_type"),
    )


class CloudCostEntryModel(Base):
    """Granular cost entry per service/resource."""
    __tablename__ = "cloud_cost_entries"

    id = Column(String(36), primary_key=True, default=_uuid)
    cost_id = Column(String(30), unique=True, nullable=False, index=True)
    account_id = Column(String(30), nullable=False, index=True)
    service_name = Column(String(200), nullable=False)
    resource_id = Column(String(30), default="")
    cost_amount = Column(Float, nullable=False, default=0.0)
    currency = Column(String(10), default="USD")
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    usage_quantity = Column(Float, default=0.0)
    usage_unit = Column(String(50), default="")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_cloud_cost_acct_period", "account_id", "period_start"),
    )


class CloudSecurityFindingModel(Base):
    """Security posture finding for a cloud resource."""
    __tablename__ = "cloud_security_findings"

    id = Column(String(36), primary_key=True, default=_uuid)
    finding_id = Column(String(30), unique=True, nullable=False, index=True)
    account_id = Column(String(30), nullable=False, index=True)
    resource_id = Column(String(30), default="")
    finding_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    recommendation = Column(Text, default="")
    compliance_frameworks = Column(JSON, default=list)
    is_resolved = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=func.now())
    resolved_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_cloud_finding_acct_resolved", "account_id", "is_resolved"),
    )


class CloudAlertModel(Base):
    """Cloud infrastructure alert."""
    __tablename__ = "cloud_alerts"

    id = Column(String(36), primary_key=True, default=_uuid)
    alert_id = Column(String(30), unique=True, nullable=False, index=True)
    account_id = Column(String(30), nullable=False, index=True)
    alert_type = Column(String(30), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    threshold_value = Column(Float, nullable=True)
    actual_value = Column(Float, nullable=True)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_cloud_alert_acct_ack", "account_id", "is_acknowledged"),
    )
