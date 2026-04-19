"""
AITHER Platform - Backup & Disaster Recovery (BDR) Persistence Models

Tables for backup policies, backup jobs, restore jobs, alerts,
and disaster recovery plans.

Provides MSP-grade BDR capabilities with full audit trail.
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
# Backup Policy
# ============================================================

class BackupPolicyModel(Base):
    """Backup policy definition."""
    __tablename__ = "bdr_policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    client_id = Column(String(100), default="", index=True)
    target_type = Column(String(30), nullable=False)  # full_image/file_level/database/vm_snapshot/cloud_sync
    schedule_cron = Column(String(100), default="0 2 * * *")  # default 2 AM daily
    retention_days = Column(Integer, default=30)
    retention_count = Column(Integer, default=10)
    compression = Column(String(20), default="gzip")
    encryption = Column(String(20), default="aes256")
    destination_type = Column(String(20), default="local")
    destination_config = Column(JSON, default=dict)
    pre_script = Column(Text, default="")
    post_script = Column(Text, default="")
    bandwidth_limit_mbps = Column(Float, nullable=True)
    is_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_bdr_policy_client_type", "client_id", "target_type"),
    )


# ============================================================
# Backup Job
# ============================================================

class BackupJobModel(Base):
    """Backup job execution record."""
    __tablename__ = "bdr_jobs"

    id = Column(String(36), primary_key=True, default=_uuid)
    job_id = Column(String(30), unique=True, nullable=False, index=True)
    policy_id = Column(String(30), nullable=False, index=True)
    endpoint_id = Column(String(30), nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    job_type = Column(String(30), default="full_image")
    status = Column(String(20), default="queued", index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    size_bytes = Column(Integer, default=0)
    size_compressed_bytes = Column(Integer, default=0)
    files_total = Column(Integer, default=0)
    files_processed = Column(Integer, default=0)
    transfer_speed_mbps = Column(Float, default=0.0)
    error_message = Column(Text, default="")
    verification_status = Column(String(20), default="pending")
    verification_hash = Column(String(128), default="")
    destination_path = Column(Text, default="")
    is_incremental = Column(Boolean, default=False)
    parent_job_id = Column(String(30), nullable=True)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_bdr_job_policy_status", "policy_id", "status"),
        Index("ix_bdr_job_endpoint_status", "endpoint_id", "status"),
    )


# ============================================================
# Restore Job
# ============================================================

class RestoreJobModel(Base):
    """Restore job execution record."""
    __tablename__ = "bdr_restores"

    id = Column(String(36), primary_key=True, default=_uuid)
    restore_id = Column(String(30), unique=True, nullable=False, index=True)
    backup_job_id = Column(String(30), nullable=False, index=True)
    endpoint_id = Column(String(30), nullable=False, index=True)
    restore_type = Column(String(20), default="full")  # full/file/granular/bare_metal/vm
    target_path = Column(Text, default="")
    status = Column(String(20), default="queued", index=True)
    files_restored = Column(Integer, default=0)
    size_restored_bytes = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())


# ============================================================
# Backup Alert
# ============================================================

class BackupAlertModel(Base):
    """BDR alert record."""
    __tablename__ = "bdr_alerts"

    id = Column(String(36), primary_key=True, default=_uuid)
    alert_id = Column(String(30), unique=True, nullable=False, index=True)
    policy_id = Column(String(30), default="", index=True)
    endpoint_id = Column(String(30), default="", index=True)
    alert_type = Column(String(30), nullable=False)
    severity = Column(String(20), default="medium")
    message = Column(Text, default="")
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_bdr_alert_type_ack", "alert_type", "is_acknowledged"),
    )


# ============================================================
# Disaster Recovery Plan
# ============================================================

class DisasterRecoveryPlanModel(Base):
    """DR plan definition."""
    __tablename__ = "bdr_dr_plans"

    id = Column(String(36), primary_key=True, default=_uuid)
    plan_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    name = Column(String(200), nullable=False)
    rto_minutes = Column(Integer, default=240)
    rpo_minutes = Column(Integer, default=60)
    priority_systems = Column(JSON, default=list)
    runbook_steps = Column(JSON, default=list)
    last_tested_at = Column(DateTime, nullable=True)
    test_result = Column(String(20), default="")
    contacts = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
