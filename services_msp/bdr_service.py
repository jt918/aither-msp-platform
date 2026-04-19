"""
AITHER Platform - Backup & Disaster Recovery (BDR) Service
Comprehensive backup, restore, and disaster recovery management for MSP operations

Provides:
- Backup policy management (CRUD)
- Backup job execution and tracking
- Restore job management
- Backup verification (hash integrity)
- Storage usage analytics
- Alert management for missed/failed backups
- Disaster Recovery plan management and testing
- Analytics: success rate, duration, storage growth trend
- Dashboard: real-time BDR health overview

G-46 pattern: DB persistence with in-memory fallback.
"""

import uuid
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.bdr import (
        BackupPolicyModel,
        BackupJobModel,
        RestoreJobModel,
        BackupAlertModel,
        DisasterRecoveryPlanModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class BackupType(str, Enum):
    """Backup target types"""
    FULL_IMAGE = "full_image"
    FILE_LEVEL = "file_level"
    DATABASE = "database"
    VM_SNAPSHOT = "vm_snapshot"
    CLOUD_SYNC = "cloud_sync"
    EXCHANGE = "exchange"
    SQL_SERVER = "sql_server"


class JobStatus(str, Enum):
    """Backup/restore job status"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    VERIFYING = "verifying"


class RestoreType(str, Enum):
    """Restore operation types"""
    FULL = "full"
    FILE = "file"
    GRANULAR = "granular"
    BARE_METAL = "bare_metal"
    VM = "vm"
    CLOUD = "cloud"


class DestinationType(str, Enum):
    """Backup destination types"""
    LOCAL = "local"
    NAS = "nas"
    S3 = "s3"
    AZURE_BLOB = "azure_blob"
    GCS = "gcs"
    OFFSITE = "offsite"


class Compression(str, Enum):
    """Compression algorithms"""
    NONE = "none"
    GZIP = "gzip"
    LZ4 = "lz4"
    ZSTD = "zstd"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class BackupPolicy:
    """Backup policy definition"""
    policy_id: str
    name: str
    client_id: str = ""
    target_type: str = BackupType.FULL_IMAGE.value
    schedule_cron: str = "0 2 * * *"
    retention_days: int = 30
    retention_count: int = 10
    compression: str = Compression.GZIP.value
    encryption: str = "aes256"
    destination_type: str = DestinationType.LOCAL.value
    destination_config: Dict[str, Any] = field(default_factory=dict)
    pre_script: str = ""
    post_script: str = ""
    bandwidth_limit_mbps: Optional[float] = None
    is_enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BackupJob:
    """Backup job execution record"""
    job_id: str
    policy_id: str
    endpoint_id: str
    client_id: str = ""
    job_type: str = BackupType.FULL_IMAGE.value
    status: str = JobStatus.QUEUED.value
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    size_bytes: int = 0
    size_compressed_bytes: int = 0
    files_total: int = 0
    files_processed: int = 0
    transfer_speed_mbps: float = 0.0
    error_message: str = ""
    verification_status: str = "pending"
    verification_hash: str = ""
    destination_path: str = ""
    is_incremental: bool = False
    parent_job_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RestoreJob:
    """Restore job execution record"""
    restore_id: str
    backup_job_id: str
    endpoint_id: str
    restore_type: str = RestoreType.FULL.value
    target_path: str = ""
    status: str = JobStatus.QUEUED.value
    files_restored: int = 0
    size_restored_bytes: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BackupAlert:
    """BDR alert"""
    alert_id: str
    policy_id: str = ""
    endpoint_id: str = ""
    alert_type: str = "backup_failed"
    severity: str = AlertSeverity.MEDIUM.value
    message: str = ""
    is_acknowledged: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class StorageUsage:
    """Storage usage summary for an endpoint/policy pair"""
    endpoint_id: str
    policy_id: str = ""
    total_bytes: int = 0
    backup_count: int = 0
    oldest_backup: Optional[datetime] = None
    newest_backup: Optional[datetime] = None
    estimated_full_backup_size: int = 0


@dataclass
class DisasterRecoveryPlan:
    """DR plan definition"""
    plan_id: str
    client_id: str = ""
    name: str = ""
    rto_minutes: int = 240
    rpo_minutes: int = 60
    priority_systems: List[str] = field(default_factory=list)
    runbook_steps: List[Dict[str, Any]] = field(default_factory=list)
    last_tested_at: Optional[datetime] = None
    test_result: str = ""
    contacts: List[Dict[str, str]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Helpers
# ============================================================

def _policy_to_dict(p: BackupPolicy) -> dict:
    return {
        "policy_id": p.policy_id,
        "name": p.name,
        "client_id": p.client_id,
        "target_type": p.target_type,
        "schedule_cron": p.schedule_cron,
        "retention_days": p.retention_days,
        "retention_count": p.retention_count,
        "compression": p.compression,
        "encryption": p.encryption,
        "destination_type": p.destination_type,
        "destination_config": p.destination_config,
        "pre_script": p.pre_script,
        "post_script": p.post_script,
        "bandwidth_limit_mbps": p.bandwidth_limit_mbps,
        "is_enabled": p.is_enabled,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def _job_to_dict(j: BackupJob) -> dict:
    return {
        "job_id": j.job_id,
        "policy_id": j.policy_id,
        "endpoint_id": j.endpoint_id,
        "client_id": j.client_id,
        "job_type": j.job_type,
        "status": j.status,
        "started_at": j.started_at.isoformat() if j.started_at else None,
        "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        "size_bytes": j.size_bytes,
        "size_compressed_bytes": j.size_compressed_bytes,
        "files_total": j.files_total,
        "files_processed": j.files_processed,
        "transfer_speed_mbps": j.transfer_speed_mbps,
        "error_message": j.error_message,
        "verification_status": j.verification_status,
        "verification_hash": j.verification_hash,
        "destination_path": j.destination_path,
        "is_incremental": j.is_incremental,
        "parent_job_id": j.parent_job_id,
        "created_at": j.created_at.isoformat() if j.created_at else None,
    }


def _restore_to_dict(r: RestoreJob) -> dict:
    return {
        "restore_id": r.restore_id,
        "backup_job_id": r.backup_job_id,
        "endpoint_id": r.endpoint_id,
        "restore_type": r.restore_type,
        "target_path": r.target_path,
        "status": r.status,
        "files_restored": r.files_restored,
        "size_restored_bytes": r.size_restored_bytes,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "error_message": r.error_message,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _alert_to_dict(a: BackupAlert) -> dict:
    return {
        "alert_id": a.alert_id,
        "policy_id": a.policy_id,
        "endpoint_id": a.endpoint_id,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "message": a.message,
        "is_acknowledged": a.is_acknowledged,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _dr_plan_to_dict(d: DisasterRecoveryPlan) -> dict:
    return {
        "plan_id": d.plan_id,
        "client_id": d.client_id,
        "name": d.name,
        "rto_minutes": d.rto_minutes,
        "rpo_minutes": d.rpo_minutes,
        "priority_systems": d.priority_systems,
        "runbook_steps": d.runbook_steps,
        "last_tested_at": d.last_tested_at.isoformat() if d.last_tested_at else None,
        "test_result": d.test_result,
        "contacts": d.contacts,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def _storage_to_dict(s: StorageUsage) -> dict:
    return {
        "endpoint_id": s.endpoint_id,
        "policy_id": s.policy_id,
        "total_bytes": s.total_bytes,
        "backup_count": s.backup_count,
        "oldest_backup": s.oldest_backup.isoformat() if s.oldest_backup else None,
        "newest_backup": s.newest_backup.isoformat() if s.newest_backup else None,
        "estimated_full_backup_size": s.estimated_full_backup_size,
    }


# ============================================================
# BDR Service
# ============================================================

class BDRService:
    """
    Backup & Disaster Recovery Service

    Comprehensive BDR management for MSP operations.
    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._policies: Dict[str, BackupPolicy] = {}
        self._jobs: Dict[str, BackupJob] = {}
        self._restores: Dict[str, RestoreJob] = {}
        self._alerts: Dict[str, BackupAlert] = {}
        self._dr_plans: Dict[str, DisasterRecoveryPlan] = {}

    # ========== Policy CRUD ==========

    def create_policy(
        self,
        name: str,
        client_id: str = "",
        target_type: str = BackupType.FULL_IMAGE.value,
        schedule_cron: str = "0 2 * * *",
        retention_days: int = 30,
        retention_count: int = 10,
        compression: str = Compression.GZIP.value,
        encryption: str = "aes256",
        destination_type: str = DestinationType.LOCAL.value,
        destination_config: Optional[Dict] = None,
        pre_script: str = "",
        post_script: str = "",
        bandwidth_limit_mbps: Optional[float] = None,
        is_enabled: bool = True,
    ) -> BackupPolicy:
        """Create a new backup policy."""
        policy_id = f"POL-{uuid.uuid4().hex[:8].upper()}"
        policy = BackupPolicy(
            policy_id=policy_id,
            name=name,
            client_id=client_id,
            target_type=target_type,
            schedule_cron=schedule_cron,
            retention_days=retention_days,
            retention_count=retention_count,
            compression=compression,
            encryption=encryption,
            destination_type=destination_type,
            destination_config=destination_config or {},
            pre_script=pre_script,
            post_script=post_script,
            bandwidth_limit_mbps=bandwidth_limit_mbps,
            is_enabled=is_enabled,
        )

        if self._use_db:
            try:
                row = BackupPolicyModel(
                    policy_id=policy_id,
                    name=name,
                    client_id=client_id,
                    target_type=target_type,
                    schedule_cron=schedule_cron,
                    retention_days=retention_days,
                    retention_count=retention_count,
                    compression=compression,
                    encryption=encryption,
                    destination_type=destination_type,
                    destination_config=destination_config or {},
                    pre_script=pre_script,
                    post_script=post_script,
                    bandwidth_limit_mbps=bandwidth_limit_mbps,
                    is_enabled=is_enabled,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating policy: {e}")
                self.db.rollback()

        self._policies[policy_id] = policy
        return policy

    def get_policy(self, policy_id: str) -> Optional[BackupPolicy]:
        """Get a backup policy by ID."""
        return self._policies.get(policy_id)

    def list_policies(self, client_id: Optional[str] = None) -> List[BackupPolicy]:
        """List all backup policies, optionally filtered by client."""
        policies = list(self._policies.values())
        if client_id:
            policies = [p for p in policies if p.client_id == client_id]
        return policies

    def update_policy(self, policy_id: str, **updates) -> Optional[BackupPolicy]:
        """Update a backup policy."""
        policy = self.get_policy(policy_id)
        if not policy:
            return None

        for key, value in updates.items():
            if hasattr(policy, key) and key != "policy_id":
                setattr(policy, key, value)

        if self._use_db:
            try:
                row = self.db.query(BackupPolicyModel).filter(
                    BackupPolicyModel.policy_id == policy_id
                ).first()
                if row:
                    for key, value in updates.items():
                        if hasattr(row, key) and key != "policy_id":
                            setattr(row, key, value)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating policy: {e}")
                self.db.rollback()

        return policy

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a backup policy."""
        if policy_id not in self._policies:
            return False

        del self._policies[policy_id]

        if self._use_db:
            try:
                self.db.query(BackupPolicyModel).filter(
                    BackupPolicyModel.policy_id == policy_id
                ).delete()
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error deleting policy: {e}")
                self.db.rollback()

        return True

    # ========== Job Management ==========

    def start_backup(
        self,
        policy_id: str,
        endpoint_id: str,
        client_id: str = "",
        job_type: Optional[str] = None,
        is_incremental: bool = False,
        parent_job_id: Optional[str] = None,
    ) -> Optional[BackupJob]:
        """Start a new backup job."""
        policy = self.get_policy(policy_id)
        if not policy:
            logger.warning(f"Policy {policy_id} not found, creating ad-hoc job")

        job_id = f"BKP-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        jtype = job_type or (policy.target_type if policy else BackupType.FULL_IMAGE.value)
        dest_path = f"/backups/{client_id or 'default'}/{endpoint_id}/{job_id}"

        job = BackupJob(
            job_id=job_id,
            policy_id=policy_id,
            endpoint_id=endpoint_id,
            client_id=client_id,
            job_type=jtype,
            status=JobStatus.RUNNING.value,
            started_at=now,
            destination_path=dest_path,
            is_incremental=is_incremental,
            parent_job_id=parent_job_id,
        )

        if self._use_db:
            try:
                row = BackupJobModel(
                    job_id=job_id,
                    policy_id=policy_id,
                    endpoint_id=endpoint_id,
                    client_id=client_id,
                    job_type=jtype,
                    status=JobStatus.RUNNING.value,
                    started_at=now,
                    destination_path=dest_path,
                    is_incremental=is_incremental,
                    parent_job_id=parent_job_id,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error starting backup: {e}")
                self.db.rollback()

        self._jobs[job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[BackupJob]:
        """Get a backup job by ID."""
        return self._jobs.get(job_id)

    def list_jobs(
        self,
        policy_id: Optional[str] = None,
        endpoint_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[BackupJob]:
        """List backup jobs with optional filters."""
        jobs = list(self._jobs.values())
        if policy_id:
            jobs = [j for j in jobs if j.policy_id == policy_id]
        if endpoint_id:
            jobs = [j for j in jobs if j.endpoint_id == endpoint_id]
        if status:
            jobs = [j for j in jobs if j.status == status]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    def cancel_job(self, job_id: str) -> Optional[BackupJob]:
        """Cancel a queued or running backup job."""
        job = self.get_job(job_id)
        if not job:
            return None
        if job.status not in (JobStatus.QUEUED.value, JobStatus.RUNNING.value):
            return job

        job.status = JobStatus.CANCELLED.value
        job.completed_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(BackupJobModel).filter(
                    BackupJobModel.job_id == job_id
                ).first()
                if row:
                    row.status = JobStatus.CANCELLED.value
                    row.completed_at = job.completed_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error cancelling job: {e}")
                self.db.rollback()

        return job

    def update_job_progress(
        self,
        job_id: str,
        files_processed: Optional[int] = None,
        size_bytes: Optional[int] = None,
        size_compressed_bytes: Optional[int] = None,
        transfer_speed_mbps: Optional[float] = None,
        status: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> Optional[BackupJob]:
        """Update progress on a running backup job."""
        job = self.get_job(job_id)
        if not job:
            return None

        if files_processed is not None:
            job.files_processed = files_processed
        if size_bytes is not None:
            job.size_bytes = size_bytes
        if size_compressed_bytes is not None:
            job.size_compressed_bytes = size_compressed_bytes
        if transfer_speed_mbps is not None:
            job.transfer_speed_mbps = transfer_speed_mbps
        if error_message is not None:
            job.error_message = error_message
        if status is not None:
            job.status = status
            if status in (JobStatus.COMPLETED.value, JobStatus.FAILED.value):
                job.completed_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(BackupJobModel).filter(
                    BackupJobModel.job_id == job_id
                ).first()
                if row:
                    if files_processed is not None:
                        row.files_processed = files_processed
                    if size_bytes is not None:
                        row.size_bytes = size_bytes
                    if size_compressed_bytes is not None:
                        row.size_compressed_bytes = size_compressed_bytes
                    if transfer_speed_mbps is not None:
                        row.transfer_speed_mbps = transfer_speed_mbps
                    if error_message is not None:
                        row.error_message = error_message
                    if status is not None:
                        row.status = status
                        if status in (JobStatus.COMPLETED.value, JobStatus.FAILED.value):
                            row.completed_at = job.completed_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating job progress: {e}")
                self.db.rollback()

        return job

    # ========== Restore ==========

    def start_restore(
        self,
        backup_job_id: str,
        endpoint_id: str,
        restore_type: str = RestoreType.FULL.value,
        target_path: str = "",
    ) -> Optional[RestoreJob]:
        """Start a restore from a completed backup."""
        backup = self.get_job(backup_job_id)
        if not backup:
            logger.error(f"Backup job {backup_job_id} not found")
            return None

        restore_id = f"RST-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        restore = RestoreJob(
            restore_id=restore_id,
            backup_job_id=backup_job_id,
            endpoint_id=endpoint_id,
            restore_type=restore_type,
            target_path=target_path or backup.destination_path,
            status=JobStatus.RUNNING.value,
            started_at=now,
        )

        if self._use_db:
            try:
                row = RestoreJobModel(
                    restore_id=restore_id,
                    backup_job_id=backup_job_id,
                    endpoint_id=endpoint_id,
                    restore_type=restore_type,
                    target_path=target_path or backup.destination_path,
                    status=JobStatus.RUNNING.value,
                    started_at=now,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error starting restore: {e}")
                self.db.rollback()

        self._restores[restore_id] = restore
        return restore

    def get_restore(self, restore_id: str) -> Optional[RestoreJob]:
        """Get a restore job by ID."""
        return self._restores.get(restore_id)

    def list_restores(
        self,
        endpoint_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[RestoreJob]:
        """List restore jobs with optional filters."""
        restores = list(self._restores.values())
        if endpoint_id:
            restores = [r for r in restores if r.endpoint_id == endpoint_id]
        if status:
            restores = [r for r in restores if r.status == status]
        restores.sort(key=lambda r: r.created_at, reverse=True)
        return restores[:limit]

    # ========== Verification ==========

    def verify_backup(self, job_id: str) -> Dict[str, Any]:
        """Verify backup integrity via hash check."""
        job = self.get_job(job_id)
        if not job:
            return {"error": "Job not found", "status": "failed"}

        if job.status != JobStatus.COMPLETED.value:
            return {"error": "Job not completed", "status": "skipped"}

        # Simulate hash verification (in production this would read the backup file)
        job.status = JobStatus.VERIFYING.value
        verification_hash = hashlib.sha256(
            f"{job.job_id}:{job.size_bytes}:{job.destination_path}".encode()
        ).hexdigest()

        job.verification_hash = verification_hash
        job.verification_status = "passed"
        job.status = JobStatus.COMPLETED.value

        if self._use_db:
            try:
                row = self.db.query(BackupJobModel).filter(
                    BackupJobModel.job_id == job_id
                ).first()
                if row:
                    row.verification_hash = verification_hash
                    row.verification_status = "passed"
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error verifying backup: {e}")
                self.db.rollback()

        return {
            "job_id": job_id,
            "verification_status": "passed",
            "verification_hash": verification_hash,
            "size_bytes": job.size_bytes,
        }

    # ========== Storage Usage ==========

    def get_storage_usage(self, endpoint_id: str) -> StorageUsage:
        """Get storage usage summary for an endpoint."""
        jobs = [j for j in self._jobs.values()
                if j.endpoint_id == endpoint_id and j.status == JobStatus.COMPLETED.value]

        total_bytes = sum(j.size_compressed_bytes or j.size_bytes for j in jobs)
        oldest = min((j.completed_at for j in jobs if j.completed_at), default=None)
        newest = max((j.completed_at for j in jobs if j.completed_at), default=None)
        estimated = max((j.size_bytes for j in jobs), default=0)

        return StorageUsage(
            endpoint_id=endpoint_id,
            total_bytes=total_bytes,
            backup_count=len(jobs),
            oldest_backup=oldest,
            newest_backup=newest,
            estimated_full_backup_size=estimated,
        )

    def get_storage_usage_all(self) -> List[StorageUsage]:
        """Get storage usage for all endpoints with completed backups."""
        endpoint_ids = set(
            j.endpoint_id for j in self._jobs.values()
            if j.status == JobStatus.COMPLETED.value
        )
        return [self.get_storage_usage(eid) for eid in endpoint_ids]

    # ========== Alerts ==========

    def _create_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        policy_id: str = "",
        endpoint_id: str = "",
    ) -> BackupAlert:
        """Internal: create a BDR alert."""
        alert_id = f"BDRA-{uuid.uuid4().hex[:8].upper()}"
        alert = BackupAlert(
            alert_id=alert_id,
            policy_id=policy_id,
            endpoint_id=endpoint_id,
            alert_type=alert_type,
            severity=severity,
            message=message,
        )

        if self._use_db:
            try:
                row = BackupAlertModel(
                    alert_id=alert_id,
                    policy_id=policy_id,
                    endpoint_id=endpoint_id,
                    alert_type=alert_type,
                    severity=severity,
                    message=message,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating alert: {e}")
                self.db.rollback()

        self._alerts[alert_id] = alert
        return alert

    def get_alerts(
        self,
        acknowledged: Optional[bool] = None,
        alert_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[BackupAlert]:
        """List BDR alerts with optional filters."""
        alerts = list(self._alerts.values())
        if acknowledged is not None:
            alerts = [a for a in alerts if a.is_acknowledged == acknowledged]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        alerts.sort(key=lambda a: a.created_at, reverse=True)
        return alerts[:limit]

    def acknowledge_alert(self, alert_id: str) -> Optional[BackupAlert]:
        """Acknowledge a BDR alert."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None

        alert.is_acknowledged = True

        if self._use_db:
            try:
                row = self.db.query(BackupAlertModel).filter(
                    BackupAlertModel.alert_id == alert_id
                ).first()
                if row:
                    row.is_acknowledged = True
                    row.acknowledged_at = datetime.now(timezone.utc)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error acknowledging alert: {e}")
                self.db.rollback()

        return alert

    def check_missed_backups(self) -> List[BackupAlert]:
        """Check for policies whose last backup is overdue and create alerts."""
        new_alerts = []
        now = datetime.now(timezone.utc)

        for policy in self._policies.values():
            if not policy.is_enabled:
                continue

            # Find latest job for this policy
            policy_jobs = [j for j in self._jobs.values() if j.policy_id == policy.policy_id]
            if not policy_jobs:
                alert = self._create_alert(
                    alert_type="backup_missed",
                    severity=AlertSeverity.HIGH.value,
                    message=f"Policy '{policy.name}' ({policy.policy_id}) has never run",
                    policy_id=policy.policy_id,
                )
                new_alerts.append(alert)
                continue

            latest = max(policy_jobs, key=lambda j: j.created_at)
            # Simple heuristic: if last job is older than 2x schedule period, it's missed
            age = (now - latest.created_at).total_seconds()
            if age > 48 * 3600:  # More than 48 hours
                alert = self._create_alert(
                    alert_type="backup_missed",
                    severity=AlertSeverity.HIGH.value,
                    message=f"Policy '{policy.name}' last ran {age / 3600:.0f}h ago",
                    policy_id=policy.policy_id,
                )
                new_alerts.append(alert)

        return new_alerts

    # ========== DR Plans ==========

    def create_dr_plan(
        self,
        name: str,
        client_id: str = "",
        rto_minutes: int = 240,
        rpo_minutes: int = 60,
        priority_systems: Optional[List[str]] = None,
        runbook_steps: Optional[List[Dict]] = None,
        contacts: Optional[List[Dict]] = None,
    ) -> DisasterRecoveryPlan:
        """Create a new disaster recovery plan."""
        plan_id = f"DRP-{uuid.uuid4().hex[:8].upper()}"
        plan = DisasterRecoveryPlan(
            plan_id=plan_id,
            client_id=client_id,
            name=name,
            rto_minutes=rto_minutes,
            rpo_minutes=rpo_minutes,
            priority_systems=priority_systems or [],
            runbook_steps=runbook_steps or [],
            contacts=contacts or [],
        )

        if self._use_db:
            try:
                row = DisasterRecoveryPlanModel(
                    plan_id=plan_id,
                    client_id=client_id,
                    name=name,
                    rto_minutes=rto_minutes,
                    rpo_minutes=rpo_minutes,
                    priority_systems=priority_systems or [],
                    runbook_steps=runbook_steps or [],
                    contacts=contacts or [],
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating DR plan: {e}")
                self.db.rollback()

        self._dr_plans[plan_id] = plan
        return plan

    def get_dr_plan(self, plan_id: str) -> Optional[DisasterRecoveryPlan]:
        """Get a DR plan by ID."""
        return self._dr_plans.get(plan_id)

    def list_dr_plans(self, client_id: Optional[str] = None) -> List[DisasterRecoveryPlan]:
        """List DR plans, optionally filtered by client."""
        plans = list(self._dr_plans.values())
        if client_id:
            plans = [p for p in plans if p.client_id == client_id]
        return plans

    def update_dr_plan(self, plan_id: str, **updates) -> Optional[DisasterRecoveryPlan]:
        """Update a DR plan."""
        plan = self.get_dr_plan(plan_id)
        if not plan:
            return None

        for key, value in updates.items():
            if hasattr(plan, key) and key != "plan_id":
                setattr(plan, key, value)

        if self._use_db:
            try:
                row = self.db.query(DisasterRecoveryPlanModel).filter(
                    DisasterRecoveryPlanModel.plan_id == plan_id
                ).first()
                if row:
                    for key, value in updates.items():
                        if hasattr(row, key) and key != "plan_id":
                            setattr(row, key, value)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating DR plan: {e}")
                self.db.rollback()

        return plan

    def delete_dr_plan(self, plan_id: str) -> bool:
        """Delete a DR plan."""
        if plan_id not in self._dr_plans:
            return False

        del self._dr_plans[plan_id]

        if self._use_db:
            try:
                self.db.query(DisasterRecoveryPlanModel).filter(
                    DisasterRecoveryPlanModel.plan_id == plan_id
                ).delete()
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error deleting DR plan: {e}")
                self.db.rollback()

        return True

    def test_dr_plan(self, plan_id: str) -> Dict[str, Any]:
        """Simulate a DR plan test and record the result."""
        plan = self.get_dr_plan(plan_id)
        if not plan:
            return {"error": "Plan not found"}

        now = datetime.now(timezone.utc)
        plan.last_tested_at = now

        # Validate the plan has required components
        issues = []
        if not plan.priority_systems:
            issues.append("No priority systems defined")
        if not plan.runbook_steps:
            issues.append("No runbook steps defined")
        if not plan.contacts:
            issues.append("No emergency contacts defined")
        if plan.rto_minutes <= 0:
            issues.append("Invalid RTO")
        if plan.rpo_minutes <= 0:
            issues.append("Invalid RPO")

        # Check if backup policies exist for priority systems
        all_policy_targets = [p.target_type for p in self._policies.values()
                             if p.client_id == plan.client_id and p.is_enabled]
        if not all_policy_targets:
            issues.append("No active backup policies for this client")

        plan.test_result = "failed" if issues else "passed"

        if self._use_db:
            try:
                row = self.db.query(DisasterRecoveryPlanModel).filter(
                    DisasterRecoveryPlanModel.plan_id == plan_id
                ).first()
                if row:
                    row.last_tested_at = now
                    row.test_result = plan.test_result
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error testing DR plan: {e}")
                self.db.rollback()

        return {
            "plan_id": plan_id,
            "test_result": plan.test_result,
            "tested_at": now.isoformat(),
            "issues": issues,
            "rto_minutes": plan.rto_minutes,
            "rpo_minutes": plan.rpo_minutes,
            "priority_systems_count": len(plan.priority_systems),
            "runbook_steps_count": len(plan.runbook_steps),
        }

    # ========== Analytics ==========

    def get_backup_success_rate(self, days: int = 30) -> Dict[str, Any]:
        """Calculate backup success rate over a period."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        recent_jobs = [
            j for j in self._jobs.values()
            if j.created_at >= cutoff and j.status in (
                JobStatus.COMPLETED.value, JobStatus.FAILED.value
            )
        ]
        total = len(recent_jobs)
        completed = len([j for j in recent_jobs if j.status == JobStatus.COMPLETED.value])
        rate = (completed / total * 100) if total > 0 else 100.0

        return {
            "period_days": days,
            "total_jobs": total,
            "completed": completed,
            "failed": total - completed,
            "success_rate_pct": round(rate, 2),
        }

    def get_average_backup_duration(self, days: int = 30) -> Dict[str, Any]:
        """Calculate average backup duration over a period."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        completed_jobs = [
            j for j in self._jobs.values()
            if j.created_at >= cutoff
            and j.status == JobStatus.COMPLETED.value
            and j.started_at and j.completed_at
        ]

        if not completed_jobs:
            return {"period_days": days, "average_seconds": 0, "job_count": 0}

        durations = [
            (j.completed_at - j.started_at).total_seconds()
            for j in completed_jobs
        ]
        avg = sum(durations) / len(durations)

        return {
            "period_days": days,
            "average_seconds": round(avg, 1),
            "min_seconds": round(min(durations), 1),
            "max_seconds": round(max(durations), 1),
            "job_count": len(completed_jobs),
        }

    def get_storage_growth_trend(self, days: int = 30) -> Dict[str, Any]:
        """Calculate storage growth trend over a period."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        recent_jobs = [
            j for j in self._jobs.values()
            if j.created_at >= cutoff and j.status == JobStatus.COMPLETED.value
        ]

        total_new_bytes = sum(j.size_compressed_bytes or j.size_bytes for j in recent_jobs)
        total_all_bytes = sum(
            j.size_compressed_bytes or j.size_bytes
            for j in self._jobs.values()
            if j.status == JobStatus.COMPLETED.value
        )

        return {
            "period_days": days,
            "new_bytes": total_new_bytes,
            "total_bytes": total_all_bytes,
            "new_backups": len(recent_jobs),
            "daily_avg_bytes": total_new_bytes // max(days, 1),
        }

    # ========== Dashboard ==========

    def get_dashboard(self) -> Dict[str, Any]:
        """Get BDR dashboard summary."""
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        jobs_today = [j for j in self._jobs.values() if j.created_at >= today_start]
        completed_today = [j for j in jobs_today if j.status == JobStatus.COMPLETED.value]
        failed_today = [j for j in jobs_today if j.status == JobStatus.FAILED.value]
        running_now = [j for j in self._jobs.values() if j.status == JobStatus.RUNNING.value]

        success_rate = self.get_backup_success_rate(days=7)
        total_storage = sum(
            j.size_compressed_bytes or j.size_bytes
            for j in self._jobs.values()
            if j.status == JobStatus.COMPLETED.value
        )
        unacked_alerts = [a for a in self._alerts.values() if not a.is_acknowledged]

        # DR plan compliance
        plans = list(self._dr_plans.values())
        tested_plans = [p for p in plans if p.test_result == "passed"]

        return {
            "jobs_today": len(jobs_today),
            "completed_today": len(completed_today),
            "failed_today": len(failed_today),
            "running_now": len(running_now),
            "success_rate_7d": success_rate["success_rate_pct"],
            "total_storage_bytes": total_storage,
            "total_policies": len(self._policies),
            "enabled_policies": len([p for p in self._policies.values() if p.is_enabled]),
            "unacknowledged_alerts": len(unacked_alerts),
            "dr_plans_total": len(plans),
            "dr_plans_compliant": len(tested_plans),
            "active_restores": len([r for r in self._restores.values()
                                    if r.status == JobStatus.RUNNING.value]),
        }
