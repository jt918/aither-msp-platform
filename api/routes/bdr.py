"""
API Routes for Backup & Disaster Recovery (BDR)
Uses BDRService for all operations
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.bdr_service import (
    BDRService,
    BackupType,
    JobStatus,
    RestoreType,
    DestinationType,
    Compression,
    AlertSeverity,
    _policy_to_dict,
    _job_to_dict,
    _restore_to_dict,
    _alert_to_dict,
    _dr_plan_to_dict,
    _storage_to_dict,
)

router = APIRouter(prefix="/bdr", tags=["BDR"])


def _init_bdr_service() -> BDRService:
    """Initialize BDRService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return BDRService(db=db)
    except Exception:
        return BDRService()


# Initialize service with DB persistence
bdr_service = _init_bdr_service()


# ========== Request/Response Models ==========

class PolicyCreate(BaseModel):
    name: str
    client_id: str = ""
    target_type: str = "full_image"
    schedule_cron: str = "0 2 * * *"
    retention_days: int = 30
    retention_count: int = 10
    compression: str = "gzip"
    encryption: str = "aes256"
    destination_type: str = "local"
    destination_config: Dict[str, Any] = {}
    pre_script: str = ""
    post_script: str = ""
    bandwidth_limit_mbps: Optional[float] = None
    is_enabled: bool = True


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    target_type: Optional[str] = None
    schedule_cron: Optional[str] = None
    retention_days: Optional[int] = None
    retention_count: Optional[int] = None
    compression: Optional[str] = None
    encryption: Optional[str] = None
    destination_type: Optional[str] = None
    destination_config: Optional[Dict[str, Any]] = None
    pre_script: Optional[str] = None
    post_script: Optional[str] = None
    bandwidth_limit_mbps: Optional[float] = None
    is_enabled: Optional[bool] = None


class BackupStart(BaseModel):
    policy_id: str
    endpoint_id: str
    client_id: str = ""
    job_type: Optional[str] = None
    is_incremental: bool = False
    parent_job_id: Optional[str] = None


class JobProgressUpdate(BaseModel):
    files_processed: Optional[int] = None
    size_bytes: Optional[int] = None
    size_compressed_bytes: Optional[int] = None
    transfer_speed_mbps: Optional[float] = None
    status: Optional[str] = None
    error_message: Optional[str] = None


class RestoreStart(BaseModel):
    backup_job_id: str
    endpoint_id: str
    restore_type: str = "full"
    target_path: str = ""


class DRPlanCreate(BaseModel):
    name: str
    client_id: str = ""
    rto_minutes: int = 240
    rpo_minutes: int = 60
    priority_systems: List[str] = []
    runbook_steps: List[Dict[str, Any]] = []
    contacts: List[Dict[str, str]] = []


class DRPlanUpdate(BaseModel):
    name: Optional[str] = None
    rto_minutes: Optional[int] = None
    rpo_minutes: Optional[int] = None
    priority_systems: Optional[List[str]] = None
    runbook_steps: Optional[List[Dict[str, Any]]] = None
    contacts: Optional[List[Dict[str, str]]] = None


# ========== Policy CRUD ==========

@router.post("/policies")
async def create_policy(data: PolicyCreate):
    """Create a new backup policy."""
    policy = bdr_service.create_policy(**data.model_dump())
    return _policy_to_dict(policy)


@router.get("/policies")
async def list_policies(client_id: Optional[str] = Query(None)):
    """List backup policies, optionally filtered by client."""
    policies = bdr_service.list_policies(client_id=client_id)
    return [_policy_to_dict(p) for p in policies]


@router.get("/policies/{policy_id}")
async def get_policy(policy_id: str):
    """Get a backup policy by ID."""
    policy = bdr_service.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _policy_to_dict(policy)


@router.put("/policies/{policy_id}")
async def update_policy(policy_id: str, data: PolicyUpdate):
    """Update a backup policy."""
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    policy = bdr_service.update_policy(policy_id, **updates)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _policy_to_dict(policy)


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str):
    """Delete a backup policy."""
    success = bdr_service.delete_policy(policy_id)
    if not success:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"deleted": True, "policy_id": policy_id}


# ========== Backup Jobs ==========

@router.post("/backup")
async def start_backup(data: BackupStart):
    """Start a new backup job."""
    job = bdr_service.start_backup(**data.model_dump())
    if not job:
        raise HTTPException(status_code=400, detail="Failed to start backup")
    return _job_to_dict(job)


@router.get("/jobs")
async def list_jobs(
    policy_id: Optional[str] = Query(None),
    endpoint_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List backup jobs with optional filters."""
    jobs = bdr_service.list_jobs(
        policy_id=policy_id, endpoint_id=endpoint_id, status=status, limit=limit
    )
    return [_job_to_dict(j) for j in jobs]


@router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    """Get a backup job by ID."""
    job = bdr_service.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_to_dict(job)


@router.put("/jobs/{job_id}/progress")
async def update_job_progress(job_id: str, data: JobProgressUpdate):
    """Update progress on a running backup job."""
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    job = bdr_service.update_job_progress(job_id, **updates)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_to_dict(job)


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    """Cancel a queued or running backup job."""
    job = bdr_service.cancel_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_to_dict(job)


# ========== Verification ==========

@router.post("/jobs/{job_id}/verify")
async def verify_backup(job_id: str):
    """Verify backup integrity via hash check."""
    result = bdr_service.verify_backup(job_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ========== Restore ==========

@router.post("/restore")
async def start_restore(data: RestoreStart):
    """Start a restore from a completed backup."""
    restore = bdr_service.start_restore(**data.model_dump())
    if not restore:
        raise HTTPException(status_code=400, detail="Failed to start restore")
    return _restore_to_dict(restore)


@router.get("/restores")
async def list_restores(
    endpoint_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List restore jobs with optional filters."""
    restores = bdr_service.list_restores(
        endpoint_id=endpoint_id, status=status, limit=limit
    )
    return [_restore_to_dict(r) for r in restores]


@router.get("/restores/{restore_id}")
async def get_restore(restore_id: str):
    """Get a restore job by ID."""
    restore = bdr_service.get_restore(restore_id)
    if not restore:
        raise HTTPException(status_code=404, detail="Restore not found")
    return _restore_to_dict(restore)


# ========== Storage ==========

@router.get("/storage")
async def get_storage_all():
    """Get storage usage for all endpoints."""
    usages = bdr_service.get_storage_usage_all()
    return [_storage_to_dict(u) for u in usages]


@router.get("/storage/{endpoint_id}")
async def get_storage(endpoint_id: str):
    """Get storage usage for a specific endpoint."""
    usage = bdr_service.get_storage_usage(endpoint_id)
    return _storage_to_dict(usage)


# ========== Alerts ==========

@router.get("/alerts")
async def get_alerts(
    acknowledged: Optional[bool] = Query(None),
    alert_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List BDR alerts with optional filters."""
    alerts = bdr_service.get_alerts(
        acknowledged=acknowledged, alert_type=alert_type, limit=limit
    )
    return [_alert_to_dict(a) for a in alerts]


@router.put("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    """Acknowledge a BDR alert."""
    alert = bdr_service.acknowledge_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_dict(alert)


@router.post("/alerts/check-missed")
async def check_missed_backups():
    """Check for missed backups and generate alerts."""
    alerts = bdr_service.check_missed_backups()
    return [_alert_to_dict(a) for a in alerts]


# ========== DR Plans ==========

@router.post("/dr-plans")
async def create_dr_plan(data: DRPlanCreate):
    """Create a new disaster recovery plan."""
    plan = bdr_service.create_dr_plan(**data.model_dump())
    return _dr_plan_to_dict(plan)


@router.get("/dr-plans")
async def list_dr_plans(client_id: Optional[str] = Query(None)):
    """List disaster recovery plans, optionally filtered by client."""
    plans = bdr_service.list_dr_plans(client_id=client_id)
    return [_dr_plan_to_dict(p) for p in plans]


@router.get("/dr-plans/{plan_id}")
async def get_dr_plan(plan_id: str):
    """Get a disaster recovery plan by ID."""
    plan = bdr_service.get_dr_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="DR plan not found")
    return _dr_plan_to_dict(plan)


@router.put("/dr-plans/{plan_id}")
async def update_dr_plan(plan_id: str, data: DRPlanUpdate):
    """Update a disaster recovery plan."""
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    plan = bdr_service.update_dr_plan(plan_id, **updates)
    if not plan:
        raise HTTPException(status_code=404, detail="DR plan not found")
    return _dr_plan_to_dict(plan)


@router.delete("/dr-plans/{plan_id}")
async def delete_dr_plan(plan_id: str):
    """Delete a disaster recovery plan."""
    success = bdr_service.delete_dr_plan(plan_id)
    if not success:
        raise HTTPException(status_code=404, detail="DR plan not found")
    return {"deleted": True, "plan_id": plan_id}


@router.post("/dr-plans/{plan_id}/test")
async def test_dr_plan(plan_id: str):
    """Simulate a DR plan test."""
    result = bdr_service.test_dr_plan(plan_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ========== Dashboard & Analytics ==========

@router.get("/dashboard")
async def get_dashboard():
    """Get BDR dashboard summary."""
    return bdr_service.get_dashboard()


@router.get("/analytics/success-rate")
async def get_success_rate(days: int = Query(30, ge=1, le=365)):
    """Get backup success rate over a period."""
    return bdr_service.get_backup_success_rate(days=days)


@router.get("/analytics/duration")
async def get_average_duration(days: int = Query(30, ge=1, le=365)):
    """Get average backup duration over a period."""
    return bdr_service.get_average_backup_duration(days=days)


@router.get("/analytics/storage-trend")
async def get_storage_trend(days: int = Query(30, ge=1, le=365)):
    """Get storage growth trend over a period."""
    return bdr_service.get_storage_growth_trend(days=days)
