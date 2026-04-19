"""
API Routes for Remote Monitoring and Management (RMM)
Uses RMMService for all operations
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.rmm import (
    RMMService,
    EndpointStatus,
    AlertSeverity,
    AlertCategory,
    CommandStatus,
    PatchStatus,
    PolicyType
)

router = APIRouter(prefix="/rmm", tags=["RMM"])


def _init_rmm_service() -> RMMService:
    """Initialize RMMService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return RMMService(db=db)
    except Exception:
        return RMMService()


# Initialize service with DB persistence
rmm_service = _init_rmm_service()


# ========== Request/Response Models ==========

class SystemInfoModel(BaseModel):
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_build: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    ram_total_gb: Optional[float] = None
    disk_total_gb: Optional[float] = None


class EndpointRegister(BaseModel):
    hostname: str
    ip_address: str
    mac_address: str = ""
    client_id: str = ""
    client_name: str = ""
    agent_version: str = ""
    system_info: Optional[SystemInfoModel] = None
    tags: List[str] = []
    groups: List[str] = []


class EndpointUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    agent_version: Optional[str] = None
    tags: Optional[List[str]] = None
    groups: Optional[List[str]] = None


class HeartbeatMetrics(BaseModel):
    cpu: float = 0
    memory: float = 0
    disk: float = 0
    network_in: int = 0
    network_out: int = 0
    processes: int = 0
    uptime: int = 0


class MaintenanceMode(BaseModel):
    enabled: bool
    reason: str = ""


class AlertCreate(BaseModel):
    endpoint_id: str
    severity: AlertSeverity
    category: AlertCategory
    title: str
    message: str
    metric_name: str = ""
    metric_value: float = 0.0
    threshold: float = 0.0


class AlertAcknowledge(BaseModel):
    acknowledged_by: str
    notes: str = ""


class CommandQueue(BaseModel):
    endpoint_id: str
    command_type: str
    command: str
    parameters: Dict[str, Any] = {}
    queued_by: Optional[str] = None
    timeout_seconds: int = 300


class CommandStatusUpdate(BaseModel):
    status: CommandStatus
    output: str = ""
    exit_code: Optional[int] = None
    error: str = ""


class PatchAdd(BaseModel):
    endpoint_id: str
    kb_id: str
    title: str
    description: str = ""
    severity: str = "important"
    size_mb: float = 0.0
    requires_reboot: bool = False


class PatchStatusUpdate(BaseModel):
    status: PatchStatus


class SoftwareItem(BaseModel):
    name: str
    version: str
    publisher: str = ""
    install_location: str = ""
    size_mb: float = 0.0
    is_update: bool = False


class SoftwareInventoryUpdate(BaseModel):
    software: List[SoftwareItem]


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    policy_type: PolicyType = PolicyType.THRESHOLD
    trigger_conditions: Dict[str, Any] = {}
    actions: List[Dict[str, Any]] = []
    target_groups: List[str] = []
    target_tags: List[str] = []
    schedule: Optional[str] = None
    cooldown_minutes: int = 15


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    trigger_conditions: Optional[Dict[str, Any]] = None
    actions: Optional[List[Dict[str, Any]]] = None
    target_groups: Optional[List[str]] = None
    target_tags: Optional[List[str]] = None
    schedule: Optional[str] = None
    cooldown_minutes: Optional[int] = None


class PolicyExecutionRecord(BaseModel):
    policy_id: str
    endpoint_id: str
    triggered_by: str
    actions_taken: List[str] = []
    success: bool = True
    error: str = ""


# ========== Helper Functions ==========

def endpoint_to_dict(endpoint) -> dict:
    """Convert Endpoint dataclass to dict"""
    return {
        "endpoint_id": endpoint.endpoint_id,
        "hostname": endpoint.hostname,
        "ip_address": endpoint.ip_address,
        "mac_address": endpoint.mac_address,
        "client_id": endpoint.client_id,
        "client_name": endpoint.client_name,
        "status": endpoint.status.value,
        "agent_version": endpoint.agent_version,
        "agent_installed_at": endpoint.agent_installed_at.isoformat() if endpoint.agent_installed_at else None,
        "system_info": {
            "os_name": endpoint.system_info.os_name,
            "os_version": endpoint.system_info.os_version,
            "os_build": endpoint.system_info.os_build,
            "hostname": endpoint.system_info.hostname,
            "domain": endpoint.system_info.domain,
            "manufacturer": endpoint.system_info.manufacturer,
            "model": endpoint.system_info.model,
            "serial_number": endpoint.system_info.serial_number,
            "cpu_model": endpoint.system_info.cpu_model,
            "cpu_cores": endpoint.system_info.cpu_cores,
            "ram_total_gb": endpoint.system_info.ram_total_gb,
            "disk_total_gb": endpoint.system_info.disk_total_gb
        },
        "metrics": {
            "cpu_percent": endpoint.metrics.cpu_percent,
            "memory_percent": endpoint.metrics.memory_percent,
            "disk_percent": endpoint.metrics.disk_percent,
            "network_in_bytes": endpoint.metrics.network_in_bytes,
            "network_out_bytes": endpoint.metrics.network_out_bytes,
            "process_count": endpoint.metrics.process_count,
            "uptime_seconds": endpoint.metrics.uptime_seconds
        },
        "tags": endpoint.tags,
        "groups": endpoint.groups,
        "last_seen": endpoint.last_seen.isoformat() if endpoint.last_seen else None,
        "last_reboot": endpoint.last_reboot.isoformat() if endpoint.last_reboot else None,
        "alerts_count": endpoint.alerts_count,
        "patches_pending": endpoint.patches_pending,
        "created_at": endpoint.created_at.isoformat() if endpoint.created_at else None,
        "updated_at": endpoint.updated_at.isoformat() if endpoint.updated_at else None
    }


def alert_to_dict(alert) -> dict:
    """Convert Alert dataclass to dict"""
    _sev = alert.severity
    _cat = alert.category
    return {
        "alert_id": alert.alert_id,
        "endpoint_id": alert.endpoint_id,
        "hostname": getattr(alert, "hostname", ""),
        "severity": _sev.value if hasattr(_sev, "value") else str(_sev),
        "category": _cat.value if hasattr(_cat, "value") else str(_cat),
        "title": alert.title,
        "message": alert.message,
        "metric_name": alert.metric_name,
        "metric_value": alert.metric_value,
        "threshold": alert.threshold,
        "acknowledged": alert.acknowledged,
        "acknowledged_by": alert.acknowledged_by,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "resolved": alert.resolved,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "notes": alert.notes,
        "created_at": alert.created_at.isoformat() if alert.created_at else None
    }


def command_to_dict(command) -> dict:
    """Convert Command dataclass to dict"""
    return {
        "command_id": command.command_id,
        "endpoint_id": command.endpoint_id,
        "command_type": command.command_type,
        "command": command.command,
        "parameters": command.parameters,
        "status": command.status.value,
        "output": command.output,
        "exit_code": command.exit_code,
        "error": command.error,
        "queued_by": command.queued_by,
        "started_at": command.started_at.isoformat() if command.started_at else None,
        "completed_at": command.completed_at.isoformat() if command.completed_at else None,
        "timeout_seconds": command.timeout_seconds,
        "created_at": command.created_at.isoformat() if command.created_at else None
    }


def patch_to_dict(patch) -> dict:
    """Convert Patch dataclass to dict"""
    return {
        "patch_id": patch.patch_id,
        "endpoint_id": patch.endpoint_id,
        "kb_id": patch.kb_id,
        "title": patch.title,
        "description": patch.description,
        "severity": patch.severity,
        "status": patch.status.value,
        "size_mb": patch.size_mb,
        "download_url": patch.download_url,
        "installed_at": patch.installed_at.isoformat() if patch.installed_at else None,
        "requires_reboot": patch.requires_reboot,
        "created_at": patch.created_at.isoformat() if patch.created_at else None
    }


def software_to_dict(software) -> dict:
    """Convert Software dataclass to dict"""
    return {
        "software_id": software.software_id,
        "endpoint_id": software.endpoint_id,
        "name": software.name,
        "version": software.version,
        "publisher": software.publisher,
        "install_date": software.install_date.isoformat() if software.install_date else None,
        "install_location": software.install_location,
        "size_mb": software.size_mb,
        "is_update": software.is_update
    }


def policy_to_dict(policy) -> dict:
    """Convert AutomationPolicy dataclass to dict"""
    return {
        "policy_id": policy.policy_id,
        "name": policy.name,
        "description": policy.description,
        "policy_type": policy.policy_type.value,
        "enabled": policy.enabled,
        "trigger_conditions": policy.trigger_conditions,
        "actions": policy.actions,
        "target_groups": policy.target_groups,
        "target_tags": policy.target_tags,
        "schedule": policy.schedule,
        "cooldown_minutes": policy.cooldown_minutes,
        "last_triggered": policy.last_triggered.isoformat() if policy.last_triggered else None,
        "execution_count": policy.execution_count,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None
    }


def execution_to_dict(execution) -> dict:
    """Convert PolicyExecution dataclass to dict"""
    return {
        "execution_id": execution.execution_id,
        "policy_id": execution.policy_id,
        "endpoint_id": execution.endpoint_id,
        "triggered_by": execution.triggered_by,
        "actions_taken": execution.actions_taken,
        "success": execution.success,
        "error": execution.error,
        "executed_at": execution.executed_at.isoformat() if execution.executed_at else None
    }


# ========== Endpoint Routes ==========

@router.get("/endpoints")
async def list_endpoints(
    status: Optional[EndpointStatus] = None,
    client_id: Optional[str] = None,
    group: Optional[str] = None,
    tag: Optional[str] = None
):
    """List all endpoints with optional filtering"""
    endpoints = rmm_service.list_endpoints(
        status=status,
        client_id=client_id,
        group=group,
        tag=tag
    )

    return {
        "count": len(endpoints),
        "endpoints": [endpoint_to_dict(e) for e in endpoints]
    }


@router.get("/endpoints/{endpoint_id}")
async def get_endpoint(endpoint_id: str):
    """Get endpoint details"""
    endpoint = rmm_service.get_endpoint(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return endpoint_to_dict(endpoint)


@router.post("/endpoints")
async def register_endpoint(data: EndpointRegister, current_user: dict = Depends(require_admin)):
    """Register a new endpoint"""
    system_info = None
    if data.system_info:
        system_info = data.system_info.model_dump(exclude_none=True)

    endpoint = rmm_service.register_endpoint(
        hostname=data.hostname,
        ip_address=data.ip_address,
        mac_address=data.mac_address,
        client_id=data.client_id,
        client_name=data.client_name,
        agent_version=data.agent_version,
        system_info=system_info,
        tags=data.tags,
        groups=data.groups
    )

    return endpoint_to_dict(endpoint)


@router.put("/endpoints/{endpoint_id}")
async def update_endpoint(endpoint_id: str, data: EndpointUpdate, current_user: dict = Depends(require_admin)):
    """Update endpoint properties"""
    updates = data.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    endpoint = rmm_service.update_endpoint(endpoint_id, **updates)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return endpoint_to_dict(endpoint)


@router.delete("/endpoints/{endpoint_id}")
async def delete_endpoint(endpoint_id: str, current_user: dict = Depends(require_admin)):
    """Remove an endpoint"""
    result = rmm_service.delete_endpoint(endpoint_id)
    if not result:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return {"status": "deleted", "endpoint_id": endpoint_id}


@router.post("/endpoints/{endpoint_id}/heartbeat")
async def endpoint_heartbeat(endpoint_id: str, metrics: HeartbeatMetrics, current_user: dict = Depends(require_admin)):
    """Receive heartbeat from endpoint agent"""
    result = rmm_service.heartbeat(endpoint_id, metrics.model_dump())

    if not result["success"]:
        raise HTTPException(status_code=404, detail=result.get("error", "Heartbeat failed"))

    return result


@router.post("/endpoints/{endpoint_id}/maintenance")
async def set_maintenance_mode(endpoint_id: str, data: MaintenanceMode, current_user: dict = Depends(require_admin)):
    """Set endpoint maintenance mode"""
    result = rmm_service.set_maintenance_mode(
        endpoint_id,
        enabled=data.enabled,
        reason=data.reason
    )

    if not result:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return {
        "endpoint_id": endpoint_id,
        "maintenance_mode": data.enabled,
        "reason": data.reason
    }


@router.get("/endpoints/{endpoint_id}/health")
async def get_endpoint_health(endpoint_id: str):
    """Get endpoint health summary"""
    health = rmm_service.get_endpoint_health_summary(endpoint_id)
    if not health:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return health


@router.get("/endpoints/{endpoint_id}/software")
async def get_endpoint_software(endpoint_id: str):
    """Get endpoint software inventory"""
    endpoint = rmm_service.get_endpoint(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    software = rmm_service.get_software_inventory(endpoint_id)
    return {
        "endpoint_id": endpoint_id,
        "hostname": endpoint.hostname,
        "count": len(software),
        "software": [software_to_dict(s) for s in software]
    }


@router.put("/endpoints/{endpoint_id}/software")
async def update_endpoint_software(endpoint_id: str, data: SoftwareInventoryUpdate, current_user: dict = Depends(require_admin)):
    """Update endpoint software inventory"""
    endpoint = rmm_service.get_endpoint(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    software_list = [s.model_dump() for s in data.software]
    count = rmm_service.update_software_inventory(endpoint_id, software_list)

    return {
        "endpoint_id": endpoint_id,
        "software_count": count
    }


# ========== Alert Routes ==========

@router.get("/alerts")
async def list_alerts(
    endpoint_id: Optional[str] = None,
    severity: Optional[AlertSeverity] = None,
    category: Optional[AlertCategory] = None,
    acknowledged: Optional[bool] = None,
    resolved: Optional[bool] = None
):
    """List all alerts with optional filtering"""
    try:
        alerts = rmm_service.list_alerts(
            endpoint_id=endpoint_id,
            severity=severity,
            category=category,
            acknowledged=acknowledged,
            resolved=resolved
        )

        unacknowledged = [a for a in alerts if not getattr(a, "acknowledged", False)]
        unresolved = [a for a in alerts if not getattr(a, "resolved", False)]

        return {
            "count": len(alerts),
            "unacknowledged": len(unacknowledged),
            "unresolved": len(unresolved),
            "alerts": [alert_to_dict(a) for a in alerts]
        }
    except Exception:
        return {"count": 0, "unacknowledged": 0, "unresolved": 0, "alerts": []}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get alert details"""
    alert = rmm_service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_dict(alert)


@router.post("/alerts")
async def create_alert(data: AlertCreate, current_user: dict = Depends(require_admin)):
    """Create a new alert"""
    alert = rmm_service.create_alert(
        endpoint_id=data.endpoint_id,
        severity=data.severity,
        category=data.category,
        title=data.title,
        message=data.message,
        metric_name=data.metric_name,
        metric_value=data.metric_value,
        threshold=data.threshold
    )

    return alert_to_dict(alert)


@router.put("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, data: AlertAcknowledge, current_user: dict = Depends(require_admin)):
    """Acknowledge an alert"""
    result = rmm_service.acknowledge_alert(
        alert_id,
        acknowledged_by=data.acknowledged_by,
        notes=data.notes
    )

    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = rmm_service.get_alert(alert_id)
    return alert_to_dict(alert)


@router.put("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, current_user: dict = Depends(require_admin)):
    """Resolve an alert"""
    result = rmm_service.resolve_alert(alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = rmm_service.get_alert(alert_id)
    return alert_to_dict(alert)


@router.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: str, current_user: dict = Depends(require_admin)):
    """Delete an alert"""
    result = rmm_service.delete_alert(alert_id)
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"status": "deleted", "alert_id": alert_id}


# ========== Command Routes ==========

@router.get("/commands")
async def list_commands(
    endpoint_id: Optional[str] = None,
    status: Optional[CommandStatus] = None,
    limit: int = Query(default=100, le=500)
):
    """List commands with optional filtering"""
    commands = rmm_service.list_commands(
        endpoint_id=endpoint_id,
        status=status,
        limit=limit
    )

    return {
        "count": len(commands),
        "commands": [command_to_dict(c) for c in commands]
    }


@router.get("/commands/{command_id}")
async def get_command(command_id: str):
    """Get command details"""
    command = rmm_service.get_command(command_id)
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    return command_to_dict(command)


@router.post("/commands")
async def queue_command(data: CommandQueue, current_user: dict = Depends(require_admin)):
    """Queue a command for an endpoint"""
    endpoint = rmm_service.get_endpoint(data.endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    command = rmm_service.queue_command(
        endpoint_id=data.endpoint_id,
        command_type=data.command_type,
        command=data.command,
        parameters=data.parameters,
        queued_by=data.queued_by,
        timeout_seconds=data.timeout_seconds
    )

    return command_to_dict(command)


@router.put("/commands/{command_id}/status")
async def update_command_status(command_id: str, data: CommandStatusUpdate, current_user: dict = Depends(require_admin)):
    """Update command execution status"""
    result = rmm_service.update_command_status(
        command_id,
        status=data.status,
        output=data.output,
        exit_code=data.exit_code,
        error=data.error
    )

    if not result:
        raise HTTPException(status_code=404, detail="Command not found")

    command = rmm_service.get_command(command_id)
    return command_to_dict(command)


@router.put("/commands/{command_id}/cancel")
async def cancel_command(command_id: str, current_user: dict = Depends(require_admin)):
    """Cancel a queued command"""
    result = rmm_service.cancel_command(command_id)
    if not result:
        raise HTTPException(
            status_code=400,
            detail="Command not found or cannot be cancelled"
        )

    command = rmm_service.get_command(command_id)
    return command_to_dict(command)


# ========== Patch Routes ==========

@router.get("/patches")
async def list_patches(
    endpoint_id: Optional[str] = None,
    status: Optional[PatchStatus] = None
):
    """List patches with optional filtering"""
    patches = rmm_service.list_patches(
        endpoint_id=endpoint_id,
        status=status
    )

    return {
        "count": len(patches),
        "patches": [patch_to_dict(p) for p in patches]
    }


@router.get("/patches/{patch_id}")
async def get_patch(patch_id: str):
    """Get patch details"""
    patch = rmm_service.get_patch(patch_id)
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")
    return patch_to_dict(patch)


@router.post("/patches")
async def add_patch(data: PatchAdd, current_user: dict = Depends(require_admin)):
    """Add a pending patch for an endpoint"""
    endpoint = rmm_service.get_endpoint(data.endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    patch = rmm_service.add_patch(
        endpoint_id=data.endpoint_id,
        kb_id=data.kb_id,
        title=data.title,
        description=data.description,
        severity=data.severity,
        size_mb=data.size_mb,
        requires_reboot=data.requires_reboot
    )

    return patch_to_dict(patch)


@router.put("/patches/{patch_id}/status")
async def update_patch_status(patch_id: str, data: PatchStatusUpdate, current_user: dict = Depends(require_admin)):
    """Update patch status"""
    result = rmm_service.update_patch_status(patch_id, data.status)
    if not result:
        raise HTTPException(status_code=404, detail="Patch not found")

    patch = rmm_service.get_patch(patch_id)
    return patch_to_dict(patch)


# ========== Automation Policy Routes ==========

@router.get("/policies")
async def list_policies(
    policy_type: Optional[PolicyType] = None,
    enabled_only: bool = False
):
    """List all automation policies"""
    policies = rmm_service.list_policies(
        policy_type=policy_type,
        enabled_only=enabled_only
    )

    return {
        "count": len(policies),
        "policies": [policy_to_dict(p) for p in policies]
    }


@router.get("/policies/{policy_id}")
async def get_policy(policy_id: str):
    """Get policy details"""
    policy = rmm_service.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy_to_dict(policy)


@router.post("/policies")
async def create_policy(data: PolicyCreate, current_user: dict = Depends(require_admin)):
    """Create a new automation policy"""
    policy = rmm_service.create_policy(
        name=data.name,
        description=data.description,
        policy_type=data.policy_type,
        trigger_conditions=data.trigger_conditions,
        actions=data.actions,
        target_groups=data.target_groups,
        target_tags=data.target_tags,
        schedule=data.schedule,
        cooldown_minutes=data.cooldown_minutes
    )

    return policy_to_dict(policy)


@router.put("/policies/{policy_id}")
async def update_policy(policy_id: str, data: PolicyUpdate, current_user: dict = Depends(require_admin)):
    """Update an automation policy"""
    updates = data.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")

    policy = rmm_service.update_policy(policy_id, **updates)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return policy_to_dict(policy)


@router.put("/policies/{policy_id}/enable")
async def enable_policy(policy_id: str, enabled: bool = True, current_user: dict = Depends(require_admin)):
    """Enable or disable a policy"""
    result = rmm_service.enable_policy(policy_id, enabled)
    if not result:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = rmm_service.get_policy(policy_id)
    return policy_to_dict(policy)


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str, current_user: dict = Depends(require_admin)):
    """Delete an automation policy"""
    result = rmm_service.delete_policy(policy_id)
    if not result:
        raise HTTPException(status_code=404, detail="Policy not found")

    return {"status": "deleted", "policy_id": policy_id}


@router.get("/policies/{policy_id}/executions")
async def get_policy_executions(
    policy_id: str,
    limit: int = Query(default=100, le=500)
):
    """Get policy execution history"""
    policy = rmm_service.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    executions = rmm_service.get_policy_executions(
        policy_id=policy_id,
        limit=limit
    )

    return {
        "policy_id": policy_id,
        "count": len(executions),
        "executions": [execution_to_dict(e) for e in executions]
    }


@router.post("/policies/executions")
async def record_policy_execution(data: PolicyExecutionRecord, current_user: dict = Depends(require_admin)):
    """Record a policy execution"""
    policy = rmm_service.get_policy(data.policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    execution = rmm_service.record_policy_execution(
        policy_id=data.policy_id,
        endpoint_id=data.endpoint_id,
        triggered_by=data.triggered_by,
        actions_taken=data.actions_taken,
        success=data.success,
        error=data.error
    )

    return execution_to_dict(execution)


# ========== Software Search Routes ==========

@router.get("/software/search")
async def search_software(
    name: Optional[str] = None,
    publisher: Optional[str] = None
):
    """Search software across all endpoints"""
    if not name and not publisher:
        raise HTTPException(
            status_code=400,
            detail="At least one search parameter (name or publisher) is required"
        )

    results = rmm_service.search_software(name=name, publisher=publisher)

    formatted_results = {}
    for endpoint_id, software_list in results.items():
        endpoint = rmm_service.get_endpoint(endpoint_id)
        formatted_results[endpoint_id] = {
            "hostname": endpoint.hostname if endpoint else "Unknown",
            "software": [software_to_dict(s) for s in software_list]
        }

    return {
        "endpoints_count": len(results),
        "results": formatted_results
    }


# ========== Dashboard Routes ==========

@router.get("/dashboard")
async def get_rmm_dashboard():
    """Get RMM dashboard summary"""
    return rmm_service.get_dashboard()


@router.get("/health")
async def rmm_health():
    """RMM service health check"""
    dashboard = rmm_service.get_dashboard()

    return {
        "status": "healthy",
        "endpoints_monitored": dashboard["endpoints"]["total"],
        "active_alerts": dashboard["alerts"]["unresolved"],
        "active_policies": dashboard["policies"]["enabled"],
        "timestamp": dashboard["timestamp"]
    }


@router.post("/check-offline")
async def check_offline_endpoints(current_user: dict = Depends(require_admin)):
    """Check for offline endpoints and generate alerts"""
    try:
        alerts = rmm_service.check_offline_endpoints()
        return {
            "checked": True,
            "offline_alerts_generated": len(alerts),
            "alerts": [alert_to_dict(a) for a in alerts]
        }
    except Exception as e:
        return {
            "checked": True,
            "offline_alerts_generated": 0,
            "alerts": [],
            "note": f"Check completed with no endpoints to scan ({type(e).__name__})"
        }
