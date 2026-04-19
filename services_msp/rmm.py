"""
AITHER Platform - RMM (Remote Monitoring & Management) Service
Comprehensive endpoint monitoring and management system

Provides:
- Endpoint registration and monitoring
- Agent management and heartbeats
- Remote command execution
- Patch management
- Alert management
- Automation policies
- Software inventory
- System information collection

G-46: Refactored for DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.msp import (
        RMMEndpoint as RMMEndpointModel,
        RMMAlert as RMMAlertModel,
        RMMCommand as RMMCommandModel,
        RMMPatch as RMMPatchModel,
        RMMSoftware as RMMSoftwareModel,
        RMMPolicy as RMMPolicyModel,
        RMMPolicyExecution as RMMPolicyExecutionModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


class EndpointStatus(str, Enum):
    """Endpoint status"""
    ONLINE = "online"
    OFFLINE = "offline"
    WARNING = "warning"
    MAINTENANCE = "maintenance"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(str, Enum):
    """Alert categories"""
    PERFORMANCE = "performance"
    SECURITY = "security"
    CONNECTIVITY = "connectivity"
    HARDWARE = "hardware"
    SOFTWARE = "software"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class CommandStatus(str, Enum):
    """Command execution status"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class PatchStatus(str, Enum):
    """Patch status"""
    AVAILABLE = "available"
    DOWNLOADING = "downloading"
    PENDING = "pending"
    INSTALLED = "installed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PolicyType(str, Enum):
    """Automation policy types"""
    THRESHOLD = "threshold"
    SCHEDULE = "schedule"
    EVENT = "event"
    CONDITION = "condition"


@dataclass
class SystemMetrics:
    """System performance metrics"""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    network_in_bytes: int = 0
    network_out_bytes: int = 0
    process_count: int = 0
    uptime_seconds: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SystemInfo:
    """System information"""
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    hostname: str = ""
    domain: str = ""
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    cpu_model: str = ""
    cpu_cores: int = 0
    ram_total_gb: float = 0.0
    disk_total_gb: float = 0.0
    last_boot: Optional[datetime] = None


@dataclass
class Endpoint:
    """Monitored endpoint"""
    endpoint_id: str
    hostname: str
    ip_address: str
    mac_address: str = ""
    client_id: str = ""
    client_name: str = ""
    status: EndpointStatus = EndpointStatus.UNKNOWN
    agent_version: str = ""
    agent_installed_at: Optional[datetime] = None
    system_info: SystemInfo = field(default_factory=SystemInfo)
    metrics: SystemMetrics = field(default_factory=SystemMetrics)
    tags: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    last_seen: Optional[datetime] = None
    last_reboot: Optional[datetime] = None
    alerts_count: int = 0
    patches_pending: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class Alert:
    """Monitoring alert"""
    alert_id: str
    endpoint_id: str
    hostname: str
    severity: AlertSeverity
    category: AlertCategory
    title: str
    message: str
    metric_name: str = ""
    metric_value: float = 0.0
    threshold: float = 0.0
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Command:
    """Remote command"""
    command_id: str
    endpoint_id: str
    command_type: str
    command: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: CommandStatus = CommandStatus.QUEUED
    output: str = ""
    exit_code: Optional[int] = None
    error: str = ""
    queued_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeout_seconds: int = 300
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Patch:
    """Software patch"""
    patch_id: str
    endpoint_id: str
    kb_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "important"
    status: PatchStatus = PatchStatus.AVAILABLE
    size_mb: float = 0.0
    download_url: str = ""
    installed_at: Optional[datetime] = None
    requires_reboot: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Software:
    """Installed software"""
    software_id: str
    endpoint_id: str
    name: str
    version: str
    publisher: str = ""
    install_date: Optional[datetime] = None
    install_location: str = ""
    size_mb: float = 0.0
    is_update: bool = False


@dataclass
class AutomationPolicy:
    """Automation policy"""
    policy_id: str
    name: str
    description: str = ""
    policy_type: PolicyType = PolicyType.THRESHOLD
    enabled: bool = True
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    target_groups: List[str] = field(default_factory=list)
    target_tags: List[str] = field(default_factory=list)
    schedule: Optional[str] = None  # Cron expression
    cooldown_minutes: int = 15
    last_triggered: Optional[datetime] = None
    execution_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class PolicyExecution:
    """Policy execution record"""
    execution_id: str
    policy_id: str
    endpoint_id: str
    triggered_by: str  # condition that triggered
    actions_taken: List[str] = field(default_factory=list)
    command_ids: List[str] = field(default_factory=list)
    success: bool = True
    error: str = ""
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _endpoint_from_row(row) -> Endpoint:
    """Convert RMMEndpointModel row to Endpoint dataclass."""
    si_data = row.system_info or {}
    sys_info = SystemInfo(**{k: v for k, v in si_data.items() if hasattr(SystemInfo, k) and k != "last_boot"})
    m_data = row.metrics or {}
    metrics = SystemMetrics(
        cpu_percent=m_data.get("cpu_percent", 0.0),
        memory_percent=m_data.get("memory_percent", 0.0),
        disk_percent=m_data.get("disk_percent", 0.0),
        network_in_bytes=m_data.get("network_in_bytes", 0),
        network_out_bytes=m_data.get("network_out_bytes", 0),
        process_count=m_data.get("process_count", 0),
        uptime_seconds=m_data.get("uptime_seconds", 0),
    )
    return Endpoint(
        endpoint_id=row.endpoint_id,
        hostname=row.hostname,
        ip_address=row.ip_address,
        mac_address=row.mac_address or "",
        client_id=row.client_id or "",
        client_name=row.client_name or "",
        status=EndpointStatus(row.status) if row.status else EndpointStatus.UNKNOWN,
        agent_version=row.agent_version or "",
        agent_installed_at=row.agent_installed_at,
        system_info=sys_info,
        metrics=metrics,
        tags=row.tags or [],
        groups=row.groups or [],
        last_seen=row.last_seen,
        last_reboot=row.last_reboot,
        alerts_count=row.alerts_count or 0,
        patches_pending=row.patches_pending or 0,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _alert_from_row(row) -> Alert:
    return Alert(
        alert_id=row.alert_id,
        endpoint_id=row.endpoint_id,
        hostname=row.hostname or "Unknown",
        severity=AlertSeverity(row.severity),
        category=AlertCategory(row.category),
        title=row.title,
        message=row.message or "",
        metric_name=row.metric_name or "",
        metric_value=row.metric_value or 0.0,
        threshold=row.threshold or 0.0,
        acknowledged=row.acknowledged or False,
        acknowledged_by=row.acknowledged_by,
        acknowledged_at=row.acknowledged_at,
        resolved=row.resolved or False,
        resolved_at=row.resolved_at,
        notes=row.notes or "",
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _command_from_row(row) -> Command:
    return Command(
        command_id=row.command_id,
        endpoint_id=row.endpoint_id,
        command_type=row.command_type,
        command=row.command,
        parameters=row.parameters or {},
        status=CommandStatus(row.status) if row.status else CommandStatus.QUEUED,
        output=row.output or "",
        exit_code=row.exit_code,
        error=row.error or "",
        queued_by=row.queued_by,
        started_at=row.started_at,
        completed_at=row.completed_at,
        timeout_seconds=row.timeout_seconds or 300,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _patch_from_row(row) -> Patch:
    return Patch(
        patch_id=row.patch_id,
        endpoint_id=row.endpoint_id,
        kb_id=row.kb_id or "",
        title=row.title or "",
        description=row.description or "",
        severity=row.severity or "important",
        status=PatchStatus(row.status) if row.status else PatchStatus.AVAILABLE,
        size_mb=row.size_mb or 0.0,
        download_url=row.download_url or "",
        installed_at=row.installed_at,
        requires_reboot=row.requires_reboot or False,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _software_from_row(row) -> Software:
    return Software(
        software_id=row.software_id,
        endpoint_id=row.endpoint_id,
        name=row.name,
        version=row.version or "",
        publisher=row.publisher or "",
        install_date=row.install_date,
        install_location=row.install_location or "",
        size_mb=row.size_mb or 0.0,
        is_update=row.is_update or False,
    )


def _policy_from_row(row) -> AutomationPolicy:
    return AutomationPolicy(
        policy_id=row.policy_id,
        name=row.name,
        description=row.description or "",
        policy_type=PolicyType(row.policy_type) if row.policy_type else PolicyType.THRESHOLD,
        enabled=row.enabled if row.enabled is not None else True,
        trigger_conditions=row.trigger_conditions or {},
        actions=row.actions or [],
        target_groups=row.target_groups or [],
        target_tags=row.target_tags or [],
        schedule=row.schedule,
        cooldown_minutes=row.cooldown_minutes or 15,
        last_triggered=row.last_triggered,
        execution_count=row.execution_count or 0,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _execution_from_row(row) -> PolicyExecution:
    return PolicyExecution(
        execution_id=row.execution_id,
        policy_id=row.policy_id,
        endpoint_id=row.endpoint_id,
        triggered_by=row.triggered_by or "",
        actions_taken=row.actions_taken or [],
        command_ids=row.command_ids if hasattr(row, "command_ids") and row.command_ids else [],
        success=row.success if row.success is not None else True,
        error=row.error or "",
        executed_at=row.executed_at or datetime.now(timezone.utc),
    )


def _sys_info_to_dict(si: SystemInfo) -> dict:
    return {
        "os_name": si.os_name, "os_version": si.os_version, "os_build": si.os_build,
        "hostname": si.hostname, "domain": si.domain, "manufacturer": si.manufacturer,
        "model": si.model, "serial_number": si.serial_number, "cpu_model": si.cpu_model,
        "cpu_cores": si.cpu_cores, "ram_total_gb": si.ram_total_gb, "disk_total_gb": si.disk_total_gb,
    }


def _metrics_to_dict(m: SystemMetrics) -> dict:
    return {
        "cpu_percent": m.cpu_percent, "memory_percent": m.memory_percent,
        "disk_percent": m.disk_percent, "network_in_bytes": m.network_in_bytes,
        "network_out_bytes": m.network_out_bytes, "process_count": m.process_count,
        "uptime_seconds": m.uptime_seconds,
    }


class RMMService:
    """
    RMM Service - Remote Monitoring & Management

    Comprehensive endpoint monitoring and management system
    for MSP operations.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: Session = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._endpoints: Dict[str, Endpoint] = {}
        self._alerts: Dict[str, Alert] = {}
        self._commands: Dict[str, Command] = {}
        self._patches: Dict[str, Patch] = {}
        self._software: Dict[str, List[Software]] = {}  # endpoint_id -> software list
        self._policies: Dict[str, AutomationPolicy] = {}
        self._policy_executions: List[PolicyExecution] = []

        # Alert thresholds
        self._thresholds = {
            "cpu_critical": 95,
            "cpu_warning": 85,
            "memory_critical": 95,
            "memory_warning": 85,
            "disk_critical": 95,
            "disk_warning": 90,
            "offline_minutes": 5
        }

        # Initialize some default policies
        self._init_default_policies()

    def _init_default_policies(self) -> None:
        """Initialize default automation policies"""
        self.create_policy(
            name="High CPU Alert",
            description="Alert when CPU exceeds 90%",
            policy_type=PolicyType.THRESHOLD,
            trigger_conditions={"metric": "cpu_percent", "operator": ">", "value": 90},
            actions=[{"type": "alert", "severity": "warning"}]
        )

        self.create_policy(
            name="Critical Memory Alert",
            description="Alert when memory exceeds 95%",
            policy_type=PolicyType.THRESHOLD,
            trigger_conditions={"metric": "memory_percent", "operator": ">", "value": 95},
            actions=[{"type": "alert", "severity": "critical"}]
        )

        self.create_policy(
            name="Disk Space Critical",
            description="Alert when disk space exceeds 95%",
            policy_type=PolicyType.THRESHOLD,
            trigger_conditions={"metric": "disk_percent", "operator": ">", "value": 95},
            actions=[{"type": "alert", "severity": "critical"}]
        )

    # ========== Endpoint Management ==========

    def register_endpoint(
        self,
        hostname: str,
        ip_address: str,
        mac_address: str = "",
        client_id: str = "",
        client_name: str = "",
        agent_version: str = "",
        system_info: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        groups: Optional[List[str]] = None
    ) -> Endpoint:
        """Register a new endpoint"""
        endpoint_id = f"EP-{uuid.uuid4().hex[:8].upper()}"

        sys_info = SystemInfo()
        if system_info:
            for key, value in system_info.items():
                if hasattr(sys_info, key):
                    setattr(sys_info, key, value)

        endpoint = Endpoint(
            endpoint_id=endpoint_id,
            hostname=hostname,
            ip_address=ip_address,
            mac_address=mac_address,
            client_id=client_id,
            client_name=client_name,
            status=EndpointStatus.ONLINE,
            agent_version=agent_version,
            agent_installed_at=datetime.now(timezone.utc),
            system_info=sys_info,
            tags=tags or [],
            groups=groups or [],
            last_seen=datetime.now(timezone.utc)
        )

        if self._use_db:
            try:
                row = RMMEndpointModel(
                    endpoint_id=endpoint_id,
                    hostname=hostname,
                    ip_address=ip_address,
                    mac_address=mac_address,
                    client_id=client_id,
                    client_name=client_name,
                    status=EndpointStatus.ONLINE.value,
                    agent_version=agent_version,
                    agent_installed_at=datetime.now(timezone.utc),
                    system_info=_sys_info_to_dict(sys_info),
                    metrics=_metrics_to_dict(endpoint.metrics),
                    tags=tags or [],
                    groups=groups or [],
                    last_seen=datetime.now(timezone.utc),
                    alerts_count=0,
                    patches_pending=0,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error registering endpoint: {e}")
                self.db.rollback()

        self._endpoints[endpoint_id] = endpoint
        return endpoint

    def update_endpoint(
        self,
        endpoint_id: str,
        **updates
    ) -> Optional[Endpoint]:
        """Update endpoint properties"""
        endpoint = self.get_endpoint(endpoint_id)
        if not endpoint:
            return None

        for key, value in updates.items():
            if hasattr(endpoint, key):
                setattr(endpoint, key, value)

        endpoint.updated_at = datetime.now(timezone.utc)
        self._endpoints[endpoint_id] = endpoint

        if self._use_db:
            try:
                row = self.db.query(RMMEndpointModel).filter(
                    RMMEndpointModel.endpoint_id == endpoint_id
                ).first()
                if row:
                    for key, value in updates.items():
                        if key == "status" and isinstance(value, EndpointStatus):
                            value = value.value
                        if hasattr(row, key):
                            setattr(row, key, value)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating endpoint: {e}")
                self.db.rollback()

        return endpoint

    def heartbeat(
        self,
        endpoint_id: str,
        metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process heartbeat from endpoint agent"""
        endpoint = self.get_endpoint(endpoint_id)
        if not endpoint:
            return {"success": False, "error": "Endpoint not found"}

        # Update metrics
        endpoint.metrics = SystemMetrics(
            cpu_percent=metrics.get("cpu", 0),
            memory_percent=metrics.get("memory", 0),
            disk_percent=metrics.get("disk", 0),
            network_in_bytes=metrics.get("network_in", 0),
            network_out_bytes=metrics.get("network_out", 0),
            process_count=metrics.get("processes", 0),
            uptime_seconds=metrics.get("uptime", 0)
        )

        endpoint.last_seen = datetime.now(timezone.utc)
        endpoint.status = EndpointStatus.ONLINE
        self._endpoints[endpoint_id] = endpoint

        if self._use_db:
            try:
                row = self.db.query(RMMEndpointModel).filter(
                    RMMEndpointModel.endpoint_id == endpoint_id
                ).first()
                if row:
                    row.metrics = _metrics_to_dict(endpoint.metrics)
                    row.last_seen = endpoint.last_seen
                    row.status = EndpointStatus.ONLINE.value
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error in heartbeat: {e}")
                self.db.rollback()

        # Check thresholds and generate alerts
        alerts_generated = self._check_thresholds(endpoint)

        # Evaluate automation policies and dispatch commands
        policy_executions = self.evaluate_policies(endpoint)

        # Check pending commands (includes any just dispatched by policies)
        pending_commands = self._get_pending_commands(endpoint_id)

        return {
            "success": True,
            "alerts_generated": len(alerts_generated),
            "policies_triggered": len(policy_executions),
            "commands_dispatched": [
                cmd_id
                for exe in policy_executions
                for cmd_id in exe.command_ids
            ],
            "pending_commands": [c.command_id for c in pending_commands]
        }

    def _check_thresholds(self, endpoint: Endpoint) -> List[Alert]:
        """Check metrics against thresholds and generate alerts"""
        alerts = []
        metrics = endpoint.metrics

        # CPU check
        if metrics.cpu_percent >= self._thresholds["cpu_critical"]:
            alert = self.create_alert(
                endpoint_id=endpoint.endpoint_id,
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.PERFORMANCE,
                title="Critical CPU Usage",
                message=f"CPU usage at {metrics.cpu_percent}% exceeds critical threshold",
                metric_name="cpu_percent",
                metric_value=metrics.cpu_percent,
                threshold=self._thresholds["cpu_critical"]
            )
            alerts.append(alert)
        elif metrics.cpu_percent >= self._thresholds["cpu_warning"]:
            alert = self.create_alert(
                endpoint_id=endpoint.endpoint_id,
                severity=AlertSeverity.MEDIUM,
                category=AlertCategory.PERFORMANCE,
                title="High CPU Usage",
                message=f"CPU usage at {metrics.cpu_percent}% exceeds warning threshold",
                metric_name="cpu_percent",
                metric_value=metrics.cpu_percent,
                threshold=self._thresholds["cpu_warning"]
            )
            alerts.append(alert)

        # Memory check
        if metrics.memory_percent >= self._thresholds["memory_critical"]:
            alert = self.create_alert(
                endpoint_id=endpoint.endpoint_id,
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.PERFORMANCE,
                title="Critical Memory Usage",
                message=f"Memory usage at {metrics.memory_percent}% exceeds critical threshold",
                metric_name="memory_percent",
                metric_value=metrics.memory_percent,
                threshold=self._thresholds["memory_critical"]
            )
            alerts.append(alert)

        # Disk check
        if metrics.disk_percent >= self._thresholds["disk_critical"]:
            alert = self.create_alert(
                endpoint_id=endpoint.endpoint_id,
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.PERFORMANCE,
                title="Critical Disk Space",
                message=f"Disk usage at {metrics.disk_percent}% exceeds critical threshold",
                metric_name="disk_percent",
                metric_value=metrics.disk_percent,
                threshold=self._thresholds["disk_critical"]
            )
            alerts.append(alert)

        return alerts

    def check_offline_endpoints(self) -> List[Alert]:
        """Check for offline endpoints and generate alerts"""
        alerts = []
        threshold_time = datetime.now(timezone.utc) - timedelta(
            minutes=self._thresholds["offline_minutes"]
        )

        for endpoint in self._get_all_endpoints():
            if endpoint.status != EndpointStatus.MAINTENANCE:
                if endpoint.last_seen and endpoint.last_seen < threshold_time:
                    if endpoint.status != EndpointStatus.OFFLINE:
                        endpoint.status = EndpointStatus.OFFLINE
                        self._endpoints[endpoint.endpoint_id] = endpoint
                        if self._use_db:
                            try:
                                row = self.db.query(RMMEndpointModel).filter(
                                    RMMEndpointModel.endpoint_id == endpoint.endpoint_id
                                ).first()
                                if row:
                                    row.status = EndpointStatus.OFFLINE.value
                                    self.db.commit()
                            except Exception:
                                self.db.rollback()

                        alert = self.create_alert(
                            endpoint_id=endpoint.endpoint_id,
                            severity=AlertSeverity.HIGH,
                            category=AlertCategory.CONNECTIVITY,
                            title="Endpoint Offline",
                            message=f"No heartbeat received for {self._thresholds['offline_minutes']} minutes",
                            metric_name="connectivity",
                            metric_value=0
                        )
                        alerts.append(alert)

        return alerts

    def set_maintenance_mode(
        self,
        endpoint_id: str,
        enabled: bool,
        reason: str = ""
    ) -> bool:
        """Set endpoint maintenance mode"""
        endpoint = self.get_endpoint(endpoint_id)
        if not endpoint:
            return False

        if enabled:
            endpoint.status = EndpointStatus.MAINTENANCE
        else:
            endpoint.status = EndpointStatus.UNKNOWN

        endpoint.updated_at = datetime.now(timezone.utc)
        self._endpoints[endpoint_id] = endpoint

        if self._use_db:
            try:
                row = self.db.query(RMMEndpointModel).filter(
                    RMMEndpointModel.endpoint_id == endpoint_id
                ).first()
                if row:
                    row.status = endpoint.status.value
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error in maintenance mode: {e}")
                self.db.rollback()

        return True

    def get_endpoint(self, endpoint_id: str) -> Optional[Endpoint]:
        """Get endpoint by ID"""
        # Check in-memory cache first
        if endpoint_id in self._endpoints:
            return self._endpoints[endpoint_id]
        # Try DB
        if self._use_db:
            try:
                row = self.db.query(RMMEndpointModel).filter(
                    RMMEndpointModel.endpoint_id == endpoint_id
                ).first()
                if row:
                    ep = _endpoint_from_row(row)
                    self._endpoints[endpoint_id] = ep
                    return ep
            except Exception as e:
                logger.error(f"DB error getting endpoint: {e}")
        return None

    def get_endpoint_by_hostname(self, hostname: str) -> Optional[Endpoint]:
        """Get endpoint by hostname"""
        for endpoint in self._get_all_endpoints():
            if endpoint.hostname.lower() == hostname.lower():
                return endpoint
        return None

    def delete_endpoint(self, endpoint_id: str) -> bool:
        """Delete an endpoint"""
        found = endpoint_id in self._endpoints
        if found:
            del self._endpoints[endpoint_id]
            self._software.pop(endpoint_id, None)

        if self._use_db:
            try:
                row = self.db.query(RMMEndpointModel).filter(
                    RMMEndpointModel.endpoint_id == endpoint_id
                ).first()
                if row:
                    self.db.delete(row)
                    # Also delete related software
                    self.db.query(RMMSoftwareModel).filter(
                        RMMSoftwareModel.endpoint_id == endpoint_id
                    ).delete()
                    self.db.commit()
                    found = True
            except Exception as e:
                logger.error(f"DB error deleting endpoint: {e}")
                self.db.rollback()

        return found

    def _get_all_endpoints(self) -> List[Endpoint]:
        """Get all endpoints from DB + memory."""
        if self._use_db:
            try:
                rows = self.db.query(RMMEndpointModel).all()
                for row in rows:
                    if row.endpoint_id not in self._endpoints:
                        self._endpoints[row.endpoint_id] = _endpoint_from_row(row)
            except Exception as e:
                logger.error(f"DB error listing endpoints: {e}")
        return list(self._endpoints.values())

    def list_endpoints(
        self,
        status: Optional[EndpointStatus] = None,
        client_id: Optional[str] = None,
        group: Optional[str] = None,
        tag: Optional[str] = None
    ) -> List[Endpoint]:
        """List endpoints with filters"""
        endpoints = self._get_all_endpoints()

        if status:
            endpoints = [e for e in endpoints if e.status == status]
        if client_id:
            endpoints = [e for e in endpoints if e.client_id == client_id]
        if group:
            endpoints = [e for e in endpoints if group in e.groups]
        if tag:
            endpoints = [e for e in endpoints if tag in e.tags]

        return sorted(endpoints, key=lambda e: e.hostname)

    # ========== Alert Management ==========

    def create_alert(
        self,
        endpoint_id: str,
        severity: AlertSeverity,
        category: AlertCategory,
        title: str,
        message: str,
        metric_name: str = "",
        metric_value: float = 0.0,
        threshold: float = 0.0
    ) -> Alert:
        """Create a new alert"""
        alert_id = f"ALR-{uuid.uuid4().hex[:8].upper()}"

        endpoint = self._endpoints.get(endpoint_id)
        hostname = endpoint.hostname if endpoint else "Unknown"

        alert = Alert(
            alert_id=alert_id,
            endpoint_id=endpoint_id,
            hostname=hostname,
            severity=severity,
            category=category,
            title=title,
            message=message,
            metric_name=metric_name,
            metric_value=metric_value,
            threshold=threshold
        )

        self._alerts[alert_id] = alert

        # Update endpoint alert count
        if endpoint:
            endpoint.alerts_count += 1

        if self._use_db:
            try:
                row = RMMAlertModel(
                    alert_id=alert_id,
                    endpoint_id=endpoint_id,
                    hostname=hostname,
                    severity=severity.value,
                    category=category.value,
                    title=title,
                    message=message,
                    metric_name=metric_name,
                    metric_value=metric_value,
                    threshold=threshold,
                )
                self.db.add(row)
                # Update endpoint alerts_count in DB too
                ep_row = self.db.query(RMMEndpointModel).filter(
                    RMMEndpointModel.endpoint_id == endpoint_id
                ).first()
                if ep_row:
                    ep_row.alerts_count = (ep_row.alerts_count or 0) + 1
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating alert: {e}")
                self.db.rollback()

        return alert

    def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
        notes: str = ""
    ) -> bool:
        """Acknowledge an alert"""
        alert = self.get_alert(alert_id)
        if not alert:
            return False

        alert.acknowledged = True
        alert.acknowledged_by = acknowledged_by
        alert.acknowledged_at = datetime.now(timezone.utc)
        if notes:
            alert.notes = notes
        self._alerts[alert_id] = alert

        if self._use_db:
            try:
                row = self.db.query(RMMAlertModel).filter(
                    RMMAlertModel.alert_id == alert_id
                ).first()
                if row:
                    row.acknowledged = True
                    row.acknowledged_by = acknowledged_by
                    row.acknowledged_at = datetime.now(timezone.utc)
                    if notes:
                        row.notes = notes
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error acknowledging alert: {e}")
                self.db.rollback()

        return True

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert"""
        alert = self.get_alert(alert_id)
        if not alert:
            return False

        alert.resolved = True
        alert.resolved_at = datetime.now(timezone.utc)
        self._alerts[alert_id] = alert

        # Update endpoint alert count
        endpoint = self._endpoints.get(alert.endpoint_id)
        if endpoint and endpoint.alerts_count > 0:
            endpoint.alerts_count -= 1

        if self._use_db:
            try:
                row = self.db.query(RMMAlertModel).filter(
                    RMMAlertModel.alert_id == alert_id
                ).first()
                if row:
                    row.resolved = True
                    row.resolved_at = datetime.now(timezone.utc)
                    self.db.commit()
                ep_row = self.db.query(RMMEndpointModel).filter(
                    RMMEndpointModel.endpoint_id == alert.endpoint_id
                ).first()
                if ep_row and (ep_row.alerts_count or 0) > 0:
                    ep_row.alerts_count -= 1
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error resolving alert: {e}")
                self.db.rollback()

        return True

    def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert"""
        found = alert_id in self._alerts
        if found:
            del self._alerts[alert_id]

        if self._use_db:
            try:
                row = self.db.query(RMMAlertModel).filter(
                    RMMAlertModel.alert_id == alert_id
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
                    found = True
            except Exception as e:
                logger.error(f"DB error deleting alert: {e}")
                self.db.rollback()

        return found

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID"""
        if alert_id in self._alerts:
            return self._alerts[alert_id]
        if self._use_db:
            try:
                row = self.db.query(RMMAlertModel).filter(
                    RMMAlertModel.alert_id == alert_id
                ).first()
                if row:
                    a = _alert_from_row(row)
                    self._alerts[alert_id] = a
                    return a
            except Exception as e:
                logger.error(f"DB error getting alert: {e}")
        return None

    def list_alerts(
        self,
        endpoint_id: Optional[str] = None,
        severity: Optional[AlertSeverity] = None,
        category: Optional[AlertCategory] = None,
        acknowledged: Optional[bool] = None,
        resolved: Optional[bool] = None
    ) -> List[Alert]:
        """List alerts with filters"""
        # Hydrate from DB
        if self._use_db:
            try:
                q = self.db.query(RMMAlertModel)
                if endpoint_id:
                    q = q.filter(RMMAlertModel.endpoint_id == endpoint_id)
                if severity:
                    q = q.filter(RMMAlertModel.severity == severity.value)
                if category:
                    q = q.filter(RMMAlertModel.category == category.value)
                if acknowledged is not None:
                    q = q.filter(RMMAlertModel.acknowledged == acknowledged)
                if resolved is not None:
                    q = q.filter(RMMAlertModel.resolved == resolved)
                rows = q.all()
                for row in rows:
                    if row.alert_id not in self._alerts:
                        self._alerts[row.alert_id] = _alert_from_row(row)
            except Exception as e:
                logger.error(f"DB error listing alerts: {e}")

        alerts = list(self._alerts.values())

        if endpoint_id:
            alerts = [a for a in alerts if a.endpoint_id == endpoint_id]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if category:
            alerts = [a for a in alerts if a.category == category]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        if resolved is not None:
            alerts = [a for a in alerts if a.resolved == resolved]

        return sorted(alerts, key=lambda a: a.created_at, reverse=True)

    # ========== Command Management ==========

    def queue_command(
        self,
        endpoint_id: str,
        command_type: str,
        command: str,
        parameters: Optional[Dict[str, Any]] = None,
        queued_by: Optional[str] = None,
        timeout_seconds: int = 300
    ) -> Command:
        """Queue a command for an endpoint"""
        command_id = f"CMD-{uuid.uuid4().hex[:8].upper()}"

        cmd = Command(
            command_id=command_id,
            endpoint_id=endpoint_id,
            command_type=command_type,
            command=command,
            parameters=parameters or {},
            queued_by=queued_by,
            timeout_seconds=timeout_seconds
        )

        self._commands[command_id] = cmd

        if self._use_db:
            try:
                row = RMMCommandModel(
                    command_id=command_id,
                    endpoint_id=endpoint_id,
                    command_type=command_type,
                    command=command,
                    parameters=parameters or {},
                    status=CommandStatus.QUEUED.value,
                    queued_by=queued_by,
                    timeout_seconds=timeout_seconds,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error queuing command: {e}")
                self.db.rollback()

        return cmd

    def _get_pending_commands(self, endpoint_id: str) -> List[Command]:
        """Get pending commands for an endpoint"""
        if self._use_db:
            try:
                rows = self.db.query(RMMCommandModel).filter(
                    RMMCommandModel.endpoint_id == endpoint_id,
                    RMMCommandModel.status == CommandStatus.QUEUED.value,
                ).all()
                for row in rows:
                    if row.command_id not in self._commands:
                        self._commands[row.command_id] = _command_from_row(row)
            except Exception:
                pass
        return [
            c for c in self._commands.values()
            if c.endpoint_id == endpoint_id and c.status == CommandStatus.QUEUED
        ]

    def update_command_status(
        self,
        command_id: str,
        status: CommandStatus,
        output: str = "",
        exit_code: Optional[int] = None,
        error: str = ""
    ) -> bool:
        """Update command execution status"""
        command = self.get_command(command_id)
        if not command:
            return False

        command.status = status
        command.output = output
        command.exit_code = exit_code
        command.error = error

        if status == CommandStatus.RUNNING:
            command.started_at = datetime.now(timezone.utc)
        elif status in [CommandStatus.COMPLETED, CommandStatus.FAILED, CommandStatus.TIMEOUT]:
            command.completed_at = datetime.now(timezone.utc)

        self._commands[command_id] = command

        if self._use_db:
            try:
                row = self.db.query(RMMCommandModel).filter(
                    RMMCommandModel.command_id == command_id
                ).first()
                if row:
                    row.status = status.value
                    row.output = output
                    row.exit_code = exit_code
                    row.error = error
                    row.started_at = command.started_at
                    row.completed_at = command.completed_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating command: {e}")
                self.db.rollback()

        return True

    def cancel_command(self, command_id: str) -> bool:
        """Cancel a queued command"""
        command = self.get_command(command_id)
        if not command or command.status != CommandStatus.QUEUED:
            return False

        command.status = CommandStatus.CANCELLED
        self._commands[command_id] = command

        if self._use_db:
            try:
                row = self.db.query(RMMCommandModel).filter(
                    RMMCommandModel.command_id == command_id
                ).first()
                if row:
                    row.status = CommandStatus.CANCELLED.value
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error cancelling command: {e}")
                self.db.rollback()

        return True

    def get_command(self, command_id: str) -> Optional[Command]:
        """Get command by ID"""
        if command_id in self._commands:
            return self._commands[command_id]
        if self._use_db:
            try:
                row = self.db.query(RMMCommandModel).filter(
                    RMMCommandModel.command_id == command_id
                ).first()
                if row:
                    c = _command_from_row(row)
                    self._commands[command_id] = c
                    return c
            except Exception as e:
                logger.error(f"DB error getting command: {e}")
        return None

    def list_commands(
        self,
        endpoint_id: Optional[str] = None,
        status: Optional[CommandStatus] = None,
        limit: int = 100
    ) -> List[Command]:
        """List commands with filters"""
        if self._use_db:
            try:
                q = self.db.query(RMMCommandModel)
                if endpoint_id:
                    q = q.filter(RMMCommandModel.endpoint_id == endpoint_id)
                if status:
                    q = q.filter(RMMCommandModel.status == status.value)
                rows = q.order_by(RMMCommandModel.created_at.desc()).limit(limit).all()
                for row in rows:
                    if row.command_id not in self._commands:
                        self._commands[row.command_id] = _command_from_row(row)
            except Exception as e:
                logger.error(f"DB error listing commands: {e}")

        commands = list(self._commands.values())

        if endpoint_id:
            commands = [c for c in commands if c.endpoint_id == endpoint_id]
        if status:
            commands = [c for c in commands if c.status == status]

        return sorted(commands, key=lambda c: c.created_at, reverse=True)[:limit]

    # ========== Patch Management ==========

    def add_patch(
        self,
        endpoint_id: str,
        kb_id: str,
        title: str,
        description: str = "",
        severity: str = "important",
        size_mb: float = 0.0,
        requires_reboot: bool = False
    ) -> Patch:
        """Add a pending patch for an endpoint"""
        patch_id = f"PAT-{uuid.uuid4().hex[:8].upper()}"

        patch = Patch(
            patch_id=patch_id,
            endpoint_id=endpoint_id,
            kb_id=kb_id,
            title=title,
            description=description,
            severity=severity,
            size_mb=size_mb,
            requires_reboot=requires_reboot
        )

        self._patches[patch_id] = patch

        # Update endpoint patches pending count
        endpoint = self._endpoints.get(endpoint_id)
        if endpoint:
            endpoint.patches_pending += 1

        if self._use_db:
            try:
                row = RMMPatchModel(
                    patch_id=patch_id,
                    endpoint_id=endpoint_id,
                    kb_id=kb_id,
                    title=title,
                    description=description,
                    severity=severity,
                    status=PatchStatus.AVAILABLE.value,
                    size_mb=size_mb,
                    requires_reboot=requires_reboot,
                )
                self.db.add(row)
                ep_row = self.db.query(RMMEndpointModel).filter(
                    RMMEndpointModel.endpoint_id == endpoint_id
                ).first()
                if ep_row:
                    ep_row.patches_pending = (ep_row.patches_pending or 0) + 1
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error adding patch: {e}")
                self.db.rollback()

        return patch

    def update_patch_status(
        self,
        patch_id: str,
        status: PatchStatus
    ) -> bool:
        """Update patch status"""
        patch = self.get_patch(patch_id)
        if not patch:
            return False

        patch.status = status
        self._patches[patch_id] = patch

        if status == PatchStatus.INSTALLED:
            patch.installed_at = datetime.now(timezone.utc)
            endpoint = self._endpoints.get(patch.endpoint_id)
            if endpoint and endpoint.patches_pending > 0:
                endpoint.patches_pending -= 1

        if self._use_db:
            try:
                row = self.db.query(RMMPatchModel).filter(
                    RMMPatchModel.patch_id == patch_id
                ).first()
                if row:
                    row.status = status.value
                    if status == PatchStatus.INSTALLED:
                        row.installed_at = datetime.now(timezone.utc)
                        ep_row = self.db.query(RMMEndpointModel).filter(
                            RMMEndpointModel.endpoint_id == patch.endpoint_id
                        ).first()
                        if ep_row and (ep_row.patches_pending or 0) > 0:
                            ep_row.patches_pending -= 1
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating patch: {e}")
                self.db.rollback()

        return True

    def get_patch(self, patch_id: str) -> Optional[Patch]:
        """Get patch by ID"""
        if patch_id in self._patches:
            return self._patches[patch_id]
        if self._use_db:
            try:
                row = self.db.query(RMMPatchModel).filter(
                    RMMPatchModel.patch_id == patch_id
                ).first()
                if row:
                    p = _patch_from_row(row)
                    self._patches[patch_id] = p
                    return p
            except Exception as e:
                logger.error(f"DB error getting patch: {e}")
        return None

    def list_patches(
        self,
        endpoint_id: Optional[str] = None,
        status: Optional[PatchStatus] = None
    ) -> List[Patch]:
        """List patches with filters"""
        if self._use_db:
            try:
                q = self.db.query(RMMPatchModel)
                if endpoint_id:
                    q = q.filter(RMMPatchModel.endpoint_id == endpoint_id)
                if status:
                    q = q.filter(RMMPatchModel.status == status.value)
                rows = q.all()
                for row in rows:
                    if row.patch_id not in self._patches:
                        self._patches[row.patch_id] = _patch_from_row(row)
            except Exception as e:
                logger.error(f"DB error listing patches: {e}")

        patches = list(self._patches.values())

        if endpoint_id:
            patches = [p for p in patches if p.endpoint_id == endpoint_id]
        if status:
            patches = [p for p in patches if p.status == status]

        return patches

    # ========== Software Inventory ==========

    def update_software_inventory(
        self,
        endpoint_id: str,
        software_list: List[Dict[str, Any]]
    ) -> int:
        """Update software inventory for an endpoint"""
        inventory = []

        for item in software_list:
            software = Software(
                software_id=f"SW-{uuid.uuid4().hex[:8].upper()}",
                endpoint_id=endpoint_id,
                name=item.get("name", ""),
                version=item.get("version", ""),
                publisher=item.get("publisher", ""),
                install_location=item.get("install_location", ""),
                size_mb=item.get("size_mb", 0.0),
                is_update=item.get("is_update", False)
            )
            inventory.append(software)

        self._software[endpoint_id] = inventory

        if self._use_db:
            try:
                # Replace all software for this endpoint
                self.db.query(RMMSoftwareModel).filter(
                    RMMSoftwareModel.endpoint_id == endpoint_id
                ).delete()
                for sw in inventory:
                    row = RMMSoftwareModel(
                        software_id=sw.software_id,
                        endpoint_id=endpoint_id,
                        name=sw.name,
                        version=sw.version,
                        publisher=sw.publisher,
                        install_location=sw.install_location,
                        size_mb=sw.size_mb,
                        is_update=sw.is_update,
                    )
                    self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating software inventory: {e}")
                self.db.rollback()

        return len(inventory)

    def get_software_inventory(self, endpoint_id: str) -> List[Software]:
        """Get software inventory for an endpoint"""
        if endpoint_id in self._software:
            return self._software[endpoint_id]
        if self._use_db:
            try:
                rows = self.db.query(RMMSoftwareModel).filter(
                    RMMSoftwareModel.endpoint_id == endpoint_id
                ).all()
                inv = [_software_from_row(r) for r in rows]
                self._software[endpoint_id] = inv
                return inv
            except Exception as e:
                logger.error(f"DB error getting software: {e}")
        return []

    def search_software(
        self,
        name: Optional[str] = None,
        publisher: Optional[str] = None
    ) -> Dict[str, List[Software]]:
        """Search software across all endpoints"""
        # Hydrate from DB if available
        if self._use_db:
            try:
                q = self.db.query(RMMSoftwareModel)
                if name:
                    q = q.filter(RMMSoftwareModel.name.ilike(f"%{name}%"))
                if publisher:
                    q = q.filter(RMMSoftwareModel.publisher.ilike(f"%{publisher}%"))
                rows = q.all()
                for row in rows:
                    ep_id = row.endpoint_id
                    if ep_id not in self._software:
                        self._software[ep_id] = []
                    sw = _software_from_row(row)
                    if not any(s.software_id == sw.software_id for s in self._software[ep_id]):
                        self._software[ep_id].append(sw)
            except Exception as e:
                logger.error(f"DB error searching software: {e}")

        results = {}
        for endpoint_id, software_list in self._software.items():
            matches = software_list
            if name:
                matches = [s for s in matches if name.lower() in s.name.lower()]
            if publisher:
                matches = [s for s in matches if publisher.lower() in s.publisher.lower()]
            if matches:
                results[endpoint_id] = matches

        return results

    # ========== Automation Policies ==========

    def create_policy(
        self,
        name: str,
        description: str = "",
        policy_type: PolicyType = PolicyType.THRESHOLD,
        trigger_conditions: Optional[Dict[str, Any]] = None,
        actions: Optional[List[Dict[str, Any]]] = None,
        target_groups: Optional[List[str]] = None,
        target_tags: Optional[List[str]] = None,
        schedule: Optional[str] = None,
        cooldown_minutes: int = 15
    ) -> AutomationPolicy:
        """Create an automation policy"""
        policy_id = f"POL-{uuid.uuid4().hex[:8].upper()}"

        policy = AutomationPolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            policy_type=policy_type,
            trigger_conditions=trigger_conditions or {},
            actions=actions or [],
            target_groups=target_groups or [],
            target_tags=target_tags or [],
            schedule=schedule,
            cooldown_minutes=cooldown_minutes
        )

        self._policies[policy_id] = policy

        if self._use_db:
            try:
                row = RMMPolicyModel(
                    policy_id=policy_id,
                    name=name,
                    description=description,
                    policy_type=policy_type.value,
                    enabled=True,
                    trigger_conditions=trigger_conditions or {},
                    actions=actions or [],
                    target_groups=target_groups or [],
                    target_tags=target_tags or [],
                    schedule=schedule,
                    cooldown_minutes=cooldown_minutes,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating policy: {e}")
                self.db.rollback()

        return policy

    def update_policy(
        self,
        policy_id: str,
        **updates
    ) -> Optional[AutomationPolicy]:
        """Update a policy"""
        policy = self.get_policy(policy_id)
        if not policy:
            return None

        for key, value in updates.items():
            if hasattr(policy, key):
                setattr(policy, key, value)

        policy.updated_at = datetime.now(timezone.utc)
        self._policies[policy_id] = policy

        if self._use_db:
            try:
                row = self.db.query(RMMPolicyModel).filter(
                    RMMPolicyModel.policy_id == policy_id
                ).first()
                if row:
                    for key, value in updates.items():
                        if key == "policy_type" and isinstance(value, PolicyType):
                            value = value.value
                        if hasattr(row, key):
                            setattr(row, key, value)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating policy: {e}")
                self.db.rollback()

        return policy

    def enable_policy(self, policy_id: str, enabled: bool) -> bool:
        """Enable or disable a policy"""
        policy = self.get_policy(policy_id)
        if not policy:
            return False

        policy.enabled = enabled
        policy.updated_at = datetime.now(timezone.utc)
        self._policies[policy_id] = policy

        if self._use_db:
            try:
                row = self.db.query(RMMPolicyModel).filter(
                    RMMPolicyModel.policy_id == policy_id
                ).first()
                if row:
                    row.enabled = enabled
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error toggling policy: {e}")
                self.db.rollback()

        return True

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy"""
        found = policy_id in self._policies
        if found:
            del self._policies[policy_id]

        if self._use_db:
            try:
                row = self.db.query(RMMPolicyModel).filter(
                    RMMPolicyModel.policy_id == policy_id
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
                    found = True
            except Exception as e:
                logger.error(f"DB error deleting policy: {e}")
                self.db.rollback()

        return found

    def get_policy(self, policy_id: str) -> Optional[AutomationPolicy]:
        """Get policy by ID"""
        if policy_id in self._policies:
            return self._policies[policy_id]
        if self._use_db:
            try:
                row = self.db.query(RMMPolicyModel).filter(
                    RMMPolicyModel.policy_id == policy_id
                ).first()
                if row:
                    p = _policy_from_row(row)
                    self._policies[policy_id] = p
                    return p
            except Exception as e:
                logger.error(f"DB error getting policy: {e}")
        return None

    def list_policies(
        self,
        policy_type: Optional[PolicyType] = None,
        enabled_only: bool = False
    ) -> List[AutomationPolicy]:
        """List policies with filters"""
        if self._use_db:
            try:
                q = self.db.query(RMMPolicyModel)
                if policy_type:
                    q = q.filter(RMMPolicyModel.policy_type == policy_type.value)
                if enabled_only:
                    q = q.filter(RMMPolicyModel.enabled == True)
                rows = q.all()
                for row in rows:
                    if row.policy_id not in self._policies:
                        self._policies[row.policy_id] = _policy_from_row(row)
            except Exception as e:
                logger.error(f"DB error listing policies: {e}")

        policies = list(self._policies.values())

        if policy_type:
            policies = [p for p in policies if p.policy_type == policy_type]
        if enabled_only:
            policies = [p for p in policies if p.enabled]

        return policies

    def record_policy_execution(
        self,
        policy_id: str,
        endpoint_id: str,
        triggered_by: str,
        actions_taken: List[str],
        command_ids: Optional[List[str]] = None,
        success: bool = True,
        error: str = ""
    ) -> PolicyExecution:
        """Record a policy execution"""
        execution = PolicyExecution(
            execution_id=f"EXE-{uuid.uuid4().hex[:8].upper()}",
            policy_id=policy_id,
            endpoint_id=endpoint_id,
            triggered_by=triggered_by,
            actions_taken=actions_taken,
            command_ids=command_ids or [],
            success=success,
            error=error
        )

        self._policy_executions.append(execution)

        # Update policy execution count
        policy = self._policies.get(policy_id)
        if policy:
            policy.execution_count += 1
            policy.last_triggered = datetime.now(timezone.utc)

        # Keep only last 1000 executions in memory
        if len(self._policy_executions) > 1000:
            self._policy_executions = self._policy_executions[-1000:]

        if self._use_db:
            try:
                row = RMMPolicyExecutionModel(
                    execution_id=execution.execution_id,
                    policy_id=policy_id,
                    endpoint_id=endpoint_id,
                    triggered_by=triggered_by,
                    actions_taken=actions_taken,
                    success=success,
                    error=error,
                )
                if hasattr(row, "command_ids"):
                    row.command_ids = command_ids or []
                self.db.add(row)
                pol_row = self.db.query(RMMPolicyModel).filter(
                    RMMPolicyModel.policy_id == policy_id
                ).first()
                if pol_row:
                    pol_row.execution_count = (pol_row.execution_count or 0) + 1
                    pol_row.last_triggered = datetime.now(timezone.utc)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error recording execution: {e}")
                self.db.rollback()

        return execution

    def get_policy_executions(
        self,
        policy_id: Optional[str] = None,
        endpoint_id: Optional[str] = None,
        limit: int = 100
    ) -> List[PolicyExecution]:
        """Get policy executions"""
        if self._use_db:
            try:
                q = self.db.query(RMMPolicyExecutionModel)
                if policy_id:
                    q = q.filter(RMMPolicyExecutionModel.policy_id == policy_id)
                if endpoint_id:
                    q = q.filter(RMMPolicyExecutionModel.endpoint_id == endpoint_id)
                rows = q.order_by(RMMPolicyExecutionModel.executed_at.desc()).limit(limit).all()
                # Return directly from DB
                return [_execution_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error getting executions: {e}")

        executions = self._policy_executions

        if policy_id:
            executions = [e for e in executions if e.policy_id == policy_id]
        if endpoint_id:
            executions = [e for e in executions if e.endpoint_id == endpoint_id]

        return sorted(executions, key=lambda e: e.executed_at, reverse=True)[:limit]

    # ========== Policy Evaluation Engine ==========

    def _evaluate_condition(
        self,
        endpoint: Endpoint,
        conditions: Dict[str, Any]
    ) -> bool:
        """Evaluate a policy trigger condition against endpoint metrics.

        Supports conditions like:
            {"metric": "cpu_percent", "operator": ">", "value": 90}
        """
        metric_name = conditions.get("metric", "")
        operator = conditions.get("operator", "")
        value = conditions.get("value")

        if not metric_name or not operator or value is None:
            return False

        # Resolve metric value from endpoint
        actual = getattr(endpoint.metrics, metric_name, None)
        if actual is None:
            return False

        try:
            value = float(value)
            actual = float(actual)
        except (TypeError, ValueError):
            return False

        if operator == ">":
            return actual > value
        elif operator == ">=":
            return actual >= value
        elif operator == "<":
            return actual < value
        elif operator == "<=":
            return actual <= value
        elif operator == "==":
            return actual == value
        elif operator == "!=":
            return actual != value
        return False

    def _dispatch_policy_action(
        self,
        action: Dict[str, Any],
        endpoint: Endpoint,
        policy: AutomationPolicy
    ) -> Optional[Command]:
        """Dispatch a single policy action through the RMM command queue.

        Returns the created Command if a command was queued, None otherwise.
        Alert-only actions still create a lightweight command for audit trail.
        """
        action_type = action.get("type", "")

        if action_type == "command":
            # Direct command execution
            cmd = self.queue_command(
                endpoint_id=endpoint.endpoint_id,
                command_type=action.get("command_type", "script"),
                command=action.get("command", ""),
                parameters=action.get("parameters", {}),
                queued_by=f"policy:{policy.policy_id}",
                timeout_seconds=action.get("timeout_seconds", 300),
            )
            return cmd

        elif action_type == "alert":
            # Create alert AND a notification command so agents can react
            severity_str = action.get("severity", "medium")
            try:
                severity = AlertSeverity(severity_str)
            except ValueError:
                severity = AlertSeverity.MEDIUM

            self.create_alert(
                endpoint_id=endpoint.endpoint_id,
                severity=severity,
                category=AlertCategory(action.get("category", "performance")),
                title=action.get("title", f"Policy triggered: {policy.name}"),
                message=action.get(
                    "message",
                    f"Automation policy '{policy.name}' triggered on {endpoint.hostname}",
                ),
                metric_name=policy.trigger_conditions.get("metric", ""),
                metric_value=getattr(
                    endpoint.metrics,
                    policy.trigger_conditions.get("metric", ""),
                    0.0,
                ),
                threshold=policy.trigger_conditions.get("value", 0.0),
            )
            # Queue a notification command so the agent knows about the alert
            cmd = self.queue_command(
                endpoint_id=endpoint.endpoint_id,
                command_type="notification",
                command="policy_alert",
                parameters={
                    "policy_id": policy.policy_id,
                    "policy_name": policy.name,
                    "severity": severity_str,
                },
                queued_by=f"policy:{policy.policy_id}",
            )
            return cmd

        elif action_type == "restart_service":
            cmd = self.queue_command(
                endpoint_id=endpoint.endpoint_id,
                command_type="service",
                command="restart",
                parameters={"service_name": action.get("service_name", "")},
                queued_by=f"policy:{policy.policy_id}",
                timeout_seconds=action.get("timeout_seconds", 120),
            )
            return cmd

        elif action_type == "reboot":
            cmd = self.queue_command(
                endpoint_id=endpoint.endpoint_id,
                command_type="system",
                command="reboot",
                parameters=action.get("parameters", {}),
                queued_by=f"policy:{policy.policy_id}",
                timeout_seconds=action.get("timeout_seconds", 60),
            )
            return cmd

        elif action_type == "patch":
            cmd = self.queue_command(
                endpoint_id=endpoint.endpoint_id,
                command_type="patch",
                command="install",
                parameters=action.get("parameters", {}),
                queued_by=f"policy:{policy.policy_id}",
                timeout_seconds=action.get("timeout_seconds", 600),
            )
            return cmd

        else:
            # Unknown action type - queue a generic command so it is not silently lost
            cmd = self.queue_command(
                endpoint_id=endpoint.endpoint_id,
                command_type=action_type or "policy_action",
                command=action.get("command", action_type),
                parameters=action,
                queued_by=f"policy:{policy.policy_id}",
            )
            return cmd

    def evaluate_policies(self, endpoint: Endpoint) -> List[PolicyExecution]:
        """Evaluate all enabled policies against an endpoint and dispatch commands.

        Called during heartbeat processing. For each policy whose trigger
        conditions match the endpoint state, every action in the policy is
        dispatched through the RMM command queue and a PolicyExecution record
        is created linking to the dispatched command IDs.

        Returns a list of PolicyExecution records for policies that fired.
        """
        executions: List[PolicyExecution] = []
        now = datetime.now(timezone.utc)

        for policy in list(self._policies.values()):
            if not policy.enabled:
                continue

            # Only evaluate threshold policies here (schedule/event handled elsewhere)
            if policy.policy_type != PolicyType.THRESHOLD:
                continue

            # Cooldown check - skip if policy fired recently
            if policy.last_triggered:
                cooldown_delta = timedelta(minutes=policy.cooldown_minutes)
                if now - policy.last_triggered < cooldown_delta:
                    continue

            # Target filtering - if policy targets specific groups/tags, check match
            if policy.target_groups:
                if not any(g in endpoint.groups for g in policy.target_groups):
                    continue
            if policy.target_tags:
                if not any(t in endpoint.tags for t in policy.target_tags):
                    continue

            # Evaluate trigger conditions
            if not self._evaluate_condition(endpoint, policy.trigger_conditions):
                continue

            # Policy triggered - dispatch each action through the command queue
            triggered_by = (
                f"{policy.trigger_conditions.get('metric', 'unknown')} "
                f"{policy.trigger_conditions.get('operator', '')} "
                f"{policy.trigger_conditions.get('value', '')}"
            )

            actions_taken: List[str] = []
            command_ids: List[str] = []
            all_success = True
            error_messages: List[str] = []

            for action in policy.actions:
                action_desc = f"{action.get('type', 'unknown')}"
                try:
                    cmd = self._dispatch_policy_action(action, endpoint, policy)
                    if cmd:
                        command_ids.append(cmd.command_id)
                        action_desc = f"{action_desc}->cmd:{cmd.command_id}"
                    actions_taken.append(action_desc)
                except Exception as e:
                    logger.error(
                        f"Error dispatching policy action {action} for "
                        f"policy {policy.policy_id} on {endpoint.endpoint_id}: {e}"
                    )
                    all_success = False
                    error_messages.append(str(e))
                    actions_taken.append(f"{action_desc}->ERROR:{e}")

            # Record the execution with command IDs
            execution = self.record_policy_execution(
                policy_id=policy.policy_id,
                endpoint_id=endpoint.endpoint_id,
                triggered_by=triggered_by,
                actions_taken=actions_taken,
                command_ids=command_ids,
                success=all_success,
                error="; ".join(error_messages) if error_messages else "",
            )
            executions.append(execution)

            logger.info(
                f"Policy '{policy.name}' triggered on {endpoint.hostname}: "
                f"{len(command_ids)} command(s) dispatched {command_ids}"
            )

        return executions

    # ========== Dashboard & Analytics ==========

    def get_dashboard(self) -> Dict[str, Any]:
        """Get RMM dashboard data"""
        endpoints = self._get_all_endpoints()
        alerts = list(self._alerts.values())

        # Also hydrate alerts from DB if needed
        if self._use_db:
            try:
                rows = self.db.query(RMMAlertModel).all()
                for row in rows:
                    if row.alert_id not in self._alerts:
                        self._alerts[row.alert_id] = _alert_from_row(row)
                alerts = list(self._alerts.values())
            except Exception:
                pass

        # Count by status
        status_counts = {status.value: 0 for status in EndpointStatus}
        for endpoint in endpoints:
            status_counts[endpoint.status.value] += 1

        # Alert counts
        unacknowledged_alerts = [a for a in alerts if not a.acknowledged]
        unresolved_alerts = [a for a in alerts if not a.resolved]

        severity_counts = {severity.value: 0 for severity in AlertSeverity}
        for alert in unresolved_alerts:
            severity_counts[alert.severity.value] += 1

        # Client summary
        clients = {}
        for endpoint in endpoints:
            if endpoint.client_name:
                if endpoint.client_name not in clients:
                    clients[endpoint.client_name] = {"total": 0, "online": 0, "alerts": 0}
                clients[endpoint.client_name]["total"] += 1
                if endpoint.status == EndpointStatus.ONLINE:
                    clients[endpoint.client_name]["online"] += 1
                clients[endpoint.client_name]["alerts"] += endpoint.alerts_count

        # Patches summary
        total_patches_pending = sum(e.patches_pending for e in endpoints)

        return {
            "endpoints": {
                "total": len(endpoints),
                "by_status": status_counts,
                "patches_pending": total_patches_pending
            },
            "alerts": {
                "total": len(alerts),
                "unacknowledged": len(unacknowledged_alerts),
                "unresolved": len(unresolved_alerts),
                "by_severity": severity_counts
            },
            "policies": {
                "total": len(self._policies),
                "enabled": len([p for p in self._policies.values() if p.enabled])
            },
            "commands": {
                "queued": len([c for c in self._commands.values() if c.status == CommandStatus.QUEUED]),
                "running": len([c for c in self._commands.values() if c.status == CommandStatus.RUNNING])
            },
            "clients": clients,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def get_endpoint_health_summary(self, endpoint_id: str) -> Dict[str, Any]:
        """Get health summary for an endpoint"""
        endpoint = self.get_endpoint(endpoint_id)
        if not endpoint:
            return {}

        alerts = [a for a in self._alerts.values() if a.endpoint_id == endpoint_id and not a.resolved]
        patches = [p for p in self._patches.values() if p.endpoint_id == endpoint_id and p.status == PatchStatus.AVAILABLE]
        recent_commands = [c for c in self._commands.values() if c.endpoint_id == endpoint_id][:10]

        # Calculate health score (0-100)
        health_score = 100
        if endpoint.status == EndpointStatus.OFFLINE:
            health_score -= 50
        elif endpoint.status == EndpointStatus.WARNING:
            health_score -= 20
        elif endpoint.status == EndpointStatus.DEGRADED:
            health_score -= 30

        health_score -= min(len(alerts) * 5, 30)  # Max 30 points for alerts
        health_score -= min(len(patches) * 2, 20)  # Max 20 points for patches

        if endpoint.metrics.cpu_percent > 90:
            health_score -= 10
        if endpoint.metrics.memory_percent > 90:
            health_score -= 10
        if endpoint.metrics.disk_percent > 90:
            health_score -= 10

        return {
            "endpoint_id": endpoint_id,
            "hostname": endpoint.hostname,
            "status": endpoint.status.value,
            "health_score": max(health_score, 0),
            "metrics": {
                "cpu": endpoint.metrics.cpu_percent,
                "memory": endpoint.metrics.memory_percent,
                "disk": endpoint.metrics.disk_percent,
                "uptime_hours": endpoint.metrics.uptime_seconds / 3600
            },
            "alerts": len(alerts),
            "patches_pending": len(patches),
            "last_seen": endpoint.last_seen.isoformat() if endpoint.last_seen else None,
            "recent_commands": len(recent_commands)
        }
