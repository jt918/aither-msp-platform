"""
AITHER Platform - MSP Persistence Models (G-46)

Tables for RMM endpoints/alerts/commands/patches/policies,
ITSM tickets, Self-Healing incident logs, and Cyber-911 incidents.

These complement the existing managed_services.py models
(ManagedDevice, ITTicket) and itsm.py models (Incident).
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
# RMM - Remote Monitoring & Management
# ============================================================

class RMMEndpoint(Base):
    """Monitored RMM endpoint."""
    __tablename__ = "rmm_endpoints"

    id = Column(String(36), primary_key=True, default=_uuid)
    endpoint_id = Column(String(30), unique=True, nullable=False, index=True)
    hostname = Column(String(200), nullable=False, index=True)
    ip_address = Column(String(50), nullable=False)
    mac_address = Column(String(30), default="")
    client_id = Column(String(100), default="", index=True)
    client_name = Column(String(200), default="")
    status = Column(String(20), default="unknown", index=True)
    agent_version = Column(String(50), default="")
    agent_installed_at = Column(DateTime, nullable=True)

    # System info stored as JSON
    system_info = Column(JSON, default=dict)
    # Current metrics snapshot
    metrics = Column(JSON, default=dict)

    tags = Column(JSON, default=list)
    groups = Column(JSON, default=list)

    last_seen = Column(DateTime, nullable=True)
    last_reboot = Column(DateTime, nullable=True)
    alerts_count = Column(Integer, default=0)
    patches_pending = Column(Integer, default=0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_rmm_ep_client_status", "client_id", "status"),
    )


class RMMAlert(Base):
    """RMM monitoring alert."""
    __tablename__ = "rmm_alerts"

    id = Column(String(36), primary_key=True, default=_uuid)
    alert_id = Column(String(30), unique=True, nullable=False, index=True)
    endpoint_id = Column(String(30), nullable=False, index=True)
    hostname = Column(String(200), default="Unknown")
    severity = Column(String(20), nullable=False, index=True)
    category = Column(String(30), nullable=False)
    title = Column(String(300), nullable=False)
    message = Column(Text, default="")
    metric_name = Column(String(100), default="")
    metric_value = Column(Float, default=0.0)
    threshold = Column(Float, default=0.0)

    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(200), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    notes = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_rmm_alert_ep_resolved", "endpoint_id", "resolved"),
    )


class RMMCommand(Base):
    """Remote command queued for an endpoint."""
    __tablename__ = "rmm_commands"

    id = Column(String(36), primary_key=True, default=_uuid)
    command_id = Column(String(30), unique=True, nullable=False, index=True)
    endpoint_id = Column(String(30), nullable=False, index=True)
    command_type = Column(String(50), nullable=False)
    command = Column(Text, nullable=False)
    parameters = Column(JSON, default=dict)
    status = Column(String(20), default="queued", index=True)
    output = Column(Text, default="")
    exit_code = Column(Integer, nullable=True)
    error = Column(Text, default="")
    queued_by = Column(String(200), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    timeout_seconds = Column(Integer, default=300)

    created_at = Column(DateTime, default=func.now())


class RMMPatch(Base):
    """Software patch tracked per endpoint."""
    __tablename__ = "rmm_patches"

    id = Column(String(36), primary_key=True, default=_uuid)
    patch_id = Column(String(30), unique=True, nullable=False, index=True)
    endpoint_id = Column(String(30), nullable=False, index=True)
    kb_id = Column(String(50), default="")
    title = Column(String(300), default="")
    description = Column(Text, default="")
    severity = Column(String(20), default="important")
    status = Column(String(20), default="available", index=True)
    size_mb = Column(Float, default=0.0)
    download_url = Column(String(500), default="")
    installed_at = Column(DateTime, nullable=True)
    requires_reboot = Column(Boolean, default=False)

    created_at = Column(DateTime, default=func.now())


class RMMSoftware(Base):
    """Software inventory item for an endpoint."""
    __tablename__ = "rmm_software"

    id = Column(String(36), primary_key=True, default=_uuid)
    software_id = Column(String(30), nullable=False, index=True)
    endpoint_id = Column(String(30), nullable=False, index=True)
    name = Column(String(300), nullable=False)
    version = Column(String(100), default="")
    publisher = Column(String(200), default="")
    install_date = Column(DateTime, nullable=True)
    install_location = Column(String(500), default="")
    size_mb = Column(Float, default=0.0)
    is_update = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_rmm_sw_endpoint", "endpoint_id"),
    )


class RMMPolicy(Base):
    """Automation policy for RMM."""
    __tablename__ = "rmm_policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    policy_type = Column(String(30), default="threshold")
    enabled = Column(Boolean, default=True)
    trigger_conditions = Column(JSON, default=dict)
    actions = Column(JSON, default=list)
    target_groups = Column(JSON, default=list)
    target_tags = Column(JSON, default=list)
    schedule = Column(String(100), nullable=True)
    cooldown_minutes = Column(Integer, default=15)
    last_triggered = Column(DateTime, nullable=True)
    execution_count = Column(Integer, default=0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class RMMPolicyExecution(Base):
    """Record of a policy execution."""
    __tablename__ = "rmm_policy_executions"

    id = Column(String(36), primary_key=True, default=_uuid)
    execution_id = Column(String(30), nullable=False, index=True)
    policy_id = Column(String(30), nullable=False, index=True)
    endpoint_id = Column(String(30), nullable=False, index=True)
    triggered_by = Column(String(200), default="")
    actions_taken = Column(JSON, default=list)
    command_ids = Column(JSON, default=list)
    success = Column(Boolean, default=True)
    error = Column(Text, default="")
    executed_at = Column(DateTime, default=func.now())


# ============================================================
# ITSM Tickets (separate from managed_services.ITTicket)
# ============================================================

class ITSMTicket(Base):
    """ITSM service ticket with SLA tracking."""
    __tablename__ = "itsm_tickets"

    id = Column(String(36), primary_key=True, default=_uuid)
    ticket_id = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    category = Column(String(30), nullable=False, index=True)
    priority = Column(String(10), nullable=False, index=True)
    status = Column(String(30), default="new", index=True)
    customer_id = Column(String(100), default="")
    customer_name = Column(String(200), default="")
    assigned_to = Column(String(200), nullable=True)
    sla_deadline = Column(DateTime, nullable=True)
    notes = Column(JSON, default=list)
    auto_healed = Column(Boolean, default=False)

    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_itsm_tkt_status_priority", "status", "priority"),
    )


# ============================================================
# Self-Healing Incident Log
# ============================================================

class SelfHealingIncident(Base):
    """Self-healing agent incident log entry."""
    __tablename__ = "self_healing_incidents"

    id = Column(String(36), primary_key=True, default=_uuid)
    fault_id = Column(String(100), nullable=False, index=True)
    fault_type = Column(String(50), nullable=False, index=True)
    endpoint = Column(String(200), default="")
    severity = Column(Integer, default=5)
    detected_at = Column(String(50), default="")
    attempts = Column(Integer, default=0)
    outcome = Column(String(30), default="", index=True)
    resolved_at = Column(String(50), default="")

    created_at = Column(DateTime, default=func.now())


# ============================================================
# Cyber-911 Incident Response
# ============================================================

class Cyber911Incident(Base):
    """Security incident response record."""
    __tablename__ = "cyber911_incidents"

    id = Column(String(36), primary_key=True, default=_uuid)
    incident_id = Column(String(100), unique=True, nullable=False, index=True)
    threat_id = Column(String(100), default="")
    threat_type = Column(String(50), nullable=False, index=True)
    severity = Column(Integer, default=1)
    affected_assets = Column(JSON, default=list)
    indicators = Column(JSON, default=dict)
    events = Column(JSON, default=list)
    actions_taken = Column(JSON, default=list)
    containment_status = Column(String(30), default="pending", index=True)
    investigation_notes = Column(Text, default="")
    detected_at = Column(DateTime, nullable=True)

    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())


class Cyber911BlockedIP(Base):
    """Blocked IP address."""
    __tablename__ = "cyber911_blocked_ips"

    id = Column(String(36), primary_key=True, default=_uuid)
    ip_address = Column(String(50), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=func.now())


class Cyber911IsolatedHost(Base):
    """Isolated host."""
    __tablename__ = "cyber911_isolated_hosts"

    id = Column(String(36), primary_key=True, default=_uuid)
    hostname = Column(String(200), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=func.now())


class Cyber911DisabledAccount(Base):
    """Disabled user account."""
    __tablename__ = "cyber911_disabled_accounts"

    id = Column(String(36), primary_key=True, default=_uuid)
    username = Column(String(200), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=func.now())


# ============================================================
# Network Discovery
# ============================================================

class NetworkDevice(Base):
    """Discovered network device."""
    __tablename__ = "network_devices"

    id = Column(String(36), primary_key=True, default=_uuid)
    device_id = Column(String(30), unique=True, nullable=False, index=True)
    ip_address = Column(String(50), nullable=False, index=True)
    mac_address = Column(String(30), default="")
    hostname = Column(String(200), default="", index=True)
    device_type = Column(String(30), default="unknown", index=True)
    vendor = Column(String(100), default="")
    model = Column(String(200), default="")
    firmware_version = Column(String(100), default="")
    serial_number = Column(String(100), default="")
    snmp_community = Column(String(100), default="")
    ports_open = Column(JSON, default=list)
    uptime = Column(Integer, default=0)
    location = Column(String(300), default="")
    contact = Column(String(200), default="")
    sys_descr = Column(Text, default="")
    sys_object_id = Column(String(200), default="")
    interface_count = Column(Integer, default=0)
    neighbors = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    notes = Column(Text, default="")
    scan_id = Column(String(30), default="", index=True)

    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_net_dev_type_vendor", "device_type", "vendor"),
    )


class NetworkScan(Base):
    """Network discovery scan record."""
    __tablename__ = "network_scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(30), unique=True, nullable=False, index=True)
    subnet = Column(String(50), nullable=False)
    scan_type = Column(String(20), default="full")
    status = Column(String(20), default="queued", index=True)
    community = Column(String(100), default="public")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    devices_found = Column(Integer, default=0)
    error = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())
