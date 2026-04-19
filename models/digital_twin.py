"""
AITHER Platform - Digital Twin Network Simulation Models

Tables for network twins, twin devices, connections, vulnerabilities,
simulation runs, simulation findings, and attack scenarios.

G-46: DB persistence with in-memory fallback.
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
# Digital Twin - Network Twin
# ============================================================

class NetworkTwinModel(Base):
    """Virtual replica of a client network."""
    __tablename__ = "digital_twin_networks"

    id = Column(String(36), primary_key=True, default=_uuid)
    twin_id = Column(String(36), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    created_from = Column(String(100), default="manual")  # discovery_scan_id or "manual"
    devices = Column(JSON, default=list)
    connections = Column(JSON, default=list)
    subnets = Column(JSON, default=list)
    security_posture_score = Column(Float, default=50.0)
    last_simulation_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Digital Twin - Device
# ============================================================

class TwinDeviceModel(Base):
    """Device within a network twin."""
    __tablename__ = "digital_twin_devices"

    id = Column(String(36), primary_key=True, default=_uuid)
    device_id = Column(String(36), unique=True, nullable=False, index=True)
    twin_id = Column(String(36), nullable=False, index=True)
    hostname = Column(String(200), nullable=False)
    ip_address = Column(String(50), nullable=False)
    mac_address = Column(String(30), default="")
    device_type = Column(String(50), default="unknown")
    os_type = Column(String(100), default="")
    os_version = Column(String(100), default="")
    open_ports = Column(JSON, default=list)
    services_running = Column(JSON, default=list)
    vulnerabilities = Column(JSON, default=list)
    patch_level = Column(String(50), default="unknown")
    is_critical_asset = Column(Boolean, default=False)
    security_score = Column(Float, default=50.0)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# Digital Twin - Connection
# ============================================================

class TwinConnectionModel(Base):
    """Network connection between twin devices."""
    __tablename__ = "digital_twin_connections"

    id = Column(String(36), primary_key=True, default=_uuid)
    connection_id = Column(String(36), unique=True, nullable=False, index=True)
    twin_id = Column(String(36), nullable=False, index=True)
    source_device_id = Column(String(36), nullable=False)
    target_device_id = Column(String(36), nullable=False)
    connection_type = Column(String(30), default="ethernet")
    bandwidth_mbps = Column(Float, default=1000.0)
    is_encrypted = Column(Boolean, default=False)
    firewall_rules = Column(JSON, default=list)
    created_at = Column(DateTime, default=func.now())


# ============================================================
# Digital Twin - Vulnerability
# ============================================================

class TwinVulnerabilityModel(Base):
    """Vulnerability discovered on a twin device."""
    __tablename__ = "digital_twin_vulnerabilities"

    id = Column(String(36), primary_key=True, default=_uuid)
    vuln_id = Column(String(36), unique=True, nullable=False, index=True)
    device_id = Column(String(36), nullable=False, index=True)
    twin_id = Column(String(36), nullable=False, index=True)
    cve_id = Column(String(30), default="")
    title = Column(String(300), nullable=False)
    severity = Column(String(20), default="medium")
    cvss_score = Column(Float, default=5.0)
    affected_service = Column(String(100), default="")
    is_exploitable = Column(Boolean, default=True)
    remediation = Column(Text, default="")
    discovered_by = Column(String(30), default="scanner")
    discovered_at = Column(DateTime, default=func.now())


# ============================================================
# Digital Twin - Simulation Run
# ============================================================

class SimulationRunModel(Base):
    """A simulation run against a network twin."""
    __tablename__ = "digital_twin_simulations"

    id = Column(String(36), primary_key=True, default=_uuid)
    sim_id = Column(String(36), unique=True, nullable=False, index=True)
    twin_id = Column(String(36), nullable=False, index=True)
    sim_type = Column(String(30), nullable=False)
    status = Column(String(20), default="pending")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    attack_vectors_tested = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    vulnerabilities_remediated = Column(Integer, default=0)
    score_before = Column(Float, default=0.0)
    score_after = Column(Float, default=0.0)
    findings = Column(JSON, default=list)
    persona_id = Column(String(100), default="")
    created_at = Column(DateTime, default=func.now())


# ============================================================
# Digital Twin - Simulation Finding
# ============================================================

class SimulationFindingModel(Base):
    """Individual finding from a simulation run."""
    __tablename__ = "digital_twin_findings"

    id = Column(String(36), primary_key=True, default=_uuid)
    finding_id = Column(String(36), unique=True, nullable=False, index=True)
    sim_id = Column(String(36), nullable=False, index=True)
    finding_type = Column(String(50), nullable=False)
    severity = Column(String(20), default="medium")
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    affected_devices = Column(JSON, default=list)
    attack_path = Column(JSON, default=list)
    remediation_steps = Column(JSON, default=list)
    was_auto_remediated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())


# ============================================================
# Digital Twin - Attack Scenario
# ============================================================

class AttackScenarioModel(Base):
    """Pre-built attack scenario template."""
    __tablename__ = "digital_twin_attack_scenarios"

    id = Column(String(36), primary_key=True, default=_uuid)
    scenario_id = Column(String(36), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    attack_type = Column(String(50), nullable=False)
    steps = Column(JSON, default=list)
    difficulty = Column(String(20), default="medium")
    estimated_impact = Column(String(20), default="high")
    created_at = Column(DateTime, default=func.now())
