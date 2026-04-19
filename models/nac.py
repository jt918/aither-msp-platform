"""
AITHER Platform - NAC (Network Access Control) Persistence Models

Tables for NAC policies, device posture assessments, access decisions,
guest registrations, captive portal configs, and blocked devices.
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON,
    Index,
)
from sqlalchemy.sql import func
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


# ============================================================
# NAC - Network Access Control
# ============================================================

class NACPolicyModel(Base):
    """NAC access policy."""
    __tablename__ = "nac_policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    posture_requirements = Column(JSON, default=dict)
    network_assignment = Column(String(30), default="corporate")
    vlan_id = Column(Integer, default=0)
    priority = Column(Integer, default=100)
    is_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_nac_pol_client_enabled", "client_id", "is_enabled"),
    )


class DevicePostureModel(Base):
    """Device posture assessment record."""
    __tablename__ = "nac_device_postures"

    id = Column(String(36), primary_key=True, default=_uuid)
    posture_id = Column(String(30), unique=True, nullable=False, index=True)
    device_id = Column(String(100), nullable=False, index=True)
    mac_address = Column(String(30), default="", index=True)
    ip_address = Column(String(50), default="")
    hostname = Column(String(200), default="")
    os_type = Column(String(50), default="")
    os_version = Column(String(100), default="")
    antivirus_status = Column(String(20), default="unknown")
    firewall_enabled = Column(Boolean, default=False)
    disk_encrypted = Column(Boolean, default=False)
    patch_compliance_pct = Column(Float, default=0.0)
    last_assessed_at = Column(DateTime, nullable=True)
    posture_score = Column(Integer, default=0)
    compliant = Column(Boolean, default=False)
    assigned_network = Column(String(30), default="quarantine")
    violations = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_nac_posture_device_mac", "device_id", "mac_address"),
    )


class AccessDecisionModel(Base):
    """NAC access decision log."""
    __tablename__ = "nac_access_decisions"

    id = Column(String(36), primary_key=True, default=_uuid)
    decision_id = Column(String(30), unique=True, nullable=False, index=True)
    device_id = Column(String(100), nullable=False, index=True)
    mac_address = Column(String(30), default="")
    policy_id = Column(String(30), default="", index=True)
    decision = Column(String(20), nullable=False)
    reason = Column(Text, default="")
    assigned_vlan = Column(Integer, default=0)
    timestamp = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_nac_decision_device_ts", "device_id", "timestamp"),
    )


class GuestRegistrationModel(Base):
    """Guest network registration."""
    __tablename__ = "nac_guest_registrations"

    id = Column(String(36), primary_key=True, default=_uuid)
    guest_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    name = Column(String(200), nullable=False)
    email = Column(String(200), default="")
    company = Column(String(200), default="")
    sponsor_email = Column(String(200), default="")
    mac_address = Column(String(30), default="")
    access_start = Column(DateTime, nullable=True)
    access_end = Column(DateTime, nullable=True)
    status = Column(String(20), default="pending", index=True)
    network_assigned = Column(String(30), default="guest")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class CaptivePortalConfigModel(Base):
    """Captive portal configuration."""
    __tablename__ = "nac_captive_portal_configs"

    id = Column(String(36), primary_key=True, default=_uuid)
    portal_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", unique=True, index=True)
    branding = Column(JSON, default=dict)
    terms_of_use = Column(Text, default="")
    require_registration = Column(Boolean, default=True)
    session_timeout_minutes = Column(Integer, default=480)
    bandwidth_limit_mbps = Column(Float, default=10.0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class BlockedDeviceModel(Base):
    """Blocked device record."""
    __tablename__ = "nac_blocked_devices"

    id = Column(String(36), primary_key=True, default=_uuid)
    mac_address = Column(String(30), unique=True, nullable=False, index=True)
    reason = Column(Text, default="")
    blocked_by = Column(String(100), default="system")
    blocked_at = Column(DateTime, default=func.now())
