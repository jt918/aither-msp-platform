"""
AITHER Platform - MDM Enhanced Persistence Models

Tables for Mobile Device Management: devices, policies, apps,
compliance rules, device actions, and geofence zones.

Extends the Nomad MDM defense pillar with full DB-backed persistence.
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


class ManagedMobileDeviceModel(Base):
    """A mobile device under MDM management."""
    __tablename__ = "mdm_devices"

    id = Column(String(36), primary_key=True, default=_uuid)
    device_id = Column(String(50), unique=True, nullable=False, index=True)
    user_id = Column(String(100), default="", index=True)
    client_id = Column(String(100), default="", index=True)
    device_name = Column(String(200), nullable=False)
    platform = Column(String(30), default="android", index=True)  # ios/android/windows_mobile
    os_version = Column(String(50), default="")
    model = Column(String(200), default="")
    serial_number = Column(String(100), default="", index=True)
    imei = Column(String(50), default="")

    enrollment_status = Column(String(30), default="pending", index=True)
    compliance_status = Column(String(30), default="unknown", index=True)
    last_checkin = Column(DateTime, nullable=True)
    management_profile_installed = Column(Boolean, default=False)
    encryption_enabled = Column(Boolean, default=False)
    passcode_set = Column(Boolean, default=False)
    jailbroken = Column(Boolean, default=False)
    roaming = Column(Boolean, default=False)
    battery_level = Column(Integer, default=100)
    storage_used_pct = Column(Float, default=0.0)

    # Work profile / BYOD
    work_profile_enabled = Column(Boolean, default=False)
    personal_apps_separated = Column(Boolean, default=False)

    # Location
    last_latitude = Column(Float, nullable=True)
    last_longitude = Column(Float, nullable=True)

    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_mdm_dev_platform_status", "platform", "enrollment_status"),
    )


class DevicePolicyModel(Base):
    """MDM policy definition."""
    __tablename__ = "mdm_policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    platform = Column(String(30), default="all", index=True)  # ios/android/all
    policy_type = Column(String(50), default="compliance", index=True)
    settings = Column(JSON, default=dict)
    is_mandatory = Column(Boolean, default=False)
    assigned_groups = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class ManagedAppModel(Base):
    """MDM-managed application."""
    __tablename__ = "mdm_apps"

    id = Column(String(36), primary_key=True, default=_uuid)
    app_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    bundle_id = Column(String(300), default="", index=True)
    platform = Column(String(30), default="all", index=True)
    version = Column(String(50), default="1.0.0")
    is_required = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    install_count = Column(Integer, default=0)
    category = Column(String(100), default="general")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class ComplianceRuleModel(Base):
    """MDM compliance rule."""
    __tablename__ = "mdm_compliance_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    rule_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    check_type = Column(String(50), nullable=False, index=True)
    expected_value = Column(String(500), default="")
    severity = Column(String(20), default="warning", index=True)  # warning/critical
    auto_remediate = Column(Boolean, default=False)
    remediation_action = Column(String(200), default="")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class DeviceActionModel(Base):
    """MDM device action / remote command."""
    __tablename__ = "mdm_device_actions"

    id = Column(String(36), primary_key=True, default=_uuid)
    action_id = Column(String(50), unique=True, nullable=False, index=True)
    device_id = Column(String(50), nullable=False, index=True)
    action_type = Column(String(30), nullable=False, index=True)
    status = Column(String(20), default="pending", index=True)
    requested_by = Column(String(100), default="system")
    requested_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    result = Column(Text, default="")
    params = Column(JSON, default=dict)

    __table_args__ = (
        Index("ix_mdm_action_device_status", "device_id", "status"),
    )


class GeofenceZoneModel(Base):
    """MDM geofence zone."""
    __tablename__ = "mdm_geofence_zones"

    id = Column(String(36), primary_key=True, default=_uuid)
    zone_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    radius_meters = Column(Float, default=500.0)
    action_on_exit = Column(String(20), default="alert")  # alert/lock/wipe
    assigned_devices = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
