"""
AITHER Platform - CMDB Persistence Models

Tables for Configuration Items, CI Relationships, Configuration Baselines,
and Configuration Changes. Single source of truth for all IT assets.
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


class ConfigurationItemModel(Base):
    """Configuration Item (CI) in the CMDB."""
    __tablename__ = "cmdb_configuration_items"

    id = Column(String(36), primary_key=True, default=_uuid)
    ci_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    ci_type = Column(String(30), nullable=False, index=True)
    name = Column(String(300), nullable=False, index=True)
    description = Column(Text, default="")
    status = Column(String(20), default="active", index=True)
    environment = Column(String(20), default="production")
    location = Column(String(300), default="")
    owner = Column(String(200), default="")
    department = Column(String(200), default="")
    attributes = Column(JSON, default=dict)
    tags = Column(JSON, default=list)
    serial_number = Column(String(100), default="")
    asset_tag = Column(String(100), default="")
    ip_address = Column(String(50), default="")
    mac_address = Column(String(30), default="")
    manufacturer = Column(String(200), default="")
    model = Column(String(200), default="")
    firmware_version = Column(String(100), default="")
    configuration_data = Column(JSON, default=dict)
    last_audit_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_cmdb_ci_client_type", "client_id", "ci_type"),
        Index("ix_cmdb_ci_client_status", "client_id", "status"),
    )


class CIRelationshipModel(Base):
    """Relationship between two Configuration Items."""
    __tablename__ = "cmdb_ci_relationships"

    id = Column(String(36), primary_key=True, default=_uuid)
    relationship_id = Column(String(30), unique=True, nullable=False, index=True)
    source_ci_id = Column(String(30), nullable=False, index=True)
    target_ci_id = Column(String(30), nullable=False, index=True)
    relationship_type = Column(String(30), nullable=False, index=True)
    description = Column(Text, default="")
    is_bidirectional = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_cmdb_rel_source_target", "source_ci_id", "target_ci_id"),
    )


class ConfigurationBaselineModel(Base):
    """Baseline snapshot of a CI's configuration."""
    __tablename__ = "cmdb_configuration_baselines"

    id = Column(String(36), primary_key=True, default=_uuid)
    baseline_id = Column(String(30), unique=True, nullable=False, index=True)
    ci_id = Column(String(30), nullable=False, index=True)
    baseline_name = Column(String(300), nullable=False)
    baseline_data = Column(JSON, default=dict)
    captured_at = Column(DateTime, default=func.now())
    captured_by = Column(String(200), default="")
    is_current = Column(Boolean, default=True)

    __table_args__ = (
        Index("ix_cmdb_bl_ci_current", "ci_id", "is_current"),
    )


class ConfigurationChangeModel(Base):
    """Audit trail for changes made to CIs."""
    __tablename__ = "cmdb_configuration_changes"

    id = Column(String(36), primary_key=True, default=_uuid)
    change_id = Column(String(30), unique=True, nullable=False, index=True)
    ci_id = Column(String(30), nullable=False, index=True)
    change_type = Column(String(20), nullable=False, index=True)
    field_changed = Column(String(100), default="")
    old_value = Column(Text, default="")
    new_value = Column(Text, default="")
    changed_by = Column(String(200), default="system")
    change_source = Column(String(20), default="manual")
    changed_at = Column(DateTime, default=func.now())
    change_ticket_id = Column(String(50), default="")

    __table_args__ = (
        Index("ix_cmdb_chg_ci_time", "ci_id", "changed_at"),
    )
