"""
AITHER Platform - PSA (Professional Services Automation) Persistence Models

Tables for PSA connections (ConnectWise, Autotask, Halo, Syncro),
sync mappings, sync logs, and entity sync records.
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


class PSAConnectionModel(Base):
    """PSA integration connection record."""
    __tablename__ = "psa_connections"

    id = Column(String(36), primary_key=True, default=_uuid)
    connection_id = Column(String(30), unique=True, nullable=False, index=True)
    psa_type = Column(String(30), nullable=False, index=True)  # connectwise/autotask/halo/syncro
    company_id = Column(String(100), default="", index=True)
    api_url = Column(String(500), nullable=False)
    client_id = Column(String(200), default="")
    public_key = Column(String(200), default="")
    private_key_ref = Column(String(200), default="")  # encrypted reference
    is_connected = Column(Boolean, default=False)
    last_sync_at = Column(DateTime, nullable=True)
    sync_status = Column(String(30), default="never")  # never/running/completed/error
    sync_config = Column(JSON, default=dict)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class SyncMappingModel(Base):
    """Field mapping between local and remote entities."""
    __tablename__ = "psa_sync_mappings"

    id = Column(String(36), primary_key=True, default=_uuid)
    mapping_id = Column(String(30), unique=True, nullable=False, index=True)
    connection_id = Column(String(30), nullable=False, index=True)
    local_entity = Column(String(50), nullable=False)  # ticket/company/contact/device
    remote_entity = Column(String(100), nullable=False)
    field_mappings = Column(JSON, default=dict)
    sync_direction = Column(String(20), default="bidirectional")  # bidirectional/push/pull
    is_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class SyncLogModel(Base):
    """Sync execution log entry."""
    __tablename__ = "psa_sync_logs"

    id = Column(String(36), primary_key=True, default=_uuid)
    log_id = Column(String(30), unique=True, nullable=False, index=True)
    connection_id = Column(String(30), nullable=False, index=True)
    sync_type = Column(String(30), nullable=False)  # full/incremental/companies/tickets/contacts
    entities_pushed = Column(Integer, default=0)
    entities_pulled = Column(Integer, default=0)
    errors = Column(JSON, default=list)
    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())


class EntitySyncModel(Base):
    """Tracks sync state for individual entities (company, ticket, contact, etc.)."""
    __tablename__ = "psa_entity_syncs"

    id = Column(String(36), primary_key=True, default=_uuid)
    connection_id = Column(String(30), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False, index=True)  # company/ticket/contact/device
    local_id = Column(String(100), nullable=False, index=True)
    remote_id = Column(String(100), nullable=False)
    entity_name = Column(String(300), default="")
    sync_status = Column(String(30), default="synced")  # synced/pending/error/conflict
    last_synced = Column(DateTime, nullable=True)
    metadata_json = Column(JSON, default=dict)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_entity_sync_lookup", "connection_id", "entity_type", "local_id"),
    )
