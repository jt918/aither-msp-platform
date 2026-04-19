"""
AITHER Platform - Agent Protocol Persistence Models

Tables for RMM agent registration, command queue, and agent updates.
Supports the server-side RMM Agent Communication Protocol.
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


class RegisteredAgentModel(Base):
    """Registered RMM agent."""
    __tablename__ = "registered_agents"

    id = Column(String(36), primary_key=True, default=_uuid)
    agent_id = Column(String(50), unique=True, nullable=False, index=True)
    endpoint_id = Column(String(50), nullable=False, index=True)
    hostname = Column(String(200), nullable=False, index=True)
    os_type = Column(String(20), nullable=False)          # windows/linux/macos
    os_version = Column(String(100), default="")
    arch = Column(String(10), default="x64")               # x64/x86/arm64
    agent_version = Column(String(50), default="")
    api_key_hash = Column(String(128), nullable=False)
    install_path = Column(String(500), default="")
    config = Column(JSON, default=dict)
    status = Column(String(20), default="active", index=True)  # active/revoked/stale

    registered_at = Column(DateTime, default=func.now())
    last_checkin_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_reg_agent_status_os", "status", "os_type"),
    )


class AgentCommandQueueModel(Base):
    """Queued command for an RMM agent."""
    __tablename__ = "agent_command_queue"

    id = Column(String(36), primary_key=True, default=_uuid)
    command_id = Column(String(50), unique=True, nullable=False, index=True)
    agent_id = Column(String(50), nullable=False, index=True)
    command_type = Column(String(30), nullable=False)      # shell/powershell/script/update/restart/uninstall/collect_logs/run_scan
    payload = Column(JSON, default=dict)
    priority = Column(String(10), default="normal")        # normal/high/urgent
    status = Column(String(20), default="queued", index=True)  # queued/sent/completed/failed/expired
    exit_code = Column(Integer, nullable=True)
    stdout = Column(Text, default="")
    stderr = Column(Text, default="")
    execution_time_ms = Column(Integer, nullable=True)

    queued_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_agent_cmd_agent_status", "agent_id", "status"),
    )


class AgentUpdateModel(Base):
    """Published agent update."""
    __tablename__ = "agent_updates"

    id = Column(String(36), primary_key=True, default=_uuid)
    version = Column(String(50), nullable=False, index=True)
    platform = Column(String(20), nullable=False)          # windows/linux/macos
    download_url = Column(String(500), nullable=False)
    checksum = Column(String(128), nullable=False)
    release_notes = Column(Text, default="")
    is_mandatory = Column(Boolean, default=False)

    published_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_agent_update_ver_plat", "version", "platform"),
    )
