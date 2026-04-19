"""
AITHER Platform - SOAR Playbook Persistence Models

Tables for SOAR playbooks, steps, executions, and step results.
Extends Cyber-911 with configurable incident response playbooks.
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


class SOARPlaybook(Base):
    """SOAR playbook definition."""
    __tablename__ = "soar_playbooks"

    id = Column(String(36), primary_key=True, default=_uuid)
    playbook_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(300), nullable=False, index=True)
    description = Column(Text, default="")
    trigger_type = Column(String(20), default="manual", index=True)
    trigger_conditions = Column(JSON, default=dict)
    steps = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    is_enabled = Column(Boolean, default=True, index=True)
    version = Column(Integer, default=1)
    created_by = Column(String(200), default="system")
    execution_count = Column(Integer, default=0)
    avg_execution_time_seconds = Column(Float, default=0.0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_soar_pb_trigger_enabled", "trigger_type", "is_enabled"),
    )


class SOARPlaybookStep(Base):
    """Individual step within a SOAR playbook."""
    __tablename__ = "soar_playbook_steps"

    id = Column(String(36), primary_key=True, default=_uuid)
    step_id = Column(String(30), unique=True, nullable=False, index=True)
    playbook_id = Column(String(30), nullable=False, index=True)
    step_number = Column(Integer, nullable=False)
    name = Column(String(300), nullable=False)
    action_type = Column(String(50), nullable=False)
    parameters = Column(JSON, default=dict)
    timeout_seconds = Column(Integer, default=300)
    on_failure = Column(String(20), default="abort")
    condition = Column(Text, nullable=True)
    wait_for_approval = Column(Boolean, default=False)
    assigned_to = Column(String(200), nullable=True)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_soar_step_pb_num", "playbook_id", "step_number"),
    )


class SOARPlaybookExecution(Base):
    """Execution record for a SOAR playbook run."""
    __tablename__ = "soar_playbook_executions"

    id = Column(String(36), primary_key=True, default=_uuid)
    execution_id = Column(String(30), unique=True, nullable=False, index=True)
    playbook_id = Column(String(30), nullable=False, index=True)
    incident_id = Column(String(100), nullable=False, index=True)
    triggered_by = Column(String(200), default="manual")
    status = Column(String(30), default="pending", index=True)
    current_step = Column(Integer, default=0)
    step_results = Column(JSON, default=list)
    context = Column(JSON, default=dict)

    started_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_soar_exec_pb_status", "playbook_id", "status"),
    )


class SOARStepResult(Base):
    """Result of a single step within an execution."""
    __tablename__ = "soar_step_results"

    id = Column(String(36), primary_key=True, default=_uuid)
    execution_id = Column(String(30), nullable=False, index=True)
    step_id = Column(String(30), nullable=False)
    step_number = Column(Integer, nullable=False)
    action_type = Column(String(50), nullable=False)
    status = Column(String(30), default="pending")
    output = Column(JSON, default=dict)
    error = Column(Text, nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_soar_sr_exec_step", "execution_id", "step_number"),
    )
