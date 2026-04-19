"""
AITHER Platform - Security Legion Persistence Models

Tables for Red/Blue/Purple team personas, security teams, missions,
after-action reports, and MITRE ATT&CK technique profiles.

Integrates with Legion Forge for persona spawning and Digital Twin
infrastructure for simulated attack/defense exercises.
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


class SecurityPersonaModel(Base):
    """Red/Blue/Purple team security persona."""
    __tablename__ = "security_personas"

    id = Column(String(36), primary_key=True, default=_uuid)
    persona_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False, index=True)
    team = Column(String(10), nullable=False, index=True)  # red / blue / purple
    role = Column(String(60), nullable=False, index=True)
    specialization = Column(String(200), default="")
    skill_level = Column(Float, default=0.5)
    experience_points = Column(Integer, default=0)
    missions_completed = Column(Integer, default=0)
    missions_success_rate = Column(Float, default=0.0)
    techniques_mastered = Column(JSON, default=list)
    certifications = Column(JSON, default=list)
    status = Column(String(20), default="available", index=True)
    current_assignment = Column(String(100), nullable=True)
    team_id = Column(String(30), nullable=True, index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_sec_persona_team_status", "team", "status"),
    )


class SecurityTeamModel(Base):
    """Security team (red/blue/purple)."""
    __tablename__ = "security_teams"

    id = Column(String(36), primary_key=True, default=_uuid)
    team_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False, index=True)
    team_type = Column(String(20), nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    personas = Column(JSON, default=list)  # list of persona_ids
    mission_count = Column(Integer, default=0)
    avg_score = Column(Float, default=0.0)
    status = Column(String(20), default="standby", index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_sec_team_client_type", "client_id", "team_type"),
    )


class SecurityMissionModel(Base):
    """Security mission / exercise record."""
    __tablename__ = "security_missions"

    id = Column(String(36), primary_key=True, default=_uuid)
    mission_id = Column(String(30), unique=True, nullable=False, index=True)
    team_id = Column(String(30), nullable=False, index=True)
    twin_id = Column(String(100), nullable=False, index=True)
    mission_type = Column(String(20), nullable=False, index=True)
    objective = Column(Text, default="")
    status = Column(String(20), default="planning", index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    findings_count = Column(Integer, default=0)
    score = Column(Float, default=0.0)
    after_action_report = Column(JSON, default=dict)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_sec_mission_team_status", "team_id", "status"),
    )


class AfterActionReportModel(Base):
    """Detailed after-action report for a completed mission."""
    __tablename__ = "security_after_action_reports"

    id = Column(String(36), primary_key=True, default=_uuid)
    report_id = Column(String(30), unique=True, nullable=False, index=True)
    mission_id = Column(String(30), nullable=False, index=True)
    executive_summary = Column(Text, default="")
    attack_narrative = Column(JSON, default=list)
    vulnerabilities_exploited = Column(JSON, default=list)
    defensive_gaps = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)
    risk_score_before = Column(Float, default=0.0)
    risk_score_after = Column(Float, default=0.0)
    lessons_learned = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())


class MITRETechniqueModel(Base):
    """MITRE ATT&CK technique reference."""
    __tablename__ = "security_mitre_techniques"

    id = Column(String(36), primary_key=True, default=_uuid)
    technique_id = Column(String(30), unique=True, nullable=False, index=True)
    mitre_id = Column(String(20), nullable=False, index=True)
    name = Column(String(200), nullable=False)
    tactic = Column(String(60), nullable=False, index=True)
    description = Column(Text, default="")
    difficulty = Column(Float, default=0.5)
    detection_difficulty = Column(Float, default=0.5)
    persona_skill_required = Column(Float, default=0.5)

    created_at = Column(DateTime, default=func.now())
