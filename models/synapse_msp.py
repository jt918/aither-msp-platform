"""
AITHER Platform - Synapse MSP Integration Persistence Models

Tables for MSP Advisors, Advisory Requests/Responses,
MSP Insights, and Automation Rules.

Connects the Synapse AI/SME engine to MSP operations for
intelligent ticket routing, threat analysis, and automated decisions.
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
# MSP Advisor - AI-powered domain expert
# ============================================================

class MSPAdvisorModel(Base):
    """Synapse MSP AI Advisor persona."""
    __tablename__ = "synapse_msp_advisors"

    id = Column(String(36), primary_key=True, default=_uuid)
    advisor_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    domain = Column(String(50), nullable=False, index=True)
    specializations = Column(JSON, default=list)
    knowledge_base = Column(JSON, default=dict)
    confidence_threshold = Column(Float, default=0.7)
    decisions_made = Column(Integer, default=0)
    accuracy_rate = Column(Float, default=1.0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_synapse_adv_domain", "domain"),
    )


# ============================================================
# Advisory Request - inbound request for AI guidance
# ============================================================

class AdvisoryRequestModel(Base):
    """Advisory request submitted to a Synapse MSP advisor."""
    __tablename__ = "synapse_msp_advisory_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    request_id = Column(String(30), unique=True, nullable=False, index=True)
    advisor_id = Column(String(30), nullable=True, index=True)
    request_type = Column(String(50), nullable=False, index=True)
    context = Column(JSON, default=dict)
    urgency = Column(String(20), default="medium")
    status = Column(String(20), default="pending", index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_synapse_req_type_status", "request_type", "status"),
    )


# ============================================================
# Advisory Response - AI recommendation
# ============================================================

class AdvisoryResponseModel(Base):
    """Advisory response / recommendation from a Synapse MSP advisor."""
    __tablename__ = "synapse_msp_advisory_responses"

    id = Column(String(36), primary_key=True, default=_uuid)
    response_id = Column(String(30), unique=True, nullable=False, index=True)
    request_id = Column(String(30), nullable=False, index=True)
    advisor_id = Column(String(30), nullable=False, index=True)
    recommendation = Column(Text, default="")
    confidence = Column(Float, default=0.0)
    reasoning = Column(JSON, default=list)
    alternative_actions = Column(JSON, default=list)
    estimated_impact = Column(Text, default="")
    auto_executable = Column(Boolean, default=False)
    executed = Column(Boolean, default=False)
    executed_at = Column(DateTime, nullable=True)

    # Feedback
    was_helpful = Column(Boolean, nullable=True)
    feedback = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_synapse_resp_req", "request_id"),
        Index("ix_synapse_resp_advisor", "advisor_id"),
    )


# ============================================================
# MSP Insight - AI-generated actionable insight
# ============================================================

class MSPInsightModel(Base):
    """Synapse MSP AI-generated insight."""
    __tablename__ = "synapse_msp_insights"

    id = Column(String(36), primary_key=True, default=_uuid)
    insight_id = Column(String(30), unique=True, nullable=False, index=True)
    insight_type = Column(String(30), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    severity = Column(String(20), default="medium")
    data_points = Column(JSON, default=dict)
    affected_clients = Column(JSON, default=list)
    action_required = Column(Boolean, default=False)

    generated_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_synapse_insight_type_sev", "insight_type", "severity"),
    )


# ============================================================
# Automation Rule - event-triggered advisor invocation
# ============================================================

class AutomationRuleModel(Base):
    """Synapse MSP automation rule linking events to advisors."""
    __tablename__ = "synapse_msp_automation_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    rule_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    trigger_event = Column(String(100), nullable=False, index=True)
    condition = Column(JSON, default=dict)
    advisor_domain = Column(String(50), nullable=False)
    action = Column(JSON, default=dict)
    is_enabled = Column(Boolean, default=True)
    executions = Column(Integer, default=0)
    last_triggered = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_synapse_rule_trigger", "trigger_event", "is_enabled"),
    )
