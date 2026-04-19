"""
API Routes for Synapse MSP Integration Service
AI-Powered MSP Command Center - Advisor Management, Advisory Pipeline,
Insights, Automation Rules, and Analytics.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from core.database import get_sync_db

from services.msp.synapse_msp import (
    SynapseMSPService,
    AdvisorDomain,
    RequestType,
    InsightType,
)

router = APIRouter(prefix="/synapse-msp", tags=["Synapse MSP - AI Command Center"])

# Singleton instance
_service_instance: Optional[SynapseMSPService] = None


def get_service() -> SynapseMSPService:
    """Get or create SynapseMSPService instance with DB persistence."""
    global _service_instance
    if _service_instance is None:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            _service_instance = SynapseMSPService(db=db)
        except Exception:
            _service_instance = SynapseMSPService()
    return _service_instance


# ========== Pydantic Models ==========

class AdvisorCreate(BaseModel):
    """Create a custom MSP advisor."""
    name: str = Field(..., min_length=1, max_length=200)
    domain: str = Field(..., description="Advisor domain (security, compliance, etc.)")
    specializations: List[str] = Field(default_factory=list)
    knowledge_base: Dict[str, Any] = Field(default_factory=dict)
    confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)


class AdvisorUpdate(BaseModel):
    """Update advisor fields."""
    name: Optional[str] = None
    domain: Optional[str] = None
    specializations: Optional[List[str]] = None
    knowledge_base: Optional[Dict[str, Any]] = None
    confidence_threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class AdvisoryRequestCreate(BaseModel):
    """Submit an advisory request."""
    request_type: str = Field(..., description="Type of advisory request")
    context: Dict[str, Any] = Field(default_factory=dict)
    urgency: str = Field(default="medium", description="low/medium/high/critical")


class TicketTriageRequest(BaseModel):
    """Quick ticket triage shortcut."""
    title: str
    description: str = ""
    client_id: Optional[str] = None
    reporter: Optional[str] = None


class ThreatAnalysisRequest(BaseModel):
    """Quick threat analysis shortcut."""
    threat_type: str
    source_ip: Optional[str] = None
    affected_assets: List[str] = Field(default_factory=list)
    indicators: Dict[str, Any] = Field(default_factory=dict)


class ComplianceCheckRequest(BaseModel):
    """Quick compliance check shortcut."""
    framework: str = "NIST"
    controls_assessed: int = 0
    controls_passing: int = 0
    gaps: List[str] = Field(default_factory=list)


class AdvisoryRating(BaseModel):
    """Rate an advisory response."""
    was_helpful: bool
    feedback: str = ""


class AutomationRuleCreate(BaseModel):
    """Create an automation rule."""
    name: str = Field(..., min_length=1, max_length=200)
    trigger_event: str
    condition: Dict[str, Any] = Field(default_factory=dict)
    advisor_domain: str
    action: Dict[str, Any] = Field(default_factory=dict)


class AutomationRuleUpdate(BaseModel):
    """Update an automation rule."""
    name: Optional[str] = None
    trigger_event: Optional[str] = None
    condition: Optional[Dict[str, Any]] = None
    advisor_domain: Optional[str] = None
    action: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None


class EventPayload(BaseModel):
    """Event to process against automation rules."""
    event_type: str
    data: Dict[str, Any] = Field(default_factory=dict)


# ========== Advisor Endpoints ==========

@router.get("/advisors")
def list_advisors(domain: Optional[str] = Query(None)):
    """List all MSP advisors, optionally filtered by domain."""
    svc = get_service()
    return {"advisors": svc.list_advisors(domain=domain)}


@router.get("/advisors/{advisor_id}")
def get_advisor(advisor_id: str):
    """Get a single advisor by ID."""
    svc = get_service()
    result = svc.get_advisor(advisor_id)
    if not result:
        raise HTTPException(status_code=404, detail="Advisor not found")
    return result


@router.post("/advisors", status_code=201)
def create_advisor(body: AdvisorCreate):
    """Create a custom MSP advisor."""
    svc = get_service()
    return svc.create_advisor(
        name=body.name,
        domain=body.domain,
        specializations=body.specializations,
        knowledge_base=body.knowledge_base,
        confidence_threshold=body.confidence_threshold,
    )


@router.put("/advisors/{advisor_id}")
def update_advisor(advisor_id: str, body: AdvisorUpdate):
    """Update an existing advisor."""
    svc = get_service()
    updates = body.dict(exclude_none=True)
    result = svc.update_advisor(advisor_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Advisor not found")
    return result


# ========== Advisory Pipeline ==========

@router.post("/advisory/request")
def submit_advisory(body: AdvisoryRequestCreate):
    """Submit an advisory request to the AI command center."""
    svc = get_service()
    return svc.request_advisory(
        request_type=body.request_type,
        context=body.context,
        urgency=body.urgency,
    )


@router.get("/advisory/{response_id}")
def get_advisory_response(response_id: str):
    """Get an advisory response by ID."""
    svc = get_service()
    history = svc.get_advisory_history()
    for resp in history:
        if resp.get("response_id") == response_id:
            return resp
    raise HTTPException(status_code=404, detail="Advisory response not found")


@router.post("/advisory/{response_id}/execute")
def execute_advisory(response_id: str):
    """Execute an auto-executable advisory recommendation."""
    svc = get_service()
    result = svc.execute_advisory(response_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/advisory/{response_id}/rate")
def rate_advisory(response_id: str, body: AdvisoryRating):
    """Rate an advisory response for accuracy tracking."""
    svc = get_service()
    result = svc.rate_advisory(response_id, body.was_helpful, body.feedback)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/advisory/history")
def advisory_history(
    advisor_id: Optional[str] = Query(None),
    request_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """Retrieve advisory history with optional filters."""
    svc = get_service()
    return {
        "history": svc.get_advisory_history(
            advisor_id=advisor_id,
            request_type=request_type,
            limit=limit,
        )
    }


# ========== Triage Shortcuts ==========

@router.post("/triage/ticket")
def triage_ticket(body: TicketTriageRequest):
    """Quick ticket triage - classify, prioritize, draft response."""
    svc = get_service()
    return svc.request_advisory(
        request_type=RequestType.TICKET_TRIAGE.value,
        context={
            "title": body.title,
            "description": body.description,
            "client_id": body.client_id,
            "reporter": body.reporter,
        },
        urgency="medium",
    )


@router.post("/triage/threat")
def triage_threat(body: ThreatAnalysisRequest):
    """Quick threat analysis - classify, assess severity, recommend containment."""
    svc = get_service()
    urgency = "critical" if body.threat_type in ("ransomware", "data_exfiltration") else "high"
    return svc.request_advisory(
        request_type=RequestType.THREAT_ANALYSIS.value,
        context={
            "threat_type": body.threat_type,
            "source_ip": body.source_ip,
            "affected_assets": body.affected_assets,
            "indicators": body.indicators,
        },
        urgency=urgency,
    )


@router.post("/triage/compliance")
def triage_compliance(body: ComplianceCheckRequest):
    """Quick compliance check - assess framework compliance and gaps."""
    svc = get_service()
    return svc.request_advisory(
        request_type=RequestType.COMPLIANCE_CHECK.value,
        context={
            "framework": body.framework,
            "controls_assessed": body.controls_assessed,
            "controls_passing": body.controls_passing,
            "gaps": body.gaps,
        },
        urgency="medium",
    )


# ========== Insights ==========

@router.get("/insights/{client_id}")
def get_insights(client_id: str):
    """Generate AI-powered insights for a client."""
    svc = get_service()
    return {"client_id": client_id, "insights": svc.generate_insights(client_id)}


# ========== Automation Rules ==========

@router.post("/automation/rules", status_code=201)
def create_rule(body: AutomationRuleCreate):
    """Create an event-triggered automation rule."""
    svc = get_service()
    return svc.create_automation_rule(
        name=body.name,
        trigger_event=body.trigger_event,
        condition=body.condition,
        advisor_domain=body.advisor_domain,
        action=body.action,
    )


@router.get("/automation/rules")
def list_rules(enabled_only: bool = Query(False)):
    """List all automation rules."""
    svc = get_service()
    return {"rules": svc.list_rules(enabled_only=enabled_only)}


@router.put("/automation/rules/{rule_id}")
def update_rule(rule_id: str, body: AutomationRuleUpdate):
    """Update an automation rule."""
    svc = get_service()
    updates = body.dict(exclude_none=True)
    result = svc.update_rule(rule_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result


@router.post("/automation/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str):
    """Toggle an automation rule on/off."""
    svc = get_service()
    result = svc.toggle_rule(rule_id)
    if not result:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result


@router.post("/automation/process-event")
def process_event(body: EventPayload):
    """Process an event against automation rules."""
    svc = get_service()
    triggered = svc.process_event({"event_type": body.event_type, "data": body.data})
    return {"event_type": body.event_type, "rules_triggered": len(triggered), "results": triggered}


# ========== Analytics ==========

@router.get("/accuracy")
def get_accuracy():
    """Get per-advisor accuracy metrics."""
    svc = get_service()
    return {"accuracy": svc.get_advisor_accuracy()}


# ========== Dashboard ==========

@router.get("/dashboard")
def get_dashboard():
    """Get Synapse MSP command center dashboard."""
    svc = get_service()
    return svc.get_dashboard()
