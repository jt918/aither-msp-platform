"""
AITHER Platform - Dynamic Honeypot & Canary Deployment API Routes

Deception-as-a-Service for MSP clients:
- Asset lifecycle (create, deploy, undeploy, retire)
- Honeypot service management
- Canary token planting and monitoring
- Automated deception rules with threat-score triggers
- Interaction capture and intelligence reporting
- Coverage analytics and dashboard
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
from sqlalchemy.orm import Session

from core.database import get_sync_db
from services.msp.dynamic_deception import DynamicDeceptionService

router = APIRouter(prefix="/deception", tags=["Defense - Dynamic Deception"])


# ==================== Request Models ====================

class AssetCreateRequest(BaseModel):
    asset_type: str = Field(..., description="honeypot/canary_token/honeyfile/honeyfolder/honey_credential/honey_service/honey_network/honey_database/breadcrumb")
    name: str = Field(..., min_length=2)
    description: str = ""
    deployment_target: str = ""
    config: Optional[Dict[str, Any]] = None


class AssetUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    deployment_target: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    status: Optional[str] = None


class DeployRequest(BaseModel):
    target: str = ""


class HoneypotCreateRequest(BaseModel):
    asset_id: str
    service_type: str = Field(..., description="ssh/rdp/http/https/ftp/smb/telnet/mysql/mssql/smtp/dns/snmp/ldap/redis/elasticsearch")
    listen_port: int
    listen_ip: str = "0.0.0.0"
    banner: str = ""
    credentials: Optional[List[Dict[str, str]]] = None
    response_templates: Optional[Dict[str, Any]] = None
    capture_level: str = "auth_capture"
    max_sessions: int = 10


class CanaryTokenCreateRequest(BaseModel):
    asset_id: str
    token_type: str = Field(..., description="aws_key/api_key/database_cred/document/url/dns/email/file_share/registry_key/env_variable")
    deployment_location: str = ""
    trigger_webhook: str = ""


class TokenCheckRequest(BaseModel):
    token_value: str


class TokenTriggerRequest(BaseModel):
    source_ip: str
    source_user: str = ""


class RuleCreateRequest(BaseModel):
    name: str = Field(..., min_length=2)
    action: str = Field(..., description="deploy_honeypot/redirect_to_honeypot/plant_canary/enable_full_capture/alert_soc")
    risk_threshold: float = 7.0
    description: str = ""
    trigger_condition: Optional[Dict[str, Any]] = None
    target_entity_type: str = "ip"
    deception_asset_id: Optional[str] = None
    cooldown_minutes: int = 60


class RuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_condition: Optional[Dict[str, Any]] = None
    risk_threshold: Optional[float] = None
    target_entity_type: Optional[str] = None
    action: Optional[str] = None
    deception_asset_id: Optional[str] = None
    cooldown_minutes: Optional[int] = None
    is_enabled: Optional[bool] = None


class ThreatEvaluateRequest(BaseModel):
    entity_type: str = Field(..., description="ip/user/host/network")
    entity_value: str
    threat_score: float = Field(..., ge=0.0, le=10.0)


class BreadcrumbRequest(BaseModel):
    target_network: str


class InteractionRecordRequest(BaseModel):
    asset_id: str
    source_ip: str
    data: Dict[str, Any] = Field(default_factory=dict)


# ==================== Helper ====================

def _get_service(db: Session) -> DynamicDeceptionService:
    return DynamicDeceptionService(db=db)


# ==================== Health ====================

@router.get("/health")
def deception_health(db: Session = Depends(get_sync_db)):
    """Check Dynamic Deception service health."""
    svc = _get_service(db)
    assets = svc.list_assets()
    active = [a for a in assets if a.get("status") in ("deployed", "active")]
    return {
        "status": "healthy",
        "module": "Dynamic Deception Engine",
        "version": "1.0.0",
        "total_assets": len(assets),
        "active_assets": len(active),
    }


# ==================== Assets CRUD ====================

@router.post("/assets")
def create_asset(req: AssetCreateRequest, db: Session = Depends(get_sync_db)):
    """Create a new deception asset."""
    svc = _get_service(db)
    result = svc.create_asset(
        asset_type=req.asset_type,
        name=req.name,
        description=req.description,
        deployment_target=req.deployment_target,
        config=req.config,
    )
    return result


@router.get("/assets")
def list_assets(
    asset_type: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_sync_db),
):
    """List deception assets with optional filters."""
    svc = _get_service(db)
    return svc.list_assets(asset_type=asset_type, status=status)


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str, db: Session = Depends(get_sync_db)):
    """Get a deception asset by ID."""
    svc = _get_service(db)
    result = svc.get_asset(asset_id)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.put("/assets/{asset_id}")
def update_asset(asset_id: str, req: AssetUpdateRequest, db: Session = Depends(get_sync_db)):
    """Update a deception asset."""
    svc = _get_service(db)
    updates = {k: v for k, v in req.dict().items() if v is not None}
    result = svc.update_asset(asset_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.post("/assets/{asset_id}/deploy")
def deploy_asset(asset_id: str, req: DeployRequest, db: Session = Depends(get_sync_db)):
    """Deploy a deception asset to its target."""
    svc = _get_service(db)
    result = svc.deploy_asset(asset_id, target=req.target)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.post("/assets/{asset_id}/undeploy")
def undeploy_asset(asset_id: str, db: Session = Depends(get_sync_db)):
    """Undeploy a deception asset."""
    svc = _get_service(db)
    result = svc.undeploy_asset(asset_id)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


@router.post("/assets/{asset_id}/retire")
def retire_asset(asset_id: str, db: Session = Depends(get_sync_db)):
    """Retire a deception asset."""
    svc = _get_service(db)
    result = svc.retire_asset(asset_id)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return result


# ==================== Honeypot Services ====================

@router.post("/honeypots")
def create_honeypot(req: HoneypotCreateRequest, db: Session = Depends(get_sync_db)):
    """Create a honeypot service bound to an asset."""
    svc = _get_service(db)
    return svc.create_honeypot_service(
        asset_id=req.asset_id,
        service_type=req.service_type,
        listen_port=req.listen_port,
        listen_ip=req.listen_ip,
        banner=req.banner,
        credentials=req.credentials,
        response_templates=req.response_templates,
        capture_level=req.capture_level,
        max_sessions=req.max_sessions,
    )


@router.get("/honeypots")
def list_honeypots(asset_id: Optional[str] = None, db: Session = Depends(get_sync_db)):
    """List honeypot services."""
    svc = _get_service(db)
    return svc.list_honeypot_services(asset_id=asset_id)


# ==================== Canary Tokens ====================

@router.post("/canary-tokens")
def create_canary_token(req: CanaryTokenCreateRequest, db: Session = Depends(get_sync_db)):
    """Create and plant a canary token."""
    svc = _get_service(db)
    return svc.create_canary_token(
        asset_id=req.asset_id,
        token_type=req.token_type,
        deployment_location=req.deployment_location,
        trigger_webhook=req.trigger_webhook,
    )


@router.post("/canary-tokens/check")
def check_canary_token(req: TokenCheckRequest, db: Session = Depends(get_sync_db)):
    """Check if a token value is a canary token (public endpoint for detection)."""
    svc = _get_service(db)
    result = svc.check_token(req.token_value)
    if not result:
        return {"triggered": False}
    return result


@router.post("/canary-tokens/{token_id}/trigger")
def record_token_trigger(token_id: str, req: TokenTriggerRequest, db: Session = Depends(get_sync_db)):
    """Record that a canary token was triggered."""
    svc = _get_service(db)
    result = svc.record_token_trigger(token_id, source_ip=req.source_ip, source_user=req.source_user)
    if not result:
        raise HTTPException(status_code=404, detail="Token not found")
    return result


# ==================== Rules ====================

@router.post("/rules")
def create_rule(req: RuleCreateRequest, db: Session = Depends(get_sync_db)):
    """Create an automated deception rule."""
    svc = _get_service(db)
    return svc.create_rule(
        name=req.name,
        action=req.action,
        risk_threshold=req.risk_threshold,
        description=req.description,
        trigger_condition=req.trigger_condition,
        target_entity_type=req.target_entity_type,
        deception_asset_id=req.deception_asset_id,
        cooldown_minutes=req.cooldown_minutes,
    )


@router.get("/rules")
def list_rules(enabled_only: bool = False, db: Session = Depends(get_sync_db)):
    """List deception rules."""
    svc = _get_service(db)
    return svc.list_rules(enabled_only=enabled_only)


@router.put("/rules/{rule_id}")
def update_rule(rule_id: str, req: RuleUpdateRequest, db: Session = Depends(get_sync_db)):
    """Update a deception rule."""
    svc = _get_service(db)
    updates = {k: v for k, v in req.dict().items() if v is not None}
    result = svc.update_rule(rule_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result


@router.post("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str, db: Session = Depends(get_sync_db)):
    """Toggle a rule's enabled/disabled state."""
    svc = _get_service(db)
    result = svc.toggle_rule(rule_id)
    if not result:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result


# ==================== Threat Evaluation ====================

@router.post("/evaluate-threat")
def evaluate_threat(req: ThreatEvaluateRequest, db: Session = Depends(get_sync_db)):
    """Evaluate a threat score and auto-deploy deception assets if thresholds are crossed."""
    svc = _get_service(db)
    return svc.evaluate_threat_and_deploy(
        entity_type=req.entity_type,
        entity_value=req.entity_value,
        threat_score=req.threat_score,
    )


@router.post("/plant-breadcrumbs")
def plant_breadcrumbs(req: BreadcrumbRequest, db: Session = Depends(get_sync_db)):
    """Plant breadcrumb trails in a target network segment."""
    svc = _get_service(db)
    return svc._plant_breadcrumbs(req.target_network)


# ==================== Interactions ====================

@router.post("/interactions")
def record_interaction(req: InteractionRecordRequest, db: Session = Depends(get_sync_db)):
    """Record an attacker interaction with a deception asset."""
    svc = _get_service(db)
    return svc.record_interaction(
        asset_id=req.asset_id,
        source_ip=req.source_ip,
        data=req.data,
    )


@router.get("/interactions")
def list_interactions(asset_id: Optional[str] = None, db: Session = Depends(get_sync_db)):
    """List interaction logs, optionally filtered by asset."""
    svc = _get_service(db)
    if asset_id:
        return svc._get_interactions_for_asset(asset_id)
    # All interactions (limited)
    if svc._use_db:
        try:
            from models.dynamic_deception import InteractionLogModel
            rows = db.query(InteractionLogModel).order_by(InteractionLogModel.timestamp.desc()).limit(200).all()
            return [svc._interaction_row_to_dict(r) for r in rows]
        except Exception:
            pass
    results = sorted(svc._interactions.values(), key=lambda i: i.timestamp, reverse=True)
    return [svc._interaction_to_dict(i) for i in results[:200]]


# ==================== Intelligence ====================

@router.post("/intelligence/{asset_id}")
def generate_intelligence_report(asset_id: str, db: Session = Depends(get_sync_db)):
    """Generate an intelligence report from interactions with a specific asset."""
    svc = _get_service(db)
    result = svc.generate_intelligence_report(asset_id)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/intelligence")
def list_intelligence_reports(db: Session = Depends(get_sync_db)):
    """List all intelligence reports."""
    svc = _get_service(db)
    if svc._use_db:
        try:
            from models.dynamic_deception import IntelligenceReportModel
            rows = db.query(IntelligenceReportModel).order_by(IntelligenceReportModel.generated_at.desc()).limit(50).all()
            return [
                {
                    "report_id": r.report_id,
                    "asset_id": r.asset_id,
                    "report_type": r.report_type,
                    "title": r.title,
                    "findings": r.findings or {},
                    "iocs_extracted": r.iocs_extracted or [],
                    "ttps_observed": r.ttps_observed or [],
                    "attacker_profile": r.attacker_profile or {},
                    "generated_at": r.generated_at.isoformat() if r.generated_at else None,
                }
                for r in rows
            ]
        except Exception:
            pass
    return [
        {
            "report_id": r.report_id,
            "asset_id": r.asset_id,
            "report_type": r.report_type,
            "title": r.title,
            "findings": r.findings,
            "iocs_extracted": r.iocs_extracted,
            "ttps_observed": r.ttps_observed,
            "attacker_profile": r.attacker_profile,
            "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        }
        for r in svc._reports.values()
    ]


# ==================== Coverage & Analytics ====================

@router.get("/coverage")
def get_coverage(client_id: str = "", db: Session = Depends(get_sync_db)):
    """Get deception coverage metrics."""
    svc = _get_service(db)
    return svc.get_deception_coverage(client_id=client_id)


@router.get("/analytics/most-triggered")
def most_triggered(limit: int = 10, db: Session = Depends(get_sync_db)):
    """Get the most triggered deception assets."""
    svc = _get_service(db)
    return svc.get_most_triggered_assets(limit=limit)


@router.get("/analytics/attacker-origins")
def attacker_origins(db: Session = Depends(get_sync_db)):
    """Get interaction counts by source IP."""
    svc = _get_service(db)
    return svc.get_attacker_origins()


@router.get("/analytics/credential-attempts")
def credential_attempts(db: Session = Depends(get_sync_db)):
    """Get all credential attempts across deception assets."""
    svc = _get_service(db)
    return svc.get_credential_attempts()


@router.get("/dashboard")
def deception_dashboard(db: Session = Depends(get_sync_db)):
    """Get full deception dashboard data."""
    svc = _get_service(db)
    return svc.get_dashboard()
