"""
API Routes for Cloud Infrastructure Monitoring
Multi-cloud resource monitoring, cost tracking, security posture, and FinOps
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.cloud_monitor import (
    CloudMonitorService,
    CloudProvider,
    ResourceType,
    FindingType,
    AlertType,
    AccountStatus,
    ResourceStatus,
    Severity,
)

router = APIRouter(prefix="/cloud-monitor", tags=["Cloud Monitor"])


def _init_service() -> CloudMonitorService:
    """Initialize CloudMonitorService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return CloudMonitorService(db=db)
    except Exception:
        return CloudMonitorService()


svc = _init_service()


# ========== Request / Response Models ==========

class AccountRegister(BaseModel):
    client_id: str
    provider: str  # aws / azure / gcp
    account_name: str
    account_identifier: str
    region: str = "us-east-1"
    credentials_ref: str = ""


class AccountUpdate(BaseModel):
    account_name: Optional[str] = None
    region: Optional[str] = None
    credentials_ref: Optional[str] = None
    status: Optional[str] = None


class CostRecord(BaseModel):
    account_id: str
    service_name: str
    cost_amount: float
    period_start: datetime
    period_end: datetime
    resource_id: str = ""
    currency: str = "USD"
    usage_quantity: float = 0.0
    usage_unit: str = ""


class AlertCreate(BaseModel):
    account_id: str
    alert_type: str
    severity: str
    title: str
    description: str = ""
    threshold_value: Optional[float] = None
    actual_value: Optional[float] = None


# ========== Account Endpoints ==========

@router.post("/accounts")
async def register_account(data: AccountRegister, user=Depends(get_current_user)):
    """Register a new cloud provider account."""
    acct = svc.register_account(
        client_id=data.client_id,
        provider=data.provider,
        account_name=data.account_name,
        account_identifier=data.account_identifier,
        region=data.region,
        credentials_ref=data.credentials_ref,
    )
    return {"status": "registered", "account": _serialize_account(acct)}


@router.get("/accounts")
async def list_accounts(
    client_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """List cloud accounts with optional filters."""
    accounts = svc.list_accounts(client_id=client_id, provider=provider)
    return {"accounts": [_serialize_account(a) for a in accounts], "total": len(accounts)}


@router.get("/accounts/{account_id}")
async def get_account(account_id: str, user=Depends(get_current_user)):
    """Get a single cloud account."""
    acct = svc.get_account(account_id)
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")
    return _serialize_account(acct)


@router.patch("/accounts/{account_id}")
async def update_account(account_id: str, data: AccountUpdate, user=Depends(get_current_user)):
    """Update cloud account properties."""
    updates = {k: v for k, v in data.dict().items() if v is not None}
    acct = svc.update_account(account_id, **updates)
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"status": "updated", "account": _serialize_account(acct)}


@router.post("/accounts/{account_id}/test")
async def test_connection(account_id: str, user=Depends(get_current_user)):
    """Test connectivity to a cloud provider."""
    result = svc.test_connection(account_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Connection test failed"))
    return result


@router.post("/accounts/{account_id}/sync")
async def sync_resources(account_id: str, user=Depends(get_current_user)):
    """Sync resources from the cloud provider."""
    result = svc.sync_resources(account_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Sync failed"))
    return result


# ========== Resource Endpoints ==========

@router.get("/resources")
async def list_resources(
    account_id: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user=Depends(get_current_user),
):
    """List cloud resources with filters."""
    resources = svc.list_resources(
        account_id=account_id,
        resource_type=resource_type,
        status=status,
        limit=limit,
        offset=offset,
    )
    return {"resources": [_serialize_resource(r) for r in resources], "total": len(resources)}


@router.get("/resources/search")
async def search_resources(
    q: str = Query(..., min_length=1),
    account_id: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """Search resources by name or identifier."""
    results = svc.search_resources(q, account_id=account_id)
    return {"results": [_serialize_resource(r) for r in results], "total": len(results)}


@router.get("/resources/{resource_id}")
async def get_resource(resource_id: str, user=Depends(get_current_user)):
    """Get a single cloud resource."""
    res = svc.get_resource(resource_id)
    if not res:
        raise HTTPException(status_code=404, detail="Resource not found")
    return _serialize_resource(res)


@router.get("/resources/{resource_id}/metrics")
async def get_resource_metrics(resource_id: str, user=Depends(get_current_user)):
    """Get current metrics for a cloud resource."""
    metrics = svc.get_resource_metrics(resource_id)
    if not metrics:
        raise HTTPException(status_code=404, detail="Resource not found")
    return metrics


# ========== Cost Endpoints ==========

@router.post("/costs")
async def record_cost(data: CostRecord, user=Depends(get_current_user)):
    """Manually record a cost entry."""
    entry = svc.record_cost(
        account_id=data.account_id,
        service_name=data.service_name,
        cost_amount=data.cost_amount,
        period_start=data.period_start,
        period_end=data.period_end,
        resource_id=data.resource_id,
        currency=data.currency,
        usage_quantity=data.usage_quantity,
        usage_unit=data.usage_unit,
    )
    return {"status": "recorded", "cost_id": entry.cost_id}


@router.get("/costs/{account_id}")
async def get_costs(
    account_id: str,
    period: str = Query("current"),
    user=Depends(get_current_user),
):
    """Get cost entries for an account."""
    costs = svc.get_costs(account_id, period=period)
    return {
        "account_id": account_id,
        "period": period,
        "entries": [_serialize_cost(c) for c in costs],
        "total": sum(c.cost_amount for c in costs),
    }


@router.get("/costs/{account_id}/breakdown")
async def get_cost_breakdown(account_id: str, user=Depends(get_current_user)):
    """Get cost breakdown by service."""
    return svc.get_cost_breakdown(account_id)


@router.get("/costs/{account_id}/trend")
async def get_cost_trend(
    account_id: str,
    months: int = Query(6, ge=2, le=24),
    user=Depends(get_current_user),
):
    """Get monthly cost trend."""
    return {"account_id": account_id, "trend": svc.get_cost_trend(account_id, months=months)}


@router.get("/costs/{account_id}/forecast")
async def get_cost_forecast(account_id: str, user=Depends(get_current_user)):
    """Get cost forecast for next 3 months."""
    return svc.get_cost_forecast(account_id)


# ========== Security Endpoints ==========

@router.post("/security/{account_id}/scan")
async def run_security_scan(account_id: str, user=Depends(get_current_user)):
    """Run security posture scan against all resources."""
    return svc.run_security_scan(account_id)


@router.get("/security/findings")
async def get_findings(
    account_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    is_resolved: Optional[bool] = Query(None),
    user=Depends(get_current_user),
):
    """Get security findings with filters."""
    findings = svc.get_findings(
        account_id=account_id,
        severity=severity,
        finding_type=finding_type,
        is_resolved=is_resolved,
    )
    return {"findings": [_serialize_finding(f) for f in findings], "total": len(findings)}


@router.post("/security/findings/{finding_id}/resolve")
async def resolve_finding(finding_id: str, user=Depends(get_current_user)):
    """Resolve a security finding."""
    finding = svc.resolve_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"status": "resolved", "finding": _serialize_finding(finding)}


@router.get("/security/{account_id}/posture")
async def get_security_posture(account_id: str, user=Depends(get_current_user)):
    """Get overall security posture score."""
    return svc.get_security_posture(account_id)


# ========== Alert Endpoints ==========

@router.post("/alerts")
async def create_alert(data: AlertCreate, user=Depends(get_current_user)):
    """Create a cloud alert."""
    alert = svc.create_alert(
        account_id=data.account_id,
        alert_type=data.alert_type,
        severity=data.severity,
        title=data.title,
        description=data.description,
        threshold_value=data.threshold_value,
        actual_value=data.actual_value,
    )
    return {"status": "created", "alert": _serialize_alert(alert)}


@router.get("/alerts")
async def get_alerts(
    account_id: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    is_acknowledged: Optional[bool] = Query(None),
    user=Depends(get_current_user),
):
    """Get cloud alerts with filters."""
    alerts = svc.get_alerts(
        account_id=account_id,
        alert_type=alert_type,
        is_acknowledged=is_acknowledged,
    )
    return {"alerts": [_serialize_alert(a) for a in alerts], "total": len(alerts)}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, user=Depends(get_current_user)):
    """Acknowledge a cloud alert."""
    alert = svc.acknowledge_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged", "alert": _serialize_alert(alert)}


# ========== FinOps Endpoints ==========

@router.get("/finops/{account_id}/recommendations")
async def get_optimization_recommendations(account_id: str, user=Depends(get_current_user)):
    """Get FinOps optimization recommendations."""
    return svc.get_optimization_recommendations(account_id)


# ========== Dashboard / Summary ==========

@router.get("/summary")
async def get_multi_cloud_summary(user=Depends(get_current_user)):
    """Aggregate summary across all cloud providers."""
    return svc.get_multi_cloud_summary()


@router.get("/dashboard/{client_id}")
async def get_dashboard(client_id: str, user=Depends(get_current_user)):
    """Full dashboard for an MSP client's cloud infrastructure."""
    return svc.get_dashboard(client_id)


# ========== Serializers ==========

def _serialize_account(a) -> dict:
    return {
        "account_id": a.account_id,
        "client_id": a.client_id,
        "provider": a.provider.value if hasattr(a.provider, "value") else a.provider,
        "account_name": a.account_name,
        "account_identifier": a.account_identifier,
        "region": a.region,
        "credentials_ref": "***" if a.credentials_ref else "",
        "status": a.status.value if hasattr(a.status, "value") else a.status,
        "last_sync_at": a.last_sync_at.isoformat() if a.last_sync_at else None,
        "resources_count": a.resources_count,
        "monthly_cost": a.monthly_cost,
        "cost_trend": a.cost_trend,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _serialize_resource(r) -> dict:
    return {
        "resource_id": r.resource_id,
        "account_id": r.account_id,
        "provider": r.provider.value if hasattr(r.provider, "value") else r.provider,
        "resource_type": r.resource_type.value if hasattr(r.resource_type, "value") else r.resource_type,
        "resource_name": r.resource_name,
        "resource_identifier": r.resource_identifier,
        "region": r.region,
        "status": r.status.value if hasattr(r.status, "value") else r.status,
        "tags": r.tags,
        "monthly_cost": r.monthly_cost,
        "metrics": r.metrics,
        "security_findings": r.security_findings,
        "compliance_status": r.compliance_status,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
    }


def _serialize_cost(c) -> dict:
    return {
        "cost_id": c.cost_id,
        "account_id": c.account_id,
        "service_name": c.service_name,
        "resource_id": c.resource_id,
        "cost_amount": c.cost_amount,
        "currency": c.currency,
        "period_start": c.period_start.isoformat() if c.period_start else None,
        "period_end": c.period_end.isoformat() if c.period_end else None,
        "usage_quantity": c.usage_quantity,
        "usage_unit": c.usage_unit,
    }


def _serialize_finding(f) -> dict:
    return {
        "finding_id": f.finding_id,
        "account_id": f.account_id,
        "resource_id": f.resource_id,
        "finding_type": f.finding_type.value if hasattr(f.finding_type, "value") else f.finding_type,
        "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "compliance_frameworks": f.compliance_frameworks,
        "is_resolved": f.is_resolved,
        "detected_at": f.detected_at.isoformat() if f.detected_at else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
    }


def _serialize_alert(a) -> dict:
    return {
        "alert_id": a.alert_id,
        "account_id": a.account_id,
        "alert_type": a.alert_type.value if hasattr(a.alert_type, "value") else a.alert_type,
        "severity": a.severity.value if hasattr(a.severity, "value") else a.severity,
        "title": a.title,
        "description": a.description,
        "threshold_value": a.threshold_value,
        "actual_value": a.actual_value,
        "is_acknowledged": a.is_acknowledged,
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
