"""
API Routes for Cyber-911 Incident Response Service
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.cyber_911 import (
    Cyber911Service,
    ThreatType,
    SeverityLevel,
    ResponseAction,
    SecurityEvent,
    Threat,
    IncidentResponse
)

router = APIRouter(prefix="/cyber-911", tags=["Cyber-911 - Incident Response"])

# Singleton instance
_cyber911_instance: Optional[Cyber911Service] = None


def get_cyber911() -> Cyber911Service:
    """Get or create Cyber911 instance with DB persistence"""
    global _cyber911_instance
    if _cyber911_instance is None:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            _cyber911_instance = Cyber911Service(db=db)
        except Exception:
            _cyber911_instance = Cyber911Service()
    return _cyber911_instance


# ========== Pydantic Models ==========

class SecurityEventCreate(BaseModel):
    """Security event creation model"""
    event_id: str
    source: str
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    description: str = ""
    raw_data: Optional[Dict[str, Any]] = None


class ThreatResponse(BaseModel):
    """Threat response model"""
    threat_id: str
    threat_type: str
    severity: int
    affected_assets: List[str]
    indicators: Dict[str, Any]
    detected_at: str
    status: str


class IncidentResponseModel(BaseModel):
    """Incident response model"""
    incident_id: str
    threat: ThreatResponse
    actions_taken: List[Dict[str, Any]]
    containment_status: str
    investigation_notes: str
    created_at: str
    resolved_at: Optional[str] = None


class ContainmentAction(BaseModel):
    """Manual containment action request"""
    action: str
    target: str
    reason: Optional[str] = None


# ========== Helper Functions ==========

def threat_to_dict(threat: Threat) -> Dict[str, Any]:
    """Convert Threat to dict"""
    return {
        "threat_id": threat.threat_id,
        "threat_type": threat.threat_type.value,
        "severity": threat.severity.value,
        "affected_assets": threat.affected_assets,
        "indicators": threat.indicators,
        "detected_at": threat.detected_at.isoformat(),
        "status": threat.status
    }


def incident_to_dict(incident: IncidentResponse) -> Dict[str, Any]:
    """Convert IncidentResponse to dict"""
    return {
        "incident_id": incident.incident_id,
        "threat": threat_to_dict(incident.threat),
        "actions_taken": incident.actions_taken,
        "containment_status": incident.containment_status,
        "investigation_notes": incident.investigation_notes,
        "created_at": incident.created_at.isoformat(),
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None
    }


# ========== Event Processing Routes ==========

@router.post("/events")
async def process_security_event(event: SecurityEventCreate, background_tasks: BackgroundTasks, current_user: dict = Depends(require_admin)):
    """
    Process a security event and trigger automated response if needed.
    Returns incident response if threat detected.
    """
    service = get_cyber911()

    security_event = SecurityEvent(
        event_id=event.event_id,
        source=event.source,
        timestamp=datetime.utcnow(),
        event_type=event.event_type,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        user=event.user,
        hostname=event.hostname,
        description=event.description,
        raw_data=event.raw_data or {}
    )

    response = await service.process_event(security_event)

    if response:
        return {
            "threat_detected": True,
            "incident": incident_to_dict(response)
        }

    return {
        "threat_detected": False,
        "message": "Event processed - no threat detected"
    }


@router.post("/events/batch")
async def process_batch_events(events: List[SecurityEventCreate], current_user: dict = Depends(require_admin)):
    """Process multiple security events"""
    service = get_cyber911()
    results = []

    for event in events:
        security_event = SecurityEvent(
            event_id=event.event_id,
            source=event.source,
            timestamp=datetime.utcnow(),
            event_type=event.event_type,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            user=event.user,
            hostname=event.hostname,
            description=event.description,
            raw_data=event.raw_data or {}
        )

        response = await service.process_event(security_event)

        results.append({
            "event_id": event.event_id,
            "threat_detected": response is not None,
            "incident_id": response.incident_id if response else None
        })

    return {
        "processed": len(results),
        "threats_detected": sum(1 for r in results if r["threat_detected"]),
        "results": results
    }


# ========== Incident Routes ==========

@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = Query(None, description="Filter by containment status"),
    severity_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity"),
    limit: int = Query(50, ge=1, le=200)
):
    """List all incidents with optional filtering"""
    service = get_cyber911()
    incidents = service.incidents

    if status:
        incidents = [i for i in incidents if i.containment_status == status]

    if severity_min:
        incidents = [i for i in incidents if i.threat.severity.value >= severity_min]

    # Sort by created_at descending
    incidents = sorted(incidents, key=lambda x: x.created_at, reverse=True)[:limit]

    return {
        "incidents": [incident_to_dict(i) for i in incidents],
        "total": len(incidents)
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get incident details"""
    service = get_cyber911()

    incident = next(
        (i for i in service.incidents if i.incident_id == incident_id),
        None
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return incident_to_dict(incident)


@router.post("/incidents/{incident_id}/contain")
async def contain_incident(incident_id: str, current_user: dict = Depends(require_admin)):
    """Initiate containment for an incident"""
    service = get_cyber911()

    incident = next(
        (i for i in service.incidents if i.incident_id == incident_id),
        None
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.containment_status = "contained"
    incident.actions_taken.append({
        "action": "containment_initiated",
        "timestamp": datetime.utcnow().isoformat(),
        "details": "Manual containment triggered via API"
    })
    service._persist_incident(incident)

    return incident_to_dict(incident)


@router.post("/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str, current_user: dict = Depends(require_admin)):
    """Resolve an incident"""
    service = get_cyber911()

    incident = next(
        (i for i in service.incidents if i.incident_id == incident_id),
        None
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.containment_status = "resolved"
    incident.resolved_at = datetime.utcnow()
    incident.actions_taken.append({
        "action": "incident_resolved",
        "timestamp": datetime.utcnow().isoformat(),
        "details": "Incident resolved via API"
    })
    service._persist_incident(incident)

    return incident_to_dict(incident)


@router.patch("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, status: str, current_user: dict = Depends(require_admin)):
    """Update incident containment status"""
    service = get_cyber911()

    valid_statuses = ["pending", "monitoring", "contained", "resolved", "escalated"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Valid: {valid_statuses}"
        )

    incident = next(
        (i for i in service.incidents if i.incident_id == incident_id),
        None
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.containment_status = status
    if status == "resolved":
        incident.resolved_at = datetime.utcnow()
    service._persist_incident(incident)

    return incident_to_dict(incident)


@router.patch("/incidents/{incident_id}/notes")
async def add_investigation_notes(incident_id: str, notes: str, current_user: dict = Depends(require_admin)):
    """Add investigation notes to incident"""
    service = get_cyber911()

    incident = next(
        (i for i in service.incidents if i.incident_id == incident_id),
        None
    )

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.investigation_notes += f"\n\n[{datetime.utcnow().isoformat()}] {notes}"
    service._persist_incident(incident)

    return incident_to_dict(incident)


# ========== Containment Routes ==========

@router.get("/containment/blocked-ips")
async def list_blocked_ips():
    """List all blocked IPs"""
    service = get_cyber911()
    return {
        "blocked_ips": list(service.blocked_ips),
        "count": len(service.blocked_ips)
    }


@router.post("/containment/block-ip")
async def block_ip(ip: str, reason: Optional[str] = None, current_user: dict = Depends(require_admin)):
    """Manually block an IP address"""
    service = get_cyber911()
    service.blocked_ips.add(ip)
    service._persist_blocked_ip(ip, add=True)

    return {
        "success": True,
        "ip": ip,
        "reason": reason,
        "blocked_at": datetime.utcnow().isoformat()
    }


@router.delete("/containment/block-ip/{ip}")
async def unblock_ip(ip: str, current_user: dict = Depends(require_admin)):
    """Unblock an IP address"""
    service = get_cyber911()

    if ip not in service.blocked_ips:
        raise HTTPException(status_code=404, detail="IP not in blocklist")

    service.blocked_ips.remove(ip)
    service._persist_blocked_ip(ip, add=False)

    return {
        "success": True,
        "ip": ip,
        "unblocked_at": datetime.utcnow().isoformat()
    }


@router.get("/containment/isolated-hosts")
async def list_isolated_hosts():
    """List all isolated hosts"""
    service = get_cyber911()
    return {
        "isolated_hosts": list(service.isolated_hosts),
        "count": len(service.isolated_hosts)
    }


@router.post("/containment/isolate-host")
async def isolate_host(hostname: str, reason: Optional[str] = None, current_user: dict = Depends(require_admin)):
    """Manually isolate a host"""
    service = get_cyber911()
    service.isolated_hosts.add(hostname)
    service._persist_isolated_host(hostname, add=True)

    return {
        "success": True,
        "hostname": hostname,
        "reason": reason,
        "isolated_at": datetime.utcnow().isoformat()
    }


@router.delete("/containment/isolate-host/{hostname}")
async def unisolate_host(hostname: str, current_user: dict = Depends(require_admin)):
    """Remove host from isolation"""
    service = get_cyber911()

    if hostname not in service.isolated_hosts:
        raise HTTPException(status_code=404, detail="Host not in isolation")

    service.isolated_hosts.remove(hostname)
    service._persist_isolated_host(hostname, add=False)

    return {
        "success": True,
        "hostname": hostname,
        "unisolated_at": datetime.utcnow().isoformat()
    }


@router.get("/containment/disabled-accounts")
async def list_disabled_accounts():
    """List all disabled accounts"""
    service = get_cyber911()
    return {
        "disabled_accounts": list(service.disabled_accounts),
        "count": len(service.disabled_accounts)
    }


@router.post("/containment/disable-account")
async def disable_account(username: str, reason: Optional[str] = None, current_user: dict = Depends(require_admin)):
    """Manually disable a user account"""
    service = get_cyber911()
    service.disabled_accounts.add(username)
    service._persist_disabled_account(username, add=True)

    return {
        "success": True,
        "username": username,
        "reason": reason,
        "disabled_at": datetime.utcnow().isoformat()
    }


@router.delete("/containment/disable-account/{username}")
async def enable_account(username: str, current_user: dict = Depends(require_admin)):
    """Re-enable a disabled account"""
    service = get_cyber911()

    if username not in service.disabled_accounts:
        raise HTTPException(status_code=404, detail="Account not disabled")

    service.disabled_accounts.remove(username)
    service._persist_disabled_account(username, add=False)

    return {
        "success": True,
        "username": username,
        "enabled_at": datetime.utcnow().isoformat()
    }


# ========== DEFCON & Status Routes ==========

@router.get("/defcon")
async def get_defcon_level():
    """Get current DEFCON level (1-5)"""
    service = get_cyber911()
    level = service.get_defcon_level()

    descriptions = {
        5: "Normal operations",
        4: "Elevated risk - increased monitoring",
        3: "Significant threat - active investigation",
        2: "Severe threat - containment in progress",
        1: "Maximum alert - total lockdown"
    }

    colors = {5: "green", 4: "blue", 3: "yellow", 2: "orange", 1: "red"}

    return {
        "level": level,
        "description": descriptions[level],
        "color": colors[level],
        "active_incidents": len([
            i for i in service.incidents
            if i.containment_status != "resolved"
        ])
    }


@router.get("/dashboard")
async def get_dashboard():
    """Get Cyber-911 dashboard data"""
    service = get_cyber911()
    return service.get_dashboard_data()


# ========== Playbook Routes ==========

@router.get("/playbooks")
async def list_playbooks():
    """List all response playbooks"""
    service = get_cyber911()

    playbooks = {}
    for threat_type, actions in service.PLAYBOOKS.items():
        playbooks[threat_type.value] = [a.value for a in actions]

    return {
        "playbooks": playbooks,
        "auto_containment_threshold": service.AUTO_CONTAINMENT_THRESHOLD
    }


@router.get("/playbooks/{threat_type}")
async def get_playbook(threat_type: str):
    """Get playbook for specific threat type"""
    service = get_cyber911()

    try:
        tt = ThreatType(threat_type)
    except ValueError:
        valid_types = [t.value for t in ThreatType]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid threat type. Valid: {valid_types}"
        )

    actions = service.PLAYBOOKS.get(tt, [ResponseAction.ALERT_SECURITY_TEAM])

    return {
        "threat_type": threat_type,
        "actions": [a.value for a in actions],
        "auto_contain": True  # All high severity threats auto-contain
    }


# ========== Reference Data Routes ==========

@router.get("/threat-types")
async def list_threat_types():
    """List all threat types"""
    return {
        "threat_types": [
            {"value": t.value, "name": t.name}
            for t in ThreatType
        ]
    }


@router.get("/severity-levels")
async def list_severity_levels():
    """List all severity levels"""
    return {
        "severity_levels": [
            {"value": s.value, "name": s.name}
            for s in SeverityLevel
        ]
    }


@router.get("/response-actions")
async def list_response_actions():
    """List all response actions"""
    return {
        "response_actions": [
            {"value": a.value, "name": a.name}
            for a in ResponseAction
        ]
    }


# ========== Statistics Routes ==========

@router.get("/statistics")
async def get_statistics():
    """Get incident statistics"""
    service = get_cyber911()

    if not service.incidents:
        return {
            "total_incidents": 0,
            "by_status": {},
            "by_threat_type": {},
            "by_severity": {},
            "avg_response_time_seconds": None
        }

    by_status = {}
    by_threat_type = {}
    by_severity = {}

    for incident in service.incidents:
        # Status
        status = incident.containment_status
        by_status[status] = by_status.get(status, 0) + 1

        # Threat type
        tt = incident.threat.threat_type.value
        by_threat_type[tt] = by_threat_type.get(tt, 0) + 1

        # Severity
        sev = incident.threat.severity.name
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total_incidents": len(service.incidents),
        "by_status": by_status,
        "by_threat_type": by_threat_type,
        "by_severity": by_severity,
        "containment_measures": {
            "blocked_ips": len(service.blocked_ips),
            "isolated_hosts": len(service.isolated_hosts),
            "disabled_accounts": len(service.disabled_accounts)
        }
    }


@router.get("/statistics/timeline")
async def get_incident_timeline(hours: int = Query(24, ge=1, le=720)):
    """Get incident timeline for past N hours"""
    service = get_cyber911()
    cutoff = datetime.utcnow().timestamp() - (hours * 3600)

    recent = [
        i for i in service.incidents
        if i.created_at.timestamp() > cutoff
    ]

    return {
        "hours": hours,
        "incidents": [
            {
                "incident_id": i.incident_id,
                "threat_type": i.threat.threat_type.value,
                "severity": i.threat.severity.value,
                "created_at": i.created_at.isoformat()
            }
            for i in sorted(recent, key=lambda x: x.created_at)
        ],
        "total": len(recent)
    }
