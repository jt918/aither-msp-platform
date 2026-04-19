"""
API Routes for MSP Solutions
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session

from services.msp import SelfHealingAgent, Cyber911Service, ITSMService
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

router = APIRouter(prefix="/msp", tags=["MSP Solutions"])

# Initialize services
self_healing = SelfHealingAgent()
cyber_911 = Cyber911Service()
itsm = ITSMService()


# ===== Request/Response Models =====

class AlertRequest(BaseModel):
    source_system: str
    alert_type: str
    severity: str
    message: str
    resource_id: str
    metrics: Optional[Dict[str, Any]] = None


class IncidentRequest(BaseModel):
    title: str
    description: str
    severity: str  # critical, high, medium, low
    affected_systems: List[str]
    attack_vector: Optional[str] = None


class TicketRequest(BaseModel):
    title: str
    description: str
    category: str  # hardware, software, network, security, email, printer, access, other
    priority: str  # critical, high, medium, low
    customer_name: Optional[str] = ""
    customer_id: Optional[str] = ""
    assigned_to: Optional[str] = None


class TicketUpdateRequest(BaseModel):
    status: Optional[str] = None  # new, assigned, in_progress, pending_customer, resolved, closed
    note: Optional[str] = None
    assigned_to: Optional[str] = None


# ===== Self-Healing Agent Routes =====

@router.post("/self-healing/alerts")
async def receive_alert(request: AlertRequest, background_tasks: BackgroundTasks, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Receive and process a system alert via detect_and_heal pipeline."""
    try:
        from services.msp.self_healing import Fault, FaultType

        # Map alert_type string to FaultType enum; default to SERVICE_DOWN
        fault_type_map = {
            "printer_spooler": FaultType.PRINTER_SPOOLER,
            "disk_space": FaultType.DISK_SPACE,
            "service_down": FaultType.SERVICE_DOWN,
            "service_crash": FaultType.SERVICE_DOWN,
            "network_connectivity": FaultType.NETWORK_CONNECTIVITY,
            "network_timeout": FaultType.NETWORK_CONNECTIVITY,
            "high_cpu": FaultType.HIGH_CPU,
            "high_memory": FaultType.HIGH_MEMORY,
            "dns_failure": FaultType.DNS_FAILURE,
            "certificate_expiry": FaultType.CERTIFICATE_EXPIRY,
        }

        # Map severity string to numeric (1-10)
        severity_str = (request.severity or "warning").lower()
        severity_num = {"critical": 9, "high": 7, "warning": 5, "info": 2}.get(severity_str, 5)

        alert_type_lower = (request.alert_type or "service_down").lower()
        fault_type = fault_type_map.get(alert_type_lower, FaultType.SERVICE_DOWN)

        fault = Fault(
            fault_id=f"ALERT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            fault_type=fault_type,
            severity=severity_num,
            endpoint=request.resource_id or "unknown",
            description=request.message or "",
            metadata=request.metrics or {},
        )

        result = await self_healing.detect_and_heal(fault)

        return {
            "status": "received",
            "alert_id": fault.fault_id,
            "auto_remediation": result.get("status") == "resolved",
            "ticket_created": result.get("ticket") is not None,
            "ticket_id": result.get("ticket", {}).get("ticket_id") if isinstance(result.get("ticket"), dict) else None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/self-healing/status")
def get_self_healing_status(db: Session = Depends(get_sync_db)):
    """Get self-healing system status"""
    return self_healing.get_system_status()


@router.get("/self-healing/dashboard")
def get_self_healing_dashboard(db: Session = Depends(get_sync_db)):
    """Get self-healing dashboard data"""
    return self_healing.get_dashboard_data()


# ===== Cyber-911 Routes =====

@router.post("/cyber-911/incidents")
async def create_incident(request: IncidentRequest, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Create a security incident by processing a synthetic security event"""
    try:
        from services.msp.cyber_911 import SecurityEvent, SeverityLevel

        # Map severity string to event_type keywords that the classifier will pick up
        severity_event_map = {
            "critical": "ransomware",
            "high": "intrusion",
            "medium": "phishing",
            "low": "policy_violation"
        }

        event_type = severity_event_map.get(request.severity.lower(), "policy_violation")

        event = SecurityEvent(
            event_id=f"EVT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            source="api",
            timestamp=datetime.utcnow(),
            event_type=event_type,
            hostname=request.affected_systems[0] if request.affected_systems else None,
            description=f"{request.title}: {request.description}",
            raw_data={"attack_vector": request.attack_vector},
        )

        response = await cyber_911.process_event(event)

        if response:
            return {
                "incident_id": response.incident_id,
                "defcon_level": cyber_911.get_defcon_level(),
                "status": response.containment_status,
                "playbook_active": len(response.actions_taken) > 0
            }

        return {
            "incident_id": None,
            "defcon_level": cyber_911.get_defcon_level(),
            "status": "no_threat_detected",
            "playbook_active": False
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cyber-911/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_sync_db)):
    """Get incident details"""
    incident = next((i for i in cyber_911.incidents if i.incident_id == incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "incident_id": incident.incident_id,
        "threat_type": incident.threat.threat_type.value,
        "severity": incident.threat.severity.value,
        "containment_status": incident.containment_status,
        "actions_taken": incident.actions_taken,
        "investigation_notes": incident.investigation_notes,
        "created_at": incident.created_at.isoformat(),
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
    }


@router.get("/cyber-911/dashboard")
def get_cyber_dashboard(db: Session = Depends(get_sync_db)):
    """Get Cyber-911 dashboard data"""
    return cyber_911.get_dashboard_data()


@router.post("/cyber-911/incidents/{incident_id}/contain")
def contain_incident(incident_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Execute containment for an incident"""
    incident = next((i for i in cyber_911.incidents if i.incident_id == incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found or already contained")

    incident.containment_status = "contained"
    incident.actions_taken.append({
        "action": "containment_initiated",
        "timestamp": datetime.utcnow().isoformat(),
        "details": "Manual containment triggered via API"
    })
    return {"status": "contained", "incident_id": incident_id}


@router.post("/cyber-911/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, lessons_learned: str = "", current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Resolve an incident"""
    incident = next((i for i in cyber_911.incidents if i.incident_id == incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.containment_status = "resolved"
    incident.resolved_at = datetime.utcnow()
    incident.actions_taken.append({
        "action": "incident_resolved",
        "timestamp": datetime.utcnow().isoformat(),
        "details": f"Resolved via API. {lessons_learned}"
    })
    return {"status": "resolved", "incident_id": incident_id, "lessons_learned": lessons_learned}


# ===== ITSM Routes =====

@router.post("/itsm/tickets")
def create_ticket(request: TicketRequest, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Create a new IT service ticket"""
    try:
        from services.msp.itsm import TicketCategory, TicketPriority

        category_map = {
            "hardware": TicketCategory.HARDWARE,
            "software": TicketCategory.SOFTWARE,
            "network": TicketCategory.NETWORK,
            "security": TicketCategory.SECURITY,
            "email": TicketCategory.EMAIL,
            "printer": TicketCategory.PRINTER,
            "access": TicketCategory.ACCESS,
            "other": TicketCategory.OTHER
        }

        priority_map = {
            "critical": TicketPriority.P1_CRITICAL,
            "high": TicketPriority.P2_HIGH,
            "medium": TicketPriority.P3_MEDIUM,
            "low": TicketPriority.P4_LOW
        }

        ticket = itsm.create_ticket(
            title=request.title,
            description=request.description,
            category=category_map.get(request.category.lower(), TicketCategory.OTHER),
            priority=priority_map.get(request.priority.lower(), TicketPriority.P3_MEDIUM),
            customer_name=request.customer_name or "",
            customer_id=request.customer_id or ""
        )

        # Auto-assign if specified
        if request.assigned_to:
            itsm.update_ticket(ticket.ticket_id, assigned_to=request.assigned_to)

        return {
            "ticket_id": ticket.ticket_id,
            "status": ticket.status.value,
            "priority": ticket.priority.value,
            "sla_deadline": ticket.sla_deadline.isoformat() if ticket.sla_deadline else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/itsm/tickets/{ticket_id}")
def get_ticket(ticket_id: str, db: Session = Depends(get_sync_db)):
    """Get ticket details"""
    ticket = itsm.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    sla_status = itsm.get_sla_status(ticket)

    return {
        "ticket_id": ticket.ticket_id,
        "title": ticket.title,
        "description": ticket.description,
        "category": ticket.category.value,
        "priority": ticket.priority.value,
        "status": ticket.status.value,
        "customer_name": ticket.customer_name,
        "customer_id": ticket.customer_id,
        "assigned_to": ticket.assigned_to,
        "created_at": ticket.created_at.isoformat(),
        "updated_at": ticket.updated_at.isoformat(),
        "resolved_at": ticket.resolved_at.isoformat() if ticket.resolved_at else None,
        "sla_deadline": ticket.sla_deadline.isoformat() if ticket.sla_deadline else None,
        "sla_status": sla_status,
        "notes": ticket.notes,
        "auto_healed": ticket.auto_healed
    }


@router.put("/itsm/tickets/{ticket_id}")
def update_ticket(ticket_id: str, request: TicketUpdateRequest, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Update a ticket"""
    from services.msp.itsm import TicketStatus

    status_map = {
        "new": TicketStatus.NEW,
        "assigned": TicketStatus.ASSIGNED,
        "in_progress": TicketStatus.IN_PROGRESS,
        "pending_customer": TicketStatus.PENDING_CUSTOMER,
        "resolved": TicketStatus.RESOLVED,
        "closed": TicketStatus.CLOSED
    }

    ticket = itsm.update_ticket(
        ticket_id=ticket_id,
        status=status_map.get(request.status) if request.status else None,
        note=request.note,
        assigned_to=request.assigned_to
    )

    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    return {"ticket_id": ticket.ticket_id, "status": ticket.status.value}


@router.get("/itsm/tickets")
def list_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_sync_db),
):
    """List tickets with optional filters"""
    tickets = list(itsm.tickets.values())

    if status:
        tickets = [t for t in tickets if t.status.value == status]
    if priority:
        tickets = [t for t in tickets if t.priority.value == priority]

    tickets = sorted(tickets, key=lambda t: t.created_at, reverse=True)[:limit]

    return {
        "count": len(tickets),
        "tickets": [
            {
                "ticket_id": t.ticket_id,
                "title": t.title,
                "category": t.category.value,
                "status": t.status.value,
                "priority": t.priority.value,
                "assigned_to": t.assigned_to,
                "created_at": t.created_at.isoformat()
            }
            for t in tickets
        ]
    }


@router.get("/itsm/dashboard")
def get_itsm_dashboard(db: Session = Depends(get_sync_db)):
    """Get ITSM dashboard data"""
    metrics = itsm.get_dashboard_metrics()
    roi = itsm.calculate_roi(metrics.get("auto_healed", 0))
    return {
        "metrics": metrics,
        "roi": roi
    }


@router.get("/itsm/sla-report")
def get_sla_report(db: Session = Depends(get_sync_db)):
    """Get SLA compliance report"""
    tickets = list(itsm.tickets.values())

    sla_data = []
    met = 0
    breached = 0
    at_risk = 0

    for ticket in tickets:
        status = itsm.get_sla_status(ticket)
        sla_data.append({
            "ticket_id": ticket.ticket_id,
            "title": ticket.title,
            "priority": ticket.priority.value,
            "sla_status": status
        })
        if status["status"] == "met":
            met += 1
        elif status["status"] == "breached":
            breached += 1
        elif status["status"] == "at_risk":
            at_risk += 1

    total = len(tickets)
    return {
        "total_tickets": total,
        "sla_met": met,
        "sla_breached": breached,
        "sla_at_risk": at_risk,
        "compliance_rate": round(met / total * 100, 1) if total > 0 else 100,
        "tickets": sla_data
    }
