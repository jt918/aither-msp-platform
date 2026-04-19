"""
MSP Device & Ticket Manager

Manages IT devices and support tickets for managed services customers.
Tracks health scores, patch status, and software inventory.
"""

from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime
import logging

from models.managed_services import (
    ManagedDevice, ITTicket, DeviceStatus, TicketStatus, TicketPriority,
)

logger = logging.getLogger(__name__)

# SLA targets by priority (hours)
SLA_TARGETS = {
    TicketPriority.CRITICAL.value: 4,
    TicketPriority.HIGH.value: 8,
    TicketPriority.MEDIUM.value: 24,
    TicketPriority.LOW.value: 72,
}


class DeviceManager:
    """
    Manages customer IT devices and support tickets.
    """

    def __init__(self, db: Session):
        self.db = db
        self._ticket_counter = None

    # ── Device Management ──────────────────────────────────────

    def register_device(
        self,
        customer_id: str,
        device_name: str,
        device_type: str = "workstation",
        os_type: str = None,
        os_version: str = None,
        ip_address: str = None,
        assigned_user: str = None,
        department: str = None,
        location: str = None,
    ) -> Dict:
        """Register a new device under managed services."""
        device = ManagedDevice(
            customer_id=customer_id,
            device_name=device_name,
            device_type=device_type,
            os_type=os_type,
            os_version=os_version,
            ip_address=ip_address,
            assigned_user=assigned_user,
            department=department,
            location=location,
            status=DeviceStatus.ONLINE.value,
            health_score=100,
            last_seen=datetime.utcnow(),
        )
        self.db.add(device)
        self.db.commit()

        return {"status": "registered", "device_id": device.id}

    def update_health(
        self,
        device_id: str,
        health_score: int = None,
        status: str = None,
        pending_patches: int = None,
        alerts: List[Dict] = None,
    ) -> Dict:
        """Update device health metrics."""
        device = self._get_device(device_id)
        if not device:
            return {"error": f"Device {device_id} not found"}

        if health_score is not None:
            device.health_score = max(0, min(100, health_score))
        if status:
            device.status = status
        if pending_patches is not None:
            device.pending_patches = pending_patches
        if alerts is not None:
            device.alerts = alerts

        device.last_seen = datetime.utcnow()
        self.db.commit()

        return {
            "device_id": device_id,
            "health_score": device.health_score,
            "status": device.status,
        }

    def get_customer_devices(self, customer_id: str) -> List[Dict]:
        """Get all devices for a customer."""
        devices = (
            self.db.query(ManagedDevice)
            .filter(ManagedDevice.customer_id == customer_id)
            .order_by(ManagedDevice.device_name)
            .all()
        )
        return [self._device_to_dict(d) for d in devices]

    def get_fleet_status(self, customer_id: str) -> Dict:
        """Get fleet-wide health and status summary."""
        devices = (
            self.db.query(ManagedDevice)
            .filter(ManagedDevice.customer_id == customer_id)
            .all()
        )

        if not devices:
            return {"total_devices": 0}

        status_counts = {}
        for s in DeviceStatus:
            status_counts[s.value] = sum(1 for d in devices if d.status == s.value)

        health_scores = [d.health_score or 0 for d in devices]
        total_patches = sum(d.pending_patches or 0 for d in devices)

        # Count total alerts across all devices
        total_alerts = sum(len(d.alerts or []) for d in devices)

        # Devices needing attention (health < 70 or offline)
        needs_attention = [
            d for d in devices
            if (d.health_score or 0) < 70 or d.status == DeviceStatus.OFFLINE.value
        ]

        return {
            "total_devices": len(devices),
            "status_breakdown": status_counts,
            "avg_health_score": round(sum(health_scores) / len(health_scores), 1),
            "min_health_score": min(health_scores),
            "total_pending_patches": total_patches,
            "total_active_alerts": total_alerts,
            "devices_needing_attention": len(needs_attention),
            "attention_list": [
                {"id": d.id, "name": d.device_name, "health": d.health_score, "status": d.status}
                for d in needs_attention[:10]
            ],
        }

    # ── Ticket Management ──────────────────────────────────────

    def create_ticket(
        self,
        customer_id: str,
        subject: str,
        description: str = None,
        category: str = "other",
        priority: str = TicketPriority.MEDIUM.value,
        device_id: str = None,
        reported_by: str = None,
        contact_email: str = None,
    ) -> Dict:
        """Create a new IT support ticket."""
        ticket_number = self._next_ticket_number()

        sla_hours = SLA_TARGETS.get(priority, 24)

        ticket = ITTicket(
            customer_id=customer_id,
            device_id=device_id,
            ticket_number=ticket_number,
            subject=subject,
            description=description,
            category=category,
            priority=priority,
            status=TicketStatus.OPEN.value,
            reported_by=reported_by,
            contact_email=contact_email,
            sla_target_hours=sla_hours,
        )
        self.db.add(ticket)
        self.db.commit()

        return {
            "status": "created",
            "ticket_id": ticket.id,
            "ticket_number": ticket_number,
            "sla_target_hours": sla_hours,
        }

    def assign_ticket(self, ticket_id: str, assigned_to: str) -> Dict:
        """Assign a ticket to a technician."""
        ticket = self._get_ticket(ticket_id)
        if not ticket:
            return {"error": f"Ticket {ticket_id} not found"}

        ticket.assigned_to = assigned_to
        if ticket.status == TicketStatus.OPEN.value:
            ticket.status = TicketStatus.IN_PROGRESS.value
        self.db.commit()

        return {
            "status": "assigned",
            "ticket_id": ticket_id,
            "assigned_to": assigned_to,
        }

    def resolve_ticket(self, ticket_id: str, resolution: str) -> Dict:
        """Resolve a ticket."""
        ticket = self._get_ticket(ticket_id)
        if not ticket:
            return {"error": f"Ticket {ticket_id} not found"}

        ticket.status = TicketStatus.RESOLVED.value
        ticket.resolution = resolution
        ticket.resolved_at = datetime.utcnow()

        # Check SLA breach
        if ticket.created_at and ticket.sla_target_hours:
            elapsed = (datetime.utcnow() - ticket.created_at).total_seconds() / 3600
            ticket.sla_breached = elapsed > ticket.sla_target_hours

        self.db.commit()

        return {
            "status": "resolved",
            "ticket_id": ticket_id,
            "ticket_number": ticket.ticket_number,
            "sla_breached": ticket.sla_breached,
        }

    def close_ticket(self, ticket_id: str) -> Dict:
        """Close a resolved ticket."""
        ticket = self._get_ticket(ticket_id)
        if not ticket:
            return {"error": f"Ticket {ticket_id} not found"}

        ticket.status = TicketStatus.CLOSED.value
        ticket.closed_at = datetime.utcnow()
        self.db.commit()

        return {"status": "closed", "ticket_id": ticket_id}

    def escalate_ticket(self, ticket_id: str, escalated_to: str) -> Dict:
        """Escalate a ticket to higher-tier support."""
        ticket = self._get_ticket(ticket_id)
        if not ticket:
            return {"error": f"Ticket {ticket_id} not found"}

        ticket.status = TicketStatus.ESCALATED.value
        ticket.escalated_to = escalated_to
        self.db.commit()

        return {
            "status": "escalated",
            "ticket_id": ticket_id,
            "escalated_to": escalated_to,
        }

    def get_customer_tickets(
        self,
        customer_id: str,
        status: str = None,
        limit: int = 50,
    ) -> List[Dict]:
        """Get tickets for a customer."""
        query = (
            self.db.query(ITTicket)
            .filter(ITTicket.customer_id == customer_id)
        )
        if status:
            query = query.filter(ITTicket.status == status)

        tickets = (
            query
            .order_by(ITTicket.created_at.desc())
            .limit(limit)
            .all()
        )
        return [self._ticket_to_dict(t) for t in tickets]

    def get_ticket_stats(self, customer_id: str) -> Dict:
        """Get ticket statistics for a customer."""
        tickets = (
            self.db.query(ITTicket)
            .filter(ITTicket.customer_id == customer_id)
            .all()
        )

        if not tickets:
            return {"total_tickets": 0}

        status_counts = {}
        for s in TicketStatus:
            status_counts[s.value] = sum(1 for t in tickets if t.status == s.value)

        priority_counts = {}
        for p in TicketPriority:
            priority_counts[p.value] = sum(1 for t in tickets if t.priority == p.value)

        open_tickets = [t for t in tickets if t.status in (
            TicketStatus.OPEN.value, TicketStatus.IN_PROGRESS.value, TicketStatus.ESCALATED.value
        )]

        resolved = [t for t in tickets if t.resolved_at and t.created_at]
        avg_resolution_hours = 0
        if resolved:
            total_hours = sum(
                (t.resolved_at - t.created_at).total_seconds() / 3600
                for t in resolved
            )
            avg_resolution_hours = round(total_hours / len(resolved), 1)

        sla_breached = sum(1 for t in tickets if t.sla_breached)

        return {
            "total_tickets": len(tickets),
            "open_tickets": len(open_tickets),
            "status_breakdown": status_counts,
            "priority_breakdown": priority_counts,
            "avg_resolution_hours": avg_resolution_hours,
            "sla_breached": sla_breached,
            "sla_compliance_pct": round(
                (1 - sla_breached / len(tickets)) * 100, 1
            ) if tickets else 100,
        }

    # ── Helpers ─────────────────────────────────────────────────

    def _get_device(self, device_id: str) -> Optional[ManagedDevice]:
        return (
            self.db.query(ManagedDevice)
            .filter(ManagedDevice.id == device_id)
            .first()
        )

    def _get_ticket(self, ticket_id: str) -> Optional[ITTicket]:
        return (
            self.db.query(ITTicket)
            .filter(ITTicket.id == ticket_id)
            .first()
        )

    def _next_ticket_number(self) -> str:
        """Generate next sequential ticket number."""
        max_ticket = (
            self.db.query(func.max(ITTicket.ticket_number))
            .scalar()
        )
        if max_ticket and max_ticket.startswith("TKT-"):
            try:
                num = int(max_ticket.split("-")[1]) + 1
            except (ValueError, IndexError):
                num = 1001
        else:
            num = 1001

        return f"TKT-{num:05d}"

    def _device_to_dict(self, d: ManagedDevice) -> Dict:
        return {
            "id": d.id,
            "device_name": d.device_name,
            "device_type": d.device_type,
            "hostname": d.hostname,
            "os_type": d.os_type,
            "os_version": d.os_version,
            "ip_address": d.ip_address,
            "assigned_user": d.assigned_user,
            "department": d.department,
            "status": d.status,
            "health_score": d.health_score,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "pending_patches": d.pending_patches,
            "alerts": d.alerts,
        }

    def _ticket_to_dict(self, t: ITTicket) -> Dict:
        return {
            "id": t.id,
            "ticket_number": t.ticket_number,
            "subject": t.subject,
            "description": t.description,
            "category": t.category,
            "priority": t.priority,
            "status": t.status,
            "assigned_to": t.assigned_to,
            "reported_by": t.reported_by,
            "resolution": t.resolution,
            "sla_breached": t.sla_breached,
            "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        }
