"""
AITHER Platform - IT Service Management
MSP Dashboard and Ticket Management

G-46: Refactored for DB persistence with in-memory fallback.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import uuid
import logging

logger = logging.getLogger(__name__)

try:
    from sqlalchemy.orm import Session
    from models.msp import ITSMTicket as ITSMTicketModel
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None


class TicketPriority(Enum):
    P1_CRITICAL = "P1"
    P2_HIGH = "P2"
    P3_MEDIUM = "P3"
    P4_LOW = "P4"


class TicketStatus(Enum):
    NEW = "new"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    PENDING_CUSTOMER = "pending_customer"
    RESOLVED = "resolved"
    CLOSED = "closed"


class TicketCategory(Enum):
    HARDWARE = "hardware"
    SOFTWARE = "software"
    NETWORK = "network"
    SECURITY = "security"
    EMAIL = "email"
    PRINTER = "printer"
    ACCESS = "access"
    OTHER = "other"


@dataclass
class Ticket:
    """Support ticket"""
    ticket_id: str
    title: str
    description: str
    category: TicketCategory
    priority: TicketPriority
    status: TicketStatus = TicketStatus.NEW
    customer_id: str = ""
    customer_name: str = ""
    assigned_to: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None
    notes: List[Dict[str, Any]] = field(default_factory=list)
    auto_healed: bool = False


@dataclass
class SLAConfig:
    """SLA configuration by priority"""
    priority: TicketPriority
    response_time_minutes: int
    resolution_time_hours: int


def _ticket_from_row(row) -> Ticket:
    """Convert ITSMTicketModel to Ticket dataclass."""
    return Ticket(
        ticket_id=row.ticket_id,
        title=row.title,
        description=row.description or "",
        category=TicketCategory(row.category),
        priority=TicketPriority(row.priority),
        status=TicketStatus(row.status) if row.status else TicketStatus.NEW,
        customer_id=row.customer_id or "",
        customer_name=row.customer_name or "",
        assigned_to=row.assigned_to,
        created_at=row.created_at or datetime.utcnow(),
        updated_at=row.updated_at or datetime.utcnow(),
        resolved_at=row.resolved_at,
        sla_deadline=row.sla_deadline,
        notes=row.notes or [],
        auto_healed=row.auto_healed or False,
    )


class ITSMService:
    """
    IT Service Management System

    Manages tickets, SLAs, and provides dashboard metrics.
    Accepts optional db: Session for persistence.
    """

    # Default SLA configurations
    SLA_CONFIGS = {
        TicketPriority.P1_CRITICAL: SLAConfig(TicketPriority.P1_CRITICAL, 15, 4),
        TicketPriority.P2_HIGH: SLAConfig(TicketPriority.P2_HIGH, 30, 8),
        TicketPriority.P3_MEDIUM: SLAConfig(TicketPriority.P3_MEDIUM, 120, 24),
        TicketPriority.P4_LOW: SLAConfig(TicketPriority.P4_LOW, 480, 72),
    }

    def __init__(self, db: Session = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE
        self.tickets: Dict[str, Ticket] = {}
        self.technicians: List[str] = ["Tech-1", "Tech-2", "Tech-3"]

        # Hydrate from DB on init
        if self._use_db:
            try:
                rows = self.db.query(ITSMTicketModel).all()
                for row in rows:
                    t = _ticket_from_row(row)
                    self.tickets[t.ticket_id] = t
            except Exception as e:
                logger.error(f"DB error hydrating tickets: {e}")

    def _persist_ticket(self, ticket: Ticket) -> None:
        """Persist a ticket to the database."""
        if not self._use_db:
            return
        try:
            existing = self.db.query(ITSMTicketModel).filter(
                ITSMTicketModel.ticket_id == ticket.ticket_id
            ).first()
            if existing:
                existing.title = ticket.title
                existing.description = ticket.description
                existing.category = ticket.category.value
                existing.priority = ticket.priority.value
                existing.status = ticket.status.value
                existing.customer_id = ticket.customer_id
                existing.customer_name = ticket.customer_name
                existing.assigned_to = ticket.assigned_to
                existing.sla_deadline = ticket.sla_deadline
                existing.notes = ticket.notes
                existing.auto_healed = ticket.auto_healed
                existing.resolved_at = ticket.resolved_at
            else:
                row = ITSMTicketModel(
                    ticket_id=ticket.ticket_id,
                    title=ticket.title,
                    description=ticket.description,
                    category=ticket.category.value,
                    priority=ticket.priority.value,
                    status=ticket.status.value,
                    customer_id=ticket.customer_id,
                    customer_name=ticket.customer_name,
                    assigned_to=ticket.assigned_to,
                    sla_deadline=ticket.sla_deadline,
                    notes=ticket.notes,
                    auto_healed=ticket.auto_healed,
                    resolved_at=ticket.resolved_at,
                )
                self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting ticket: {e}")
            self.db.rollback()

    def create_ticket(
        self,
        title: str,
        description: str,
        category: TicketCategory,
        priority: TicketPriority,
        customer_id: str = "",
        customer_name: str = "",
        auto_healed: bool = False
    ) -> Ticket:
        """Create a new support ticket"""

        ticket_id = f"TKT-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        # Calculate SLA deadline
        sla = self.SLA_CONFIGS.get(priority)
        sla_deadline = None
        if sla:
            sla_deadline = datetime.utcnow() + timedelta(hours=sla.resolution_time_hours)

        ticket = Ticket(
            ticket_id=ticket_id,
            title=title,
            description=description,
            category=category,
            priority=priority,
            customer_id=customer_id,
            customer_name=customer_name,
            sla_deadline=sla_deadline,
            auto_healed=auto_healed
        )

        self.tickets[ticket_id] = ticket
        self._persist_ticket(ticket)
        return ticket

    def update_ticket(
        self,
        ticket_id: str,
        status: Optional[TicketStatus] = None,
        assigned_to: Optional[str] = None,
        note: Optional[str] = None
    ) -> Optional[Ticket]:
        """Update a ticket"""

        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return None

        ticket.updated_at = datetime.utcnow()

        if status:
            ticket.status = status
            if status == TicketStatus.RESOLVED:
                ticket.resolved_at = datetime.utcnow()

        if assigned_to:
            ticket.assigned_to = assigned_to
            if ticket.status == TicketStatus.NEW:
                ticket.status = TicketStatus.ASSIGNED

        if note:
            ticket.notes.append({
                "timestamp": datetime.utcnow().isoformat(),
                "note": note,
                "author": assigned_to or "system"
            })

        self._persist_ticket(ticket)
        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[Ticket]:
        """Get a ticket by ID"""
        if ticket_id in self.tickets:
            return self.tickets[ticket_id]
        if self._use_db:
            try:
                row = self.db.query(ITSMTicketModel).filter(
                    ITSMTicketModel.ticket_id == ticket_id
                ).first()
                if row:
                    t = _ticket_from_row(row)
                    self.tickets[ticket_id] = t
                    return t
            except Exception as e:
                logger.error(f"DB error getting ticket: {e}")
        return None

    def get_tickets(
        self,
        status: Optional[TicketStatus] = None,
        priority: Optional[TicketPriority] = None,
        assigned_to: Optional[str] = None,
        customer_id: Optional[str] = None
    ) -> List[Ticket]:
        """Get tickets with optional filters"""

        results = list(self.tickets.values())

        if status:
            results = [t for t in results if t.status == status]

        if priority:
            results = [t for t in results if t.priority == priority]

        if assigned_to:
            results = [t for t in results if t.assigned_to == assigned_to]

        if customer_id:
            results = [t for t in results if t.customer_id == customer_id]

        # Sort by priority then created date
        priority_order = {
            TicketPriority.P1_CRITICAL: 0,
            TicketPriority.P2_HIGH: 1,
            TicketPriority.P3_MEDIUM: 2,
            TicketPriority.P4_LOW: 3,
        }

        results.sort(key=lambda t: (priority_order.get(t.priority, 99), t.created_at))

        return results

    def get_sla_status(self, ticket: Ticket) -> Dict[str, Any]:
        """Check SLA status for a ticket"""

        if not ticket.sla_deadline:
            return {"status": "no_sla", "message": "No SLA configured"}

        now = datetime.utcnow()

        if ticket.status in [TicketStatus.RESOLVED, TicketStatus.CLOSED]:
            # Check if resolved within SLA
            resolved_at = ticket.resolved_at or now
            if resolved_at <= ticket.sla_deadline:
                return {
                    "status": "met",
                    "message": "SLA met",
                    "resolved_within": str(ticket.sla_deadline - resolved_at)
                }
            else:
                return {
                    "status": "breached",
                    "message": "SLA breached",
                    "overdue_by": str(resolved_at - ticket.sla_deadline)
                }

        # Ticket still open
        if now > ticket.sla_deadline:
            return {
                "status": "breached",
                "message": "SLA breached - overdue",
                "overdue_by": str(now - ticket.sla_deadline)
            }

        time_remaining = ticket.sla_deadline - now

        if time_remaining < timedelta(hours=1):
            return {
                "status": "at_risk",
                "message": "SLA at risk",
                "time_remaining": str(time_remaining)
            }

        return {
            "status": "on_track",
            "message": "On track",
            "time_remaining": str(time_remaining)
        }

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get metrics for the ITSM dashboard"""

        all_tickets = list(self.tickets.values())
        now = datetime.utcnow()

        # Status counts
        open_tickets = [t for t in all_tickets if t.status not in [TicketStatus.RESOLVED, TicketStatus.CLOSED]]
        resolved_today = [
            t for t in all_tickets
            if t.resolved_at and t.resolved_at.date() == now.date()
        ]

        # Priority breakdown
        by_priority = {}
        for priority in TicketPriority:
            by_priority[priority.value] = len([t for t in open_tickets if t.priority == priority])

        # Category breakdown
        by_category = {}
        for category in TicketCategory:
            by_category[category.value] = len([t for t in open_tickets if t.category == category])

        # SLA metrics
        sla_at_risk = 0
        sla_breached = 0
        for ticket in open_tickets:
            sla_status = self.get_sla_status(ticket)
            if sla_status["status"] == "at_risk":
                sla_at_risk += 1
            elif sla_status["status"] == "breached":
                sla_breached += 1

        # Auto-heal metrics
        auto_healed = len([t for t in all_tickets if t.auto_healed])

        # Average resolution time (for resolved tickets)
        resolution_times = []
        for ticket in all_tickets:
            if ticket.resolved_at:
                duration = (ticket.resolved_at - ticket.created_at).total_seconds() / 3600
                resolution_times.append(duration)

        avg_resolution_hours = sum(resolution_times) / len(resolution_times) if resolution_times else 0

        return {
            "total_tickets": len(all_tickets),
            "open_tickets": len(open_tickets),
            "resolved_today": len(resolved_today),
            "by_priority": by_priority,
            "by_category": by_category,
            "sla_at_risk": sla_at_risk,
            "sla_breached": sla_breached,
            "auto_healed": auto_healed,
            "avg_resolution_hours": round(avg_resolution_hours, 2),
            "technician_load": {
                tech: len([t for t in open_tickets if t.assigned_to == tech])
                for tech in self.technicians
            }
        }

    def calculate_roi(
        self,
        auto_healed_count: int,
        avg_ticket_cost: float = 75.0,
        avg_resolution_minutes: int = 45
    ) -> Dict[str, Any]:
        """Calculate ROI from automation"""

        cost_savings = auto_healed_count * avg_ticket_cost
        time_savings_hours = (auto_healed_count * avg_resolution_minutes) / 60

        # Estimate monthly projections
        monthly_tickets_estimate = auto_healed_count * 4  # Assuming weekly data
        monthly_savings = monthly_tickets_estimate * avg_ticket_cost

        return {
            "auto_healed_count": auto_healed_count,
            "cost_savings": cost_savings,
            "time_savings_hours": round(time_savings_hours, 1),
            "monthly_projection": {
                "tickets": monthly_tickets_estimate,
                "savings": monthly_savings
            },
            "annual_projection": {
                "tickets": monthly_tickets_estimate * 12,
                "savings": monthly_savings * 12
            }
        }
