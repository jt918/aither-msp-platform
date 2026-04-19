"""
Tests for ITSM (IT Service Management) Service
"""

import pytest
from datetime import datetime, timedelta

from services.msp.itsm import (
    ITSMService,
    TicketPriority,
    TicketStatus,
    TicketCategory,
    Ticket,
    SLAConfig
)


class TestITSMService:
    """Tests for ITSMService"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = ITSMService()

    # ========== Ticket Creation Tests ==========

    def test_create_ticket(self):
        """Test basic ticket creation"""
        ticket = self.service.create_ticket(
            title="Computer won't start",
            description="User's computer does not power on",
            category=TicketCategory.HARDWARE,
            priority=TicketPriority.P2_HIGH,
            customer_id="CUST-001",
            customer_name="Acme Corp"
        )

        assert ticket is not None
        assert ticket.ticket_id.startswith("TKT-")
        assert ticket.title == "Computer won't start"
        assert ticket.category == TicketCategory.HARDWARE
        assert ticket.priority == TicketPriority.P2_HIGH
        assert ticket.status == TicketStatus.NEW
        assert ticket.customer_id == "CUST-001"

    def test_create_ticket_generates_unique_id(self):
        """Test that each ticket gets unique ID"""
        ticket1 = self.service.create_ticket(
            title="Test 1",
            description="Desc 1",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        ticket2 = self.service.create_ticket(
            title="Test 2",
            description="Desc 2",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        assert ticket1.ticket_id != ticket2.ticket_id

    def test_create_ticket_sets_sla_deadline(self):
        """Test that SLA deadline is set based on priority"""
        ticket = self.service.create_ticket(
            title="Critical issue",
            description="System down",
            category=TicketCategory.NETWORK,
            priority=TicketPriority.P1_CRITICAL
        )

        assert ticket.sla_deadline is not None
        # P1 has 4 hour resolution time
        expected_deadline = ticket.created_at + timedelta(hours=4)
        # Allow 1 second tolerance
        assert abs((ticket.sla_deadline - expected_deadline).total_seconds()) < 1

    def test_create_auto_healed_ticket(self):
        """Test creating an auto-healed ticket"""
        ticket = self.service.create_ticket(
            title="Auto-resolved issue",
            description="Self-healing agent fixed this",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM,
            auto_healed=True
        )

        assert ticket.auto_healed is True

    def test_ticket_stored(self):
        """Test ticket is stored in service"""
        ticket = self.service.create_ticket(
            title="Test",
            description="Test",
            category=TicketCategory.OTHER,
            priority=TicketPriority.P4_LOW
        )

        assert ticket.ticket_id in self.service.tickets
        assert self.service.tickets[ticket.ticket_id] == ticket

    # ========== Ticket Update Tests ==========

    def test_update_ticket_status(self):
        """Test updating ticket status"""
        ticket = self.service.create_ticket(
            title="Test",
            description="Test",
            category=TicketCategory.EMAIL,
            priority=TicketPriority.P3_MEDIUM
        )

        updated = self.service.update_ticket(
            ticket.ticket_id,
            status=TicketStatus.IN_PROGRESS
        )

        assert updated is not None
        assert updated.status == TicketStatus.IN_PROGRESS

    def test_update_ticket_resolved_sets_timestamp(self):
        """Test resolving ticket sets resolved_at"""
        ticket = self.service.create_ticket(
            title="Test",
            description="Test",
            category=TicketCategory.PRINTER,
            priority=TicketPriority.P4_LOW
        )

        self.service.update_ticket(
            ticket.ticket_id,
            status=TicketStatus.RESOLVED
        )

        assert ticket.resolved_at is not None

    def test_update_ticket_assign(self):
        """Test assigning ticket to technician"""
        ticket = self.service.create_ticket(
            title="Test",
            description="Test",
            category=TicketCategory.ACCESS,
            priority=TicketPriority.P3_MEDIUM
        )

        self.service.update_ticket(
            ticket.ticket_id,
            assigned_to="Tech-1"
        )

        assert ticket.assigned_to == "Tech-1"
        assert ticket.status == TicketStatus.ASSIGNED

    def test_update_ticket_add_note(self):
        """Test adding note to ticket"""
        ticket = self.service.create_ticket(
            title="Test",
            description="Test",
            category=TicketCategory.SECURITY,
            priority=TicketPriority.P2_HIGH
        )

        self.service.update_ticket(
            ticket.ticket_id,
            note="Initial investigation complete"
        )

        assert len(ticket.notes) == 1
        assert ticket.notes[0]["note"] == "Initial investigation complete"

    def test_update_nonexistent_ticket(self):
        """Test updating nonexistent ticket returns None"""
        result = self.service.update_ticket(
            "INVALID-ID",
            status=TicketStatus.CLOSED
        )

        assert result is None

    # ========== Ticket Retrieval Tests ==========

    def test_get_ticket(self):
        """Test getting ticket by ID"""
        ticket = self.service.create_ticket(
            title="Test",
            description="Test",
            category=TicketCategory.HARDWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        retrieved = self.service.get_ticket(ticket.ticket_id)

        assert retrieved is not None
        assert retrieved.ticket_id == ticket.ticket_id

    def test_get_nonexistent_ticket(self):
        """Test getting nonexistent ticket returns None"""
        result = self.service.get_ticket("INVALID-ID")
        assert result is None

    def test_get_tickets_all(self):
        """Test getting all tickets"""
        self.service.create_ticket(
            title="Test 1",
            description="Desc",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        self.service.create_ticket(
            title="Test 2",
            description="Desc",
            category=TicketCategory.NETWORK,
            priority=TicketPriority.P2_HIGH
        )

        tickets = self.service.get_tickets()

        assert len(tickets) == 2

    def test_get_tickets_by_status(self):
        """Test filtering tickets by status"""
        t1 = self.service.create_ticket(
            title="Open",
            description="Desc",
            category=TicketCategory.OTHER,
            priority=TicketPriority.P4_LOW
        )

        t2 = self.service.create_ticket(
            title="Resolved",
            description="Desc",
            category=TicketCategory.OTHER,
            priority=TicketPriority.P4_LOW
        )

        self.service.update_ticket(t2.ticket_id, status=TicketStatus.RESOLVED)

        new_tickets = self.service.get_tickets(status=TicketStatus.NEW)
        resolved_tickets = self.service.get_tickets(status=TicketStatus.RESOLVED)

        assert len(new_tickets) == 1
        assert len(resolved_tickets) == 1

    def test_get_tickets_by_priority(self):
        """Test filtering tickets by priority"""
        self.service.create_ticket(
            title="Critical",
            description="Desc",
            category=TicketCategory.NETWORK,
            priority=TicketPriority.P1_CRITICAL
        )

        self.service.create_ticket(
            title="Low",
            description="Desc",
            category=TicketCategory.OTHER,
            priority=TicketPriority.P4_LOW
        )

        critical = self.service.get_tickets(priority=TicketPriority.P1_CRITICAL)

        assert len(critical) == 1
        assert critical[0].priority == TicketPriority.P1_CRITICAL

    def test_get_tickets_by_assigned(self):
        """Test filtering tickets by assigned technician"""
        t1 = self.service.create_ticket(
            title="Test 1",
            description="Desc",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        self.service.update_ticket(t1.ticket_id, assigned_to="Tech-1")

        self.service.create_ticket(
            title="Unassigned",
            description="Desc",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        tech1_tickets = self.service.get_tickets(assigned_to="Tech-1")

        assert len(tech1_tickets) == 1

    def test_tickets_sorted_by_priority(self):
        """Test tickets are sorted by priority"""
        self.service.create_ticket(
            title="Low",
            description="Desc",
            category=TicketCategory.OTHER,
            priority=TicketPriority.P4_LOW
        )

        self.service.create_ticket(
            title="Critical",
            description="Desc",
            category=TicketCategory.NETWORK,
            priority=TicketPriority.P1_CRITICAL
        )

        tickets = self.service.get_tickets()

        assert tickets[0].priority == TicketPriority.P1_CRITICAL
        assert tickets[1].priority == TicketPriority.P4_LOW

    # ========== SLA Tests ==========

    def test_sla_on_track(self):
        """Test SLA status when on track"""
        ticket = self.service.create_ticket(
            title="Test",
            description="Desc",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM  # 24 hour SLA
        )

        sla_status = self.service.get_sla_status(ticket)

        assert sla_status["status"] == "on_track"

    def test_sla_met(self):
        """Test SLA status when resolved in time"""
        ticket = self.service.create_ticket(
            title="Test",
            description="Desc",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        self.service.update_ticket(ticket.ticket_id, status=TicketStatus.RESOLVED)

        sla_status = self.service.get_sla_status(ticket)

        assert sla_status["status"] == "met"

    def test_sla_no_config(self):
        """Test SLA status when no deadline set"""
        ticket = Ticket(
            ticket_id="TEST-001",
            title="No SLA",
            description="Test",
            category=TicketCategory.OTHER,
            priority=TicketPriority.P4_LOW,
            sla_deadline=None
        )

        sla_status = self.service.get_sla_status(ticket)

        assert sla_status["status"] == "no_sla"

    # ========== Dashboard Tests ==========

    def test_dashboard_metrics_empty(self):
        """Test dashboard metrics with no tickets"""
        metrics = self.service.get_dashboard_metrics()

        assert metrics["total_tickets"] == 0
        assert metrics["open_tickets"] == 0
        assert metrics["resolved_today"] == 0
        assert metrics["avg_resolution_hours"] == 0

    def test_dashboard_metrics_with_tickets(self):
        """Test dashboard metrics with tickets"""
        self.service.create_ticket(
            title="Open 1",
            description="Desc",
            category=TicketCategory.HARDWARE,
            priority=TicketPriority.P2_HIGH
        )

        t2 = self.service.create_ticket(
            title="Resolved",
            description="Desc",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        self.service.update_ticket(t2.ticket_id, status=TicketStatus.RESOLVED)

        metrics = self.service.get_dashboard_metrics()

        assert metrics["total_tickets"] == 2
        assert metrics["open_tickets"] == 1
        assert metrics["resolved_today"] == 1

    def test_dashboard_priority_breakdown(self):
        """Test dashboard priority breakdown"""
        self.service.create_ticket(
            title="Critical",
            description="Desc",
            category=TicketCategory.NETWORK,
            priority=TicketPriority.P1_CRITICAL
        )

        self.service.create_ticket(
            title="High",
            description="Desc",
            category=TicketCategory.SECURITY,
            priority=TicketPriority.P2_HIGH
        )

        metrics = self.service.get_dashboard_metrics()

        assert metrics["by_priority"]["P1"] == 1
        assert metrics["by_priority"]["P2"] == 1
        assert metrics["by_priority"]["P3"] == 0

    def test_dashboard_category_breakdown(self):
        """Test dashboard category breakdown"""
        self.service.create_ticket(
            title="Hardware issue",
            description="Desc",
            category=TicketCategory.HARDWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        metrics = self.service.get_dashboard_metrics()

        assert metrics["by_category"]["hardware"] == 1

    def test_dashboard_technician_load(self):
        """Test dashboard technician load"""
        t1 = self.service.create_ticket(
            title="Test 1",
            description="Desc",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM
        )

        self.service.update_ticket(t1.ticket_id, assigned_to="Tech-1")

        metrics = self.service.get_dashboard_metrics()

        assert metrics["technician_load"]["Tech-1"] == 1
        assert metrics["technician_load"]["Tech-2"] == 0

    def test_dashboard_auto_healed_count(self):
        """Test dashboard auto-healed count"""
        self.service.create_ticket(
            title="Auto fixed",
            description="Desc",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P3_MEDIUM,
            auto_healed=True
        )

        metrics = self.service.get_dashboard_metrics()

        assert metrics["auto_healed"] == 1

    # ========== ROI Calculation Tests ==========

    def test_calculate_roi(self):
        """Test ROI calculation"""
        roi = self.service.calculate_roi(
            auto_healed_count=100,
            avg_ticket_cost=75.0,
            avg_resolution_minutes=45
        )

        assert roi["auto_healed_count"] == 100
        assert roi["cost_savings"] == 7500.0  # 100 * 75
        assert roi["time_savings_hours"] == 75.0  # (100 * 45) / 60
        assert roi["monthly_projection"]["savings"] == 30000.0  # 100 * 4 * 75
        assert roi["annual_projection"]["savings"] == 360000.0  # Monthly * 12

    def test_calculate_roi_zero(self):
        """Test ROI calculation with zero auto-healed"""
        roi = self.service.calculate_roi(auto_healed_count=0)

        assert roi["cost_savings"] == 0
        assert roi["time_savings_hours"] == 0


class TestTicket:
    """Tests for Ticket dataclass"""

    def test_ticket_creation(self):
        """Test Ticket creation"""
        ticket = Ticket(
            ticket_id="TKT-001",
            title="Test Ticket",
            description="Test description",
            category=TicketCategory.SOFTWARE,
            priority=TicketPriority.P2_HIGH
        )

        assert ticket.ticket_id == "TKT-001"
        assert ticket.status == TicketStatus.NEW
        assert ticket.assigned_to is None
        assert ticket.resolved_at is None
        assert ticket.auto_healed is False

    def test_ticket_notes_default(self):
        """Test ticket notes default to empty list"""
        ticket = Ticket(
            ticket_id="TKT-002",
            title="Test",
            description="Desc",
            category=TicketCategory.OTHER,
            priority=TicketPriority.P4_LOW
        )

        assert ticket.notes == []


class TestSLAConfig:
    """Tests for SLAConfig dataclass"""

    def test_sla_config_creation(self):
        """Test SLAConfig creation"""
        config = SLAConfig(
            priority=TicketPriority.P1_CRITICAL,
            response_time_minutes=15,
            resolution_time_hours=4
        )

        assert config.priority == TicketPriority.P1_CRITICAL
        assert config.response_time_minutes == 15
        assert config.resolution_time_hours == 4


class TestEnums:
    """Tests for ITSM enums"""

    def test_ticket_priority_values(self):
        """Test TicketPriority enum values"""
        assert TicketPriority.P1_CRITICAL.value == "P1"
        assert TicketPriority.P2_HIGH.value == "P2"
        assert TicketPriority.P3_MEDIUM.value == "P3"
        assert TicketPriority.P4_LOW.value == "P4"

    def test_ticket_status_values(self):
        """Test TicketStatus enum values"""
        assert TicketStatus.NEW.value == "new"
        assert TicketStatus.ASSIGNED.value == "assigned"
        assert TicketStatus.IN_PROGRESS.value == "in_progress"
        assert TicketStatus.PENDING_CUSTOMER.value == "pending_customer"
        assert TicketStatus.RESOLVED.value == "resolved"
        assert TicketStatus.CLOSED.value == "closed"

    def test_ticket_category_values(self):
        """Test TicketCategory enum values"""
        assert TicketCategory.HARDWARE.value == "hardware"
        assert TicketCategory.SOFTWARE.value == "software"
        assert TicketCategory.NETWORK.value == "network"
        assert TicketCategory.SECURITY.value == "security"
        assert TicketCategory.EMAIL.value == "email"
        assert TicketCategory.PRINTER.value == "printer"
        assert TicketCategory.ACCESS.value == "access"
        assert TicketCategory.OTHER.value == "other"


class TestSLAConfigs:
    """Tests for SLA configurations"""

    def test_sla_configs_exist(self):
        """Test SLA configs are defined"""
        service = ITSMService()

        assert TicketPriority.P1_CRITICAL in service.SLA_CONFIGS
        assert TicketPriority.P2_HIGH in service.SLA_CONFIGS
        assert TicketPriority.P3_MEDIUM in service.SLA_CONFIGS
        assert TicketPriority.P4_LOW in service.SLA_CONFIGS

    def test_p1_sla_config(self):
        """Test P1 SLA configuration"""
        service = ITSMService()
        config = service.SLA_CONFIGS[TicketPriority.P1_CRITICAL]

        assert config.response_time_minutes == 15
        assert config.resolution_time_hours == 4

    def test_p2_sla_config(self):
        """Test P2 SLA configuration"""
        service = ITSMService()
        config = service.SLA_CONFIGS[TicketPriority.P2_HIGH]

        assert config.response_time_minutes == 30
        assert config.resolution_time_hours == 8

    def test_p3_sla_config(self):
        """Test P3 SLA configuration"""
        service = ITSMService()
        config = service.SLA_CONFIGS[TicketPriority.P3_MEDIUM]

        assert config.response_time_minutes == 120
        assert config.resolution_time_hours == 24

    def test_p4_sla_config(self):
        """Test P4 SLA configuration"""
        service = ITSMService()
        config = service.SLA_CONFIGS[TicketPriority.P4_LOW]

        assert config.response_time_minutes == 480
        assert config.resolution_time_hours == 72


class TestITSMInitialization:
    """Tests for ITSM initialization"""

    def test_initialization(self):
        """Test ITSMService initializes correctly"""
        service = ITSMService()

        assert service.tickets is not None
        assert len(service.tickets) == 0
        assert len(service.technicians) == 3

    def test_technicians_list(self):
        """Test default technicians"""
        service = ITSMService()

        assert "Tech-1" in service.technicians
        assert "Tech-2" in service.technicians
        assert "Tech-3" in service.technicians
