"""
Tests for PSA (Professional Services Automation) Connector Service
"""

import pytest
from datetime import datetime

from services.integrations.psa_connector import (
    PSAConnectorService,
    PSAConnection,
    SyncMapping,
    SyncLog,
    CompanySync,
    TicketSync,
    PSAType,
    SyncDirection,
    SyncStatus,
    ConflictStrategy,
    CW_PRIORITY_MAP,
    CW_STATUS_MAP,
)


class TestPSAConnectorService:
    """Tests for PSAConnectorService"""

    def setup_method(self):
        """Set up test fixtures"""
        self.svc = PSAConnectorService()

    # ========== Connection Lifecycle ==========

    def test_create_connection(self):
        """Test creating a PSA connection"""
        conn = self.svc.create_connection(
            psa_type="connectwise",
            company_id="aither_test",
            api_url="https://na.myconnectwise.net/v4_6_release/apis/3.0/",
            client_id="test-client-id",
            public_key="test-pub-key",
            private_key_ref="vault://psa/cw/private",
        )

        assert conn is not None
        assert conn.connection_id.startswith("PSA-")
        assert conn.psa_type == "connectwise"
        assert conn.company_id == "aither_test"
        assert conn.api_url == "https://na.myconnectwise.net/v4_6_release/apis/3.0/"
        assert conn.client_id == "test-client-id"
        assert conn.is_connected is False
        assert conn.sync_status == "never"

    def test_get_connection(self):
        """Test retrieving a connection by ID"""
        conn = self.svc.create_connection(
            psa_type="connectwise",
            company_id="test_co",
            api_url="https://na.myconnectwise.net/",
        )
        fetched = self.svc.get_connection(conn.connection_id)
        assert fetched is not None
        assert fetched.connection_id == conn.connection_id

    def test_get_connection_not_found(self):
        """Test retrieving a nonexistent connection"""
        assert self.svc.get_connection("NOPE") is None

    def test_update_connection(self):
        """Test updating a PSA connection"""
        conn = self.svc.create_connection(
            psa_type="connectwise",
            company_id="test_co",
            api_url="https://example.com/api/",
        )
        updated = self.svc.update_connection(
            conn.connection_id,
            api_url="https://new-url.com/api/",
            is_connected=True,
        )
        assert updated is not None
        assert updated.api_url == "https://new-url.com/api/"
        assert updated.is_connected is True

    def test_update_connection_not_found(self):
        """Test updating a nonexistent connection"""
        assert self.svc.update_connection("NOPE", api_url="x") is None

    def test_delete_connection(self):
        """Test deleting a PSA connection"""
        conn = self.svc.create_connection(
            psa_type="connectwise",
            company_id="del_co",
            api_url="https://example.com/",
        )
        assert self.svc.delete_connection(conn.connection_id) is True
        assert self.svc.get_connection(conn.connection_id) is None

    def test_delete_connection_not_found(self):
        """Test deleting a nonexistent connection"""
        assert self.svc.delete_connection("NOPE") is False

    def test_list_connections(self):
        """Test listing connections with optional type filter"""
        self.svc.create_connection(psa_type="connectwise", company_id="co1", api_url="https://a.com/")
        self.svc.create_connection(psa_type="autotask", company_id="co2", api_url="https://b.com/")
        self.svc.create_connection(psa_type="connectwise", company_id="co3", api_url="https://c.com/")

        all_conns = self.svc.list_connections()
        assert len(all_conns) == 3

        cw_only = self.svc.list_connections(psa_type="connectwise")
        assert len(cw_only) == 2

    def test_test_connection_success(self):
        """Test connection test with valid credentials"""
        conn = self.svc.create_connection(
            psa_type="connectwise",
            company_id="test_co",
            api_url="https://na.myconnectwise.net/",
            client_id="cid",
            public_key="pub",
            private_key_ref="priv",
        )
        result = self.svc.test_connection(conn.connection_id)
        assert result["success"] is True
        assert result["psa_type"] == "connectwise"
        assert "api_version" in result

    def test_test_connection_missing_creds(self):
        """Test connection test with missing credentials"""
        conn = self.svc.create_connection(
            psa_type="connectwise",
            company_id="test_co",
            api_url="https://na.myconnectwise.net/",
        )
        result = self.svc.test_connection(conn.connection_id)
        assert result["success"] is False
        assert "Missing credentials" in result["error"]

    def test_test_connection_not_found(self):
        """Test connection test for nonexistent connection"""
        result = self.svc.test_connection("NOPE")
        assert result["success"] is False

    # ========== Mapping CRUD ==========

    def test_create_mapping(self):
        """Test creating a sync mapping"""
        conn = self.svc.create_connection(
            psa_type="connectwise", company_id="co", api_url="https://a.com/"
        )
        mapping = self.svc.create_mapping(
            connection_id=conn.connection_id,
            local_entity="ticket",
            remote_entity="service/tickets",
            field_mappings={"title": "summary", "description": "initialDescription"},
            sync_direction="bidirectional",
        )

        assert mapping is not None
        assert mapping.mapping_id.startswith("MAP-")
        assert mapping.local_entity == "ticket"
        assert mapping.remote_entity == "service/tickets"
        assert mapping.field_mappings["title"] == "summary"

    def test_create_mapping_invalid_connection(self):
        """Test creating a mapping for a nonexistent connection"""
        mapping = self.svc.create_mapping(
            connection_id="NOPE",
            local_entity="ticket",
            remote_entity="service/tickets",
        )
        assert mapping is None

    def test_update_mapping(self):
        """Test updating a sync mapping"""
        conn = self.svc.create_connection(
            psa_type="connectwise", company_id="co", api_url="https://a.com/"
        )
        mapping = self.svc.create_mapping(
            connection_id=conn.connection_id,
            local_entity="ticket",
            remote_entity="service/tickets",
        )
        updated = self.svc.update_mapping(
            mapping.mapping_id,
            sync_direction="push",
            is_enabled=False,
        )
        assert updated is not None
        assert updated.sync_direction == "push"
        assert updated.is_enabled is False

    def test_list_mappings(self):
        """Test listing mappings with optional connection filter"""
        conn1 = self.svc.create_connection(psa_type="connectwise", company_id="co1", api_url="https://a.com/")
        conn2 = self.svc.create_connection(psa_type="autotask", company_id="co2", api_url="https://b.com/")

        self.svc.create_mapping(connection_id=conn1.connection_id, local_entity="ticket", remote_entity="tickets")
        self.svc.create_mapping(connection_id=conn1.connection_id, local_entity="company", remote_entity="companies")
        self.svc.create_mapping(connection_id=conn2.connection_id, local_entity="ticket", remote_entity="tickets")

        all_mappings = self.svc.list_mappings()
        assert len(all_mappings) == 3

        conn1_mappings = self.svc.list_mappings(connection_id=conn1.connection_id)
        assert len(conn1_mappings) == 2

    # ========== ConnectWise Ticket Payload ==========

    def test_cw_build_ticket_payload(self):
        """Test building a ConnectWise ticket payload from ITSM ticket"""
        itsm_ticket = {
            "ticket_id": "TKT-001",
            "title": "Server down",
            "description": "Production server unresponsive",
            "priority": "P1",
            "status": "new",
            "category": "hardware",
            "customer_name": "John Doe",
            "cw_board_id": 5,
            "cw_company_id": 42,
            "assigned_to": "tech1",
        }

        payload = self.svc.cw_build_ticket_payload(itsm_ticket)

        assert payload["summary"] == "Server down"
        assert payload["initialDescription"] == "Production server unresponsive"
        assert payload["priority"]["id"] == 1
        assert payload["priority"]["name"] == "Priority 1 - Emergency"
        assert payload["status"]["id"] == 1
        assert payload["status"]["name"] == "New"
        assert payload["company"]["id"] == 42
        assert payload["board"]["id"] == 5
        assert payload["contactName"] == "John Doe"
        assert payload["owner"]["identifier"] == "tech1"
        assert payload["type"]["name"] == "hardware"

    def test_cw_build_ticket_payload_defaults(self):
        """Test building a ConnectWise ticket payload with minimal data"""
        payload = self.svc.cw_build_ticket_payload({})
        assert payload["summary"] == "Untitled Ticket"
        assert payload["priority"]["id"] == 3  # default P3

    def test_cw_parse_ticket(self):
        """Test parsing a ConnectWise ticket JSON into ITSM dict"""
        cw_json = {
            "id": 12345,
            "summary": "Printer not working",
            "initialDescription": "Printer on 3rd floor jammed",
            "priority": {"id": 2, "name": "Priority 2 - High"},
            "status": {"id": 3, "name": "In Progress"},
            "type": {"name": "hardware"},
            "company": {"id": 10, "name": "Acme Corp"},
            "board": {"id": 1},
            "contactName": "Jane Smith",
            "owner": {"identifier": "tech2"},
            "_info": {"lastUpdated": "2026-04-19T10:00:00Z"},
        }

        parsed = self.svc.cw_parse_ticket(cw_json)

        assert parsed["remote_ticket_id"] == "12345"
        assert parsed["title"] == "Printer not working"
        assert parsed["priority"] == "P2"
        assert parsed["status"] == "in_progress"
        assert parsed["category"] == "hardware"
        assert parsed["company_name"] == "Acme Corp"
        assert parsed["assigned_to"] == "tech2"

    # ========== Priority / Status Mapping ==========

    def test_cw_map_priority(self):
        """Test priority mapping"""
        assert self.svc.cw_map_priority("P1")["id"] == 1
        assert self.svc.cw_map_priority("critical")["id"] == 1
        assert self.svc.cw_map_priority("P4")["id"] == 4
        assert self.svc.cw_map_priority("low")["id"] == 4
        # Unknown priority falls back to P3
        assert self.svc.cw_map_priority("unknown")["id"] == 3

    def test_cw_map_status(self):
        """Test status mapping"""
        assert self.svc.cw_map_status("new")["name"] == "New"
        assert self.svc.cw_map_status("in_progress")["name"] == "In Progress"
        assert self.svc.cw_map_status("pending_customer")["name"] == "Waiting on Client"
        assert self.svc.cw_map_status("closed")["name"] == "Closed"
        # Unknown status falls back to New
        assert self.svc.cw_map_status("unknown")["name"] == "New"

    # ========== Sync Operations ==========

    def test_full_sync(self):
        """Test full sync execution"""
        conn = self.svc.create_connection(
            psa_type="connectwise",
            company_id="test_co",
            api_url="https://na.myconnectwise.net/",
            client_id="cid",
            public_key="pub",
            private_key_ref="priv",
        )
        result = self.svc.full_sync(conn.connection_id)

        assert result["status"] == "completed"
        assert result["psa_type"] == "connectwise"
        assert "results" in result
        assert "companies" in result["results"]
        assert "tickets_pull" in result["results"]

        # Connection should now show completed
        updated = self.svc.get_connection(conn.connection_id)
        assert updated.sync_status == SyncStatus.COMPLETED
        assert updated.last_sync_at is not None

    def test_incremental_sync(self):
        """Test incremental sync execution"""
        conn = self.svc.create_connection(
            psa_type="connectwise",
            company_id="test_co",
            api_url="https://na.myconnectwise.net/",
        )
        result = self.svc.incremental_sync(conn.connection_id)

        assert result["status"] == "completed"
        assert "sync_since" in result

    def test_full_sync_not_found(self):
        """Test full sync for nonexistent connection"""
        result = self.svc.full_sync("NOPE")
        assert "error" in result

    def test_cw_sync_companies(self):
        """Test company sync"""
        conn = self.svc.create_connection(
            psa_type="connectwise", company_id="co", api_url="https://a.com/"
        )
        result = self.svc.cw_sync_companies(conn.connection_id)
        assert result["status"] == "completed"
        assert result["sync_type"] == "companies"

    def test_cw_sync_tickets_push(self):
        """Test pushing tickets to ConnectWise"""
        conn = self.svc.create_connection(
            psa_type="connectwise", company_id="co", api_url="https://a.com/"
        )
        tickets = [
            {"ticket_id": "TKT-001", "title": "Test ticket 1", "priority": "P2", "status": "new"},
            {"ticket_id": "TKT-002", "title": "Test ticket 2", "priority": "P3", "status": "assigned"},
        ]
        result = self.svc.cw_sync_tickets_push(conn.connection_id, tickets=tickets)
        assert result["status"] == "completed"
        assert result["pushed"] == 2
        assert len(result["errors"]) == 0

    def test_cw_sync_tickets_pull(self):
        """Test pulling tickets from ConnectWise"""
        conn = self.svc.create_connection(
            psa_type="connectwise", company_id="co", api_url="https://a.com/"
        )
        result = self.svc.cw_sync_tickets_pull(conn.connection_id)
        assert result["status"] == "completed"
        assert "conditions_query" in result

    # ========== Sync Log ==========

    def test_get_sync_log(self):
        """Test sync log retrieval"""
        conn = self.svc.create_connection(
            psa_type="connectwise", company_id="co", api_url="https://a.com/"
        )
        # Trigger some syncs to generate logs
        self.svc.cw_sync_companies(conn.connection_id)
        self.svc.cw_sync_tickets_pull(conn.connection_id)

        logs = self.svc.get_sync_log(conn.connection_id)
        assert len(logs) >= 2
        assert logs[0]["sync_type"] in ("companies", "tickets_pull")
        assert "started_at" in logs[0]
        assert "completed_at" in logs[0]

    # ========== Conflict Resolution ==========

    def test_resolve_conflict_local_wins(self):
        """Test conflict resolution with local_wins strategy"""
        result = self.svc.resolve_conflict(
            local={"title": "Local", "updated_at": "2026-04-19"},
            remote={"title": "Remote", "updated_at": "2026-04-18"},
            strategy="local_wins",
        )
        assert result["winner"] == "local"
        assert result["data"]["title"] == "Local"

    def test_resolve_conflict_remote_wins(self):
        """Test conflict resolution with remote_wins strategy"""
        result = self.svc.resolve_conflict(
            local={"title": "Local"},
            remote={"title": "Remote"},
            strategy="remote_wins",
        )
        assert result["winner"] == "remote"

    def test_resolve_conflict_newest_wins(self):
        """Test conflict resolution with newest_wins strategy"""
        result = self.svc.resolve_conflict(
            local={"title": "Local", "updated_at": "2026-04-18"},
            remote={"title": "Remote", "updated_at": "2026-04-19"},
            strategy="newest_wins",
        )
        assert result["winner"] == "remote"

    # ========== Dashboard ==========

    def test_get_dashboard(self):
        """Test dashboard stats"""
        self.svc.create_connection(psa_type="connectwise", company_id="co1", api_url="https://a.com/")
        self.svc.create_connection(psa_type="autotask", company_id="co2", api_url="https://b.com/")

        dashboard = self.svc.get_dashboard()

        assert dashboard["total_connections"] == 2
        assert dashboard["connected"] == 0
        assert dashboard["disconnected"] == 2
        assert "total_syncs_executed" in dashboard
        assert "total_errors" in dashboard
        assert "connections" in dashboard
        assert "by_psa_type" in dashboard

    def test_get_dashboard_empty(self):
        """Test dashboard with no connections"""
        dashboard = self.svc.get_dashboard()
        assert dashboard["total_connections"] == 0
        assert dashboard["connected"] == 0

    # ========== Delete cascade ==========

    def test_delete_connection_removes_mappings(self):
        """Test that deleting a connection also removes its mappings"""
        conn = self.svc.create_connection(
            psa_type="connectwise", company_id="co", api_url="https://a.com/"
        )
        self.svc.create_mapping(
            connection_id=conn.connection_id,
            local_entity="ticket",
            remote_entity="service/tickets",
        )
        self.svc.create_mapping(
            connection_id=conn.connection_id,
            local_entity="company",
            remote_entity="company/companies",
        )

        assert len(self.svc.list_mappings(connection_id=conn.connection_id)) == 2
        self.svc.delete_connection(conn.connection_id)
        assert len(self.svc.list_mappings(connection_id=conn.connection_id)) == 0
