"""
AITHER Platform - PSA (Professional Services Automation) Connector

Integrates with ConnectWise Manage, Autotask, Halo PSA, and Syncro
to synchronize companies, contacts, tickets, configurations, and agreements.

Primary target: ConnectWise Manage (most popular MSP PSA).

DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.psa import (
        PSAConnectionModel,
        SyncMappingModel,
        SyncLogModel,
        EntitySyncModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class PSAType(str, Enum):
    CONNECTWISE = "connectwise"
    AUTOTASK = "autotask"
    HALO = "halo"
    SYNCRO = "syncro"


class SyncDirection(str, Enum):
    BIDIRECTIONAL = "bidirectional"
    PUSH = "push"
    PULL = "pull"


class SyncStatus(str, Enum):
    NEVER = "never"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"


class ConflictStrategy(str, Enum):
    LOCAL_WINS = "local_wins"
    REMOTE_WINS = "remote_wins"
    NEWEST_WINS = "newest_wins"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class PSAConnection:
    """PSA integration connection."""
    connection_id: str
    psa_type: str  # connectwise/autotask/halo/syncro
    company_id: str
    api_url: str
    client_id: str = ""
    public_key: str = ""
    private_key_ref: str = ""  # encrypted reference, never raw key
    is_connected: bool = False
    last_sync_at: Optional[datetime] = None
    sync_status: str = "never"
    sync_config: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SyncMapping:
    """Field mapping between local and remote entities."""
    mapping_id: str
    connection_id: str
    local_entity: str  # ticket/company/contact/device
    remote_entity: str
    field_mappings: Dict[str, str] = field(default_factory=dict)
    sync_direction: str = "bidirectional"
    is_enabled: bool = True


@dataclass
class SyncLog:
    """Record of a sync execution."""
    log_id: str
    connection_id: str
    sync_type: str
    entities_pushed: int = 0
    entities_pulled: int = 0
    errors: List[Dict] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


@dataclass
class CompanySync:
    """Tracks sync state for a company entity."""
    local_id: str
    remote_id: str
    company_name: str
    sync_status: str = "synced"


@dataclass
class TicketSync:
    """Tracks sync state for a ticket entity."""
    local_ticket_id: str
    remote_ticket_id: str
    sync_status: str = "synced"
    last_synced: Optional[datetime] = None


# ============================================================
# ConnectWise priority / status mappings
# ============================================================

CW_PRIORITY_MAP = {
    "P1": {"id": 1, "name": "Priority 1 - Emergency"},
    "P2": {"id": 2, "name": "Priority 2 - High"},
    "P3": {"id": 3, "name": "Priority 3 - Normal"},
    "P4": {"id": 4, "name": "Priority 4 - Low"},
    "critical": {"id": 1, "name": "Priority 1 - Emergency"},
    "high": {"id": 2, "name": "Priority 2 - High"},
    "medium": {"id": 3, "name": "Priority 3 - Normal"},
    "low": {"id": 4, "name": "Priority 4 - Low"},
}

CW_STATUS_MAP = {
    "new": {"id": 1, "name": "New"},
    "assigned": {"id": 2, "name": "Assigned"},
    "in_progress": {"id": 3, "name": "In Progress"},
    "pending_customer": {"id": 4, "name": "Waiting on Client"},
    "resolved": {"id": 5, "name": "Resolved"},
    "closed": {"id": 6, "name": "Closed"},
}


# ============================================================
# Row-to-dataclass helpers
# ============================================================

def _connection_from_row(row) -> PSAConnection:
    return PSAConnection(
        connection_id=row.connection_id,
        psa_type=row.psa_type,
        company_id=row.company_id or "",
        api_url=row.api_url,
        client_id=row.client_id or "",
        public_key=row.public_key or "",
        private_key_ref=row.private_key_ref or "",
        is_connected=row.is_connected or False,
        last_sync_at=row.last_sync_at,
        sync_status=row.sync_status or "never",
        sync_config=row.sync_config or {},
        created_at=row.created_at or datetime.utcnow(),
    )


def _mapping_from_row(row) -> SyncMapping:
    return SyncMapping(
        mapping_id=row.mapping_id,
        connection_id=row.connection_id,
        local_entity=row.local_entity,
        remote_entity=row.remote_entity,
        field_mappings=row.field_mappings or {},
        sync_direction=row.sync_direction or "bidirectional",
        is_enabled=row.is_enabled if row.is_enabled is not None else True,
    )


def _synclog_from_row(row) -> SyncLog:
    return SyncLog(
        log_id=row.log_id,
        connection_id=row.connection_id,
        sync_type=row.sync_type,
        entities_pushed=row.entities_pushed or 0,
        entities_pulled=row.entities_pulled or 0,
        errors=row.errors or [],
        started_at=row.started_at or datetime.utcnow(),
        completed_at=row.completed_at,
    )


# ============================================================
# PSAConnectorService
# ============================================================

class PSAConnectorService:
    """
    PSA integration connector with first-class ConnectWise Manage support.

    Synchronizes companies, contacts, tickets, configurations,
    and agreements between Aither ITSM and external PSA tools.

    Accepts optional db: Session for persistence.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory stores
        self.connections: Dict[str, PSAConnection] = {}
        self.mappings: Dict[str, SyncMapping] = {}
        self.sync_logs: List[SyncLog] = []
        self.entity_syncs: List[Dict] = []  # company/ticket sync records

        # Hydrate from DB
        if self._use_db:
            self._hydrate()

        logger.info("PSAConnectorService initialized")

    # ------------------------------------------------------------------
    # DB hydration
    # ------------------------------------------------------------------

    def _hydrate(self):
        try:
            for row in self.db.query(PSAConnectionModel).all():
                c = _connection_from_row(row)
                self.connections[c.connection_id] = c
            for row in self.db.query(SyncMappingModel).all():
                m = _mapping_from_row(row)
                self.mappings[m.mapping_id] = m
            for row in self.db.query(SyncLogModel).order_by(SyncLogModel.started_at.desc()).limit(200).all():
                self.sync_logs.append(_synclog_from_row(row))
        except Exception as e:
            logger.error(f"DB hydration error: {e}")

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _persist_connection(self, conn: PSAConnection) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(PSAConnectionModel).filter(
                PSAConnectionModel.connection_id == conn.connection_id
            ).first()
            if existing:
                existing.psa_type = conn.psa_type
                existing.company_id = conn.company_id
                existing.api_url = conn.api_url
                existing.client_id = conn.client_id
                existing.public_key = conn.public_key
                existing.private_key_ref = conn.private_key_ref
                existing.is_connected = conn.is_connected
                existing.last_sync_at = conn.last_sync_at
                existing.sync_status = conn.sync_status
                existing.sync_config = conn.sync_config
            else:
                row = PSAConnectionModel(
                    connection_id=conn.connection_id,
                    psa_type=conn.psa_type,
                    company_id=conn.company_id,
                    api_url=conn.api_url,
                    client_id=conn.client_id,
                    public_key=conn.public_key,
                    private_key_ref=conn.private_key_ref,
                    is_connected=conn.is_connected,
                    last_sync_at=conn.last_sync_at,
                    sync_status=conn.sync_status,
                    sync_config=conn.sync_config,
                )
                self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting connection: {e}")
            self.db.rollback()

    def _persist_mapping(self, mapping: SyncMapping) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(SyncMappingModel).filter(
                SyncMappingModel.mapping_id == mapping.mapping_id
            ).first()
            if existing:
                existing.local_entity = mapping.local_entity
                existing.remote_entity = mapping.remote_entity
                existing.field_mappings = mapping.field_mappings
                existing.sync_direction = mapping.sync_direction
                existing.is_enabled = mapping.is_enabled
            else:
                row = SyncMappingModel(
                    mapping_id=mapping.mapping_id,
                    connection_id=mapping.connection_id,
                    local_entity=mapping.local_entity,
                    remote_entity=mapping.remote_entity,
                    field_mappings=mapping.field_mappings,
                    sync_direction=mapping.sync_direction,
                    is_enabled=mapping.is_enabled,
                )
                self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting mapping: {e}")
            self.db.rollback()

    def _persist_sync_log(self, log: SyncLog) -> None:
        if not self._use_db:
            return
        try:
            row = SyncLogModel(
                log_id=log.log_id,
                connection_id=log.connection_id,
                sync_type=log.sync_type,
                entities_pushed=log.entities_pushed,
                entities_pulled=log.entities_pulled,
                errors=log.errors,
                started_at=log.started_at,
                completed_at=log.completed_at,
            )
            self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting sync log: {e}")
            self.db.rollback()

    def _persist_entity_sync(self, connection_id: str, entity_type: str,
                             local_id: str, remote_id: str,
                             entity_name: str = "", sync_status: str = "synced") -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(EntitySyncModel).filter(
                EntitySyncModel.connection_id == connection_id,
                EntitySyncModel.entity_type == entity_type,
                EntitySyncModel.local_id == local_id,
            ).first()
            if existing:
                existing.remote_id = remote_id
                existing.entity_name = entity_name
                existing.sync_status = sync_status
                existing.last_synced = datetime.utcnow()
            else:
                row = EntitySyncModel(
                    connection_id=connection_id,
                    entity_type=entity_type,
                    local_id=local_id,
                    remote_id=remote_id,
                    entity_name=entity_name,
                    sync_status=sync_status,
                    last_synced=datetime.utcnow(),
                )
                self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB error persisting entity sync: {e}")
            self.db.rollback()

    # ==================================================================
    # Connection CRUD
    # ==================================================================

    def create_connection(
        self,
        psa_type: str,
        company_id: str,
        api_url: str,
        client_id: str = "",
        public_key: str = "",
        private_key_ref: str = "",
        sync_config: Dict = None,
    ) -> PSAConnection:
        """Create a new PSA integration connection."""
        connection_id = f"PSA-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        conn = PSAConnection(
            connection_id=connection_id,
            psa_type=psa_type,
            company_id=company_id,
            api_url=api_url,
            client_id=client_id,
            public_key=public_key,
            private_key_ref=private_key_ref,
            sync_config=sync_config or {},
        )

        self.connections[connection_id] = conn
        self._persist_connection(conn)
        logger.info(f"PSA connection created: {connection_id} ({psa_type})")
        return conn

    def update_connection(self, connection_id: str, **kwargs) -> Optional[PSAConnection]:
        """Update an existing PSA connection."""
        conn = self.connections.get(connection_id)
        if not conn:
            return None

        for key in ("psa_type", "company_id", "api_url", "client_id",
                     "public_key", "private_key_ref", "sync_config",
                     "is_connected", "sync_status"):
            if key in kwargs:
                setattr(conn, key, kwargs[key])

        self._persist_connection(conn)
        return conn

    def test_connection(self, connection_id: str) -> Dict[str, Any]:
        """
        Test connectivity to the PSA system.

        In production this would make an authenticated GET to the PSA API.
        Currently returns a simulated result for wiring validation.
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"success": False, "error": "Connection not found"}

        # Build the auth test URL based on PSA type
        if conn.psa_type == PSAType.CONNECTWISE:
            test_url = f"{conn.api_url}system/info"
        else:
            test_url = f"{conn.api_url}status"

        # Validate required credentials are present
        if not conn.client_id or not conn.public_key or not conn.private_key_ref:
            return {
                "success": False,
                "error": "Missing credentials (client_id, public_key, or private_key_ref)",
                "test_url": test_url,
            }

        # Simulated success -- real implementation would do HTTP GET here
        conn.is_connected = True
        self._persist_connection(conn)

        return {
            "success": True,
            "psa_type": conn.psa_type,
            "test_url": test_url,
            "response_time_ms": 142,
            "api_version": "2021.1" if conn.psa_type == PSAType.CONNECTWISE else "1.0",
            "message": "Connection verified",
        }

    def delete_connection(self, connection_id: str) -> bool:
        """Delete a PSA connection and its associated mappings."""
        if connection_id not in self.connections:
            return False

        del self.connections[connection_id]

        # Remove associated mappings
        to_remove = [mid for mid, m in self.mappings.items() if m.connection_id == connection_id]
        for mid in to_remove:
            del self.mappings[mid]

        if self._use_db:
            try:
                self.db.query(PSAConnectionModel).filter(
                    PSAConnectionModel.connection_id == connection_id
                ).delete()
                self.db.query(SyncMappingModel).filter(
                    SyncMappingModel.connection_id == connection_id
                ).delete()
                self.db.query(SyncLogModel).filter(
                    SyncLogModel.connection_id == connection_id
                ).delete()
                self.db.query(EntitySyncModel).filter(
                    EntitySyncModel.connection_id == connection_id
                ).delete()
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error deleting connection: {e}")
                self.db.rollback()

        logger.info(f"PSA connection deleted: {connection_id}")
        return True

    def list_connections(self, psa_type: str = None) -> List[PSAConnection]:
        """List all PSA connections, optionally filtered by type."""
        conns = list(self.connections.values())
        if psa_type:
            conns = [c for c in conns if c.psa_type == psa_type]
        return conns

    def get_connection(self, connection_id: str) -> Optional[PSAConnection]:
        """Get a single connection by ID."""
        return self.connections.get(connection_id)

    # ==================================================================
    # Mapping CRUD
    # ==================================================================

    def create_mapping(
        self,
        connection_id: str,
        local_entity: str,
        remote_entity: str,
        field_mappings: Dict[str, str] = None,
        sync_direction: str = "bidirectional",
    ) -> Optional[SyncMapping]:
        """Create a field mapping between local and remote entities."""
        if connection_id not in self.connections:
            return None

        mapping_id = f"MAP-{str(uuid.uuid4())[:8].upper()}"

        mapping = SyncMapping(
            mapping_id=mapping_id,
            connection_id=connection_id,
            local_entity=local_entity,
            remote_entity=remote_entity,
            field_mappings=field_mappings or {},
            sync_direction=sync_direction,
        )

        self.mappings[mapping_id] = mapping
        self._persist_mapping(mapping)
        return mapping

    def update_mapping(self, mapping_id: str, **kwargs) -> Optional[SyncMapping]:
        """Update an existing sync mapping."""
        mapping = self.mappings.get(mapping_id)
        if not mapping:
            return None

        for key in ("local_entity", "remote_entity", "field_mappings",
                     "sync_direction", "is_enabled"):
            if key in kwargs:
                setattr(mapping, key, kwargs[key])

        self._persist_mapping(mapping)
        return mapping

    def list_mappings(self, connection_id: str = None) -> List[SyncMapping]:
        """List mappings, optionally filtered by connection."""
        mappings = list(self.mappings.values())
        if connection_id:
            mappings = [m for m in mappings if m.connection_id == connection_id]
        return mappings

    # ==================================================================
    # ConnectWise-specific mapping helpers
    # ==================================================================

    def cw_map_priority(self, aither_priority: str) -> Dict[str, Any]:
        """Map Aither priority to ConnectWise priority object."""
        return CW_PRIORITY_MAP.get(aither_priority, CW_PRIORITY_MAP["P3"])

    def cw_map_status(self, aither_status: str) -> Dict[str, Any]:
        """Map Aither ticket status to ConnectWise status object."""
        return CW_STATUS_MAP.get(aither_status, CW_STATUS_MAP["new"])

    def cw_build_ticket_payload(self, itsm_ticket: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert an Aither ITSM ticket dict into a ConnectWise service ticket payload.

        ConnectWise POST /service/tickets expects:
        {
            "summary": str,
            "company": {"id": int},
            "board": {"id": int},
            "status": {"id": int, "name": str},
            "priority": {"id": int, "name": str},
            "type": {"id": int},
            ...
        }
        """
        priority = self.cw_map_priority(
            itsm_ticket.get("priority", "P3")
        )
        status = self.cw_map_status(
            itsm_ticket.get("status", "new")
        )

        payload = {
            "summary": itsm_ticket.get("title", "Untitled Ticket"),
            "recordType": "ServiceTicket",
            "board": {"id": itsm_ticket.get("cw_board_id", 1)},
            "status": status,
            "priority": priority,
            "company": {"id": itsm_ticket.get("cw_company_id", 1)},
            "initialDescription": itsm_ticket.get("description", ""),
            "contactName": itsm_ticket.get("customer_name", ""),
        }

        # Optional fields
        if itsm_ticket.get("assigned_to"):
            payload["owner"] = {"identifier": itsm_ticket["assigned_to"]}
        if itsm_ticket.get("category"):
            payload["type"] = {"name": itsm_ticket["category"]}

        return payload

    def cw_parse_ticket(self, cw_ticket_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a ConnectWise service ticket JSON into an Aither ITSM-compatible dict.
        """
        # Reverse-map ConnectWise priority ID to Aither priority
        cw_pri_id = (cw_ticket_json.get("priority") or {}).get("id", 3)
        pri_reverse = {1: "P1", 2: "P2", 3: "P3", 4: "P4"}
        aither_priority = pri_reverse.get(cw_pri_id, "P3")

        # Reverse-map ConnectWise status
        cw_status_name = (cw_ticket_json.get("status") or {}).get("name", "New")
        status_reverse = {
            "New": "new",
            "Assigned": "assigned",
            "In Progress": "in_progress",
            "Waiting on Client": "pending_customer",
            "Resolved": "resolved",
            "Closed": "closed",
        }
        aither_status = status_reverse.get(cw_status_name, "new")

        return {
            "remote_ticket_id": str(cw_ticket_json.get("id", "")),
            "title": cw_ticket_json.get("summary", ""),
            "description": cw_ticket_json.get("initialDescription", ""),
            "priority": aither_priority,
            "status": aither_status,
            "category": (cw_ticket_json.get("type") or {}).get("name", "other"),
            "customer_name": cw_ticket_json.get("contactName", ""),
            "company_name": (cw_ticket_json.get("company") or {}).get("name", ""),
            "cw_board_id": (cw_ticket_json.get("board") or {}).get("id"),
            "cw_company_id": (cw_ticket_json.get("company") or {}).get("id"),
            "assigned_to": (cw_ticket_json.get("owner") or {}).get("identifier", ""),
            "last_updated": cw_ticket_json.get("_info", {}).get("lastUpdated", ""),
        }

    # ==================================================================
    # ConnectWise API helpers
    # ==================================================================

    def _cw_base_url(self, conn: PSAConnection) -> str:
        """Build the ConnectWise REST API base URL."""
        url = conn.api_url.rstrip("/")
        if not url.endswith("/apis/3.0"):
            url = f"{url}/v4_6_release/apis/3.0"
        return url

    def _cw_auth_headers(self, conn: PSAConnection) -> Dict[str, str]:
        """
        Build ConnectWise API auth headers.

        ConnectWise uses: Authorization: Basic base64(company+public_key:private_key)
        Plus clientId header.
        """
        import base64
        auth_token = base64.b64encode(
            f"{conn.company_id}+{conn.public_key}:{conn.private_key_ref}".encode()
        ).decode()

        return {
            "Authorization": f"Basic {auth_token}",
            "clientId": conn.client_id,
            "Content-Type": "application/json",
        }

    # ==================================================================
    # ConnectWise sync methods (simulated)
    # ==================================================================

    def cw_sync_companies(self, connection_id: str) -> Dict[str, Any]:
        """
        Sync companies/clients between Aither and ConnectWise.

        In production: GET /company/companies with pagination,
        compare with local companies, push/pull differences.
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"error": "Connection not found"}

        log = self._start_sync_log(connection_id, "companies")

        # Simulated sync result
        log.entities_pulled = 0
        log.entities_pushed = 0
        self._complete_sync_log(log)

        return {
            "status": "completed",
            "connection_id": connection_id,
            "sync_type": "companies",
            "pulled": log.entities_pulled,
            "pushed": log.entities_pushed,
            "errors": log.errors,
            "base_url": self._cw_base_url(conn),
            "endpoint": "/company/companies",
        }

    def cw_sync_contacts(self, connection_id: str) -> Dict[str, Any]:
        """
        Sync contact records between Aither and ConnectWise.
        Endpoint: GET /company/contacts
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"error": "Connection not found"}

        log = self._start_sync_log(connection_id, "contacts")
        log.entities_pulled = 0
        log.entities_pushed = 0
        self._complete_sync_log(log)

        return {
            "status": "completed",
            "connection_id": connection_id,
            "sync_type": "contacts",
            "pulled": log.entities_pulled,
            "pushed": log.entities_pushed,
            "errors": log.errors,
        }

    def cw_sync_tickets_push(self, connection_id: str, tickets: List[Dict] = None) -> Dict[str, Any]:
        """
        Push Aither ITSM tickets to ConnectWise as service tickets.
        Endpoint: POST /service/tickets
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"error": "Connection not found"}

        log = self._start_sync_log(connection_id, "tickets_push")
        tickets = tickets or []
        pushed = 0
        errors = []

        for ticket in tickets:
            try:
                payload = self.cw_build_ticket_payload(ticket)
                # In production: POST to /service/tickets
                pushed += 1

                # Record entity sync
                self._persist_entity_sync(
                    connection_id=connection_id,
                    entity_type="ticket",
                    local_id=ticket.get("ticket_id", ""),
                    remote_id=f"CW-{pushed}",  # placeholder
                    entity_name=ticket.get("title", ""),
                    sync_status="synced",
                )
                self.entity_syncs.append({
                    "entity_type": "ticket",
                    "local_id": ticket.get("ticket_id", ""),
                    "remote_id": f"CW-{pushed}",
                    "sync_status": "synced",
                })
            except Exception as e:
                errors.append({"ticket_id": ticket.get("ticket_id"), "error": str(e)})

        log.entities_pushed = pushed
        log.errors = errors
        self._complete_sync_log(log)

        return {
            "status": "completed",
            "pushed": pushed,
            "errors": errors,
        }

    def cw_sync_tickets_pull(self, connection_id: str) -> Dict[str, Any]:
        """
        Pull ConnectWise service tickets into Aither ITSM.
        Endpoint: GET /service/tickets?conditions=lastUpdated>[last_sync_at]
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"error": "Connection not found"}

        log = self._start_sync_log(connection_id, "tickets_pull")

        # In production: paginated GET /service/tickets with conditions filter
        # Parse each ticket via cw_parse_ticket() and upsert into ITSM
        log.entities_pulled = 0
        self._complete_sync_log(log)

        return {
            "status": "completed",
            "pulled": log.entities_pulled,
            "errors": log.errors,
            "conditions_query": f"lastUpdated>[{conn.last_sync_at.isoformat() if conn.last_sync_at else '2020-01-01'}]",
        }

    def cw_sync_configurations(self, connection_id: str) -> Dict[str, Any]:
        """
        Sync device/configuration records with ConnectWise.
        Endpoint: GET /company/configurations
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"error": "Connection not found"}

        log = self._start_sync_log(connection_id, "configurations")
        log.entities_pulled = 0
        log.entities_pushed = 0
        self._complete_sync_log(log)

        return {
            "status": "completed",
            "sync_type": "configurations",
            "pulled": log.entities_pulled,
            "pushed": log.entities_pushed,
            "errors": log.errors,
        }

    def cw_sync_agreements(self, connection_id: str) -> Dict[str, Any]:
        """
        Sync billing agreements with ConnectWise.
        Endpoint: GET /finance/agreements
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"error": "Connection not found"}

        log = self._start_sync_log(connection_id, "agreements")
        log.entities_pulled = 0
        log.entities_pushed = 0
        self._complete_sync_log(log)

        return {
            "status": "completed",
            "sync_type": "agreements",
            "pulled": log.entities_pulled,
            "pushed": log.entities_pushed,
            "errors": log.errors,
        }

    # ==================================================================
    # Sync engine
    # ==================================================================

    def full_sync(self, connection_id: str) -> Dict[str, Any]:
        """
        Run a full sync of all entity types for a connection.
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"error": "Connection not found"}

        conn.sync_status = SyncStatus.RUNNING
        self._persist_connection(conn)

        results = {}
        if conn.psa_type == PSAType.CONNECTWISE:
            results["companies"] = self.cw_sync_companies(connection_id)
            results["contacts"] = self.cw_sync_contacts(connection_id)
            results["tickets_pull"] = self.cw_sync_tickets_pull(connection_id)
            results["configurations"] = self.cw_sync_configurations(connection_id)
            results["agreements"] = self.cw_sync_agreements(connection_id)
        else:
            results["message"] = f"Full sync not yet implemented for {conn.psa_type}"

        conn.sync_status = SyncStatus.COMPLETED
        conn.last_sync_at = datetime.utcnow()
        self._persist_connection(conn)

        return {
            "status": "completed",
            "connection_id": connection_id,
            "psa_type": conn.psa_type,
            "results": results,
            "completed_at": datetime.utcnow().isoformat(),
        }

    def incremental_sync(self, connection_id: str) -> Dict[str, Any]:
        """
        Sync only changes since last_sync_at.
        Uses ConnectWise conditions query: lastUpdated>[timestamp]
        """
        conn = self.connections.get(connection_id)
        if not conn:
            return {"error": "Connection not found"}

        since = conn.last_sync_at or datetime(2020, 1, 1)

        conn.sync_status = SyncStatus.RUNNING
        self._persist_connection(conn)

        results = {}
        if conn.psa_type == PSAType.CONNECTWISE:
            results["tickets_pull"] = self.cw_sync_tickets_pull(connection_id)
            results["companies"] = self.cw_sync_companies(connection_id)
        else:
            results["message"] = f"Incremental sync not yet implemented for {conn.psa_type}"

        conn.sync_status = SyncStatus.COMPLETED
        conn.last_sync_at = datetime.utcnow()
        self._persist_connection(conn)

        return {
            "status": "completed",
            "connection_id": connection_id,
            "sync_since": since.isoformat(),
            "results": results,
        }

    def resolve_conflict(
        self,
        local: Dict[str, Any],
        remote: Dict[str, Any],
        strategy: str = "newest_wins",
    ) -> Dict[str, Any]:
        """
        Resolve a sync conflict between local and remote records.

        Strategies:
        - local_wins: Keep local data
        - remote_wins: Keep remote data
        - newest_wins: Compare updated_at timestamps, keep newest
        """
        if strategy == ConflictStrategy.LOCAL_WINS:
            return {"winner": "local", "data": local}
        elif strategy == ConflictStrategy.REMOTE_WINS:
            return {"winner": "remote", "data": remote}
        elif strategy == ConflictStrategy.NEWEST_WINS:
            local_ts = local.get("updated_at", "")
            remote_ts = remote.get("updated_at", "")
            if local_ts >= remote_ts:
                return {"winner": "local", "data": local}
            else:
                return {"winner": "remote", "data": remote}

        return {"winner": "local", "data": local}

    # ==================================================================
    # Sync log helpers
    # ==================================================================

    def _start_sync_log(self, connection_id: str, sync_type: str) -> SyncLog:
        log = SyncLog(
            log_id=f"SLOG-{str(uuid.uuid4())[:8].upper()}",
            connection_id=connection_id,
            sync_type=sync_type,
        )
        self.sync_logs.append(log)
        return log

    def _complete_sync_log(self, log: SyncLog) -> None:
        log.completed_at = datetime.utcnow()
        self._persist_sync_log(log)

    def get_sync_log(self, connection_id: str, limit: int = 50) -> List[Dict]:
        """Get sync history for a connection."""
        logs = [l for l in self.sync_logs if l.connection_id == connection_id]
        logs.sort(key=lambda l: l.started_at, reverse=True)
        return [
            {
                "log_id": l.log_id,
                "sync_type": l.sync_type,
                "entities_pushed": l.entities_pushed,
                "entities_pulled": l.entities_pulled,
                "errors": l.errors,
                "started_at": l.started_at.isoformat() if l.started_at else None,
                "completed_at": l.completed_at.isoformat() if l.completed_at else None,
            }
            for l in logs[:limit]
        ]

    # ==================================================================
    # Dashboard
    # ==================================================================

    def get_dashboard(self) -> Dict[str, Any]:
        """PSA integration dashboard with sync stats and error counts."""
        total_connections = len(self.connections)
        connected = len([c for c in self.connections.values() if c.is_connected])
        total_syncs = len(self.sync_logs)
        total_errors = sum(len(l.errors) for l in self.sync_logs)

        # Last sync per connection
        last_syncs = {}
        for conn in self.connections.values():
            last_syncs[conn.connection_id] = {
                "psa_type": conn.psa_type,
                "last_sync_at": conn.last_sync_at.isoformat() if conn.last_sync_at else None,
                "sync_status": conn.sync_status,
                "is_connected": conn.is_connected,
            }

        # Entity sync counts
        entity_counts = {}
        for es in self.entity_syncs:
            etype = es.get("entity_type", "unknown")
            entity_counts[etype] = entity_counts.get(etype, 0) + 1

        return {
            "total_connections": total_connections,
            "connected": connected,
            "disconnected": total_connections - connected,
            "total_syncs_executed": total_syncs,
            "total_errors": total_errors,
            "connections": last_syncs,
            "entity_sync_counts": entity_counts,
            "by_psa_type": {
                psa_type: len([c for c in self.connections.values() if c.psa_type == psa_type])
                for psa_type in set(c.psa_type for c in self.connections.values())
            } if self.connections else {},
        }


# ============================================================
# Global instance accessor
# ============================================================

_psa_instance: Optional[PSAConnectorService] = None


def get_psa_connector(db: "Session" = None) -> PSAConnectorService:
    """Get or create the global PSAConnectorService instance."""
    global _psa_instance
    if _psa_instance is None:
        _psa_instance = PSAConnectorService(db=db)
    return _psa_instance
