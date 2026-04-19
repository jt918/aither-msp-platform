"""
API Routes for PSA (Professional Services Automation) Connector

Full CRUD for connections and mappings, sync triggers,
sync log retrieval, and integration dashboard.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from services.integrations.psa_connector import PSAConnectorService, get_psa_connector
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

router = APIRouter(prefix="/psa", tags=["PSA Connector"])


# ===== Request / Response Models =====

class CreateConnectionRequest(BaseModel):
    psa_type: str  # connectwise/autotask/halo/syncro
    company_id: str
    api_url: str
    client_id: Optional[str] = ""
    public_key: Optional[str] = ""
    private_key_ref: Optional[str] = ""
    sync_config: Optional[Dict[str, Any]] = None


class UpdateConnectionRequest(BaseModel):
    psa_type: Optional[str] = None
    company_id: Optional[str] = None
    api_url: Optional[str] = None
    client_id: Optional[str] = None
    public_key: Optional[str] = None
    private_key_ref: Optional[str] = None
    sync_config: Optional[Dict[str, Any]] = None


class CreateMappingRequest(BaseModel):
    connection_id: str
    local_entity: str  # ticket/company/contact/device
    remote_entity: str
    field_mappings: Optional[Dict[str, str]] = None
    sync_direction: Optional[str] = "bidirectional"


class UpdateMappingRequest(BaseModel):
    local_entity: Optional[str] = None
    remote_entity: Optional[str] = None
    field_mappings: Optional[Dict[str, str]] = None
    sync_direction: Optional[str] = None
    is_enabled: Optional[bool] = None


class SyncTicketsRequest(BaseModel):
    tickets: Optional[List[Dict[str, Any]]] = None
    direction: Optional[str] = "push"  # push/pull


# ===== Helper =====

def _get_service(db: Session = Depends(get_sync_db)) -> PSAConnectorService:
    return get_psa_connector(db=db)


def _conn_to_dict(conn) -> Dict[str, Any]:
    return {
        "connection_id": conn.connection_id,
        "psa_type": conn.psa_type,
        "company_id": conn.company_id,
        "api_url": conn.api_url,
        "client_id": conn.client_id,
        "is_connected": conn.is_connected,
        "last_sync_at": conn.last_sync_at.isoformat() if conn.last_sync_at else None,
        "sync_status": conn.sync_status,
        "sync_config": conn.sync_config,
        "created_at": conn.created_at.isoformat() if conn.created_at else None,
    }


def _mapping_to_dict(m) -> Dict[str, Any]:
    return {
        "mapping_id": m.mapping_id,
        "connection_id": m.connection_id,
        "local_entity": m.local_entity,
        "remote_entity": m.remote_entity,
        "field_mappings": m.field_mappings,
        "sync_direction": m.sync_direction,
        "is_enabled": m.is_enabled,
    }


# ===== Connection CRUD =====

@router.post("/connections")
async def create_connection(
    request: CreateConnectionRequest,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Create a new PSA integration connection."""
    conn = svc.create_connection(
        psa_type=request.psa_type,
        company_id=request.company_id,
        api_url=request.api_url,
        client_id=request.client_id,
        public_key=request.public_key,
        private_key_ref=request.private_key_ref,
        sync_config=request.sync_config,
    )
    return {"status": "created", "connection": _conn_to_dict(conn)}


@router.get("/connections")
async def list_connections(
    psa_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    svc: PSAConnectorService = Depends(_get_service),
):
    """List all PSA connections."""
    conns = svc.list_connections(psa_type=psa_type)
    return {"connections": [_conn_to_dict(c) for c in conns]}


@router.get("/connections/{connection_id}")
async def get_connection(
    connection_id: str,
    current_user: dict = Depends(get_current_user),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Get a PSA connection by ID."""
    conn = svc.get_connection(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return _conn_to_dict(conn)


@router.put("/connections/{connection_id}")
async def update_connection(
    connection_id: str,
    request: UpdateConnectionRequest,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Update a PSA connection."""
    updates = {k: v for k, v in request.dict().items() if v is not None}
    conn = svc.update_connection(connection_id, **updates)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"status": "updated", "connection": _conn_to_dict(conn)}


@router.delete("/connections/{connection_id}")
async def delete_connection(
    connection_id: str,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Delete a PSA connection and associated mappings."""
    deleted = svc.delete_connection(connection_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"status": "deleted", "connection_id": connection_id}


# ===== Connection test =====

@router.post("/connections/{connection_id}/test")
async def test_connection(
    connection_id: str,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Test connectivity to the PSA system."""
    result = svc.test_connection(connection_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Test failed"))
    return result


# ===== Sync triggers =====

@router.post("/connections/{connection_id}/sync")
async def trigger_full_sync(
    connection_id: str,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Trigger a full sync for a PSA connection."""
    result = svc.full_sync(connection_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/connections/{connection_id}/sync/incremental")
async def trigger_incremental_sync(
    connection_id: str,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Trigger an incremental sync (changes since last sync)."""
    result = svc.incremental_sync(connection_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/connections/{connection_id}/sync/companies")
async def sync_companies(
    connection_id: str,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Sync companies only for a ConnectWise connection."""
    result = svc.cw_sync_companies(connection_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/connections/{connection_id}/sync/tickets")
async def sync_tickets(
    connection_id: str,
    request: SyncTicketsRequest = None,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Sync tickets for a ConnectWise connection (push or pull)."""
    if request and request.direction == "pull":
        result = svc.cw_sync_tickets_pull(connection_id)
    else:
        tickets = request.tickets if request else None
        result = svc.cw_sync_tickets_push(connection_id, tickets=tickets or [])
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ===== Sync log =====

@router.get("/connections/{connection_id}/sync-log")
async def get_sync_log(
    connection_id: str,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Get sync history for a connection."""
    logs = svc.get_sync_log(connection_id, limit=limit)
    return {"connection_id": connection_id, "logs": logs}


# ===== Mapping CRUD =====

@router.post("/mappings")
async def create_mapping(
    request: CreateMappingRequest,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Create a new sync mapping."""
    mapping = svc.create_mapping(
        connection_id=request.connection_id,
        local_entity=request.local_entity,
        remote_entity=request.remote_entity,
        field_mappings=request.field_mappings,
        sync_direction=request.sync_direction,
    )
    if not mapping:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"status": "created", "mapping": _mapping_to_dict(mapping)}


@router.get("/mappings")
async def list_mappings(
    connection_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    svc: PSAConnectorService = Depends(_get_service),
):
    """List sync mappings, optionally filtered by connection."""
    mappings = svc.list_mappings(connection_id=connection_id)
    return {"mappings": [_mapping_to_dict(m) for m in mappings]}


@router.put("/mappings/{mapping_id}")
async def update_mapping(
    mapping_id: str,
    request: UpdateMappingRequest,
    current_user: dict = Depends(require_admin),
    svc: PSAConnectorService = Depends(_get_service),
):
    """Update a sync mapping."""
    updates = {k: v for k, v in request.dict().items() if v is not None}
    mapping = svc.update_mapping(mapping_id, **updates)
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return {"status": "updated", "mapping": _mapping_to_dict(mapping)}


# ===== Dashboard =====

@router.get("/dashboard")
async def psa_dashboard(
    current_user: dict = Depends(get_current_user),
    svc: PSAConnectorService = Depends(_get_service),
):
    """PSA integration dashboard - sync stats, last sync times, error counts."""
    return svc.get_dashboard()
