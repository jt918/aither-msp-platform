"""
API Routes for Configuration Management Database (CMDB)
Single source of truth for IT configuration items and their relationships.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from core.database import get_sync_db

from services.msp.cmdb import (
    CMDBService,
    CIType,
    CIStatus,
    Environment,
    RelationshipType,
    ChangeType,
    ChangeSource,
    ImpactType,
)

router = APIRouter(prefix="/cmdb", tags=["CMDB"])


def _init_cmdb_service() -> CMDBService:
    """Initialize CMDBService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return CMDBService(db=db)
    except Exception:
        return CMDBService()


cmdb_service = _init_cmdb_service()


# ========== Request/Response Models ==========

class CICreate(BaseModel):
    client_id: str
    ci_type: str  # CIType enum value
    name: str
    description: Optional[str] = ""
    status: Optional[str] = "active"
    environment: Optional[str] = "production"
    location: Optional[str] = ""
    owner: Optional[str] = ""
    department: Optional[str] = ""
    attributes: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    serial_number: Optional[str] = ""
    asset_tag: Optional[str] = ""
    ip_address: Optional[str] = ""
    mac_address: Optional[str] = ""
    manufacturer: Optional[str] = ""
    model: Optional[str] = ""
    firmware_version: Optional[str] = ""
    configuration_data: Optional[Dict[str, Any]] = None


class CIUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    environment: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    configuration_data: Optional[Dict[str, Any]] = None
    changed_by: Optional[str] = "system"


class RelationshipCreate(BaseModel):
    source_ci_id: str
    target_ci_id: str
    relationship_type: str  # RelationshipType enum value
    description: Optional[str] = ""
    is_bidirectional: Optional[bool] = False


class BaselineCapture(BaseModel):
    baseline_name: Optional[str] = None
    captured_by: Optional[str] = "system"


class SearchRequest(BaseModel):
    query: str
    filters: Optional[Dict[str, Any]] = None


def _ci_to_dict(ci) -> dict:
    return {
        "ci_id": ci.ci_id,
        "client_id": ci.client_id,
        "ci_type": ci.ci_type.value if hasattr(ci.ci_type, "value") else ci.ci_type,
        "name": ci.name,
        "description": ci.description,
        "status": ci.status.value if hasattr(ci.status, "value") else ci.status,
        "environment": ci.environment.value if hasattr(ci.environment, "value") else ci.environment,
        "location": ci.location,
        "owner": ci.owner,
        "department": ci.department,
        "attributes": ci.attributes,
        "tags": ci.tags,
        "serial_number": ci.serial_number,
        "asset_tag": ci.asset_tag,
        "ip_address": ci.ip_address,
        "mac_address": ci.mac_address,
        "manufacturer": ci.manufacturer,
        "model": ci.model,
        "firmware_version": ci.firmware_version,
        "configuration_data": ci.configuration_data,
        "last_audit_at": ci.last_audit_at.isoformat() if ci.last_audit_at else None,
        "created_at": ci.created_at.isoformat() if ci.created_at else None,
        "updated_at": ci.updated_at.isoformat() if ci.updated_at else None,
    }


def _rel_to_dict(rel) -> dict:
    return {
        "relationship_id": rel.relationship_id,
        "source_ci_id": rel.source_ci_id,
        "target_ci_id": rel.target_ci_id,
        "relationship_type": rel.relationship_type.value if hasattr(rel.relationship_type, "value") else rel.relationship_type,
        "description": rel.description,
        "is_bidirectional": rel.is_bidirectional,
        "created_at": rel.created_at.isoformat() if rel.created_at else None,
    }


def _baseline_to_dict(bl) -> dict:
    return {
        "baseline_id": bl.baseline_id,
        "ci_id": bl.ci_id,
        "baseline_name": bl.baseline_name,
        "baseline_data": bl.baseline_data,
        "captured_at": bl.captured_at.isoformat() if bl.captured_at else None,
        "captured_by": bl.captured_by,
        "is_current": bl.is_current,
    }


def _change_to_dict(chg) -> dict:
    return {
        "change_id": chg.change_id,
        "ci_id": chg.ci_id,
        "change_type": chg.change_type.value if hasattr(chg.change_type, "value") else chg.change_type,
        "field_changed": chg.field_changed,
        "old_value": chg.old_value,
        "new_value": chg.new_value,
        "changed_by": chg.changed_by,
        "change_source": chg.change_source.value if hasattr(chg.change_source, "value") else chg.change_source,
        "changed_at": chg.changed_at.isoformat() if chg.changed_at else None,
        "change_ticket_id": chg.change_ticket_id,
    }


# ========== CI CRUD ==========

@router.post("/cis")
async def create_ci(data: CICreate):
    """Create a new Configuration Item."""
    try:
        ci_type = CIType(data.ci_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid ci_type: {data.ci_type}")

    status = CIStatus(data.status) if data.status else CIStatus.ACTIVE
    env = Environment(data.environment) if data.environment else Environment.PRODUCTION

    ci = cmdb_service.create_ci(
        client_id=data.client_id,
        ci_type=ci_type,
        name=data.name,
        description=data.description or "",
        status=status,
        environment=env,
        location=data.location or "",
        owner=data.owner or "",
        department=data.department or "",
        attributes=data.attributes,
        tags=data.tags,
        serial_number=data.serial_number or "",
        asset_tag=data.asset_tag or "",
        ip_address=data.ip_address or "",
        mac_address=data.mac_address or "",
        manufacturer=data.manufacturer or "",
        model=data.model or "",
        firmware_version=data.firmware_version or "",
        configuration_data=data.configuration_data,
    )
    return _ci_to_dict(ci)


@router.get("/cis")
async def list_cis(
    client_id: Optional[str] = None,
    ci_type: Optional[str] = None,
    status: Optional[str] = None,
    environment: Optional[str] = None,
):
    """List Configuration Items with optional filters."""
    cis = cmdb_service.list_cis(
        client_id=client_id,
        ci_type=CIType(ci_type) if ci_type else None,
        status=CIStatus(status) if status else None,
        environment=Environment(environment) if environment else None,
    )
    return [_ci_to_dict(ci) for ci in cis]


@router.get("/cis/{ci_id}")
async def get_ci(ci_id: str):
    """Get a Configuration Item by ID."""
    ci = cmdb_service.get_ci(ci_id)
    if not ci:
        raise HTTPException(status_code=404, detail="Configuration Item not found")
    return _ci_to_dict(ci)


@router.put("/cis/{ci_id}")
async def update_ci(ci_id: str, data: CIUpdate):
    """Update a Configuration Item."""
    updates = {k: v for k, v in data.dict(exclude_unset=True).items() if v is not None}

    # Convert enum string values
    if "status" in updates:
        updates["status"] = CIStatus(updates["status"])
    if "environment" in updates:
        updates["environment"] = Environment(updates["environment"])
    if "ci_type" in updates:
        updates["ci_type"] = CIType(updates["ci_type"])

    ci = cmdb_service.update_ci(ci_id, **updates)
    if not ci:
        raise HTTPException(status_code=404, detail="Configuration Item not found")
    return _ci_to_dict(ci)


@router.delete("/cis/{ci_id}")
async def delete_ci(ci_id: str):
    """Soft-delete (decommission) a Configuration Item."""
    success = cmdb_service.delete_ci(ci_id)
    if not success:
        raise HTTPException(status_code=404, detail="Configuration Item not found")
    return {"status": "decommissioned", "ci_id": ci_id}


@router.post("/cis/search")
async def search_cis(data: SearchRequest):
    """Search Configuration Items by name, description, IP, serial number, etc."""
    results = cmdb_service.search_cis(data.query, data.filters)
    return [_ci_to_dict(ci) for ci in results]


# ========== Relationships ==========

@router.post("/relationships")
async def create_relationship(data: RelationshipCreate):
    """Create a relationship between two CIs."""
    try:
        rel_type = RelationshipType(data.relationship_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid relationship_type: {data.relationship_type}")

    rel = cmdb_service.create_relationship(
        source_ci_id=data.source_ci_id,
        target_ci_id=data.target_ci_id,
        relationship_type=rel_type,
        description=data.description or "",
        is_bidirectional=data.is_bidirectional or False,
    )
    if not rel:
        raise HTTPException(status_code=404, detail="One or both CIs not found")
    return _rel_to_dict(rel)


@router.get("/relationships/{ci_id}")
async def get_relationships(ci_id: str):
    """Get all relationships for a CI."""
    rels = cmdb_service.get_relationships(ci_id)
    return [_rel_to_dict(r) for r in rels]


@router.delete("/relationships/{relationship_id}")
async def delete_relationship(relationship_id: str):
    """Delete a CI relationship."""
    success = cmdb_service.delete_relationship(relationship_id)
    if not success:
        raise HTTPException(status_code=404, detail="Relationship not found")
    return {"status": "deleted", "relationship_id": relationship_id}


@router.get("/dependencies/{ci_id}")
async def get_dependency_tree(ci_id: str):
    """Get recursive dependency tree for a CI."""
    tree = cmdb_service.get_dependency_tree(ci_id)
    return tree


# ========== Baselines ==========

@router.post("/baselines/{ci_id}")
async def capture_baseline(ci_id: str, data: BaselineCapture = None):
    """Capture a baseline snapshot of a CI's configuration."""
    if data is None:
        data = BaselineCapture()
    bl = cmdb_service.capture_baseline(
        ci_id=ci_id,
        baseline_name=data.baseline_name,
        captured_by=data.captured_by or "system",
    )
    if not bl:
        raise HTTPException(status_code=404, detail="Configuration Item not found")
    return _baseline_to_dict(bl)


@router.get("/baselines/{ci_id}")
async def get_baselines(ci_id: str):
    """Get all baselines for a CI."""
    baselines = cmdb_service.get_baselines(ci_id)
    return [_baseline_to_dict(bl) for bl in baselines]


@router.get("/baselines/{ci_id}/drift")
async def compare_to_baseline(ci_id: str):
    """Compare current CI state to its baseline - drift detection."""
    result = cmdb_service.compare_to_baseline(ci_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ========== Change History ==========

@router.get("/changes/{ci_id}")
async def get_change_history(ci_id: str, limit: int = Query(50, ge=1, le=500)):
    """Get change history for a CI."""
    changes = cmdb_service.get_change_history(ci_id, limit=limit)
    return [_change_to_dict(c) for c in changes]


@router.get("/changes")
async def get_recent_changes(
    client_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
):
    """Get recent changes across all CIs."""
    changes = cmdb_service.get_recent_changes(client_id=client_id, limit=limit)
    return [_change_to_dict(c) for c in changes]


# ========== Impact Analysis ==========

@router.get("/impact/{ci_id}")
async def analyze_impact(ci_id: str, impact_type: str = "outage"):
    """Analyze the impact of an event on a CI and its dependencies."""
    try:
        it = ImpactType(impact_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid impact_type: {impact_type}")

    ci = cmdb_service.get_ci(ci_id)
    if not ci:
        raise HTTPException(status_code=404, detail="Configuration Item not found")

    analysis = cmdb_service.analyze_impact(ci_id, it)
    return {
        "analysis_id": analysis.analysis_id,
        "ci_id": analysis.ci_id,
        "impact_type": analysis.impact_type.value,
        "affected_cis": analysis.affected_cis,
        "impact_level": analysis.impact_level.value,
        "analysis_details": analysis.analysis_details,
        "generated_at": analysis.generated_at.isoformat(),
    }


# ========== Sync ==========

@router.post("/sync/rmm/{client_id}")
async def sync_from_rmm(client_id: str):
    """Sync CIs from RMM endpoint data."""
    result = cmdb_service.sync_from_rmm(client_id)
    return result


@router.post("/sync/discovery/{client_id}")
async def sync_from_discovery(client_id: str):
    """Sync CIs from network discovery data."""
    result = cmdb_service.sync_from_discovery(client_id)
    return result


# ========== Audit ==========

@router.get("/audit/stale")
async def get_stale_cis(days: int = Query(90, ge=1)):
    """Get CIs that haven't been audited recently."""
    stale = cmdb_service.get_stale_cis(days=days)
    return [_ci_to_dict(ci) for ci in stale]


@router.post("/audit/{ci_id}")
async def mark_audited(ci_id: str):
    """Mark a CI as recently audited."""
    success = cmdb_service.mark_audited(ci_id)
    if not success:
        raise HTTPException(status_code=404, detail="Configuration Item not found")
    return {"status": "audited", "ci_id": ci_id}


# ========== Visualization ==========

@router.get("/topology/{client_id}")
async def get_topology_map(client_id: str):
    """Get CIs and relationships as a graph for topology visualization."""
    return cmdb_service.get_topology_map(client_id)


@router.get("/stats/by-type")
async def get_ci_count_by_type(client_id: Optional[str] = None):
    """Get CI counts grouped by type."""
    return cmdb_service.get_ci_count_by_type(client_id=client_id)


@router.get("/stats/by-status")
async def get_ci_count_by_status(client_id: Optional[str] = None):
    """Get CI counts grouped by status."""
    return cmdb_service.get_ci_count_by_status(client_id=client_id)


@router.get("/dashboard")
async def get_dashboard():
    """Get CMDB dashboard with aggregated stats."""
    return cmdb_service.get_dashboard()


# ========== Enum Reference ==========

@router.get("/enums")
async def get_enums():
    """Return all CMDB enum values for UI dropdowns."""
    return {
        "ci_types": [e.value for e in CIType],
        "ci_statuses": [e.value for e in CIStatus],
        "environments": [e.value for e in Environment],
        "relationship_types": [e.value for e in RelationshipType],
        "change_types": [e.value for e in ChangeType],
        "change_sources": [e.value for e in ChangeSource],
        "impact_types": [e.value for e in ImpactType],
    }
