"""
API Routes for DNS Filtering / Content Filtering
Uses DNSFilteringService for all operations.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.dns_filtering import (
    DNSFilteringService,
    ContentCategory,
    QueryAction,
    BLOCKING_PROFILES,
)

router = APIRouter(prefix="/dns-filtering", tags=["DNS Filtering"])


def _init_service() -> DNSFilteringService:
    """Initialize DNSFilteringService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return DNSFilteringService(db=db)
    except Exception:
        return DNSFilteringService()


dns_svc = _init_service()


# ========== Request / Response Models ==========

class PolicyCreate(BaseModel):
    client_id: str
    name: str
    blocked_categories: List[str] = []
    allowed_overrides: List[str] = []
    custom_blocklist: List[str] = []
    custom_allowlist: List[str] = []
    safe_search_enforced: bool = False
    logging_enabled: bool = True
    block_page_url: str = ""
    profile: Optional[str] = Field(None, description="Pre-built profile name")


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    blocked_categories: Optional[List[str]] = None
    allowed_overrides: Optional[List[str]] = None
    custom_blocklist: Optional[List[str]] = None
    custom_allowlist: Optional[List[str]] = None
    safe_search_enforced: Optional[bool] = None
    logging_enabled: Optional[bool] = None
    block_page_url: Optional[str] = None
    is_enabled: Optional[bool] = None


class PolicyToggle(BaseModel):
    enabled: bool


class EvaluateRequest(BaseModel):
    client_id: str
    source_ip: str
    domain: str
    query_type: str = "A"
    device_id: str = ""


class BlocklistAdd(BaseModel):
    domain_pattern: str
    reason: str = ""
    source: str = "manual"
    added_by: str = "system"
    expires_at: Optional[str] = None


class BlocklistImport(BaseModel):
    entries: List[Dict[str, str]]


class AllowlistAdd(BaseModel):
    domain_pattern: str
    reason: str = ""
    source: str = "manual"
    added_by: str = "system"
    expires_at: Optional[str] = None


class CategorizeDomain(BaseModel):
    domain: str
    category: str
    subcategory: str = ""
    confidence: float = 1.0
    source: str = "manual"


class BulkCategorize(BaseModel):
    entries: List[Dict[str, Any]]


# ========== Query Evaluation ==========

@router.post("/evaluate")
async def evaluate_query(req: EvaluateRequest, user=Depends(get_current_user)):
    """Evaluate a DNS query against client policies and return allow/block decision."""
    result = dns_svc.evaluate_query(
        client_id=req.client_id,
        source_ip=req.source_ip,
        domain=req.domain,
        query_type=req.query_type,
        device_id=req.device_id,
    )
    return result


# ========== Policy CRUD ==========

@router.post("/policies")
async def create_policy(req: PolicyCreate, user=Depends(get_current_user)):
    """Create a new DNS filtering policy."""
    return dns_svc.create_policy(
        client_id=req.client_id,
        name=req.name,
        blocked_categories=req.blocked_categories,
        allowed_overrides=req.allowed_overrides,
        custom_blocklist=req.custom_blocklist,
        custom_allowlist=req.custom_allowlist,
        safe_search_enforced=req.safe_search_enforced,
        logging_enabled=req.logging_enabled,
        block_page_url=req.block_page_url,
        profile=req.profile,
    )


@router.get("/policies")
async def list_policies(
    client_id: Optional[str] = None,
    user=Depends(get_current_user),
):
    """List all DNS policies, optionally filtered by client."""
    return dns_svc.list_policies(client_id=client_id)


@router.get("/policies/{policy_id}")
async def get_policy(policy_id: str, user=Depends(get_current_user)):
    """Get a single DNS policy by ID."""
    result = dns_svc.get_policy(policy_id)
    if not result:
        raise HTTPException(status_code=404, detail="Policy not found")
    return result


@router.put("/policies/{policy_id}")
async def update_policy(policy_id: str, req: PolicyUpdate, user=Depends(get_current_user)):
    """Update an existing DNS policy."""
    updates = req.dict(exclude_unset=True)
    try:
        return dns_svc.update_policy(policy_id, updates)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/policies/{policy_id}/toggle")
async def toggle_policy(policy_id: str, req: PolicyToggle, user=Depends(get_current_user)):
    """Enable or disable a policy."""
    try:
        return dns_svc.toggle_policy(policy_id, req.enabled)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str, user=Depends(get_current_user)):
    """Delete a DNS policy."""
    dns_svc.delete_policy(policy_id)
    return {"status": "deleted", "policy_id": policy_id}


# ========== Profiles ==========

@router.get("/profiles")
async def list_profiles(user=Depends(get_current_user)):
    """Return all pre-built blocking profiles."""
    return dns_svc.get_profiles()


# ========== Blocklist ==========

@router.post("/blocklist")
async def add_to_blocklist(req: BlocklistAdd, user=Depends(get_current_user)):
    """Add a domain pattern to the blocklist."""
    expires = None
    if req.expires_at:
        try:
            expires = datetime.fromisoformat(req.expires_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid expires_at format")
    return dns_svc.add_to_blocklist(
        domain_pattern=req.domain_pattern,
        reason=req.reason,
        source=req.source,
        added_by=req.added_by,
        expires_at=expires,
    )


@router.delete("/blocklist/{entry_id}")
async def remove_from_blocklist(entry_id: str, user=Depends(get_current_user)):
    """Remove an entry from the blocklist."""
    dns_svc.remove_from_blocklist(entry_id)
    return {"status": "removed", "entry_id": entry_id}


@router.post("/blocklist/import")
async def import_blocklist(req: BlocklistImport, user=Depends(get_current_user)):
    """Bulk import blocklist entries."""
    return dns_svc.import_blocklist(req.entries)


@router.get("/blocklist")
async def get_blocklist(user=Depends(get_current_user)):
    """Return all blocklist entries."""
    return dns_svc.get_blocklist()


# ========== Allowlist ==========

@router.post("/allowlist")
async def add_to_allowlist(req: AllowlistAdd, user=Depends(get_current_user)):
    """Add a domain pattern to the allowlist."""
    expires = None
    if req.expires_at:
        try:
            expires = datetime.fromisoformat(req.expires_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid expires_at format")
    return dns_svc.add_to_allowlist(
        domain_pattern=req.domain_pattern,
        reason=req.reason,
        source=req.source,
        added_by=req.added_by,
        expires_at=expires,
    )


@router.delete("/allowlist/{entry_id}")
async def remove_from_allowlist(entry_id: str, user=Depends(get_current_user)):
    """Remove an entry from the allowlist."""
    dns_svc.remove_from_allowlist(entry_id)
    return {"status": "removed", "entry_id": entry_id}


@router.get("/allowlist")
async def get_allowlist(user=Depends(get_current_user)):
    """Return all allowlist entries."""
    return dns_svc.get_allowlist()


# ========== Categories ==========

@router.post("/categories")
async def categorize_domain(req: CategorizeDomain, user=Depends(get_current_user)):
    """Set or update the category for a domain."""
    return dns_svc.categorize_domain(
        domain=req.domain,
        category=req.category,
        subcategory=req.subcategory,
        confidence=req.confidence,
        source=req.source,
    )


@router.post("/categories/bulk")
async def bulk_categorize(req: BulkCategorize, user=Depends(get_current_user)):
    """Bulk categorize domains."""
    return dns_svc.bulk_categorize(req.entries)


@router.get("/categories/{domain:path}")
async def get_domain_category(domain: str, user=Depends(get_current_user)):
    """Get the category for a specific domain."""
    result = dns_svc.get_domain_category(domain)
    if not result:
        raise HTTPException(status_code=404, detail="Domain not categorized")
    return result


@router.get("/categories")
async def list_categories(user=Depends(get_current_user)):
    """Return all available content categories."""
    return dns_svc.list_categories()


# ========== Logs ==========

@router.get("/logs/{client_id}")
async def get_query_logs(
    client_id: str,
    action: Optional[str] = None,
    domain: Optional[str] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    user=Depends(get_current_user),
):
    """Retrieve DNS query logs for a client."""
    return dns_svc.get_query_logs(
        client_id=client_id,
        action=action,
        domain=domain,
        limit=limit,
        offset=offset,
    )


# ========== Stats & Analytics ==========

@router.get("/stats/{client_id}")
async def get_query_stats(
    client_id: str,
    period: str = Query("24h", pattern="^(1h|6h|12h|24h|7d|30d)$"),
    user=Depends(get_current_user),
):
    """Get aggregated query statistics for a client."""
    return dns_svc.get_query_stats(client_id, period)


@router.get("/analytics/top-blocked/{client_id}")
async def get_top_blocked_domains(
    client_id: str,
    limit: int = Query(20, le=100),
    period: str = "24h",
    user=Depends(get_current_user),
):
    """Return the most frequently blocked domains for a client."""
    return dns_svc.get_top_blocked_domains(client_id, limit, period)


@router.get("/analytics/top-categories/{client_id}")
async def get_top_categories(
    client_id: str,
    limit: int = Query(10, le=50),
    period: str = "24h",
    user=Depends(get_current_user),
):
    """Return the most frequently hit categories for a client."""
    return dns_svc.get_top_categories(client_id, limit, period)


@router.get("/analytics/volume-trend/{client_id}")
async def get_query_volume_trend(
    client_id: str,
    period: str = "24h",
    buckets: int = Query(24, le=100),
    user=Depends(get_current_user),
):
    """Return query volume over time in equal buckets."""
    return dns_svc.get_query_volume_trend(client_id, period, buckets)


@router.get("/analytics/devices-blocked/{client_id}")
async def get_devices_most_blocked(
    client_id: str,
    limit: int = Query(10, le=50),
    period: str = "24h",
    user=Depends(get_current_user),
):
    """Return devices with the most blocked queries."""
    return dns_svc.get_devices_most_blocked(client_id, limit, period)


# ========== Dashboard ==========

@router.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    """Global DNS filtering dashboard with key metrics."""
    return dns_svc.get_dashboard()
