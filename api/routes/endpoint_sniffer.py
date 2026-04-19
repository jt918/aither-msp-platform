"""Endpoint Sniffer API routes for discovering and mapping API endpoints."""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum
from middleware.auth import get_current_user, require_admin
from sqlalchemy.orm import Session
from core.database import get_sync_db

router = APIRouter(prefix="/api/endpoint-sniffer", tags=["Endpoint Sniffer"])


class ScanStatus(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class EndpointStatus(str, Enum):
    DISCOVERED = "discovered"
    TESTED = "tested"
    VERIFIED = "verified"
    FAILED = "failed"


class ScanCreate(BaseModel):
    target_url: str
    depth: int = 3
    rate_limit: str = "normal"
    methods: List[str] = ["GET", "POST", "PUT", "DELETE"]
    auth_token: Optional[str] = None


class EndpointTest(BaseModel):
    endpoint_id: str
    test_params: Optional[dict] = None
    headers: Optional[dict] = None


# In-memory storage
scans_db = [
    {
        "id": "1",
        "target_url": "https://api.retailmax.com/v2",
        "status": "running",
        "started_at": "2025-02-06T10:30:00",
        "endpoints_found": 47,
        "endpoints_tested": 32,
        "progress": 68,
        "depth": 3,
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "rate_limit": "normal"
    },
    {
        "id": "2",
        "target_url": "https://crm.sfpro.com/api",
        "status": "completed",
        "started_at": "2025-02-05T14:00:00",
        "completed_at": "2025-02-05T14:45:00",
        "endpoints_found": 89,
        "endpoints_tested": 89,
        "progress": 100,
        "depth": 4,
        "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
        "rate_limit": "fast"
    }
]

endpoints_db = [
    {
        "id": "1",
        "scan_id": "1",
        "path": "/products",
        "method": "GET",
        "status": "verified",
        "response_code": 200,
        "response_time": 145,
        "requires_auth": True,
        "parameters": [
            {"name": "page", "type": "integer", "location": "query"},
            {"name": "limit", "type": "integer", "location": "query"}
        ],
        "headers": [{"key": "Authorization", "value": "Bearer <token>"}],
        "sample_response": '{"products": [], "total": 150}',
        "discovered_at": "2025-02-06T10:35:00",
        "last_tested": "2025-02-06T11:00:00"
    },
    {
        "id": "2",
        "scan_id": "1",
        "path": "/products/{id}",
        "method": "GET",
        "status": "verified",
        "response_code": 200,
        "response_time": 89,
        "requires_auth": True,
        "parameters": [{"name": "id", "type": "string", "location": "path"}],
        "headers": [],
        "sample_response": '{"id": "123", "name": "Product"}',
        "discovered_at": "2025-02-06T10:35:00",
        "last_tested": "2025-02-06T11:00:00"
    },
    {
        "id": "3",
        "scan_id": "1",
        "path": "/orders",
        "method": "POST",
        "status": "tested",
        "response_code": 201,
        "response_time": 234,
        "requires_auth": True,
        "parameters": [
            {"name": "customer_id", "type": "string", "location": "body"},
            {"name": "items", "type": "array", "location": "body"}
        ],
        "headers": [{"key": "Content-Type", "value": "application/json"}],
        "sample_response": '{"order_id": "ord-123", "status": "created"}',
        "discovered_at": "2025-02-06T10:40:00",
        "last_tested": "2025-02-06T11:05:00"
    }
]


@router.get("/scans")
def list_scans(status: Optional[str] = None, db: Session = Depends(get_sync_db)):
    """List all scan sessions."""
    filtered = scans_db.copy()
    if status:
        filtered = [s for s in filtered if s["status"] == status]

    return {
        "scans": filtered,
        "total": len(filtered),
        "active": len([s for s in scans_db if s["status"] == "running"])
    }


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_sync_db)):
    """Get scan session details."""
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_endpoints = [e for e in endpoints_db if e["scan_id"] == scan_id]
    return {**scan, "endpoints": scan_endpoints}


@router.post("/scans")
def create_scan(scan: ScanCreate, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Start a new endpoint discovery scan."""
    new_scan = {
        "id": str(len(scans_db) + 1),
        "target_url": scan.target_url,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "endpoints_found": 0,
        "endpoints_tested": 0,
        "progress": 0,
        "depth": scan.depth,
        "methods": scan.methods,
        "rate_limit": scan.rate_limit
    }
    scans_db.append(new_scan)
    return new_scan


@router.post("/scans/{scan_id}/pause")
def pause_scan(scan_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Pause a running scan."""
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["status"] != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    scan["status"] = "paused"
    return {"message": "Scan paused", "scan": scan}


@router.post("/scans/{scan_id}/resume")
def resume_scan(scan_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Resume a paused scan."""
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["status"] != "paused":
        raise HTTPException(status_code=400, detail="Scan is not paused")

    scan["status"] = "running"
    return {"message": "Scan resumed", "scan": scan}


@router.post("/scans/{scan_id}/stop")
def stop_scan(scan_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Stop a running scan."""
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan["status"] = "completed"
    scan["completed_at"] = datetime.now().isoformat()
    return {"message": "Scan stopped", "scan": scan}


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Delete a scan and its discovered endpoints."""
    global scans_db, endpoints_db
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scans_db = [s for s in scans_db if s["id"] != scan_id]
    endpoints_db = [e for e in endpoints_db if e["scan_id"] != scan_id]
    return {"message": "Scan deleted", "id": scan_id}


@router.get("/endpoints")
def list_endpoints(
    scan_id: Optional[str] = None,
    method: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None
):
    """List discovered endpoints with filtering."""
    filtered = endpoints_db.copy()

    if scan_id:
        filtered = [e for e in filtered if e["scan_id"] == scan_id]
    if method:
        filtered = [e for e in filtered if e["method"] == method.upper()]
    if status:
        filtered = [e for e in filtered if e["status"] == status]
    if search:
        search_lower = search.lower()
        filtered = [e for e in filtered if search_lower in e["path"].lower()]

    return {
        "endpoints": filtered,
        "total": len(filtered),
        "by_status": {
            "discovered": len([e for e in filtered if e["status"] == "discovered"]),
            "tested": len([e for e in filtered if e["status"] == "tested"]),
            "verified": len([e for e in filtered if e["status"] == "verified"]),
            "failed": len([e for e in filtered if e["status"] == "failed"])
        }
    }


@router.get("/endpoints/{endpoint_id}")
def get_endpoint(endpoint_id: str, db: Session = Depends(get_sync_db)):
    """Get endpoint details."""
    endpoint = next((e for e in endpoints_db if e["id"] == endpoint_id), None)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return endpoint


@router.post("/endpoints/{endpoint_id}/test")
def test_endpoint(endpoint_id: str, test: Optional[EndpointTest] = None, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Test a discovered endpoint."""
    endpoint = next((e for e in endpoints_db if e["id"] == endpoint_id), None)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Simulate testing
    endpoint["status"] = "tested"
    endpoint["last_tested"] = datetime.now().isoformat()
    endpoint["response_code"] = 200
    endpoint["response_time"] = 150

    return {"message": "Endpoint tested", "endpoint": endpoint}


@router.post("/endpoints/{endpoint_id}/verify")
def verify_endpoint(endpoint_id: str, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Mark an endpoint as verified."""
    endpoint = next((e for e in endpoints_db if e["id"] == endpoint_id), None)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    endpoint["status"] = "verified"
    return {"message": "Endpoint verified", "endpoint": endpoint}


@router.post("/endpoints/{endpoint_id}/add-to-documentation")
def add_to_documentation(endpoint_id: str, project_id: Optional[str] = None, current_user: dict = Depends(require_admin), db: Session = Depends(get_sync_db)):
    """Add a discovered endpoint to API documentation."""
    endpoint = next((e for e in endpoints_db if e["id"] == endpoint_id), None)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return {
        "message": "Endpoint added to documentation",
        "endpoint_id": endpoint_id,
        "project_id": project_id
    }


@router.get("/export/{scan_id}")
def export_scan_results(scan_id: str, format: str = "openapi", db: Session = Depends(get_sync_db)):
    """Export scan results in various formats."""
    scan = next((s for s in scans_db if s["id"] == scan_id), None)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_endpoints = [e for e in endpoints_db if e["scan_id"] == scan_id]

    if format == "openapi":
        # Generate OpenAPI spec
        paths = {}
        for ep in scan_endpoints:
            if ep["path"] not in paths:
                paths[ep["path"]] = {}
            paths[ep["path"]][ep["method"].lower()] = {
                "summary": f"{ep['method']} {ep['path']}",
                "parameters": ep["parameters"],
                "responses": {"200": {"description": "Success"}}
            }

        return {
            "openapi": "3.0.0",
            "info": {"title": f"Discovered API - {scan['target_url']}", "version": "1.0.0"},
            "paths": paths
        }

    return {"endpoints": scan_endpoints}
