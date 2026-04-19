"""
API Routes for Network Discovery Service
Uses NetworkDiscoveryService for all operations
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.network_discovery import (
    NetworkDiscoveryService,
    DeviceType,
    ScanStatus,
    ScanType,
    DiscoveredDevice,
    DiscoveryScan,
)

router = APIRouter(prefix="/network-discovery", tags=["Network Discovery"])


def _init_nd_service() -> NetworkDiscoveryService:
    """Initialize NetworkDiscoveryService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return NetworkDiscoveryService(db=db)
    except Exception:
        return NetworkDiscoveryService()


# Initialize service with DB persistence
nd_service = _init_nd_service()


# ========== Request/Response Models ==========

class ScanRequest(BaseModel):
    subnet: str = Field(..., description="Subnet in CIDR notation, e.g. 192.168.1.0/24")
    scan_type: str = Field("full", description="Scan type: ping_sweep, snmp_walk, arp_scan, full")
    community: str = Field("public", description="SNMP community string")


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    location: Optional[str] = None
    contact: Optional[str] = None


class SNMPWalkRequest(BaseModel):
    community: Optional[str] = Field(None, description="SNMP community string override")


# ========== Helpers ==========

def _scan_to_dict(scan: DiscoveryScan) -> dict:
    return {
        "scan_id": scan.scan_id,
        "subnet": scan.subnet,
        "scan_type": scan.scan_type.value,
        "status": scan.status.value,
        "community": scan.community,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "devices_found": scan.devices_found,
        "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


def _device_to_dict(dev: DiscoveredDevice) -> dict:
    return {
        "device_id": dev.device_id,
        "ip": dev.ip,
        "mac": dev.mac,
        "hostname": dev.hostname,
        "device_type": dev.device_type.value,
        "vendor": dev.vendor,
        "model": dev.model,
        "firmware_version": dev.firmware_version,
        "serial_number": dev.serial_number,
        "snmp_community": dev.snmp_community,
        "ports_open": dev.ports_open,
        "uptime": dev.uptime,
        "location": dev.location,
        "contact": dev.contact,
        "sys_descr": dev.sys_descr,
        "sys_object_id": dev.sys_object_id,
        "interface_count": dev.interface_count,
        "neighbors": dev.neighbors,
        "tags": dev.tags,
        "notes": dev.notes,
        "scan_id": dev.scan_id,
        "first_seen": dev.first_seen.isoformat() if dev.first_seen else None,
        "last_seen": dev.last_seen.isoformat() if dev.last_seen else None,
        "created_at": dev.created_at.isoformat() if dev.created_at else None,
        "updated_at": dev.updated_at.isoformat() if dev.updated_at else None,
    }


# ========== Scan Routes ==========

@router.post("/scans")
async def start_scan(req: ScanRequest, user=Depends(get_current_user)):
    """Start a network discovery scan on a subnet."""
    try:
        scan_type = ScanType(req.scan_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan_type: {req.scan_type}. Must be one of: "
                   f"{', '.join(t.value for t in ScanType)}",
        )

    scan = nd_service.start_scan(
        subnet=req.subnet,
        scan_type=scan_type,
        community=req.community,
    )
    return _scan_to_dict(scan)


@router.get("/scans")
async def list_scans(
    limit: int = Query(50, ge=1, le=200),
    user=Depends(get_current_user),
):
    """List recent discovery scans."""
    scans = nd_service.list_scans(limit=limit)
    return {"scans": [_scan_to_dict(s) for s in scans], "total": len(scans)}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    """Get the status of a specific discovery scan."""
    scan = nd_service.get_scan_status(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_dict(scan)


# ========== Device Routes ==========

@router.get("/devices")
async def list_devices(
    device_type: Optional[str] = Query(None, description="Filter by device type"),
    vendor: Optional[str] = Query(None, description="Filter by vendor name"),
    subnet: Optional[str] = Query(None, description="Filter by subnet prefix"),
    limit: int = Query(200, ge=1, le=1000),
    user=Depends(get_current_user),
):
    """List discovered network devices."""
    dtype = None
    if device_type:
        try:
            dtype = DeviceType(device_type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid device_type: {device_type}. Must be one of: "
                       f"{', '.join(t.value for t in DeviceType)}",
            )

    devices = nd_service.get_devices(
        device_type=dtype, vendor=vendor, subnet=subnet, limit=limit,
    )
    return {"devices": [_device_to_dict(d) for d in devices], "total": len(devices)}


@router.get("/devices/{device_id}")
async def get_device(device_id: str, user=Depends(get_current_user)):
    """Get a specific discovered device."""
    device = nd_service.get_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return _device_to_dict(device)


@router.put("/devices/{device_id}")
async def update_device(
    device_id: str, req: DeviceUpdate, user=Depends(get_current_user),
):
    """Update a discovered device (label, type override, notes, tags)."""
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No update fields provided")

    device = nd_service.update_device(device_id, **updates)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return _device_to_dict(device)


@router.delete("/devices/{device_id}")
async def delete_device(device_id: str, user=Depends(get_current_user)):
    """Remove a discovered device from inventory."""
    deleted = nd_service.delete_device(device_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"success": True, "device_id": device_id}


# ========== SNMP Walk Route ==========

@router.post("/devices/{device_id}/snmp-walk")
async def snmp_walk_device(
    device_id: str,
    req: SNMPWalkRequest = SNMPWalkRequest(),
    user=Depends(get_current_user),
):
    """Run an SNMP walk on a specific device and update its record."""
    result = nd_service.snmp_walk_device(device_id, community=req.community)
    if not result.get("success"):
        raise HTTPException(
            status_code=404 if "not found" in result.get("error", "").lower() else 502,
            detail=result.get("error", "SNMP walk failed"),
        )
    return result


# ========== Topology & Dashboard ==========

@router.get("/topology")
async def get_topology(user=Depends(get_current_user)):
    """Get network topology map from discovered devices."""
    return nd_service.get_topology_map()


@router.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    """Get network discovery dashboard statistics."""
    return nd_service.get_dashboard()
