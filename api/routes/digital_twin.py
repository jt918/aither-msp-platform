"""
API Routes for Digital Twin Network Simulation
Uses DigitalTwinService for all operations
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.digital_twin import (
    DigitalTwinService,
    SimulationType,
    FindingSeverity,
    FindingType,
    AttackType,
)

router = APIRouter(prefix="/digital-twin", tags=["Digital Twin - Network Simulation"])


def _init_service() -> DigitalTwinService:
    """Initialize DigitalTwinService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return DigitalTwinService(db=db)
    except Exception:
        return DigitalTwinService()


# Singleton instance
_service = _init_service()


# ========== Pydantic Models ==========

class DeviceCreate(BaseModel):
    hostname: str
    ip_address: str
    mac_address: Optional[str] = ""
    device_type: Optional[str] = "unknown"
    os_type: Optional[str] = ""
    os_version: Optional[str] = ""
    open_ports: Optional[List[int]] = []
    services_running: Optional[List[str]] = []
    is_critical_asset: Optional[bool] = False


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    device_type: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    open_ports: Optional[List[int]] = None
    services_running: Optional[List[str]] = None
    is_critical_asset: Optional[bool] = None
    patch_level: Optional[str] = None


class ConnectionCreate(BaseModel):
    source_device_id: str
    target_device_id: str
    connection_type: Optional[str] = "ethernet"
    bandwidth_mbps: Optional[float] = 1000.0
    is_encrypted: Optional[bool] = False
    firewall_rules: Optional[List[str]] = []


class TwinCreateManual(BaseModel):
    client_id: str
    name: str
    devices: Optional[List[DeviceCreate]] = []
    connections: Optional[List[ConnectionCreate]] = []


class TwinCreateFromDiscovery(BaseModel):
    client_id: str
    discovered_devices: Optional[List[Dict[str, Any]]] = []


class TwinUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class SimulationRequest(BaseModel):
    scenario_id: Optional[str] = None


class BlueTeamRequest(BaseModel):
    findings: Optional[List[Dict[str, Any]]] = []


# ========== Twin CRUD ==========

@router.post("/twins")
async def create_twin_manual(data: TwinCreateManual, user=Depends(get_current_user)):
    """Create a network twin manually with provided devices and connections."""
    devices = [d.dict() for d in (data.devices or [])]
    connections = [c.dict() for c in (data.connections or [])]
    result = _service.create_twin_manual(data.client_id, data.name, devices, connections)
    return result


@router.post("/twins/from-discovery/{scan_id}")
async def create_twin_from_discovery(scan_id: str, data: TwinCreateFromDiscovery,
                                      user=Depends(get_current_user)):
    """Auto-create a network twin from a network discovery scan."""
    result = _service.create_twin_from_discovery(data.client_id, scan_id, data.discovered_devices)
    return result


@router.get("/twins")
async def list_twins(client_id: Optional[str] = Query(None),
                     user=Depends(get_current_user)):
    """List all network twins, optionally filtered by client_id."""
    return _service.list_twins(client_id)


@router.get("/twins/{twin_id}")
async def get_twin(twin_id: str, user=Depends(get_current_user)):
    """Get a network twin by ID."""
    result = _service.get_twin(twin_id)
    if not result:
        raise HTTPException(status_code=404, detail="Twin not found")
    return result


@router.put("/twins/{twin_id}")
async def update_twin(twin_id: str, data: TwinUpdate, user=Depends(get_current_user)):
    """Update a network twin's metadata."""
    updates = {k: v for k, v in data.dict().items() if v is not None}
    result = _service.update_twin(twin_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Twin not found")
    return result


@router.delete("/twins/{twin_id}")
async def delete_twin(twin_id: str, user=Depends(get_current_user)):
    """Delete a network twin and all associated data."""
    success = _service.delete_twin(twin_id)
    if not success:
        raise HTTPException(status_code=404, detail="Twin not found")
    return {"deleted": True, "twin_id": twin_id}


# ========== Device Management ==========

@router.post("/twins/{twin_id}/devices")
async def add_device(twin_id: str, data: DeviceCreate, user=Depends(get_current_user)):
    """Add a device to a network twin."""
    result = _service.add_device(twin_id, data.dict())
    if not result:
        raise HTTPException(status_code=404, detail="Twin not found")
    return result


@router.put("/twins/{twin_id}/devices/{device_id}")
async def update_device(twin_id: str, device_id: str, data: DeviceUpdate,
                        user=Depends(get_current_user)):
    """Update a device in a network twin."""
    updates = {k: v for k, v in data.dict().items() if v is not None}
    result = _service.update_device(device_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail="Device not found")
    return result


@router.delete("/twins/{twin_id}/devices/{device_id}")
async def remove_device(twin_id: str, device_id: str, user=Depends(get_current_user)):
    """Remove a device from a network twin."""
    success = _service.remove_device(twin_id, device_id)
    if not success:
        raise HTTPException(status_code=404, detail="Twin or device not found")
    return {"removed": True, "device_id": device_id}


# ========== Connections ==========

@router.post("/twins/{twin_id}/connections")
async def add_connection(twin_id: str, data: ConnectionCreate,
                         user=Depends(get_current_user)):
    """Add a connection between devices in a twin."""
    result = _service.add_connection(twin_id, data.dict())
    if not result:
        raise HTTPException(status_code=404, detail="Twin not found")
    return result


@router.delete("/twins/{twin_id}/connections/{connection_id}")
async def remove_connection(twin_id: str, connection_id: str,
                            user=Depends(get_current_user)):
    """Remove a connection from a twin."""
    success = _service.remove_connection(twin_id, connection_id)
    if not success:
        raise HTTPException(status_code=404, detail="Twin or connection not found")
    return {"removed": True, "connection_id": connection_id}


# ========== Vulnerability Scanning ==========

@router.post("/twins/{twin_id}/devices/{device_id}/scan")
async def scan_device_vulnerabilities(twin_id: str, device_id: str,
                                       user=Depends(get_current_user)):
    """Simulate vulnerability scan on a twin device."""
    result = _service.scan_device_vulnerabilities(device_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ========== Simulations ==========

@router.post("/twins/{twin_id}/simulate/red-team")
async def run_red_team(twin_id: str, data: Optional[SimulationRequest] = None,
                       user=Depends(get_current_user)):
    """Run a red team attack simulation against a twin."""
    scenario_id = data.scenario_id if data else None
    result = _service.run_red_team_simulation(twin_id, scenario_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/twins/{twin_id}/simulate/blue-team")
async def run_blue_team(twin_id: str, data: Optional[BlueTeamRequest] = None,
                        user=Depends(get_current_user)):
    """Run a blue team defense simulation."""
    findings = data.findings if data else None
    result = _service.run_blue_team_simulation(twin_id, findings)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/twins/{twin_id}/simulate/purple-team")
async def run_purple_team(twin_id: str, data: Optional[SimulationRequest] = None,
                          user=Depends(get_current_user)):
    """Run a combined red + blue team assessment."""
    scenario_id = data.scenario_id if data else None
    result = _service.run_purple_team(twin_id, scenario_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/simulations")
async def list_simulations(twin_id: Optional[str] = Query(None),
                           sim_type: Optional[str] = Query(None),
                           user=Depends(get_current_user)):
    """List simulation runs."""
    return _service.list_simulations(twin_id, sim_type)


@router.get("/simulations/{sim_id}")
async def get_simulation(sim_id: str, user=Depends(get_current_user)):
    """Get a simulation run by ID."""
    result = _service.get_simulation(sim_id)
    if not result:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return result


# ========== Analysis ==========

@router.get("/twins/{twin_id}/posture")
async def get_posture(twin_id: str, user=Depends(get_current_user)):
    """Calculate and return security posture score for a twin."""
    result = _service.calculate_security_posture(twin_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/twins/{twin_id}/attack-paths/{device_id}")
async def get_attack_paths(twin_id: str, device_id: str,
                           user=Depends(get_current_user)):
    """Find all possible attack paths to reach a target device."""
    result = _service.get_attack_path_analysis(twin_id, device_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/twins/{twin_id}/blast-radius/{device_id}")
async def get_blast_radius(twin_id: str, device_id: str,
                           user=Depends(get_current_user)):
    """Calculate blast radius from a compromised device."""
    result = _service.get_blast_radius(twin_id, device_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/twins/{twin_id}/posture-trend")
async def get_posture_trend(twin_id: str, user=Depends(get_current_user)):
    """Get security posture score trend over time."""
    result = _service.compare_posture_over_time(twin_id)
    return result


# ========== Scenarios ==========

@router.get("/scenarios")
async def list_scenarios(user=Depends(get_current_user)):
    """List all available attack scenarios."""
    return _service.list_scenarios()


@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str, user=Depends(get_current_user)):
    """Get an attack scenario by ID."""
    result = _service.get_scenario(scenario_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return result


# ========== Dashboard ==========

@router.get("/dashboard/{client_id}")
async def get_dashboard(client_id: str, user=Depends(get_current_user)):
    """Get digital twin dashboard for a client."""
    return _service.get_dashboard(client_id)
