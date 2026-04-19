"""
API Routes for RMM Agent Communication Protocol

Agent endpoints (called by the agent binary):
  POST /agent/register         - register new agent
  POST /agent/checkin          - heartbeat
  GET  /agent/commands         - poll pending commands
  POST /agent/commands/{id}/result - submit command result
  GET  /agent/config           - get current config
  GET  /agent/update/check     - check for updates
  GET  /agent/update/download/{version} - download update binary

Admin endpoints (dashboard / fleet management):
  GET    /agent/agents            - list agents
  GET    /agent/agents/{id}       - agent detail
  DELETE /agent/agents/{id}       - revoke agent
  POST   /agent/agents/{id}/rotate-key - rotate API key
  PUT    /agent/agents/{id}/config     - push config
  GET    /agent/dashboard         - fleet stats
"""

from fastapi import APIRouter, HTTPException, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.agent_protocol import AgentProtocolService

router = APIRouter(prefix="/agent", tags=["Agent Protocol"])


def _init_agent_service() -> AgentProtocolService:
    """Initialize AgentProtocolService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return AgentProtocolService(db=db)
    except Exception:
        return AgentProtocolService()


agent_service = _init_agent_service()


# ========== Pydantic Request/Response Models ==========

class AgentRegisterRequest(BaseModel):
    hostname: str
    os_type: str = "windows"
    os_version: str = ""
    arch: str = "x64"
    agent_version: str = ""
    install_path: str = ""
    endpoint_id: Optional[str] = None


class AgentCheckinRequest(BaseModel):
    system_metrics: Dict[str, Any] = {}
    running_services: List[str] = []
    installed_updates: List[str] = []
    agent_status: str = "healthy"


class CommandResultRequest(BaseModel):
    command_id: str
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: int = 0


class QueueCommandRequest(BaseModel):
    agent_id: str
    command_type: str
    payload: Dict[str, Any] = {}
    priority: str = "normal"
    expires_in_seconds: int = 3600


class AgentConfigUpdate(BaseModel):
    checkin_interval_seconds: Optional[int] = None
    command_poll_interval_seconds: Optional[int] = None
    log_level: Optional[str] = None
    features_enabled: Optional[List[str]] = None
    proxy_config: Optional[Dict[str, str]] = None
    bandwidth_limit: Optional[int] = None


class UpdateCheckRequest(BaseModel):
    current_version: str


# ========== Helper: Agent Auth ==========

def _authenticate_agent(
    x_agent_id: str = Header(None, alias="X-Agent-ID"),
    x_agent_key: str = Header(None, alias="X-Agent-Key"),
) -> str:
    """Validate agent identity via X-Agent-ID + X-Agent-Key headers."""
    if not x_agent_id or not x_agent_key:
        raise HTTPException(status_code=401, detail="Missing agent credentials")
    if not agent_service.authenticate_agent(x_agent_id, x_agent_key):
        raise HTTPException(status_code=403, detail="Invalid agent credentials")
    return x_agent_id


# ========== Agent Endpoints (called by agent binary) ==========

@router.post("/register")
async def register_agent(data: AgentRegisterRequest):
    """Register a new agent and receive API key + config."""
    result = agent_service.register_agent(data.model_dump(exclude_none=True))
    return result


@router.post("/checkin")
async def agent_checkin(
    data: AgentCheckinRequest,
    agent_id: str = Depends(_authenticate_agent),
):
    """Agent heartbeat. Sends metrics, receives pending commands."""
    result = agent_service.agent_checkin(agent_id, data.model_dump())
    return result


@router.get("/commands")
async def get_pending_commands(
    agent_id: str = Depends(_authenticate_agent),
):
    """Poll for pending commands."""
    commands = agent_service.get_pending_commands(agent_id)
    return {
        "commands": [
            {
                "command_id": c.command_id,
                "command_type": c.command_type,
                "payload": c.payload,
                "priority": c.priority,
            }
            for c in commands
        ]
    }


@router.post("/commands/{command_id}/result")
async def submit_command_result(
    command_id: str,
    data: CommandResultRequest,
    agent_id: str = Depends(_authenticate_agent),
):
    """Submit command execution result."""
    result_data = data.model_dump()
    result_data["command_id"] = command_id
    result = agent_service.submit_command_result(agent_id, result_data)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/config")
async def get_agent_config(
    agent_id: str = Depends(_authenticate_agent),
):
    """Get current agent configuration."""
    config = agent_service.get_agent_config(agent_id)
    if not config:
        raise HTTPException(status_code=404, detail="Agent not found")
    return config


@router.get("/update/check")
async def check_for_update(
    current_version: str = Query(...),
    agent_id: str = Depends(_authenticate_agent),
):
    """Check if a newer agent version is available."""
    update = agent_service.check_for_update(agent_id, current_version)
    if update:
        return {"update_available": True, **update}
    return {"update_available": False}


@router.get("/update/download/{version}")
async def download_update(
    version: str,
    agent_id: str = Depends(_authenticate_agent),
):
    """
    Get download URL for a specific agent update version.
    The actual binary download is served from the URL returned.
    """
    update = agent_service.check_for_update(agent_id, "0.0.0")  # force match
    if update and update.get("version") == version:
        return {
            "version": version,
            "download_url": update["download_url"],
            "checksum_sha256": update["checksum_sha256"],
        }
    raise HTTPException(status_code=404, detail="Update version not found")


# ========== Admin Endpoints (dashboard / fleet management) ==========

@router.get("/agents")
async def list_agents(
    status: Optional[str] = None,
    os_type: Optional[str] = None,
    hostname: Optional[str] = None,
    _user=Depends(get_current_user),
):
    """List all registered agents with optional filters."""
    filters = {}
    if status:
        filters["status"] = status
    if os_type:
        filters["os_type"] = os_type
    if hostname:
        filters["hostname"] = hostname
    agents = agent_service.list_agents(filters)
    return {"agents": agents, "total": len(agents)}


@router.get("/agents/{agent_id}")
async def get_agent_detail(
    agent_id: str,
    _user=Depends(get_current_user),
):
    """Get detailed info for a specific agent."""
    detail = agent_service.get_agent_detail(agent_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Agent not found")
    return detail


@router.delete("/agents/{agent_id}")
async def revoke_agent(
    agent_id: str,
    _user=Depends(get_current_user),
):
    """Revoke an agent (deactivate its API key)."""
    if agent_service.revoke_agent(agent_id):
        return {"status": "revoked", "agent_id": agent_id}
    raise HTTPException(status_code=404, detail="Agent not found")


@router.post("/agents/{agent_id}/rotate-key")
async def rotate_agent_key(
    agent_id: str,
    _user=Depends(get_current_user),
):
    """Rotate an agent's API key. Returns the new key (once)."""
    new_key = agent_service.rotate_api_key(agent_id)
    if new_key:
        return {"agent_id": agent_id, "new_api_key": new_key}
    raise HTTPException(status_code=404, detail="Agent not found or revoked")


@router.put("/agents/{agent_id}/config")
async def update_agent_config(
    agent_id: str,
    data: AgentConfigUpdate,
    _user=Depends(get_current_user),
):
    """Push configuration changes to an agent."""
    config_data = {k: v for k, v in data.model_dump().items() if v is not None}
    if not config_data:
        raise HTTPException(status_code=400, detail="No config fields provided")
    result = agent_service.update_agent_config(agent_id, config_data)
    return result


@router.get("/dashboard")
async def get_dashboard(
    _user=Depends(get_current_user),
):
    """Agent fleet dashboard statistics."""
    return agent_service.get_dashboard()


# ========== Admin: Queue a command (not called by agent) ==========

@router.post("/agents/{agent_id}/commands")
async def queue_command_for_agent(
    agent_id: str,
    data: QueueCommandRequest,
    _user=Depends(get_current_user),
):
    """Queue a command for a specific agent (admin action)."""
    cmd = agent_service.queue_command(
        agent_id=agent_id,
        command_type=data.command_type,
        payload=data.payload,
        priority=data.priority,
        expires_in_seconds=data.expires_in_seconds,
    )
    return {
        "command_id": cmd.command_id,
        "agent_id": agent_id,
        "command_type": cmd.command_type,
        "status": cmd.status,
        "queued_at": cmd.queued_at.isoformat(),
    }


@router.get("/agents/{agent_id}/health")
async def get_agent_health(
    agent_id: str,
    _user=Depends(get_current_user),
):
    """Get health metrics for a specific agent."""
    health = agent_service.get_agent_health(agent_id)
    if not health:
        raise HTTPException(status_code=404, detail="Agent not found")
    return health
