"""
API Routes for Security Legion - Red/Blue/Purple Team Service
Manages security persona teams, missions, and after-action reporting.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from core.database import get_sync_db

from services.msp.security_legion import (
    SecurityLegionService,
    TeamType,
    RedRole,
    BlueRole,
    PersonaStatus,
    MissionStatus,
)

router = APIRouter(prefix="/security-legion", tags=["Security Legion - Red/Blue/Purple Teams"])

# Singleton instance
_instance: Optional[SecurityLegionService] = None


def _svc() -> SecurityLegionService:
    global _instance
    if _instance is None:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            _instance = SecurityLegionService(db=db)
        except Exception:
            _instance = SecurityLegionService()
    return _instance


# ========== Pydantic Schemas ==========

class SpawnTeamRequest(BaseModel):
    client_id: str
    size: int = 4


class CustomPersonaConfig(BaseModel):
    name: str = "Agent"
    team: str = "red"
    role: str = "recon_specialist"
    specialization: str = ""
    skill_level: float = 0.7
    techniques_mastered: List[str] = []
    certifications: List[str] = []


class SpawnCustomTeamRequest(BaseModel):
    client_id: str
    team_type: str = "red_team"
    persona_configs: List[CustomPersonaConfig]


class DeployMissionRequest(BaseModel):
    team_id: str
    twin_id: str
    mission_objective: str = "Full-scope penetration test"


class TrainRequest(BaseModel):
    technique_id: str


# ========== Team Routes ==========

@router.post("/teams/red", summary="Spawn a Red Team")
async def spawn_red_team(req: SpawnTeamRequest):
    result = _svc().spawn_red_team(req.client_id, req.size)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/teams/blue", summary="Spawn a Blue Team")
async def spawn_blue_team(req: SpawnTeamRequest):
    result = _svc().spawn_blue_team(req.client_id, req.size)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/teams/purple", summary="Spawn a Purple Team")
async def spawn_purple_team(req: SpawnTeamRequest):
    result = _svc().spawn_purple_team(req.client_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/teams/custom", summary="Spawn a Custom Team")
async def spawn_custom_team(req: SpawnCustomTeamRequest):
    configs = [c.dict() for c in req.persona_configs]
    result = _svc().spawn_custom_team(req.client_id, req.team_type, configs)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.get("/teams", summary="List all teams")
async def list_teams(client_id: Optional[str] = Query(None)):
    return _svc().list_teams(client_id)


@router.get("/teams/{team_id}", summary="Get team details")
async def get_team(team_id: str):
    result = _svc().get_team(team_id)
    if not result:
        raise HTTPException(status_code=404, detail="Team not found")
    return result


@router.delete("/teams/{team_id}", summary="Disband a team")
async def disband_team(team_id: str):
    result = _svc().disband_team(team_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ========== Persona Routes ==========

@router.get("/personas", summary="List all personas")
async def list_personas(
    team: Optional[str] = Query(None, description="Filter by team: red, blue"),
    status: Optional[str] = Query(None, description="Filter by status"),
):
    return _svc().list_personas(team, status)


@router.get("/personas/{persona_id}", summary="Get persona details")
async def get_persona(persona_id: str):
    result = _svc().get_persona(persona_id)
    if not result:
        raise HTTPException(status_code=404, detail="Persona not found")
    return result


@router.post("/personas/{persona_id}/train", summary="Train persona on a technique")
async def train_persona(persona_id: str, req: TrainRequest):
    result = _svc().assign_training(persona_id, req.technique_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/personas/{persona_id}/promote", summary="Promote a high-performing persona")
async def promote_persona(persona_id: str):
    result = _svc().promote_persona(persona_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/personas/{persona_id}/retire", summary="Retire a persona")
async def retire_persona(persona_id: str):
    result = _svc().retire_persona(persona_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ========== Mission Routes ==========

@router.post("/missions/deploy", summary="Deploy a team on a mission")
async def deploy_mission(req: DeployMissionRequest):
    result = _svc().deploy_team(req.team_id, req.twin_id, req.mission_objective)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/missions/{mission_id}/execute", summary="Execute a planned mission")
async def execute_mission(mission_id: str):
    result = _svc().execute_mission(mission_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.get("/missions", summary="List all missions")
async def list_missions(
    team_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    return _svc().list_missions(team_id, status)


@router.get("/missions/{mission_id}", summary="Get mission details")
async def get_mission(mission_id: str):
    result = _svc().get_mission(mission_id)
    if not result:
        raise HTTPException(status_code=404, detail="Mission not found")
    return result


@router.post("/missions/{mission_id}/abort", summary="Abort a mission")
async def abort_mission(mission_id: str):
    result = _svc().abort_mission(mission_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ========== Report Routes ==========

@router.get("/missions/{mission_id}/report", summary="Get after-action report")
async def get_report(mission_id: str):
    result = _svc().get_report(mission_id)
    if not result:
        # Try generating one
        result = _svc().generate_after_action_report(mission_id)
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
    return result


# ========== Technique Routes ==========

@router.get("/techniques", summary="List all MITRE ATT&CK techniques")
async def list_techniques():
    return _svc().list_techniques()


@router.get("/teams/{team_id}/coverage", summary="Get technique coverage for a team")
async def get_coverage(team_id: str):
    result = _svc().get_technique_coverage(team_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ========== Leaderboard & Dashboard ==========

@router.get("/leaderboard", summary="Top persona performers")
async def leaderboard(limit: int = Query(20, ge=1, le=100)):
    return _svc().get_leaderboard(limit)


@router.get("/dashboard/{client_id}", summary="Client security dashboard")
async def dashboard(client_id: str):
    return _svc().get_dashboard(client_id)
