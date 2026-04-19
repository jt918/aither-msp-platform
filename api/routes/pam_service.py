"""
API Routes for Privileged Access Management (PAM)
Uses PAMService for all operations
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.pam_service import (
    PAMService,
    CredentialType,
    SessionStatus,
    RequestStatus,
)

router = APIRouter(prefix="/pam", tags=["PAM"])


def _init_pam_service() -> PAMService:
    """Initialize PAMService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return PAMService(db=db)
    except Exception:
        return PAMService()


# Initialize service with DB persistence
pam_service = _init_pam_service()


# ========== Request/Response Models ==========

class VaultCreate(BaseModel):
    client_id: str
    name: str
    description: str = ""
    access_policy: Dict[str, Any] = {}


class CredentialAdd(BaseModel):
    vault_id: str
    name: str
    credential_type: str = "admin_account"
    username: str = ""
    password: Optional[str] = None
    hostname: str = ""
    port: Optional[int] = None
    notes: str = ""
    rotation_interval_days: int = 90


class CredentialUpdate(BaseModel):
    name: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    notes: Optional[str] = None
    rotation_interval_days: Optional[int] = None


class CheckoutRequest(BaseModel):
    user_id: str
    purpose: str = ""
    duration_minutes: Optional[int] = None
    ip_address: str = ""


class ForceCheckinRequest(BaseModel):
    reason: str = ""


class AccessRequestCreate(BaseModel):
    user_id: str
    cred_id: str
    purpose: str = ""
    urgency: str = "normal"
    max_duration_minutes: int = 60


class ApprovalAction(BaseModel):
    approved_by: str


class DenialAction(BaseModel):
    denied_by: str
    reason: str = ""


class SessionStart(BaseModel):
    cred_id: str
    user_id: str
    purpose: str = ""
    ip_address: str = ""
    approval_id: Optional[str] = None


class CommandLog(BaseModel):
    command: str
    output: str = ""
    exit_code: Optional[int] = None


class TerminateSession(BaseModel):
    reason: str = ""


class RotateCredential(BaseModel):
    new_password: Optional[str] = None
    complexity: Optional[Dict[str, Any]] = None


class RotationPolicyCreate(BaseModel):
    name: str
    description: str = ""
    credential_types: List[str] = []
    rotation_interval_days: int = 90
    complexity_requirements: Dict[str, Any] = {}
    notify_on_rotation: bool = True


# ========== Helper Functions ==========

def vault_to_dict(vault) -> dict:
    return {
        "vault_id": vault.vault_id,
        "client_id": vault.client_id,
        "name": vault.name,
        "description": vault.description,
        "credential_count": vault.credential_count,
        "access_policy": vault.access_policy,
        "created_at": vault.created_at.isoformat() if vault.created_at else None,
        "updated_at": vault.updated_at.isoformat() if vault.updated_at else None,
    }


def credential_to_dict(cred) -> dict:
    _ct = cred.credential_type
    return {
        "cred_id": cred.cred_id,
        "vault_id": cred.vault_id,
        "name": cred.name,
        "credential_type": _ct.value if hasattr(_ct, "value") else str(_ct),
        "username": cred.username,
        "hostname": cred.hostname,
        "port": cred.port,
        "notes": cred.notes,
        "last_rotated": cred.last_rotated.isoformat() if cred.last_rotated else None,
        "rotation_interval_days": cred.rotation_interval_days,
        "is_checked_out": cred.is_checked_out,
        "checked_out_by": cred.checked_out_by,
        "checkout_expires_at": cred.checkout_expires_at.isoformat() if cred.checkout_expires_at else None,
        "access_count": cred.access_count,
        "created_at": cred.created_at.isoformat() if cred.created_at else None,
        "updated_at": cred.updated_at.isoformat() if cred.updated_at else None,
    }


def request_to_dict(req) -> dict:
    _st = req.status
    return {
        "request_id": req.request_id,
        "user_id": req.user_id,
        "cred_id": req.cred_id,
        "purpose": req.purpose,
        "urgency": req.urgency,
        "status": _st.value if hasattr(_st, "value") else str(_st),
        "requested_at": req.requested_at.isoformat() if req.requested_at else None,
        "approved_by": req.approved_by,
        "approved_at": req.approved_at.isoformat() if req.approved_at else None,
        "expires_at": req.expires_at.isoformat() if req.expires_at else None,
        "max_duration_minutes": req.max_duration_minutes,
    }


def session_to_dict(session) -> dict:
    _st = session.status
    return {
        "session_id": session.session_id,
        "cred_id": session.cred_id,
        "user_id": session.user_id,
        "purpose": session.purpose,
        "status": _st.value if hasattr(_st, "value") else str(_st),
        "started_at": session.started_at.isoformat() if session.started_at else None,
        "ended_at": session.ended_at.isoformat() if session.ended_at else None,
        "duration_seconds": session.duration_seconds,
        "command_count": len(session.commands_logged),
        "ip_address": session.ip_address,
        "approval_id": session.approval_id,
    }


def policy_to_dict(policy) -> dict:
    return {
        "policy_id": policy.policy_id,
        "name": policy.name,
        "description": policy.description,
        "credential_types": policy.credential_types,
        "rotation_interval_days": policy.rotation_interval_days,
        "complexity_requirements": policy.complexity_requirements,
        "notify_on_rotation": policy.notify_on_rotation,
        "enabled": policy.enabled,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }


# ========== Vault Routes ==========

@router.post("/vaults")
async def create_vault(data: VaultCreate):
    """Create a new credential vault."""
    vault = pam_service.create_vault(
        client_id=data.client_id,
        name=data.name,
        description=data.description,
        access_policy=data.access_policy,
    )
    return {"status": "created", "vault": vault_to_dict(vault)}


@router.get("/vaults")
async def list_vaults(client_id: Optional[str] = Query(None)):
    """List all credential vaults."""
    vaults = pam_service.list_vaults(client_id=client_id)
    return {"vaults": [vault_to_dict(v) for v in vaults], "count": len(vaults)}


@router.get("/vaults/{vault_id}")
async def get_vault(vault_id: str):
    """Get a specific vault."""
    vault = pam_service.get_vault(vault_id)
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    return vault_to_dict(vault)


# ========== Credential Routes ==========

@router.post("/credentials")
async def add_credential(data: CredentialAdd):
    """Add a credential to a vault."""
    cred = pam_service.add_credential(
        vault_id=data.vault_id,
        name=data.name,
        credential_type=data.credential_type,
        username=data.username,
        password=data.password,
        hostname=data.hostname,
        port=data.port,
        notes=data.notes,
        rotation_interval_days=data.rotation_interval_days,
    )
    if not cred:
        raise HTTPException(status_code=404, detail="Vault not found")
    return {"status": "created", "credential": credential_to_dict(cred)}


@router.get("/credentials")
async def list_credentials(
    vault_id: Optional[str] = Query(None),
    credential_type: Optional[str] = Query(None),
):
    """List credentials with optional filters."""
    creds = pam_service.list_credentials(vault_id=vault_id, credential_type=credential_type)
    return {"credentials": [credential_to_dict(c) for c in creds], "count": len(creds)}


@router.get("/credentials/{cred_id}")
async def get_credential(cred_id: str):
    """Get credential metadata (password masked)."""
    cred = pam_service.get_credential(cred_id)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    return credential_to_dict(cred)


@router.put("/credentials/{cred_id}")
async def update_credential(cred_id: str, data: CredentialUpdate):
    """Update credential metadata."""
    updates = {k: v for k, v in data.dict().items() if v is not None}
    cred = pam_service.update_credential(cred_id, **updates)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    return {"status": "updated", "credential": credential_to_dict(cred)}


# ========== Checkout / Checkin Routes ==========

@router.post("/credentials/{cred_id}/checkout")
async def checkout_credential(cred_id: str, data: CheckoutRequest):
    """Check out a credential for JIT access."""
    result = pam_service.checkout_credential(
        cred_id=cred_id,
        user_id=data.user_id,
        purpose=data.purpose,
        duration_minutes=data.duration_minutes,
        ip_address=data.ip_address,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Credential not found")
    if "error" in result:
        raise HTTPException(status_code=409, detail=result["error"])
    return {"status": "checked_out", "access": result}


@router.post("/credentials/{cred_id}/checkin")
async def checkin_credential(cred_id: str):
    """Check in a credential."""
    success = pam_service.checkin_credential(cred_id)
    if not success:
        raise HTTPException(status_code=404, detail="Credential not found or not checked out")
    return {"status": "checked_in", "cred_id": cred_id}


@router.post("/credentials/{cred_id}/force-checkin")
async def force_checkin_credential(cred_id: str, data: ForceCheckinRequest):
    """Force check in a credential (admin action)."""
    success = pam_service.force_checkin(cred_id, reason=data.reason)
    if not success:
        raise HTTPException(status_code=404, detail="Credential not found")
    return {"status": "force_checked_in", "cred_id": cred_id}


# ========== Access Request Routes ==========

@router.post("/access-requests")
async def create_access_request(data: AccessRequestCreate):
    """Submit a JIT access request."""
    request = pam_service.request_access(
        user_id=data.user_id,
        cred_id=data.cred_id,
        purpose=data.purpose,
        urgency=data.urgency,
        max_duration_minutes=data.max_duration_minutes,
    )
    if not request:
        raise HTTPException(status_code=404, detail="Credential not found")
    return {"status": "submitted", "request": request_to_dict(request)}


@router.get("/access-requests/pending")
async def get_pending_requests(cred_id: Optional[str] = Query(None)):
    """Get all pending access requests."""
    requests = pam_service.get_pending_requests(cred_id=cred_id)
    return {"requests": [request_to_dict(r) for r in requests], "count": len(requests)}


@router.post("/access-requests/{request_id}/approve")
async def approve_request(request_id: str, data: ApprovalAction):
    """Approve an access request."""
    request = pam_service.approve_request(request_id, approved_by=data.approved_by)
    if not request:
        raise HTTPException(status_code=404, detail="Request not found or not pending")
    return {"status": "approved", "request": request_to_dict(request)}


@router.post("/access-requests/{request_id}/deny")
async def deny_request(request_id: str, data: DenialAction):
    """Deny an access request."""
    request = pam_service.deny_request(request_id, denied_by=data.denied_by, reason=data.reason)
    if not request:
        raise HTTPException(status_code=404, detail="Request not found or not pending")
    return {"status": "denied", "request": request_to_dict(request)}


# ========== Session Routes ==========

@router.post("/sessions")
async def start_session(data: SessionStart):
    """Start a privileged access session."""
    session = pam_service.start_session(
        cred_id=data.cred_id,
        user_id=data.user_id,
        purpose=data.purpose,
        ip_address=data.ip_address,
        approval_id=data.approval_id,
    )
    if not session:
        raise HTTPException(status_code=500, detail="Failed to start session")
    return {"status": "started", "session": session_to_dict(session)}


@router.post("/sessions/{session_id}/end")
async def end_session(session_id: str):
    """End a session normally."""
    session = pam_service.end_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or not active")
    return {"status": "ended", "session": session_to_dict(session)}


@router.post("/sessions/{session_id}/terminate")
async def terminate_session(session_id: str, data: TerminateSession):
    """Terminate a session (admin action)."""
    session = pam_service.terminate_session(session_id, reason=data.reason)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or not active")
    return {"status": "terminated", "session": session_to_dict(session)}


@router.post("/sessions/{session_id}/commands")
async def log_command(session_id: str, data: CommandLog):
    """Log a command executed during a session."""
    success = pam_service.log_command(
        session_id=session_id,
        command=data.command,
        output=data.output,
        exit_code=data.exit_code,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or not active")
    return {"status": "logged", "session_id": session_id}


@router.get("/sessions/{session_id}/recording")
async def get_session_recording(session_id: str):
    """Get full session recording including all commands."""
    recording = pam_service.get_session_recording(session_id)
    if not recording:
        raise HTTPException(status_code=404, detail="Session not found")
    return recording


# ========== Rotation Routes ==========

@router.post("/credentials/{cred_id}/rotate")
async def rotate_credential(cred_id: str, data: RotateCredential):
    """Rotate a credential's password."""
    result = pam_service.rotate_credential(
        cred_id=cred_id,
        new_password=data.new_password,
        complexity=data.complexity,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Credential not found")
    if "error" in result:
        raise HTTPException(status_code=409, detail=result["error"])
    return {"status": "rotated", **result}


@router.post("/rotation/rotate-expired")
async def rotate_all_expired():
    """Rotate all credentials past their rotation interval."""
    results = pam_service.rotate_all_expired()
    return {"status": "completed", "rotated": results, "count": len(results)}


@router.post("/rotation/policies")
async def create_rotation_policy(data: RotationPolicyCreate):
    """Create a rotation policy."""
    policy = pam_service.create_rotation_policy(
        name=data.name,
        description=data.description,
        credential_types=data.credential_types,
        rotation_interval_days=data.rotation_interval_days,
        complexity_requirements=data.complexity_requirements,
        notify_on_rotation=data.notify_on_rotation,
    )
    return {"status": "created", "policy": policy_to_dict(policy)}


@router.get("/rotation/policies")
async def get_policies():
    """Get all rotation policies."""
    policies = pam_service.get_policies()
    return {"policies": [policy_to_dict(p) for p in policies], "count": len(policies)}


@router.get("/rotation/compliance")
async def check_rotation_compliance():
    """Check credential rotation compliance."""
    return pam_service.check_rotation_compliance()


# ========== Audit & Dashboard Routes ==========

@router.get("/audit/trail")
async def get_audit_trail(
    cred_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    """Get access audit trail."""
    trail = pam_service.get_access_audit_trail(
        cred_id=cred_id, user_id=user_id, limit=limit,
    )
    return {"audit_trail": trail, "count": len(trail)}


@router.get("/audit/high-risk")
async def get_high_risk_sessions():
    """Get high-risk sessions."""
    sessions = pam_service.get_high_risk_sessions()
    return {"high_risk_sessions": sessions, "count": len(sessions)}


@router.get("/dashboard")
async def get_dashboard():
    """Get PAM dashboard metrics."""
    return pam_service.get_dashboard()
