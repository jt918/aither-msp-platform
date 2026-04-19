"""
AITHER Platform - PAM (Privileged Access Management) Service
Credential vaulting, JIT access, session recording, and privileged account lifecycle

Provides:
- Credential vault management
- Vaulted credential CRUD with encrypted password references
- Just-in-time checkout/checkin with expiration
- Access request workflows (request -> approve/deny)
- Session recording with command logging
- Credential rotation with configurable policies
- Compliance auditing and high-risk session detection
- Dashboard metrics

G-46: DB persistence with in-memory fallback.
"""

import uuid
import string
import secrets
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.pam import (
        CredentialVaultModel,
        VaultedCredentialModel,
        AccessSessionModel,
        AccessRequestModel,
        RotationPolicyModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class CredentialType(str, Enum):
    """Types of privileged credentials"""
    ADMIN_ACCOUNT = "admin_account"
    SERVICE_ACCOUNT = "service_account"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    DATABASE = "database"
    NETWORK_DEVICE = "network_device"
    CLOUD_IAM = "cloud_iam"
    ROOT_ACCOUNT = "root_account"


class SessionStatus(str, Enum):
    """Access session status"""
    ACTIVE = "active"
    COMPLETED = "completed"
    TERMINATED = "terminated"
    EXPIRED = "expired"


class RequestStatus(str, Enum):
    """Access request status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class CredentialVault:
    """A credential vault belonging to a client"""
    vault_id: str
    client_id: str
    name: str
    description: str = ""
    credentials: List[str] = field(default_factory=list)  # cred_id list
    access_policy: Dict[str, Any] = field(default_factory=dict)
    credential_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class VaultedCredential:
    """A single vaulted credential"""
    cred_id: str
    vault_id: str
    name: str
    credential_type: CredentialType = CredentialType.ADMIN_ACCOUNT
    username: str = ""
    encrypted_password: str = ""
    hostname: str = ""
    port: Optional[int] = None
    notes: str = ""
    last_rotated: Optional[datetime] = None
    rotation_interval_days: int = 90
    is_checked_out: bool = False
    checked_out_by: Optional[str] = None
    checkout_expires_at: Optional[datetime] = None
    access_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class AccessSession:
    """Privileged access session with command recording"""
    session_id: str
    cred_id: str
    user_id: str
    purpose: str = ""
    status: SessionStatus = SessionStatus.ACTIVE
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    duration_seconds: int = 0
    commands_logged: List[Dict[str, Any]] = field(default_factory=list)
    ip_address: str = ""
    approval_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AccessRequest:
    """Just-in-time access request"""
    request_id: str
    user_id: str
    cred_id: str
    purpose: str = ""
    urgency: str = "normal"
    status: RequestStatus = RequestStatus.PENDING
    requested_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    max_duration_minutes: int = 60
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RotationPolicy:
    """Credential rotation policy"""
    policy_id: str
    name: str
    description: str = ""
    credential_types: List[str] = field(default_factory=list)
    rotation_interval_days: int = 90
    complexity_requirements: Dict[str, Any] = field(default_factory=dict)
    notify_on_rotation: bool = True
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _vault_from_row(row) -> CredentialVault:
    return CredentialVault(
        vault_id=row.vault_id,
        client_id=row.client_id,
        name=row.name,
        description=row.description or "",
        credentials=[],
        access_policy=row.access_policy or {},
        credential_count=row.credential_count or 0,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _credential_from_row(row) -> VaultedCredential:
    return VaultedCredential(
        cred_id=row.cred_id,
        vault_id=row.vault_id,
        name=row.name,
        credential_type=CredentialType(row.credential_type) if row.credential_type else CredentialType.ADMIN_ACCOUNT,
        username=row.username or "",
        encrypted_password=row.encrypted_password or "",
        hostname=row.hostname or "",
        port=row.port,
        notes=row.notes or "",
        last_rotated=row.last_rotated,
        rotation_interval_days=row.rotation_interval_days or 90,
        is_checked_out=row.is_checked_out or False,
        checked_out_by=row.checked_out_by,
        checkout_expires_at=row.checkout_expires_at,
        access_count=row.access_count or 0,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _session_from_row(row) -> AccessSession:
    return AccessSession(
        session_id=row.session_id,
        cred_id=row.cred_id,
        user_id=row.user_id,
        purpose=row.purpose or "",
        status=SessionStatus(row.status) if row.status else SessionStatus.ACTIVE,
        started_at=row.started_at,
        ended_at=row.ended_at,
        duration_seconds=row.duration_seconds or 0,
        commands_logged=row.commands_logged or [],
        ip_address=row.ip_address or "",
        approval_id=row.approval_id,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _request_from_row(row) -> AccessRequest:
    return AccessRequest(
        request_id=row.request_id,
        user_id=row.user_id,
        cred_id=row.cred_id,
        purpose=row.purpose or "",
        urgency=row.urgency or "normal",
        status=RequestStatus(row.status) if row.status else RequestStatus.PENDING,
        requested_at=row.requested_at,
        approved_by=row.approved_by,
        approved_at=row.approved_at,
        expires_at=row.expires_at,
        max_duration_minutes=row.max_duration_minutes or 60,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _policy_from_row(row) -> RotationPolicy:
    return RotationPolicy(
        policy_id=row.policy_id,
        name=row.name,
        description=row.description or "",
        credential_types=row.credential_types or [],
        rotation_interval_days=row.rotation_interval_days or 90,
        complexity_requirements=row.complexity_requirements or {},
        notify_on_rotation=row.notify_on_rotation if row.notify_on_rotation is not None else True,
        enabled=row.enabled if row.enabled is not None else True,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


# ============================================================
# Password utilities
# ============================================================

def _generate_password(length: int = 24, uppercase: bool = True, lowercase: bool = True,
                       digits: bool = True, special: bool = True) -> str:
    """Generate a cryptographically secure password."""
    chars = ""
    required: List[str] = []
    if uppercase:
        chars += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if lowercase:
        chars += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if digits:
        chars += string.digits
        required.append(secrets.choice(string.digits))
    if special:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        required.append(secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"))
    if not chars:
        chars = string.ascii_letters + string.digits
    remaining = length - len(required)
    password_chars = required + [secrets.choice(chars) for _ in range(max(0, remaining))]
    # Shuffle
    result = list(password_chars)
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]
    return "".join(result)


def _encrypt_password(password: str) -> str:
    """Encrypt password for storage. Uses SHA-256 hash as reference token.
    In production, use a proper vault (HashiCorp Vault, Azure Key Vault, etc.)."""
    salt = secrets.token_hex(8)
    hashed = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"enc:v1:{salt}:{hashed}"


def _mask_password(encrypted: str) -> str:
    """Return masked representation."""
    return "********"


class PAMService:
    """
    Privileged Access Management Service

    Manages credential vaulting, just-in-time access, session recording,
    and privileged account lifecycle for MSP technicians and client environments.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._vaults: Dict[str, CredentialVault] = {}
        self._credentials: Dict[str, VaultedCredential] = {}
        self._sessions: Dict[str, AccessSession] = {}
        self._requests: Dict[str, AccessRequest] = {}
        self._policies: Dict[str, RotationPolicy] = {}

        # Password cache (cred_id -> plaintext) for active checkouts only
        self._password_cache: Dict[str, str] = {}

        # Default checkout duration in minutes
        self._default_checkout_minutes = 60

    # ============================================================
    # Vault Management
    # ============================================================

    def create_vault(self, client_id: str, name: str, description: str = "",
                     access_policy: Optional[Dict[str, Any]] = None) -> CredentialVault:
        """Create a new credential vault."""
        vault_id = f"VLT-{uuid.uuid4().hex[:8].upper()}"
        vault = CredentialVault(
            vault_id=vault_id,
            client_id=client_id,
            name=name,
            description=description,
            access_policy=access_policy or {},
        )

        if self._use_db:
            try:
                row = CredentialVaultModel(
                    vault_id=vault_id,
                    client_id=client_id,
                    name=name,
                    description=description,
                    access_policy=access_policy or {},
                    credential_count=0,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating vault: {e}")
                self.db.rollback()

        self._vaults[vault_id] = vault
        return vault

    def list_vaults(self, client_id: Optional[str] = None) -> List[CredentialVault]:
        """List all vaults, optionally filtered by client."""
        if self._use_db:
            try:
                q = self.db.query(CredentialVaultModel)
                if client_id:
                    q = q.filter(CredentialVaultModel.client_id == client_id)
                return [_vault_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error listing vaults: {e}")

        vaults = list(self._vaults.values())
        if client_id:
            vaults = [v for v in vaults if v.client_id == client_id]
        return vaults

    def get_vault(self, vault_id: str) -> Optional[CredentialVault]:
        """Get a vault by ID."""
        if self._use_db:
            try:
                row = self.db.query(CredentialVaultModel).filter(
                    CredentialVaultModel.vault_id == vault_id
                ).first()
                if row:
                    return _vault_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting vault: {e}")

        return self._vaults.get(vault_id)

    # ============================================================
    # Credential Management
    # ============================================================

    def add_credential(self, vault_id: str, name: str, credential_type: str,
                       username: str = "", password: Optional[str] = None,
                       hostname: str = "", port: Optional[int] = None,
                       notes: str = "", rotation_interval_days: int = 90) -> Optional[VaultedCredential]:
        """Add a credential to a vault."""
        vault = self.get_vault(vault_id)
        if not vault:
            logger.warning(f"Vault {vault_id} not found")
            return None

        cred_id = f"CRD-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        # Encrypt password or generate one
        if password:
            encrypted = _encrypt_password(password)
            self._password_cache[cred_id] = password
        else:
            generated = _generate_password()
            encrypted = _encrypt_password(generated)
            self._password_cache[cred_id] = generated

        try:
            cred_type = CredentialType(credential_type)
        except ValueError:
            cred_type = CredentialType.ADMIN_ACCOUNT

        cred = VaultedCredential(
            cred_id=cred_id,
            vault_id=vault_id,
            name=name,
            credential_type=cred_type,
            username=username,
            encrypted_password=encrypted,
            hostname=hostname,
            port=port,
            notes=notes,
            last_rotated=now,
            rotation_interval_days=rotation_interval_days,
        )

        if self._use_db:
            try:
                row = VaultedCredentialModel(
                    cred_id=cred_id,
                    vault_id=vault_id,
                    name=name,
                    credential_type=cred_type.value,
                    username=username,
                    encrypted_password=encrypted,
                    hostname=hostname,
                    port=port,
                    notes=notes,
                    last_rotated=now,
                    rotation_interval_days=rotation_interval_days,
                    is_checked_out=False,
                    access_count=0,
                )
                self.db.add(row)
                # Update vault credential count
                vault_row = self.db.query(CredentialVaultModel).filter(
                    CredentialVaultModel.vault_id == vault_id
                ).first()
                if vault_row:
                    vault_row.credential_count = (vault_row.credential_count or 0) + 1
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error adding credential: {e}")
                self.db.rollback()

        self._credentials[cred_id] = cred
        vault.credentials.append(cred_id)
        vault.credential_count += 1
        return cred

    def get_credential(self, cred_id: str) -> Optional[VaultedCredential]:
        """Get credential metadata (password masked)."""
        if self._use_db:
            try:
                row = self.db.query(VaultedCredentialModel).filter(
                    VaultedCredentialModel.cred_id == cred_id
                ).first()
                if row:
                    return _credential_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting credential: {e}")

        return self._credentials.get(cred_id)

    def list_credentials(self, vault_id: Optional[str] = None,
                         credential_type: Optional[str] = None) -> List[VaultedCredential]:
        """List credentials with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(VaultedCredentialModel)
                if vault_id:
                    q = q.filter(VaultedCredentialModel.vault_id == vault_id)
                if credential_type:
                    q = q.filter(VaultedCredentialModel.credential_type == credential_type)
                return [_credential_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error listing credentials: {e}")

        creds = list(self._credentials.values())
        if vault_id:
            creds = [c for c in creds if c.vault_id == vault_id]
        if credential_type:
            creds = [c for c in creds if c.credential_type.value == credential_type]
        return creds

    def update_credential(self, cred_id: str, **kwargs) -> Optional[VaultedCredential]:
        """Update credential metadata."""
        cred = self.get_credential(cred_id)
        if not cred:
            return None

        updatable = ["name", "username", "hostname", "port", "notes", "rotation_interval_days"]
        for key in updatable:
            if key in kwargs and kwargs[key] is not None:
                setattr(cred, key, kwargs[key])
        cred.updated_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(VaultedCredentialModel).filter(
                    VaultedCredentialModel.cred_id == cred_id
                ).first()
                if row:
                    for key in updatable:
                        if key in kwargs and kwargs[key] is not None:
                            setattr(row, key, kwargs[key])
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating credential: {e}")
                self.db.rollback()

        self._credentials[cred_id] = cred
        return cred

    # ============================================================
    # Checkout / Checkin (JIT Access)
    # ============================================================

    def checkout_credential(self, cred_id: str, user_id: str, purpose: str = "",
                            duration_minutes: Optional[int] = None,
                            ip_address: str = "") -> Optional[Dict[str, Any]]:
        """Check out a credential for JIT access. Returns decrypted password."""
        cred = self.get_credential(cred_id)
        if not cred:
            return None

        if cred.is_checked_out:
            # Check if checkout expired
            if cred.checkout_expires_at and datetime.now(timezone.utc) > cred.checkout_expires_at:
                self._do_checkin(cred_id, expired=True)
            else:
                return {"error": "Credential is already checked out",
                        "checked_out_by": cred.checked_out_by}

        now = datetime.now(timezone.utc)
        duration = duration_minutes or self._default_checkout_minutes
        expires_at = now + timedelta(minutes=duration)

        # Update credential state
        cred.is_checked_out = True
        cred.checked_out_by = user_id
        cred.checkout_expires_at = expires_at
        cred.access_count += 1
        cred.updated_at = now

        if self._use_db:
            try:
                row = self.db.query(VaultedCredentialModel).filter(
                    VaultedCredentialModel.cred_id == cred_id
                ).first()
                if row:
                    row.is_checked_out = True
                    row.checked_out_by = user_id
                    row.checkout_expires_at = expires_at
                    row.access_count = (row.access_count or 0) + 1
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error checking out credential: {e}")
                self.db.rollback()

        self._credentials[cred_id] = cred

        # Start an access session
        session = self.start_session(cred_id, user_id, purpose, ip_address)

        # Return the password from cache
        password = self._password_cache.get(cred_id, _mask_password(cred.encrypted_password))

        return {
            "cred_id": cred_id,
            "username": cred.username,
            "password": password,
            "hostname": cred.hostname,
            "port": cred.port,
            "expires_at": expires_at.isoformat(),
            "session_id": session.session_id if session else None,
        }

    def checkin_credential(self, cred_id: str) -> bool:
        """Check in a credential, ending the active session."""
        return self._do_checkin(cred_id)

    def force_checkin(self, cred_id: str, reason: str = "") -> bool:
        """Force check in a credential (admin action)."""
        result = self._do_checkin(cred_id, forced=True)
        if result:
            logger.warning(f"Force checkin of {cred_id}: {reason}")
        return result

    def _do_checkin(self, cred_id: str, expired: bool = False, forced: bool = False) -> bool:
        """Internal checkin logic."""
        cred = self.get_credential(cred_id)
        if not cred:
            return False

        cred.is_checked_out = False
        cred.checked_out_by = None
        cred.checkout_expires_at = None
        cred.updated_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(VaultedCredentialModel).filter(
                    VaultedCredentialModel.cred_id == cred_id
                ).first()
                if row:
                    row.is_checked_out = False
                    row.checked_out_by = None
                    row.checkout_expires_at = None
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error checking in credential: {e}")
                self.db.rollback()

        self._credentials[cred_id] = cred

        # End any active sessions for this credential
        for sess in self._get_active_sessions_for_cred(cred_id):
            status = SessionStatus.EXPIRED if expired else (
                SessionStatus.TERMINATED if forced else SessionStatus.COMPLETED
            )
            self._end_session_internal(sess.session_id, status)

        return True

    # ============================================================
    # Access Requests
    # ============================================================

    def request_access(self, user_id: str, cred_id: str, purpose: str = "",
                       urgency: str = "normal", max_duration_minutes: int = 60) -> Optional[AccessRequest]:
        """Submit a JIT access request."""
        cred = self.get_credential(cred_id)
        if not cred:
            return None

        request_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        request = AccessRequest(
            request_id=request_id,
            user_id=user_id,
            cred_id=cred_id,
            purpose=purpose,
            urgency=urgency,
            requested_at=now,
            max_duration_minutes=max_duration_minutes,
        )

        if self._use_db:
            try:
                row = AccessRequestModel(
                    request_id=request_id,
                    user_id=user_id,
                    cred_id=cred_id,
                    purpose=purpose,
                    urgency=urgency,
                    status=RequestStatus.PENDING.value,
                    requested_at=now,
                    max_duration_minutes=max_duration_minutes,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating access request: {e}")
                self.db.rollback()

        self._requests[request_id] = request
        return request

    def approve_request(self, request_id: str, approved_by: str) -> Optional[AccessRequest]:
        """Approve a pending access request."""
        request = self._get_request(request_id)
        if not request or request.status != RequestStatus.PENDING:
            return None

        now = datetime.now(timezone.utc)
        request.status = RequestStatus.APPROVED
        request.approved_by = approved_by
        request.approved_at = now
        request.expires_at = now + timedelta(minutes=request.max_duration_minutes)

        if self._use_db:
            try:
                row = self.db.query(AccessRequestModel).filter(
                    AccessRequestModel.request_id == request_id
                ).first()
                if row:
                    row.status = RequestStatus.APPROVED.value
                    row.approved_by = approved_by
                    row.approved_at = now
                    row.expires_at = request.expires_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error approving request: {e}")
                self.db.rollback()

        self._requests[request_id] = request
        return request

    def deny_request(self, request_id: str, denied_by: str, reason: str = "") -> Optional[AccessRequest]:
        """Deny a pending access request."""
        request = self._get_request(request_id)
        if not request or request.status != RequestStatus.PENDING:
            return None

        request.status = RequestStatus.DENIED
        request.approved_by = denied_by  # reuse field for who denied

        if self._use_db:
            try:
                row = self.db.query(AccessRequestModel).filter(
                    AccessRequestModel.request_id == request_id
                ).first()
                if row:
                    row.status = RequestStatus.DENIED.value
                    row.approved_by = denied_by
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error denying request: {e}")
                self.db.rollback()

        self._requests[request_id] = request
        return request

    def get_pending_requests(self, cred_id: Optional[str] = None) -> List[AccessRequest]:
        """Get all pending access requests."""
        if self._use_db:
            try:
                q = self.db.query(AccessRequestModel).filter(
                    AccessRequestModel.status == RequestStatus.PENDING.value
                )
                if cred_id:
                    q = q.filter(AccessRequestModel.cred_id == cred_id)
                return [_request_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error getting pending requests: {e}")

        reqs = [r for r in self._requests.values() if r.status == RequestStatus.PENDING]
        if cred_id:
            reqs = [r for r in reqs if r.cred_id == cred_id]
        return reqs

    def _get_request(self, request_id: str) -> Optional[AccessRequest]:
        if self._use_db:
            try:
                row = self.db.query(AccessRequestModel).filter(
                    AccessRequestModel.request_id == request_id
                ).first()
                if row:
                    return _request_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting request: {e}")
        return self._requests.get(request_id)

    # ============================================================
    # Session Management
    # ============================================================

    def start_session(self, cred_id: str, user_id: str, purpose: str = "",
                      ip_address: str = "", approval_id: Optional[str] = None) -> Optional[AccessSession]:
        """Start a privileged access session."""
        session_id = f"SES-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        session = AccessSession(
            session_id=session_id,
            cred_id=cred_id,
            user_id=user_id,
            purpose=purpose,
            status=SessionStatus.ACTIVE,
            started_at=now,
            ip_address=ip_address,
            approval_id=approval_id,
        )

        if self._use_db:
            try:
                row = AccessSessionModel(
                    session_id=session_id,
                    cred_id=cred_id,
                    user_id=user_id,
                    purpose=purpose,
                    status=SessionStatus.ACTIVE.value,
                    started_at=now,
                    ip_address=ip_address,
                    approval_id=approval_id,
                    commands_logged=[],
                    duration_seconds=0,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error starting session: {e}")
                self.db.rollback()

        self._sessions[session_id] = session
        return session

    def end_session(self, session_id: str) -> Optional[AccessSession]:
        """End a session normally."""
        return self._end_session_internal(session_id, SessionStatus.COMPLETED)

    def terminate_session(self, session_id: str, reason: str = "") -> Optional[AccessSession]:
        """Terminate a session (admin action)."""
        session = self._end_session_internal(session_id, SessionStatus.TERMINATED)
        if session:
            logger.warning(f"Session {session_id} terminated: {reason}")
        return session

    def _end_session_internal(self, session_id: str, status: SessionStatus) -> Optional[AccessSession]:
        """Internal session ending logic."""
        session = self._get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return None

        now = datetime.now(timezone.utc)
        session.status = status
        session.ended_at = now
        if session.started_at:
            session.duration_seconds = int((now - session.started_at).total_seconds())

        if self._use_db:
            try:
                row = self.db.query(AccessSessionModel).filter(
                    AccessSessionModel.session_id == session_id
                ).first()
                if row:
                    row.status = status.value
                    row.ended_at = now
                    row.duration_seconds = session.duration_seconds
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error ending session: {e}")
                self.db.rollback()

        self._sessions[session_id] = session
        return session

    def log_command(self, session_id: str, command: str, output: str = "",
                    exit_code: Optional[int] = None) -> bool:
        """Log a command executed during a session."""
        session = self._get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return False

        entry = {
            "command": command,
            "output": output[:1000] if output else "",
            "exit_code": exit_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        session.commands_logged.append(entry)

        if self._use_db:
            try:
                row = self.db.query(AccessSessionModel).filter(
                    AccessSessionModel.session_id == session_id
                ).first()
                if row:
                    cmds = row.commands_logged or []
                    cmds.append(entry)
                    row.commands_logged = cmds
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error logging command: {e}")
                self.db.rollback()

        self._sessions[session_id] = session
        return True

    def get_session_recording(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get full session recording including all commands."""
        session = self._get_session(session_id)
        if not session:
            return None

        return {
            "session_id": session.session_id,
            "cred_id": session.cred_id,
            "user_id": session.user_id,
            "purpose": session.purpose,
            "status": session.status.value,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "ended_at": session.ended_at.isoformat() if session.ended_at else None,
            "duration_seconds": session.duration_seconds,
            "commands": session.commands_logged,
            "command_count": len(session.commands_logged),
            "ip_address": session.ip_address,
        }

    def _get_session(self, session_id: str) -> Optional[AccessSession]:
        if self._use_db:
            try:
                row = self.db.query(AccessSessionModel).filter(
                    AccessSessionModel.session_id == session_id
                ).first()
                if row:
                    return _session_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting session: {e}")
        return self._sessions.get(session_id)

    def _get_active_sessions_for_cred(self, cred_id: str) -> List[AccessSession]:
        if self._use_db:
            try:
                rows = self.db.query(AccessSessionModel).filter(
                    AccessSessionModel.cred_id == cred_id,
                    AccessSessionModel.status == SessionStatus.ACTIVE.value,
                ).all()
                return [_session_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error getting active sessions: {e}")

        return [s for s in self._sessions.values()
                if s.cred_id == cred_id and s.status == SessionStatus.ACTIVE]

    # ============================================================
    # Credential Rotation
    # ============================================================

    def rotate_credential(self, cred_id: str, new_password: Optional[str] = None,
                          complexity: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Rotate a credential's password."""
        cred = self.get_credential(cred_id)
        if not cred:
            return None

        if cred.is_checked_out:
            return {"error": "Cannot rotate credential while checked out"}

        # Generate or use provided password
        if new_password:
            password = new_password
        else:
            comp = complexity or {}
            password = _generate_password(
                length=comp.get("length", 24),
                uppercase=comp.get("uppercase", True),
                lowercase=comp.get("lowercase", True),
                digits=comp.get("digits", True),
                special=comp.get("special", True),
            )

        encrypted = _encrypt_password(password)
        now = datetime.now(timezone.utc)

        cred.encrypted_password = encrypted
        cred.last_rotated = now
        cred.updated_at = now
        self._password_cache[cred_id] = password

        if self._use_db:
            try:
                row = self.db.query(VaultedCredentialModel).filter(
                    VaultedCredentialModel.cred_id == cred_id
                ).first()
                if row:
                    row.encrypted_password = encrypted
                    row.last_rotated = now
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error rotating credential: {e}")
                self.db.rollback()

        self._credentials[cred_id] = cred
        return {
            "cred_id": cred_id,
            "rotated_at": now.isoformat(),
            "next_rotation": (now + timedelta(days=cred.rotation_interval_days)).isoformat(),
        }

    def rotate_all_expired(self) -> List[Dict[str, Any]]:
        """Rotate all credentials past their rotation interval."""
        results = []
        now = datetime.now(timezone.utc)

        creds = self.list_credentials()
        for cred in creds:
            if cred.last_rotated:
                next_rotation = cred.last_rotated + timedelta(days=cred.rotation_interval_days)
                if now > next_rotation and not cred.is_checked_out:
                    result = self.rotate_credential(cred.cred_id)
                    if result and "error" not in result:
                        results.append(result)

        return results

    # ============================================================
    # Rotation Policies
    # ============================================================

    def create_rotation_policy(self, name: str, credential_types: Optional[List[str]] = None,
                               rotation_interval_days: int = 90,
                               complexity_requirements: Optional[Dict[str, Any]] = None,
                               notify_on_rotation: bool = True,
                               description: str = "") -> RotationPolicy:
        """Create a rotation policy."""
        policy_id = f"POL-{uuid.uuid4().hex[:8].upper()}"

        policy = RotationPolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            credential_types=credential_types or [],
            rotation_interval_days=rotation_interval_days,
            complexity_requirements=complexity_requirements or {},
            notify_on_rotation=notify_on_rotation,
        )

        if self._use_db:
            try:
                row = RotationPolicyModel(
                    policy_id=policy_id,
                    name=name,
                    description=description,
                    credential_types=credential_types or [],
                    rotation_interval_days=rotation_interval_days,
                    complexity_requirements=complexity_requirements or {},
                    notify_on_rotation=notify_on_rotation,
                    enabled=True,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating rotation policy: {e}")
                self.db.rollback()

        self._policies[policy_id] = policy
        return policy

    def get_policies(self) -> List[RotationPolicy]:
        """Get all rotation policies."""
        if self._use_db:
            try:
                return [_policy_from_row(r) for r in self.db.query(RotationPolicyModel).all()]
            except Exception as e:
                logger.error(f"DB error getting policies: {e}")

        return list(self._policies.values())

    def check_rotation_compliance(self) -> Dict[str, Any]:
        """Check all credentials against rotation policies."""
        now = datetime.now(timezone.utc)
        compliant = 0
        non_compliant = 0
        overdue: List[Dict[str, Any]] = []

        creds = self.list_credentials()
        for cred in creds:
            if cred.last_rotated:
                next_rotation = cred.last_rotated + timedelta(days=cred.rotation_interval_days)
                if now > next_rotation:
                    non_compliant += 1
                    days_overdue = (now - next_rotation).days
                    overdue.append({
                        "cred_id": cred.cred_id,
                        "name": cred.name,
                        "credential_type": cred.credential_type.value,
                        "days_overdue": days_overdue,
                        "last_rotated": cred.last_rotated.isoformat(),
                    })
                else:
                    compliant += 1
            else:
                non_compliant += 1
                overdue.append({
                    "cred_id": cred.cred_id,
                    "name": cred.name,
                    "credential_type": cred.credential_type.value,
                    "days_overdue": -1,
                    "last_rotated": None,
                })

        total = compliant + non_compliant
        return {
            "total_credentials": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "compliance_rate": round(compliant / total * 100, 1) if total else 100.0,
            "overdue_credentials": overdue,
        }

    # ============================================================
    # Audit & Reporting
    # ============================================================

    def get_access_audit_trail(self, cred_id: Optional[str] = None,
                               user_id: Optional[str] = None,
                               limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit trail of access sessions."""
        if self._use_db:
            try:
                q = self.db.query(AccessSessionModel)
                if cred_id:
                    q = q.filter(AccessSessionModel.cred_id == cred_id)
                if user_id:
                    q = q.filter(AccessSessionModel.user_id == user_id)
                q = q.order_by(AccessSessionModel.created_at.desc()).limit(limit)
                sessions = [_session_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error getting audit trail: {e}")
                sessions = []
        else:
            sessions = list(self._sessions.values())
            if cred_id:
                sessions = [s for s in sessions if s.cred_id == cred_id]
            if user_id:
                sessions = [s for s in sessions if s.user_id == user_id]
            sessions = sorted(sessions, key=lambda s: s.created_at, reverse=True)[:limit]

        return [
            {
                "session_id": s.session_id,
                "cred_id": s.cred_id,
                "user_id": s.user_id,
                "purpose": s.purpose,
                "status": s.status.value,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "ended_at": s.ended_at.isoformat() if s.ended_at else None,
                "duration_seconds": s.duration_seconds,
                "command_count": len(s.commands_logged),
                "ip_address": s.ip_address,
            }
            for s in sessions
        ]

    def get_high_risk_sessions(self) -> List[Dict[str, Any]]:
        """Identify high-risk sessions based on heuristics."""
        all_sessions = self.get_access_audit_trail(limit=500)
        high_risk = []

        for s in all_sessions:
            risk_score = 0
            risk_factors = []

            # Long sessions
            if s["duration_seconds"] > 3600:
                risk_score += 30
                risk_factors.append("session_over_1h")

            # Many commands
            if s["command_count"] > 50:
                risk_score += 25
                risk_factors.append("high_command_count")

            # Terminated sessions
            if s["status"] == SessionStatus.TERMINATED.value:
                risk_score += 40
                risk_factors.append("terminated")

            # Active sessions running long
            if s["status"] == SessionStatus.ACTIVE.value and s["duration_seconds"] > 1800:
                risk_score += 35
                risk_factors.append("long_running_active")

            if risk_score >= 25:
                s["risk_score"] = risk_score
                s["risk_factors"] = risk_factors
                high_risk.append(s)

        high_risk.sort(key=lambda x: x["risk_score"], reverse=True)
        return high_risk

    def get_dashboard(self) -> Dict[str, Any]:
        """Get PAM dashboard metrics."""
        vaults = self.list_vaults()
        creds = self.list_credentials()
        now = datetime.now(timezone.utc)

        checked_out = [c for c in creds if c.is_checked_out]
        pending_requests = self.get_pending_requests()
        compliance = self.check_rotation_compliance()

        # Count by type
        type_counts: Dict[str, int] = {}
        for c in creds:
            t = c.credential_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        # Active sessions
        active_sessions = []
        if self._use_db:
            try:
                rows = self.db.query(AccessSessionModel).filter(
                    AccessSessionModel.status == SessionStatus.ACTIVE.value
                ).all()
                active_sessions = [_session_from_row(r) for r in rows]
            except Exception:
                pass
        else:
            active_sessions = [s for s in self._sessions.values()
                               if s.status == SessionStatus.ACTIVE]

        return {
            "total_vaults": len(vaults),
            "total_credentials": len(creds),
            "checked_out": len(checked_out),
            "active_sessions": len(active_sessions),
            "pending_requests": len(pending_requests),
            "credential_types": type_counts,
            "compliance_rate": compliance["compliance_rate"],
            "overdue_rotations": compliance["non_compliant"],
            "high_risk_sessions": len(self.get_high_risk_sessions()),
        }
