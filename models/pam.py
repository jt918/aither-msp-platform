"""
AITHER Platform - PAM (Privileged Access Management) Persistence Models

Tables for credential vaults, vaulted credentials, access sessions,
access requests, and rotation policies.
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON,
    Index,
)
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


# ============================================================
# PAM - Credential Vaults
# ============================================================

class CredentialVaultModel(Base):
    """Credential vault for a client."""
    __tablename__ = "pam_credential_vaults"

    id = Column(String(36), primary_key=True, default=_uuid)
    vault_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    name = Column(String(300), nullable=False)
    description = Column(Text, default="")
    access_policy = Column(JSON, default=dict)
    credential_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# PAM - Vaulted Credentials
# ============================================================

class VaultedCredentialModel(Base):
    """Individual vaulted credential."""
    __tablename__ = "pam_vaulted_credentials"

    id = Column(String(36), primary_key=True, default=_uuid)
    cred_id = Column(String(30), unique=True, nullable=False, index=True)
    vault_id = Column(String(30), nullable=False, index=True)
    name = Column(String(300), nullable=False)
    credential_type = Column(String(30), nullable=False, index=True)
    username = Column(String(200), default="")
    encrypted_password = Column(Text, default="")
    hostname = Column(String(300), default="")
    port = Column(Integer, nullable=True)
    notes = Column(Text, default="")
    last_rotated = Column(DateTime, nullable=True)
    rotation_interval_days = Column(Integer, default=90)
    is_checked_out = Column(Boolean, default=False)
    checked_out_by = Column(String(200), nullable=True)
    checkout_expires_at = Column(DateTime, nullable=True)
    access_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_pam_cred_vault_type", "vault_id", "credential_type"),
    )


# ============================================================
# PAM - Access Sessions
# ============================================================

class AccessSessionModel(Base):
    """Privileged access session recording."""
    __tablename__ = "pam_access_sessions"

    id = Column(String(36), primary_key=True, default=_uuid)
    session_id = Column(String(30), unique=True, nullable=False, index=True)
    cred_id = Column(String(30), nullable=False, index=True)
    user_id = Column(String(200), nullable=False, index=True)
    purpose = Column(Text, default="")
    status = Column(String(20), default="active", index=True)
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, default=0)
    commands_logged = Column(JSON, default=list)
    ip_address = Column(String(50), default="")
    approval_id = Column(String(30), nullable=True)
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_pam_session_cred_status", "cred_id", "status"),
    )


# ============================================================
# PAM - Access Requests
# ============================================================

class AccessRequestModel(Base):
    """Just-in-time access request."""
    __tablename__ = "pam_access_requests"

    id = Column(String(36), primary_key=True, default=_uuid)
    request_id = Column(String(30), unique=True, nullable=False, index=True)
    user_id = Column(String(200), nullable=False, index=True)
    cred_id = Column(String(30), nullable=False, index=True)
    purpose = Column(Text, default="")
    urgency = Column(String(20), default="normal")
    status = Column(String(20), default="pending", index=True)
    requested_at = Column(DateTime, nullable=True)
    approved_by = Column(String(200), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    max_duration_minutes = Column(Integer, default=60)
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_pam_request_user_status", "user_id", "status"),
    )


# ============================================================
# PAM - Rotation Policies
# ============================================================

class RotationPolicyModel(Base):
    """Credential rotation policy."""
    __tablename__ = "pam_rotation_policies"

    id = Column(String(36), primary_key=True, default=_uuid)
    policy_id = Column(String(30), unique=True, nullable=False, index=True)
    name = Column(String(300), nullable=False)
    description = Column(Text, default="")
    credential_types = Column(JSON, default=list)
    rotation_interval_days = Column(Integer, default=90)
    complexity_requirements = Column(JSON, default=dict)
    notify_on_rotation = Column(Boolean, default=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
