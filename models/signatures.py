"""
signatures.py — Aither Shield Signature Pipeline persistence models

Stores threat signatures, versioned signature databases, delta updates,
distribution tracking, and feed source configuration.

Created: 2026-04-19 (Shield Signature Update Pipeline)
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, Index, JSON,
)
from core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc)


# ── ThreatSignature ────────────────────────────────────────────────────────

class ThreatSignatureModel(Base):
    """Individual threat signature record."""
    __tablename__ = "shield_threat_signatures"

    id = Column(String(36), primary_key=True, default=_uuid)
    signature_id = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    threat_type = Column(String(30), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    hash_md5 = Column(String(32), nullable=True, index=True)
    hash_sha256 = Column(String(64), nullable=True, index=True)
    yara_rule = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    cve_id = Column(String(20), nullable=True, index=True)
    platform = Column(String(20), nullable=False, default="all")
    detection_engine = Column(String(20), nullable=False, default="signature")
    false_positive_rate = Column(Float, default=0.0)
    first_seen = Column(DateTime, default=_now)
    last_updated = Column(DateTime, default=_now)
    is_active = Column(Boolean, default=True, index=True)
    metadata_json = Column(JSON, default=dict)

    __table_args__ = (
        Index("ix_sig_type_severity", "threat_type", "severity"),
        Index("ix_sig_platform_active", "platform", "is_active"),
    )


# ── SignatureDatabase ──────────────────────────────────────────────────────

class SignatureDatabaseModel(Base):
    """Versioned snapshot of the signature database."""
    __tablename__ = "shield_signature_databases"

    id = Column(String(36), primary_key=True, default=_uuid)
    db_id = Column(String(64), nullable=False, unique=True, index=True)
    version = Column(String(20), nullable=False, index=True)
    build_number = Column(Integer, nullable=False, index=True)
    total_signatures = Column(Integer, default=0)
    new_in_version = Column(Integer, default=0)
    removed_in_version = Column(Integer, default=0)
    size_bytes = Column(Integer, default=0)
    checksum_sha256 = Column(String(64), nullable=False)
    published_at = Column(DateTime, default=_now)
    release_notes = Column(Text, nullable=True)
    signature_ids_json = Column(JSON, default=list)


# ── SignatureDelta ─────────────────────────────────────────────────────────

class SignatureDeltaModel(Base):
    """Delta update between two signature database versions."""
    __tablename__ = "shield_signature_deltas"

    id = Column(String(36), primary_key=True, default=_uuid)
    delta_id = Column(String(64), nullable=False, unique=True, index=True)
    from_version = Column(String(20), nullable=False, index=True)
    to_version = Column(String(20), nullable=False, index=True)
    added_signatures_json = Column(JSON, default=list)
    removed_signature_ids_json = Column(JSON, default=list)
    modified_signatures_json = Column(JSON, default=list)
    size_bytes = Column(Integer, default=0)
    checksum_sha256 = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=_now)

    __table_args__ = (
        Index("ix_delta_versions", "from_version", "to_version"),
    )


# ── UpdateDistribution ────────────────────────────────────────────────────

class UpdateDistributionModel(Base):
    """Tracks signature update delivery to endpoints."""
    __tablename__ = "shield_update_distributions"

    id = Column(String(36), primary_key=True, default=_uuid)
    distribution_id = Column(String(64), nullable=False, unique=True, index=True)
    db_version = Column(String(20), nullable=False, index=True)
    endpoint_id = Column(String(64), nullable=False, index=True)
    device_id = Column(String(64), nullable=True)
    status = Column(String(20), default="pending", index=True)
    requested_at = Column(DateTime, default=_now)
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_dist_endpoint_version", "endpoint_id", "db_version"),
    )


# ── FeedSource ─────────────────────────────────────────────────────────────

class FeedSourceModel(Base):
    """External threat intelligence feed configuration."""
    __tablename__ = "shield_feed_sources"

    id = Column(String(36), primary_key=True, default=_uuid)
    source_id = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False)
    source_type = Column(String(30), nullable=False, index=True)
    api_url = Column(Text, nullable=True)
    api_key_ref = Column(String(255), nullable=True)
    update_interval_hours = Column(Integer, default=24)
    last_pull_at = Column(DateTime, nullable=True)
    signatures_contributed = Column(Integer, default=0)
    is_enabled = Column(Boolean, default=True, index=True)
    config_json = Column(JSON, default=dict)
