"""
dark_web.py — Dark Web Monitoring persistence models

Persists monitored identities, breach records, exposure alerts, and scan history
for the MSP Dark Web Monitoring service.

Created: 2026-04-19
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


# -- MonitoredIdentity -------------------------------------------------------

class MonitoredIdentityModel(Base):
    """
    An identity value (email, phone, SSN, etc.) being monitored for breaches.
    The identity_value is stored as a SHA-256 hash for security.
    """
    __tablename__ = "dark_web_monitored_identities"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), nullable=False, index=True)
    identity_type = Column(String(30), nullable=False)  # email, phone, ssn, credit_card, username, domain, ip_address
    identity_value_hash = Column(String(64), nullable=False)
    display_hint = Column(String(100), nullable=False)  # masked: j***@gmail.com
    is_active = Column(Boolean, default=True, index=True)
    added_at = Column(DateTime, default=_now)
    last_checked_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_dw_identity_value_hash", "identity_value_hash"),
        Index("ix_dw_identity_user_type", "user_id", "identity_type"),
    )


# -- BreachRecord ------------------------------------------------------------

class BreachRecordModel(Base):
    """
    A known data breach from any provider (HIBP, SpyCloud, manual ingest).
    """
    __tablename__ = "dark_web_breach_records"

    id = Column(String(36), primary_key=True, default=_uuid)
    breach_name = Column(String(255), nullable=False, unique=True)
    breach_date = Column(DateTime, nullable=True)
    breach_description = Column(Text, nullable=True)
    data_types_exposed = Column(JSON, default=list)  # ["password", "email", ...]
    total_accounts_affected = Column(Integer, default=0)
    source_url = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium")  # critical, high, medium, low, info
    is_verified = Column(Boolean, default=False)
    discovered_at = Column(DateTime, default=_now)

    __table_args__ = (
        Index("ix_dw_breach_severity", "severity"),
        Index("ix_dw_breach_date", "breach_date"),
    )


# -- ExposureAlert -----------------------------------------------------------

class ExposureAlertModel(Base):
    """
    An alert linking a monitored identity to a breach — the core deliverable.
    """
    __tablename__ = "dark_web_exposure_alerts"

    id = Column(String(36), primary_key=True, default=_uuid)
    identity_id = Column(String(36), nullable=False, index=True)
    user_id = Column(String(36), nullable=False, index=True)
    breach_id = Column(String(36), nullable=False, index=True)
    exposed_data_types = Column(JSON, default=list)
    severity = Column(String(20), nullable=False, default="medium")
    status = Column(String(20), default="new", index=True)  # new, acknowledged, resolved, false_positive
    recommended_actions = Column(JSON, default=list)
    auto_actions_taken = Column(JSON, default=list)
    discovered_at = Column(DateTime, default=_now)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_dw_exposure_user_status", "user_id", "status"),
        Index("ix_dw_exposure_discovered", "discovered_at"),
    )


# -- DarkWebScan -------------------------------------------------------------

class DarkWebScanModel(Base):
    """
    Scan execution log — one row per identity scan attempt.
    """
    __tablename__ = "dark_web_scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    identity_id = Column(String(36), nullable=False, index=True)
    breaches_found = Column(Integer, default=0)
    new_exposures = Column(Integer, default=0)
    scan_duration_ms = Column(Integer, default=0)
    scanned_at = Column(DateTime, default=_now)

    __table_args__ = (
        Index("ix_dw_scan_identity_date", "identity_id", "scanned_at"),
    )
