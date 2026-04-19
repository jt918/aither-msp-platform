"""
AITHER Platform - Certificate Lifecycle Management Models

Tables for SSL/TLS certificates, alerts, renewal requests, and scans.
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


class CertificateModel(Base):
    """Tracked SSL/TLS certificate."""
    __tablename__ = "certificates_lifecycle"

    id = Column(String(36), primary_key=True, default=_uuid)
    cert_id = Column(String(30), unique=True, nullable=False, index=True)
    client_id = Column(String(100), default="", index=True)
    common_name = Column(String(300), nullable=False, index=True)
    san_names = Column(JSON, default=list)
    issuer = Column(String(300), default="")
    serial_number = Column(String(200), default="")
    fingerprint_sha256 = Column(String(100), default="")
    key_algorithm = Column(String(30), default="RSA")
    key_size = Column(Integer, default=2048)
    valid_from = Column(DateTime, nullable=True)
    valid_to = Column(DateTime, nullable=True)
    days_until_expiry = Column(Integer, default=0)
    status = Column(String(30), default="active", index=True)
    cert_type = Column(String(30), default="dv")
    installed_on = Column(JSON, default=list)
    auto_renew = Column(Boolean, default=False)
    renewal_provider = Column(String(50), default="manual")
    last_checked_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_cert_lc_client_status", "client_id", "status"),
        Index("ix_cert_lc_valid_to", "valid_to"),
    )


class CertificateAlertModel(Base):
    """Certificate-related alert."""
    __tablename__ = "certificate_alerts"

    id = Column(String(36), primary_key=True, default=_uuid)
    alert_id = Column(String(30), unique=True, nullable=False, index=True)
    cert_id = Column(String(30), nullable=False, index=True)
    alert_type = Column(String(40), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    message = Column(Text, default="")
    is_acknowledged = Column(Boolean, default=False)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_cert_alert_cert_ack", "cert_id", "is_acknowledged"),
    )


class RenewalRequestModel(Base):
    """Certificate renewal request."""
    __tablename__ = "certificate_renewals"

    id = Column(String(36), primary_key=True, default=_uuid)
    renewal_id = Column(String(30), unique=True, nullable=False, index=True)
    cert_id = Column(String(30), nullable=False, index=True)
    status = Column(String(20), default="pending", index=True)
    requested_by = Column(String(200), default="")
    requested_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)
    new_cert_id = Column(String(30), nullable=True)
    error_message = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())


class CertificateScanModel(Base):
    """SSL/TLS scan result."""
    __tablename__ = "certificate_scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    scan_id = Column(String(30), unique=True, nullable=False, index=True)
    target_host = Column(String(300), nullable=False, index=True)
    port = Column(Integer, default=443)
    scanned_at = Column(DateTime, default=func.now())
    cert_found = Column(Boolean, default=False)
    cert_id = Column(String(30), nullable=True)
    chain_valid = Column(Boolean, default=True)
    protocol_version = Column(String(30), default="")
    cipher_suite = Column(String(200), default="")
    grade = Column(String(5), default="")
    issues = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
