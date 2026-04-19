"""
AITHER Platform - Defense Models
SQLAlchemy models for IP Sentinel: Licenses, Violations, Fingerprints, Activations
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    Text, ForeignKey, Index, JSON,
)
from sqlalchemy.orm import relationship
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


class LicenseRecord(Base):
    """Persisted software license"""
    __tablename__ = "licenses"

    id = Column(String(36), primary_key=True, default=_uuid)
    organization_id = Column(Integer, index=True, nullable=True)
    license_id = Column(String(100), unique=True, nullable=False, index=True)
    license_key = Column(String(255), unique=True, nullable=False, index=True)
    license_type = Column(String(50), nullable=False)
    customer_id = Column(String(100), nullable=False, index=True)
    customer_name = Column(String(255))
    product_id = Column(String(100), nullable=False, index=True)
    product_name = Column(String(255))
    issued_at = Column(String(100))
    expires_at = Column(String(100))
    max_activations = Column(Integer, default=1)
    current_activations = Column(Integer, default=0)
    features = Column(JSON, default=list)
    restrictions = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    activations = relationship("ActivationRecord", back_populates="license")
    violations = relationship("LicenseViolationRecord", back_populates="license")
    fingerprints = relationship("CodeFingerprintRecord", back_populates="license")


class ActivationRecord(Base):
    """License activation on a machine"""
    __tablename__ = "license_activations"

    id = Column(String(36), primary_key=True, default=_uuid)
    activation_id = Column(String(100), unique=True, nullable=False, index=True)
    license_id = Column(String(100), ForeignKey("licenses.license_id"), nullable=False)
    machine_fingerprint = Column(String(255), nullable=False)
    activated_at = Column(String(100))
    last_verified = Column(String(100))
    ip_address = Column(String(50))
    hostname = Column(String(255))
    is_active = Column(Boolean, default=True)

    # Relationships
    license = relationship("LicenseRecord", back_populates="activations")


class CodeFingerprintRecord(Base):
    """Code fingerprint for tracking protected code"""
    __tablename__ = "code_fingerprints"

    id = Column(String(36), primary_key=True, default=_uuid)
    fingerprint_id = Column(String(100), unique=True, nullable=False, index=True)
    code_hash = Column(String(255), nullable=False)
    structure_hash = Column(String(255))
    semantic_hash = Column(String(255))
    watermark = Column(String(255))
    created_at = Column(String(100))
    product_id = Column(String(100), index=True)
    license_id = Column(String(100), ForeignKey("licenses.license_id"), nullable=True)
    metadata_json = Column(JSON, default=dict)

    # Relationships
    license = relationship("LicenseRecord", back_populates="fingerprints")


class LicenseViolationRecord(Base):
    """IP violation record"""
    __tablename__ = "license_violations"

    id = Column(String(36), primary_key=True, default=_uuid)
    violation_id = Column(String(100), unique=True, nullable=False, index=True)
    violation_type = Column(String(100), nullable=False)
    license_id = Column(String(100), ForeignKey("licenses.license_id"), nullable=True)
    fingerprint_id = Column(String(100), nullable=True)
    detected_at = Column(String(100))
    severity = Column(String(20))
    description = Column(Text)
    evidence = Column(JSON, default=dict)
    source_ip = Column(String(50))
    resolved = Column(Boolean, default=False)
    resolution_notes = Column(Text, default="")

    # Relationships
    license = relationship("LicenseRecord", back_populates="violations")


class ProtectedCodeRecord(Base):
    """Protected code with watermark applied"""
    __tablename__ = "protected_code"

    id = Column(String(36), primary_key=True, default=_uuid)
    code_id = Column(String(100), unique=True, nullable=False, index=True)
    original_hash = Column(String(255))
    protected_code = Column(Text)
    watermark = Column(String(255))
    fingerprint_id = Column(String(100))
    protection_level = Column(String(50))
    created_at = Column(String(100))
    license_id = Column(String(100), nullable=True)


class HardwareFingerprintRecord(Base):
    """Hardware fingerprint for machine identification"""
    __tablename__ = "hardware_fingerprints"

    id = Column(String(36), primary_key=True, default=_uuid)
    license_id = Column(String(100), ForeignKey("licenses.license_id"), nullable=True)
    fingerprint_hash = Column(String(255))
    cpu_id = Column(String(255))
    mac_address = Column(String(50))
    hostname = Column(String(255))
    os_info = Column(String(255))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_primary = Column(Boolean, default=True)
