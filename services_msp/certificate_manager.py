"""
AITHER Platform - Certificate Lifecycle Management Service
Tracks SSL/TLS certificates across client infrastructure,
alerts on expiration, and manages renewal workflows.

Provides:
- Certificate CRUD and discovery
- SSL/TLS host scanning with grading
- Expiration tracking and alerts
- Renewal workflow management (including ACME simulation)
- Compliance and analytics dashboards

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.certificate_manager import (
        CertificateModel,
        CertificateAlertModel,
        RenewalRequestModel,
        CertificateScanModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class CertType(str, Enum):
    DV = "dv"
    OV = "ov"
    EV = "ev"
    SELF_SIGNED = "self_signed"
    INTERNAL_CA = "internal_ca"
    WILDCARD = "wildcard"
    CODE_SIGNING = "code_signing"
    CLIENT = "client"


class CertStatus(str, Enum):
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING_RENEWAL = "pending_renewal"


class AlertType(str, Enum):
    EXPIRING_30D = "expiring_30d"
    EXPIRING_7D = "expiring_7d"
    EXPIRING_1D = "expiring_1d"
    EXPIRED = "expired"
    WEAK_KEY = "weak_key"
    SHA1_DETECTED = "sha1_detected"
    SELF_SIGNED_PRODUCTION = "self_signed_production"
    CHAIN_INCOMPLETE = "chain_incomplete"
    PROTOCOL_OUTDATED = "protocol_outdated"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanGrade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class RenewalStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class Certificate:
    cert_id: str
    client_id: str = ""
    common_name: str = ""
    san_names: List[str] = field(default_factory=list)
    issuer: str = ""
    serial_number: str = ""
    fingerprint_sha256: str = ""
    key_algorithm: str = "RSA"
    key_size: int = 2048
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_until_expiry: int = 0
    status: CertStatus = CertStatus.ACTIVE
    cert_type: CertType = CertType.DV
    installed_on: List[str] = field(default_factory=list)
    auto_renew: bool = False
    renewal_provider: str = "manual"
    last_checked_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CertificateAlert:
    alert_id: str
    cert_id: str
    alert_type: AlertType
    severity: AlertSeverity
    message: str = ""
    is_acknowledged: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RenewalRequest:
    renewal_id: str
    cert_id: str
    status: RenewalStatus = RenewalStatus.PENDING
    requested_by: str = ""
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    new_cert_id: Optional[str] = None
    error_message: str = ""


@dataclass
class CertificateScan:
    scan_id: str
    target_host: str
    port: int = 443
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cert_found: bool = False
    cert_id: Optional[str] = None
    chain_valid: bool = True
    protocol_version: str = ""
    cipher_suite: str = ""
    grade: str = ""
    issues: List[str] = field(default_factory=list)


@dataclass
class CABundle:
    bundle_id: str
    name: str = ""
    certificates: List[str] = field(default_factory=list)
    is_default: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Helper converters
# ============================================================

def _cert_from_row(row) -> Certificate:
    return Certificate(
        cert_id=row.cert_id,
        client_id=row.client_id or "",
        common_name=row.common_name,
        san_names=row.san_names or [],
        issuer=row.issuer or "",
        serial_number=row.serial_number or "",
        fingerprint_sha256=row.fingerprint_sha256 or "",
        key_algorithm=row.key_algorithm or "RSA",
        key_size=row.key_size or 2048,
        valid_from=row.valid_from,
        valid_to=row.valid_to,
        days_until_expiry=row.days_until_expiry or 0,
        status=CertStatus(row.status) if row.status else CertStatus.ACTIVE,
        cert_type=CertType(row.cert_type) if row.cert_type else CertType.DV,
        installed_on=row.installed_on or [],
        auto_renew=row.auto_renew or False,
        renewal_provider=row.renewal_provider or "manual",
        last_checked_at=row.last_checked_at,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _alert_from_row(row) -> CertificateAlert:
    return CertificateAlert(
        alert_id=row.alert_id,
        cert_id=row.cert_id,
        alert_type=AlertType(row.alert_type) if row.alert_type else AlertType.EXPIRED,
        severity=AlertSeverity(row.severity) if row.severity else AlertSeverity.MEDIUM,
        message=row.message or "",
        is_acknowledged=row.is_acknowledged or False,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _renewal_from_row(row) -> RenewalRequest:
    return RenewalRequest(
        renewal_id=row.renewal_id,
        cert_id=row.cert_id,
        status=RenewalStatus(row.status) if row.status else RenewalStatus.PENDING,
        requested_by=row.requested_by or "",
        requested_at=row.requested_at or datetime.now(timezone.utc),
        completed_at=row.completed_at,
        new_cert_id=row.new_cert_id,
        error_message=row.error_message or "",
    )


def _scan_from_row(row) -> CertificateScan:
    return CertificateScan(
        scan_id=row.scan_id,
        target_host=row.target_host,
        port=row.port or 443,
        scanned_at=row.scanned_at or datetime.now(timezone.utc),
        cert_found=row.cert_found or False,
        cert_id=row.cert_id,
        chain_valid=row.chain_valid if row.chain_valid is not None else True,
        protocol_version=row.protocol_version or "",
        cipher_suite=row.cipher_suite or "",
        grade=row.grade or "",
        issues=row.issues or [],
    )


# ============================================================
# Service
# ============================================================

class CertificateManagerService:
    """
    Certificate Lifecycle Management Service.

    Tracks SSL/TLS certificates across all client infrastructure,
    alerts on expiration, and manages renewal workflows.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._certificates: Dict[str, Certificate] = {}
        self._alerts: Dict[str, CertificateAlert] = {}
        self._renewals: Dict[str, RenewalRequest] = {}
        self._scans: Dict[str, CertificateScan] = {}
        self._bundles: Dict[str, CABundle] = {}

    # ========== Certificate CRUD ==========

    def add_certificate(
        self,
        common_name: str,
        client_id: str = "",
        san_names: Optional[List[str]] = None,
        issuer: str = "",
        serial_number: str = "",
        fingerprint_sha256: str = "",
        key_algorithm: str = "RSA",
        key_size: int = 2048,
        valid_from: Optional[datetime] = None,
        valid_to: Optional[datetime] = None,
        cert_type: str = "dv",
        installed_on: Optional[List[str]] = None,
        auto_renew: bool = False,
        renewal_provider: str = "manual",
    ) -> Certificate:
        """Register a new certificate for tracking."""
        cert_id = f"CERT-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        days_until = 0
        status = CertStatus.ACTIVE
        if valid_to:
            delta = valid_to - now
            days_until = max(int(delta.total_seconds() / 86400), 0)
            if days_until <= 0:
                status = CertStatus.EXPIRED
            elif days_until <= 30:
                status = CertStatus.EXPIRING_SOON

        if not fingerprint_sha256:
            fingerprint_sha256 = hashlib.sha256(
                f"{common_name}:{serial_number}:{cert_id}".encode()
            ).hexdigest()

        cert = Certificate(
            cert_id=cert_id,
            client_id=client_id,
            common_name=common_name,
            san_names=san_names or [],
            issuer=issuer,
            serial_number=serial_number or uuid.uuid4().hex[:16].upper(),
            fingerprint_sha256=fingerprint_sha256,
            key_algorithm=key_algorithm,
            key_size=key_size,
            valid_from=valid_from or now,
            valid_to=valid_to,
            days_until_expiry=days_until,
            status=status,
            cert_type=CertType(cert_type) if cert_type in [e.value for e in CertType] else CertType.DV,
            installed_on=installed_on or [],
            auto_renew=auto_renew,
            renewal_provider=renewal_provider,
            last_checked_at=now,
            created_at=now,
        )

        if self._use_db:
            try:
                row = CertificateModel(
                    cert_id=cert_id,
                    client_id=client_id,
                    common_name=common_name,
                    san_names=san_names or [],
                    issuer=issuer,
                    serial_number=cert.serial_number,
                    fingerprint_sha256=cert.fingerprint_sha256,
                    key_algorithm=key_algorithm,
                    key_size=key_size,
                    valid_from=cert.valid_from,
                    valid_to=valid_to,
                    days_until_expiry=days_until,
                    status=status.value,
                    cert_type=cert.cert_type.value,
                    installed_on=installed_on or [],
                    auto_renew=auto_renew,
                    renewal_provider=renewal_provider,
                    last_checked_at=now,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error adding certificate: {e}")
                self.db.rollback()

        self._certificates[cert_id] = cert
        logger.info(f"Certificate added: {cert_id} ({common_name})")
        return cert

    def get_certificate(self, cert_id: str) -> Optional[Certificate]:
        """Get a certificate by ID."""
        if cert_id in self._certificates:
            return self._certificates[cert_id]

        if self._use_db:
            try:
                row = self.db.query(CertificateModel).filter(
                    CertificateModel.cert_id == cert_id
                ).first()
                if row:
                    cert = _cert_from_row(row)
                    self._certificates[cert_id] = cert
                    return cert
            except Exception as e:
                logger.error(f"DB error getting certificate: {e}")

        return None

    def list_certificates(
        self,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
        cert_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Certificate]:
        """List certificates with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(CertificateModel)
                if client_id:
                    q = q.filter(CertificateModel.client_id == client_id)
                if status:
                    q = q.filter(CertificateModel.status == status)
                if cert_type:
                    q = q.filter(CertificateModel.cert_type == cert_type)
                q = q.order_by(CertificateModel.valid_to.asc())
                rows = q.offset(offset).limit(limit).all()
                certs = [_cert_from_row(r) for r in rows]
                for c in certs:
                    self._certificates[c.cert_id] = c
                return certs
            except Exception as e:
                logger.error(f"DB error listing certificates: {e}")

        results = list(self._certificates.values())
        if client_id:
            results = [c for c in results if c.client_id == client_id]
        if status:
            results = [c for c in results if c.status.value == status]
        if cert_type:
            results = [c for c in results if c.cert_type.value == cert_type]
        results.sort(key=lambda c: c.valid_to or datetime.max.replace(tzinfo=timezone.utc))
        return results[offset:offset + limit]

    def update_certificate(self, cert_id: str, updates: Dict[str, Any]) -> Optional[Certificate]:
        """Update a certificate's tracked fields."""
        cert = self.get_certificate(cert_id)
        if not cert:
            return None

        for key, value in updates.items():
            if hasattr(cert, key) and key not in ("cert_id", "created_at"):
                setattr(cert, key, value)

        # Recalculate expiry-based fields
        if cert.valid_to:
            now = datetime.now(timezone.utc)
            delta = cert.valid_to - now
            cert.days_until_expiry = max(int(delta.total_seconds() / 86400), 0)
            # Only auto-set status when it is not explicitly managed
            if cert.status not in (CertStatus.PENDING_RENEWAL, CertStatus.REVOKED):
                if "status" not in updates:
                    if cert.days_until_expiry <= 0:
                        cert.status = CertStatus.EXPIRED
                    elif cert.days_until_expiry <= 30:
                        cert.status = CertStatus.EXPIRING_SOON
                    else:
                        cert.status = CertStatus.ACTIVE

        cert.last_checked_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(CertificateModel).filter(
                    CertificateModel.cert_id == cert_id
                ).first()
                if row:
                    for key, value in updates.items():
                        if hasattr(row, key) and key not in ("cert_id", "id", "created_at"):
                            if isinstance(value, Enum):
                                value = value.value
                            setattr(row, key, value)
                    row.days_until_expiry = cert.days_until_expiry
                    row.status = cert.status.value
                    row.last_checked_at = cert.last_checked_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating certificate: {e}")
                self.db.rollback()

        self._certificates[cert_id] = cert
        return cert

    def delete_certificate(self, cert_id: str) -> bool:
        """Remove a certificate from tracking."""
        if self._use_db:
            try:
                row = self.db.query(CertificateModel).filter(
                    CertificateModel.cert_id == cert_id
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error deleting certificate: {e}")
                self.db.rollback()

        if cert_id in self._certificates:
            del self._certificates[cert_id]
            return True
        return False

    # ========== Discovery & Scanning ==========

    def scan_host(self, host: str, port: int = 443) -> CertificateScan:
        """
        Connect to a host and extract SSL/TLS certificate information.
        Simulates the connection and grades the SSL configuration.
        """
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        issues: List[str] = []

        # Simulate SSL connection and cert extraction
        cert_found = True
        protocol = random.choice(["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"])
        cipher = random.choice([
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-SHA",
            "RC4-SHA",
        ])
        key_algo = random.choice(["RSA", "ECDSA", "Ed25519"])
        key_size = {"RSA": random.choice([2048, 4096]), "ECDSA": 256, "Ed25519": 256}[key_algo]
        chain_valid = random.random() > 0.15

        # Detect issues
        if protocol in ("TLSv1.0", "TLSv1.1"):
            issues.append(f"Outdated protocol: {protocol}")
        if cipher == "RC4-SHA":
            issues.append("Weak cipher: RC4-SHA")
        if key_algo == "RSA" and key_size < 2048:
            issues.append(f"Weak key size: {key_size}-bit RSA")
        if not chain_valid:
            issues.append("Certificate chain incomplete or untrusted")

        grade = self._grade_ssl_config(protocol, cipher, key_size, chain_valid)

        # Create a certificate record from scan
        valid_from = now - timedelta(days=random.randint(30, 365))
        valid_to = now + timedelta(days=random.randint(-30, 365))
        cert = self.add_certificate(
            common_name=host,
            san_names=[host, f"www.{host}"],
            issuer="Let's Encrypt Authority X3" if random.random() > 0.3 else "Self-Signed",
            key_algorithm=key_algo,
            key_size=key_size,
            valid_from=valid_from,
            valid_to=valid_to,
            cert_type="wildcard" if host.startswith("*.") else "dv",
            installed_on=[f"{host}:{port}"],
            auto_renew=random.random() > 0.5,
            renewal_provider=random.choice(["lets_encrypt", "digicert", "sectigo", "manual"]),
        )

        scan = CertificateScan(
            scan_id=scan_id,
            target_host=host,
            port=port,
            scanned_at=now,
            cert_found=cert_found,
            cert_id=cert.cert_id,
            chain_valid=chain_valid,
            protocol_version=protocol,
            cipher_suite=cipher,
            grade=grade,
            issues=issues,
        )

        if self._use_db:
            try:
                row = CertificateScanModel(
                    scan_id=scan_id,
                    target_host=host,
                    port=port,
                    scanned_at=now,
                    cert_found=cert_found,
                    cert_id=cert.cert_id,
                    chain_valid=chain_valid,
                    protocol_version=protocol,
                    cipher_suite=cipher,
                    grade=grade,
                    issues=issues,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error saving scan: {e}")
                self.db.rollback()

        self._scans[scan_id] = scan
        logger.info(f"Scan completed: {scan_id} ({host}:{port}) grade={grade}")
        return scan

    def scan_network(self, client_id: str, hosts: List[str], port: int = 443) -> List[CertificateScan]:
        """Bulk scan multiple hosts for a given client."""
        results = []
        for host in hosts:
            scan = self.scan_host(host, port)
            # Assign client on the discovered cert
            if scan.cert_id:
                self.update_certificate(scan.cert_id, {"client_id": client_id})
            results.append(scan)
        logger.info(f"Network scan complete for client {client_id}: {len(results)} hosts")
        return results

    def _grade_ssl_config(
        self, protocol: str, cipher: str, key_size: int, chain_valid: bool
    ) -> str:
        """Grade an SSL/TLS configuration (SSL Labs style)."""
        score = 100

        # Protocol scoring
        proto_scores = {
            "TLSv1.3": 0,
            "TLSv1.2": -5,
            "TLSv1.1": -30,
            "TLSv1.0": -50,
            "SSLv3": -80,
        }
        score += proto_scores.get(protocol, -40)

        # Cipher scoring
        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
        if any(wc in cipher.upper() for wc in weak_ciphers):
            score -= 40

        # Key size scoring
        if key_size < 1024:
            score -= 50
        elif key_size < 2048:
            score -= 20

        # Chain validity
        if not chain_valid:
            score -= 30

        if score >= 95:
            return ScanGrade.A_PLUS.value
        elif score >= 80:
            return ScanGrade.A.value
        elif score >= 65:
            return ScanGrade.B.value
        elif score >= 50:
            return ScanGrade.C.value
        elif score >= 35:
            return ScanGrade.D.value
        else:
            return ScanGrade.F.value

    # ========== Expiration Tracking ==========

    def check_expirations(self) -> List[CertificateAlert]:
        """Scan all certificates and create alerts for expiring ones."""
        alerts_created = []
        now = datetime.now(timezone.utc)
        certs = self.list_certificates(limit=10000)

        for cert in certs:
            if not cert.valid_to:
                continue

            delta = cert.valid_to - now
            days = int(delta.total_seconds() / 86400)
            cert.days_until_expiry = max(days, 0)

            if days <= 0:
                alert = self._create_alert(
                    cert.cert_id, AlertType.EXPIRED, AlertSeverity.CRITICAL,
                    f"Certificate {cert.common_name} has EXPIRED ({abs(days)} days ago)"
                )
                cert.status = CertStatus.EXPIRED
                alerts_created.append(alert)
            elif days <= 1:
                alert = self._create_alert(
                    cert.cert_id, AlertType.EXPIRING_1D, AlertSeverity.CRITICAL,
                    f"Certificate {cert.common_name} expires in {days} day(s)"
                )
                cert.status = CertStatus.EXPIRING_SOON
                alerts_created.append(alert)
            elif days <= 7:
                alert = self._create_alert(
                    cert.cert_id, AlertType.EXPIRING_7D, AlertSeverity.HIGH,
                    f"Certificate {cert.common_name} expires in {days} days"
                )
                cert.status = CertStatus.EXPIRING_SOON
                alerts_created.append(alert)
            elif days <= 30:
                alert = self._create_alert(
                    cert.cert_id, AlertType.EXPIRING_30D, AlertSeverity.MEDIUM,
                    f"Certificate {cert.common_name} expires in {days} days"
                )
                cert.status = CertStatus.EXPIRING_SOON
                alerts_created.append(alert)

            # Update the cert status in storage
            self.update_certificate(cert.cert_id, {
                "days_until_expiry": cert.days_until_expiry,
                "status": cert.status,
            })

        logger.info(f"Expiration check complete: {len(alerts_created)} alerts created")
        return alerts_created

    def get_expiring_certificates(self, days_ahead: int = 30) -> List[Certificate]:
        """Get certificates expiring within the specified number of days."""
        now = datetime.now(timezone.utc)
        cutoff = now + timedelta(days=days_ahead)

        if self._use_db:
            try:
                rows = self.db.query(CertificateModel).filter(
                    CertificateModel.valid_to <= cutoff,
                    CertificateModel.valid_to >= now,
                    CertificateModel.status != CertStatus.REVOKED.value,
                ).order_by(CertificateModel.valid_to.asc()).all()
                return [_cert_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error getting expiring certs: {e}")

        return [
            c for c in self._certificates.values()
            if c.valid_to and now <= c.valid_to <= cutoff
            and c.status != CertStatus.REVOKED
        ]

    # ========== Renewal ==========

    def request_renewal(self, cert_id: str, requested_by: str = "system") -> Optional[RenewalRequest]:
        """Request renewal of a certificate."""
        cert = self.get_certificate(cert_id)
        if not cert:
            return None

        renewal_id = f"REN-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        renewal = RenewalRequest(
            renewal_id=renewal_id,
            cert_id=cert_id,
            status=RenewalStatus.PENDING,
            requested_by=requested_by,
            requested_at=now,
        )

        if self._use_db:
            try:
                row = RenewalRequestModel(
                    renewal_id=renewal_id,
                    cert_id=cert_id,
                    status=RenewalStatus.PENDING.value,
                    requested_by=requested_by,
                    requested_at=now,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating renewal request: {e}")
                self.db.rollback()

        self._renewals[renewal_id] = renewal
        self.update_certificate(cert_id, {"status": CertStatus.PENDING_RENEWAL})

        # If auto-renew, simulate ACME flow
        if cert.auto_renew and cert.renewal_provider == "lets_encrypt":
            self._simulate_acme_renewal(cert, renewal)

        logger.info(f"Renewal requested: {renewal_id} for cert {cert_id}")
        return renewal

    def complete_renewal(
        self, renewal_id: str, new_cert_data: Dict[str, Any]
    ) -> Optional[RenewalRequest]:
        """Complete a renewal request with new certificate data."""
        renewal = self._renewals.get(renewal_id)
        if not renewal and self._use_db:
            try:
                row = self.db.query(RenewalRequestModel).filter(
                    RenewalRequestModel.renewal_id == renewal_id
                ).first()
                if row:
                    renewal = _renewal_from_row(row)
            except Exception:
                pass

        if not renewal:
            return None

        # Create the new certificate
        new_cert = self.add_certificate(**new_cert_data)
        now = datetime.now(timezone.utc)

        renewal.status = RenewalStatus.COMPLETED
        renewal.completed_at = now
        renewal.new_cert_id = new_cert.cert_id

        if self._use_db:
            try:
                row = self.db.query(RenewalRequestModel).filter(
                    RenewalRequestModel.renewal_id == renewal_id
                ).first()
                if row:
                    row.status = RenewalStatus.COMPLETED.value
                    row.completed_at = now
                    row.new_cert_id = new_cert.cert_id
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error completing renewal: {e}")
                self.db.rollback()

        self._renewals[renewal_id] = renewal
        # Mark old cert as active again (renewed)
        self.update_certificate(renewal.cert_id, {"status": CertStatus.ACTIVE})
        logger.info(f"Renewal completed: {renewal_id} -> {new_cert.cert_id}")
        return renewal

    def get_renewals(
        self,
        cert_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[RenewalRequest]:
        """List renewal requests with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(RenewalRequestModel)
                if cert_id:
                    q = q.filter(RenewalRequestModel.cert_id == cert_id)
                if status:
                    q = q.filter(RenewalRequestModel.status == status)
                rows = q.order_by(RenewalRequestModel.requested_at.desc()).limit(limit).all()
                return [_renewal_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing renewals: {e}")

        results = list(self._renewals.values())
        if cert_id:
            results = [r for r in results if r.cert_id == cert_id]
        if status:
            results = [r for r in results if r.status.value == status]
        return results[:limit]

    def _simulate_acme_renewal(self, cert: Certificate, renewal: RenewalRequest) -> None:
        """Simulate a Let's Encrypt ACME renewal flow."""
        renewal.status = RenewalStatus.IN_PROGRESS
        now = datetime.now(timezone.utc)

        # Simulate ACME challenge success (90% success rate)
        success = random.random() > 0.1

        if success:
            new_valid_from = now
            new_valid_to = now + timedelta(days=90)  # LE certs are 90 days
            new_cert = self.add_certificate(
                common_name=cert.common_name,
                client_id=cert.client_id,
                san_names=cert.san_names,
                issuer="Let's Encrypt Authority X3",
                key_algorithm=cert.key_algorithm,
                key_size=cert.key_size,
                valid_from=new_valid_from,
                valid_to=new_valid_to,
                cert_type=cert.cert_type.value,
                installed_on=cert.installed_on,
                auto_renew=True,
                renewal_provider="lets_encrypt",
            )
            renewal.status = RenewalStatus.COMPLETED
            renewal.completed_at = now
            renewal.new_cert_id = new_cert.cert_id
            logger.info(f"ACME renewal succeeded for {cert.common_name}")
        else:
            renewal.status = RenewalStatus.FAILED
            renewal.error_message = "ACME challenge failed: DNS validation timeout"
            logger.warning(f"ACME renewal failed for {cert.common_name}")

        if self._use_db:
            try:
                row = self.db.query(RenewalRequestModel).filter(
                    RenewalRequestModel.renewal_id == renewal.renewal_id
                ).first()
                if row:
                    row.status = renewal.status.value
                    row.completed_at = renewal.completed_at
                    row.new_cert_id = renewal.new_cert_id
                    row.error_message = renewal.error_message
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating ACME renewal: {e}")
                self.db.rollback()

        self._renewals[renewal.renewal_id] = renewal

    # ========== Alerts ==========

    def _create_alert(
        self, cert_id: str, alert_type: AlertType, severity: AlertSeverity, message: str
    ) -> CertificateAlert:
        """Create a certificate alert."""
        alert_id = f"CALRT-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        alert = CertificateAlert(
            alert_id=alert_id,
            cert_id=cert_id,
            alert_type=alert_type,
            severity=severity,
            message=message,
            created_at=now,
        )

        if self._use_db:
            try:
                row = CertificateAlertModel(
                    alert_id=alert_id,
                    cert_id=cert_id,
                    alert_type=alert_type.value,
                    severity=severity.value,
                    message=message,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating alert: {e}")
                self.db.rollback()

        self._alerts[alert_id] = alert
        return alert

    def get_alerts(
        self,
        cert_id: Optional[str] = None,
        alert_type: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 100,
    ) -> List[CertificateAlert]:
        """List alerts with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(CertificateAlertModel)
                if cert_id:
                    q = q.filter(CertificateAlertModel.cert_id == cert_id)
                if alert_type:
                    q = q.filter(CertificateAlertModel.alert_type == alert_type)
                if acknowledged is not None:
                    q = q.filter(CertificateAlertModel.is_acknowledged == acknowledged)
                rows = q.order_by(CertificateAlertModel.created_at.desc()).limit(limit).all()
                return [_alert_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing alerts: {e}")

        results = list(self._alerts.values())
        if cert_id:
            results = [a for a in results if a.cert_id == cert_id]
        if alert_type:
            results = [a for a in results if a.alert_type.value == alert_type]
        if acknowledged is not None:
            results = [a for a in results if a.is_acknowledged == acknowledged]
        return results[:limit]

    def acknowledge_alert(self, alert_id: str) -> Optional[CertificateAlert]:
        """Acknowledge a certificate alert."""
        alert = self._alerts.get(alert_id)
        if not alert and self._use_db:
            try:
                row = self.db.query(CertificateAlertModel).filter(
                    CertificateAlertModel.alert_id == alert_id
                ).first()
                if row:
                    alert = _alert_from_row(row)
            except Exception:
                pass

        if not alert:
            return None

        alert.is_acknowledged = True

        if self._use_db:
            try:
                row = self.db.query(CertificateAlertModel).filter(
                    CertificateAlertModel.alert_id == alert_id
                ).first()
                if row:
                    row.is_acknowledged = True
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error acknowledging alert: {e}")
                self.db.rollback()

        self._alerts[alert_id] = alert
        return alert

    # ========== Analytics ==========

    def get_expiration_timeline(self, months: int = 12) -> Dict[str, int]:
        """Get count of certificates expiring per month for next N months."""
        now = datetime.now(timezone.utc)
        timeline: Dict[str, int] = {}

        for i in range(months):
            month_start = (now + timedelta(days=30 * i)).replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
            if i + 1 < months:
                month_end = (now + timedelta(days=30 * (i + 1))).replace(
                    day=1, hour=0, minute=0, second=0, microsecond=0
                )
            else:
                month_end = month_start + timedelta(days=31)

            label = month_start.strftime("%Y-%m")
            count = 0

            certs = self.list_certificates(limit=10000)
            for cert in certs:
                if cert.valid_to and month_start <= cert.valid_to < month_end:
                    count += 1

            timeline[label] = count

        return timeline

    def get_cert_inventory(self, client_id: Optional[str] = None) -> Dict[str, Any]:
        """Get certificate inventory breakdown by type, issuer, key algorithm."""
        certs = self.list_certificates(client_id=client_id, limit=10000)

        by_type: Dict[str, int] = {}
        by_issuer: Dict[str, int] = {}
        by_algorithm: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for cert in certs:
            t = cert.cert_type.value
            by_type[t] = by_type.get(t, 0) + 1

            issuer = cert.issuer or "Unknown"
            by_issuer[issuer] = by_issuer.get(issuer, 0) + 1

            algo = cert.key_algorithm
            by_algorithm[algo] = by_algorithm.get(algo, 0) + 1

            s = cert.status.value
            by_status[s] = by_status.get(s, 0) + 1

        return {
            "total": len(certs),
            "by_type": by_type,
            "by_issuer": by_issuer,
            "by_algorithm": by_algorithm,
            "by_status": by_status,
        }

    def get_weak_certificates(self) -> List[Dict[str, Any]]:
        """Find certificates with weak keys, SHA1, or self-signed in production."""
        weak = []
        certs = self.list_certificates(limit=10000)

        for cert in certs:
            issues = []
            if cert.key_algorithm == "RSA" and cert.key_size < 2048:
                issues.append(f"Weak RSA key: {cert.key_size}-bit")
            if cert.cert_type == CertType.SELF_SIGNED and cert.installed_on:
                issues.append("Self-signed certificate in production")
            if cert.key_size < 128:
                issues.append("Dangerously small key size")

            if issues:
                weak.append({
                    "cert_id": cert.cert_id,
                    "common_name": cert.common_name,
                    "client_id": cert.client_id,
                    "issues": issues,
                    "key_algorithm": cert.key_algorithm,
                    "key_size": cert.key_size,
                    "cert_type": cert.cert_type.value,
                })

        return weak

    def get_compliance_status(self) -> Dict[str, Any]:
        """Check PCI-DSS and HIPAA certificate requirements."""
        certs = self.list_certificates(limit=10000)
        total = len(certs)

        pci_violations = []
        hipaa_violations = []

        for cert in certs:
            # PCI-DSS: No SSL/early TLS, min 2048-bit RSA, no self-signed
            if cert.key_algorithm == "RSA" and cert.key_size < 2048:
                pci_violations.append({
                    "cert_id": cert.cert_id,
                    "common_name": cert.common_name,
                    "violation": f"Key size {cert.key_size} < 2048 required minimum",
                })
            if cert.cert_type == CertType.SELF_SIGNED and cert.installed_on:
                pci_violations.append({
                    "cert_id": cert.cert_id,
                    "common_name": cert.common_name,
                    "violation": "Self-signed certificate on production host",
                })
            if cert.status == CertStatus.EXPIRED:
                pci_violations.append({
                    "cert_id": cert.cert_id,
                    "common_name": cert.common_name,
                    "violation": "Expired certificate still tracked",
                })

            # HIPAA: Encryption in transit required, no expired certs
            if cert.status == CertStatus.EXPIRED:
                hipaa_violations.append({
                    "cert_id": cert.cert_id,
                    "common_name": cert.common_name,
                    "violation": "Expired certificate - potential gap in encryption",
                })

        pci_pass = len(pci_violations) == 0
        hipaa_pass = len(hipaa_violations) == 0

        return {
            "total_certificates": total,
            "pci_dss": {
                "compliant": pci_pass,
                "violations": len(pci_violations),
                "details": pci_violations[:20],
            },
            "hipaa": {
                "compliant": hipaa_pass,
                "violations": len(hipaa_violations),
                "details": hipaa_violations[:20],
            },
            "overall_compliant": pci_pass and hipaa_pass,
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Get certificate management dashboard summary."""
        certs = self.list_certificates(limit=10000)
        alerts = self.get_alerts(acknowledged=False, limit=10000)
        now = datetime.now(timezone.utc)

        total = len(certs)
        active = sum(1 for c in certs if c.status == CertStatus.ACTIVE)
        expiring_soon = sum(1 for c in certs if c.status == CertStatus.EXPIRING_SOON)
        expired = sum(1 for c in certs if c.status == CertStatus.EXPIRED)
        pending_renewal = sum(1 for c in certs if c.status == CertStatus.PENDING_RENEWAL)
        revoked = sum(1 for c in certs if c.status == CertStatus.REVOKED)
        auto_renew_count = sum(1 for c in certs if c.auto_renew)

        # Grade distribution from recent scans
        scans = list(self._scans.values()) if not self._use_db else self._get_recent_scans(50)
        grade_dist: Dict[str, int] = {}
        for s in scans:
            g = s.grade or "Unknown"
            grade_dist[g] = grade_dist.get(g, 0) + 1

        # Certs expiring in next 7 days
        expiring_7d = [
            {
                "cert_id": c.cert_id,
                "common_name": c.common_name,
                "days_until_expiry": c.days_until_expiry,
                "auto_renew": c.auto_renew,
            }
            for c in certs
            if c.valid_to and 0 < (c.valid_to - now).total_seconds() / 86400 <= 7
        ]

        return {
            "total_certificates": total,
            "active": active,
            "expiring_soon": expiring_soon,
            "expired": expired,
            "pending_renewal": pending_renewal,
            "revoked": revoked,
            "auto_renew_enabled": auto_renew_count,
            "unacknowledged_alerts": len(alerts),
            "scan_grade_distribution": grade_dist,
            "expiring_next_7_days": expiring_7d,
            "last_check": now.isoformat(),
        }

    def _get_recent_scans(self, limit: int = 50) -> List[CertificateScan]:
        """Get recent scans from DB."""
        if self._use_db:
            try:
                rows = self.db.query(CertificateScanModel).order_by(
                    CertificateScanModel.scanned_at.desc()
                ).limit(limit).all()
                return [_scan_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error getting recent scans: {e}")
        return list(self._scans.values())[:limit]

    def get_scans(
        self,
        host: Optional[str] = None,
        limit: int = 100,
    ) -> List[CertificateScan]:
        """List scan results with optional host filter."""
        if self._use_db:
            try:
                q = self.db.query(CertificateScanModel)
                if host:
                    q = q.filter(CertificateScanModel.target_host == host)
                rows = q.order_by(CertificateScanModel.scanned_at.desc()).limit(limit).all()
                return [_scan_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing scans: {e}")

        results = list(self._scans.values())
        if host:
            results = [s for s in results if s.target_host == host]
        return results[:limit]
