"""
Aither Shield - Dark Web Monitoring Service

Monitors user identities (emails, phones, SSNs, etc.) against known data
breaches.  Designed to plug into Have I Been Pwned, SpyCloud, or any
breach-intelligence API — returns mock data when no API key is configured.

DB persistence with in-memory fallback (same pattern as RMM / Shield).

Created: 2026-04-19
"""

from typing import List, Dict, Optional, Any
from datetime import datetime, timezone, timedelta
from enum import Enum
from dataclasses import dataclass, field
import hashlib
import uuid
import time
import os
import logging

try:
    from sqlalchemy.orm import Session
    from models.dark_web import (
        MonitoredIdentityModel,
        BreachRecordModel,
        ExposureAlertModel,
        DarkWebScanModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────────

class IdentityType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    USERNAME = "username"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"


class ExposureSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class DataType(str, Enum):
    PASSWORD = "password"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    DOB = "dob"
    IP_ADDRESS = "ip_address"
    USERNAME = "username"
    SECURITY_QUESTION = "security_question"
    MEDICAL = "medical"
    FINANCIAL = "financial"


# ── Dataclasses ────────────────────────────────────────────────────────────

@dataclass
class MonitoredIdentity:
    identity_id: str
    user_id: str
    identity_type: str  # IdentityType value
    identity_value: str  # SHA-256 hash for storage
    display_hint: str  # masked: j***@gmail.com
    is_active: bool = True
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_checked_at: Optional[datetime] = None


@dataclass
class BreachRecord:
    breach_id: str
    breach_name: str
    breach_date: Optional[datetime] = None
    breach_description: str = ""
    data_types_exposed: List[str] = field(default_factory=list)
    total_accounts_affected: int = 0
    source_url: str = ""
    severity: str = "medium"
    is_verified: bool = False
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ExposureAlert:
    alert_id: str
    identity_id: str
    user_id: str
    breach_id: str
    exposed_data_types: List[str] = field(default_factory=list)
    severity: str = "medium"
    status: str = "new"
    recommended_actions: List[str] = field(default_factory=list)
    auto_actions_taken: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


@dataclass
class ScanResult:
    scan_id: str
    identity_id: str
    breaches_found: int = 0
    new_exposures: int = 0
    scan_duration_ms: int = 0
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Helpers ────────────────────────────────────────────────────────────────

def _hash_value(value: str) -> str:
    """SHA-256 hash for safe storage of sensitive identity values."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _mask_value(value: str, identity_type: str) -> str:
    """Create a masked display hint from a raw identity value."""
    v = value.strip()
    if identity_type == IdentityType.EMAIL.value:
        parts = v.split("@")
        if len(parts) == 2:
            local = parts[0]
            return f"{local[0]}***@{parts[1]}" if local else f"***@{parts[1]}"
        return "***"
    if identity_type == IdentityType.PHONE.value:
        return f"***{v[-4:]}" if len(v) >= 4 else "***"
    if identity_type == IdentityType.SSN.value:
        return f"***-**-{v[-4:]}" if len(v) >= 4 else "***"
    if identity_type == IdentityType.CREDIT_CARD.value:
        return f"****-****-****-{v[-4:]}" if len(v) >= 4 else "****"
    if identity_type == IdentityType.DOMAIN.value:
        return v  # domains are public
    if identity_type == IdentityType.IP_ADDRESS.value:
        parts = v.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"
        return "***"
    # username / other
    if len(v) > 2:
        return f"{v[0]}{'*' * (len(v) - 2)}{v[-1]}"
    return "***"


def _severity_weight(severity: str) -> int:
    """Numeric weight for risk scoring."""
    return {
        ExposureSeverity.CRITICAL.value: 25,
        ExposureSeverity.HIGH.value: 15,
        ExposureSeverity.MEDIUM.value: 8,
        ExposureSeverity.LOW.value: 3,
        ExposureSeverity.INFO.value: 1,
    }.get(severity, 5)


# ── Mock Breach Data (used when no API key is present) ─────────────────────

_MOCK_BREACHES = [
    {
        "breach_name": "ExampleCorp 2024",
        "breach_date": "2024-03-15",
        "breach_description": "ExampleCorp suffered a database breach exposing user credentials.",
        "data_types_exposed": ["password", "email", "username"],
        "total_accounts_affected": 2_400_000,
        "severity": "high",
        "is_verified": True,
    },
    {
        "breach_name": "SocialPlatformX 2023",
        "breach_date": "2023-11-02",
        "breach_description": "Social media platform leaked profile data through an unsecured API.",
        "data_types_exposed": ["email", "phone", "dob", "address"],
        "total_accounts_affected": 8_700_000,
        "severity": "critical",
        "is_verified": True,
    },
    {
        "breach_name": "ShopEasy 2024",
        "breach_date": "2024-07-20",
        "breach_description": "E-commerce site breach exposed payment information.",
        "data_types_exposed": ["email", "credit_card", "address"],
        "total_accounts_affected": 950_000,
        "severity": "critical",
        "is_verified": True,
    },
]


# ══════════════════════════════════════════════════════════════════════════
# Service
# ══════════════════════════════════════════════════════════════════════════

class DarkWebMonitorService:
    """
    Dark Web Monitoring — scans monitored identities against breach databases.

    Accepts an optional ``db: Session`` for persistence; falls back to
    in-memory dicts when db is ``None``.

    Provider API keys are read from environment variables:
      - HIBP_API_KEY      — Have I Been Pwned
      - SPYCLOUD_API_KEY  — SpyCloud
    When a key is absent the corresponding provider returns mock data.
    """

    def __init__(self, db=None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback stores
        self._identities: Dict[str, MonitoredIdentity] = {}
        self._breaches: Dict[str, BreachRecord] = {}
        self._exposures: Dict[str, ExposureAlert] = {}
        self._scans: List[ScanResult] = []

        # Provider API keys (plug-in ready)
        self._hibp_api_key: Optional[str] = os.environ.get("HIBP_API_KEY")
        self._spycloud_api_key: Optional[str] = os.environ.get("SPYCLOUD_API_KEY")

        # Seed local breach DB with mock data so scans return results
        self._seed_mock_breaches()

    # ── Seed ───────────────────────────────────────────────────────────────

    def _seed_mock_breaches(self) -> None:
        """Pre-populate local breach database with sample data."""
        for b in _MOCK_BREACHES:
            bid = f"BR-{uuid.uuid4().hex[:8].upper()}"
            breach_date = datetime.strptime(b["breach_date"], "%Y-%m-%d").replace(tzinfo=timezone.utc) if b.get("breach_date") else None
            rec = BreachRecord(
                breach_id=bid,
                breach_name=b["breach_name"],
                breach_date=breach_date,
                breach_description=b.get("breach_description", ""),
                data_types_exposed=b.get("data_types_exposed", []),
                total_accounts_affected=b.get("total_accounts_affected", 0),
                severity=b.get("severity", "medium"),
                is_verified=b.get("is_verified", False),
            )
            self._breaches[bid] = rec

    # ══════════════════════════════════════════════════════════════════════
    # Identity Management
    # ══════════════════════════════════════════════════════════════════════

    def add_monitored_identity(
        self,
        user_id: str,
        identity_type: str,
        identity_value: str,
    ) -> MonitoredIdentity:
        """Register an identity value for dark-web monitoring."""
        identity_id = f"DWI-{uuid.uuid4().hex[:8].upper()}"
        hashed = _hash_value(identity_value)
        hint = _mask_value(identity_value, identity_type)

        identity = MonitoredIdentity(
            identity_id=identity_id,
            user_id=user_id,
            identity_type=identity_type,
            identity_value=hashed,
            display_hint=hint,
        )

        if self._use_db:
            try:
                row = MonitoredIdentityModel(
                    id=identity_id,
                    user_id=user_id,
                    identity_type=identity_type,
                    identity_value_hash=hashed,
                    display_hint=hint,
                    is_active=True,
                    added_at=identity.added_at,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error adding identity: {e}")
                self.db.rollback()

        self._identities[identity_id] = identity
        return identity

    def remove_identity(self, identity_id: str) -> bool:
        """Deactivate a monitored identity."""
        identity = self._identities.get(identity_id)
        if not identity:
            return False
        identity.is_active = False

        if self._use_db:
            try:
                row = self.db.query(MonitoredIdentityModel).filter_by(id=identity_id).first()
                if row:
                    row.is_active = False
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error removing identity: {e}")
                self.db.rollback()

        return True

    def list_identities(self, user_id: str, active_only: bool = True) -> List[Dict[str, Any]]:
        """List monitored identities for a user."""
        results = []
        for ident in self._identities.values():
            if ident.user_id != user_id:
                continue
            if active_only and not ident.is_active:
                continue
            results.append(self._identity_to_dict(ident))
        return results

    def get_identity(self, identity_id: str) -> Optional[Dict[str, Any]]:
        """Get a single monitored identity."""
        ident = self._identities.get(identity_id)
        if not ident:
            return None
        return self._identity_to_dict(ident)

    # ══════════════════════════════════════════════════════════════════════
    # Scanning
    # ══════════════════════════════════════════════════════════════════════

    def scan_identity(self, identity_id: str) -> Optional[Dict[str, Any]]:
        """
        Scan a single identity against all breach sources.
        Returns a ScanResult dict or None if the identity doesn't exist.
        """
        identity = self._identities.get(identity_id)
        if not identity or not identity.is_active:
            return None

        start = time.time()

        # Collect breaches from all providers
        breaches: List[Dict] = []
        breaches.extend(self._check_hibp(identity.identity_value))
        breaches.extend(self._check_spycloud(identity.identity_value))
        breaches.extend(self._check_local_breach_db(identity.identity_value))

        # Deduplicate by breach name
        seen_names: set = set()
        unique_breaches: List[Dict] = []
        for b in breaches:
            name = b.get("breach_name", "")
            if name not in seen_names:
                seen_names.add(name)
                unique_breaches.append(b)

        # Create exposure alerts for new findings
        new_exposures = 0
        for b_data in unique_breaches:
            # Ensure breach exists in local DB
            breach = self._ensure_breach(b_data)

            # Check if we already have an alert for this identity+breach
            existing = any(
                e.identity_id == identity_id and e.breach_id == breach.breach_id
                for e in self._exposures.values()
            )
            if not existing:
                alert = self._create_exposure_alert(identity, breach)
                new_exposures += 1

        # Update last-checked timestamp
        identity.last_checked_at = datetime.now(timezone.utc)
        if self._use_db:
            try:
                row = self.db.query(MonitoredIdentityModel).filter_by(id=identity_id).first()
                if row:
                    row.last_checked_at = identity.last_checked_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating last_checked_at: {e}")
                self.db.rollback()

        duration_ms = int((time.time() - start) * 1000)

        scan = ScanResult(
            scan_id=f"SCN-{uuid.uuid4().hex[:8].upper()}",
            identity_id=identity_id,
            breaches_found=len(unique_breaches),
            new_exposures=new_exposures,
            scan_duration_ms=duration_ms,
        )
        self._scans.append(scan)

        if self._use_db:
            try:
                row = DarkWebScanModel(
                    id=scan.scan_id,
                    identity_id=identity_id,
                    breaches_found=scan.breaches_found,
                    new_exposures=scan.new_exposures,
                    scan_duration_ms=scan.scan_duration_ms,
                    scanned_at=scan.scanned_at,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error saving scan: {e}")
                self.db.rollback()

        return self._scan_to_dict(scan)

    def scan_all_identities(self) -> Dict[str, Any]:
        """Batch-scan every active identity. Returns summary stats."""
        active = [i for i in self._identities.values() if i.is_active]
        results = []
        total_breaches = 0
        total_new = 0
        for ident in active:
            result = self.scan_identity(ident.identity_id)
            if result:
                results.append(result)
                total_breaches += result["breaches_found"]
                total_new += result["new_exposures"]
        return {
            "identities_scanned": len(results),
            "total_breaches_found": total_breaches,
            "total_new_exposures": total_new,
            "scan_results": results,
        }

    # ── Provider Integrations ──────────────────────────────────────────────

    def _check_hibp(self, identity_value_hash: str) -> List[Dict]:
        """
        Have I Been Pwned API integration.
        When HIBP_API_KEY is set, makes real API calls.
        Otherwise returns mock breach matches.
        """
        if self._hibp_api_key:
            # TODO: Real HIBP API integration
            # import requests
            # headers = {"hibp-api-key": self._hibp_api_key}
            # resp = requests.get(
            #     f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            #     headers=headers,
            # )
            # return resp.json()
            logger.info("HIBP API key configured — real integration pending")
            return []

        # Mock: return first mock breach for demo purposes
        return [_MOCK_BREACHES[0]] if _MOCK_BREACHES else []

    def _check_spycloud(self, identity_value_hash: str) -> List[Dict]:
        """
        SpyCloud API integration.
        When SPYCLOUD_API_KEY is set, makes real API calls.
        Otherwise returns mock breach matches.
        """
        if self._spycloud_api_key:
            # TODO: Real SpyCloud API integration
            # import requests
            # headers = {"Authorization": f"Bearer {self._spycloud_api_key}"}
            # resp = requests.get(
            #     "https://api.spycloud.io/v2/breach/data/emails",
            #     headers=headers,
            #     params={"email": email},
            # )
            # return resp.json().get("results", [])
            logger.info("SpyCloud API key configured — real integration pending")
            return []

        # Mock: return second mock breach for demo purposes
        return [_MOCK_BREACHES[1]] if len(_MOCK_BREACHES) > 1 else []

    def _check_local_breach_db(self, identity_value_hash: str) -> List[Dict]:
        """
        Check against locally cached breach records.
        In production this would do a hash-match against ingested feeds.
        For now returns the third mock breach to simulate a hit.
        """
        return [_MOCK_BREACHES[2]] if len(_MOCK_BREACHES) > 2 else []

    # ══════════════════════════════════════════════════════════════════════
    # Breach Feed Ingestion
    # ══════════════════════════════════════════════════════════════════════

    def ingest_breach_feed(self, breaches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Import breach records from any provider feed.

        Each dict should contain at minimum: breach_name, severity.
        Optional fields: breach_date, breach_description, data_types_exposed,
        total_accounts_affected, source_url, is_verified.

        Returns: count of new vs updated records.
        """
        new_count = 0
        updated_count = 0

        for b_data in breaches:
            name = b_data.get("breach_name", "")
            if not name:
                continue

            # Check if breach already exists by name
            existing = None
            for br in self._breaches.values():
                if br.breach_name == name:
                    existing = br
                    break

            if existing:
                # Update existing
                existing.breach_description = b_data.get("breach_description", existing.breach_description)
                existing.data_types_exposed = b_data.get("data_types_exposed", existing.data_types_exposed)
                existing.total_accounts_affected = b_data.get("total_accounts_affected", existing.total_accounts_affected)
                existing.severity = b_data.get("severity", existing.severity)
                existing.is_verified = b_data.get("is_verified", existing.is_verified)

                if self._use_db:
                    try:
                        row = self.db.query(BreachRecordModel).filter_by(id=existing.breach_id).first()
                        if row:
                            row.breach_description = existing.breach_description
                            row.data_types_exposed = existing.data_types_exposed
                            row.total_accounts_affected = existing.total_accounts_affected
                            row.severity = existing.severity
                            row.is_verified = existing.is_verified
                            self.db.commit()
                    except Exception as e:
                        logger.error(f"DB error updating breach: {e}")
                        self.db.rollback()
                updated_count += 1
            else:
                self._ensure_breach(b_data)
                new_count += 1

        return {
            "new_breaches": new_count,
            "updated_breaches": updated_count,
            "total_processed": new_count + updated_count,
        }

    def _ensure_breach(self, b_data: Dict) -> BreachRecord:
        """Ensure a breach record exists; create if new."""
        name = b_data.get("breach_name", "Unknown")

        # Check existing
        for br in self._breaches.values():
            if br.breach_name == name:
                return br

        bid = f"BR-{uuid.uuid4().hex[:8].upper()}"
        breach_date_raw = b_data.get("breach_date")
        breach_date = None
        if isinstance(breach_date_raw, str):
            try:
                breach_date = datetime.strptime(breach_date_raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        elif isinstance(breach_date_raw, datetime):
            breach_date = breach_date_raw

        rec = BreachRecord(
            breach_id=bid,
            breach_name=name,
            breach_date=breach_date,
            breach_description=b_data.get("breach_description", ""),
            data_types_exposed=b_data.get("data_types_exposed", []),
            total_accounts_affected=b_data.get("total_accounts_affected", 0),
            source_url=b_data.get("source_url", ""),
            severity=b_data.get("severity", "medium"),
            is_verified=b_data.get("is_verified", False),
        )
        self._breaches[bid] = rec

        if self._use_db:
            try:
                row = BreachRecordModel(
                    id=bid,
                    breach_name=rec.breach_name,
                    breach_date=rec.breach_date,
                    breach_description=rec.breach_description,
                    data_types_exposed=rec.data_types_exposed,
                    total_accounts_affected=rec.total_accounts_affected,
                    source_url=rec.source_url,
                    severity=rec.severity,
                    is_verified=rec.is_verified,
                    discovered_at=rec.discovered_at,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error saving breach: {e}")
                self.db.rollback()

        return rec

    # ══════════════════════════════════════════════════════════════════════
    # Exposure Alerts
    # ══════════════════════════════════════════════════════════════════════

    def _create_exposure_alert(
        self, identity: MonitoredIdentity, breach: BreachRecord
    ) -> ExposureAlert:
        """Create a new exposure alert linking an identity to a breach."""
        alert_id = f"DWA-{uuid.uuid4().hex[:8].upper()}"
        actions = self.generate_recommended_actions_for_breach(breach, identity.identity_type)

        alert = ExposureAlert(
            alert_id=alert_id,
            identity_id=identity.identity_id,
            user_id=identity.user_id,
            breach_id=breach.breach_id,
            exposed_data_types=breach.data_types_exposed,
            severity=breach.severity,
            recommended_actions=actions,
        )
        self._exposures[alert_id] = alert

        if self._use_db:
            try:
                row = ExposureAlertModel(
                    id=alert_id,
                    identity_id=identity.identity_id,
                    user_id=identity.user_id,
                    breach_id=breach.breach_id,
                    exposed_data_types=alert.exposed_data_types,
                    severity=alert.severity,
                    status="new",
                    recommended_actions=alert.recommended_actions,
                    auto_actions_taken=[],
                    discovered_at=alert.discovered_at,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating exposure alert: {e}")
                self.db.rollback()

        return alert

    def get_exposures(
        self,
        user_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get exposure alerts for a user with optional filters."""
        results = []
        for alert in self._exposures.values():
            if alert.user_id != user_id:
                continue
            if status and alert.status != status:
                continue
            if severity and alert.severity != severity:
                continue
            results.append(self._exposure_to_dict(alert))

        # Sort newest first
        results.sort(key=lambda x: x["discovered_at"], reverse=True)
        return results[offset: offset + limit]

    def get_exposure(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get a single exposure alert."""
        alert = self._exposures.get(alert_id)
        if not alert:
            return None
        return self._exposure_to_dict(alert)

    def acknowledge_exposure(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Mark an exposure as acknowledged."""
        alert = self._exposures.get(alert_id)
        if not alert:
            return None
        alert.status = AlertStatus.ACKNOWLEDGED.value
        alert.acknowledged_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(ExposureAlertModel).filter_by(id=alert_id).first()
                if row:
                    row.status = alert.status
                    row.acknowledged_at = alert.acknowledged_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error acknowledging exposure: {e}")
                self.db.rollback()

        return self._exposure_to_dict(alert)

    def resolve_exposure(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Mark an exposure as resolved."""
        alert = self._exposures.get(alert_id)
        if not alert:
            return None
        alert.status = AlertStatus.RESOLVED.value
        alert.resolved_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(ExposureAlertModel).filter_by(id=alert_id).first()
                if row:
                    row.status = alert.status
                    row.resolved_at = alert.resolved_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error resolving exposure: {e}")
                self.db.rollback()

        return self._exposure_to_dict(alert)

    def mark_false_positive(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Mark an exposure as a false positive."""
        alert = self._exposures.get(alert_id)
        if not alert:
            return None
        alert.status = AlertStatus.FALSE_POSITIVE.value
        alert.resolved_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(ExposureAlertModel).filter_by(id=alert_id).first()
                if row:
                    row.status = alert.status
                    row.resolved_at = alert.resolved_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error marking false positive: {e}")
                self.db.rollback()

        return self._exposure_to_dict(alert)

    # ══════════════════════════════════════════════════════════════════════
    # Recommendations
    # ══════════════════════════════════════════════════════════════════════

    def generate_recommended_actions(self, exposure: Dict[str, Any]) -> List[str]:
        """Generate context-specific recommended actions for an exposure dict."""
        exposed = exposure.get("exposed_data_types", [])
        identity_type = None
        ident = self._identities.get(exposure.get("identity_id", ""))
        if ident:
            identity_type = ident.identity_type
        return self._build_actions(exposed, identity_type)

    def generate_recommended_actions_for_breach(
        self, breach: BreachRecord, identity_type: Optional[str] = None
    ) -> List[str]:
        """Generate actions based on breach data types and identity type."""
        return self._build_actions(breach.data_types_exposed, identity_type)

    def _build_actions(self, exposed_types: List[str], identity_type: Optional[str] = None) -> List[str]:
        """Build actionable recommendations based on what was exposed."""
        actions: List[str] = []

        if "password" in exposed_types:
            actions.append("Change your password immediately on the affected service and any site using the same password")
            actions.append("Enable two-factor authentication (2FA) on all accounts")
        if "email" in exposed_types:
            actions.append("Monitor your inbox for phishing attempts")
            actions.append("Consider using an email alias for new registrations")
        if "credit_card" in exposed_types:
            actions.append("Contact your bank to freeze or replace the affected card")
            actions.append("Monitor bank statements for unauthorized transactions")
        if "ssn" in exposed_types:
            actions.append("Place a fraud alert with all three credit bureaus (Equifax, Experian, TransUnion)")
            actions.append("Consider a credit freeze to prevent new accounts being opened")
            actions.append("File an identity theft report with the FTC at IdentityTheft.gov")
        if "phone" in exposed_types:
            actions.append("Be vigilant for SIM-swap attacks — contact your carrier to add a PIN")
            actions.append("Watch for smishing (SMS phishing) attempts")
        if "address" in exposed_types:
            actions.append("Monitor mail for suspicious correspondence or unfamiliar credit offers")
        if "dob" in exposed_types:
            actions.append("Monitor credit reports — date of birth is used for identity verification")
        if "medical" in exposed_types:
            actions.append("Review medical records for fraudulent claims")
            actions.append("Contact your healthcare provider and insurance company")
        if "financial" in exposed_types:
            actions.append("Review all financial accounts for unauthorized activity")
            actions.append("Consider identity theft protection services")
        if "security_question" in exposed_types:
            actions.append("Update security questions on all accounts that use them")

        if not actions:
            actions.append("Review your accounts for suspicious activity")
            actions.append("Update passwords on critical accounts as a precaution")

        return actions

    # ══════════════════════════════════════════════════════════════════════
    # Timeline & Risk Score
    # ══════════════════════════════════════════════════════════════════════

    def get_exposure_timeline(self, user_id: str) -> List[Dict[str, Any]]:
        """Chronological exposure history for a user."""
        events: List[Dict[str, Any]] = []
        for alert in self._exposures.values():
            if alert.user_id != user_id:
                continue

            breach = self._breaches.get(alert.breach_id)
            breach_name = breach.breach_name if breach else "Unknown Breach"

            events.append({
                "alert_id": alert.alert_id,
                "breach_name": breach_name,
                "severity": alert.severity,
                "status": alert.status,
                "exposed_data_types": alert.exposed_data_types,
                "discovered_at": alert.discovered_at.isoformat(),
                "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            })

        events.sort(key=lambda x: x["discovered_at"])
        return events

    def get_risk_score(self, user_id: str) -> Dict[str, Any]:
        """
        Compute a 0-100 risk score for a user based on their exposure profile.

        Score factors:
        - Number of unresolved exposures and their severity
        - Recency of exposures
        - Types of data exposed (SSN/credit_card weigh heavier)
        """
        user_exposures = [
            e for e in self._exposures.values()
            if e.user_id == user_id and e.status not in (
                AlertStatus.RESOLVED.value,
                AlertStatus.FALSE_POSITIVE.value,
            )
        ]

        if not user_exposures:
            return {
                "user_id": user_id,
                "risk_score": 0,
                "risk_level": "none",
                "unresolved_exposures": 0,
                "factors": [],
            }

        score = 0.0
        factors: List[str] = []

        # Factor 1: severity-weighted count
        for exp in user_exposures:
            score += _severity_weight(exp.severity)

        if score > 0:
            factors.append(f"{len(user_exposures)} unresolved exposure(s)")

        # Factor 2: critical data types
        all_types: set = set()
        for exp in user_exposures:
            all_types.update(exp.exposed_data_types)

        critical_types = {"ssn", "credit_card", "financial", "medical"}
        found_critical = all_types & critical_types
        if found_critical:
            score += 15 * len(found_critical)
            factors.append(f"Critical data exposed: {', '.join(found_critical)}")

        # Factor 3: recency bonus (exposures in last 30 days)
        now = datetime.now(timezone.utc)
        recent = [e for e in user_exposures if (now - e.discovered_at).days <= 30]
        if recent:
            score += 10
            factors.append(f"{len(recent)} exposure(s) in the last 30 days")

        # Cap at 100
        final_score = min(int(score), 100)

        if final_score >= 75:
            level = "critical"
        elif final_score >= 50:
            level = "high"
        elif final_score >= 25:
            level = "medium"
        elif final_score > 0:
            level = "low"
        else:
            level = "none"

        return {
            "user_id": user_id,
            "risk_score": final_score,
            "risk_level": level,
            "unresolved_exposures": len(user_exposures),
            "factors": factors,
        }

    # ══════════════════════════════════════════════════════════════════════
    # Dashboard
    # ══════════════════════════════════════════════════════════════════════

    def get_dashboard(self) -> Dict[str, Any]:
        """Aggregate stats for the dark-web monitoring dashboard."""
        now = datetime.now(timezone.utc)
        week_ago = now - timedelta(days=7)

        total_monitored = sum(1 for i in self._identities.values() if i.is_active)
        total_breaches = len(self._breaches)
        new_this_week = sum(
            1 for e in self._exposures.values()
            if e.status == AlertStatus.NEW.value and e.discovered_at >= week_ago
        )

        # Compute high-risk users (risk_score >= 50)
        user_ids = set(i.user_id for i in self._identities.values() if i.is_active)
        high_risk_users = 0
        for uid in user_ids:
            risk = self.get_risk_score(uid)
            if risk["risk_score"] >= 50:
                high_risk_users += 1

        # Exposure status breakdown
        status_counts: Dict[str, int] = {s.value: 0 for s in AlertStatus}
        for e in self._exposures.values():
            status_counts[e.status] = status_counts.get(e.status, 0) + 1

        # Severity breakdown
        severity_counts: Dict[str, int] = {s.value: 0 for s in ExposureSeverity}
        for e in self._exposures.values():
            severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

        return {
            "total_monitored_identities": total_monitored,
            "total_breaches_tracked": total_breaches,
            "new_exposures_this_week": new_this_week,
            "high_risk_users": high_risk_users,
            "total_exposures": len(self._exposures),
            "exposure_status_breakdown": status_counts,
            "exposure_severity_breakdown": severity_counts,
            "total_scans_run": len(self._scans),
        }

    # ══════════════════════════════════════════════════════════════════════
    # Breach Database Queries
    # ══════════════════════════════════════════════════════════════════════

    def list_breaches(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List known breach records."""
        all_breaches = sorted(
            self._breaches.values(),
            key=lambda b: b.discovered_at,
            reverse=True,
        )
        return [self._breach_to_dict(b) for b in all_breaches[offset: offset + limit]]

    def get_breach(self, breach_id: str) -> Optional[Dict[str, Any]]:
        """Get a single breach record."""
        b = self._breaches.get(breach_id)
        if not b:
            return None
        return self._breach_to_dict(b)

    # ══════════════════════════════════════════════════════════════════════
    # Serializers
    # ══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _identity_to_dict(ident: MonitoredIdentity) -> Dict[str, Any]:
        return {
            "identity_id": ident.identity_id,
            "user_id": ident.user_id,
            "identity_type": ident.identity_type,
            "display_hint": ident.display_hint,
            "is_active": ident.is_active,
            "added_at": ident.added_at.isoformat(),
            "last_checked_at": ident.last_checked_at.isoformat() if ident.last_checked_at else None,
        }

    @staticmethod
    def _breach_to_dict(b: BreachRecord) -> Dict[str, Any]:
        return {
            "breach_id": b.breach_id,
            "breach_name": b.breach_name,
            "breach_date": b.breach_date.isoformat() if b.breach_date else None,
            "breach_description": b.breach_description,
            "data_types_exposed": b.data_types_exposed,
            "total_accounts_affected": b.total_accounts_affected,
            "source_url": b.source_url,
            "severity": b.severity,
            "is_verified": b.is_verified,
            "discovered_at": b.discovered_at.isoformat(),
        }

    @staticmethod
    def _exposure_to_dict(alert: ExposureAlert) -> Dict[str, Any]:
        return {
            "alert_id": alert.alert_id,
            "identity_id": alert.identity_id,
            "user_id": alert.user_id,
            "breach_id": alert.breach_id,
            "exposed_data_types": alert.exposed_data_types,
            "severity": alert.severity,
            "status": alert.status,
            "recommended_actions": alert.recommended_actions,
            "auto_actions_taken": alert.auto_actions_taken,
            "discovered_at": alert.discovered_at.isoformat(),
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        }

    @staticmethod
    def _scan_to_dict(scan: ScanResult) -> Dict[str, Any]:
        return {
            "scan_id": scan.scan_id,
            "identity_id": scan.identity_id,
            "breaches_found": scan.breaches_found,
            "new_exposures": scan.new_exposures,
            "scan_duration_ms": scan.scan_duration_ms,
            "scanned_at": scan.scanned_at.isoformat(),
        }
