"""
Aither Shield - Signature Update Pipeline Service

Manages the threat signature database: ingestion from external feeds,
versioning, delta generation, and distribution to Shield endpoints.

The actual signature content comes from external providers (ClamAV, YARA repos,
AlienVault OTX, etc.).  This service builds the complete infrastructure to
receive, store, version, and distribute signatures.

Created: 2026-04-19
"""

from typing import List, Dict, Optional, Any
from datetime import datetime, timezone, timedelta
from enum import Enum
from dataclasses import dataclass, field
import hashlib
import json
import uuid
import logging

logger = logging.getLogger(__name__)

try:
    from sqlalchemy.orm import Session
    from models.signatures import (
        ThreatSignatureModel,
        SignatureDatabaseModel,
        SignatureDeltaModel,
        UpdateDistributionModel,
        FeedSourceModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None


# ── Enums ──────────────────────────────────────────────────────────────────

class SignaturePlatform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    ALL = "all"


class UpdateStatus(str, Enum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    INSTALLED = "installed"
    FAILED = "failed"
    SKIPPED = "skipped"


class FeedType(str, Enum):
    CLAMAV = "clamav"
    YARA_REPO = "yara_repo"
    ALIENVAULT_OTX = "alienvault_otx"
    VIRUSTOTAL = "virustotal"
    ABUSE_IPDB = "abuse_ipdb"
    CUSTOM = "custom"
    MANUAL = "manual"


class DetectionEngine(str, Enum):
    SIGNATURE = "signature"
    HEURISTIC = "heuristic"
    BEHAVIORAL = "behavioral"


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Dataclasses ────────────────────────────────────────────────────────────

@dataclass
class ThreatSignature:
    signature_id: str
    name: str
    threat_type: str
    severity: str
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    yara_rule: Optional[str] = None
    description: Optional[str] = None
    cve_id: Optional[str] = None
    platform: str = "all"
    detection_engine: str = "signature"
    false_positive_rate: float = 0.0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


@dataclass
class SignatureDatabase:
    db_id: str
    version: str
    build_number: int
    total_signatures: int = 0
    new_in_version: int = 0
    removed_in_version: int = 0
    size_bytes: int = 0
    checksum_sha256: str = ""
    published_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    release_notes: str = ""
    signature_ids: List[str] = field(default_factory=list)


@dataclass
class SignatureDelta:
    delta_id: str
    from_version: str
    to_version: str
    added_signatures: List[Dict] = field(default_factory=list)
    removed_signature_ids: List[str] = field(default_factory=list)
    modified_signatures: List[Dict] = field(default_factory=list)
    size_bytes: int = 0
    checksum_sha256: str = ""


@dataclass
class UpdateDistribution:
    distribution_id: str
    db_version: str
    endpoint_id: str
    device_id: Optional[str] = None
    status: str = "pending"
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


@dataclass
class FeedSource:
    source_id: str
    name: str
    source_type: str
    api_url: Optional[str] = None
    api_key_ref: Optional[str] = None
    update_interval_hours: int = 24
    last_pull_at: Optional[datetime] = None
    signatures_contributed: int = 0
    is_enabled: bool = True


# ── Helpers ────────────────────────────────────────────────────────────────

def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _sig_to_dict(sig: ThreatSignature) -> Dict:
    return {
        "signature_id": sig.signature_id,
        "name": sig.name,
        "threat_type": sig.threat_type,
        "severity": sig.severity,
        "hash_md5": sig.hash_md5,
        "hash_sha256": sig.hash_sha256,
        "yara_rule": sig.yara_rule,
        "description": sig.description,
        "cve_id": sig.cve_id,
        "platform": sig.platform,
        "detection_engine": sig.detection_engine,
        "false_positive_rate": sig.false_positive_rate,
        "first_seen": sig.first_seen.isoformat() if sig.first_seen else None,
        "last_updated": sig.last_updated.isoformat() if sig.last_updated else None,
        "is_active": sig.is_active,
    }


# ── Seed Data ──────────────────────────────────────────────────────────────

def _build_seed_signatures() -> List[ThreatSignature]:
    """Pre-seed with 25 sample signatures covering multiple categories."""
    now = _now()
    sigs: List[ThreatSignature] = []

    # ---- EICAR and test signatures ----
    sigs.append(ThreatSignature(
        signature_id="SIG-EICAR-001", name="EICAR-Test-File",
        threat_type="test", severity="low",
        hash_md5="44d88612fea8a8f36de82e1278abb02f",
        hash_sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        description="EICAR anti-malware test file", platform="all",
        detection_engine="signature", false_positive_rate=0.0,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-EICAR-002", name="EICAR-Test-Zip",
        threat_type="test", severity="low",
        hash_md5="e4968ef99266df7c9a1f0637d2389dab",
        hash_sha256="2546dcffc5ad854d4ddb8d2f2f22d30c0c0c8f66c77b5e1d3e6f4a2d1b8c9e0f",
        description="EICAR test file inside ZIP archive", platform="all",
        detection_engine="signature", false_positive_rate=0.0,
        first_seen=now, last_updated=now,
    ))

    # ---- Known malware hashes ----
    sigs.append(ThreatSignature(
        signature_id="SIG-MAL-001", name="Trojan.GenericKD.46",
        threat_type="trojan", severity="high",
        hash_md5="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        hash_sha256="deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef",
        description="Generic trojan downloader family", platform="windows",
        detection_engine="signature", false_positive_rate=0.001,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-MAL-002", name="Ransomware.WannaCry.A",
        threat_type="ransomware", severity="critical",
        hash_md5="db349b97c37d22f5ea1d1841e3c89eb4",
        hash_sha256="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        description="WannaCry ransomware variant", platform="windows",
        detection_engine="signature", false_positive_rate=0.0,
        cve_id="CVE-2017-0144",
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-MAL-003", name="Adware.BrowserModifier.A",
        threat_type="adware", severity="low",
        hash_md5="1234567890abcdef1234567890abcdef",
        hash_sha256="aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
        description="Browser modifier that injects ads", platform="windows",
        detection_engine="heuristic", false_positive_rate=0.05,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-MAL-004", name="Spyware.KeyLogger.C",
        threat_type="spyware", severity="high",
        hash_md5="fedcba0987654321fedcba0987654321",
        hash_sha256="11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd",
        description="Keystroke logging spyware", platform="windows",
        detection_engine="behavioral", false_positive_rate=0.01,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-MAL-005", name="PUP.OptionalInstaller",
        threat_type="pup", severity="low",
        hash_md5="abcdef1234567890abcdef1234567890",
        hash_sha256="5566778899aabbcc5566778899aabbcc5566778899aabbcc5566778899aabbcc",
        description="Potentially unwanted bundled installer", platform="windows",
        detection_engine="signature", false_positive_rate=0.1,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-MAL-006", name="Trojan.AndroidSMS.A",
        threat_type="trojan", severity="high",
        hash_md5="0a1b2c3d4e5f0a1b2c3d4e5f0a1b2c3d",
        hash_sha256="aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd",
        description="Android SMS-stealing trojan", platform="android",
        detection_engine="signature", false_positive_rate=0.002,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-MAL-007", name="Ransomware.LockBit3",
        threat_type="ransomware", severity="critical",
        hash_md5="b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
        hash_sha256="ccdd00112233aabb44556677889900aabbccdd00112233aabb44556677889900",
        description="LockBit 3.0 ransomware", platform="windows",
        detection_engine="signature", false_positive_rate=0.0,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-MAL-008", name="Backdoor.Linux.Mirai",
        threat_type="malware", severity="critical",
        hash_md5="e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
        hash_sha256="eeff00112233445566778899aabbccddeeff00112233445566778899aabbcc01",
        description="Mirai botnet variant for Linux/IoT", platform="linux",
        detection_engine="signature", false_positive_rate=0.0,
        first_seen=now, last_updated=now,
    ))

    # ---- YARA rule examples ----
    sigs.append(ThreatSignature(
        signature_id="SIG-YARA-001", name="YARA.SuspiciousPacker",
        threat_type="malware", severity="medium",
        yara_rule='rule suspicious_packer { strings: $mz = "MZ" $upx = "UPX!" condition: $mz at 0 and $upx }',
        description="Detects UPX-packed executables", platform="windows",
        detection_engine="signature", false_positive_rate=0.15,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-YARA-002", name="YARA.CobaltStrikeBeacon",
        threat_type="malware", severity="critical",
        yara_rule='rule cobalt_beacon { strings: $s1 = "%s as %s\\n" $s2 = "beacon.dll" condition: all of them }',
        description="Cobalt Strike beacon implant", platform="all",
        detection_engine="signature", false_positive_rate=0.02,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-YARA-003", name="YARA.PowerShellDownloader",
        threat_type="malware", severity="high",
        yara_rule='rule ps_downloader { strings: $a = "IEX" nocase $b = "DownloadString" nocase condition: all of them }',
        description="PowerShell download cradle pattern", platform="windows",
        detection_engine="heuristic", false_positive_rate=0.08,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-YARA-004", name="YARA.MacOSBackdoor",
        threat_type="malware", severity="high",
        yara_rule='rule macos_backdoor { strings: $a = "launchctl" $b = "/tmp/.hidden" condition: all of them }',
        description="macOS persistence backdoor pattern", platform="macos",
        detection_engine="behavioral", false_positive_rate=0.03,
        first_seen=now, last_updated=now,
    ))

    # ---- Network IOCs ----
    sigs.append(ThreatSignature(
        signature_id="SIG-NET-001", name="IOC.C2.EvilDomain",
        threat_type="network_attack", severity="critical",
        description="Known C2 domain: evil-update-server[.]com",
        platform="all", detection_engine="signature", false_positive_rate=0.0,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-NET-002", name="IOC.C2.MaliciousIP",
        threat_type="network_attack", severity="high",
        description="Known C2 IP range: 185.220.101.0/24 (TOR exit + botnet C2)",
        platform="all", detection_engine="signature", false_positive_rate=0.001,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-NET-003", name="IOC.Phishing.FakeBankDomain",
        threat_type="phishing", severity="high",
        description="Phishing domain mimicking major bank: secure-banklogin[.]net",
        platform="all", detection_engine="signature", false_positive_rate=0.0,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-NET-004", name="IOC.DNSTunnel.Suspicious",
        threat_type="network_attack", severity="medium",
        description="DNS tunneling detection - excessive TXT record queries",
        platform="all", detection_engine="heuristic", false_positive_rate=0.12,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-NET-005", name="IOC.CryptoMiner.Pool",
        threat_type="malware", severity="medium",
        description="Connection to known crypto mining pool: stratum+tcp://pool.minexmr.com",
        platform="all", detection_engine="signature", false_positive_rate=0.01,
        first_seen=now, last_updated=now,
    ))

    # ---- Behavioral / heuristic ----
    sigs.append(ThreatSignature(
        signature_id="SIG-BEH-001", name="Behavior.RansomEncrypt",
        threat_type="ransomware", severity="critical",
        description="Rapid file encryption pattern detected (>50 files/sec rename+encrypt)",
        platform="all", detection_engine="behavioral", false_positive_rate=0.005,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-BEH-002", name="Behavior.CredentialDump",
        threat_type="malware", severity="critical",
        description="LSASS memory access pattern consistent with credential dumping",
        platform="windows", detection_engine="behavioral", false_positive_rate=0.02,
        cve_id="CVE-2021-36934",
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-BEH-003", name="Behavior.PrivilegeEscalation",
        threat_type="malware", severity="high",
        description="Unexpected SYSTEM token impersonation from user-mode process",
        platform="windows", detection_engine="behavioral", false_positive_rate=0.03,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-BEH-004", name="Behavior.DataExfiltration",
        threat_type="spyware", severity="high",
        description="Large outbound data transfer to newly-registered domain",
        platform="all", detection_engine="behavioral", false_positive_rate=0.07,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-BEH-005", name="Behavior.LateralMovement",
        threat_type="network_attack", severity="critical",
        description="WMI/PSExec lateral movement pattern across subnet",
        platform="windows", detection_engine="behavioral", false_positive_rate=0.04,
        first_seen=now, last_updated=now,
    ))
    sigs.append(ThreatSignature(
        signature_id="SIG-NET-006", name="IOC.TOR.ExitNode",
        threat_type="network_attack", severity="medium",
        description="Traffic to known TOR exit node relay list",
        platform="all", detection_engine="signature", false_positive_rate=0.05,
        first_seen=now, last_updated=now,
    ))

    return sigs


# ── Service ────────────────────────────────────────────────────────────────

class SignaturePipelineService:
    """
    Manages the Shield threat signature lifecycle: ingestion, versioning,
    delta generation, and distribution to endpoints.

    Supports DB persistence with graceful in-memory fallback.
    """

    def __init__(self, db: Optional[Any] = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory stores (fallback / cache)
        self._signatures: Dict[str, ThreatSignature] = {}
        self._databases: Dict[str, SignatureDatabase] = {}
        self._deltas: Dict[str, SignatureDelta] = {}
        self._distributions: Dict[str, UpdateDistribution] = {}
        self._feeds: Dict[str, FeedSource] = {}
        self._current_version: Optional[str] = None
        self._next_build: int = 1

        self._seed()

    # ── Seeding ────────────────────────────────────────────────────────

    def _seed(self):
        """Load sample signatures into the store."""
        for sig in _build_seed_signatures():
            self._signatures[sig.signature_id] = sig
        logger.info("SignaturePipeline seeded with %d signatures", len(self._signatures))

        # Seed two feed sources
        self._feeds["FEED-CLAMAV"] = FeedSource(
            source_id="FEED-CLAMAV", name="ClamAV Official",
            source_type=FeedType.CLAMAV.value,
            api_url="https://database.clamav.net",
            update_interval_hours=6, is_enabled=True,
        )
        self._feeds["FEED-YARA"] = FeedSource(
            source_id="FEED-YARA", name="YARA Rules Community",
            source_type=FeedType.YARA_REPO.value,
            api_url="https://github.com/Yara-Rules/rules",
            update_interval_hours=12, is_enabled=True,
        )
        self._feeds["FEED-OTX"] = FeedSource(
            source_id="FEED-OTX", name="AlienVault OTX",
            source_type=FeedType.ALIENVAULT_OTX.value,
            api_url="https://otx.alienvault.com/api/v1/pulses/subscribed",
            api_key_ref="vault://shield/otx_api_key",
            update_interval_hours=4, is_enabled=False,
        )

    # ── DB helpers ─────────────────────────────────────────────────────

    def _sig_from_model(self, m: Any) -> ThreatSignature:
        return ThreatSignature(
            signature_id=m.signature_id, name=m.name,
            threat_type=m.threat_type, severity=m.severity,
            hash_md5=m.hash_md5, hash_sha256=m.hash_sha256,
            yara_rule=m.yara_rule, description=m.description,
            cve_id=m.cve_id, platform=m.platform,
            detection_engine=m.detection_engine,
            false_positive_rate=m.false_positive_rate,
            first_seen=m.first_seen, last_updated=m.last_updated,
            is_active=m.is_active,
        )

    def _sig_to_model(self, sig: ThreatSignature) -> Any:
        return ThreatSignatureModel(
            signature_id=sig.signature_id, name=sig.name,
            threat_type=sig.threat_type, severity=sig.severity,
            hash_md5=sig.hash_md5, hash_sha256=sig.hash_sha256,
            yara_rule=sig.yara_rule, description=sig.description,
            cve_id=sig.cve_id, platform=sig.platform,
            detection_engine=sig.detection_engine,
            false_positive_rate=sig.false_positive_rate,
            first_seen=sig.first_seen, last_updated=sig.last_updated,
            is_active=sig.is_active,
        )

    # ── Signature CRUD ─────────────────────────────────────────────────

    def add_signature(self, data: Dict) -> Dict:
        """Add a new threat signature."""
        sig_id = data.get("signature_id", f"SIG-{_uid()[:8].upper()}")
        sig = ThreatSignature(
            signature_id=sig_id,
            name=data["name"],
            threat_type=data.get("threat_type", "malware"),
            severity=data.get("severity", "medium"),
            hash_md5=data.get("hash_md5"),
            hash_sha256=data.get("hash_sha256"),
            yara_rule=data.get("yara_rule"),
            description=data.get("description"),
            cve_id=data.get("cve_id"),
            platform=data.get("platform", "all"),
            detection_engine=data.get("detection_engine", "signature"),
            false_positive_rate=data.get("false_positive_rate", 0.0),
            is_active=data.get("is_active", True),
        )
        if self._use_db:
            try:
                self.db.add(self._sig_to_model(sig))
                self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB add_signature failed, using memory: %s", e)
        self._signatures[sig.signature_id] = sig
        return {"signature_id": sig.signature_id, "name": sig.name, "status": "created"}

    def update_signature(self, signature_id: str, data: Dict) -> Dict:
        """Update an existing signature."""
        sig = self._signatures.get(signature_id)
        if not sig:
            return {"error": "Signature not found", "signature_id": signature_id}
        for k, v in data.items():
            if hasattr(sig, k) and k != "signature_id":
                setattr(sig, k, v)
        sig.last_updated = _now()
        if self._use_db:
            try:
                m = self.db.query(ThreatSignatureModel).filter_by(signature_id=signature_id).first()
                if m:
                    for k, v in data.items():
                        if hasattr(m, k) and k not in ("signature_id", "id"):
                            setattr(m, k, v)
                    m.last_updated = sig.last_updated
                    self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB update_signature failed: %s", e)
        return {"signature_id": signature_id, "status": "updated"}

    def delete_signature(self, signature_id: str) -> Dict:
        """Soft-delete a signature (set inactive)."""
        sig = self._signatures.get(signature_id)
        if not sig:
            return {"error": "Signature not found", "signature_id": signature_id}
        sig.is_active = False
        sig.last_updated = _now()
        if self._use_db:
            try:
                m = self.db.query(ThreatSignatureModel).filter_by(signature_id=signature_id).first()
                if m:
                    m.is_active = False
                    m.last_updated = sig.last_updated
                    self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB delete_signature failed: %s", e)
        return {"signature_id": signature_id, "status": "deleted"}

    def get_signature(self, signature_id: str) -> Optional[Dict]:
        """Get a single signature by ID."""
        sig = self._signatures.get(signature_id)
        if not sig:
            return None
        return _sig_to_dict(sig)

    def search_signatures(self, query: str = "", filters: Optional[Dict] = None) -> List[Dict]:
        """Search signatures by name/description, with optional filters."""
        filters = filters or {}
        results = []
        q_lower = query.lower()
        for sig in self._signatures.values():
            if not sig.is_active and not filters.get("include_inactive"):
                continue
            if q_lower:
                searchable = f"{sig.name} {sig.description or ''} {sig.threat_type} {sig.cve_id or ''}".lower()
                if q_lower not in searchable:
                    continue
            if filters.get("threat_type") and sig.threat_type != filters["threat_type"]:
                continue
            if filters.get("severity") and sig.severity != filters["severity"]:
                continue
            if filters.get("platform") and sig.platform not in (filters["platform"], "all"):
                continue
            if filters.get("detection_engine") and sig.detection_engine != filters["detection_engine"]:
                continue
            results.append(_sig_to_dict(sig))
        return results

    # ── Batch Import ───────────────────────────────────────────────────

    def import_signatures_batch(self, signatures: List[Dict]) -> Dict:
        """Bulk import signatures from a feed."""
        imported = 0
        skipped = 0
        errors = 0
        for s in signatures:
            try:
                if "name" not in s:
                    errors += 1
                    continue
                sig_id = s.get("signature_id", f"SIG-{_uid()[:8].upper()}")
                if sig_id in self._signatures:
                    skipped += 1
                    continue
                self.add_signature({**s, "signature_id": sig_id})
                imported += 1
            except Exception as e:
                logger.warning("Import error for sig: %s", e)
                errors += 1
        return {
            "imported": imported,
            "skipped": skipped,
            "errors": errors,
            "total_in_db": len([s for s in self._signatures.values() if s.is_active]),
        }

    # ── Database Versioning ────────────────────────────────────────────

    def publish_database(self, release_notes: str = "") -> Dict:
        """Publish a new versioned snapshot of active signatures."""
        active_sigs = {k: v for k, v in self._signatures.items() if v.is_active}
        build = self._next_build
        self._next_build += 1
        version = f"1.0.{build}"

        # Compute stats vs previous
        prev_ids = set()
        if self._current_version and self._current_version in self._databases:
            prev_ids = set(self._databases[self._current_version].signature_ids)
        current_ids = set(active_sigs.keys())
        new_count = len(current_ids - prev_ids)
        removed_count = len(prev_ids - current_ids)

        payload = json.dumps(sorted(current_ids))
        checksum = _sha256(payload)
        db_id = f"SIGDB-{build}"

        db = SignatureDatabase(
            db_id=db_id, version=version, build_number=build,
            total_signatures=len(active_sigs),
            new_in_version=new_count, removed_in_version=removed_count,
            size_bytes=len(payload), checksum_sha256=checksum,
            release_notes=release_notes,
            signature_ids=sorted(current_ids),
        )
        self._databases[version] = db
        self._current_version = version

        if self._use_db:
            try:
                m = SignatureDatabaseModel(
                    db_id=db_id, version=version, build_number=build,
                    total_signatures=db.total_signatures,
                    new_in_version=new_count, removed_in_version=removed_count,
                    size_bytes=db.size_bytes, checksum_sha256=checksum,
                    release_notes=release_notes,
                    signature_ids_json=db.signature_ids,
                )
                self.db.add(m)
                self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB publish_database failed: %s", e)

        return {
            "db_id": db_id, "version": version, "build_number": build,
            "total_signatures": db.total_signatures,
            "new_in_version": new_count, "removed_in_version": removed_count,
            "checksum_sha256": checksum, "release_notes": release_notes,
        }

    def get_database_version(self) -> Optional[Dict]:
        """Return the current (latest) database version info."""
        if not self._current_version:
            return None
        db = self._databases.get(self._current_version)
        if not db:
            return None
        return {
            "db_id": db.db_id, "version": db.version,
            "build_number": db.build_number,
            "total_signatures": db.total_signatures,
            "new_in_version": db.new_in_version,
            "removed_in_version": db.removed_in_version,
            "size_bytes": db.size_bytes,
            "checksum_sha256": db.checksum_sha256,
            "published_at": db.published_at.isoformat(),
            "release_notes": db.release_notes,
        }

    def list_database_versions(self) -> List[Dict]:
        """Return all published database versions."""
        versions = []
        for db in sorted(self._databases.values(), key=lambda d: d.build_number, reverse=True):
            versions.append({
                "db_id": db.db_id, "version": db.version,
                "build_number": db.build_number,
                "total_signatures": db.total_signatures,
                "published_at": db.published_at.isoformat(),
                "release_notes": db.release_notes,
            })
        return versions

    # ── Delta Generation ───────────────────────────────────────────────

    def generate_delta(self, from_version: str, to_version: str) -> Optional[Dict]:
        """Create a delta update package between two versions."""
        from_db = self._databases.get(from_version)
        to_db = self._databases.get(to_version)
        if not from_db or not to_db:
            return {"error": "One or both versions not found"}

        from_ids = set(from_db.signature_ids)
        to_ids = set(to_db.signature_ids)

        added_ids = to_ids - from_ids
        removed_ids = from_ids - to_ids

        added = [_sig_to_dict(self._signatures[sid]) for sid in added_ids if sid in self._signatures]
        removed = list(removed_ids)
        # modified = signatures present in both but with different last_updated
        modified = []
        for sid in from_ids & to_ids:
            sig = self._signatures.get(sid)
            if sig and sig.last_updated and sig.last_updated > from_db.published_at:
                modified.append(_sig_to_dict(sig))

        payload = json.dumps({"added": added, "removed": removed, "modified": modified})
        checksum = _sha256(payload)
        delta_id = f"DELTA-{from_version}-{to_version}"

        delta = SignatureDelta(
            delta_id=delta_id, from_version=from_version, to_version=to_version,
            added_signatures=added, removed_signature_ids=removed,
            modified_signatures=modified,
            size_bytes=len(payload), checksum_sha256=checksum,
        )
        self._deltas[delta_id] = delta

        if self._use_db:
            try:
                m = SignatureDeltaModel(
                    delta_id=delta_id, from_version=from_version, to_version=to_version,
                    added_signatures_json=added, removed_signature_ids_json=removed,
                    modified_signatures_json=modified,
                    size_bytes=delta.size_bytes, checksum_sha256=checksum,
                )
                self.db.add(m)
                self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB generate_delta failed: %s", e)

        return {
            "delta_id": delta_id,
            "from_version": from_version, "to_version": to_version,
            "added_count": len(added), "removed_count": len(removed),
            "modified_count": len(modified),
            "size_bytes": delta.size_bytes, "checksum_sha256": checksum,
        }

    def get_delta(self, from_version: str) -> Optional[Dict]:
        """Get delta from the given version to current."""
        if not self._current_version:
            return {"error": "No published database yet"}
        if from_version == self._current_version:
            return {"status": "up_to_date", "version": self._current_version}
        return self.generate_delta(from_version, self._current_version)

    # ── Update Distribution ────────────────────────────────────────────

    def request_update(self, endpoint_id: str, current_version: Optional[str] = None,
                       device_id: Optional[str] = None) -> Dict:
        """Check and queue an update for an endpoint."""
        if not self._current_version:
            return {"status": "no_database", "message": "No signature database published yet"}

        if current_version == self._current_version:
            return {"status": "up_to_date", "version": self._current_version}

        dist_id = f"DIST-{_uid()[:8].upper()}"
        dist = UpdateDistribution(
            distribution_id=dist_id, db_version=self._current_version,
            endpoint_id=endpoint_id, device_id=device_id,
            status=UpdateStatus.PENDING.value,
        )
        self._distributions[dist_id] = dist

        if self._use_db:
            try:
                m = UpdateDistributionModel(
                    distribution_id=dist_id, db_version=self._current_version,
                    endpoint_id=endpoint_id, device_id=device_id,
                    status=UpdateStatus.PENDING.value,
                )
                self.db.add(m)
                self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB request_update failed: %s", e)

        result: Dict[str, Any] = {
            "distribution_id": dist_id,
            "status": "update_available",
            "current_version": current_version,
            "latest_version": self._current_version,
            "endpoint_id": endpoint_id,
        }
        # Include delta if upgrading from a known version
        if current_version and current_version in self._databases:
            delta = self.generate_delta(current_version, self._current_version)
            result["delta"] = delta
        return result

    def record_update_result(self, distribution_id: str, status: str,
                             error: Optional[str] = None) -> Dict:
        """Record the outcome of an update distribution."""
        dist = self._distributions.get(distribution_id)
        if not dist:
            return {"error": "Distribution not found"}
        dist.status = status
        if status in (UpdateStatus.INSTALLED.value, UpdateStatus.FAILED.value):
            dist.completed_at = _now()
        if error:
            dist.error = error

        if self._use_db:
            try:
                m = self.db.query(UpdateDistributionModel).filter_by(
                    distribution_id=distribution_id).first()
                if m:
                    m.status = status
                    m.completed_at = dist.completed_at
                    m.error = error
                    self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB record_update_result failed: %s", e)

        return {
            "distribution_id": distribution_id,
            "status": status,
            "completed_at": dist.completed_at.isoformat() if dist.completed_at else None,
        }

    # ── Feed Sources ───────────────────────────────────────────────────

    def register_feed_source(self, data: Dict) -> Dict:
        """Register a new external feed source."""
        src_id = data.get("source_id", f"FEED-{_uid()[:8].upper()}")
        feed = FeedSource(
            source_id=src_id,
            name=data["name"],
            source_type=data.get("source_type", FeedType.CUSTOM.value),
            api_url=data.get("api_url"),
            api_key_ref=data.get("api_key_ref"),
            update_interval_hours=data.get("update_interval_hours", 24),
            is_enabled=data.get("is_enabled", True),
        )
        self._feeds[src_id] = feed

        if self._use_db:
            try:
                m = FeedSourceModel(
                    source_id=src_id, name=feed.name,
                    source_type=feed.source_type,
                    api_url=feed.api_url, api_key_ref=feed.api_key_ref,
                    update_interval_hours=feed.update_interval_hours,
                    is_enabled=feed.is_enabled,
                )
                self.db.add(m)
                self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB register_feed_source failed: %s", e)

        return {"source_id": src_id, "name": feed.name, "status": "registered"}

    def update_feed_source(self, source_id: str, data: Dict) -> Dict:
        """Update a feed source configuration."""
        feed = self._feeds.get(source_id)
        if not feed:
            return {"error": "Feed source not found"}
        for k, v in data.items():
            if hasattr(feed, k) and k != "source_id":
                setattr(feed, k, v)

        if self._use_db:
            try:
                m = self.db.query(FeedSourceModel).filter_by(source_id=source_id).first()
                if m:
                    for k, v in data.items():
                        if hasattr(m, k) and k not in ("source_id", "id"):
                            setattr(m, k, v)
                    self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB update_feed_source failed: %s", e)

        return {"source_id": source_id, "status": "updated"}

    def delete_feed_source(self, source_id: str) -> Dict:
        """Remove a feed source."""
        if source_id not in self._feeds:
            return {"error": "Feed source not found"}
        del self._feeds[source_id]

        if self._use_db:
            try:
                m = self.db.query(FeedSourceModel).filter_by(source_id=source_id).first()
                if m:
                    self.db.delete(m)
                    self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB delete_feed_source failed: %s", e)

        return {"source_id": source_id, "status": "deleted"}

    def list_feed_sources(self) -> List[Dict]:
        """List all configured feed sources."""
        return [
            {
                "source_id": f.source_id, "name": f.name,
                "source_type": f.source_type, "api_url": f.api_url,
                "update_interval_hours": f.update_interval_hours,
                "last_pull_at": f.last_pull_at.isoformat() if f.last_pull_at else None,
                "signatures_contributed": f.signatures_contributed,
                "is_enabled": f.is_enabled,
            }
            for f in self._feeds.values()
        ]

    def pull_feed(self, source_id: str) -> Dict:
        """
        Pull latest signatures from a feed source.

        This is a mock implementation — ready for real API keys and HTTP
        calls.  Each feed type produces simulated signatures.
        """
        feed = self._feeds.get(source_id)
        if not feed:
            return {"error": "Feed source not found"}
        if not feed.is_enabled:
            return {"source_id": source_id, "status": "disabled", "imported": 0}

        # Mock: generate 3-5 signatures per pull
        import random
        count = random.randint(3, 5)
        mock_sigs = []
        for i in range(count):
            uid = _uid()[:6].upper()
            mock_sigs.append({
                "signature_id": f"SIG-{feed.source_type.upper()[:4]}-{uid}",
                "name": f"{feed.name}.AutoSig.{uid}",
                "threat_type": random.choice(["malware", "trojan", "phishing", "network_attack"]),
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "hash_sha256": _sha256(uid),
                "description": f"Auto-imported from {feed.name} feed",
                "platform": random.choice(["windows", "linux", "all"]),
                "detection_engine": "signature",
                "false_positive_rate": round(random.uniform(0.0, 0.1), 3),
            })

        result = self.import_signatures_batch(mock_sigs)
        feed.last_pull_at = _now()
        feed.signatures_contributed += result["imported"]

        if self._use_db:
            try:
                m = self.db.query(FeedSourceModel).filter_by(source_id=source_id).first()
                if m:
                    m.last_pull_at = feed.last_pull_at
                    m.signatures_contributed = feed.signatures_contributed
                    self.db.commit()
            except Exception as e:
                self.db.rollback()
                logger.warning("DB pull_feed update failed: %s", e)

        return {
            "source_id": source_id, "source_name": feed.name,
            "status": "pulled", **result,
        }

    def pull_all_feeds(self) -> Dict:
        """Pull from all enabled feed sources."""
        results = []
        total_imported = 0
        for src_id, feed in self._feeds.items():
            if feed.is_enabled:
                r = self.pull_feed(src_id)
                results.append(r)
                total_imported += r.get("imported", 0)
        return {
            "feeds_pulled": len(results),
            "total_imported": total_imported,
            "results": results,
        }

    # ── Stats & Dashboard ──────────────────────────────────────────────

    def get_signature_stats(self) -> Dict:
        """Signature statistics: total, by type, platform, engine."""
        active = [s for s in self._signatures.values() if s.is_active]
        by_type: Dict[str, int] = {}
        by_platform: Dict[str, int] = {}
        by_engine: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for s in active:
            by_type[s.threat_type] = by_type.get(s.threat_type, 0) + 1
            by_platform[s.platform] = by_platform.get(s.platform, 0) + 1
            by_engine[s.detection_engine] = by_engine.get(s.detection_engine, 0) + 1
            by_severity[s.severity] = by_severity.get(s.severity, 0) + 1
        return {
            "total_active": len(active),
            "total_inactive": len(self._signatures) - len(active),
            "by_threat_type": by_type,
            "by_platform": by_platform,
            "by_detection_engine": by_engine,
            "by_severity": by_severity,
        }

    def get_distribution_stats(self) -> Dict:
        """Distribution statistics across endpoints."""
        total = len(self._distributions)
        by_status: Dict[str, int] = {}
        for d in self._distributions.values():
            by_status[d.status] = by_status.get(d.status, 0) + 1
        return {
            "total_distributions": total,
            "by_status": by_status,
            "up_to_date": by_status.get(UpdateStatus.INSTALLED.value, 0),
            "pending": by_status.get(UpdateStatus.PENDING.value, 0),
            "failed": by_status.get(UpdateStatus.FAILED.value, 0),
            "current_version": self._current_version,
        }

    def get_dashboard(self) -> Dict:
        """Combined dashboard view."""
        return {
            "signatures": self.get_signature_stats(),
            "distribution": self.get_distribution_stats(),
            "database": self.get_database_version(),
            "feeds": {
                "total": len(self._feeds),
                "enabled": len([f for f in self._feeds.values() if f.is_enabled]),
                "sources": self.list_feed_sources(),
            },
            "versions_published": len(self._databases),
        }
