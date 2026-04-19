"""
AITHER Platform - NAC (Network Access Control) Service
Enforces device posture assessment before granting network access,
manages 802.1X policies, and handles guest/BYOD network segmentation.

Provides:
- NAC policy CRUD and enforcement
- Device posture assessment and scoring
- 802.1X network access decisions
- Guest/BYOD registration and management
- Captive portal configuration
- Device quarantine and blocking
- Compliance reporting and dashboards

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.nac import (
        NACPolicyModel,
        DevicePostureModel,
        AccessDecisionModel,
        GuestRegistrationModel,
        CaptivePortalConfigModel,
        BlockedDeviceModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class NetworkZone(str, Enum):
    """Network zone assignments"""
    CORPORATE = "corporate"
    GUEST = "guest"
    QUARANTINE = "quarantine"
    RESTRICTED = "restricted"
    IOT = "iot"
    BYOD = "byod"


class PostureResult(str, Enum):
    """Posture assessment result"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class AccessDecisionType(str, Enum):
    """Access decision types"""
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    DENY = "deny"
    GUEST = "guest"


class AntivirusStatus(str, Enum):
    """Antivirus status values"""
    INSTALLED = "installed"
    OUTDATED = "outdated"
    MISSING = "missing"
    UNKNOWN = "unknown"


class GuestStatus(str, Enum):
    """Guest registration status"""
    PENDING = "pending"
    APPROVED = "approved"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class NACPolicy:
    """NAC access control policy"""
    policy_id: str
    client_id: str = ""
    name: str = ""
    description: str = ""
    posture_requirements: Dict[str, Any] = field(default_factory=lambda: {
        "min_os_version": "",
        "antivirus_required": False,
        "firewall_required": False,
        "encryption_required": False,
        "patch_compliance_min_pct": 0.0,
        "approved_os": [],
    })
    network_assignment: str = NetworkZone.CORPORATE.value
    vlan_id: int = 0
    priority: int = 100
    is_enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class DevicePosture:
    """Device posture assessment"""
    posture_id: str
    device_id: str
    mac_address: str = ""
    ip_address: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    antivirus_status: str = AntivirusStatus.UNKNOWN.value
    firewall_enabled: bool = False
    disk_encrypted: bool = False
    patch_compliance_pct: float = 0.0
    last_assessed_at: Optional[datetime] = None
    posture_score: int = 0
    compliant: bool = False
    assigned_network: str = NetworkZone.QUARANTINE.value
    violations: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class AccessDecision:
    """Access control decision record"""
    decision_id: str
    device_id: str
    mac_address: str = ""
    policy_id: str = ""
    decision: str = AccessDecisionType.DENY.value
    reason: str = ""
    assigned_vlan: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class GuestRegistration:
    """Guest network registration"""
    guest_id: str
    client_id: str = ""
    name: str = ""
    email: str = ""
    company: str = ""
    sponsor_email: str = ""
    mac_address: str = ""
    access_start: Optional[datetime] = None
    access_end: Optional[datetime] = None
    status: str = GuestStatus.PENDING.value
    network_assigned: str = NetworkZone.GUEST.value
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class CaptivePortalConfig:
    """Captive portal configuration"""
    portal_id: str
    client_id: str = ""
    branding: Dict[str, Any] = field(default_factory=lambda: {
        "logo_url": "",
        "background_color": "#ffffff",
        "primary_color": "#0066cc",
        "company_name": "Aither MSP",
    })
    terms_of_use: str = ""
    require_registration: bool = True
    session_timeout_minutes: int = 480
    bandwidth_limit_mbps: float = 10.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class BlockedDevice:
    """Blocked device record"""
    mac_address: str
    reason: str = ""
    blocked_by: str = "system"
    blocked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _policy_from_row(row) -> NACPolicy:
    return NACPolicy(
        policy_id=row.policy_id,
        client_id=row.client_id or "",
        name=row.name,
        description=row.description or "",
        posture_requirements=row.posture_requirements or {},
        network_assignment=row.network_assignment or NetworkZone.CORPORATE.value,
        vlan_id=row.vlan_id or 0,
        priority=row.priority or 100,
        is_enabled=row.is_enabled if row.is_enabled is not None else True,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _posture_from_row(row) -> DevicePosture:
    return DevicePosture(
        posture_id=row.posture_id,
        device_id=row.device_id,
        mac_address=row.mac_address or "",
        ip_address=row.ip_address or "",
        hostname=row.hostname or "",
        os_type=row.os_type or "",
        os_version=row.os_version or "",
        antivirus_status=row.antivirus_status or AntivirusStatus.UNKNOWN.value,
        firewall_enabled=row.firewall_enabled or False,
        disk_encrypted=row.disk_encrypted or False,
        patch_compliance_pct=row.patch_compliance_pct or 0.0,
        last_assessed_at=row.last_assessed_at,
        posture_score=row.posture_score or 0,
        compliant=row.compliant or False,
        assigned_network=row.assigned_network or NetworkZone.QUARANTINE.value,
        violations=row.violations or [],
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _decision_from_row(row) -> AccessDecision:
    return AccessDecision(
        decision_id=row.decision_id,
        device_id=row.device_id,
        mac_address=row.mac_address or "",
        policy_id=row.policy_id or "",
        decision=row.decision,
        reason=row.reason or "",
        assigned_vlan=row.assigned_vlan or 0,
        timestamp=row.timestamp or datetime.now(timezone.utc),
    )


def _guest_from_row(row) -> GuestRegistration:
    return GuestRegistration(
        guest_id=row.guest_id,
        client_id=row.client_id or "",
        name=row.name,
        email=row.email or "",
        company=row.company or "",
        sponsor_email=row.sponsor_email or "",
        mac_address=row.mac_address or "",
        access_start=row.access_start,
        access_end=row.access_end,
        status=row.status or GuestStatus.PENDING.value,
        network_assigned=row.network_assigned or NetworkZone.GUEST.value,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _portal_from_row(row) -> CaptivePortalConfig:
    return CaptivePortalConfig(
        portal_id=row.portal_id,
        client_id=row.client_id or "",
        branding=row.branding or {},
        terms_of_use=row.terms_of_use or "",
        require_registration=row.require_registration if row.require_registration is not None else True,
        session_timeout_minutes=row.session_timeout_minutes or 480,
        bandwidth_limit_mbps=row.bandwidth_limit_mbps or 10.0,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _blocked_from_row(row) -> BlockedDevice:
    return BlockedDevice(
        mac_address=row.mac_address,
        reason=row.reason or "",
        blocked_by=row.blocked_by or "system",
        blocked_at=row.blocked_at or datetime.now(timezone.utc),
    )


# ============================================================
# Serialization helpers
# ============================================================

def _policy_to_dict(p: NACPolicy) -> dict:
    return {
        "policy_id": p.policy_id, "client_id": p.client_id, "name": p.name,
        "description": p.description, "posture_requirements": p.posture_requirements,
        "network_assignment": p.network_assignment, "vlan_id": p.vlan_id,
        "priority": p.priority, "is_enabled": p.is_enabled,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _posture_to_dict(p: DevicePosture) -> dict:
    return {
        "posture_id": p.posture_id, "device_id": p.device_id,
        "mac_address": p.mac_address, "ip_address": p.ip_address,
        "hostname": p.hostname, "os_type": p.os_type, "os_version": p.os_version,
        "antivirus_status": p.antivirus_status, "firewall_enabled": p.firewall_enabled,
        "disk_encrypted": p.disk_encrypted, "patch_compliance_pct": p.patch_compliance_pct,
        "last_assessed_at": p.last_assessed_at.isoformat() if p.last_assessed_at else None,
        "posture_score": p.posture_score, "compliant": p.compliant,
        "assigned_network": p.assigned_network, "violations": p.violations,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _decision_to_dict(d: AccessDecision) -> dict:
    return {
        "decision_id": d.decision_id, "device_id": d.device_id,
        "mac_address": d.mac_address, "policy_id": d.policy_id,
        "decision": d.decision, "reason": d.reason,
        "assigned_vlan": d.assigned_vlan,
        "timestamp": d.timestamp.isoformat() if d.timestamp else None,
    }


def _guest_to_dict(g: GuestRegistration) -> dict:
    return {
        "guest_id": g.guest_id, "client_id": g.client_id, "name": g.name,
        "email": g.email, "company": g.company, "sponsor_email": g.sponsor_email,
        "mac_address": g.mac_address,
        "access_start": g.access_start.isoformat() if g.access_start else None,
        "access_end": g.access_end.isoformat() if g.access_end else None,
        "status": g.status, "network_assigned": g.network_assigned,
        "created_at": g.created_at.isoformat() if g.created_at else None,
        "updated_at": g.updated_at.isoformat() if g.updated_at else None,
    }


def _portal_to_dict(c: CaptivePortalConfig) -> dict:
    return {
        "portal_id": c.portal_id, "client_id": c.client_id,
        "branding": c.branding, "terms_of_use": c.terms_of_use,
        "require_registration": c.require_registration,
        "session_timeout_minutes": c.session_timeout_minutes,
        "bandwidth_limit_mbps": c.bandwidth_limit_mbps,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _blocked_to_dict(b: BlockedDevice) -> dict:
    return {
        "mac_address": b.mac_address, "reason": b.reason,
        "blocked_by": b.blocked_by,
        "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None,
    }


# ============================================================
# NAC Service
# ============================================================

class NACService:
    """
    Network Access Control Service

    Enforces device posture assessment before granting network access,
    manages 802.1X policies, and handles guest/BYOD network segmentation.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._policies: Dict[str, NACPolicy] = {}
        self._postures: Dict[str, DevicePosture] = {}  # device_id -> posture
        self._decisions: List[AccessDecision] = []
        self._guests: Dict[str, GuestRegistration] = {}
        self._portal_configs: Dict[str, CaptivePortalConfig] = {}  # client_id -> config
        self._blocked: Dict[str, BlockedDevice] = {}  # mac_address -> blocked

        self._init_default_policies()

    # ---- Default policies ----

    def _init_default_policies(self) -> None:
        """Initialize pre-built NAC policies."""
        defaults = [
            {
                "name": "Corporate Standard",
                "description": "Full posture enforcement for corporate devices",
                "posture_requirements": {
                    "antivirus_required": True,
                    "firewall_required": True,
                    "encryption_required": True,
                    "patch_compliance_min_pct": 80.0,
                    "approved_os": ["Windows 10", "Windows 11", "macOS 13", "macOS 14", "Ubuntu 22.04"],
                },
                "network_assignment": NetworkZone.CORPORATE.value,
                "vlan_id": 10,
                "priority": 10,
            },
            {
                "name": "BYOD Minimum",
                "description": "Minimum requirements for BYOD devices",
                "posture_requirements": {
                    "antivirus_required": True,
                    "firewall_required": False,
                    "encryption_required": False,
                    "patch_compliance_min_pct": 0.0,
                },
                "network_assignment": NetworkZone.BYOD.value,
                "vlan_id": 50,
                "priority": 50,
            },
            {
                "name": "IoT Restricted",
                "description": "Isolated VLAN for IoT devices, no internet access to LAN",
                "posture_requirements": {},
                "network_assignment": NetworkZone.IOT.value,
                "vlan_id": 100,
                "priority": 80,
            },
            {
                "name": "Guest WiFi",
                "description": "Captive portal required, bandwidth limited",
                "posture_requirements": {},
                "network_assignment": NetworkZone.GUEST.value,
                "vlan_id": 200,
                "priority": 90,
            },
        ]
        for dflt in defaults:
            self.create_policy(**dflt)

    # ============================================================
    # Policy CRUD
    # ============================================================

    def create_policy(self, name: str, client_id: str = "", **kwargs) -> NACPolicy:
        """Create a new NAC policy."""
        pid = f"NAC-POL-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        policy = NACPolicy(
            policy_id=pid,
            client_id=client_id,
            name=name,
            description=kwargs.get("description", ""),
            posture_requirements=kwargs.get("posture_requirements", {}),
            network_assignment=kwargs.get("network_assignment", NetworkZone.CORPORATE.value),
            vlan_id=kwargs.get("vlan_id", 0),
            priority=kwargs.get("priority", 100),
            is_enabled=kwargs.get("is_enabled", True),
            created_at=now,
        )
        if self._use_db:
            try:
                row = NACPolicyModel(
                    policy_id=policy.policy_id, client_id=policy.client_id,
                    name=policy.name, description=policy.description,
                    posture_requirements=policy.posture_requirements,
                    network_assignment=policy.network_assignment,
                    vlan_id=policy.vlan_id, priority=policy.priority,
                    is_enabled=policy.is_enabled,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("NAC policy created in DB: %s", pid)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for policy %s, using memory: %s", pid, exc)
                self._policies[pid] = policy
        else:
            self._policies[pid] = policy
        return policy

    def get_policy(self, policy_id: str) -> Optional[NACPolicy]:
        """Get a NAC policy by ID."""
        if self._use_db:
            try:
                row = self.db.query(NACPolicyModel).filter(
                    NACPolicyModel.policy_id == policy_id
                ).first()
                return _policy_from_row(row) if row else None
            except Exception:
                pass
        return self._policies.get(policy_id)

    def list_policies(self, client_id: str = "", enabled_only: bool = False) -> List[NACPolicy]:
        """List NAC policies with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(NACPolicyModel)
                if client_id:
                    q = q.filter(NACPolicyModel.client_id == client_id)
                if enabled_only:
                    q = q.filter(NACPolicyModel.is_enabled == True)  # noqa: E712
                return [_policy_from_row(r) for r in q.order_by(NACPolicyModel.priority).all()]
            except Exception:
                pass
        policies = list(self._policies.values())
        if client_id:
            policies = [p for p in policies if p.client_id == client_id]
        if enabled_only:
            policies = [p for p in policies if p.is_enabled]
        return sorted(policies, key=lambda p: p.priority)

    def update_policy(self, policy_id: str, **kwargs) -> Optional[NACPolicy]:
        """Update an existing NAC policy."""
        if self._use_db:
            try:
                row = self.db.query(NACPolicyModel).filter(
                    NACPolicyModel.policy_id == policy_id
                ).first()
                if not row:
                    return None
                for k, v in kwargs.items():
                    if hasattr(row, k):
                        setattr(row, k, v)
                self.db.commit()
                return _policy_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for policy %s: %s", policy_id, exc)
        pol = self._policies.get(policy_id)
        if not pol:
            return None
        for k, v in kwargs.items():
            if hasattr(pol, k):
                setattr(pol, k, v)
        pol.updated_at = datetime.now(timezone.utc)
        return pol

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a NAC policy."""
        if self._use_db:
            try:
                row = self.db.query(NACPolicyModel).filter(
                    NACPolicyModel.policy_id == policy_id
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
                    return True
                return False
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete failed for policy %s: %s", policy_id, exc)
        return self._policies.pop(policy_id, None) is not None

    # ============================================================
    # Device Posture Assessment
    # ============================================================

    def assess_device_posture(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate device posture against active policies.
        Returns posture assessment and access decision.
        """
        device_id = device_data.get("device_id", f"DEV-{uuid.uuid4().hex[:8].upper()}")
        mac = device_data.get("mac_address", "")

        # Check if device is blocked
        if self._is_blocked(mac):
            decision = self._record_decision(
                device_id=device_id, mac_address=mac, policy_id="",
                decision=AccessDecisionType.DENY.value,
                reason="Device MAC address is blocked", assigned_vlan=0,
            )
            return {"posture": None, "decision": _decision_to_dict(decision), "blocked": True}

        # Build posture
        now = datetime.now(timezone.utc)
        posture_id = f"POST-{uuid.uuid4().hex[:8].upper()}"
        violations = []
        score = 100

        av_status = device_data.get("antivirus_status", AntivirusStatus.UNKNOWN.value)
        fw_enabled = device_data.get("firewall_enabled", False)
        encrypted = device_data.get("disk_encrypted", False)
        patch_pct = device_data.get("patch_compliance_pct", 0.0)
        os_type = device_data.get("os_type", "")
        os_version = device_data.get("os_version", "")

        # Find best matching enabled policy
        policies = self.list_policies(enabled_only=True)
        matched_policy = None
        for pol in policies:
            reqs = pol.posture_requirements
            if not reqs:
                continue
            # Check approved OS
            approved = reqs.get("approved_os", [])
            if approved:
                os_match = any(
                    ao.lower() in f"{os_type} {os_version}".lower()
                    for ao in approved
                )
                if not os_match:
                    continue
            matched_policy = pol
            break

        if not matched_policy:
            # Default to Guest WiFi policy
            matched_policy = next(
                (p for p in policies if p.network_assignment == NetworkZone.GUEST.value),
                None,
            )

        # Evaluate against matched policy
        if matched_policy and matched_policy.posture_requirements:
            reqs = matched_policy.posture_requirements

            if reqs.get("antivirus_required") and av_status != AntivirusStatus.INSTALLED.value:
                violations.append(f"Antivirus {av_status} (required: installed)")
                score -= 25

            if reqs.get("firewall_required") and not fw_enabled:
                violations.append("Firewall not enabled (required)")
                score -= 20

            if reqs.get("encryption_required") and not encrypted:
                violations.append("Disk encryption not enabled (required)")
                score -= 20

            min_patch = reqs.get("patch_compliance_min_pct", 0.0)
            if min_patch > 0 and patch_pct < min_patch:
                violations.append(f"Patch compliance {patch_pct}% < {min_patch}% minimum")
                score -= 15

            if av_status == AntivirusStatus.OUTDATED.value:
                violations.append("Antivirus definitions outdated")
                score -= 10

        score = max(0, min(100, score))
        compliant = len(violations) == 0
        assigned_network = (
            matched_policy.network_assignment if matched_policy and compliant
            else NetworkZone.QUARANTINE.value
        )

        posture = DevicePosture(
            posture_id=posture_id, device_id=device_id,
            mac_address=mac, ip_address=device_data.get("ip_address", ""),
            hostname=device_data.get("hostname", ""),
            os_type=os_type, os_version=os_version,
            antivirus_status=av_status, firewall_enabled=fw_enabled,
            disk_encrypted=encrypted, patch_compliance_pct=patch_pct,
            last_assessed_at=now, posture_score=score,
            compliant=compliant, assigned_network=assigned_network,
            violations=violations,
        )

        # Persist posture
        self._save_posture(posture)

        # Determine access decision
        if compliant:
            dec_type = AccessDecisionType.ALLOW.value
            reason = "Device meets all posture requirements"
            vlan = matched_policy.vlan_id if matched_policy else 0
        elif score >= 50:
            dec_type = AccessDecisionType.QUARANTINE.value
            reason = f"Partial compliance ({score}/100) - quarantined for remediation"
            vlan = 999  # quarantine VLAN
        else:
            dec_type = AccessDecisionType.DENY.value
            reason = f"Device fails posture check ({score}/100): {'; '.join(violations)}"
            vlan = 0

        decision = self._record_decision(
            device_id=device_id, mac_address=mac,
            policy_id=matched_policy.policy_id if matched_policy else "",
            decision=dec_type, reason=reason, assigned_vlan=vlan,
        )

        return {
            "posture": _posture_to_dict(posture),
            "decision": _decision_to_dict(decision),
            "blocked": False,
        }

    def get_posture(self, device_id: str) -> Optional[DevicePosture]:
        """Get the latest posture for a device."""
        if self._use_db:
            try:
                row = self.db.query(DevicePostureModel).filter(
                    DevicePostureModel.device_id == device_id
                ).order_by(DevicePostureModel.last_assessed_at.desc()).first()
                return _posture_from_row(row) if row else None
            except Exception:
                pass
        return self._postures.get(device_id)

    def list_postures(self, compliant: Optional[bool] = None,
                      network: str = "") -> List[DevicePosture]:
        """List device posture records with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(DevicePostureModel)
                if compliant is not None:
                    q = q.filter(DevicePostureModel.compliant == compliant)
                if network:
                    q = q.filter(DevicePostureModel.assigned_network == network)
                return [_posture_from_row(r) for r in q.all()]
            except Exception:
                pass
        postures = list(self._postures.values())
        if compliant is not None:
            postures = [p for p in postures if p.compliant == compliant]
        if network:
            postures = [p for p in postures if p.assigned_network == network]
        return postures

    def reassess_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Re-assess an already-known device."""
        existing = self.get_posture(device_id)
        if not existing:
            return None
        device_data = {
            "device_id": device_id,
            "mac_address": existing.mac_address,
            "ip_address": existing.ip_address,
            "hostname": existing.hostname,
            "os_type": existing.os_type,
            "os_version": existing.os_version,
            "antivirus_status": existing.antivirus_status,
            "firewall_enabled": existing.firewall_enabled,
            "disk_encrypted": existing.disk_encrypted,
            "patch_compliance_pct": existing.patch_compliance_pct,
        }
        return self.assess_device_posture(device_data)

    def _save_posture(self, posture: DevicePosture) -> None:
        """Persist a posture record."""
        if self._use_db:
            try:
                row = DevicePostureModel(
                    posture_id=posture.posture_id, device_id=posture.device_id,
                    mac_address=posture.mac_address, ip_address=posture.ip_address,
                    hostname=posture.hostname, os_type=posture.os_type,
                    os_version=posture.os_version, antivirus_status=posture.antivirus_status,
                    firewall_enabled=posture.firewall_enabled, disk_encrypted=posture.disk_encrypted,
                    patch_compliance_pct=posture.patch_compliance_pct,
                    last_assessed_at=posture.last_assessed_at,
                    posture_score=posture.posture_score, compliant=posture.compliant,
                    assigned_network=posture.assigned_network, violations=posture.violations,
                )
                self.db.add(row)
                self.db.commit()
                return
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB save posture failed: %s", exc)
        self._postures[posture.device_id] = posture

    # ============================================================
    # Access Decisions
    # ============================================================

    def _record_decision(self, device_id: str, mac_address: str, policy_id: str,
                         decision: str, reason: str, assigned_vlan: int) -> AccessDecision:
        """Record an access decision."""
        did = f"DEC-{uuid.uuid4().hex[:8].upper()}"
        dec = AccessDecision(
            decision_id=did, device_id=device_id, mac_address=mac_address,
            policy_id=policy_id, decision=decision, reason=reason,
            assigned_vlan=assigned_vlan,
        )
        if self._use_db:
            try:
                row = AccessDecisionModel(
                    decision_id=dec.decision_id, device_id=dec.device_id,
                    mac_address=dec.mac_address, policy_id=dec.policy_id,
                    decision=dec.decision, reason=dec.reason,
                    assigned_vlan=dec.assigned_vlan,
                )
                self.db.add(row)
                self.db.commit()
                return dec
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB save decision failed: %s", exc)
        self._decisions.append(dec)
        return dec

    def get_access_log(self, device_id: str = "", decision: str = "",
                       limit: int = 100) -> List[Dict[str, Any]]:
        """Get access decision log with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(AccessDecisionModel)
                if device_id:
                    q = q.filter(AccessDecisionModel.device_id == device_id)
                if decision:
                    q = q.filter(AccessDecisionModel.decision == decision)
                rows = q.order_by(AccessDecisionModel.timestamp.desc()).limit(limit).all()
                return [_decision_to_dict(_decision_from_row(r)) for r in rows]
            except Exception:
                pass
        decs = self._decisions[:]
        if device_id:
            decs = [d for d in decs if d.device_id == device_id]
        if decision:
            decs = [d for d in decs if d.decision == decision]
        return [_decision_to_dict(d) for d in decs[-limit:]]

    # ============================================================
    # Quarantine Management
    # ============================================================

    def get_quarantined_devices(self) -> List[Dict[str, Any]]:
        """Get all devices currently in quarantine."""
        return [_posture_to_dict(p) for p in self.list_postures(network=NetworkZone.QUARANTINE.value)]

    def release_from_quarantine(self, device_id: str,
                                target_network: str = NetworkZone.CORPORATE.value) -> Optional[Dict[str, Any]]:
        """Release a device from quarantine to target network."""
        posture = self.get_posture(device_id)
        if not posture or posture.assigned_network != NetworkZone.QUARANTINE.value:
            return None
        posture.assigned_network = target_network
        posture.updated_at = datetime.now(timezone.utc)
        if self._use_db:
            try:
                row = self.db.query(DevicePostureModel).filter(
                    DevicePostureModel.device_id == device_id
                ).order_by(DevicePostureModel.last_assessed_at.desc()).first()
                if row:
                    row.assigned_network = target_network
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB release quarantine failed: %s", exc)
        decision = self._record_decision(
            device_id=device_id, mac_address=posture.mac_address,
            policy_id="", decision=AccessDecisionType.ALLOW.value,
            reason=f"Released from quarantine to {target_network}",
            assigned_vlan=0,
        )
        return {"posture": _posture_to_dict(posture), "decision": _decision_to_dict(decision)}

    # ============================================================
    # Device Blocking
    # ============================================================

    def block_device(self, mac_address: str, reason: str = "",
                     blocked_by: str = "system") -> BlockedDevice:
        """Block a device by MAC address."""
        blocked = BlockedDevice(
            mac_address=mac_address, reason=reason,
            blocked_by=blocked_by,
        )
        if self._use_db:
            try:
                row = BlockedDeviceModel(
                    mac_address=mac_address, reason=reason,
                    blocked_by=blocked_by,
                )
                self.db.add(row)
                self.db.commit()
                return blocked
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB block failed: %s", exc)
        self._blocked[mac_address] = blocked
        return blocked

    def unblock_device(self, mac_address: str) -> bool:
        """Unblock a device by MAC address."""
        if self._use_db:
            try:
                row = self.db.query(BlockedDeviceModel).filter(
                    BlockedDeviceModel.mac_address == mac_address
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
                    return True
                return False
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB unblock failed: %s", exc)
        return self._blocked.pop(mac_address, None) is not None

    def get_blocked_devices(self) -> List[Dict[str, Any]]:
        """Get all blocked devices."""
        if self._use_db:
            try:
                rows = self.db.query(BlockedDeviceModel).all()
                return [_blocked_to_dict(_blocked_from_row(r)) for r in rows]
            except Exception:
                pass
        return [_blocked_to_dict(b) for b in self._blocked.values()]

    def _is_blocked(self, mac_address: str) -> bool:
        """Check if a MAC address is blocked."""
        if not mac_address:
            return False
        if self._use_db:
            try:
                return self.db.query(BlockedDeviceModel).filter(
                    BlockedDeviceModel.mac_address == mac_address
                ).first() is not None
            except Exception:
                pass
        return mac_address in self._blocked

    # ============================================================
    # Guest / BYOD Registration
    # ============================================================

    def register_guest(self, name: str, email: str = "", company: str = "",
                       sponsor_email: str = "", mac_address: str = "",
                       client_id: str = "",
                       hours: int = 8, **kwargs) -> GuestRegistration:
        """Register a guest for network access."""
        gid = f"GUEST-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        guest = GuestRegistration(
            guest_id=gid, client_id=client_id, name=name,
            email=email, company=company, sponsor_email=sponsor_email,
            mac_address=mac_address,
            access_start=now,
            access_end=now + timedelta(hours=hours),
            status=GuestStatus.PENDING.value,
            network_assigned=NetworkZone.GUEST.value,
        )
        if self._use_db:
            try:
                row = GuestRegistrationModel(
                    guest_id=guest.guest_id, client_id=guest.client_id,
                    name=guest.name, email=guest.email, company=guest.company,
                    sponsor_email=guest.sponsor_email, mac_address=guest.mac_address,
                    access_start=guest.access_start, access_end=guest.access_end,
                    status=guest.status, network_assigned=guest.network_assigned,
                )
                self.db.add(row)
                self.db.commit()
                return guest
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB guest registration failed: %s", exc)
        self._guests[gid] = guest
        return guest

    def approve_guest(self, guest_id: str) -> Optional[GuestRegistration]:
        """Approve a guest registration."""
        return self._update_guest_status(guest_id, GuestStatus.APPROVED.value)

    def revoke_guest(self, guest_id: str) -> Optional[GuestRegistration]:
        """Revoke guest access."""
        return self._update_guest_status(guest_id, GuestStatus.REVOKED.value)

    def list_guests(self, client_id: str = "", status: str = "") -> List[GuestRegistration]:
        """List guest registrations."""
        if self._use_db:
            try:
                q = self.db.query(GuestRegistrationModel)
                if client_id:
                    q = q.filter(GuestRegistrationModel.client_id == client_id)
                if status:
                    q = q.filter(GuestRegistrationModel.status == status)
                return [_guest_from_row(r) for r in q.all()]
            except Exception:
                pass
        guests = list(self._guests.values())
        if client_id:
            guests = [g for g in guests if g.client_id == client_id]
        if status:
            guests = [g for g in guests if g.status == status]
        return guests

    def _update_guest_status(self, guest_id: str, new_status: str) -> Optional[GuestRegistration]:
        """Update guest registration status."""
        if self._use_db:
            try:
                row = self.db.query(GuestRegistrationModel).filter(
                    GuestRegistrationModel.guest_id == guest_id
                ).first()
                if not row:
                    return None
                row.status = new_status
                self.db.commit()
                return _guest_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB guest status update failed: %s", exc)
        guest = self._guests.get(guest_id)
        if not guest:
            return None
        guest.status = new_status
        guest.updated_at = datetime.now(timezone.utc)
        return guest

    # ============================================================
    # Captive Portal
    # ============================================================

    def configure_captive_portal(self, client_id: str, **kwargs) -> CaptivePortalConfig:
        """Configure captive portal for a client."""
        pid = f"PORTAL-{uuid.uuid4().hex[:8].upper()}"
        config = CaptivePortalConfig(
            portal_id=pid, client_id=client_id,
            branding=kwargs.get("branding", {
                "logo_url": "",
                "background_color": "#ffffff",
                "primary_color": "#0066cc",
                "company_name": "Aither MSP",
            }),
            terms_of_use=kwargs.get("terms_of_use", ""),
            require_registration=kwargs.get("require_registration", True),
            session_timeout_minutes=kwargs.get("session_timeout_minutes", 480),
            bandwidth_limit_mbps=kwargs.get("bandwidth_limit_mbps", 10.0),
        )
        if self._use_db:
            try:
                row = CaptivePortalConfigModel(
                    portal_id=config.portal_id, client_id=config.client_id,
                    branding=config.branding, terms_of_use=config.terms_of_use,
                    require_registration=config.require_registration,
                    session_timeout_minutes=config.session_timeout_minutes,
                    bandwidth_limit_mbps=config.bandwidth_limit_mbps,
                )
                self.db.add(row)
                self.db.commit()
                return config
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB portal config failed: %s", exc)
        self._portal_configs[client_id] = config
        return config

    def get_portal_config(self, client_id: str) -> Optional[CaptivePortalConfig]:
        """Get captive portal configuration for a client."""
        if self._use_db:
            try:
                row = self.db.query(CaptivePortalConfigModel).filter(
                    CaptivePortalConfigModel.client_id == client_id
                ).first()
                return _portal_from_row(row) if row else None
            except Exception:
                pass
        return self._portal_configs.get(client_id)

    # ============================================================
    # Compliance & Reporting
    # ============================================================

    def get_compliance_report(self, client_id: str = "") -> Dict[str, Any]:
        """Generate compliance report - % compliant by category."""
        postures = self.list_postures()
        total = len(postures)
        if total == 0:
            return {
                "total_devices": 0, "compliant_count": 0, "non_compliant_count": 0,
                "compliance_pct": 0.0, "by_category": {},
            }

        compliant_count = sum(1 for p in postures if p.compliant)
        av_ok = sum(1 for p in postures if p.antivirus_status == AntivirusStatus.INSTALLED.value)
        fw_ok = sum(1 for p in postures if p.firewall_enabled)
        enc_ok = sum(1 for p in postures if p.disk_encrypted)
        patch_ok = sum(1 for p in postures if p.patch_compliance_pct >= 80)

        return {
            "total_devices": total,
            "compliant_count": compliant_count,
            "non_compliant_count": total - compliant_count,
            "compliance_pct": round(compliant_count / total * 100, 1) if total else 0.0,
            "by_category": {
                "antivirus": {"compliant": av_ok, "total": total, "pct": round(av_ok / total * 100, 1)},
                "firewall": {"compliant": fw_ok, "total": total, "pct": round(fw_ok / total * 100, 1)},
                "encryption": {"compliant": enc_ok, "total": total, "pct": round(enc_ok / total * 100, 1)},
                "patch_compliance": {"compliant": patch_ok, "total": total, "pct": round(patch_ok / total * 100, 1)},
            },
        }

    def get_network_zone_distribution(self) -> Dict[str, int]:
        """Get count of devices in each network zone."""
        postures = self.list_postures()
        dist: Dict[str, int] = {}
        for p in postures:
            zone = p.assigned_network
            dist[zone] = dist.get(zone, 0) + 1
        return dist

    def get_dashboard(self) -> Dict[str, Any]:
        """Get NAC dashboard summary."""
        postures = self.list_postures()
        total = len(postures)
        compliant = sum(1 for p in postures if p.compliant)
        quarantined = sum(1 for p in postures if p.assigned_network == NetworkZone.QUARANTINE.value)
        blocked = len(self.get_blocked_devices())
        guests = self.list_guests()
        active_guests = sum(1 for g in guests if g.status in (GuestStatus.APPROVED.value, GuestStatus.ACTIVE.value))
        policies = self.list_policies()

        recent_decisions = self.get_access_log(limit=10)

        return {
            "total_devices": total,
            "compliant_devices": compliant,
            "non_compliant_devices": total - compliant,
            "compliance_pct": round(compliant / total * 100, 1) if total else 0.0,
            "quarantined_devices": quarantined,
            "blocked_devices": blocked,
            "active_guests": active_guests,
            "total_policies": len(policies),
            "enabled_policies": sum(1 for p in policies if p.is_enabled),
            "zone_distribution": self.get_network_zone_distribution(),
            "recent_decisions": recent_decisions,
        }
