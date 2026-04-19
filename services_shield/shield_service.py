"""
Aither Shield - Consumer Security Service

Core service for the consumer antivirus/firewall product.
Leverages Cyber-911 backend for threat intelligence.

FORGE G-21 2026-04-11: Migrated from 9 in-memory Dict stores to SQLAlchemy
persistence.  _plans and _signatures remain in-memory (static reference data).
All DB operations wrapped in try/except for graceful degradation to in-memory
fallback when the database is unavailable.
"""

from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from dataclasses import dataclass, field
import hashlib
import uuid
import random
import logging

logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanType(Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    SCHEDULED = "scheduled"
    REALTIME = "realtime"


class ProtectionStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    OUTDATED = "outdated"
    EXPIRED = "expired"


class DeviceType(Enum):
    IPHONE = "iphone"
    ANDROID = "android"
    WINDOWS = "windows"
    MAC = "mac"


class SubscriptionStatus(Enum):
    TRIAL = "trial"
    ACTIVE = "active"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ThreatType(Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    PUP = "pup"
    ADWARE = "adware"
    NETWORK_ATTACK = "network_attack"
    TROJAN = "trojan"
    SPYWARE = "spyware"


class DetectionEngine(Enum):
    SIGNATURE = "signature"
    HEURISTIC = "heuristic"
    AI = "ai"
    CLOUD = "cloud"
    BEHAVIORAL = "behavioral"


class FirewallRuleType(Enum):
    ALLOW = "allow"
    BLOCK = "block"


class FirewallDirection(Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


class VPNStatus(Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"


class DarkWebAlertType(Enum):
    EMAIL_BREACH = "email_breach"
    PASSWORD_LEAK = "password_leak"
    SSN_FOUND = "ssn_found"
    CREDIT_CARD = "credit_card"
    PHONE_NUMBER = "phone_number"


class DarkWebAlertStatus(Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class ShieldPlan:
    """Subscription plan definition."""
    id: str
    name: str
    slug: str
    platform: str
    price_monthly: Optional[float]
    price_yearly: Optional[float]
    max_devices: int
    features: Dict[str, Any]
    is_active: bool = True


@dataclass
class ShieldUser:
    """Shield user/subscriber."""
    id: str
    email: str
    name: Optional[str]
    plan_id: Optional[str]
    subscription_status: SubscriptionStatus
    subscription_expires_at: Optional[datetime]
    devices_registered: int = 0
    threats_blocked_total: int = 0
    is_family_admin: bool = False
    family_group_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ShieldDevice:
    """Registered protected device."""
    id: str
    user_id: str
    device_name: str
    device_type: DeviceType
    os_version: Optional[str]
    app_version: str
    device_fingerprint: str
    protection_status: ProtectionStatus
    last_seen_at: Optional[datetime] = None
    last_scan_at: Optional[datetime] = None
    threats_blocked: int = 0
    scans_completed: int = 0
    push_token: Optional[str] = None


@dataclass
class ShieldThreat:
    """Detected threat record."""
    id: str
    user_id: str
    device_id: str
    threat_type: ThreatType
    threat_name: str
    threat_severity: ThreatSeverity
    threat_hash: Optional[str]
    source_type: str
    source_path: Optional[str]
    source_url: Optional[str]
    action_taken: str
    detection_engine: DetectionEngine
    confidence_score: float
    detected_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShieldScan:
    """Scan record."""
    id: str
    user_id: str
    device_id: str
    scan_type: ScanType
    status: str
    files_scanned: int = 0
    threats_found: int = 0
    threats_resolved: int = 0
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    results: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FirewallRule:
    """Firewall rule definition."""
    id: str
    device_id: str
    name: str
    description: Optional[str]
    rule_type: FirewallRuleType
    direction: FirewallDirection
    protocol: str
    local_port: Optional[str]
    remote_port: Optional[str]
    remote_ip: Optional[str]
    application_path: Optional[str]
    is_enabled: bool = True
    is_system_rule: bool = False
    times_triggered: int = 0
    last_triggered_at: Optional[datetime] = None


@dataclass
class VPNSession:
    """VPN connection session."""
    id: str
    user_id: str
    device_id: str
    server_location: str
    server_ip: str
    assigned_ip: str
    protocol: str
    status: VPNStatus
    connected_at: Optional[datetime] = None
    disconnected_at: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class DarkWebAlert:
    """Dark web exposure alert."""
    id: str
    user_id: str
    alert_type: DarkWebAlertType
    exposed_data_type: str
    source_breach: str
    status: DarkWebAlertStatus
    recommended_actions: List[str]
    discovered_at: datetime = field(default_factory=datetime.now)
    acknowledged_at: Optional[datetime] = None


@dataclass
class ThreatSignature:
    """Threat signature for detection."""
    id: str
    signature_hash: str
    signature_type: str
    threat_type: ThreatType
    threat_name: str
    severity: ThreatSeverity
    detections_count: int = 0
    source: str = "internal"
    is_active: bool = True


class ShieldService:
    """
    Main service for Aither Shield consumer security.

    Handles:
    - Device registration and management
    - Threat scanning and detection
    - Firewall rule management
    - VPN connection management
    - Subscription verification
    - Dark web monitoring
    """

    def __init__(self, db=None):
        """
        Args:
            db: Optional SQLAlchemy Session.  When provided, all CRUD goes to
                the database.  When None, falls back to in-memory dicts (the
                original behaviour) so nothing breaks if the DB is unavailable.
        """
        self.db = db

        # In-memory storage — used as fallback when db is None
        self._plans: Dict[str, ShieldPlan] = {}
        self._users: Dict[str, ShieldUser] = {}
        self._devices: Dict[str, ShieldDevice] = {}
        self._threats: Dict[str, ShieldThreat] = {}
        self._scans: Dict[str, ShieldScan] = {}
        self._firewall_rules: Dict[str, FirewallRule] = {}
        self._vpn_sessions: Dict[str, VPNSession] = {}
        self._dark_web_alerts: Dict[str, DarkWebAlert] = {}
        self._signatures: Dict[str, ThreatSignature] = {}

        # Lazy-import models (avoid circular imports at module level)
        self._models_loaded = False
        self._m = None  # will hold the models module

        # Initialize default plans
        self._initialize_plans()

        # Signature version tracking
        self._signature_version = "2024.02.08.001"
        self._latest_app_versions = {
            "iphone": "2.1.0",
            "android": "2.1.0",
            "windows": "3.0.5",
            "mac": "3.0.5"
        }

        # VPN server list
        self._vpn_servers = [
            {"id": "us-east", "location": "New York, US", "ip": "198.51.100.1", "load": 45, "latency_ms": 20},
            {"id": "us-west", "location": "Los Angeles, US", "ip": "198.51.100.2", "load": 38, "latency_ms": 65},
            {"id": "eu-west", "location": "London, UK", "ip": "198.51.100.3", "load": 52, "latency_ms": 85},
            {"id": "eu-central", "location": "Frankfurt, DE", "ip": "198.51.100.4", "load": 41, "latency_ms": 95},
            {"id": "asia-east", "location": "Tokyo, JP", "ip": "198.51.100.5", "load": 33, "latency_ms": 150},
            {"id": "asia-south", "location": "Singapore", "ip": "198.51.100.6", "load": 28, "latency_ms": 180},
            {"id": "oceania", "location": "Sydney, AU", "ip": "198.51.100.7", "load": 22, "latency_ms": 200},
        ]

    def _initialize_plans(self):
        """Initialize subscription plans."""
        plans = [
            # Mobile
            ShieldPlan(
                id=str(uuid.uuid4()), name="Free", slug="mobile-free", platform="mobile",
                price_monthly=0, price_yearly=0, max_devices=1,
                features={"basic_scan": True, "phishing_checker": True}
            ),
            ShieldPlan(
                id=str(uuid.uuid4()), name="Personal", slug="mobile-personal", platform="mobile",
                price_monthly=4.99, price_yearly=49.99, max_devices=3,
                features={"realtime_protection": True, "vpn_daily_mb": 500, "phishing_checker": True}
            ),
            ShieldPlan(
                id=str(uuid.uuid4()), name="Family", slug="mobile-family", platform="mobile",
                price_monthly=9.99, price_yearly=99.99, max_devices=6,
                features={"realtime_protection": True, "vpn_unlimited": True, "parental_controls": True, "family_dashboard": True}
            ),
            # Desktop
            ShieldPlan(
                id=str(uuid.uuid4()), name="Basic", slug="desktop-basic", platform="desktop",
                price_monthly=None, price_yearly=29.99, max_devices=1,
                features={"antivirus": True, "basic_firewall": True}
            ),
            ShieldPlan(
                id=str(uuid.uuid4()), name="Pro", slug="desktop-pro", platform="desktop",
                price_monthly=None, price_yearly=49.99, max_devices=3,
                features={"antivirus": True, "advanced_firewall": True, "vpn": True}
            ),
            ShieldPlan(
                id=str(uuid.uuid4()), name="Ultimate", slug="desktop-ultimate", platform="desktop",
                price_monthly=None, price_yearly=79.99, max_devices=5,
                features={"antivirus": True, "advanced_firewall": True, "vpn": True, "password_manager": True, "dark_web_monitoring": True}
            ),
            # Bundle
            ShieldPlan(
                id=str(uuid.uuid4()), name="Shield 360", slug="shield-360", platform="bundle",
                price_monthly=None, price_yearly=99.99, max_devices=10,
                features={"all_features": True, "priority_support": True, "cross_platform": True}
            )
        ]
        for plan in plans:
            self._plans[plan.id] = plan

    # ==================== DB HELPERS ====================

    def _load_models(self):
        """Lazy-load SQLAlchemy models to avoid circular imports."""
        if not self._models_loaded:
            try:
                from models.shield import (
                    ShieldUserModel, ShieldDeviceModel, ShieldThreatModel,
                    ShieldScanModel, ShieldFirewallRuleModel,
                    ShieldVPNSessionModel, ShieldDarkWebAlertModel,
                )
                class _M:
                    User = ShieldUserModel
                    Device = ShieldDeviceModel
                    Threat = ShieldThreatModel
                    Scan = ShieldScanModel
                    FirewallRule = ShieldFirewallRuleModel
                    VPNSession = ShieldVPNSessionModel
                    DarkWebAlert = ShieldDarkWebAlertModel
                self._m = _M
                self._models_loaded = True
            except Exception as e:
                logger.warning(f"Shield models not available, using in-memory fallback: {e}")
                self.db = None  # force fallback
        return self._m

    @property
    def _use_db(self) -> bool:
        """True when a live DB session is available and models are loaded."""
        if self.db is None:
            return False
        self._load_models()
        return self._m is not None and self.db is not None

    def _safe_commit(self):
        """Commit with fallback — if commit fails, rollback and log."""
        try:
            self.db.commit()
        except Exception as e:
            logger.error(f"Shield DB commit failed: {e}")
            self.db.rollback()
            raise

    # ==================== SUBSCRIPTION PLANS ====================

    def get_plans(self, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get available subscription plans."""
        plans = list(self._plans.values())
        if platform:
            plans = [p for p in plans if p.platform == platform or p.platform == "bundle"]

        return [{
            "id": p.id,
            "name": p.name,
            "slug": p.slug,
            "platform": p.platform,
            "price_monthly": p.price_monthly,
            "price_yearly": p.price_yearly,
            "max_devices": p.max_devices,
            "features": p.features,
            "is_active": p.is_active
        } for p in plans]

    def get_plan_by_slug(self, slug: str) -> Optional[Dict[str, Any]]:
        """Get plan by slug."""
        for plan in self._plans.values():
            if plan.slug == slug:
                return {
                    "id": plan.id,
                    "name": plan.name,
                    "slug": plan.slug,
                    "platform": plan.platform,
                    "price_monthly": plan.price_monthly,
                    "price_yearly": plan.price_yearly,
                    "max_devices": plan.max_devices,
                    "features": plan.features
                }
        return None

    # ==================== USER MANAGEMENT ====================

    def create_user(self, email: str, password_hash: str, name: Optional[str] = None,
                    plan_slug: str = "mobile-free") -> Dict[str, Any]:
        """Create a new shield user."""
        # Check if email exists
        if self._use_db:
            try:
                existing = self.db.query(self._m.User).filter(self._m.User.email == email).first()
                if existing:
                    return {"success": False, "error": "Email already registered"}
            except Exception as e:
                logger.error(f"DB email check failed: {e}")
        else:
            for user in self._users.values():
                if user.email == email:
                    return {"success": False, "error": "Email already registered"}

        plan = self.get_plan_by_slug(plan_slug)
        user_id = str(uuid.uuid4())
        expires = datetime.now() + timedelta(days=14)

        user = ShieldUser(
            id=user_id,
            email=email,
            name=name,
            plan_id=plan["id"] if plan else None,
            subscription_status=SubscriptionStatus.TRIAL,
            subscription_expires_at=expires,
        )
        self._users[user.id] = user

        if self._use_db:
            try:
                record = self._m.User(
                    id=user_id, email=email, name=name,
                    plan_id=plan["id"] if plan else None,
                    subscription_status="trial",
                    subscription_expires_at=expires,
                )
                self.db.add(record)
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB create_user failed: {e}")

        return {
            "success": True,
            "user_id": user.id,
            "email": user.email,
            "plan": plan["name"] if plan else "Free",
            "trial_expires": user.subscription_expires_at.isoformat()
        }

    def _get_user_obj(self, user_id: str) -> Optional[ShieldUser]:
        """Retrieve a ShieldUser dataclass — DB first, then in-memory."""
        if self._use_db:
            try:
                row = self.db.query(self._m.User).filter(self._m.User.id == user_id).first()
                if row:
                    # Hydrate into the dataclass so downstream code stays the same
                    user = ShieldUser(
                        id=row.id, email=row.email, name=row.name,
                        plan_id=row.plan_id,
                        subscription_status=SubscriptionStatus(row.subscription_status),
                        subscription_expires_at=row.subscription_expires_at,
                        devices_registered=row.devices_registered or 0,
                        threats_blocked_total=row.threats_blocked_total or 0,
                        is_family_admin=row.is_family_admin or False,
                        family_group_id=row.family_group_id,
                        created_at=row.created_at or datetime.now(),
                    )
                    self._users[user_id] = user  # cache
                    return user
            except Exception as e:
                logger.error(f"DB get_user_obj failed: {e}")
        return self._users.get(user_id)

    def _persist_user(self, user: ShieldUser):
        """Write a ShieldUser dataclass back to DB."""
        if not self._use_db:
            return
        try:
            row = self.db.query(self._m.User).filter(self._m.User.id == user.id).first()
            if row:
                row.email = user.email
                row.name = user.name
                row.plan_id = user.plan_id
                row.subscription_status = user.subscription_status.value
                row.subscription_expires_at = user.subscription_expires_at
                row.devices_registered = user.devices_registered
                row.threats_blocked_total = user.threats_blocked_total
                row.is_family_admin = user.is_family_admin
                row.family_group_id = user.family_group_id
            else:
                row = self._m.User(
                    id=user.id, email=user.email, name=user.name,
                    plan_id=user.plan_id,
                    subscription_status=user.subscription_status.value,
                    subscription_expires_at=user.subscription_expires_at,
                    devices_registered=user.devices_registered,
                    threats_blocked_total=user.threats_blocked_total,
                    is_family_admin=user.is_family_admin,
                    family_group_id=user.family_group_id,
                    created_at=user.created_at,
                )
                self.db.add(row)
            self._safe_commit()
        except Exception as e:
            logger.error(f"DB persist_user failed: {e}")

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user details."""
        user = self._get_user_obj(user_id)
        if not user:
            return None

        plan = None
        if user.plan_id:
            plan = self._plans.get(user.plan_id)

        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "plan": plan.name if plan else "Free",
            "plan_features": plan.features if plan else {"basic_scan": True},
            "subscription_status": user.subscription_status.value,
            "subscription_expires_at": user.subscription_expires_at.isoformat() if user.subscription_expires_at else None,
            "devices_registered": user.devices_registered,
            "max_devices": plan.max_devices if plan else 1,
            "threats_blocked_total": user.threats_blocked_total,
            "is_family_admin": user.is_family_admin,
            "created_at": user.created_at.isoformat()
        }

    def verify_subscription(self, user_id: str) -> Dict[str, Any]:
        """Verify user's subscription is active and valid."""
        user = self._get_user_obj(user_id)
        if not user:
            return {"valid": False, "error": "User not found"}

        # Check expiration
        if user.subscription_expires_at and user.subscription_expires_at < datetime.now():
            user.subscription_status = SubscriptionStatus.EXPIRED
            self._persist_user(user)

        plan = self._plans.get(user.plan_id) if user.plan_id else None

        return {
            "valid": user.subscription_status in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL],
            "user_id": user_id,
            "subscription_status": user.subscription_status.value,
            "plan": plan.name if plan else "Free",
            "expires_at": user.subscription_expires_at.isoformat() if user.subscription_expires_at else None,
            "devices_allowed": plan.max_devices if plan else 1,
            "devices_registered": user.devices_registered,
            "features": plan.features if plan else {"basic_scan": True}
        }

    def upgrade_subscription(self, user_id: str, plan_slug: str, billing_cycle: str = "yearly") -> Dict[str, Any]:
        """Upgrade user subscription."""
        user = self._get_user_obj(user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        plan = self.get_plan_by_slug(plan_slug)
        if not plan:
            return {"success": False, "error": "Invalid plan"}

        user.plan_id = plan["id"]
        user.subscription_status = SubscriptionStatus.ACTIVE
        user.subscription_expires_at = datetime.now() + timedelta(days=365 if billing_cycle == "yearly" else 30)
        self._persist_user(user)

        return {
            "success": True,
            "plan": plan["name"],
            "expires_at": user.subscription_expires_at.isoformat(),
            "features": plan["features"]
        }

    # ==================== DEVICE MANAGEMENT ====================

    def _get_device_obj(self, device_id: str) -> Optional[ShieldDevice]:
        """Retrieve a ShieldDevice dataclass — DB first, then in-memory."""
        if self._use_db:
            try:
                row = self.db.query(self._m.Device).filter(self._m.Device.id == device_id).first()
                if row:
                    dev = ShieldDevice(
                        id=row.id, user_id=row.user_id,
                        device_name=row.device_name,
                        device_type=DeviceType(row.device_type),
                        os_version=row.os_version,
                        app_version=row.app_version,
                        device_fingerprint=row.device_fingerprint,
                        protection_status=ProtectionStatus(row.protection_status),
                        last_seen_at=row.last_seen_at,
                        last_scan_at=row.last_scan_at,
                        threats_blocked=row.threats_blocked or 0,
                        scans_completed=row.scans_completed or 0,
                        push_token=row.push_token,
                    )
                    self._devices[device_id] = dev
                    return dev
            except Exception as e:
                logger.error(f"DB get_device_obj failed: {e}")
        return self._devices.get(device_id)

    def _persist_device(self, device: ShieldDevice):
        """Write a ShieldDevice back to DB."""
        if not self._use_db:
            return
        try:
            row = self.db.query(self._m.Device).filter(self._m.Device.id == device.id).first()
            if row:
                row.user_id = device.user_id
                row.device_name = device.device_name
                row.device_type = device.device_type.value
                row.os_version = device.os_version
                row.app_version = device.app_version
                row.device_fingerprint = device.device_fingerprint
                row.protection_status = device.protection_status.value
                row.last_seen_at = device.last_seen_at
                row.last_scan_at = device.last_scan_at
                row.threats_blocked = device.threats_blocked
                row.scans_completed = device.scans_completed
                row.push_token = device.push_token
            else:
                row = self._m.Device(
                    id=device.id, user_id=device.user_id,
                    device_name=device.device_name,
                    device_type=device.device_type.value,
                    os_version=device.os_version,
                    app_version=device.app_version,
                    device_fingerprint=device.device_fingerprint,
                    protection_status=device.protection_status.value,
                    last_seen_at=device.last_seen_at,
                    last_scan_at=device.last_scan_at,
                    threats_blocked=device.threats_blocked,
                    scans_completed=device.scans_completed,
                    push_token=device.push_token,
                )
                self.db.add(row)
            self._safe_commit()
        except Exception as e:
            logger.error(f"DB persist_device failed: {e}")

    def register_device(self, user_id: str, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new device for protection."""
        user = self._get_user_obj(user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        plan = self._plans.get(user.plan_id) if user.plan_id else None
        max_devices = plan.max_devices if plan else 1

        # Check device limit
        if user.devices_registered >= max_devices:
            return {
                "success": False,
                "error": f"Device limit reached ({max_devices}). Upgrade your plan for more devices."
            }

        # Generate device fingerprint
        fingerprint = self._generate_device_fingerprint(device_info)

        # Check if device already registered — DB then in-memory
        if self._use_db:
            try:
                existing = self.db.query(self._m.Device).filter(
                    self._m.Device.device_fingerprint == fingerprint
                ).first()
                if existing:
                    return {"success": True, "device_id": existing.id, "message": "Device already registered"}
            except Exception as e:
                logger.error(f"DB fingerprint check failed: {e}")
        else:
            for device in self._devices.values():
                if device.device_fingerprint == fingerprint:
                    return {"success": True, "device_id": device.id, "message": "Device already registered"}

        device = ShieldDevice(
            id=str(uuid.uuid4()),
            user_id=user_id,
            device_name=device_info.get("name", f"{device_info['type']} Device"),
            device_type=DeviceType(device_info["type"]),
            os_version=device_info.get("os_version"),
            app_version=device_info.get("app_version", "1.0.0"),
            device_fingerprint=fingerprint,
            protection_status=ProtectionStatus.ACTIVE,
            push_token=device_info.get("push_token"),
            last_seen_at=datetime.now()
        )
        self._devices[device.id] = device
        self._persist_device(device)

        user.devices_registered += 1
        self._persist_user(user)

        # Initialize default firewall rules for desktop
        if device.device_type in [DeviceType.WINDOWS, DeviceType.MAC]:
            self._initialize_firewall_rules(device.id)

        return {
            "success": True,
            "device_id": device.id,
            "device_name": device.device_name,
            "protection_status": device.protection_status.value,
            "features": plan.features if plan else {"basic_scan": True}
        }

    def get_device_status(self, device_id: str) -> Dict[str, Any]:
        """Get current protection status for a device."""
        device = self._get_device_obj(device_id)
        if not device:
            return {"error": "Device not found"}

        user = self._get_user_obj(device.user_id)
        plan = self._plans.get(user.plan_id) if user and user.plan_id else None

        # Check subscription status
        if user and user.subscription_status == SubscriptionStatus.EXPIRED:
            protection_status = ProtectionStatus.EXPIRED
        elif device.app_version != self._latest_app_versions.get(device.device_type.value):
            protection_status = ProtectionStatus.OUTDATED
        else:
            protection_status = device.protection_status

        # Get recent threats — DB or in-memory
        recent_count = 0
        cutoff = datetime.now() - timedelta(days=7)
        if self._use_db:
            try:
                recent_count = self.db.query(self._m.Threat).filter(
                    self._m.Threat.device_id == device_id,
                    self._m.Threat.detected_at > cutoff
                ).count()
            except Exception as e:
                logger.error(f"DB recent threats count failed: {e}")
                recent_count = len([t for t in self._threats.values()
                                    if t.device_id == device_id and t.detected_at > cutoff])
        else:
            recent_count = len([t for t in self._threats.values()
                                if t.device_id == device_id and t.detected_at > cutoff])

        return {
            "device_id": device_id,
            "device_name": device.device_name,
            "device_type": device.device_type.value,
            "protection_status": protection_status.value,
            "last_scan": device.last_scan_at.isoformat() if device.last_scan_at else None,
            "last_seen": device.last_seen_at.isoformat() if device.last_seen_at else None,
            "threats_blocked_7d": recent_count,
            "threats_blocked_total": device.threats_blocked,
            "scans_completed": device.scans_completed,
            "app_version": device.app_version,
            "latest_version": self._latest_app_versions.get(device.device_type.value),
            "needs_update": protection_status == ProtectionStatus.OUTDATED,
            "subscription_valid": user.subscription_status in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL] if user else False
        }

    def get_user_devices(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all devices for a user."""
        if self._use_db:
            try:
                rows = self.db.query(self._m.Device).filter(self._m.Device.user_id == user_id).all()
                return [self.get_device_status(r.id) for r in rows]
            except Exception as e:
                logger.error(f"DB get_user_devices failed: {e}")
        devices = [d for d in self._devices.values() if d.user_id == user_id]
        return [self.get_device_status(d.id) for d in devices]

    def device_heartbeat(self, device_id: str) -> Dict[str, Any]:
        """Update device last seen timestamp."""
        device = self._get_device_obj(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}

        device.last_seen_at = datetime.now()
        self._persist_device(device)
        return {"success": True, "timestamp": device.last_seen_at.isoformat()}

    def remove_device(self, device_id: str) -> Dict[str, Any]:
        """Remove a device from protection."""
        device = self._get_device_obj(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}

        user = self._get_user_obj(device.user_id)
        if user:
            user.devices_registered = max(0, user.devices_registered - 1)
            self._persist_user(user)

        # Remove from in-memory
        self._devices.pop(device_id, None)

        # Remove from DB
        if self._use_db:
            try:
                self.db.query(self._m.Device).filter(self._m.Device.id == device_id).delete()
                # Remove associated firewall rules from DB
                self.db.query(self._m.FirewallRule).filter(self._m.FirewallRule.device_id == device_id).delete()
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB remove_device failed: {e}")

        # Remove associated firewall rules from in-memory
        rules_to_remove = [r.id for r in self._firewall_rules.values() if r.device_id == device_id]
        for rule_id in rules_to_remove:
            del self._firewall_rules[rule_id]

        return {"success": True, "message": "Device removed"}

    # ==================== SCANNING ====================

    def start_scan(self, device_id: str, scan_type: str, custom_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """Initiate a security scan on a device."""
        device = self._get_device_obj(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}

        scan = ShieldScan(
            id=str(uuid.uuid4()),
            user_id=device.user_id,
            device_id=device_id,
            scan_type=ScanType(scan_type),
            status="running"
        )
        self._scans[scan.id] = scan

        # Persist scan to DB
        if self._use_db:
            try:
                row = self._m.Scan(
                    id=scan.id, user_id=scan.user_id, device_id=scan.device_id,
                    scan_type=scan_type, status="running",
                    started_at=scan.started_at,
                )
                self.db.add(row)
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB start_scan persist failed: {e}")

        scan_config = {
            "scan_id": scan.id,
            "scan_type": scan_type,
            "paths": custom_paths or self._get_default_scan_paths(scan_type, device.device_type.value),
            "signature_version": self._signature_version,
            "heuristic_enabled": True,
            "cloud_lookup_enabled": True,
            "quarantine_threats": True
        }

        return {
            "success": True,
            "scan_id": scan.id,
            "config": scan_config
        }

    def _get_scan_obj(self, scan_id: str) -> Optional[ShieldScan]:
        """Retrieve a ShieldScan — DB first, then in-memory."""
        if self._use_db:
            try:
                row = self.db.query(self._m.Scan).filter(self._m.Scan.id == scan_id).first()
                if row:
                    scan = ShieldScan(
                        id=row.id, user_id=row.user_id, device_id=row.device_id,
                        scan_type=ScanType(row.scan_type), status=row.status,
                        files_scanned=row.files_scanned or 0,
                        threats_found=row.threats_found or 0,
                        threats_resolved=row.threats_resolved or 0,
                        started_at=row.started_at or datetime.now(),
                        completed_at=row.completed_at,
                        duration_seconds=row.duration_seconds,
                        results=row.results_json or {},
                    )
                    self._scans[scan_id] = scan
                    return scan
            except Exception as e:
                logger.error(f"DB get_scan_obj failed: {e}")
        return self._scans.get(scan_id)

    def _persist_scan(self, scan: ShieldScan):
        """Write a ShieldScan back to DB."""
        if not self._use_db:
            return
        try:
            row = self.db.query(self._m.Scan).filter(self._m.Scan.id == scan.id).first()
            if row:
                row.status = scan.status
                row.files_scanned = scan.files_scanned
                row.threats_found = scan.threats_found
                row.threats_resolved = scan.threats_resolved
                row.completed_at = scan.completed_at
                row.duration_seconds = scan.duration_seconds
                row.results_json = scan.results
                self._safe_commit()
        except Exception as e:
            logger.error(f"DB persist_scan failed: {e}")

    def report_scan_progress(self, scan_id: str, progress: Dict[str, Any]) -> Dict[str, Any]:
        """Receive progress updates from device during scan."""
        scan = self._get_scan_obj(scan_id)
        if not scan:
            return {"success": False, "error": "Scan not found"}

        scan.files_scanned = progress.get("files_scanned", scan.files_scanned)

        # If threats found, record them
        if "threats" in progress:
            for threat_data in progress["threats"]:
                self._record_threat(scan.user_id, scan.device_id, threat_data, scan_id)
                scan.threats_found += 1

        self._persist_scan(scan)
        return {"success": True, "acknowledged": True}

    def complete_scan(self, scan_id: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Mark scan as completed with final results."""
        scan = self._get_scan_obj(scan_id)
        if not scan:
            return {"success": False, "error": "Scan not found"}

        device = self._get_device_obj(scan.device_id)

        scan.status = "completed"
        scan.completed_at = datetime.now()
        scan.duration_seconds = results.get("duration_seconds")
        scan.files_scanned = results.get("files_scanned", scan.files_scanned)
        scan.threats_found = results.get("threats_found", scan.threats_found)
        scan.threats_resolved = results.get("threats_resolved", 0)
        scan.results = results
        self._persist_scan(scan)

        if device:
            device.last_scan_at = datetime.now()
            device.scans_completed += 1
            self._persist_device(device)

        return {
            "success": True,
            "scan_summary": {
                "scan_id": scan_id,
                "files_scanned": scan.files_scanned,
                "threats_found": scan.threats_found,
                "threats_resolved": scan.threats_resolved,
                "duration_seconds": scan.duration_seconds,
                "protection_status": "secure" if scan.threats_found == 0 else "threats_found"
            }
        }

    def get_scan_history(self, device_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get scan history for a device."""
        if self._use_db:
            try:
                rows = (self.db.query(self._m.Scan)
                        .filter(self._m.Scan.device_id == device_id)
                        .order_by(self._m.Scan.started_at.desc())
                        .limit(limit)
                        .all())
                return [{
                    "scan_id": r.id,
                    "scan_type": r.scan_type,
                    "status": r.status,
                    "files_scanned": r.files_scanned or 0,
                    "threats_found": r.threats_found or 0,
                    "threats_resolved": r.threats_resolved or 0,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    "duration_seconds": r.duration_seconds,
                } for r in rows]
            except Exception as e:
                logger.error(f"DB get_scan_history failed: {e}")

        scans = [s for s in self._scans.values() if s.device_id == device_id]
        scans.sort(key=lambda x: x.started_at, reverse=True)

        return [{
            "scan_id": s.id,
            "scan_type": s.scan_type.value,
            "status": s.status,
            "files_scanned": s.files_scanned,
            "threats_found": s.threats_found,
            "threats_resolved": s.threats_resolved,
            "started_at": s.started_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "duration_seconds": s.duration_seconds
        } for s in scans[:limit]]

    # ==================== THREAT DETECTION ====================

    def check_file(self, device_id: str, file_hash: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """Real-time file check against threat database."""
        # Check local signature database
        signature = self._check_signature(file_hash)

        if signature:
            device = self._get_device_obj(device_id)
            threat = self._record_threat(
                user_id=device.user_id if device else "",
                device_id=device_id,
                threat_data={
                    "threat_type": signature.threat_type.value,
                    "threat_name": signature.threat_name,
                    "severity": signature.severity.value,
                    "hash": file_hash,
                    "source_path": file_path,
                    "detection_engine": "signature"
                }
            )

            return {
                "is_threat": True,
                "threat_id": threat["threat_id"],
                "threat_type": signature.threat_type.value,
                "threat_name": signature.threat_name,
                "severity": signature.severity.value,
                "action": "quarantine",
                "confidence": 1.0
            }

        # Simulate cloud check (would integrate with Cyber-911)
        # For demo, randomly detect some threats
        if random.random() < 0.001:  # 0.1% chance
            return {
                "is_threat": True,
                "threat_type": "unknown_malware",
                "threat_name": "Suspicious.Gen.A",
                "severity": "medium",
                "action": "quarantine",
                "confidence": 0.75
            }

        return {"is_threat": False, "safe": True}

    def check_url(self, device_id: str, url: str) -> Dict[str, Any]:
        """Check if URL is safe (phishing, malware, etc.)."""
        # Hash the URL for lookup
        url_hash = hashlib.sha256(url.encode()).hexdigest()

        # Check against known bad patterns
        dangerous_patterns = ["phish", "malware", "hack", "steal", "login-verify"]
        is_dangerous = any(pattern in url.lower() for pattern in dangerous_patterns)

        if is_dangerous:
            device = self._get_device_obj(device_id)
            self._record_threat(
                user_id=device.user_id if device else "",
                device_id=device_id,
                threat_data={
                    "threat_type": "phishing",
                    "threat_name": "Phishing URL Detected",
                    "severity": "high",
                    "source_type": "url",
                    "source_url": url,
                    "detection_engine": "cloud"
                }
            )

            return {
                "is_safe": False,
                "threat_type": "phishing",
                "risk_level": "high",
                "action": "block",
                "reason": "This URL has been identified as a phishing attempt."
            }

        return {"is_safe": True, "risk_level": "none"}

    def report_threat(self, device_id: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Report a detected threat from device."""
        device = self._get_device_obj(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}

        threat = self._record_threat(device.user_id, device_id, threat_data)
        return {"success": True, "threat_id": threat["threat_id"]}

    def get_threat_history(self, device_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get threat history for a device."""
        if self._use_db:
            try:
                rows = (self.db.query(self._m.Threat)
                        .filter(self._m.Threat.device_id == device_id)
                        .order_by(self._m.Threat.detected_at.desc())
                        .limit(limit)
                        .all())
                return [{
                    "threat_id": r.id,
                    "threat_type": r.threat_type,
                    "threat_name": r.threat_name,
                    "severity": r.threat_severity,
                    "source_type": r.source_type,
                    "source_path": r.source_path,
                    "source_url": r.source_url,
                    "action_taken": r.action_taken,
                    "detection_engine": r.detection_engine,
                    "confidence": r.confidence_score,
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                    "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
                } for r in rows]
            except Exception as e:
                logger.error(f"DB get_threat_history failed: {e}")

        threats = [t for t in self._threats.values() if t.device_id == device_id]
        threats.sort(key=lambda x: x.detected_at, reverse=True)

        return [{
            "threat_id": t.id,
            "threat_type": t.threat_type.value,
            "threat_name": t.threat_name,
            "severity": t.threat_severity.value,
            "source_type": t.source_type,
            "source_path": t.source_path,
            "source_url": t.source_url,
            "action_taken": t.action_taken,
            "detection_engine": t.detection_engine.value,
            "confidence": t.confidence_score,
            "detected_at": t.detected_at.isoformat(),
            "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None
        } for t in threats[:limit]]

    def get_user_threat_stats(self, user_id: str) -> Dict[str, Any]:
        """Get threat statistics for a user."""
        if self._use_db:
            try:
                rows = self.db.query(self._m.Threat).filter(self._m.Threat.user_id == user_id).all()
                by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
                by_type: Dict[str, int] = {}
                now = datetime.now()
                last_7 = 0
                last_30 = 0
                for r in rows:
                    sev = r.threat_severity or "medium"
                    by_severity[sev] = by_severity.get(sev, 0) + 1
                    tt = r.threat_type or "malware"
                    by_type[tt] = by_type.get(tt, 0) + 1
                    if r.detected_at and r.detected_at > now - timedelta(days=7):
                        last_7 += 1
                    if r.detected_at and r.detected_at > now - timedelta(days=30):
                        last_30 += 1
                return {
                    "total_threats": len(rows),
                    "last_7_days": last_7,
                    "last_30_days": last_30,
                    "by_severity": by_severity,
                    "by_type": by_type,
                }
            except Exception as e:
                logger.error(f"DB get_user_threat_stats failed: {e}")

        user_threats = [t for t in self._threats.values() if t.user_id == user_id]

        by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        by_type: Dict[str, int] = {}

        for t in user_threats:
            by_severity[t.threat_severity.value] = by_severity.get(t.threat_severity.value, 0) + 1
            by_type[t.threat_type.value] = by_type.get(t.threat_type.value, 0) + 1

        last_7_days = [t for t in user_threats if t.detected_at > datetime.now() - timedelta(days=7)]
        last_30_days = [t for t in user_threats if t.detected_at > datetime.now() - timedelta(days=30)]

        return {
            "total_threats": len(user_threats),
            "last_7_days": len(last_7_days),
            "last_30_days": len(last_30_days),
            "by_severity": by_severity,
            "by_type": by_type
        }

    # ==================== FIREWALL (Desktop) ====================

    def get_firewall_rules(self, device_id: str) -> List[Dict[str, Any]]:
        """Get all firewall rules for a device."""
        if self._use_db:
            try:
                rows = self.db.query(self._m.FirewallRule).filter(
                    self._m.FirewallRule.device_id == device_id
                ).all()
                return [{
                    "id": r.id, "name": r.name, "description": r.description,
                    "rule_type": r.rule_type, "direction": r.direction,
                    "protocol": r.protocol, "local_port": r.local_port,
                    "remote_port": r.remote_port, "remote_ip": r.remote_ip,
                    "application_path": r.application_path,
                    "is_enabled": r.is_enabled, "is_system_rule": r.is_system_rule,
                    "times_triggered": r.times_triggered or 0,
                    "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
                } for r in rows]
            except Exception as e:
                logger.error(f"DB get_firewall_rules failed: {e}")

        rules = [r for r in self._firewall_rules.values() if r.device_id == device_id]

        return [{
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "rule_type": r.rule_type.value,
            "direction": r.direction.value,
            "protocol": r.protocol,
            "local_port": r.local_port,
            "remote_port": r.remote_port,
            "remote_ip": r.remote_ip,
            "application_path": r.application_path,
            "is_enabled": r.is_enabled,
            "is_system_rule": r.is_system_rule,
            "times_triggered": r.times_triggered,
            "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None
        } for r in rules]

    def create_firewall_rule(self, device_id: str, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new firewall rule."""
        rule = FirewallRule(
            id=str(uuid.uuid4()),
            device_id=device_id,
            name=rule_data["name"],
            description=rule_data.get("description"),
            rule_type=FirewallRuleType(rule_data["rule_type"]),
            direction=FirewallDirection(rule_data["direction"]),
            protocol=rule_data.get("protocol", "any"),
            local_port=rule_data.get("local_port"),
            remote_port=rule_data.get("remote_port"),
            remote_ip=rule_data.get("remote_ip"),
            application_path=rule_data.get("application_path"),
            is_system_rule=False
        )
        self._firewall_rules[rule.id] = rule

        if self._use_db:
            try:
                row = self._m.FirewallRule(
                    id=rule.id, device_id=device_id, name=rule.name,
                    description=rule.description,
                    rule_type=rule.rule_type.value, direction=rule.direction.value,
                    protocol=rule.protocol, local_port=rule.local_port,
                    remote_port=rule.remote_port, remote_ip=rule.remote_ip,
                    application_path=rule.application_path, is_system_rule=False,
                )
                self.db.add(row)
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB create_firewall_rule failed: {e}")

        return {"success": True, "rule_id": rule.id}

    def _get_firewall_rule_obj(self, rule_id: str) -> Optional[FirewallRule]:
        """Retrieve a FirewallRule — DB first, then in-memory."""
        if self._use_db:
            try:
                row = self.db.query(self._m.FirewallRule).filter(self._m.FirewallRule.id == rule_id).first()
                if row:
                    rule = FirewallRule(
                        id=row.id, device_id=row.device_id, name=row.name,
                        description=row.description,
                        rule_type=FirewallRuleType(row.rule_type),
                        direction=FirewallDirection(row.direction),
                        protocol=row.protocol or "any",
                        local_port=row.local_port, remote_port=row.remote_port,
                        remote_ip=row.remote_ip, application_path=row.application_path,
                        is_enabled=row.is_enabled if row.is_enabled is not None else True,
                        is_system_rule=row.is_system_rule or False,
                        times_triggered=row.times_triggered or 0,
                        last_triggered_at=row.last_triggered_at,
                    )
                    self._firewall_rules[rule_id] = rule
                    return rule
            except Exception as e:
                logger.error(f"DB get_firewall_rule_obj failed: {e}")
        return self._firewall_rules.get(rule_id)

    def _persist_firewall_rule(self, rule: FirewallRule):
        """Write a FirewallRule back to DB."""
        if not self._use_db:
            return
        try:
            row = self.db.query(self._m.FirewallRule).filter(self._m.FirewallRule.id == rule.id).first()
            if row:
                row.name = rule.name
                row.description = rule.description
                row.rule_type = rule.rule_type.value
                row.direction = rule.direction.value
                row.protocol = rule.protocol
                row.is_enabled = rule.is_enabled
                row.times_triggered = rule.times_triggered
                row.last_triggered_at = rule.last_triggered_at
                self._safe_commit()
        except Exception as e:
            logger.error(f"DB persist_firewall_rule failed: {e}")

    def update_firewall_rule(self, rule_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update a firewall rule."""
        rule = self._get_firewall_rule_obj(rule_id)
        if not rule:
            return {"success": False, "error": "Rule not found"}

        if rule.is_system_rule:
            return {"success": False, "error": "Cannot modify system rules"}

        if "name" in updates:
            rule.name = updates["name"]
        if "description" in updates:
            rule.description = updates["description"]
        if "rule_type" in updates:
            rule.rule_type = FirewallRuleType(updates["rule_type"])
        if "direction" in updates:
            rule.direction = FirewallDirection(updates["direction"])
        if "is_enabled" in updates:
            rule.is_enabled = updates["is_enabled"]

        self._persist_firewall_rule(rule)
        return {"success": True, "rule_id": rule_id}

    def toggle_firewall_rule(self, rule_id: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable a firewall rule."""
        rule = self._get_firewall_rule_obj(rule_id)
        if not rule:
            return {"success": False, "error": "Rule not found"}

        if rule.is_system_rule:
            return {"success": False, "error": "Cannot modify system rules"}

        rule.is_enabled = enabled
        self._persist_firewall_rule(rule)
        return {"success": True, "is_enabled": enabled}

    def delete_firewall_rule(self, rule_id: str) -> Dict[str, Any]:
        """Delete a firewall rule."""
        rule = self._get_firewall_rule_obj(rule_id)
        if not rule:
            return {"success": False, "error": "Rule not found"}

        if rule.is_system_rule:
            return {"success": False, "error": "Cannot delete system rules"}

        self._firewall_rules.pop(rule_id, None)

        if self._use_db:
            try:
                self.db.query(self._m.FirewallRule).filter(self._m.FirewallRule.id == rule_id).delete()
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB delete_firewall_rule failed: {e}")

        return {"success": True}

    def log_firewall_event(self, device_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Log a firewall block/allow event."""
        if event.get("rule_id"):
            rule = self._get_firewall_rule_obj(event["rule_id"])
            if rule:
                rule.times_triggered += 1
                rule.last_triggered_at = datetime.now()
                self._persist_firewall_rule(rule)

        # If blocked, record as threat
        if event.get("action") == "blocked":
            device = self._get_device_obj(device_id)
            self._record_threat(
                user_id=device.user_id if device else "",
                device_id=device_id,
                threat_data={
                    "threat_type": "network_attack",
                    "threat_name": event.get("threat_name", "Blocked Connection"),
                    "severity": event.get("severity", "medium"),
                    "source_type": "network",
                    "action_taken": "blocked",
                    "metadata": event
                }
            )

        return {"success": True}

    # ==================== VPN ====================

    def _ensure_user(self, user_id: str) -> "ShieldUser":
        """
        FORGE S4: Lazy-create a ShieldUser on first reference so API
        consumers don't get spurious 'User not found' errors. Uses the
        BASIC plan by default. This is safe because all downstream checks
        still enforce subscription/plan features.

        FORGE G-21: Now checks DB first before creating.
        """
        # Try DB then in-memory
        user = self._get_user_obj(user_id)
        if user is not None:
            return user

        # Lazy-create with basic trial plan
        default_plan = None
        for p in self._plans.values():
            if getattr(p, "slug", None) in ("basic", "trial", "free", "standard"):
                default_plan = p
                break
        if default_plan is None and self._plans:
            default_plan = next(iter(self._plans.values()))

        user = ShieldUser(
            id=user_id,
            email=f"auto-{user_id}@aither.local",
            name=f"Auto-provisioned user {user_id}",
            plan_id=default_plan.id if default_plan else None,
            subscription_status=SubscriptionStatus.TRIAL,
            subscription_expires_at=datetime.now() + timedelta(days=14),
        )
        self._users[user_id] = user
        self._persist_user(user)
        return user

    def get_vpn_servers(self, user_id: str) -> Dict[str, Any]:
        """Get available VPN servers for user's plan."""
        user = self._ensure_user(user_id)
        plan = self._plans.get(user.plan_id) if user.plan_id else None

        if not plan or not (plan.features.get("vpn") or plan.features.get("vpn_daily_mb") or plan.features.get("vpn_unlimited")):
            # Return server list anyway so the admin can see options;
            # real access enforcement happens at connect_vpn time.
            return {"servers": self._vpn_servers, "plan_blocks_vpn": True}

        return {"servers": self._vpn_servers}

    def connect_vpn(self, device_id: str, server_id: str) -> Dict[str, Any]:
        """Request VPN connection."""
        device = self._get_device_obj(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}

        user = self._get_user_obj(device.user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        plan = self._plans.get(user.plan_id) if user.plan_id else None

        # Check VPN access
        if not plan or not (plan.features.get("vpn") or plan.features.get("vpn_unlimited") or plan.features.get("vpn_daily_mb")):
            return {"success": False, "error": "VPN not included in your plan"}

        # Find server
        server = next((s for s in self._vpn_servers if s["id"] == server_id), None)
        if not server:
            return {"success": False, "error": "Invalid server"}

        # Close existing session for this device — DB then in-memory
        if self._use_db:
            try:
                active = self.db.query(self._m.VPNSession).filter(
                    self._m.VPNSession.device_id == device_id,
                    self._m.VPNSession.status == "connected",
                ).all()
                for row in active:
                    row.status = "disconnected"
                    row.disconnected_at = datetime.now()
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB close existing VPN sessions failed: {e}")

        for sess in self._vpn_sessions.values():
            if sess.device_id == device_id and sess.status == VPNStatus.CONNECTED:
                sess.status = VPNStatus.DISCONNECTED
                sess.disconnected_at = datetime.now()

        # Create new session
        session = VPNSession(
            id=str(uuid.uuid4()),
            user_id=user.id,
            device_id=device_id,
            server_location=server["location"],
            server_ip=server["ip"],
            assigned_ip=f"10.8.{random.randint(1, 254)}.{random.randint(1, 254)}",
            protocol="wireguard",
            status=VPNStatus.CONNECTED,
            connected_at=datetime.now()
        )
        self._vpn_sessions[session.id] = session

        if self._use_db:
            try:
                row = self._m.VPNSession(
                    id=session.id, user_id=session.user_id, device_id=session.device_id,
                    server_location=session.server_location, server_ip=session.server_ip,
                    assigned_ip=session.assigned_ip, protocol=session.protocol,
                    status="connected", connected_at=session.connected_at,
                )
                self.db.add(row)
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB create VPN session failed: {e}")

        return {
            "success": True,
            "session_id": session.id,
            "config": {
                "server_endpoint": f"{server_id}.vpn.aithershield.com:51820",
                "server_ip": server["ip"],
                "assigned_ip": session.assigned_ip,
                "dns": ["1.1.1.1", "1.0.0.1"],
                "allowed_ips": "0.0.0.0/0",
                "persistent_keepalive": 25
            }
        }

    def disconnect_vpn(self, device_id: str) -> Dict[str, Any]:
        """Disconnect VPN."""
        # Try DB first
        if self._use_db:
            try:
                row = self.db.query(self._m.VPNSession).filter(
                    self._m.VPNSession.device_id == device_id,
                    self._m.VPNSession.status == "connected",
                ).first()
                if row:
                    row.status = "disconnected"
                    row.disconnected_at = datetime.now()
                    self._safe_commit()
                    # Also update in-memory
                    sess = self._vpn_sessions.get(row.id)
                    if sess:
                        sess.status = VPNStatus.DISCONNECTED
                        sess.disconnected_at = row.disconnected_at
                    return {"success": True, "session_id": row.id}
            except Exception as e:
                logger.error(f"DB disconnect_vpn failed: {e}")

        for session in self._vpn_sessions.values():
            if session.device_id == device_id and session.status == VPNStatus.CONNECTED:
                session.status = VPNStatus.DISCONNECTED
                session.disconnected_at = datetime.now()
                return {"success": True, "session_id": session.id}

        return {"success": False, "error": "No active VPN session"}

    def get_vpn_status(self, device_id: str) -> Dict[str, Any]:
        """Get current VPN status for device."""
        if self._use_db:
            try:
                row = self.db.query(self._m.VPNSession).filter(
                    self._m.VPNSession.device_id == device_id,
                    self._m.VPNSession.status == "connected",
                ).first()
                if row:
                    return {
                        "connected": True,
                        "session_id": row.id,
                        "server_location": row.server_location,
                        "assigned_ip": row.assigned_ip,
                        "connected_at": row.connected_at.isoformat() if row.connected_at else None,
                        "bytes_sent": row.bytes_sent or 0,
                        "bytes_received": row.bytes_received or 0,
                    }
                return {"connected": False}
            except Exception as e:
                logger.error(f"DB get_vpn_status failed: {e}")

        for session in self._vpn_sessions.values():
            if session.device_id == device_id and session.status == VPNStatus.CONNECTED:
                return {
                    "connected": True,
                    "session_id": session.id,
                    "server_location": session.server_location,
                    "assigned_ip": session.assigned_ip,
                    "connected_at": session.connected_at.isoformat() if session.connected_at else None,
                    "bytes_sent": session.bytes_sent,
                    "bytes_received": session.bytes_received
                }

        return {"connected": False}

    def report_vpn_usage(self, session_id: str, bytes_sent: int, bytes_received: int) -> Dict[str, Any]:
        """Report VPN bandwidth usage."""
        # Try DB first
        if self._use_db:
            try:
                row = self.db.query(self._m.VPNSession).filter(self._m.VPNSession.id == session_id).first()
                if row:
                    row.bytes_sent = (row.bytes_sent or 0) + bytes_sent
                    row.bytes_received = (row.bytes_received or 0) + bytes_received
                    self._safe_commit()
                    # Update in-memory too
                    sess = self._vpn_sessions.get(session_id)
                    if sess:
                        sess.bytes_sent = row.bytes_sent
                        sess.bytes_received = row.bytes_received
                    return {
                        "success": True,
                        "total_bytes_sent": row.bytes_sent,
                        "total_bytes_received": row.bytes_received,
                    }
                elif not self._vpn_sessions.get(session_id):
                    return {"success": False, "error": "Session not found"}
            except Exception as e:
                logger.error(f"DB report_vpn_usage failed: {e}")

        session = self._vpn_sessions.get(session_id)
        if not session:
            return {"success": False, "error": "Session not found"}

        session.bytes_sent += bytes_sent
        session.bytes_received += bytes_received

        return {
            "success": True,
            "total_bytes_sent": session.bytes_sent,
            "total_bytes_received": session.bytes_received
        }

    # ==================== DARK WEB MONITORING ====================

    def check_dark_web(self, user_id: str) -> Dict[str, Any]:
        """Check if user's data appears on dark web."""
        user = self._ensure_user(user_id)  # FORGE S4: lazy auto-provision

        plan = self._plans.get(user.plan_id) if user.plan_id else None

        if not plan or not plan.features.get("dark_web_monitoring"):
            return {
                "breaches_found": 0,
                "alerts": [],
                "plan_blocks_dark_web": True,
                "last_checked": datetime.now().isoformat(),
            }

        # Simulate dark web scan (would integrate with actual threat intel)
        # For demo, sometimes return sample breaches
        breaches = []
        if random.random() < 0.3:  # 30% chance of finding something
            sample_breaches = [
                {"type": "email_breach", "data_type": "email", "source": "DataBreach2023", "recommendations": ["Change passwords", "Enable 2FA"]},
                {"type": "password_leak", "data_type": "password_hash", "source": "LeakedDB", "recommendations": ["Reset all passwords", "Use password manager"]}
            ]
            breaches = [random.choice(sample_breaches)]

        # Record alerts
        new_alerts = []
        for breach in breaches:
            alert = DarkWebAlert(
                id=str(uuid.uuid4()),
                user_id=user_id,
                alert_type=DarkWebAlertType(breach["type"]),
                exposed_data_type=breach["data_type"],
                source_breach=breach["source"],
                status=DarkWebAlertStatus.NEW,
                recommended_actions=breach.get("recommendations", [])
            )
            self._dark_web_alerts[alert.id] = alert
            new_alerts.append(alert)

            # Persist to DB
            if self._use_db:
                try:
                    row = self._m.DarkWebAlert(
                        id=alert.id, user_id=alert.user_id,
                        alert_type=alert.alert_type.value,
                        exposed_data_type=alert.exposed_data_type,
                        source_breach=alert.source_breach,
                        status=alert.status.value,
                        recommended_actions=alert.recommended_actions,
                        discovered_at=alert.discovered_at,
                    )
                    self.db.add(row)
                except Exception as e:
                    logger.error(f"DB dark web alert persist failed: {e}")

        if self._use_db and new_alerts:
            try:
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB dark web alerts commit failed: {e}")

        return {
            "breaches_found": len(breaches),
            "alerts": [{
                "id": a.id,
                "type": a.alert_type.value,
                "source": a.source_breach,
                "status": a.status.value,
                "discovered_at": a.discovered_at.isoformat()
            } for a in new_alerts],
            "last_checked": datetime.now().isoformat()
        }

    def get_dark_web_alerts(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all dark web alerts for user."""
        if self._use_db:
            try:
                rows = (self.db.query(self._m.DarkWebAlert)
                        .filter(self._m.DarkWebAlert.user_id == user_id)
                        .order_by(self._m.DarkWebAlert.discovered_at.desc())
                        .all())
                return [{
                    "id": r.id,
                    "alert_type": r.alert_type,
                    "exposed_data_type": r.exposed_data_type,
                    "source_breach": r.source_breach,
                    "status": r.status,
                    "recommended_actions": r.recommended_actions or [],
                    "discovered_at": r.discovered_at.isoformat() if r.discovered_at else None,
                    "acknowledged_at": r.acknowledged_at.isoformat() if r.acknowledged_at else None,
                } for r in rows]
            except Exception as e:
                logger.error(f"DB get_dark_web_alerts failed: {e}")

        alerts = [a for a in self._dark_web_alerts.values() if a.user_id == user_id]
        alerts.sort(key=lambda x: x.discovered_at, reverse=True)

        return [{
            "id": a.id,
            "alert_type": a.alert_type.value,
            "exposed_data_type": a.exposed_data_type,
            "source_breach": a.source_breach,
            "status": a.status.value,
            "recommended_actions": a.recommended_actions,
            "discovered_at": a.discovered_at.isoformat(),
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None
        } for a in alerts]

    def acknowledge_dark_web_alert(self, alert_id: str) -> Dict[str, Any]:
        """Acknowledge a dark web alert."""
        # Try DB first
        if self._use_db:
            try:
                row = self.db.query(self._m.DarkWebAlert).filter(self._m.DarkWebAlert.id == alert_id).first()
                if row:
                    row.status = "acknowledged"
                    row.acknowledged_at = datetime.now()
                    self._safe_commit()
                    # Update in-memory
                    alert = self._dark_web_alerts.get(alert_id)
                    if alert:
                        alert.status = DarkWebAlertStatus.ACKNOWLEDGED
                        alert.acknowledged_at = row.acknowledged_at
                    return {"success": True, "status": "acknowledged"}
                elif not self._dark_web_alerts.get(alert_id):
                    return {"success": False, "error": "Alert not found"}
            except Exception as e:
                logger.error(f"DB acknowledge_dark_web_alert failed: {e}")

        alert = self._dark_web_alerts.get(alert_id)
        if not alert:
            return {"success": False, "error": "Alert not found"}

        alert.status = DarkWebAlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = datetime.now()

        return {"success": True, "status": alert.status.value}

    def resolve_dark_web_alert(self, alert_id: str) -> Dict[str, Any]:
        """Mark a dark web alert as resolved."""
        if self._use_db:
            try:
                row = self.db.query(self._m.DarkWebAlert).filter(self._m.DarkWebAlert.id == alert_id).first()
                if row:
                    row.status = "resolved"
                    self._safe_commit()
                    alert = self._dark_web_alerts.get(alert_id)
                    if alert:
                        alert.status = DarkWebAlertStatus.RESOLVED
                    return {"success": True, "status": "resolved"}
                elif not self._dark_web_alerts.get(alert_id):
                    return {"success": False, "error": "Alert not found"}
            except Exception as e:
                logger.error(f"DB resolve_dark_web_alert failed: {e}")

        alert = self._dark_web_alerts.get(alert_id)
        if not alert:
            return {"success": False, "error": "Alert not found"}

        alert.status = DarkWebAlertStatus.RESOLVED

        return {"success": True, "status": alert.status.value}

    # ==================== SIGNATURES ====================

    def get_signature_version(self) -> Dict[str, Any]:
        """Get latest threat signature version."""
        return {
            "version": self._signature_version,
            "signature_count": len(self._signatures),
            "last_updated": datetime.now().isoformat()
        }

    def get_signature_updates(self, current_version: str) -> Dict[str, Any]:
        """Get signature updates since version."""
        # In production, would return delta of signatures
        return {
            "current_version": current_version,
            "latest_version": self._signature_version,
            "needs_update": current_version != self._signature_version,
            "update_size_bytes": 1024 * 1024 * 5,  # 5MB
            "signatures_added": 150,
            "signatures_removed": 12
        }

    # ==================== HELPERS ====================

    def _generate_device_fingerprint(self, device_info: Dict[str, Any]) -> str:
        """Generate unique device fingerprint."""
        # Use `or ""` to coerce None values (Optional fields) to empty strings
        # before joining — Pydantic dict() preserves None for unset Optionals.
        components = [
            device_info.get("device_id") or "",
            device_info.get("type") or "",
            device_info.get("model") or "",
            device_info.get("serial") or "",
        ]
        return hashlib.sha256("".join(components).encode()).hexdigest()

    def _get_default_scan_paths(self, scan_type: str, device_type: str) -> List[str]:
        """Get default scan paths based on scan type and OS."""
        if device_type == "windows":
            if scan_type == "quick":
                return ["C:\\Users", "C:\\Windows\\Temp", "C:\\ProgramData"]
            return ["C:\\"]
        elif device_type == "mac":
            if scan_type == "quick":
                return ["/Users", "/tmp", "/Applications"]
            return ["/"]
        elif device_type in ["iphone", "android"]:
            return ["/data", "/storage"]
        return []

    def _initialize_firewall_rules(self, device_id: str):
        """Create default firewall rules for new desktop device."""
        default_rules = [
            {"name": "Block Inbound - Known Malware Ports", "rule_type": "block",
             "direction": "inbound", "protocol": "tcp", "local_port": "4444,5555,6666",
             "is_system_rule": True},
            {"name": "Allow Outbound - HTTP/HTTPS", "rule_type": "allow",
             "direction": "outbound", "protocol": "tcp", "remote_port": "80,443",
             "is_system_rule": True},
            {"name": "Allow Outbound - DNS", "rule_type": "allow",
             "direction": "outbound", "protocol": "udp", "remote_port": "53",
             "is_system_rule": True},
            {"name": "Block Inbound - SMB", "rule_type": "block",
             "direction": "inbound", "protocol": "tcp", "local_port": "445",
             "is_system_rule": True},
            {"name": "Block Inbound - RDP from Internet", "rule_type": "block",
             "direction": "inbound", "protocol": "tcp", "local_port": "3389",
             "remote_ip": "!192.168.0.0/16", "is_system_rule": True},
        ]

        for rule_data in default_rules:
            rule = FirewallRule(
                id=str(uuid.uuid4()),
                device_id=device_id,
                name=rule_data["name"],
                description=None,
                rule_type=FirewallRuleType(rule_data["rule_type"]),
                direction=FirewallDirection(rule_data["direction"]),
                protocol=rule_data.get("protocol", "any"),
                local_port=rule_data.get("local_port"),
                remote_port=rule_data.get("remote_port"),
                remote_ip=rule_data.get("remote_ip"),
                application_path=None,
                is_system_rule=rule_data.get("is_system_rule", False)
            )
            self._firewall_rules[rule.id] = rule

            if self._use_db:
                try:
                    row = self._m.FirewallRule(
                        id=rule.id, device_id=device_id, name=rule.name,
                        description=None,
                        rule_type=rule.rule_type.value, direction=rule.direction.value,
                        protocol=rule.protocol, local_port=rule.local_port,
                        remote_port=rule.remote_port, remote_ip=rule.remote_ip,
                        application_path=None,
                        is_system_rule=rule.is_system_rule,
                    )
                    self.db.add(row)
                except Exception as e:
                    logger.error(f"DB init firewall rule failed: {e}")

        if self._use_db:
            try:
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB init firewall rules commit failed: {e}")

    def _check_signature(self, file_hash: str) -> Optional[ThreatSignature]:
        """Check if file hash matches known threat signature."""
        for sig in self._signatures.values():
            if sig.signature_hash == file_hash and sig.is_active:
                sig.detections_count += 1
                return sig
        return None

    def _record_threat(self, user_id: str, device_id: str, threat_data: Dict[str, Any],
                       scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Record a detected threat."""
        threat = ShieldThreat(
            id=str(uuid.uuid4()),
            user_id=user_id,
            device_id=device_id,
            threat_type=ThreatType(threat_data.get("threat_type", "malware")),
            threat_name=threat_data.get("threat_name", "Unknown Threat"),
            threat_severity=ThreatSeverity(threat_data.get("severity", "medium")),
            threat_hash=threat_data.get("hash"),
            source_type=threat_data.get("source_type", "file"),
            source_path=threat_data.get("source_path"),
            source_url=threat_data.get("source_url"),
            action_taken=threat_data.get("action_taken", "quarantined"),
            detection_engine=DetectionEngine(threat_data.get("detection_engine", "signature")),
            confidence_score=threat_data.get("confidence", 1.0),
            metadata=threat_data.get("metadata", {})
        )
        self._threats[threat.id] = threat

        # Persist threat to DB
        if self._use_db:
            try:
                row = self._m.Threat(
                    id=threat.id, user_id=user_id, device_id=device_id,
                    threat_type=threat.threat_type.value,
                    threat_name=threat.threat_name,
                    threat_severity=threat.threat_severity.value,
                    threat_hash=threat.threat_hash,
                    source_type=threat.source_type,
                    source_path=threat.source_path,
                    source_url=threat.source_url,
                    action_taken=threat.action_taken,
                    detection_engine=threat.detection_engine.value,
                    confidence_score=threat.confidence_score,
                    detected_at=threat.detected_at,
                    metadata_json=threat.metadata,
                )
                self.db.add(row)
                self._safe_commit()
            except Exception as e:
                logger.error(f"DB _record_threat failed: {e}")

        # Update device and user stats
        device = self._get_device_obj(device_id)
        if device:
            device.threats_blocked += 1
            self._persist_device(device)

        user = self._get_user_obj(user_id)
        if user:
            user.threats_blocked_total += 1
            self._persist_user(user)

        return {"threat_id": threat.id, "recorded": True}

    # ==================== DASHBOARD/STATS ====================

    def get_dashboard_stats(self, user_id: str) -> Dict[str, Any]:
        """Get dashboard statistics for user."""
        user = self._get_user_obj(user_id)
        if not user:
            return {"error": "User not found"}

        # Get devices
        if self._use_db:
            try:
                dev_rows = self.db.query(self._m.Device).filter(self._m.Device.user_id == user_id).all()
                devices_data = [{
                    "protection_status": r.protection_status,
                    "scans_completed": r.scans_completed or 0,
                    "last_scan_at": r.last_scan_at,
                } for r in dev_rows]
            except Exception as e:
                logger.error(f"DB dashboard devices failed: {e}")
                devices_data = None
        else:
            devices_data = None

        if devices_data is None:
            devs = [d for d in self._devices.values() if d.user_id == user_id]
            devices_data = [{
                "protection_status": d.protection_status.value,
                "scans_completed": d.scans_completed,
                "last_scan_at": d.last_scan_at,
            } for d in devs]

        total_devices = len(devices_data)
        active_devices = len([d for d in devices_data if d["protection_status"] == "active"
                              or d["protection_status"] == ProtectionStatus.ACTIVE])

        # Get threat counts
        now = datetime.now()
        threats_24h = 0
        threats_7d = 0
        if self._use_db:
            try:
                threats_24h = self.db.query(self._m.Threat).filter(
                    self._m.Threat.user_id == user_id,
                    self._m.Threat.detected_at > now - timedelta(hours=24)
                ).count()
                threats_7d = self.db.query(self._m.Threat).filter(
                    self._m.Threat.user_id == user_id,
                    self._m.Threat.detected_at > now - timedelta(days=7)
                ).count()
            except Exception as e:
                logger.error(f"DB dashboard threats failed: {e}")
                threats = [t for t in self._threats.values() if t.user_id == user_id]
                threats_24h = len([t for t in threats if t.detected_at > now - timedelta(hours=24)])
                threats_7d = len([t for t in threats if t.detected_at > now - timedelta(days=7)])
        else:
            threats = [t for t in self._threats.values() if t.user_id == user_id]
            threats_24h = len([t for t in threats if t.detected_at > now - timedelta(hours=24)])
            threats_7d = len([t for t in threats if t.detected_at > now - timedelta(days=7)])

        plan = self._plans.get(user.plan_id) if user.plan_id else None

        total_completed = sum(d["scans_completed"] for d in devices_data)
        scan_dates = [d["last_scan_at"] for d in devices_data if d["last_scan_at"]]
        last_scan = max(scan_dates) if scan_dates else None

        return {
            "user": {
                "name": user.name,
                "email": user.email,
                "plan": plan.name if plan else "Free",
                "subscription_status": user.subscription_status.value
            },
            "protection": {
                "total_devices": total_devices,
                "active_devices": active_devices,
                "max_devices": plan.max_devices if plan else 1,
                "all_protected": active_devices == total_devices and total_devices > 0
            },
            "threats": {
                "total_blocked": user.threats_blocked_total,
                "last_24h": threats_24h,
                "last_7d": threats_7d
            },
            "scans": {
                "total_completed": total_completed,
                "last_scan": last_scan
            }
        }
