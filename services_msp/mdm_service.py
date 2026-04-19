"""
AITHER Platform - MDM Enhanced Service
MSP Pillar - Mobile Device Management

Full-featured MDM service with BYOD policy enforcement, app management,
device compliance, geofencing, and remote actions.

DB persistence with in-memory fallback.
"""

import math
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.mdm import (
        ManagedMobileDeviceModel,
        DevicePolicyModel,
        ManagedAppModel,
        ComplianceRuleModel,
        DeviceActionModel,
        GeofenceZoneModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ── Enums ─────────────────────────────────────────────────────────────

class PolicyType(str, Enum):
    PASSCODE = "passcode"
    ENCRYPTION = "encryption"
    APP_WHITELIST = "app_whitelist"
    APP_BLACKLIST = "app_blacklist"
    WIFI_CONFIG = "wifi_config"
    VPN_CONFIG = "vpn_config"
    EMAIL_CONFIG = "email_config"
    RESTRICTIONS = "restrictions"
    GEOFENCE = "geofence"
    COMPLIANCE = "compliance"
    DATA_PROTECTION = "data_protection"


class EnrollmentStatus(str, Enum):
    ENROLLED = "enrolled"
    PENDING = "pending"
    UNENROLLED = "unenrolled"
    WIPED = "wiped"
    SUSPENDED = "suspended"


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    GRACE_PERIOD = "grace_period"


class DeviceActionType(str, Enum):
    LOCK = "lock"
    WIPE = "wipe"
    SELECTIVE_WIPE = "selective_wipe"
    RING = "ring"
    LOCATE = "locate"
    MESSAGE = "message"
    INSTALL_APP = "install_app"
    REMOVE_APP = "remove_app"
    UPDATE_POLICY = "update_policy"
    RESTART = "restart"
    ENABLE_LOST_MODE = "enable_lost_mode"


# ── Dataclasses ───────────────────────────────────────────────────────

@dataclass
class ManagedMobileDevice:
    device_id: str
    user_id: str
    client_id: str
    device_name: str
    platform: str  # ios/android/windows_mobile
    os_version: str
    model: str
    serial_number: str
    imei: str = ""
    enrollment_status: str = "pending"
    compliance_status: str = "unknown"
    last_checkin: Optional[str] = None
    management_profile_installed: bool = False
    encryption_enabled: bool = False
    passcode_set: bool = False
    jailbroken: bool = False
    roaming: bool = False
    battery_level: int = 100
    storage_used_pct: float = 0.0
    work_profile_enabled: bool = False
    personal_apps_separated: bool = False
    last_latitude: Optional[float] = None
    last_longitude: Optional[float] = None


@dataclass
class DevicePolicy:
    policy_id: str
    name: str
    description: str = ""
    platform: str = "all"
    policy_type: str = "compliance"
    settings: Dict[str, Any] = field(default_factory=dict)
    is_mandatory: bool = False
    assigned_groups: List[str] = field(default_factory=list)
    created_at: str = ""


@dataclass
class AppManagement:
    app_id: str
    name: str
    bundle_id: str
    platform: str = "all"
    version: str = "1.0.0"
    is_required: bool = False
    is_blocked: bool = False
    install_count: int = 0
    category: str = "general"


@dataclass
class ComplianceRule:
    rule_id: str
    name: str
    description: str = ""
    check_type: str = ""  # os_version_min/encryption_required/passcode_required/...
    expected_value: str = ""
    severity: str = "warning"  # warning/critical
    auto_remediate: bool = False
    remediation_action: str = ""


@dataclass
class DeviceAction:
    action_id: str
    device_id: str
    action_type: str
    status: str = "pending"
    requested_by: str = "system"
    requested_at: str = ""
    completed_at: Optional[str] = None
    result: str = ""
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeofenceZone:
    zone_id: str
    name: str
    latitude: float
    longitude: float
    radius_meters: float = 500.0
    action_on_exit: str = "alert"  # alert/lock/wipe
    assigned_devices: List[str] = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────

def _gen_id(prefix: str = "MDM") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _haversine_meters(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Return distance in meters between two lat/lng pairs."""
    R = 6_371_000  # Earth radius in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lng2 - lng1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ── Service ───────────────────────────────────────────────────────────

class MDMService:
    """
    Enhanced Mobile Device Management service.

    Covers device enrollment, BYOD work/personal separation,
    policy enforcement, app management, compliance evaluation,
    remote actions, and geofencing.

    Integrates with:
    - Nomad MDM (legacy defense MDM)
    - Shield Defense (endpoint protection)
    - Compliance Frameworks (HIPAA, SOC2)
    """

    def __init__(self, db: Optional["Session"] = None):
        self.db = db
        self._devices: Dict[str, ManagedMobileDevice] = {}
        self._policies: Dict[str, DevicePolicy] = {}
        self._apps: Dict[str, AppManagement] = {}
        self._rules: Dict[str, ComplianceRule] = {}
        self._actions: Dict[str, DeviceAction] = {}
        self._zones: Dict[str, GeofenceZone] = {}
        self._loaded = False
        self._seed_defaults()

    # ── Persistence helpers ───────────────────────────────────────────

    def _use_db(self) -> bool:
        return ORM_AVAILABLE and self.db is not None

    def _seed_defaults(self):
        """Seed default compliance rules and a baseline policy."""
        now = _now_iso()
        # Default compliance rules
        defaults = [
            ("RULE-ENC", "Encryption Required", "encryption_required", "true", "critical"),
            ("RULE-PASS", "Passcode Required", "passcode_required", "true", "critical"),
            ("RULE-JB", "Jailbreak Check", "jailbreak_check", "false", "critical"),
            ("RULE-OSMIN", "Minimum OS Version", "os_version_min", "14.0", "warning"),
            ("RULE-ROAM", "Roaming Disabled", "roaming_disabled", "true", "warning"),
        ]
        for rid, name, check, val, sev in defaults:
            self._rules[rid] = ComplianceRule(
                rule_id=rid, name=name, check_type=check,
                expected_value=val, severity=sev,
                auto_remediate=(sev == "warning"),
                remediation_action="notify_user" if sev == "warning" else "quarantine",
            )
        # Default baseline policy
        self._policies["POL-BASELINE"] = DevicePolicy(
            policy_id="POL-BASELINE",
            name="Baseline Security",
            description="Mandatory baseline for all enrolled devices",
            platform="all",
            policy_type=PolicyType.COMPLIANCE.value,
            settings={"require_encryption": True, "require_passcode": True, "min_passcode_length": 6},
            is_mandatory=True,
            created_at=now,
        )

    # ── Device Management ─────────────────────────────────────────────

    def enroll_device(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enroll a new device into MDM management."""
        device_id = _gen_id("DEV")
        now = _now_iso()
        device = ManagedMobileDevice(
            device_id=device_id,
            user_id=data.get("user_id", ""),
            client_id=data.get("client_id", ""),
            device_name=data.get("device_name", "Unknown Device"),
            platform=data.get("platform", "android"),
            os_version=data.get("os_version", ""),
            model=data.get("model", ""),
            serial_number=data.get("serial_number", ""),
            imei=data.get("imei", ""),
            enrollment_status=EnrollmentStatus.ENROLLED.value,
            compliance_status=ComplianceStatus.UNKNOWN.value,
            last_checkin=now,
            management_profile_installed=True,
        )
        if self._use_db():
            row = ManagedMobileDeviceModel(
                device_id=device_id, user_id=device.user_id,
                client_id=device.client_id, device_name=device.device_name,
                platform=device.platform, os_version=device.os_version,
                model=device.model, serial_number=device.serial_number,
                imei=device.imei, enrollment_status=device.enrollment_status,
                compliance_status=device.compliance_status,
                last_checkin=datetime.now(timezone.utc),
                management_profile_installed=True,
            )
            self.db.add(row)
            self.db.commit()
        self._devices[device_id] = device
        logger.info(f"MDM device enrolled: {device_id}")
        return {"success": True, "device_id": device_id, "enrollment_status": device.enrollment_status}

    def unenroll_device(self, device_id: str) -> Dict[str, Any]:
        """Remove a device from MDM management."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        device.enrollment_status = EnrollmentStatus.UNENROLLED.value
        device.compliance_status = ComplianceStatus.UNKNOWN.value
        device.management_profile_installed = False
        if self._use_db():
            row = self.db.query(ManagedMobileDeviceModel).filter(
                ManagedMobileDeviceModel.device_id == device_id
            ).first()
            if row:
                row.enrollment_status = device.enrollment_status
                row.compliance_status = device.compliance_status
                row.management_profile_installed = False
                self.db.commit()
        logger.info(f"MDM device unenrolled: {device_id}")
        return {"success": True, "device_id": device_id, "status": device.enrollment_status}

    def get_device(self, device_id: str) -> Dict[str, Any]:
        """Get details for a single device."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        return {"success": True, "device": vars(device)}

    def list_devices(
        self,
        platform: Optional[str] = None,
        enrollment_status: Optional[str] = None,
        compliance_status: Optional[str] = None,
        client_id: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """List managed devices with optional filters."""
        results = list(self._devices.values())
        if platform:
            results = [d for d in results if d.platform == platform]
        if enrollment_status:
            results = [d for d in results if d.enrollment_status == enrollment_status]
        if compliance_status:
            results = [d for d in results if d.compliance_status == compliance_status]
        if client_id:
            results = [d for d in results if d.client_id == client_id]
        return {
            "total": len(results),
            "devices": [vars(d) for d in results[:limit]],
        }

    def update_device_info(self, device_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update device metadata (model, os_version, etc.)."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        allowed = {
            "device_name", "os_version", "model", "serial_number", "imei",
            "battery_level", "storage_used_pct", "roaming",
        }
        applied = []
        for k, v in updates.items():
            if k in allowed and hasattr(device, k):
                setattr(device, k, v)
                applied.append(k)
        if self._use_db() and applied:
            row = self.db.query(ManagedMobileDeviceModel).filter(
                ManagedMobileDeviceModel.device_id == device_id
            ).first()
            if row:
                for k in applied:
                    if hasattr(row, k):
                        setattr(row, k, getattr(device, k))
                self.db.commit()
        return {"success": True, "device_id": device_id, "updated_fields": applied}

    def checkin(self, device_id: str, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a device check-in with updated telemetry."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        now = _now_iso()
        device.last_checkin = now
        for field_name in ("battery_level", "storage_used_pct", "roaming",
                           "encryption_enabled", "passcode_set", "jailbroken",
                           "os_version"):
            if field_name in device_data:
                setattr(device, field_name, device_data[field_name])
        if "latitude" in device_data and "longitude" in device_data:
            device.last_latitude = device_data["latitude"]
            device.last_longitude = device_data["longitude"]
        # Auto-evaluate compliance on checkin
        compliance = self.evaluate_compliance(device_id)
        if self._use_db():
            row = self.db.query(ManagedMobileDeviceModel).filter(
                ManagedMobileDeviceModel.device_id == device_id
            ).first()
            if row:
                row.last_checkin = datetime.now(timezone.utc)
                row.battery_level = device.battery_level
                row.storage_used_pct = device.storage_used_pct
                row.encryption_enabled = device.encryption_enabled
                row.passcode_set = device.passcode_set
                row.jailbroken = device.jailbroken
                row.roaming = device.roaming
                row.compliance_status = device.compliance_status
                if device.last_latitude is not None:
                    row.last_latitude = device.last_latitude
                    row.last_longitude = device.last_longitude
                self.db.commit()
        return {
            "success": True,
            "device_id": device_id,
            "checkin_time": now,
            "compliance": compliance,
        }

    # ── Policy Management ─────────────────────────────────────────────

    def create_policy(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new device policy."""
        policy_id = _gen_id("POL")
        policy = DevicePolicy(
            policy_id=policy_id,
            name=data.get("name", "Untitled Policy"),
            description=data.get("description", ""),
            platform=data.get("platform", "all"),
            policy_type=data.get("policy_type", PolicyType.COMPLIANCE.value),
            settings=data.get("settings", {}),
            is_mandatory=data.get("is_mandatory", False),
            assigned_groups=data.get("assigned_groups", []),
            created_at=_now_iso(),
        )
        if self._use_db():
            row = DevicePolicyModel(
                policy_id=policy_id, name=policy.name,
                description=policy.description, platform=policy.platform,
                policy_type=policy.policy_type, settings=policy.settings,
                is_mandatory=policy.is_mandatory,
                assigned_groups=policy.assigned_groups,
            )
            self.db.add(row)
            self.db.commit()
        self._policies[policy_id] = policy
        return {"success": True, "policy_id": policy_id, "name": policy.name}

    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing policy."""
        policy = self._policies.get(policy_id)
        if not policy:
            return {"success": False, "error": "Policy not found"}
        for k in ("name", "description", "platform", "policy_type", "settings",
                   "is_mandatory", "assigned_groups"):
            if k in updates:
                setattr(policy, k, updates[k])
        if self._use_db():
            row = self.db.query(DevicePolicyModel).filter(
                DevicePolicyModel.policy_id == policy_id
            ).first()
            if row:
                for k in ("name", "description", "platform", "policy_type",
                           "settings", "is_mandatory", "assigned_groups"):
                    if k in updates and hasattr(row, k):
                        setattr(row, k, updates[k])
                self.db.commit()
        return {"success": True, "policy_id": policy_id}

    def delete_policy(self, policy_id: str) -> Dict[str, Any]:
        """Delete a policy."""
        if policy_id not in self._policies:
            return {"success": False, "error": "Policy not found"}
        del self._policies[policy_id]
        if self._use_db():
            self.db.query(DevicePolicyModel).filter(
                DevicePolicyModel.policy_id == policy_id
            ).delete()
            self.db.commit()
        return {"success": True, "policy_id": policy_id}

    def list_policies(self, platform: Optional[str] = None) -> Dict[str, Any]:
        """List all policies with optional platform filter."""
        results = list(self._policies.values())
        if platform:
            results = [p for p in results if p.platform in (platform, "all")]
        return {
            "total": len(results),
            "policies": [vars(p) for p in results],
        }

    def assign_policy_to_group(self, policy_id: str, group: str) -> Dict[str, Any]:
        """Assign a policy to a device group."""
        policy = self._policies.get(policy_id)
        if not policy:
            return {"success": False, "error": "Policy not found"}
        if group not in policy.assigned_groups:
            policy.assigned_groups.append(group)
        return {"success": True, "policy_id": policy_id, "assigned_groups": policy.assigned_groups}

    def get_effective_policies(self, device_id: str) -> Dict[str, Any]:
        """Get all policies that apply to a device (mandatory + group-matched)."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        effective = []
        for p in self._policies.values():
            if p.platform not in (device.platform, "all"):
                continue
            if p.is_mandatory:
                effective.append(vars(p))
            # Group matching could be expanded with device group assignments
        return {"device_id": device_id, "effective_policies": effective, "count": len(effective)}

    # ── App Management ────────────────────────────────────────────────

    def register_app(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register an app in the MDM catalog."""
        app_id = _gen_id("APP")
        app = AppManagement(
            app_id=app_id,
            name=data.get("name", "Unknown App"),
            bundle_id=data.get("bundle_id", ""),
            platform=data.get("platform", "all"),
            version=data.get("version", "1.0.0"),
            is_required=data.get("is_required", False),
            is_blocked=data.get("is_blocked", False),
            category=data.get("category", "general"),
        )
        if self._use_db():
            row = ManagedAppModel(
                app_id=app_id, name=app.name, bundle_id=app.bundle_id,
                platform=app.platform, version=app.version,
                is_required=app.is_required, is_blocked=app.is_blocked,
                category=app.category,
            )
            self.db.add(row)
            self.db.commit()
        self._apps[app_id] = app
        return {"success": True, "app_id": app_id, "name": app.name}

    def block_app(self, app_id: str) -> Dict[str, Any]:
        """Block an app from being installed on managed devices."""
        app = self._apps.get(app_id)
        if not app:
            return {"success": False, "error": "App not found"}
        app.is_blocked = True
        app.is_required = False
        if self._use_db():
            row = self.db.query(ManagedAppModel).filter(
                ManagedAppModel.app_id == app_id
            ).first()
            if row:
                row.is_blocked = True
                row.is_required = False
                self.db.commit()
        return {"success": True, "app_id": app_id, "status": "blocked"}

    def require_app(self, app_id: str) -> Dict[str, Any]:
        """Mark an app as required on all managed devices."""
        app = self._apps.get(app_id)
        if not app:
            return {"success": False, "error": "App not found"}
        app.is_required = True
        app.is_blocked = False
        if self._use_db():
            row = self.db.query(ManagedAppModel).filter(
                ManagedAppModel.app_id == app_id
            ).first()
            if row:
                row.is_required = True
                row.is_blocked = False
                self.db.commit()
        return {"success": True, "app_id": app_id, "status": "required"}

    def list_apps(self, platform: Optional[str] = None, category: Optional[str] = None) -> Dict[str, Any]:
        """List all managed apps."""
        results = list(self._apps.values())
        if platform:
            results = [a for a in results if a.platform in (platform, "all")]
        if category:
            results = [a for a in results if a.category == category]
        return {"total": len(results), "apps": [vars(a) for a in results]}

    def get_app_install_status(self, device_id: str) -> Dict[str, Any]:
        """Check which required/blocked apps are installed on a device."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        required = [vars(a) for a in self._apps.values() if a.is_required and a.platform in (device.platform, "all")]
        blocked = [vars(a) for a in self._apps.values() if a.is_blocked and a.platform in (device.platform, "all")]
        return {
            "device_id": device_id,
            "required_apps": required,
            "blocked_apps": blocked,
            "required_count": len(required),
            "blocked_count": len(blocked),
        }

    # ── Compliance ────────────────────────────────────────────────────

    def create_compliance_rule(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new compliance rule."""
        rule_id = _gen_id("RULE")
        rule = ComplianceRule(
            rule_id=rule_id,
            name=data.get("name", "Untitled Rule"),
            description=data.get("description", ""),
            check_type=data.get("check_type", ""),
            expected_value=data.get("expected_value", ""),
            severity=data.get("severity", "warning"),
            auto_remediate=data.get("auto_remediate", False),
            remediation_action=data.get("remediation_action", ""),
        )
        if self._use_db():
            row = ComplianceRuleModel(
                rule_id=rule_id, name=rule.name, description=rule.description,
                check_type=rule.check_type, expected_value=rule.expected_value,
                severity=rule.severity, auto_remediate=rule.auto_remediate,
                remediation_action=rule.remediation_action,
            )
            self.db.add(row)
            self.db.commit()
        self._rules[rule_id] = rule
        return {"success": True, "rule_id": rule_id, "name": rule.name}

    def evaluate_compliance(self, device_id: str) -> Dict[str, Any]:
        """Evaluate a device against all compliance rules."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        violations = []
        for rule in self._rules.values():
            violated = False
            detail = ""
            if rule.check_type == "encryption_required" and not device.encryption_enabled:
                violated = True
                detail = "Encryption is not enabled"
            elif rule.check_type == "passcode_required" and not device.passcode_set:
                violated = True
                detail = "Passcode is not set"
            elif rule.check_type == "jailbreak_check" and device.jailbroken:
                violated = True
                detail = "Device is jailbroken/rooted"
            elif rule.check_type == "os_version_min":
                try:
                    if device.os_version and device.os_version < rule.expected_value:
                        violated = True
                        detail = f"OS version {device.os_version} below minimum {rule.expected_value}"
                except Exception:
                    pass
            elif rule.check_type == "roaming_disabled" and device.roaming:
                violated = True
                detail = "Device is roaming"
            if violated:
                violations.append({
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "detail": detail,
                    "auto_remediate": rule.auto_remediate,
                    "remediation_action": rule.remediation_action,
                })
        compliant = len(violations) == 0
        new_status = ComplianceStatus.COMPLIANT.value if compliant else ComplianceStatus.NON_COMPLIANT.value
        device.compliance_status = new_status
        return {
            "device_id": device_id,
            "compliant": compliant,
            "status": new_status,
            "violations": violations,
            "rules_checked": len(self._rules),
            "checked_at": _now_iso(),
        }

    def evaluate_all_compliance(self) -> Dict[str, Any]:
        """Evaluate compliance for all enrolled devices."""
        results = []
        for did, dev in self._devices.items():
            if dev.enrollment_status == EnrollmentStatus.ENROLLED.value:
                r = self.evaluate_compliance(did)
                results.append(r)
        compliant_count = sum(1 for r in results if r.get("compliant"))
        return {
            "total_evaluated": len(results),
            "compliant": compliant_count,
            "non_compliant": len(results) - compliant_count,
            "compliance_rate": round(compliant_count / max(len(results), 1) * 100, 1),
            "results": results,
        }

    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate an aggregate compliance report."""
        enrolled = [d for d in self._devices.values() if d.enrollment_status == EnrollmentStatus.ENROLLED.value]
        compliant = sum(1 for d in enrolled if d.compliance_status == ComplianceStatus.COMPLIANT.value)
        non_compliant = sum(1 for d in enrolled if d.compliance_status == ComplianceStatus.NON_COMPLIANT.value)
        unknown = sum(1 for d in enrolled if d.compliance_status in (ComplianceStatus.UNKNOWN.value, ComplianceStatus.GRACE_PERIOD.value))
        total = len(enrolled)
        # Count violations per rule
        rule_violations: Dict[str, int] = {}
        for dev in enrolled:
            result = self.evaluate_compliance(dev.device_id)
            for v in result.get("violations", []):
                rn = v["rule_name"]
                rule_violations[rn] = rule_violations.get(rn, 0) + 1
        top_violations = sorted(rule_violations.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "total_enrolled": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "unknown": unknown,
            "compliance_rate": round(compliant / max(total, 1) * 100, 1),
            "top_non_compliant_rules": [{"rule": r, "count": c} for r, c in top_violations],
            "generated_at": _now_iso(),
        }

    # ── Device Actions ────────────────────────────────────────────────

    def send_action(self, device_id: str, action_type: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a remote action to a device."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        if device.enrollment_status != EnrollmentStatus.ENROLLED.value:
            return {"success": False, "error": "Device is not enrolled"}
        try:
            DeviceActionType(action_type)
        except ValueError:
            return {"success": False, "error": f"Invalid action type: {action_type}"}

        action_id = _gen_id("ACT")
        now = _now_iso()
        action = DeviceAction(
            action_id=action_id,
            device_id=device_id,
            action_type=action_type,
            status="completed",  # simulated immediate execution
            requested_by=params.get("requested_by", "admin") if params else "admin",
            requested_at=now,
            completed_at=now,
            result=f"Action '{action_type}' executed successfully",
            params=params or {},
        )
        # Apply side-effects
        if action_type == DeviceActionType.WIPE.value:
            device.enrollment_status = EnrollmentStatus.WIPED.value
            device.compliance_status = ComplianceStatus.UNKNOWN.value
        elif action_type == DeviceActionType.SELECTIVE_WIPE.value:
            device.work_profile_enabled = False
            device.personal_apps_separated = False
        elif action_type == DeviceActionType.LOCK.value:
            action.result = f"Device locked. Message: {params.get('message', 'Locked by admin')}" if params else "Device locked"

        if self._use_db():
            row = DeviceActionModel(
                action_id=action_id, device_id=device_id,
                action_type=action_type, status="completed",
                requested_by=action.requested_by,
                completed_at=datetime.now(timezone.utc),
                result=action.result, params=params or {},
            )
            self.db.add(row)
            self.db.commit()
        self._actions[action_id] = action
        return {"success": True, "action_id": action_id, "action_type": action_type, "status": "completed"}

    def get_action_status(self, action_id: str) -> Dict[str, Any]:
        """Get status of a specific action."""
        action = self._actions.get(action_id)
        if not action:
            return {"success": False, "error": "Action not found"}
        return {"success": True, "action": vars(action)}

    def list_actions(self, device_id: Optional[str] = None, status: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        """List device actions with optional filters."""
        results = list(self._actions.values())
        if device_id:
            results = [a for a in results if a.device_id == device_id]
        if status:
            results = [a for a in results if a.status == status]
        results.sort(key=lambda a: a.requested_at, reverse=True)
        return {"total": len(results), "actions": [vars(a) for a in results[:limit]]}

    # ── Geofencing ────────────────────────────────────────────────────

    def create_zone(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a geofence zone."""
        zone_id = _gen_id("GEO")
        zone = GeofenceZone(
            zone_id=zone_id,
            name=data.get("name", "Untitled Zone"),
            latitude=data.get("latitude", 0.0),
            longitude=data.get("longitude", 0.0),
            radius_meters=data.get("radius_meters", 500.0),
            action_on_exit=data.get("action_on_exit", "alert"),
            assigned_devices=data.get("assigned_devices", []),
        )
        if self._use_db():
            row = GeofenceZoneModel(
                zone_id=zone_id, name=zone.name,
                latitude=zone.latitude, longitude=zone.longitude,
                radius_meters=zone.radius_meters,
                action_on_exit=zone.action_on_exit,
                assigned_devices=zone.assigned_devices,
            )
            self.db.add(row)
            self.db.commit()
        self._zones[zone_id] = zone
        return {"success": True, "zone_id": zone_id, "name": zone.name}

    def update_zone(self, zone_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update a geofence zone."""
        zone = self._zones.get(zone_id)
        if not zone:
            return {"success": False, "error": "Zone not found"}
        for k in ("name", "latitude", "longitude", "radius_meters", "action_on_exit", "assigned_devices"):
            if k in updates:
                setattr(zone, k, updates[k])
        if self._use_db():
            row = self.db.query(GeofenceZoneModel).filter(
                GeofenceZoneModel.zone_id == zone_id
            ).first()
            if row:
                for k in ("name", "latitude", "longitude", "radius_meters", "action_on_exit", "assigned_devices"):
                    if k in updates and hasattr(row, k):
                        setattr(row, k, updates[k])
                self.db.commit()
        return {"success": True, "zone_id": zone_id}

    def delete_zone(self, zone_id: str) -> Dict[str, Any]:
        """Delete a geofence zone."""
        if zone_id not in self._zones:
            return {"success": False, "error": "Zone not found"}
        del self._zones[zone_id]
        if self._use_db():
            self.db.query(GeofenceZoneModel).filter(
                GeofenceZoneModel.zone_id == zone_id
            ).delete()
            self.db.commit()
        return {"success": True, "zone_id": zone_id}

    def list_zones(self) -> Dict[str, Any]:
        """List all geofence zones."""
        return {
            "total": len(self._zones),
            "zones": [vars(z) for z in self._zones.values()],
        }

    def check_device_location(self, device_id: str, lat: float, lng: float) -> Dict[str, Any]:
        """Check if a device is within any assigned geofence zones."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        device.last_latitude = lat
        device.last_longitude = lng
        alerts = []
        for zone in self._zones.values():
            if device_id not in zone.assigned_devices and "*" not in zone.assigned_devices:
                continue
            dist = _haversine_meters(lat, lng, zone.latitude, zone.longitude)
            inside = dist <= zone.radius_meters
            if not inside:
                alerts.append({
                    "zone_id": zone.zone_id,
                    "zone_name": zone.name,
                    "distance_meters": round(dist, 1),
                    "action": zone.action_on_exit,
                    "status": "outside_geofence",
                })
                # Auto-trigger action
                if zone.action_on_exit in ("lock", "wipe"):
                    self.send_action(device_id, zone.action_on_exit)
        return {
            "device_id": device_id,
            "latitude": lat,
            "longitude": lng,
            "alerts": alerts,
            "inside_all_zones": len(alerts) == 0,
        }

    # ── BYOD ──────────────────────────────────────────────────────────

    def separate_work_personal(self, device_id: str) -> Dict[str, Any]:
        """Enable work/personal separation (BYOD container)."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        device.work_profile_enabled = True
        device.personal_apps_separated = True
        if self._use_db():
            row = self.db.query(ManagedMobileDeviceModel).filter(
                ManagedMobileDeviceModel.device_id == device_id
            ).first()
            if row:
                row.work_profile_enabled = True
                row.personal_apps_separated = True
                self.db.commit()
        return {
            "success": True,
            "device_id": device_id,
            "work_profile_enabled": True,
            "personal_apps_separated": True,
        }

    def get_work_profile_status(self, device_id: str) -> Dict[str, Any]:
        """Get BYOD work profile status for a device."""
        device = self._devices.get(device_id)
        if not device:
            return {"success": False, "error": "Device not found"}
        return {
            "device_id": device_id,
            "work_profile_enabled": device.work_profile_enabled,
            "personal_apps_separated": device.personal_apps_separated,
            "platform": device.platform,
        }

    # ── Dashboard ─────────────────────────────────────────────────────

    def get_dashboard(self) -> Dict[str, Any]:
        """Get MDM dashboard overview."""
        all_devices = list(self._devices.values())
        enrolled = [d for d in all_devices if d.enrollment_status == EnrollmentStatus.ENROLLED.value]
        # Platform breakdown
        by_platform: Dict[str, int] = {}
        for d in enrolled:
            by_platform[d.platform] = by_platform.get(d.platform, 0) + 1
        # Compliance
        compliant = sum(1 for d in enrolled if d.compliance_status == ComplianceStatus.COMPLIANT.value)
        total = len(enrolled)
        # Pending actions
        pending_actions = sum(1 for a in self._actions.values() if a.status == "pending")
        # Top non-compliant rules
        rule_violations: Dict[str, int] = {}
        for dev in enrolled:
            if dev.compliance_status == ComplianceStatus.NON_COMPLIANT.value:
                result = self.evaluate_compliance(dev.device_id)
                for v in result.get("violations", []):
                    rn = v["rule_name"]
                    rule_violations[rn] = rule_violations.get(rn, 0) + 1
        top_rules = sorted(rule_violations.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "total_devices": len(all_devices),
            "enrolled": total,
            "unenrolled": sum(1 for d in all_devices if d.enrollment_status == EnrollmentStatus.UNENROLLED.value),
            "wiped": sum(1 for d in all_devices if d.enrollment_status == EnrollmentStatus.WIPED.value),
            "by_platform": by_platform,
            "compliance_rate": round(compliant / max(total, 1) * 100, 1),
            "compliant_devices": compliant,
            "non_compliant_devices": total - compliant,
            "pending_actions": pending_actions,
            "total_policies": len(self._policies),
            "total_apps": len(self._apps),
            "total_geofences": len(self._zones),
            "top_non_compliant_rules": [{"rule": r, "count": c} for r, c in top_rules],
            "generated_at": _now_iso(),
        }
