"""
shield.py — Aither Shield consumer security persistence models

FORGE G-21: This model file persists Shield data that previously lived
in services/shield/shield_service.py as 7 in-memory Dict stores:
  self._users, self._devices, self._threats, self._scans,
  self._firewall_rules, self._vpn_sessions, self._dark_web_alerts

Every field maps 1:1 to the original @dataclass fields in shield_service.py.
_plans and _signatures remain in-memory (static reference data).

Created: 2026-04-11 (Gap G-21 — biggest persistence gap in platform)
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


# ── ShieldUser ──────────────────────────────────────────────────────────────

class ShieldUserModel(Base):
    """
    Replaces self._users: Dict[str, ShieldUser]
    """
    __tablename__ = "shield_users"

    id = Column(String(36), primary_key=True, default=_uuid)
    email = Column(String(255), nullable=False, index=True)
    name = Column(String(255), nullable=True)
    plan_id = Column(String(36), nullable=True)
    subscription_status = Column(String(20), default="trial", index=True)
    subscription_expires_at = Column(DateTime, nullable=True)
    devices_registered = Column(Integer, default=0)
    threats_blocked_total = Column(Integer, default=0)
    is_family_admin = Column(Boolean, default=False)
    family_group_id = Column(String(36), nullable=True)
    created_at = Column(DateTime, default=_now)


# ── ShieldDevice ────────────────────────────────────────────────────────────

class ShieldDeviceModel(Base):
    """
    Replaces self._devices: Dict[str, ShieldDevice]
    """
    __tablename__ = "shield_devices"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), nullable=False, index=True)
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(20), nullable=False)  # iphone, android, windows, mac
    os_version = Column(String(50), nullable=True)
    app_version = Column(String(20), nullable=False)
    device_fingerprint = Column(String(64), nullable=False, index=True)
    protection_status = Column(String(20), default="active", index=True)
    last_seen_at = Column(DateTime, nullable=True)
    last_scan_at = Column(DateTime, nullable=True)
    threats_blocked = Column(Integer, default=0)
    scans_completed = Column(Integer, default=0)
    push_token = Column(String(255), nullable=True)


# ── ShieldThreat ────────────────────────────────────────────────────────────

class ShieldThreatModel(Base):
    """
    Replaces self._threats: Dict[str, ShieldThreat]
    """
    __tablename__ = "shield_threats"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), nullable=False, index=True)
    device_id = Column(String(36), nullable=False, index=True)
    threat_type = Column(String(30), nullable=False)  # malware, phishing, ransomware, etc.
    threat_name = Column(String(255), nullable=False)
    threat_severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    threat_hash = Column(String(64), nullable=True)
    source_type = Column(String(30), nullable=False, default="file")
    source_path = Column(Text, nullable=True)
    source_url = Column(Text, nullable=True)
    action_taken = Column(String(30), default="quarantined")
    detection_engine = Column(String(20), default="signature")  # signature, heuristic, ai, cloud, behavioral
    confidence_score = Column(Float, default=1.0)
    detected_at = Column(DateTime, default=_now)
    resolved_at = Column(DateTime, nullable=True)
    metadata_json = Column(JSON, default=dict)

    __table_args__ = (
        Index("ix_shield_threat_user_detected", "user_id", "detected_at"),
        Index("ix_shield_threat_device_detected", "device_id", "detected_at"),
    )


# ── ShieldScan ──────────────────────────────────────────────────────────────

class ShieldScanModel(Base):
    """
    Replaces self._scans: Dict[str, ShieldScan]
    """
    __tablename__ = "shield_scans"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), nullable=False, index=True)
    device_id = Column(String(36), nullable=False, index=True)
    scan_type = Column(String(20), nullable=False)  # quick, full, custom, scheduled, realtime
    status = Column(String(20), default="running", index=True)
    files_scanned = Column(Integer, default=0)
    threats_found = Column(Integer, default=0)
    threats_resolved = Column(Integer, default=0)
    started_at = Column(DateTime, default=_now)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    results_json = Column(JSON, default=dict)


# ── FirewallRule ────────────────────────────────────────────────────────────

class ShieldFirewallRuleModel(Base):
    """
    Replaces self._firewall_rules: Dict[str, FirewallRule]
    """
    __tablename__ = "shield_firewall_rules"

    id = Column(String(36), primary_key=True, default=_uuid)
    device_id = Column(String(36), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    rule_type = Column(String(10), nullable=False)  # allow, block
    direction = Column(String(10), nullable=False)  # inbound, outbound, both
    protocol = Column(String(10), default="any")
    local_port = Column(String(50), nullable=True)
    remote_port = Column(String(50), nullable=True)
    remote_ip = Column(String(100), nullable=True)
    application_path = Column(Text, nullable=True)
    is_enabled = Column(Boolean, default=True)
    is_system_rule = Column(Boolean, default=False)
    times_triggered = Column(Integer, default=0)
    last_triggered_at = Column(DateTime, nullable=True)


# ── VPNSession ──────────────────────────────────────────────────────────────

class ShieldVPNSessionModel(Base):
    """
    Replaces self._vpn_sessions: Dict[str, VPNSession]
    """
    __tablename__ = "shield_vpn_sessions"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), nullable=False, index=True)
    device_id = Column(String(36), nullable=False, index=True)
    server_location = Column(String(100), nullable=False)
    server_ip = Column(String(45), nullable=False)
    assigned_ip = Column(String(45), nullable=False)
    protocol = Column(String(20), default="wireguard")
    status = Column(String(20), default="connected", index=True)  # connected, disconnected, connecting
    connected_at = Column(DateTime, nullable=True)
    disconnected_at = Column(DateTime, nullable=True)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)


# ── DarkWebAlert ────────────────────────────────────────────────────────────

class ShieldDarkWebAlertModel(Base):
    """
    Replaces self._dark_web_alerts: Dict[str, DarkWebAlert]
    """
    __tablename__ = "shield_dark_web_alerts"

    id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), nullable=False, index=True)
    alert_type = Column(String(30), nullable=False)  # email_breach, password_leak, ssn_found, etc.
    exposed_data_type = Column(String(50), nullable=False)
    source_breach = Column(String(255), nullable=False)
    status = Column(String(20), default="new", index=True)  # new, acknowledged, resolved
    recommended_actions = Column(JSON, default=list)
    discovered_at = Column(DateTime, default=_now)
    acknowledged_at = Column(DateTime, nullable=True)
