"""
AITHER Platform - UEBA (User & Entity Behavior Analytics) Engine
Tracks user/device/IP actions, builds behavioral baselines,
detects anomalies in real-time, and feeds the threat scoring system.

G-46: DB persistence with in-memory fallback.
"""

import uuid
import math
import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.ueba import (
        UserBehaviorProfileModel,
        BehaviorEventModel,
        BehavioralBaselineModel,
        AnomalyDetectionModel,
        ThreatIndicatorModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ── Enums ────────────────────────────────────────────────────────────────

class EntityType(str, Enum):
    USER = "user"
    DEVICE = "device"
    IP_ADDRESS = "ip_address"
    SERVICE_ACCOUNT = "service_account"
    API_KEY = "api_key"
    NETWORK_SEGMENT = "network_segment"


class EventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    MFA_CHALLENGE = "mfa_challenge"
    FILE_ACCESS = "file_access"
    FILE_DOWNLOAD = "file_download"
    FILE_UPLOAD = "file_upload"
    FILE_DELETE = "file_delete"
    ADMIN_ACTION = "admin_action"
    PRIVILEGE_CHANGE = "privilege_change"
    CONFIG_CHANGE = "config_change"
    API_CALL = "api_call"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    EMAIL_SENT = "email_sent"
    EMAIL_RECEIVED = "email_received"
    PROCESS_EXECUTION = "process_execution"
    SERVICE_ACCESS = "service_access"
    DATA_EXPORT = "data_export"
    PRINT_JOB = "print_job"
    USB_INSERT = "usb_insert"
    VPN_CONNECT = "vpn_connect"
    VPN_DISCONNECT = "vpn_disconnect"
    REMOTE_ACCESS = "remote_access"


class AnomalyType(str, Enum):
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    UNUSUAL_LOGIN_TIME = "unusual_login_time"
    UNUSUAL_LOGIN_LOCATION = "unusual_login_location"
    EXCESSIVE_FAILURES = "excessive_failures"
    UNUSUAL_DATA_VOLUME = "unusual_data_volume"
    FIRST_TIME_ACCESS = "first_time_access"
    PRIVILEGE_ANOMALY = "privilege_anomaly"
    VELOCITY_ANOMALY = "velocity_anomaly"
    DEVICE_ANOMALY = "device_anomaly"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    SESSION_ANOMALY = "session_anomaly"
    LATERAL_MOVEMENT_PATTERN = "lateral_movement_pattern"
    EXFILTRATION_PATTERN = "exfiltration_pattern"
    BOT_BEHAVIOR = "bot_behavior"
    CREDENTIAL_SHARING = "credential_sharing"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimeWindow(str, Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ThreatIndicatorType(str, Enum):
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    COMPROMISED_ACCOUNT = "compromised_account"
    BOT_ACTIVITY = "bot_activity"
    PORT_SCAN = "port_scan"


# ── Dataclasses ──────────────────────────────────────────────────────────

@dataclass
class UserProfile:
    """Entity behavior profile."""
    profile_id: str
    entity_type: str = EntityType.USER.value
    entity_id: str = ""
    entity_name: str = ""
    client_id: str = ""
    baseline_established: bool = False
    baseline_data: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_level: str = RiskLevel.LOW.value
    total_events: int = 0
    anomaly_count: int = 0
    last_activity_at: Optional[datetime] = None
    first_seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = field(default_factory=list)
    is_watchlisted: bool = False


@dataclass
class BehaviorEvent:
    """Recorded behavioral event."""
    event_id: str
    profile_id: str = ""
    entity_id: str = ""
    event_type: str = EventType.LOGIN_SUCCESS.value
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = ""
    destination_ip: str = ""
    user_agent: str = ""
    geo_location: Dict[str, Any] = field(default_factory=dict)
    device_fingerprint: str = ""
    session_id: str = ""
    resource_accessed: str = ""
    action_performed: str = ""
    outcome: str = "success"
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_contribution: float = 0.0


@dataclass
class BehavioralBaseline:
    """Statistical baseline for one metric."""
    baseline_id: str
    profile_id: str = ""
    metric_name: str = ""
    expected_value: float = 0.0
    std_deviation: float = 0.0
    sample_count: int = 0
    confidence: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    time_window: str = TimeWindow.DAILY.value


@dataclass
class AnomalyDetection:
    """Detected anomaly record."""
    anomaly_id: str
    profile_id: str = ""
    event_id: str = ""
    anomaly_type: str = AnomalyType.BEHAVIORAL_DRIFT.value
    severity: str = RiskLevel.MEDIUM.value
    description: str = ""
    deviation_score: float = 0.0
    baseline_value: float = 0.0
    observed_value: float = 0.0
    is_confirmed: bool = False
    is_false_positive: bool = False
    auto_response_taken: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_at: Optional[datetime] = None
    reviewed_by: str = ""


@dataclass
class ThreatIndicator:
    """Correlated threat indicator."""
    indicator_id: str
    indicator_type: str = ThreatIndicatorType.BRUTE_FORCE.value
    related_profiles: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)
    confidence: float = 0.0
    severity: str = RiskLevel.MEDIUM.value
    ttps: List[str] = field(default_factory=list)
    is_active: bool = True
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""


# ── Helpers ──────────────────────────────────────────────────────────────

def _gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def _haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Great-circle distance between two coordinates in km."""
    R = 6371.0
    rlat1, rlng1, rlat2, rlng2 = map(math.radians, [lat1, lng1, lat2, lng2])
    dlat = rlat2 - rlat1
    dlng = rlng2 - rlng1
    a = math.sin(dlat / 2) ** 2 + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlng / 2) ** 2
    return R * 2 * math.asin(math.sqrt(a))


def _risk_level_from_score(score: float) -> str:
    if score >= 80:
        return RiskLevel.CRITICAL.value
    if score >= 60:
        return RiskLevel.HIGH.value
    if score >= 30:
        return RiskLevel.MEDIUM.value
    return RiskLevel.LOW.value


# ── Service ──────────────────────────────────────────────────────────────

class UEBAEngineService:
    """
    User & Entity Behavior Analytics engine.

    Tracks all user/device/IP actions, builds statistical baselines,
    detects anomalies in real-time, and feeds threat scoring.
    Supports PostgreSQL persistence with automatic in-memory fallback.
    """

    def __init__(self, db: "Session | None" = None):
        self.db = db
        self.use_db = db is not None and ORM_AVAILABLE
        # In-memory stores (fallback)
        self._profiles: Dict[str, UserProfile] = {}
        self._events: Dict[str, BehaviorEvent] = {}
        self._baselines: Dict[str, BehavioralBaseline] = {}
        self._anomalies: Dict[str, AnomalyDetection] = {}
        self._threats: Dict[str, ThreatIndicator] = {}
        # Index: entity_id -> profile_id
        self._entity_index: Dict[str, str] = {}
        # Index: profile_id -> list of event_ids
        self._profile_events: Dict[str, List[str]] = {}
        logger.info("UEBAEngineService initialized (db=%s)", "yes" if self.use_db else "in-memory")

    # ── Profile Management ───────────────────────────────────────────

    def create_profile(
        self,
        entity_type: str,
        entity_id: str,
        entity_name: str = "",
        client_id: str = "",
        tags: Optional[List[str]] = None,
    ) -> UserProfile:
        """Create a new entity behavior profile."""
        profile_id = _gen_id("UEBA")
        now = datetime.now(timezone.utc)
        profile = UserProfile(
            profile_id=profile_id,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name or entity_id,
            client_id=client_id,
            first_seen_at=now,
            tags=tags or [],
        )
        if self.use_db:
            try:
                row = UserBehaviorProfileModel(
                    profile_id=profile.profile_id,
                    entity_type=profile.entity_type,
                    entity_id=profile.entity_id,
                    entity_name=profile.entity_name,
                    client_id=profile.client_id,
                    baseline_established=False,
                    baseline_data={},
                    risk_score=0.0,
                    risk_level=RiskLevel.LOW.value,
                    total_events=0,
                    anomaly_count=0,
                    first_seen_at=now,
                    tags=profile.tags,
                    is_watchlisted=False,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for profile %s: %s", profile_id, exc)
        self._profiles[profile_id] = profile
        self._entity_index[entity_id] = profile_id
        self._profile_events.setdefault(profile_id, [])
        return profile

    def get_profile(self, profile_id: str) -> Optional[UserProfile]:
        """Retrieve a profile by ID."""
        if profile_id in self._profiles:
            return self._profiles[profile_id]
        if self.use_db:
            try:
                row = self.db.query(UserBehaviorProfileModel).filter_by(profile_id=profile_id).first()
                if row:
                    p = self._row_to_profile(row)
                    self._profiles[profile_id] = p
                    return p
            except Exception:
                pass
        return None

    def list_profiles(
        self,
        entity_type: Optional[str] = None,
        client_id: Optional[str] = None,
        risk_level: Optional[str] = None,
        watchlisted: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[UserProfile]:
        """List profiles with optional filters."""
        if self.use_db:
            try:
                q = self.db.query(UserBehaviorProfileModel)
                if entity_type:
                    q = q.filter_by(entity_type=entity_type)
                if client_id:
                    q = q.filter_by(client_id=client_id)
                if risk_level:
                    q = q.filter_by(risk_level=risk_level)
                if watchlisted is not None:
                    q = q.filter_by(is_watchlisted=watchlisted)
                rows = q.order_by(UserBehaviorProfileModel.risk_score.desc()).offset(offset).limit(limit).all()
                return [self._row_to_profile(r) for r in rows]
            except Exception:
                pass
        profiles = list(self._profiles.values())
        if entity_type:
            profiles = [p for p in profiles if p.entity_type == entity_type]
        if client_id:
            profiles = [p for p in profiles if p.client_id == client_id]
        if risk_level:
            profiles = [p for p in profiles if p.risk_level == risk_level]
        if watchlisted is not None:
            profiles = [p for p in profiles if p.is_watchlisted == watchlisted]
        profiles.sort(key=lambda p: p.risk_score, reverse=True)
        return profiles[offset: offset + limit]

    def update_profile(self, profile_id: str, **kwargs) -> Optional[UserProfile]:
        """Update profile fields."""
        profile = self.get_profile(profile_id)
        if not profile:
            return None
        for k, v in kwargs.items():
            if hasattr(profile, k):
                setattr(profile, k, v)
        self._profiles[profile_id] = profile
        if self.use_db:
            try:
                row = self.db.query(UserBehaviorProfileModel).filter_by(profile_id=profile_id).first()
                if row:
                    for k, v in kwargs.items():
                        if hasattr(row, k):
                            setattr(row, k, v)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for profile %s: %s", profile_id, exc)
        return profile

    def watchlist_profile(self, profile_id: str) -> Optional[UserProfile]:
        """Add a profile to the watchlist."""
        return self.update_profile(profile_id, is_watchlisted=True)

    def unwatchlist_profile(self, profile_id: str) -> Optional[UserProfile]:
        """Remove a profile from the watchlist."""
        return self.update_profile(profile_id, is_watchlisted=False)

    # ── Event Recording ──────────────────────────────────────────────

    def record_event(
        self,
        entity_id: str,
        event_type: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a behavioral event, run anomaly checks, return risk assessment.
        Auto-creates profile if entity_id is unknown.
        """
        context = context or {}
        now = datetime.now(timezone.utc)

        # Find or create profile
        profile_id = self._entity_index.get(entity_id)
        if not profile_id:
            profile = self.create_profile(
                entity_type=context.get("entity_type", EntityType.USER.value),
                entity_id=entity_id,
                entity_name=context.get("entity_name", entity_id),
                client_id=context.get("client_id", ""),
            )
            profile_id = profile.profile_id
        profile = self.get_profile(profile_id)

        event_id = _gen_id("EVT")
        event = BehaviorEvent(
            event_id=event_id,
            profile_id=profile_id,
            entity_id=entity_id,
            event_type=event_type,
            timestamp=now,
            source_ip=context.get("source_ip", ""),
            destination_ip=context.get("destination_ip", ""),
            user_agent=context.get("user_agent", ""),
            geo_location=context.get("geo_location", {}),
            device_fingerprint=context.get("device_fingerprint", ""),
            session_id=context.get("session_id", ""),
            resource_accessed=context.get("resource_accessed", ""),
            action_performed=context.get("action_performed", event_type),
            outcome=context.get("outcome", "success"),
            metadata=context.get("metadata", {}),
        )

        # Persist event
        self._events[event_id] = event
        self._profile_events.setdefault(profile_id, []).append(event_id)
        if self.use_db:
            try:
                row = BehaviorEventModel(
                    event_id=event.event_id,
                    profile_id=event.profile_id,
                    entity_id=event.entity_id,
                    event_type=event.event_type,
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    user_agent=event.user_agent,
                    geo_location=event.geo_location,
                    device_fingerprint=event.device_fingerprint,
                    session_id=event.session_id,
                    resource_accessed=event.resource_accessed,
                    action_performed=event.action_performed,
                    outcome=event.outcome,
                    metadata=event.metadata,
                    risk_contribution=0.0,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for event %s: %s", event_id, exc)

        # Update profile stats
        profile.total_events += 1
        profile.last_activity_at = now

        # Run anomaly detection
        anomalies = self._run_anomaly_checks(event, profile)

        # Update risk contribution on event
        risk_contribution = sum(a.deviation_score * 0.1 for a in anomalies)
        event.risk_contribution = min(risk_contribution, 25.0)

        # Recalculate risk score
        self.calculate_risk_score(profile_id)
        self._sync_profile_to_db(profile)

        return {
            "event_id": event_id,
            "profile_id": profile_id,
            "anomalies_detected": len(anomalies),
            "anomalies": [
                {"anomaly_id": a.anomaly_id, "type": a.anomaly_type, "severity": a.severity}
                for a in anomalies
            ],
            "risk_score": profile.risk_score,
            "risk_level": profile.risk_level,
        }

    def record_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Bulk event recording. Each item needs entity_id, event_type, and optional context."""
        results = []
        total_anomalies = 0
        for evt in events:
            r = self.record_event(
                entity_id=evt.get("entity_id", ""),
                event_type=evt.get("event_type", EventType.API_CALL.value),
                context=evt.get("context", {}),
            )
            results.append(r)
            total_anomalies += r["anomalies_detected"]
        return {
            "events_processed": len(results),
            "total_anomalies": total_anomalies,
            "results": results,
        }

    # ── Baseline Management ──────────────────────────────────────────

    def build_baseline(self, profile_id: str) -> Dict[str, Any]:
        """
        Build behavioral baseline from historical events.
        Computes statistics for login times, locations, data volumes, etc.
        """
        profile = self.get_profile(profile_id)
        if not profile:
            return {"error": "Profile not found"}

        events = self._get_profile_events(profile_id)
        if len(events) < 5:
            return {"error": "Insufficient events for baseline", "event_count": len(events)}

        baselines_built = []

        # Login hour distribution
        login_events = [e for e in events if e.event_type in (
            EventType.LOGIN_SUCCESS.value, EventType.LOGIN_FAILURE.value
        )]
        if login_events:
            hours = [e.timestamp.hour for e in login_events]
            bl = self._create_baseline(profile_id, "login_hour",
                                       statistics.mean(hours),
                                       statistics.pstdev(hours) if len(hours) > 1 else 4.0,
                                       len(hours))
            baselines_built.append(bl.metric_name)

        # Average daily event count
        dates: Dict[str, int] = {}
        for e in events:
            day = e.timestamp.strftime("%Y-%m-%d")
            dates[day] = dates.get(day, 0) + 1
        if dates:
            counts = list(dates.values())
            bl = self._create_baseline(profile_id, "avg_daily_events",
                                       statistics.mean(counts),
                                       statistics.pstdev(counts) if len(counts) > 1 else 5.0,
                                       len(counts))
            baselines_built.append(bl.metric_name)

        # Failed auth rate
        total_auth = len([e for e in events if e.event_type in (
            EventType.LOGIN_SUCCESS.value, EventType.LOGIN_FAILURE.value
        )])
        failed_auth = len([e for e in events if e.event_type == EventType.LOGIN_FAILURE.value])
        if total_auth > 0:
            rate = failed_auth / total_auth
            bl = self._create_baseline(profile_id, "failed_auth_rate",
                                       rate, 0.1, total_auth)
            baselines_built.append(bl.metric_name)

        # Unique source IPs
        ips = set(e.source_ip for e in events if e.source_ip)
        bl = self._create_baseline(profile_id, "unique_source_ips",
                                   float(len(ips)), float(max(1, len(ips) // 3)), len(events))
        baselines_built.append(bl.metric_name)

        # Unique devices
        devices = set(e.device_fingerprint for e in events if e.device_fingerprint)
        bl = self._create_baseline(profile_id, "unique_devices",
                                   float(len(devices)), 1.0, len(events))
        baselines_built.append(bl.metric_name)

        # Data volume (from metadata)
        volumes = [e.metadata.get("bytes_transferred", 0) for e in events if e.metadata.get("bytes_transferred")]
        if volumes:
            bl = self._create_baseline(profile_id, "data_volume_daily",
                                       statistics.mean(volumes),
                                       statistics.pstdev(volumes) if len(volumes) > 1 else statistics.mean(volumes) * 0.5,
                                       len(volumes))
            baselines_built.append(bl.metric_name)

        # Unique resources accessed
        resources = set(e.resource_accessed for e in events if e.resource_accessed)
        bl = self._create_baseline(profile_id, "unique_resources",
                                   float(len(resources)), float(max(1, len(resources) // 3)), len(events))
        baselines_built.append(bl.metric_name)

        profile.baseline_established = True
        profile.baseline_data = {m: True for m in baselines_built}
        self._profiles[profile_id] = profile
        self._sync_profile_to_db(profile)

        return {
            "profile_id": profile_id,
            "baselines_built": baselines_built,
            "event_count": len(events),
            "baseline_established": True,
        }

    def update_baseline(self, profile_id: str) -> Dict[str, Any]:
        """Re-compute baselines with latest event data."""
        return self.build_baseline(profile_id)

    def get_baselines(self, profile_id: str) -> List[BehavioralBaseline]:
        """Get all baselines for a profile."""
        if self.use_db:
            try:
                rows = self.db.query(BehavioralBaselineModel).filter_by(profile_id=profile_id).all()
                if rows:
                    return [self._row_to_baseline(r) for r in rows]
            except Exception:
                pass
        return [b for b in self._baselines.values() if b.profile_id == profile_id]

    # ── Anomaly Detection Checks ─────────────────────────────────────

    def _run_anomaly_checks(self, event: BehaviorEvent, profile: UserProfile) -> List[AnomalyDetection]:
        """Run all applicable anomaly detection checks on an event."""
        anomalies: List[AnomalyDetection] = []
        events = self._get_profile_events(profile.profile_id, limit=200)

        # Only run checks if we have some history
        if len(events) < 2:
            return anomalies

        checks = [
            self._check_impossible_travel,
            self._check_login_time_anomaly,
            self._check_location_anomaly,
            self._check_velocity_anomaly,
            self._check_data_volume_anomaly,
            self._check_device_anomaly,
            self._check_failure_rate,
            self._check_privilege_anomaly,
            self._check_first_time_access,
        ]
        for check in checks:
            try:
                anomaly = check(event, profile)
                if anomaly:
                    anomalies.append(anomaly)
            except Exception as exc:
                logger.debug("Anomaly check %s failed: %s", check.__name__, exc)

        # Multi-event pattern checks
        if len(events) >= 5:
            for check in [self._check_lateral_movement, self._check_exfiltration_pattern, self._check_bot_behavior]:
                try:
                    anomaly = check(events, profile)
                    if anomaly:
                        anomalies.append(anomaly)
                except Exception as exc:
                    logger.debug("Pattern check %s failed: %s", check.__name__, exc)

        # Update anomaly count
        profile.anomaly_count += len(anomalies)
        return anomalies

    def _check_impossible_travel(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect impossible travel: geo distance vs time between logins."""
        if not event.geo_location.get("lat") or event.event_type not in (
            EventType.LOGIN_SUCCESS.value, EventType.VPN_CONNECT.value
        ):
            return None
        events = self._get_profile_events(profile.profile_id, limit=50)
        prev_geo_events = [
            e for e in events
            if e.event_id != event.event_id
            and e.geo_location.get("lat")
            and e.event_type in (EventType.LOGIN_SUCCESS.value, EventType.VPN_CONNECT.value)
        ]
        if not prev_geo_events:
            return None
        prev = max(prev_geo_events, key=lambda e: e.timestamp)
        dist = _haversine_km(
            prev.geo_location["lat"], prev.geo_location["lng"],
            event.geo_location["lat"], event.geo_location["lng"],
        )
        dt_hours = max((event.timestamp - prev.timestamp).total_seconds() / 3600, 0.001)
        speed_kmh = dist / dt_hours
        # Max plausible speed: ~900 km/h (commercial jet)
        if speed_kmh > 900 and dist > 100:
            anomaly = self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.IMPOSSIBLE_TRAVEL.value, RiskLevel.CRITICAL.value,
                f"Impossible travel detected: {dist:.0f} km in {dt_hours:.1f}h ({speed_kmh:.0f} km/h)",
                speed_kmh, 900.0, speed_kmh,
            )
            return anomaly
        return None

    def _check_login_time_anomaly(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect logins outside typical hours."""
        if event.event_type != EventType.LOGIN_SUCCESS.value:
            return None
        baselines = self.get_baselines(profile.profile_id)
        login_bl = next((b for b in baselines if b.metric_name == "login_hour"), None)
        if not login_bl or login_bl.sample_count < 5:
            return None
        hour = event.timestamp.hour
        deviation = abs(hour - login_bl.expected_value)
        if deviation > 12:
            deviation = 24 - deviation
        if login_bl.std_deviation > 0 and deviation > login_bl.std_deviation * 3:
            return self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.UNUSUAL_LOGIN_TIME.value, RiskLevel.MEDIUM.value,
                f"Login at unusual hour {hour}:00 (baseline mean={login_bl.expected_value:.1f}, std={login_bl.std_deviation:.1f})",
                deviation / max(login_bl.std_deviation, 0.1), login_bl.expected_value, float(hour),
            )
        return None

    def _check_location_anomaly(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect logins from previously unseen locations."""
        geo = event.geo_location
        if not geo.get("country"):
            return None
        events = self._get_profile_events(profile.profile_id, limit=100)
        known_countries = set(
            e.geo_location.get("country") for e in events
            if e.event_id != event.event_id and e.geo_location.get("country")
        )
        if known_countries and geo["country"] not in known_countries:
            return self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.UNUSUAL_LOGIN_LOCATION.value, RiskLevel.HIGH.value,
                f"Login from new country: {geo['country']} (known: {', '.join(sorted(known_countries))})",
                3.0, 0.0, 1.0,
            )
        return None

    def _check_velocity_anomaly(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect excessive event velocity (too many events too fast)."""
        events = self._get_profile_events(profile.profile_id, limit=100)
        now = event.timestamp
        window = timedelta(minutes=5)
        recent = [e for e in events if (now - e.timestamp) < window]
        if len(recent) > 50:
            return self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.VELOCITY_ANOMALY.value, RiskLevel.HIGH.value,
                f"{len(recent)} events in 5 minutes (threshold: 50)",
                float(len(recent)), 50.0, float(len(recent)),
            )
        return None

    def _check_data_volume_anomaly(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect unusual data transfer volumes."""
        volume = event.metadata.get("bytes_transferred", 0)
        if not volume:
            return None
        baselines = self.get_baselines(profile.profile_id)
        vol_bl = next((b for b in baselines if b.metric_name == "data_volume_daily"), None)
        if not vol_bl or vol_bl.std_deviation == 0:
            return None
        deviation = abs(volume - vol_bl.expected_value) / max(vol_bl.std_deviation, 1.0)
        if deviation > 3:
            return self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.UNUSUAL_DATA_VOLUME.value, RiskLevel.HIGH.value,
                f"Data volume {volume} bytes deviates {deviation:.1f} sigma from baseline {vol_bl.expected_value:.0f}",
                deviation, vol_bl.expected_value, float(volume),
            )
        return None

    def _check_device_anomaly(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect login from unknown device fingerprint."""
        fp = event.device_fingerprint
        if not fp:
            return None
        events = self._get_profile_events(profile.profile_id, limit=200)
        known_fps = set(e.device_fingerprint for e in events if e.event_id != event.event_id and e.device_fingerprint)
        if known_fps and fp not in known_fps:
            return self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.DEVICE_ANOMALY.value, RiskLevel.MEDIUM.value,
                f"New device fingerprint: {fp[:20]}... (known devices: {len(known_fps)})",
                2.0, float(len(known_fps)), float(len(known_fps) + 1),
            )
        return None

    def _check_failure_rate(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect excessive authentication failures."""
        if event.event_type != EventType.LOGIN_FAILURE.value:
            return None
        events = self._get_profile_events(profile.profile_id, limit=100)
        window = timedelta(minutes=15)
        now = event.timestamp
        recent_failures = [
            e for e in events
            if e.event_type == EventType.LOGIN_FAILURE.value and (now - e.timestamp) < window
        ]
        if len(recent_failures) >= 5:
            return self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.EXCESSIVE_FAILURES.value, RiskLevel.HIGH.value,
                f"{len(recent_failures)} failed logins in 15 minutes",
                float(len(recent_failures)), 5.0, float(len(recent_failures)),
            )
        return None

    def _check_privilege_anomaly(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect unusual privilege escalation or admin actions."""
        if event.event_type not in (EventType.PRIVILEGE_CHANGE.value, EventType.ADMIN_ACTION.value):
            return None
        events = self._get_profile_events(profile.profile_id, limit=200)
        prev_priv_events = [
            e for e in events
            if e.event_id != event.event_id
            and e.event_type in (EventType.PRIVILEGE_CHANGE.value, EventType.ADMIN_ACTION.value)
        ]
        if not prev_priv_events and profile.total_events > 10:
            return self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.PRIVILEGE_ANOMALY.value, RiskLevel.HIGH.value,
                f"First-ever privilege/admin action after {profile.total_events} normal events",
                4.0, 0.0, 1.0,
            )
        return None

    def _check_first_time_access(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect first-time access to a resource."""
        if not event.resource_accessed:
            return None
        events = self._get_profile_events(profile.profile_id, limit=200)
        known_resources = set(
            e.resource_accessed for e in events if e.event_id != event.event_id and e.resource_accessed
        )
        if known_resources and event.resource_accessed not in known_resources and len(known_resources) > 5:
            return self._create_anomaly(
                profile.profile_id, event.event_id,
                AnomalyType.FIRST_TIME_ACCESS.value, RiskLevel.LOW.value,
                f"First access to resource: {event.resource_accessed}",
                1.5, float(len(known_resources)), float(len(known_resources) + 1),
            )
        return None

    def _check_lateral_movement(self, events: List[BehaviorEvent], profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect lateral movement patterns (accessing many distinct hosts quickly)."""
        window = timedelta(minutes=30)
        now = datetime.now(timezone.utc)
        recent = [e for e in events if (now - e.timestamp) < window and e.destination_ip]
        unique_dests = set(e.destination_ip for e in recent)
        if len(unique_dests) >= 10:
            return self._create_anomaly(
                profile.profile_id, events[-1].event_id if events else "",
                AnomalyType.LATERAL_MOVEMENT_PATTERN.value, RiskLevel.CRITICAL.value,
                f"Lateral movement: {len(unique_dests)} unique destinations in 30 min",
                float(len(unique_dests)), 10.0, float(len(unique_dests)),
            )
        return None

    def _check_exfiltration_pattern(self, events: List[BehaviorEvent], profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect data exfiltration patterns (large outbound data volumes)."""
        window = timedelta(hours=1)
        now = datetime.now(timezone.utc)
        recent = [e for e in events if (now - e.timestamp) < window]
        total_bytes = sum(e.metadata.get("bytes_transferred", 0) for e in recent
                         if e.event_type in (EventType.FILE_DOWNLOAD.value, EventType.DATA_EXPORT.value,
                                             EventType.FILE_UPLOAD.value))
        threshold = 500 * 1024 * 1024  # 500 MB
        if total_bytes > threshold:
            return self._create_anomaly(
                profile.profile_id, events[-1].event_id if events else "",
                AnomalyType.EXFILTRATION_PATTERN.value, RiskLevel.CRITICAL.value,
                f"Possible exfiltration: {total_bytes / (1024*1024):.0f} MB transferred in 1 hour",
                float(total_bytes) / threshold, float(threshold), float(total_bytes),
            )
        return None

    def _check_bot_behavior(self, events: List[BehaviorEvent], profile: UserProfile) -> Optional[AnomalyDetection]:
        """Detect inhuman timing patterns (perfectly regular intervals)."""
        if len(events) < 10:
            return None
        sorted_events = sorted(events, key=lambda e: e.timestamp)[-20:]
        intervals = []
        for i in range(1, len(sorted_events)):
            dt = (sorted_events[i].timestamp - sorted_events[i - 1].timestamp).total_seconds()
            if dt > 0:
                intervals.append(dt)
        if len(intervals) < 5:
            return None
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return None
        cv = statistics.pstdev(intervals) / mean_interval if mean_interval > 0 else 1.0
        # Very low coefficient of variation = suspiciously regular
        if cv < 0.05 and mean_interval < 5.0:
            return self._create_anomaly(
                profile.profile_id, events[-1].event_id if events else "",
                AnomalyType.BOT_BEHAVIOR.value, RiskLevel.HIGH.value,
                f"Bot-like behavior: interval CV={cv:.3f}, mean={mean_interval:.2f}s",
                (0.05 - cv) / 0.05 * 5, 0.05, cv,
            )
        return None

    # ── Anomaly Management ───────────────────────────────────────────

    def get_anomalies(
        self,
        profile_id: Optional[str] = None,
        anomaly_type: Optional[str] = None,
        severity: Optional[str] = None,
        confirmed: Optional[bool] = None,
        false_positive: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AnomalyDetection]:
        """Get anomalies with filters."""
        if self.use_db:
            try:
                q = self.db.query(AnomalyDetectionModel)
                if profile_id:
                    q = q.filter_by(profile_id=profile_id)
                if anomaly_type:
                    q = q.filter_by(anomaly_type=anomaly_type)
                if severity:
                    q = q.filter_by(severity=severity)
                if confirmed is not None:
                    q = q.filter_by(is_confirmed=confirmed)
                if false_positive is not None:
                    q = q.filter_by(is_false_positive=false_positive)
                rows = q.order_by(AnomalyDetectionModel.detected_at.desc()).offset(offset).limit(limit).all()
                return [self._row_to_anomaly(r) for r in rows]
            except Exception:
                pass
        anomalies = list(self._anomalies.values())
        if profile_id:
            anomalies = [a for a in anomalies if a.profile_id == profile_id]
        if anomaly_type:
            anomalies = [a for a in anomalies if a.anomaly_type == anomaly_type]
        if severity:
            anomalies = [a for a in anomalies if a.severity == severity]
        if confirmed is not None:
            anomalies = [a for a in anomalies if a.is_confirmed == confirmed]
        if false_positive is not None:
            anomalies = [a for a in anomalies if a.is_false_positive == false_positive]
        anomalies.sort(key=lambda a: a.detected_at, reverse=True)
        return anomalies[offset: offset + limit]

    def confirm_anomaly(self, anomaly_id: str) -> Optional[AnomalyDetection]:
        """Confirm an anomaly as genuine."""
        anomaly = self._anomalies.get(anomaly_id)
        if not anomaly:
            if self.use_db:
                try:
                    row = self.db.query(AnomalyDetectionModel).filter_by(anomaly_id=anomaly_id).first()
                    if row:
                        anomaly = self._row_to_anomaly(row)
                except Exception:
                    pass
        if not anomaly:
            return None
        anomaly.is_confirmed = True
        anomaly.reviewed_at = datetime.now(timezone.utc)
        self._anomalies[anomaly_id] = anomaly
        if self.use_db:
            try:
                row = self.db.query(AnomalyDetectionModel).filter_by(anomaly_id=anomaly_id).first()
                if row:
                    row.is_confirmed = True
                    row.reviewed_at = anomaly.reviewed_at
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for anomaly %s: %s", anomaly_id, exc)
        return anomaly

    def mark_false_positive(self, anomaly_id: str) -> Optional[AnomalyDetection]:
        """Mark anomaly as false positive."""
        anomaly = self._anomalies.get(anomaly_id)
        if not anomaly:
            if self.use_db:
                try:
                    row = self.db.query(AnomalyDetectionModel).filter_by(anomaly_id=anomaly_id).first()
                    if row:
                        anomaly = self._row_to_anomaly(row)
                except Exception:
                    pass
        if not anomaly:
            return None
        anomaly.is_false_positive = True
        anomaly.reviewed_at = datetime.now(timezone.utc)
        self._anomalies[anomaly_id] = anomaly
        if self.use_db:
            try:
                row = self.db.query(AnomalyDetectionModel).filter_by(anomaly_id=anomaly_id).first()
                if row:
                    row.is_false_positive = True
                    row.reviewed_at = anomaly.reviewed_at
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for anomaly %s: %s", anomaly_id, exc)
        return anomaly

    def review_anomaly(self, anomaly_id: str, reviewer: str) -> Optional[AnomalyDetection]:
        """Mark anomaly as reviewed by a person."""
        anomaly = self._anomalies.get(anomaly_id)
        if not anomaly:
            if self.use_db:
                try:
                    row = self.db.query(AnomalyDetectionModel).filter_by(anomaly_id=anomaly_id).first()
                    if row:
                        anomaly = self._row_to_anomaly(row)
                except Exception:
                    pass
        if not anomaly:
            return None
        anomaly.reviewed_at = datetime.now(timezone.utc)
        anomaly.reviewed_by = reviewer
        self._anomalies[anomaly_id] = anomaly
        if self.use_db:
            try:
                row = self.db.query(AnomalyDetectionModel).filter_by(anomaly_id=anomaly_id).first()
                if row:
                    row.reviewed_at = anomaly.reviewed_at
                    row.reviewed_by = reviewer
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for anomaly %s: %s", anomaly_id, exc)
        return anomaly

    # ── Threat Indicators ────────────────────────────────────────────

    def create_indicator(
        self,
        indicator_type: str,
        severity: str = RiskLevel.MEDIUM.value,
        related_profiles: Optional[List[str]] = None,
        related_events: Optional[List[str]] = None,
        ttps: Optional[List[str]] = None,
        confidence: float = 0.5,
        description: str = "",
    ) -> ThreatIndicator:
        """Create a threat indicator."""
        indicator_id = _gen_id("THR")
        now = datetime.now(timezone.utc)
        indicator = ThreatIndicator(
            indicator_id=indicator_id,
            indicator_type=indicator_type,
            related_profiles=related_profiles or [],
            related_events=related_events or [],
            confidence=confidence,
            severity=severity,
            ttps=ttps or [],
            first_seen=now,
            last_seen=now,
            description=description,
        )
        self._threats[indicator_id] = indicator
        if self.use_db:
            try:
                row = ThreatIndicatorModel(
                    indicator_id=indicator.indicator_id,
                    indicator_type=indicator.indicator_type,
                    related_profiles=indicator.related_profiles,
                    related_events=indicator.related_events,
                    confidence=indicator.confidence,
                    severity=indicator.severity,
                    ttps=indicator.ttps,
                    is_active=True,
                    first_seen=now,
                    last_seen=now,
                    description=indicator.description,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for threat %s: %s", indicator_id, exc)
        return indicator

    def get_indicators(
        self,
        indicator_type: Optional[str] = None,
        severity: Optional[str] = None,
        active_only: bool = True,
        limit: int = 100,
    ) -> List[ThreatIndicator]:
        """Get threat indicators."""
        if self.use_db:
            try:
                q = self.db.query(ThreatIndicatorModel)
                if indicator_type:
                    q = q.filter_by(indicator_type=indicator_type)
                if severity:
                    q = q.filter_by(severity=severity)
                if active_only:
                    q = q.filter_by(is_active=True)
                rows = q.order_by(ThreatIndicatorModel.last_seen.desc()).limit(limit).all()
                return [self._row_to_threat(r) for r in rows]
            except Exception:
                pass
        threats = list(self._threats.values())
        if indicator_type:
            threats = [t for t in threats if t.indicator_type == indicator_type]
        if severity:
            threats = [t for t in threats if t.severity == severity]
        if active_only:
            threats = [t for t in threats if t.is_active]
        return threats[:limit]

    def update_indicator(self, indicator_id: str, **kwargs) -> Optional[ThreatIndicator]:
        """Update a threat indicator."""
        indicator = self._threats.get(indicator_id)
        if not indicator:
            return None
        for k, v in kwargs.items():
            if hasattr(indicator, k):
                setattr(indicator, k, v)
        indicator.last_seen = datetime.now(timezone.utc)
        self._threats[indicator_id] = indicator
        if self.use_db:
            try:
                row = self.db.query(ThreatIndicatorModel).filter_by(indicator_id=indicator_id).first()
                if row:
                    for k, v in kwargs.items():
                        if hasattr(row, k):
                            setattr(row, k, v)
                    row.last_seen = indicator.last_seen
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for threat %s: %s", indicator_id, exc)
        return indicator

    def _correlate_anomalies(self) -> List[ThreatIndicator]:
        """Correlate anomalies into threat indicators."""
        indicators_created: List[ThreatIndicator] = []
        anomalies = list(self._anomalies.values())
        if not anomalies:
            return indicators_created

        # Group anomalies by profile
        by_profile: Dict[str, List[AnomalyDetection]] = {}
        for a in anomalies:
            if not a.is_false_positive:
                by_profile.setdefault(a.profile_id, []).append(a)

        for pid, profile_anomalies in by_profile.items():
            # Brute force indicator: many excessive failures
            failures = [a for a in profile_anomalies if a.anomaly_type == AnomalyType.EXCESSIVE_FAILURES.value]
            if len(failures) >= 3:
                ind = self.create_indicator(
                    indicator_type=ThreatIndicatorType.BRUTE_FORCE.value,
                    severity=RiskLevel.HIGH.value,
                    related_profiles=[pid],
                    related_events=[a.event_id for a in failures],
                    ttps=["T1110"],
                    confidence=0.8,
                    description=f"Brute force pattern: {len(failures)} excessive failure anomalies",
                )
                indicators_created.append(ind)

            # Compromised account: impossible travel + new device
            travel = [a for a in profile_anomalies if a.anomaly_type == AnomalyType.IMPOSSIBLE_TRAVEL.value]
            device = [a for a in profile_anomalies if a.anomaly_type == AnomalyType.DEVICE_ANOMALY.value]
            if travel and device:
                ind = self.create_indicator(
                    indicator_type=ThreatIndicatorType.COMPROMISED_ACCOUNT.value,
                    severity=RiskLevel.CRITICAL.value,
                    related_profiles=[pid],
                    related_events=[a.event_id for a in travel + device],
                    ttps=["T1078"],
                    confidence=0.85,
                    description="Possible compromised account: impossible travel + new device",
                )
                indicators_created.append(ind)

            # Data exfiltration
            exfil = [a for a in profile_anomalies if a.anomaly_type == AnomalyType.EXFILTRATION_PATTERN.value]
            if exfil:
                ind = self.create_indicator(
                    indicator_type=ThreatIndicatorType.DATA_EXFILTRATION.value,
                    severity=RiskLevel.CRITICAL.value,
                    related_profiles=[pid],
                    related_events=[a.event_id for a in exfil],
                    ttps=["T1041"],
                    confidence=0.7,
                    description=f"Data exfiltration pattern detected ({len(exfil)} anomalies)",
                )
                indicators_created.append(ind)

            # Lateral movement
            lateral = [a for a in profile_anomalies if a.anomaly_type == AnomalyType.LATERAL_MOVEMENT_PATTERN.value]
            if lateral:
                ind = self.create_indicator(
                    indicator_type=ThreatIndicatorType.LATERAL_MOVEMENT.value,
                    severity=RiskLevel.CRITICAL.value,
                    related_profiles=[pid],
                    related_events=[a.event_id for a in lateral],
                    ttps=["T1021"],
                    confidence=0.75,
                    description=f"Lateral movement detected ({len(lateral)} anomalies)",
                )
                indicators_created.append(ind)

            # Privilege escalation
            priv = [a for a in profile_anomalies if a.anomaly_type == AnomalyType.PRIVILEGE_ANOMALY.value]
            if priv:
                ind = self.create_indicator(
                    indicator_type=ThreatIndicatorType.PRIVILEGE_ESCALATION.value,
                    severity=RiskLevel.HIGH.value,
                    related_profiles=[pid],
                    related_events=[a.event_id for a in priv],
                    ttps=["T1068"],
                    confidence=0.65,
                    description=f"Privilege escalation pattern ({len(priv)} anomalies)",
                )
                indicators_created.append(ind)

            # Bot activity
            bots = [a for a in profile_anomalies if a.anomaly_type == AnomalyType.BOT_BEHAVIOR.value]
            if bots:
                ind = self.create_indicator(
                    indicator_type=ThreatIndicatorType.BOT_ACTIVITY.value,
                    severity=RiskLevel.HIGH.value,
                    related_profiles=[pid],
                    related_events=[a.event_id for a in bots],
                    ttps=["T1059"],
                    confidence=0.7,
                    description=f"Bot activity detected ({len(bots)} anomalies)",
                )
                indicators_created.append(ind)

        return indicators_created

    # ── Risk Scoring ─────────────────────────────────────────────────

    def calculate_risk_score(self, profile_id: str) -> float:
        """
        Calculate weighted composite risk score for a profile.
        Considers anomaly count, severity, recency, and watchlist status.
        """
        profile = self.get_profile(profile_id)
        if not profile:
            return 0.0

        score = 0.0
        anomalies = [a for a in self._anomalies.values() if a.profile_id == profile_id and not a.is_false_positive]

        severity_weights = {
            RiskLevel.CRITICAL.value: 25.0,
            RiskLevel.HIGH.value: 15.0,
            RiskLevel.MEDIUM.value: 8.0,
            RiskLevel.LOW.value: 3.0,
        }

        now = datetime.now(timezone.utc)
        for a in anomalies:
            weight = severity_weights.get(a.severity, 5.0)
            # Decay: recent anomalies weigh more
            age_hours = max((now - a.detected_at).total_seconds() / 3600, 0.1)
            decay = max(0.1, 1.0 / (1.0 + age_hours / 24.0))
            score += weight * decay * a.deviation_score * 0.5

        # Watchlist bonus
        if profile.is_watchlisted:
            score *= 1.2

        # Cap at 100
        score = min(score, 100.0)

        profile.risk_score = round(score, 1)
        profile.risk_level = _risk_level_from_score(score)
        self._profiles[profile_id] = profile
        return score

    def compare_to_peers(self, profile_id: str) -> Dict[str, Any]:
        """Compare a profile's behavior to peers (same entity_type + client)."""
        profile = self.get_profile(profile_id)
        if not profile:
            return {"error": "Profile not found"}
        peers = [
            p for p in self._profiles.values()
            if p.entity_type == profile.entity_type
            and p.client_id == profile.client_id
            and p.profile_id != profile_id
        ]
        if not peers:
            return {
                "profile_id": profile_id,
                "peer_count": 0,
                "message": "No peers found for comparison",
            }
        peer_scores = [p.risk_score for p in peers]
        peer_events = [p.total_events for p in peers]
        peer_anomalies = [p.anomaly_count for p in peers]
        return {
            "profile_id": profile_id,
            "peer_count": len(peers),
            "profile_risk_score": profile.risk_score,
            "peer_avg_risk_score": round(statistics.mean(peer_scores), 1) if peer_scores else 0,
            "peer_max_risk_score": max(peer_scores) if peer_scores else 0,
            "profile_total_events": profile.total_events,
            "peer_avg_events": round(statistics.mean(peer_events), 1) if peer_events else 0,
            "profile_anomaly_count": profile.anomaly_count,
            "peer_avg_anomalies": round(statistics.mean(peer_anomalies), 1) if peer_anomalies else 0,
            "percentile_risk": self._percentile(peer_scores, profile.risk_score),
            "percentile_events": self._percentile(peer_events, profile.total_events),
        }

    # ── Dashboard & Analytics ────────────────────────────────────────

    def get_risk_distribution(self) -> Dict[str, int]:
        """Count profiles by risk level."""
        dist = {rl.value: 0 for rl in RiskLevel}
        for p in self._profiles.values():
            dist[p.risk_level] = dist.get(p.risk_level, 0) + 1
        return dist

    def get_high_risk_entities(self, threshold: float = 60.0) -> List[Dict[str, Any]]:
        """Get entities with risk score above threshold."""
        results = []
        profiles = sorted(self._profiles.values(), key=lambda p: p.risk_score, reverse=True)
        for p in profiles:
            if p.risk_score >= threshold:
                results.append({
                    "profile_id": p.profile_id,
                    "entity_id": p.entity_id,
                    "entity_name": p.entity_name,
                    "entity_type": p.entity_type,
                    "risk_score": p.risk_score,
                    "risk_level": p.risk_level,
                    "anomaly_count": p.anomaly_count,
                    "is_watchlisted": p.is_watchlisted,
                })
        return results

    def get_anomaly_timeline(self, profile_id: str) -> List[Dict[str, Any]]:
        """Get chronological anomaly timeline for a profile."""
        anomalies = [a for a in self._anomalies.values() if a.profile_id == profile_id]
        anomalies.sort(key=lambda a: a.detected_at)
        return [
            {
                "anomaly_id": a.anomaly_id,
                "anomaly_type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "detected_at": a.detected_at.isoformat(),
                "is_confirmed": a.is_confirmed,
                "is_false_positive": a.is_false_positive,
                "deviation_score": a.deviation_score,
            }
            for a in anomalies
        ]

    def get_dashboard(self) -> Dict[str, Any]:
        """Main UEBA dashboard summary."""
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        all_anomalies = list(self._anomalies.values())
        today_anomalies = [a for a in all_anomalies if a.detected_at >= today_start]

        active_threats = [t for t in self._threats.values() if t.is_active]
        top_threats = sorted(active_threats, key=lambda t: t.confidence, reverse=True)[:5]

        high_risk = self.get_high_risk_entities(threshold=60.0)

        return {
            "total_profiles": len(self._profiles),
            "total_events": sum(p.total_events for p in self._profiles.values()),
            "high_risk_count": len(high_risk),
            "watchlisted_count": sum(1 for p in self._profiles.values() if p.is_watchlisted),
            "anomalies_today": len(today_anomalies),
            "anomalies_total": len(all_anomalies),
            "unreviewed_anomalies": len([a for a in all_anomalies if not a.reviewed_at]),
            "false_positive_rate": (
                len([a for a in all_anomalies if a.is_false_positive]) / len(all_anomalies)
                if all_anomalies else 0.0
            ),
            "active_threats": len(active_threats),
            "top_threats": [
                {
                    "indicator_id": t.indicator_id,
                    "type": t.indicator_type,
                    "severity": t.severity,
                    "confidence": t.confidence,
                    "description": t.description,
                }
                for t in top_threats
            ],
            "risk_distribution": self.get_risk_distribution(),
            "entity_type_breakdown": self._entity_type_breakdown(),
        }

    # ── Internal Helpers ─────────────────────────────────────────────

    def _get_profile_events(self, profile_id: str, limit: int = 200) -> List[BehaviorEvent]:
        """Get events for a profile from memory or DB."""
        event_ids = self._profile_events.get(profile_id, [])
        events = [self._events[eid] for eid in event_ids if eid in self._events]
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]

    def _create_baseline(
        self, profile_id: str, metric_name: str,
        expected: float, std_dev: float, sample_count: int,
        time_window: str = TimeWindow.DAILY.value,
    ) -> BehavioralBaseline:
        """Create or update a baseline metric."""
        now = datetime.now(timezone.utc)
        confidence = min(1.0, sample_count / 30.0)
        # Check for existing baseline
        existing_key = None
        for bid, bl in self._baselines.items():
            if bl.profile_id == profile_id and bl.metric_name == metric_name:
                existing_key = bid
                break
        baseline_id = existing_key or _gen_id("BL")
        baseline = BehavioralBaseline(
            baseline_id=baseline_id,
            profile_id=profile_id,
            metric_name=metric_name,
            expected_value=round(expected, 4),
            std_deviation=round(std_dev, 4),
            sample_count=sample_count,
            confidence=round(confidence, 3),
            last_updated=now,
            time_window=time_window,
        )
        self._baselines[baseline_id] = baseline
        if self.use_db:
            try:
                row = self.db.query(BehavioralBaselineModel).filter_by(
                    profile_id=profile_id, metric_name=metric_name
                ).first()
                if row:
                    row.expected_value = baseline.expected_value
                    row.std_deviation = baseline.std_deviation
                    row.sample_count = baseline.sample_count
                    row.confidence = baseline.confidence
                    row.last_updated = now
                else:
                    row = BehavioralBaselineModel(
                        baseline_id=baseline.baseline_id,
                        profile_id=profile_id,
                        metric_name=metric_name,
                        expected_value=baseline.expected_value,
                        std_deviation=baseline.std_deviation,
                        sample_count=baseline.sample_count,
                        confidence=baseline.confidence,
                        last_updated=now,
                        time_window=time_window,
                    )
                    self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for baseline %s: %s", baseline_id, exc)
        return baseline

    def _create_anomaly(
        self, profile_id: str, event_id: str,
        anomaly_type: str, severity: str, description: str,
        deviation_score: float, baseline_value: float, observed_value: float,
    ) -> AnomalyDetection:
        """Create and persist an anomaly detection record."""
        anomaly_id = _gen_id("ANOM")
        now = datetime.now(timezone.utc)
        anomaly = AnomalyDetection(
            anomaly_id=anomaly_id,
            profile_id=profile_id,
            event_id=event_id,
            anomaly_type=anomaly_type,
            severity=severity,
            description=description,
            deviation_score=round(deviation_score, 3),
            baseline_value=round(baseline_value, 3),
            observed_value=round(observed_value, 3),
            detected_at=now,
        )
        self._anomalies[anomaly_id] = anomaly
        if self.use_db:
            try:
                row = AnomalyDetectionModel(
                    anomaly_id=anomaly.anomaly_id,
                    profile_id=profile_id,
                    event_id=event_id,
                    anomaly_type=anomaly_type,
                    severity=severity,
                    description=description,
                    deviation_score=anomaly.deviation_score,
                    baseline_value=anomaly.baseline_value,
                    observed_value=anomaly.observed_value,
                    detected_at=now,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for anomaly %s: %s", anomaly_id, exc)
        return anomaly

    def _sync_profile_to_db(self, profile: UserProfile):
        """Sync profile data to DB."""
        if not self.use_db:
            return
        try:
            row = self.db.query(UserBehaviorProfileModel).filter_by(profile_id=profile.profile_id).first()
            if row:
                row.risk_score = profile.risk_score
                row.risk_level = profile.risk_level
                row.total_events = profile.total_events
                row.anomaly_count = profile.anomaly_count
                row.last_activity_at = profile.last_activity_at
                row.baseline_established = profile.baseline_established
                row.baseline_data = profile.baseline_data
                row.is_watchlisted = profile.is_watchlisted
                row.tags = profile.tags
                self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.warning("DB sync failed for profile %s: %s", profile.profile_id, exc)

    def _entity_type_breakdown(self) -> Dict[str, int]:
        """Count profiles by entity type."""
        breakdown: Dict[str, int] = {}
        for p in self._profiles.values():
            breakdown[p.entity_type] = breakdown.get(p.entity_type, 0) + 1
        return breakdown

    @staticmethod
    def _percentile(values: List[float], target: float) -> float:
        """Calculate what percentile target falls in among values."""
        if not values:
            return 50.0
        below = sum(1 for v in values if v < target)
        return round(below / len(values) * 100, 1)

    # ── ORM Row Converters ───────────────────────────────────────────

    @staticmethod
    def _row_to_profile(row) -> UserProfile:
        return UserProfile(
            profile_id=row.profile_id,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            entity_name=row.entity_name or "",
            client_id=row.client_id or "",
            baseline_established=row.baseline_established or False,
            baseline_data=row.baseline_data or {},
            risk_score=row.risk_score or 0.0,
            risk_level=row.risk_level or RiskLevel.LOW.value,
            total_events=row.total_events or 0,
            anomaly_count=row.anomaly_count or 0,
            last_activity_at=row.last_activity_at,
            first_seen_at=row.first_seen_at or datetime.now(timezone.utc),
            tags=row.tags or [],
            is_watchlisted=row.is_watchlisted or False,
        )

    @staticmethod
    def _row_to_baseline(row) -> BehavioralBaseline:
        return BehavioralBaseline(
            baseline_id=row.baseline_id,
            profile_id=row.profile_id,
            metric_name=row.metric_name,
            expected_value=row.expected_value or 0.0,
            std_deviation=row.std_deviation or 0.0,
            sample_count=row.sample_count or 0,
            confidence=row.confidence or 0.0,
            last_updated=row.last_updated or datetime.now(timezone.utc),
            time_window=row.time_window or TimeWindow.DAILY.value,
        )

    @staticmethod
    def _row_to_anomaly(row) -> AnomalyDetection:
        return AnomalyDetection(
            anomaly_id=row.anomaly_id,
            profile_id=row.profile_id,
            event_id=row.event_id or "",
            anomaly_type=row.anomaly_type,
            severity=row.severity,
            description=row.description or "",
            deviation_score=row.deviation_score or 0.0,
            baseline_value=row.baseline_value or 0.0,
            observed_value=row.observed_value or 0.0,
            is_confirmed=row.is_confirmed or False,
            is_false_positive=row.is_false_positive or False,
            auto_response_taken=row.auto_response_taken or [],
            detected_at=row.detected_at or datetime.now(timezone.utc),
            reviewed_at=row.reviewed_at,
            reviewed_by=row.reviewed_by or "",
        )

    @staticmethod
    def _row_to_threat(row) -> ThreatIndicator:
        return ThreatIndicator(
            indicator_id=row.indicator_id,
            indicator_type=row.indicator_type,
            related_profiles=row.related_profiles or [],
            related_events=row.related_events or [],
            confidence=row.confidence or 0.0,
            severity=row.severity,
            ttps=row.ttps or [],
            is_active=row.is_active if row.is_active is not None else True,
            first_seen=row.first_seen or datetime.now(timezone.utc),
            last_seen=row.last_seen or datetime.now(timezone.utc),
            description=row.description or "",
        )
