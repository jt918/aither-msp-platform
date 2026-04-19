"""
AITHER Platform - IP & Entity Threat Scoring Service
Real-time trust/threat scoring engine for IPs, users, devices, domains, emails.

Every entity gets a TRUST SCORE (0-100, higher=more trusted) and
THREAT SCORE (0-100, higher=more dangerous).  Scores decay toward
neutral (50) over time.  Pre-built thresholds trigger auto-actions
(alert, rate-limit, block, isolate, honeypot redirect).

DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.threat_scoring import (
        EntityScoreModel,
        ScoreEventModel,
        ScoreThresholdModel,
        ReputationFeedModel,
        ScoreHistoryModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ── Enums ─────────────────────────────────────────────────────────────

class EntityType(str, Enum):
    IP_ADDRESS = "ip_address"
    USER = "user"
    DEVICE = "device"
    DOMAIN = "domain"
    EMAIL = "email"
    URL = "url"
    HASH = "hash"


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKED = "blocked"


class AutoAction(str, Enum):
    NONE = "none"
    ALERT = "alert"
    RATE_LIMIT = "rate_limit"
    CAPTCHA = "captcha"
    BLOCK = "block"
    ISOLATE = "isolate"
    HONEYPOT_REDIRECT = "honeypot_redirect"


# ── Dataclasses ───────────────────────────────────────────────────────

@dataclass
class ScoreFactor:
    factor_name: str
    factor_weight: float
    factor_value: float
    description: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = ""


@dataclass
class EntityScore:
    score_id: str
    entity_type: EntityType
    entity_value: str
    trust_score: float = 50.0
    threat_score: float = 50.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    score_factors: List[ScoreFactor] = field(default_factory=list)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_events: int = 0
    positive_events: int = 0
    negative_events: int = 0
    is_whitelisted: bool = False
    is_blacklisted: bool = False
    auto_block_triggered: bool = False
    geo_data: Dict[str, Any] = field(default_factory=dict)
    decay_rate: float = 1.0


@dataclass
class ScoreEvent:
    event_id: str
    entity_value: str
    entity_type: EntityType
    event_type: str  # positive / negative / neutral
    impact_points: float
    reason: str = ""
    source_service: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ScoreThreshold:
    threshold_id: str
    name: str
    risk_level: RiskLevel
    trust_score_min: float = 0.0
    trust_score_max: float = 100.0
    threat_score_min: float = 0.0
    threat_score_max: float = 100.0
    auto_action: AutoAction = AutoAction.NONE
    notification_channel: str = ""


@dataclass
class ReputationFeed:
    feed_id: str
    name: str
    feed_type: str  # blocklist / allowlist / reputation
    source_url: str = ""
    format: str = "plaintext"
    last_updated: Optional[datetime] = None
    entries_count: int = 0
    is_enabled: bool = True
    update_interval_hours: int = 24


@dataclass
class ScoreHistory:
    history_id: str
    entity_value: str
    trust_score: float = 50.0
    threat_score: float = 50.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    snapshot_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Positive / Negative factor presets ────────────────────────────────

POSITIVE_FACTORS: Dict[str, float] = {
    "successful_auth": 2,
    "whitelisted": 20,
    "known_device": 5,
    "domestic_ip": 3,
    "passed_mfa": 5,
    "regular_hours": 1,
    "consistent_behavior": 3,
    "long_history": 5,
}

NEGATIVE_FACTORS: Dict[str, float] = {
    "failed_auth": -5,
    "multiple_fails_5min": -25,
    "new_ip": -3,
    "foreign_ip": -10,
    "tor_exit": -30,
    "known_vpn_proxy": -15,
    "blacklisted": -50,
    "port_scan": -20,
    "brute_force": -40,
    "sqli_attempt": -50,
    "xss_attempt": -35,
    "dir_traversal": -30,
    "suspicious_ua": -10,
    "impossible_travel": -25,
    "exfiltration_pattern": -45,
    "malware_comm": -50,
    "bot_behavior": -20,
}

# ── Default thresholds ────────────────────────────────────────────────

DEFAULT_THRESHOLDS: List[Dict[str, Any]] = [
    {"name": "Safe", "risk_level": "safe", "trust_min": 80, "trust_max": 100,
     "threat_min": 0, "threat_max": 20, "action": "none"},
    {"name": "Low", "risk_level": "low", "trust_min": 60, "trust_max": 79,
     "threat_min": 21, "threat_max": 40, "action": "none"},
    {"name": "Medium", "risk_level": "medium", "trust_min": 40, "trust_max": 59,
     "threat_min": 41, "threat_max": 60, "action": "alert"},
    {"name": "High", "risk_level": "high", "trust_min": 20, "trust_max": 39,
     "threat_min": 61, "threat_max": 80, "action": "rate_limit"},
    {"name": "Critical", "risk_level": "critical", "trust_min": 0, "trust_max": 19,
     "threat_min": 81, "threat_max": 95, "action": "block"},
    {"name": "Blocked", "risk_level": "blocked", "trust_min": 0, "trust_max": 0,
     "threat_min": 96, "threat_max": 100, "action": "isolate"},
]


# ══════════════════════════════════════════════════════════════════════
# Service
# ══════════════════════════════════════════════════════════════════════

class ThreatScoringService:
    """Real-time IP & Entity Threat Scoring engine."""

    def __init__(self, db: "Session | None" = None):
        self.db = db
        self.use_db = db is not None and ORM_AVAILABLE
        # In-memory fallback stores
        self._scores: Dict[str, EntityScore] = {}
        self._events: List[ScoreEvent] = []
        self._thresholds: Dict[str, ScoreThreshold] = {}
        self._feeds: Dict[str, ReputationFeed] = {}
        self._history: List[ScoreHistory] = []
        self._init_default_thresholds()
        logger.info("ThreatScoringService initialized (db=%s)", self.use_db)

    # ── Bootstrap ─────────────────────────────────────────────────────

    def _init_default_thresholds(self):
        """Seed default thresholds if none exist."""
        existing = self.get_thresholds()
        if existing:
            return
        for t in DEFAULT_THRESHOLDS:
            self.create_threshold(
                name=t["name"],
                risk_level=t["risk_level"],
                trust_score_min=t["trust_min"],
                trust_score_max=t["trust_max"],
                threat_score_min=t["threat_min"],
                threat_score_max=t["threat_max"],
                auto_action=t["action"],
            )

    # ══════════════════════════════════════════════════════════════════
    # SCORING
    # ══════════════════════════════════════════════════════════════════

    def score_event(
        self,
        entity_type: str,
        entity_value: str,
        event_type: str,
        impact_points: float,
        reason: str = "",
        source: str = "",
        raw_data: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Record a scoring event and recalculate entity score."""
        ev = ScoreEvent(
            event_id=str(uuid.uuid4()),
            entity_value=entity_value,
            entity_type=EntityType(entity_type),
            event_type=event_type,
            impact_points=impact_points,
            reason=reason,
            source_service=source,
            raw_data=raw_data or {},
        )
        # Persist event
        if self.use_db:
            try:
                row = ScoreEventModel(
                    event_id=ev.event_id,
                    entity_value=ev.entity_value,
                    entity_type=ev.entity_type.value,
                    event_type=ev.event_type,
                    impact_points=ev.impact_points,
                    reason=ev.reason,
                    source_service=ev.source_service,
                    raw_data=ev.raw_data,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB event write failed: %s", exc)
        self._events.append(ev)

        # Ensure entity exists
        entity = self._get_or_create_entity(entity_type, entity_value)

        # Update counters
        entity.total_events += 1
        if event_type == "positive":
            entity.positive_events += 1
        elif event_type == "negative":
            entity.negative_events += 1
        entity.last_seen = datetime.now(timezone.utc)

        # Add factor
        factor = ScoreFactor(
            factor_name=reason or event_type,
            factor_weight=abs(impact_points),
            factor_value=impact_points,
            description=reason,
            source=source,
        )
        entity.score_factors.append(factor)
        # Keep last 100 factors
        if len(entity.score_factors) > 100:
            entity.score_factors = entity.score_factors[-100:]

        # Recalculate
        self._recalculate_score(entity)
        threshold = self._check_thresholds(entity)
        if threshold:
            self._execute_auto_action(entity, threshold)

        # Persist entity
        self._save_entity(entity)

        return {
            "event_id": ev.event_id,
            "entity_value": entity_value,
            "trust_score": entity.trust_score,
            "threat_score": entity.threat_score,
            "risk_level": entity.risk_level.value if isinstance(entity.risk_level, RiskLevel) else entity.risk_level,
            "auto_action_triggered": threshold.auto_action.value if threshold else "none",
        }

    def score_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process multiple scoring events at once."""
        results = []
        for ev in events:
            result = self.score_event(
                entity_type=ev.get("entity_type", "ip_address"),
                entity_value=ev.get("entity_value", ""),
                event_type=ev.get("event_type", "neutral"),
                impact_points=ev.get("impact_points", 0),
                reason=ev.get("reason", ""),
                source=ev.get("source", ""),
                raw_data=ev.get("raw_data"),
            )
            results.append(result)
        return results

    # ══════════════════════════════════════════════════════════════════
    # ENTITY CRUD
    # ══════════════════════════════════════════════════════════════════

    def _get_or_create_entity(self, entity_type: str, entity_value: str) -> EntityScore:
        """Fetch existing entity or create new one."""
        key = f"{entity_type}::{entity_value}"
        if key in self._scores:
            return self._scores[key]
        # Try DB
        if self.use_db:
            try:
                row = (
                    self.db.query(EntityScoreModel)
                    .filter_by(entity_type=entity_type, entity_value=entity_value)
                    .first()
                )
                if row:
                    es = self._model_to_entity(row)
                    self._scores[key] = es
                    return es
            except Exception as exc:
                logger.warning("DB entity lookup failed: %s", exc)
        # Create new
        es = EntityScore(
            score_id=str(uuid.uuid4()),
            entity_type=EntityType(entity_type),
            entity_value=entity_value,
        )
        self._scores[key] = es
        return es

    def _model_to_entity(self, row: "EntityScoreModel") -> EntityScore:
        factors = []
        for f in (row.score_factors or []):
            factors.append(ScoreFactor(
                factor_name=f.get("factor_name", ""),
                factor_weight=f.get("factor_weight", 0),
                factor_value=f.get("factor_value", 0),
                description=f.get("description", ""),
                source=f.get("source", ""),
            ))
        return EntityScore(
            score_id=row.score_id,
            entity_type=EntityType(row.entity_type),
            entity_value=row.entity_value,
            trust_score=row.trust_score,
            threat_score=row.threat_score,
            risk_level=RiskLevel(row.risk_level),
            score_factors=factors,
            first_seen=row.first_seen or datetime.now(timezone.utc),
            last_seen=row.last_seen or datetime.now(timezone.utc),
            last_updated=row.last_updated or datetime.now(timezone.utc),
            total_events=row.total_events,
            positive_events=row.positive_events,
            negative_events=row.negative_events,
            is_whitelisted=row.is_whitelisted,
            is_blacklisted=row.is_blacklisted,
            auto_block_triggered=row.auto_block_triggered,
            geo_data=row.geo_data or {},
            decay_rate=row.decay_rate,
        )

    def _entity_to_dict(self, es: EntityScore) -> Dict[str, Any]:
        return {
            "score_id": es.score_id,
            "entity_type": es.entity_type.value if isinstance(es.entity_type, EntityType) else es.entity_type,
            "entity_value": es.entity_value,
            "trust_score": round(es.trust_score, 2),
            "threat_score": round(es.threat_score, 2),
            "risk_level": es.risk_level.value if isinstance(es.risk_level, RiskLevel) else es.risk_level,
            "first_seen": es.first_seen.isoformat() if es.first_seen else None,
            "last_seen": es.last_seen.isoformat() if es.last_seen else None,
            "last_updated": es.last_updated.isoformat() if es.last_updated else None,
            "total_events": es.total_events,
            "positive_events": es.positive_events,
            "negative_events": es.negative_events,
            "is_whitelisted": es.is_whitelisted,
            "is_blacklisted": es.is_blacklisted,
            "auto_block_triggered": es.auto_block_triggered,
            "geo_data": es.geo_data,
            "decay_rate": es.decay_rate,
            "recent_factors": [
                {
                    "factor_name": f.factor_name,
                    "factor_value": f.factor_value,
                    "description": f.description,
                    "source": f.source,
                    "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                }
                for f in (es.score_factors[-10:] if es.score_factors else [])
            ],
        }

    def _save_entity(self, es: EntityScore):
        """Persist entity to DB."""
        key = f"{es.entity_type.value if isinstance(es.entity_type, EntityType) else es.entity_type}::{es.entity_value}"
        self._scores[key] = es
        if not self.use_db:
            return
        try:
            etype = es.entity_type.value if isinstance(es.entity_type, EntityType) else es.entity_type
            rlevel = es.risk_level.value if isinstance(es.risk_level, RiskLevel) else es.risk_level
            row = (
                self.db.query(EntityScoreModel)
                .filter_by(entity_type=etype, entity_value=es.entity_value)
                .first()
            )
            factors_json = [
                {
                    "factor_name": f.factor_name,
                    "factor_weight": f.factor_weight,
                    "factor_value": f.factor_value,
                    "description": f.description,
                    "source": f.source,
                }
                for f in (es.score_factors[-50:] if es.score_factors else [])
            ]
            if row:
                row.trust_score = es.trust_score
                row.threat_score = es.threat_score
                row.risk_level = rlevel
                row.score_factors = factors_json
                row.last_seen = es.last_seen
                row.total_events = es.total_events
                row.positive_events = es.positive_events
                row.negative_events = es.negative_events
                row.is_whitelisted = es.is_whitelisted
                row.is_blacklisted = es.is_blacklisted
                row.auto_block_triggered = es.auto_block_triggered
                row.geo_data = es.geo_data
                row.decay_rate = es.decay_rate
            else:
                row = EntityScoreModel(
                    score_id=es.score_id,
                    entity_type=etype,
                    entity_value=es.entity_value,
                    trust_score=es.trust_score,
                    threat_score=es.threat_score,
                    risk_level=rlevel,
                    score_factors=factors_json,
                    first_seen=es.first_seen,
                    last_seen=es.last_seen,
                    total_events=es.total_events,
                    positive_events=es.positive_events,
                    negative_events=es.negative_events,
                    is_whitelisted=es.is_whitelisted,
                    is_blacklisted=es.is_blacklisted,
                    auto_block_triggered=es.auto_block_triggered,
                    geo_data=es.geo_data,
                    decay_rate=es.decay_rate,
                )
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.warning("DB entity save failed: %s", exc)

    # ══════════════════════════════════════════════════════════════════
    # SCORE CALCULATION
    # ══════════════════════════════════════════════════════════════════

    def _recalculate_score(self, entity: EntityScore):
        """Recompute trust/threat from accumulated factors, then classify."""
        trust = 50.0
        threat = 50.0
        for f in entity.score_factors:
            if f.factor_value > 0:
                trust += f.factor_value
                threat -= f.factor_value * 0.5
            else:
                trust += f.factor_value  # negative = reduces trust
                threat -= f.factor_value  # double negative = increases threat

        # Apply whitelist / blacklist overrides
        if entity.is_whitelisted:
            trust = max(trust, 90.0)
            threat = min(threat, 10.0)
        if entity.is_blacklisted:
            trust = 0.0
            threat = 100.0

        # Clamp
        entity.trust_score = max(0.0, min(100.0, trust))
        entity.threat_score = max(0.0, min(100.0, threat))
        entity.last_updated = datetime.now(timezone.utc)

        # Classify risk level
        entity.risk_level = self._classify_risk(entity.trust_score, entity.threat_score)

    def _classify_risk(self, trust: float, threat: float) -> RiskLevel:
        """Determine risk level from scores."""
        if trust >= 80 and threat <= 20:
            return RiskLevel.SAFE
        elif trust >= 60 and threat <= 40:
            return RiskLevel.LOW
        elif trust >= 40 and threat <= 60:
            return RiskLevel.MEDIUM
        elif trust >= 20 and threat <= 80:
            return RiskLevel.HIGH
        elif threat >= 96:
            return RiskLevel.BLOCKED
        else:
            return RiskLevel.CRITICAL

    def _apply_decay(self):
        """Decay all scores toward neutral (50) by decay_rate per hour."""
        now = datetime.now(timezone.utc)
        entities = list(self._scores.values())
        for entity in entities:
            if entity.last_updated:
                hours_elapsed = (now - entity.last_updated).total_seconds() / 3600.0
                if hours_elapsed < 0.1:
                    continue
                decay = entity.decay_rate * hours_elapsed
                if entity.trust_score > 50:
                    entity.trust_score = max(50.0, entity.trust_score - decay)
                elif entity.trust_score < 50:
                    entity.trust_score = min(50.0, entity.trust_score + decay)
                if entity.threat_score > 50:
                    entity.threat_score = max(50.0, entity.threat_score - decay)
                elif entity.threat_score < 50:
                    entity.threat_score = min(50.0, entity.threat_score + decay)
                entity.risk_level = self._classify_risk(entity.trust_score, entity.threat_score)
                entity.last_updated = now

    def _check_thresholds(self, entity: EntityScore) -> Optional[ScoreThreshold]:
        """Find matching threshold for entity and return it if auto-action needed."""
        for t in self._thresholds.values():
            if (
                t.trust_score_min <= entity.trust_score <= t.trust_score_max
                and t.threat_score_min <= entity.threat_score <= t.threat_score_max
                and t.auto_action != AutoAction.NONE
            ):
                return t
        return None

    def _execute_auto_action(self, entity: EntityScore, threshold: ScoreThreshold):
        """Execute the auto-action defined by a threshold."""
        action = threshold.auto_action
        etype = entity.entity_type.value if isinstance(entity.entity_type, EntityType) else entity.entity_type
        logger.warning(
            "AUTO-ACTION %s on %s %s (trust=%.1f, threat=%.1f, level=%s)",
            action.value if isinstance(action, AutoAction) else action,
            etype,
            entity.entity_value,
            entity.trust_score,
            entity.threat_score,
            entity.risk_level.value if isinstance(entity.risk_level, RiskLevel) else entity.risk_level,
        )
        if action in (AutoAction.BLOCK, AutoAction.ISOLATE):
            entity.auto_block_triggered = True

        # Record snapshot
        self._record_history(entity)

    # ══════════════════════════════════════════════════════════════════
    # READ
    # ══════════════════════════════════════════════════════════════════

    def get_score(self, entity_type: str, entity_value: str) -> Optional[Dict[str, Any]]:
        """Get current score for an entity."""
        key = f"{entity_type}::{entity_value}"
        if key in self._scores:
            return self._entity_to_dict(self._scores[key])
        if self.use_db:
            try:
                row = (
                    self.db.query(EntityScoreModel)
                    .filter_by(entity_type=entity_type, entity_value=entity_value)
                    .first()
                )
                if row:
                    es = self._model_to_entity(row)
                    self._scores[key] = es
                    return self._entity_to_dict(es)
            except Exception as exc:
                logger.warning("DB get_score failed: %s", exc)
        return None

    def get_scores(
        self,
        entity_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        is_blacklisted: Optional[bool] = None,
        min_threat: Optional[float] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get filtered list of entity scores."""
        if self.use_db:
            try:
                q = self.db.query(EntityScoreModel)
                if entity_type:
                    q = q.filter(EntityScoreModel.entity_type == entity_type)
                if risk_level:
                    q = q.filter(EntityScoreModel.risk_level == risk_level)
                if is_blacklisted is not None:
                    q = q.filter(EntityScoreModel.is_blacklisted == is_blacklisted)
                if min_threat is not None:
                    q = q.filter(EntityScoreModel.threat_score >= min_threat)
                total = q.count()
                rows = q.order_by(EntityScoreModel.threat_score.desc()).offset(offset).limit(limit).all()
                return {
                    "entities": [self._entity_to_dict(self._model_to_entity(r)) for r in rows],
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                }
            except Exception as exc:
                logger.warning("DB get_scores failed: %s", exc)

        # Fallback: in-memory
        entities = list(self._scores.values())
        if entity_type:
            entities = [e for e in entities if (e.entity_type.value if isinstance(e.entity_type, EntityType) else e.entity_type) == entity_type]
        if risk_level:
            entities = [e for e in entities if (e.risk_level.value if isinstance(e.risk_level, RiskLevel) else e.risk_level) == risk_level]
        if is_blacklisted is not None:
            entities = [e for e in entities if e.is_blacklisted == is_blacklisted]
        if min_threat is not None:
            entities = [e for e in entities if e.threat_score >= min_threat]
        entities.sort(key=lambda e: e.threat_score, reverse=True)
        total = len(entities)
        page = entities[offset: offset + limit]
        return {
            "entities": [self._entity_to_dict(e) for e in page],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def get_score_history(
        self,
        entity_value: str,
        period_hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """Get score history snapshots for an entity."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=period_hours)
        if self.use_db:
            try:
                rows = (
                    self.db.query(ScoreHistoryModel)
                    .filter(
                        ScoreHistoryModel.entity_value == entity_value,
                        ScoreHistoryModel.snapshot_at >= cutoff,
                    )
                    .order_by(ScoreHistoryModel.snapshot_at.asc())
                    .all()
                )
                return [
                    {
                        "history_id": r.history_id,
                        "entity_value": r.entity_value,
                        "trust_score": r.trust_score,
                        "threat_score": r.threat_score,
                        "risk_level": r.risk_level,
                        "snapshot_at": r.snapshot_at.isoformat() if r.snapshot_at else None,
                    }
                    for r in rows
                ]
            except Exception as exc:
                logger.warning("DB get_score_history failed: %s", exc)
        # Fallback
        return [
            {
                "history_id": h.history_id,
                "entity_value": h.entity_value,
                "trust_score": h.trust_score,
                "threat_score": h.threat_score,
                "risk_level": h.risk_level.value if isinstance(h.risk_level, RiskLevel) else h.risk_level,
                "snapshot_at": h.snapshot_at.isoformat() if h.snapshot_at else None,
            }
            for h in self._history
            if h.entity_value == entity_value and h.snapshot_at >= cutoff
        ]

    def _record_history(self, entity: EntityScore):
        """Take a score snapshot."""
        h = ScoreHistory(
            history_id=str(uuid.uuid4()),
            entity_value=entity.entity_value,
            trust_score=entity.trust_score,
            threat_score=entity.threat_score,
            risk_level=entity.risk_level,
            snapshot_at=datetime.now(timezone.utc),
        )
        self._history.append(h)
        if self.use_db:
            try:
                rlevel = h.risk_level.value if isinstance(h.risk_level, RiskLevel) else h.risk_level
                row = ScoreHistoryModel(
                    history_id=h.history_id,
                    entity_value=h.entity_value,
                    trust_score=h.trust_score,
                    threat_score=h.threat_score,
                    risk_level=rlevel,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB history save failed: %s", exc)

    # ══════════════════════════════════════════════════════════════════
    # WHITELIST / BLACKLIST
    # ══════════════════════════════════════════════════════════════════

    def whitelist_entity(self, entity_type: str, entity_value: str, reason: str = "") -> Dict[str, Any]:
        """Add entity to whitelist and boost trust."""
        entity = self._get_or_create_entity(entity_type, entity_value)
        entity.is_whitelisted = True
        entity.is_blacklisted = False
        entity.auto_block_triggered = False
        self.score_event(entity_type, entity_value, "positive", POSITIVE_FACTORS["whitelisted"], reason=reason or "Whitelisted", source="admin")
        return self._entity_to_dict(entity)

    def blacklist_entity(self, entity_type: str, entity_value: str, reason: str = "") -> Dict[str, Any]:
        """Add entity to blacklist and set threat to max."""
        entity = self._get_or_create_entity(entity_type, entity_value)
        entity.is_blacklisted = True
        entity.is_whitelisted = False
        self.score_event(entity_type, entity_value, "negative", NEGATIVE_FACTORS["blacklisted"], reason=reason or "Blacklisted", source="admin")
        return self._entity_to_dict(entity)

    def remove_from_list(self, entity_value: str) -> Dict[str, Any]:
        """Remove entity from both whitelist and blacklist."""
        for key, entity in self._scores.items():
            if entity.entity_value == entity_value:
                entity.is_whitelisted = False
                entity.is_blacklisted = False
                entity.auto_block_triggered = False
                self._recalculate_score(entity)
                self._save_entity(entity)
                return self._entity_to_dict(entity)
        return {"status": "not_found", "entity_value": entity_value}

    # ══════════════════════════════════════════════════════════════════
    # THRESHOLD CRUD
    # ══════════════════════════════════════════════════════════════════

    def create_threshold(
        self,
        name: str,
        risk_level: str,
        trust_score_min: float = 0,
        trust_score_max: float = 100,
        threat_score_min: float = 0,
        threat_score_max: float = 100,
        auto_action: str = "none",
        notification_channel: str = "",
    ) -> Dict[str, Any]:
        tid = str(uuid.uuid4())
        t = ScoreThreshold(
            threshold_id=tid,
            name=name,
            risk_level=RiskLevel(risk_level),
            trust_score_min=trust_score_min,
            trust_score_max=trust_score_max,
            threat_score_min=threat_score_min,
            threat_score_max=threat_score_max,
            auto_action=AutoAction(auto_action),
            notification_channel=notification_channel,
        )
        self._thresholds[tid] = t
        if self.use_db:
            try:
                row = ScoreThresholdModel(
                    threshold_id=tid,
                    name=name,
                    risk_level=risk_level,
                    trust_score_min=trust_score_min,
                    trust_score_max=trust_score_max,
                    threat_score_min=threat_score_min,
                    threat_score_max=threat_score_max,
                    auto_action=auto_action,
                    notification_channel=notification_channel,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB threshold create failed: %s", exc)
        return self._threshold_to_dict(t)

    def get_thresholds(self) -> List[Dict[str, Any]]:
        if self._thresholds:
            return [self._threshold_to_dict(t) for t in self._thresholds.values()]
        if self.use_db:
            try:
                rows = self.db.query(ScoreThresholdModel).all()
                for r in rows:
                    t = ScoreThreshold(
                        threshold_id=r.threshold_id,
                        name=r.name,
                        risk_level=RiskLevel(r.risk_level),
                        trust_score_min=r.trust_score_min,
                        trust_score_max=r.trust_score_max,
                        threat_score_min=r.threat_score_min,
                        threat_score_max=r.threat_score_max,
                        auto_action=AutoAction(r.auto_action),
                        notification_channel=r.notification_channel or "",
                    )
                    self._thresholds[r.threshold_id] = t
                return [self._threshold_to_dict(t) for t in self._thresholds.values()]
            except Exception as exc:
                logger.warning("DB threshold load failed: %s", exc)
        return []

    def update_threshold(self, threshold_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        t = self._thresholds.get(threshold_id)
        if not t:
            return None
        for k, v in updates.items():
            if k == "risk_level":
                t.risk_level = RiskLevel(v)
            elif k == "auto_action":
                t.auto_action = AutoAction(v)
            elif hasattr(t, k):
                setattr(t, k, v)
        if self.use_db:
            try:
                row = self.db.query(ScoreThresholdModel).filter_by(threshold_id=threshold_id).first()
                if row:
                    for k, v in updates.items():
                        if hasattr(row, k):
                            setattr(row, k, v)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB threshold update failed: %s", exc)
        return self._threshold_to_dict(t)

    def delete_threshold(self, threshold_id: str) -> bool:
        if threshold_id in self._thresholds:
            del self._thresholds[threshold_id]
        if self.use_db:
            try:
                self.db.query(ScoreThresholdModel).filter_by(threshold_id=threshold_id).delete()
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB threshold delete failed: %s", exc)
        return True

    def _threshold_to_dict(self, t: ScoreThreshold) -> Dict[str, Any]:
        return {
            "threshold_id": t.threshold_id,
            "name": t.name,
            "risk_level": t.risk_level.value if isinstance(t.risk_level, RiskLevel) else t.risk_level,
            "trust_score_min": t.trust_score_min,
            "trust_score_max": t.trust_score_max,
            "threat_score_min": t.threat_score_min,
            "threat_score_max": t.threat_score_max,
            "auto_action": t.auto_action.value if isinstance(t.auto_action, AutoAction) else t.auto_action,
            "notification_channel": t.notification_channel,
        }

    # ══════════════════════════════════════════════════════════════════
    # REPUTATION FEEDS
    # ══════════════════════════════════════════════════════════════════

    def register_feed(
        self,
        name: str,
        feed_type: str,
        source_url: str = "",
        format: str = "plaintext",
        update_interval_hours: int = 24,
    ) -> Dict[str, Any]:
        fid = str(uuid.uuid4())
        feed = ReputationFeed(
            feed_id=fid, name=name, feed_type=feed_type,
            source_url=source_url, format=format,
            update_interval_hours=update_interval_hours,
        )
        self._feeds[fid] = feed
        if self.use_db:
            try:
                row = ReputationFeedModel(
                    feed_id=fid, name=name, feed_type=feed_type,
                    source_url=source_url, format=format,
                    update_interval_hours=update_interval_hours,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB feed register failed: %s", exc)
        return self._feed_to_dict(feed)

    def pull_feed(self, feed_id: str) -> Dict[str, Any]:
        """Pull and import a reputation feed (stub -- real implementation would HTTP-fetch)."""
        feed = self._feeds.get(feed_id)
        if not feed:
            return {"error": "Feed not found"}
        # In production this would fetch source_url and parse entries
        feed.last_updated = datetime.now(timezone.utc)
        logger.info("Pull feed %s (%s) -- stub, no live fetch", feed.name, feed.source_url)
        return {
            "feed_id": feed_id,
            "name": feed.name,
            "status": "pulled",
            "entries_imported": 0,
            "last_updated": feed.last_updated.isoformat(),
        }

    def pull_all_feeds(self) -> List[Dict[str, Any]]:
        results = []
        for fid in list(self._feeds.keys()):
            results.append(self.pull_feed(fid))
        return results

    def list_feeds(self) -> List[Dict[str, Any]]:
        if not self._feeds and self.use_db:
            try:
                rows = self.db.query(ReputationFeedModel).all()
                for r in rows:
                    self._feeds[r.feed_id] = ReputationFeed(
                        feed_id=r.feed_id, name=r.name, feed_type=r.feed_type,
                        source_url=r.source_url or "", format=r.format or "plaintext",
                        last_updated=r.last_updated, entries_count=r.entries_count,
                        is_enabled=r.is_enabled, update_interval_hours=r.update_interval_hours,
                    )
            except Exception as exc:
                logger.warning("DB feed list failed: %s", exc)
        return [self._feed_to_dict(f) for f in self._feeds.values()]

    def _import_blocklist(self, feed: ReputationFeed, entries: List[str]):
        """Import a list of IPs/domains from a blocklist feed."""
        for entry in entries:
            entry = entry.strip()
            if not entry or entry.startswith("#"):
                continue
            entity_type = "domain" if "." in entry and not entry[0].isdigit() else "ip_address"
            self.blacklist_entity(entity_type, entry, reason=f"Feed: {feed.name}")
        feed.entries_count = len(entries)
        feed.last_updated = datetime.now(timezone.utc)

    def _feed_to_dict(self, f: ReputationFeed) -> Dict[str, Any]:
        return {
            "feed_id": f.feed_id,
            "name": f.name,
            "feed_type": f.feed_type,
            "source_url": f.source_url,
            "format": f.format,
            "last_updated": f.last_updated.isoformat() if f.last_updated else None,
            "entries_count": f.entries_count,
            "is_enabled": f.is_enabled,
            "update_interval_hours": f.update_interval_hours,
        }

    # ══════════════════════════════════════════════════════════════════
    # ANALYTICS
    # ══════════════════════════════════════════════════════════════════

    def get_risk_distribution(self) -> Dict[str, int]:
        """Count entities per risk level."""
        dist: Dict[str, int] = {r.value: 0 for r in RiskLevel}
        entities = self._all_entities()
        for e in entities:
            rl = e.risk_level.value if isinstance(e.risk_level, RiskLevel) else e.risk_level
            dist[rl] = dist.get(rl, 0) + 1
        return dist

    def get_top_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return top N entities by threat score."""
        entities = self._all_entities()
        entities.sort(key=lambda e: e.threat_score, reverse=True)
        return [self._entity_to_dict(e) for e in entities[:limit]]

    def get_score_trends(self, period_hours: int = 24) -> Dict[str, Any]:
        """Aggregate score trends over a period."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=period_hours)
        recent_events = [e for e in self._events if e.timestamp >= cutoff]
        positive = sum(1 for e in recent_events if e.event_type == "positive")
        negative = sum(1 for e in recent_events if e.event_type == "negative")
        neutral = sum(1 for e in recent_events if e.event_type == "neutral")
        return {
            "period_hours": period_hours,
            "total_events": len(recent_events),
            "positive_events": positive,
            "negative_events": negative,
            "neutral_events": neutral,
            "threat_ratio": round(negative / max(len(recent_events), 1), 3),
        }

    def get_geographic_threat_map(self) -> List[Dict[str, Any]]:
        """Group threats by geo location."""
        geo_map: Dict[str, Dict[str, Any]] = {}
        for e in self._all_entities():
            country = (e.geo_data or {}).get("country", "Unknown")
            if country not in geo_map:
                geo_map[country] = {"country": country, "count": 0, "avg_threat": 0, "total_threat": 0}
            geo_map[country]["count"] += 1
            geo_map[country]["total_threat"] += e.threat_score
        for v in geo_map.values():
            v["avg_threat"] = round(v["total_threat"] / max(v["count"], 1), 2)
            del v["total_threat"]
        return sorted(geo_map.values(), key=lambda x: x["avg_threat"], reverse=True)

    def get_network_posture(self) -> Dict[str, Any]:
        """Overall network security posture summary."""
        entities = self._all_entities()
        total = len(entities)
        if total == 0:
            return {
                "total_entities": 0,
                "avg_trust": 50.0,
                "avg_threat": 50.0,
                "posture": "unknown",
                "blocked_count": 0,
                "critical_count": 0,
                "whitelisted_count": 0,
                "blacklisted_count": 0,
            }
        avg_trust = sum(e.trust_score for e in entities) / total
        avg_threat = sum(e.threat_score for e in entities) / total
        blocked = sum(1 for e in entities if (e.risk_level.value if isinstance(e.risk_level, RiskLevel) else e.risk_level) == "blocked")
        critical = sum(1 for e in entities if (e.risk_level.value if isinstance(e.risk_level, RiskLevel) else e.risk_level) == "critical")
        whitelisted = sum(1 for e in entities if e.is_whitelisted)
        blacklisted = sum(1 for e in entities if e.is_blacklisted)

        if avg_threat < 25:
            posture = "strong"
        elif avg_threat < 45:
            posture = "moderate"
        elif avg_threat < 65:
            posture = "elevated"
        else:
            posture = "critical"

        return {
            "total_entities": total,
            "avg_trust": round(avg_trust, 2),
            "avg_threat": round(avg_threat, 2),
            "posture": posture,
            "blocked_count": blocked,
            "critical_count": critical,
            "whitelisted_count": whitelisted,
            "blacklisted_count": blacklisted,
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Unified dashboard payload."""
        return {
            "posture": self.get_network_posture(),
            "risk_distribution": self.get_risk_distribution(),
            "top_threats": self.get_top_threats(5),
            "trends_24h": self.get_score_trends(24),
            "geo_map": self.get_geographic_threat_map(),
            "thresholds": self.get_thresholds(),
            "feeds": self.list_feeds(),
        }

    # ── helpers ────────────────────────────────────────────────────────

    def _all_entities(self) -> List[EntityScore]:
        """Return all tracked entities (in-memory cache or DB)."""
        if self._scores:
            return list(self._scores.values())
        if self.use_db:
            try:
                rows = self.db.query(EntityScoreModel).limit(5000).all()
                for r in rows:
                    es = self._model_to_entity(r)
                    key = f"{r.entity_type}::{r.entity_value}"
                    self._scores[key] = es
                return list(self._scores.values())
            except Exception as exc:
                logger.warning("DB _all_entities failed: %s", exc)
        return []
