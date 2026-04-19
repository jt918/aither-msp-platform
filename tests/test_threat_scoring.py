"""
Tests for IP & Entity Threat Scoring Engine
Full coverage of ThreatScoringService
"""

import pytest
from datetime import datetime, timezone, timedelta
from services.msp.threat_scoring import (
    ThreatScoringService,
    EntityType,
    RiskLevel,
    AutoAction,
    EntityScore,
    ScoreFactor,
    ScoreEvent,
    ScoreThreshold,
    ReputationFeed,
    ScoreHistory,
    POSITIVE_FACTORS,
    NEGATIVE_FACTORS,
    DEFAULT_THRESHOLDS,
)


@pytest.fixture
def svc():
    """Fresh ThreatScoringService with no DB."""
    return ThreatScoringService(db=None)


# ── Enums ────────────────────────────────────────────────────────────

class TestEnums:
    def test_entity_types(self):
        assert EntityType.IP_ADDRESS.value == "ip_address"
        assert EntityType.USER.value == "user"
        assert EntityType.DEVICE.value == "device"
        assert EntityType.DOMAIN.value == "domain"
        assert EntityType.EMAIL.value == "email"
        assert EntityType.URL.value == "url"
        assert EntityType.HASH.value == "hash"

    def test_risk_levels(self):
        assert RiskLevel.SAFE.value == "safe"
        assert RiskLevel.BLOCKED.value == "blocked"

    def test_auto_actions(self):
        assert AutoAction.NONE.value == "none"
        assert AutoAction.HONEYPOT_REDIRECT.value == "honeypot_redirect"


# ── Dataclasses ──────────────────────────────────────────────────────

class TestDataclasses:
    def test_entity_score_defaults(self):
        es = EntityScore(score_id="s1", entity_type=EntityType.IP_ADDRESS, entity_value="1.2.3.4")
        assert es.trust_score == 50.0
        assert es.threat_score == 50.0
        assert es.risk_level == RiskLevel.MEDIUM
        assert es.total_events == 0
        assert es.is_whitelisted is False
        assert es.is_blacklisted is False
        assert es.decay_rate == 1.0

    def test_score_factor(self):
        f = ScoreFactor(factor_name="failed_auth", factor_weight=5, factor_value=-5, description="bad pw")
        assert f.factor_name == "failed_auth"
        assert f.factor_value == -5

    def test_score_event(self):
        ev = ScoreEvent(event_id="e1", entity_value="1.2.3.4", entity_type=EntityType.IP_ADDRESS,
                        event_type="negative", impact_points=-5)
        assert ev.event_type == "negative"

    def test_score_threshold(self):
        t = ScoreThreshold(threshold_id="t1", name="Test", risk_level=RiskLevel.HIGH,
                           auto_action=AutoAction.BLOCK)
        assert t.auto_action == AutoAction.BLOCK

    def test_reputation_feed(self):
        f = ReputationFeed(feed_id="f1", name="AbuseIPDB", feed_type="blocklist")
        assert f.is_enabled is True
        assert f.update_interval_hours == 24

    def test_score_history(self):
        h = ScoreHistory(history_id="h1", entity_value="1.2.3.4")
        assert h.trust_score == 50.0


# ── Presets ───────────────────────────────────────────────────────────

class TestPresets:
    def test_positive_factors(self):
        assert POSITIVE_FACTORS["successful_auth"] == 2
        assert POSITIVE_FACTORS["whitelisted"] == 20
        assert POSITIVE_FACTORS["passed_mfa"] == 5

    def test_negative_factors(self):
        assert NEGATIVE_FACTORS["failed_auth"] == -5
        assert NEGATIVE_FACTORS["sqli_attempt"] == -50
        assert NEGATIVE_FACTORS["brute_force"] == -40
        assert NEGATIVE_FACTORS["tor_exit"] == -30

    def test_default_thresholds_count(self):
        assert len(DEFAULT_THRESHOLDS) == 6


# ── Service Init ─────────────────────────────────────────────────────

class TestInit:
    def test_init_no_db(self, svc):
        assert svc.use_db is False
        assert len(svc._thresholds) == 6  # default thresholds seeded

    def test_default_thresholds_seeded(self, svc):
        thresholds = svc.get_thresholds()
        names = [t["name"] for t in thresholds]
        assert "Safe" in names
        assert "Blocked" in names


# ── Scoring Events ───────────────────────────────────────────────────

class TestScoring:
    def test_score_positive_event(self, svc):
        result = svc.score_event("ip_address", "10.0.0.1", "positive", 5, reason="successful_auth", source="auth")
        assert result["entity_value"] == "10.0.0.1"
        assert result["trust_score"] > 50
        assert result["threat_score"] < 50

    def test_score_negative_event(self, svc):
        result = svc.score_event("ip_address", "10.0.0.2", "negative", -10, reason="failed_auth", source="auth")
        assert result["trust_score"] < 50
        assert result["threat_score"] > 50

    def test_score_multiple_negatives_escalates(self, svc):
        for _ in range(5):
            result = svc.score_event("ip_address", "evil.ip", "negative", -25, reason="brute_force", source="ids")
        assert result["threat_score"] > 80
        assert result["risk_level"] in ("critical", "blocked")

    def test_score_batch(self, svc):
        events = [
            {"entity_type": "ip_address", "entity_value": "1.1.1.1", "event_type": "positive", "impact_points": 5, "reason": "ok"},
            {"entity_type": "ip_address", "entity_value": "2.2.2.2", "event_type": "negative", "impact_points": -10, "reason": "bad"},
        ]
        results = svc.score_batch(events)
        assert len(results) == 2
        assert results[0]["trust_score"] > 50
        assert results[1]["threat_score"] > 50

    def test_neutral_event(self, svc):
        result = svc.score_event("user", "alice", "neutral", 0, reason="page_view")
        assert result["entity_value"] == "alice"

    def test_event_counter_increments(self, svc):
        svc.score_event("device", "dev-001", "positive", 3, reason="known_device")
        svc.score_event("device", "dev-001", "negative", -5, reason="failed_auth")
        svc.score_event("device", "dev-001", "neutral", 0, reason="heartbeat")
        score = svc.get_score("device", "dev-001")
        assert score["total_events"] == 3
        assert score["positive_events"] == 1
        assert score["negative_events"] == 1

    def test_auto_action_triggered(self, svc):
        """Severe negative events should trigger auto-action."""
        for _ in range(10):
            result = svc.score_event("ip_address", "attacker", "negative", -50, reason="sqli_attempt")
        # Should have triggered block or isolate
        score = svc.get_score("ip_address", "attacker")
        assert score["auto_block_triggered"] is True


# ── Entity CRUD ──────────────────────────────────────────────────────

class TestEntityCRUD:
    def test_get_score_not_found(self, svc):
        assert svc.get_score("ip_address", "nonexistent") is None

    def test_get_score_after_event(self, svc):
        svc.score_event("ip_address", "10.0.0.5", "positive", 10, reason="test")
        score = svc.get_score("ip_address", "10.0.0.5")
        assert score is not None
        assert score["entity_value"] == "10.0.0.5"

    def test_get_scores_all(self, svc):
        svc.score_event("ip_address", "a.b.c.d", "positive", 5)
        svc.score_event("user", "bob", "negative", -10)
        result = svc.get_scores()
        assert result["total"] == 2

    def test_get_scores_filter_type(self, svc):
        svc.score_event("ip_address", "a.b.c.d", "positive", 5)
        svc.score_event("user", "bob", "negative", -10)
        result = svc.get_scores(entity_type="user")
        assert result["total"] == 1
        assert result["entities"][0]["entity_type"] == "user"

    def test_get_scores_filter_risk(self, svc):
        svc.score_event("ip_address", "safe.ip", "positive", 30)
        svc.score_event("ip_address", "danger.ip", "negative", -40)
        result = svc.get_scores(risk_level="safe")
        for e in result["entities"]:
            assert e["risk_level"] == "safe"

    def test_get_scores_filter_min_threat(self, svc):
        svc.score_event("ip_address", "ok.ip", "positive", 20)
        svc.score_event("ip_address", "bad.ip", "negative", -30)
        result = svc.get_scores(min_threat=60)
        for e in result["entities"]:
            assert e["threat_score"] >= 60

    def test_get_scores_pagination(self, svc):
        for i in range(5):
            svc.score_event("ip_address", f"10.0.0.{i}", "positive", 1)
        result = svc.get_scores(limit=2, offset=0)
        assert len(result["entities"]) == 2
        assert result["total"] == 5


# ── Score History ────────────────────────────────────────────────────

class TestHistory:
    def test_history_after_auto_action(self, svc):
        for _ in range(10):
            svc.score_event("ip_address", "hist.ip", "negative", -50)
        history = svc.get_score_history("hist.ip", period_hours=1)
        assert len(history) > 0

    def test_history_empty_for_unknown(self, svc):
        history = svc.get_score_history("no.such.ip", period_hours=24)
        assert history == []


# ── Whitelist / Blacklist ────────────────────────────────────────────

class TestLists:
    def test_whitelist(self, svc):
        result = svc.whitelist_entity("ip_address", "10.0.0.100", reason="trusted office")
        assert result["is_whitelisted"] is True
        assert result["trust_score"] >= 90

    def test_blacklist(self, svc):
        result = svc.blacklist_entity("ip_address", "evil.com", reason="known C2")
        assert result["is_blacklisted"] is True
        assert result["threat_score"] == 100

    def test_whitelist_clears_blacklist(self, svc):
        svc.blacklist_entity("ip_address", "flip.ip")
        result = svc.whitelist_entity("ip_address", "flip.ip")
        assert result["is_whitelisted"] is True
        assert result["is_blacklisted"] is False

    def test_blacklist_clears_whitelist(self, svc):
        svc.whitelist_entity("ip_address", "flip2.ip")
        result = svc.blacklist_entity("ip_address", "flip2.ip")
        assert result["is_blacklisted"] is True
        assert result["is_whitelisted"] is False

    def test_remove_from_list(self, svc):
        svc.whitelist_entity("ip_address", "remove.ip")
        result = svc.remove_from_list("remove.ip")
        assert result["is_whitelisted"] is False
        assert result["is_blacklisted"] is False

    def test_remove_not_found(self, svc):
        result = svc.remove_from_list("never.seen.ip")
        assert result["status"] == "not_found"


# ── Threshold CRUD ───────────────────────────────────────────────────

class TestThresholds:
    def test_get_defaults(self, svc):
        thresholds = svc.get_thresholds()
        assert len(thresholds) == 6

    def test_create_threshold(self, svc):
        result = svc.create_threshold(
            name="Custom", risk_level="high",
            trust_score_min=10, trust_score_max=30,
            threat_score_min=70, threat_score_max=90,
            auto_action="captcha",
        )
        assert result["name"] == "Custom"
        assert result["auto_action"] == "captcha"

    def test_update_threshold(self, svc):
        t = svc.create_threshold(name="Update Me", risk_level="low", auto_action="none")
        updated = svc.update_threshold(t["threshold_id"], {"auto_action": "alert", "name": "Updated"})
        assert updated["auto_action"] == "alert"
        assert updated["name"] == "Updated"

    def test_update_nonexistent(self, svc):
        assert svc.update_threshold("no-such-id", {"name": "x"}) is None

    def test_delete_threshold(self, svc):
        t = svc.create_threshold(name="Delete Me", risk_level="low")
        assert svc.delete_threshold(t["threshold_id"]) is True
        # Should be gone (minus default thresholds)
        remaining_ids = [th["threshold_id"] for th in svc.get_thresholds()]
        assert t["threshold_id"] not in remaining_ids


# ── Reputation Feeds ─────────────────────────────────────────────────

class TestFeeds:
    def test_register_feed(self, svc):
        result = svc.register_feed(name="AbuseIPDB", feed_type="blocklist", source_url="https://api.abuseipdb.com/")
        assert result["name"] == "AbuseIPDB"
        assert result["feed_type"] == "blocklist"
        assert result["is_enabled"] is True

    def test_list_feeds(self, svc):
        svc.register_feed(name="Feed1", feed_type="blocklist")
        svc.register_feed(name="Feed2", feed_type="allowlist")
        feeds = svc.list_feeds()
        assert len(feeds) == 2

    def test_pull_feed(self, svc):
        f = svc.register_feed(name="TestFeed", feed_type="blocklist", source_url="https://example.com/feed.txt")
        result = svc.pull_feed(f["feed_id"])
        assert result["status"] == "pulled"

    def test_pull_feed_not_found(self, svc):
        result = svc.pull_feed("nonexistent")
        assert "error" in result

    def test_pull_all_feeds(self, svc):
        svc.register_feed(name="F1", feed_type="blocklist")
        svc.register_feed(name="F2", feed_type="reputation")
        results = svc.pull_all_feeds()
        assert len(results) == 2

    def test_import_blocklist(self, svc):
        f = ReputationFeed(feed_id="imp", name="Manual", feed_type="blocklist")
        svc._import_blocklist(f, ["1.2.3.4", "evil.domain.com", "# comment", ""])
        assert f.entries_count == 4
        # Check entities were blacklisted
        score_ip = svc.get_score("ip_address", "1.2.3.4")
        assert score_ip is not None
        assert score_ip["is_blacklisted"] is True
        score_dom = svc.get_score("domain", "evil.domain.com")
        assert score_dom is not None


# ── Analytics ────────────────────────────────────────────────────────

class TestAnalytics:
    def test_risk_distribution_empty(self, svc):
        dist = svc.get_risk_distribution()
        assert sum(dist.values()) == 0

    def test_risk_distribution_populated(self, svc):
        svc.score_event("ip_address", "safe1", "positive", 40)
        svc.score_event("ip_address", "bad1", "negative", -40)
        dist = svc.get_risk_distribution()
        assert sum(dist.values()) == 2

    def test_top_threats_empty(self, svc):
        assert svc.get_top_threats(5) == []

    def test_top_threats_order(self, svc):
        svc.score_event("ip_address", "mild", "negative", -5)
        svc.score_event("ip_address", "severe", "negative", -40)
        top = svc.get_top_threats(10)
        assert top[0]["entity_value"] == "severe"

    def test_score_trends(self, svc):
        svc.score_event("ip_address", "t1", "positive", 5)
        svc.score_event("ip_address", "t2", "negative", -10)
        svc.score_event("ip_address", "t3", "neutral", 0)
        trends = svc.get_score_trends(24)
        assert trends["total_events"] == 3
        assert trends["positive_events"] == 1
        assert trends["negative_events"] == 1
        assert trends["neutral_events"] == 1
        assert 0 <= trends["threat_ratio"] <= 1

    def test_geo_map_empty(self, svc):
        geo = svc.get_geographic_threat_map()
        assert isinstance(geo, list)

    def test_geo_map_with_data(self, svc):
        svc.score_event("ip_address", "cn.ip", "negative", -20, raw_data={"geo": "CN"})
        # Manually set geo_data
        entity = svc._get_or_create_entity("ip_address", "cn.ip")
        entity.geo_data = {"country": "CN"}
        geo = svc.get_geographic_threat_map()
        countries = [g["country"] for g in geo]
        assert "CN" in countries

    def test_network_posture_empty(self, svc):
        posture = svc.get_network_posture()
        assert posture["total_entities"] == 0
        assert posture["posture"] == "unknown"

    def test_network_posture_populated(self, svc):
        svc.score_event("ip_address", "p1", "positive", 20)
        svc.score_event("ip_address", "p2", "positive", 30)
        posture = svc.get_network_posture()
        assert posture["total_entities"] == 2
        assert posture["posture"] in ("strong", "moderate", "elevated", "critical")

    def test_dashboard(self, svc):
        svc.score_event("ip_address", "d1", "positive", 10)
        svc.score_event("ip_address", "d2", "negative", -20)
        dash = svc.get_dashboard()
        assert "posture" in dash
        assert "risk_distribution" in dash
        assert "top_threats" in dash
        assert "trends_24h" in dash
        assert "geo_map" in dash
        assert "thresholds" in dash
        assert "feeds" in dash


# ── Score Decay ──────────────────────────────────────────────────────

class TestDecay:
    def test_apply_decay(self, svc):
        svc.score_event("ip_address", "decay.ip", "positive", 30)
        entity = svc._get_or_create_entity("ip_address", "decay.ip")
        # Simulate 10 hours ago
        entity.last_updated = datetime.now(timezone.utc) - timedelta(hours=10)
        old_trust = entity.trust_score
        svc._apply_decay()
        # Trust should have decayed toward 50
        assert entity.trust_score < old_trust or entity.trust_score == 50.0


# ── Risk Classification ─────────────────────────────────────────────

class TestClassification:
    def test_safe(self, svc):
        assert svc._classify_risk(90, 10) == RiskLevel.SAFE

    def test_low(self, svc):
        assert svc._classify_risk(70, 30) == RiskLevel.LOW

    def test_medium(self, svc):
        assert svc._classify_risk(50, 50) == RiskLevel.MEDIUM

    def test_high(self, svc):
        assert svc._classify_risk(30, 70) == RiskLevel.HIGH

    def test_critical(self, svc):
        assert svc._classify_risk(10, 90) == RiskLevel.CRITICAL

    def test_blocked(self, svc):
        assert svc._classify_risk(0, 100) == RiskLevel.BLOCKED


# ── Entity Type Coverage ─────────────────────────────────────────────

class TestEntityTypes:
    def test_user_entity(self, svc):
        result = svc.score_event("user", "admin@corp.com", "negative", -15, reason="impossible_travel")
        assert result["entity_value"] == "admin@corp.com"

    def test_device_entity(self, svc):
        result = svc.score_event("device", "LAPTOP-ABC", "positive", 5, reason="known_device")
        assert result["entity_value"] == "LAPTOP-ABC"

    def test_domain_entity(self, svc):
        result = svc.score_event("domain", "malware.example.com", "negative", -50, reason="malware_comm")
        assert result["threat_score"] > 80

    def test_email_entity(self, svc):
        result = svc.score_event("email", "phisher@evil.com", "negative", -35, reason="xss_attempt")
        assert result["threat_score"] > 50

    def test_url_entity(self, svc):
        result = svc.score_event("url", "https://evil.com/payload", "negative", -50, reason="sqli_attempt")
        assert result["threat_score"] > 80

    def test_hash_entity(self, svc):
        result = svc.score_event("hash", "abc123deadbeef", "negative", -50, reason="malware_comm")
        assert result["threat_score"] > 80


# ── Factor management ────────────────────────────────────────────────

class TestFactors:
    def test_factors_capped_at_100(self, svc):
        """Score factors list should not grow unbounded."""
        for i in range(150):
            svc.score_event("ip_address", "factor.ip", "negative", -1, reason=f"event_{i}")
        entity = svc._get_or_create_entity("ip_address", "factor.ip")
        assert len(entity.score_factors) <= 100

    def test_recent_factors_in_dict(self, svc):
        svc.score_event("ip_address", "rf.ip", "positive", 5, reason="good_thing")
        score = svc.get_score("ip_address", "rf.ip")
        assert len(score["recent_factors"]) > 0
        assert score["recent_factors"][-1]["factor_name"] == "good_thing"
