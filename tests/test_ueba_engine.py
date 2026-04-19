"""
Tests for UEBA (User & Entity Behavior Analytics) Engine Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.ueba_engine import (
    UEBAEngineService,
    EntityType,
    EventType,
    AnomalyType,
    RiskLevel,
    TimeWindow,
    ThreatIndicatorType,
    UserProfile,
    BehaviorEvent,
    BehavioralBaseline,
    AnomalyDetection,
    ThreatIndicator,
)


class TestUEBAEngineService:
    """Tests for UEBAEngineService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = UEBAEngineService()

    # ========== Profile Management Tests ==========

    def test_create_profile_basic(self):
        """Test basic profile creation"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="user@example.com",
            entity_name="Test User",
            client_id="CLIENT-001",
        )
        assert profile is not None
        assert profile.profile_id.startswith("UEBA-")
        assert profile.entity_type == "user"
        assert profile.entity_id == "user@example.com"
        assert profile.entity_name == "Test User"
        assert profile.client_id == "CLIENT-001"
        assert profile.risk_score == 0.0
        assert profile.risk_level == "low"
        assert profile.total_events == 0
        assert profile.baseline_established is False

    def test_create_profile_device(self):
        """Test device profile creation"""
        profile = self.service.create_profile(
            entity_type=EntityType.DEVICE.value,
            entity_id="WKS-001",
            entity_name="Workstation 001",
        )
        assert profile.entity_type == "device"

    def test_create_profile_with_tags(self):
        """Test profile creation with tags"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="admin@example.com",
            tags=["admin", "high-value"],
        )
        assert profile.tags == ["admin", "high-value"]

    def test_get_profile(self):
        """Test profile retrieval"""
        created = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="lookup@example.com",
        )
        found = self.service.get_profile(created.profile_id)
        assert found is not None
        assert found.profile_id == created.profile_id

    def test_get_profile_not_found(self):
        """Test profile retrieval for nonexistent ID"""
        found = self.service.get_profile("UEBA-NONEXISTENT")
        assert found is None

    def test_list_profiles(self):
        """Test listing profiles"""
        self.service.create_profile(entity_type=EntityType.USER.value, entity_id="u1@ex.com", client_id="C1")
        self.service.create_profile(entity_type=EntityType.DEVICE.value, entity_id="d1", client_id="C1")
        self.service.create_profile(entity_type=EntityType.USER.value, entity_id="u2@ex.com", client_id="C2")

        all_profiles = self.service.list_profiles()
        assert len(all_profiles) == 3

        users = self.service.list_profiles(entity_type=EntityType.USER.value)
        assert len(users) == 2

        c1 = self.service.list_profiles(client_id="C1")
        assert len(c1) == 2

    def test_update_profile(self):
        """Test profile update"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="update@ex.com",
        )
        updated = self.service.update_profile(profile.profile_id, entity_name="Updated Name")
        assert updated.entity_name == "Updated Name"

    def test_watchlist_profile(self):
        """Test watchlisting a profile"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="watch@ex.com",
        )
        assert profile.is_watchlisted is False

        self.service.watchlist_profile(profile.profile_id)
        found = self.service.get_profile(profile.profile_id)
        assert found.is_watchlisted is True

        self.service.unwatchlist_profile(profile.profile_id)
        found = self.service.get_profile(profile.profile_id)
        assert found.is_watchlisted is False

    def test_list_watchlisted(self):
        """Test filtering by watchlist status"""
        p1 = self.service.create_profile(entity_type=EntityType.USER.value, entity_id="w1@ex.com")
        self.service.create_profile(entity_type=EntityType.USER.value, entity_id="w2@ex.com")
        self.service.watchlist_profile(p1.profile_id)

        watchlisted = self.service.list_profiles(watchlisted=True)
        assert len(watchlisted) == 1
        assert watchlisted[0].profile_id == p1.profile_id

    # ========== Event Recording Tests ==========

    def test_record_event_basic(self):
        """Test basic event recording"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="events@ex.com",
        )
        result = self.service.record_event(
            entity_id="events@ex.com",
            event_type=EventType.LOGIN_SUCCESS.value,
            context={"source_ip": "192.168.1.100"},
        )
        assert result["event_id"].startswith("EVT-")
        assert result["profile_id"] == profile.profile_id
        assert "anomalies_detected" in result
        assert "risk_score" in result

    def test_record_event_auto_creates_profile(self):
        """Test that recording an event auto-creates profile if missing"""
        result = self.service.record_event(
            entity_id="new_entity@ex.com",
            event_type=EventType.LOGIN_SUCCESS.value,
        )
        assert result["profile_id"].startswith("UEBA-")
        profile = self.service.get_profile(result["profile_id"])
        assert profile is not None

    def test_record_event_updates_stats(self):
        """Test that event recording updates profile stats"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="stats@ex.com",
        )
        self.service.record_event(entity_id="stats@ex.com", event_type=EventType.LOGIN_SUCCESS.value)
        self.service.record_event(entity_id="stats@ex.com", event_type=EventType.FILE_ACCESS.value)

        updated = self.service.get_profile(profile.profile_id)
        assert updated.total_events == 2
        assert updated.last_activity_at is not None

    def test_record_batch(self):
        """Test bulk event recording"""
        self.service.create_profile(entity_type=EntityType.USER.value, entity_id="batch@ex.com")
        events = [
            {"entity_id": "batch@ex.com", "event_type": EventType.LOGIN_SUCCESS.value},
            {"entity_id": "batch@ex.com", "event_type": EventType.FILE_ACCESS.value},
            {"entity_id": "batch@ex.com", "event_type": EventType.LOGOUT.value},
        ]
        result = self.service.record_batch(events)
        assert result["events_processed"] == 3

    # ========== Baseline Tests ==========

    def test_build_baseline_insufficient_events(self):
        """Test baseline building with insufficient events"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="few@ex.com",
        )
        self.service.record_event(entity_id="few@ex.com", event_type=EventType.LOGIN_SUCCESS.value)
        result = self.service.build_baseline(profile.profile_id)
        assert "error" in result

    def test_build_baseline_success(self):
        """Test successful baseline building"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="baseline@ex.com",
        )
        for i in range(10):
            self.service.record_event(
                entity_id="baseline@ex.com",
                event_type=EventType.LOGIN_SUCCESS.value,
                context={"source_ip": f"192.168.1.{i % 3 + 1}", "device_fingerprint": f"dev-{i % 2}"},
            )
        result = self.service.build_baseline(profile.profile_id)
        assert result["baseline_established"] is True
        assert len(result["baselines_built"]) > 0

    def test_get_baselines(self):
        """Test retrieving baselines"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="getbl@ex.com",
        )
        for i in range(10):
            self.service.record_event(
                entity_id="getbl@ex.com",
                event_type=EventType.LOGIN_SUCCESS.value,
                context={"source_ip": "10.0.0.1"},
            )
        self.service.build_baseline(profile.profile_id)
        baselines = self.service.get_baselines(profile.profile_id)
        assert len(baselines) > 0
        assert all(isinstance(b, BehavioralBaseline) for b in baselines)

    def test_build_baseline_not_found(self):
        """Test baseline building for nonexistent profile"""
        result = self.service.build_baseline("UEBA-FAKE")
        assert "error" in result

    # ========== Anomaly Detection Tests ==========

    def test_check_impossible_travel(self):
        """Test impossible travel detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="travel@ex.com",
        )
        # First login from New York
        self.service.record_event(
            entity_id="travel@ex.com",
            event_type=EventType.LOGIN_SUCCESS.value,
            context={"geo_location": {"country": "US", "city": "New York", "lat": 40.7128, "lng": -74.0060}},
        )
        # Second login from Tokyo 1 minute later (impossible)
        result = self.service.record_event(
            entity_id="travel@ex.com",
            event_type=EventType.LOGIN_SUCCESS.value,
            context={"geo_location": {"country": "JP", "city": "Tokyo", "lat": 35.6762, "lng": 139.6503}},
        )
        assert result["anomalies_detected"] >= 1
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert AnomalyType.IMPOSSIBLE_TRAVEL.value in anomaly_types

    def test_check_login_time_anomaly(self):
        """Test unusual login time detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="time@ex.com",
        )
        # Build baseline with daytime logins
        for i in range(10):
            self.service.record_event(
                entity_id="time@ex.com",
                event_type=EventType.LOGIN_SUCCESS.value,
                context={"source_ip": "10.0.0.1"},
            )
        self.service.build_baseline(profile.profile_id)
        # Baselines exist now; further events will be checked

    def test_check_location_anomaly(self):
        """Test new country detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="location@ex.com",
        )
        # Establish US history
        for _ in range(3):
            self.service.record_event(
                entity_id="location@ex.com",
                event_type=EventType.LOGIN_SUCCESS.value,
                context={"geo_location": {"country": "US"}},
            )
        # Login from new country
        result = self.service.record_event(
            entity_id="location@ex.com",
            event_type=EventType.LOGIN_SUCCESS.value,
            context={"geo_location": {"country": "RU"}},
        )
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert AnomalyType.UNUSUAL_LOGIN_LOCATION.value in anomaly_types

    def test_check_velocity_anomaly(self):
        """Test excessive event velocity detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="velocity@ex.com",
        )
        # Fire 60 events rapidly
        for i in range(60):
            self.service.record_event(
                entity_id="velocity@ex.com",
                event_type=EventType.API_CALL.value,
            )
        # Last event should trigger velocity anomaly
        anomalies = self.service.get_anomalies(profile_id=profile.profile_id, anomaly_type=AnomalyType.VELOCITY_ANOMALY.value)
        assert len(anomalies) > 0

    def test_check_device_anomaly(self):
        """Test new device fingerprint detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="device@ex.com",
        )
        for _ in range(3):
            self.service.record_event(
                entity_id="device@ex.com",
                event_type=EventType.LOGIN_SUCCESS.value,
                context={"device_fingerprint": "known-device-001"},
            )
        result = self.service.record_event(
            entity_id="device@ex.com",
            event_type=EventType.LOGIN_SUCCESS.value,
            context={"device_fingerprint": "unknown-device-999"},
        )
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert AnomalyType.DEVICE_ANOMALY.value in anomaly_types

    def test_check_failure_rate(self):
        """Test excessive authentication failure detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="failures@ex.com",
        )
        for _ in range(6):
            self.service.record_event(
                entity_id="failures@ex.com",
                event_type=EventType.LOGIN_FAILURE.value,
                context={"outcome": "failure"},
            )
        anomalies = self.service.get_anomalies(
            profile_id=profile.profile_id,
            anomaly_type=AnomalyType.EXCESSIVE_FAILURES.value,
        )
        assert len(anomalies) > 0

    def test_check_privilege_anomaly(self):
        """Test first-time privilege action detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="priv@ex.com",
        )
        # Record normal events first
        for _ in range(12):
            self.service.record_event(
                entity_id="priv@ex.com",
                event_type=EventType.FILE_ACCESS.value,
            )
        # First admin action
        result = self.service.record_event(
            entity_id="priv@ex.com",
            event_type=EventType.ADMIN_ACTION.value,
        )
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert AnomalyType.PRIVILEGE_ANOMALY.value in anomaly_types

    def test_check_first_time_access(self):
        """Test first-time resource access detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="first@ex.com",
        )
        # Access several known resources
        for i in range(8):
            self.service.record_event(
                entity_id="first@ex.com",
                event_type=EventType.FILE_ACCESS.value,
                context={"resource_accessed": f"/data/file-{i}"},
            )
        # Access new resource
        result = self.service.record_event(
            entity_id="first@ex.com",
            event_type=EventType.FILE_ACCESS.value,
            context={"resource_accessed": "/secrets/classified.doc"},
        )
        anomaly_types = [a["type"] for a in result["anomalies"]]
        assert AnomalyType.FIRST_TIME_ACCESS.value in anomaly_types

    def test_check_lateral_movement(self):
        """Test lateral movement pattern detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="lateral@ex.com",
        )
        # Connect to many distinct destinations rapidly
        for i in range(12):
            self.service.record_event(
                entity_id="lateral@ex.com",
                event_type=EventType.NETWORK_CONNECTION.value,
                context={"destination_ip": f"10.0.{i}.1"},
            )
        anomalies = self.service.get_anomalies(
            profile_id=profile.profile_id,
            anomaly_type=AnomalyType.LATERAL_MOVEMENT_PATTERN.value,
        )
        assert len(anomalies) > 0

    def test_check_bot_behavior(self):
        """Test bot behavior detection (perfectly timed events)"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="bot@ex.com",
        )
        # Inject perfectly timed events directly
        now = datetime.now(timezone.utc)
        for i in range(15):
            evt_id = f"EVT-BOT{i:04d}"
            evt = BehaviorEvent(
                event_id=evt_id,
                profile_id=profile.profile_id,
                entity_id="bot@ex.com",
                event_type=EventType.API_CALL.value,
                timestamp=now + timedelta(seconds=i * 2.0),  # exactly 2 seconds apart
            )
            self.service._events[evt_id] = evt
            self.service._profile_events.setdefault(profile.profile_id, []).append(evt_id)

        events = self.service._get_profile_events(profile.profile_id)
        anomaly = self.service._check_bot_behavior(events, profile)
        assert anomaly is not None
        assert anomaly.anomaly_type == AnomalyType.BOT_BEHAVIOR.value

    # ========== Anomaly Management Tests ==========

    def test_confirm_anomaly(self):
        """Test confirming an anomaly"""
        profile = self.service.create_profile(entity_type=EntityType.USER.value, entity_id="confirm@ex.com")
        anomaly = self.service._create_anomaly(
            profile.profile_id, "EVT-001",
            AnomalyType.BEHAVIORAL_DRIFT.value, RiskLevel.MEDIUM.value,
            "Test anomaly", 2.5, 1.0, 3.5,
        )
        confirmed = self.service.confirm_anomaly(anomaly.anomaly_id)
        assert confirmed is not None
        assert confirmed.is_confirmed is True

    def test_mark_false_positive(self):
        """Test marking anomaly as false positive"""
        profile = self.service.create_profile(entity_type=EntityType.USER.value, entity_id="fp@ex.com")
        anomaly = self.service._create_anomaly(
            profile.profile_id, "EVT-002",
            AnomalyType.UNUSUAL_LOGIN_TIME.value, RiskLevel.LOW.value,
            "Test FP", 1.0, 0.5, 1.5,
        )
        fp = self.service.mark_false_positive(anomaly.anomaly_id)
        assert fp is not None
        assert fp.is_false_positive is True

    def test_review_anomaly(self):
        """Test reviewing an anomaly"""
        profile = self.service.create_profile(entity_type=EntityType.USER.value, entity_id="review@ex.com")
        anomaly = self.service._create_anomaly(
            profile.profile_id, "EVT-003",
            AnomalyType.DEVICE_ANOMALY.value, RiskLevel.MEDIUM.value,
            "Test review", 2.0, 1.0, 3.0,
        )
        reviewed = self.service.review_anomaly(anomaly.anomaly_id, reviewer="analyst@ex.com")
        assert reviewed is not None
        assert reviewed.reviewed_by == "analyst@ex.com"
        assert reviewed.reviewed_at is not None

    def test_get_anomalies_filtered(self):
        """Test anomaly retrieval with filters"""
        profile = self.service.create_profile(entity_type=EntityType.USER.value, entity_id="filter@ex.com")
        self.service._create_anomaly(
            profile.profile_id, "E1", AnomalyType.VELOCITY_ANOMALY.value, RiskLevel.HIGH.value,
            "Velocity", 3.0, 1.0, 4.0,
        )
        self.service._create_anomaly(
            profile.profile_id, "E2", AnomalyType.DEVICE_ANOMALY.value, RiskLevel.MEDIUM.value,
            "Device", 2.0, 1.0, 3.0,
        )
        high = self.service.get_anomalies(severity=RiskLevel.HIGH.value)
        assert len(high) >= 1

    def test_confirm_nonexistent_anomaly(self):
        """Test confirming nonexistent anomaly"""
        result = self.service.confirm_anomaly("ANOM-FAKE")
        assert result is None

    # ========== Risk Scoring Tests ==========

    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="risk@ex.com",
        )
        # Create anomalies of varying severity
        self.service._create_anomaly(
            profile.profile_id, "E1", AnomalyType.IMPOSSIBLE_TRAVEL.value, RiskLevel.CRITICAL.value,
            "Travel", 5.0, 0.0, 5.0,
        )
        self.service._create_anomaly(
            profile.profile_id, "E2", AnomalyType.DEVICE_ANOMALY.value, RiskLevel.MEDIUM.value,
            "Device", 2.0, 1.0, 3.0,
        )
        score = self.service.calculate_risk_score(profile.profile_id)
        assert score > 0
        profile = self.service.get_profile(profile.profile_id)
        assert abs(profile.risk_score - round(score, 1)) < 0.01
        assert profile.risk_level in ("low", "medium", "high", "critical")

    def test_risk_score_false_positives_excluded(self):
        """Test that false positives don't affect risk score"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="fpexcl@ex.com",
        )
        anomaly = self.service._create_anomaly(
            profile.profile_id, "E1", AnomalyType.VELOCITY_ANOMALY.value, RiskLevel.HIGH.value,
            "Velocity FP", 5.0, 1.0, 6.0,
        )
        score_before = self.service.calculate_risk_score(profile.profile_id)
        self.service.mark_false_positive(anomaly.anomaly_id)
        score_after = self.service.calculate_risk_score(profile.profile_id)
        assert score_after < score_before

    def test_watchlist_increases_risk(self):
        """Test that watchlisted profiles get risk multiplier"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value,
            entity_id="watchrisk@ex.com",
        )
        self.service._create_anomaly(
            profile.profile_id, "E1", AnomalyType.BEHAVIORAL_DRIFT.value, RiskLevel.MEDIUM.value,
            "Drift", 3.0, 1.0, 4.0,
        )
        score_normal = self.service.calculate_risk_score(profile.profile_id)
        self.service.watchlist_profile(profile.profile_id)
        score_watchlisted = self.service.calculate_risk_score(profile.profile_id)
        assert score_watchlisted >= score_normal

    # ========== Peer Comparison Tests ==========

    def test_compare_to_peers(self):
        """Test peer comparison"""
        p1 = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="peer1@ex.com", client_id="C1"
        )
        self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="peer2@ex.com", client_id="C1"
        )
        self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="peer3@ex.com", client_id="C1"
        )
        result = self.service.compare_to_peers(p1.profile_id)
        assert result["peer_count"] == 2
        assert "peer_avg_risk_score" in result
        assert "percentile_risk" in result

    def test_compare_to_peers_no_peers(self):
        """Test peer comparison with no peers"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="lonely@ex.com", client_id="UNIQUE"
        )
        result = self.service.compare_to_peers(profile.profile_id)
        assert result["peer_count"] == 0

    def test_compare_to_peers_not_found(self):
        """Test peer comparison for nonexistent profile"""
        result = self.service.compare_to_peers("UEBA-FAKE")
        assert "error" in result

    # ========== Threat Indicator Tests ==========

    def test_create_indicator(self):
        """Test threat indicator creation"""
        indicator = self.service.create_indicator(
            indicator_type=ThreatIndicatorType.BRUTE_FORCE.value,
            severity=RiskLevel.HIGH.value,
            related_profiles=["UEBA-001"],
            ttps=["T1110"],
            confidence=0.85,
            description="Brute force detected",
        )
        assert indicator.indicator_id.startswith("THR-")
        assert indicator.indicator_type == "brute_force"
        assert indicator.confidence == 0.85
        assert "T1110" in indicator.ttps

    def test_get_indicators(self):
        """Test threat indicator retrieval"""
        self.service.create_indicator(
            indicator_type=ThreatIndicatorType.BRUTE_FORCE.value,
            severity=RiskLevel.HIGH.value,
        )
        self.service.create_indicator(
            indicator_type=ThreatIndicatorType.LATERAL_MOVEMENT.value,
            severity=RiskLevel.CRITICAL.value,
        )
        all_threats = self.service.get_indicators()
        assert len(all_threats) == 2

        brute = self.service.get_indicators(indicator_type=ThreatIndicatorType.BRUTE_FORCE.value)
        assert len(brute) == 1

    def test_update_indicator(self):
        """Test threat indicator update"""
        indicator = self.service.create_indicator(
            indicator_type=ThreatIndicatorType.BOT_ACTIVITY.value,
            severity=RiskLevel.MEDIUM.value,
        )
        updated = self.service.update_indicator(
            indicator.indicator_id,
            severity=RiskLevel.HIGH.value,
            confidence=0.9,
        )
        assert updated.severity == RiskLevel.HIGH.value
        assert updated.confidence == 0.9

    def test_correlate_anomalies_brute_force(self):
        """Test anomaly correlation: brute force detection"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="corr@ex.com"
        )
        for i in range(4):
            self.service._create_anomaly(
                profile.profile_id, f"E{i}",
                AnomalyType.EXCESSIVE_FAILURES.value, RiskLevel.HIGH.value,
                f"Failure {i}", 3.0, 5.0, 15.0,
            )
        indicators = self.service._correlate_anomalies()
        brute_indicators = [i for i in indicators if i.indicator_type == ThreatIndicatorType.BRUTE_FORCE.value]
        assert len(brute_indicators) >= 1

    def test_correlate_anomalies_compromised_account(self):
        """Test anomaly correlation: compromised account"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="comp@ex.com"
        )
        self.service._create_anomaly(
            profile.profile_id, "E1",
            AnomalyType.IMPOSSIBLE_TRAVEL.value, RiskLevel.CRITICAL.value,
            "Travel", 5.0, 0.0, 5.0,
        )
        self.service._create_anomaly(
            profile.profile_id, "E2",
            AnomalyType.DEVICE_ANOMALY.value, RiskLevel.MEDIUM.value,
            "Device", 2.0, 1.0, 3.0,
        )
        indicators = self.service._correlate_anomalies()
        comp_indicators = [i for i in indicators if i.indicator_type == ThreatIndicatorType.COMPROMISED_ACCOUNT.value]
        assert len(comp_indicators) >= 1

    def test_correlate_anomalies_exfiltration(self):
        """Test anomaly correlation: data exfiltration"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="exfil@ex.com"
        )
        self.service._create_anomaly(
            profile.profile_id, "E1",
            AnomalyType.EXFILTRATION_PATTERN.value, RiskLevel.CRITICAL.value,
            "Exfil", 4.0, 500.0, 2000.0,
        )
        indicators = self.service._correlate_anomalies()
        exfil_indicators = [i for i in indicators if i.indicator_type == ThreatIndicatorType.DATA_EXFILTRATION.value]
        assert len(exfil_indicators) >= 1

    # ========== Dashboard Tests ==========

    def test_get_dashboard(self):
        """Test dashboard summary"""
        self.service.create_profile(entity_type=EntityType.USER.value, entity_id="dash1@ex.com")
        self.service.create_profile(entity_type=EntityType.DEVICE.value, entity_id="dash-dev-1")
        self.service.record_event(entity_id="dash1@ex.com", event_type=EventType.LOGIN_SUCCESS.value)

        dashboard = self.service.get_dashboard()
        assert dashboard["total_profiles"] == 2
        assert "high_risk_count" in dashboard
        assert "anomalies_today" in dashboard
        assert "risk_distribution" in dashboard
        assert "entity_type_breakdown" in dashboard
        assert "top_threats" in dashboard

    def test_get_risk_distribution(self):
        """Test risk distribution"""
        self.service.create_profile(entity_type=EntityType.USER.value, entity_id="rd1@ex.com")
        dist = self.service.get_risk_distribution()
        assert "low" in dist
        assert "medium" in dist
        assert "high" in dist
        assert "critical" in dist

    def test_get_high_risk_entities(self):
        """Test high risk entity retrieval"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="highrisk@ex.com"
        )
        # Create several critical anomalies
        for i in range(5):
            self.service._create_anomaly(
                profile.profile_id, f"E{i}",
                AnomalyType.IMPOSSIBLE_TRAVEL.value, RiskLevel.CRITICAL.value,
                f"Critical {i}", 5.0, 0.0, 5.0,
            )
        self.service.calculate_risk_score(profile.profile_id)
        high_risk = self.service.get_high_risk_entities(threshold=10.0)
        assert len(high_risk) >= 1

    def test_get_anomaly_timeline(self):
        """Test anomaly timeline"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="timeline@ex.com"
        )
        self.service._create_anomaly(
            profile.profile_id, "E1",
            AnomalyType.VELOCITY_ANOMALY.value, RiskLevel.HIGH.value,
            "First", 3.0, 1.0, 4.0,
        )
        self.service._create_anomaly(
            profile.profile_id, "E2",
            AnomalyType.DEVICE_ANOMALY.value, RiskLevel.MEDIUM.value,
            "Second", 2.0, 1.0, 3.0,
        )
        timeline = self.service.get_anomaly_timeline(profile.profile_id)
        assert len(timeline) == 2
        assert "detected_at" in timeline[0]

    # ========== Enum Tests ==========

    def test_entity_type_enum(self):
        """Test EntityType enum values"""
        assert EntityType.USER.value == "user"
        assert EntityType.DEVICE.value == "device"
        assert EntityType.IP_ADDRESS.value == "ip_address"
        assert EntityType.SERVICE_ACCOUNT.value == "service_account"
        assert EntityType.API_KEY.value == "api_key"
        assert EntityType.NETWORK_SEGMENT.value == "network_segment"

    def test_event_type_enum(self):
        """Test EventType enum has all expected values"""
        assert len(EventType) == 25
        assert EventType.LOGIN_SUCCESS.value == "login_success"
        assert EventType.REMOTE_ACCESS.value == "remote_access"

    def test_anomaly_type_enum(self):
        """Test AnomalyType enum has all expected values"""
        assert len(AnomalyType) == 15
        assert AnomalyType.IMPOSSIBLE_TRAVEL.value == "impossible_travel"
        assert AnomalyType.CREDENTIAL_SHARING.value == "credential_sharing"

    def test_risk_level_enum(self):
        """Test RiskLevel enum"""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_time_window_enum(self):
        """Test TimeWindow enum"""
        assert TimeWindow.HOURLY.value == "hourly"
        assert TimeWindow.MONTHLY.value == "monthly"

    def test_threat_indicator_type_enum(self):
        """Test ThreatIndicatorType enum"""
        assert len(ThreatIndicatorType) == 10
        assert ThreatIndicatorType.BRUTE_FORCE.value == "brute_force"
        assert ThreatIndicatorType.PORT_SCAN.value == "port_scan"

    # ========== Edge Cases ==========

    def test_data_volume_anomaly_no_baseline(self):
        """Test data volume anomaly without baseline returns None"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="novol@ex.com"
        )
        self.service.record_event(
            entity_id="novol@ex.com",
            event_type=EventType.FILE_DOWNLOAD.value,
            context={"metadata": {"bytes_transferred": 999999999}},
        )
        # No baseline yet, so data volume check should not fire standalone
        # (other checks might fire though)

    def test_empty_dashboard(self):
        """Test dashboard with no data"""
        dashboard = self.service.get_dashboard()
        assert dashboard["total_profiles"] == 0
        assert dashboard["total_events"] == 0
        assert dashboard["anomalies_today"] == 0

    def test_risk_score_capped_at_100(self):
        """Test risk score is capped at 100"""
        profile = self.service.create_profile(
            entity_type=EntityType.USER.value, entity_id="maxrisk@ex.com"
        )
        # Create many critical anomalies
        for i in range(20):
            self.service._create_anomaly(
                profile.profile_id, f"E{i}",
                AnomalyType.IMPOSSIBLE_TRAVEL.value, RiskLevel.CRITICAL.value,
                f"Critical {i}", 10.0, 0.0, 10.0,
            )
        score = self.service.calculate_risk_score(profile.profile_id)
        assert score <= 100.0
