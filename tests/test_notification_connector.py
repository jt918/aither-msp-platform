"""
Tests for Notification Connector Service

Covers:
- backend/services/integrations/notification_connector.py
- Channel CRUD (create, update, delete, list, get)
- Rule CRUD (create, update, delete, list)
- Notification dispatch with rule matching and severity filtering
- Cooldown / throttling logic
- Delivery log queries
- Dashboard statistics
- Dispatcher error handling
- Test channel functionality
- Singleton accessor
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from services.integrations.notification_connector import (
    NotificationConnectorService,
    NotificationChannel,
    NotificationRule,
    NotificationLog,
    ChannelType,
    EventType,
    SeverityLevel,
    NotificationStatus,
    get_notification_connector,
)


# ============================================================
# ENUM TESTS
# ============================================================


class TestChannelTypeEnum:
    """Test channel type enum values."""

    def test_all_types(self):
        assert ChannelType.EMAIL.value == "email"
        assert ChannelType.SLACK.value == "slack"
        assert ChannelType.PAGERDUTY.value == "pagerduty"
        assert ChannelType.MSTEAMS.value == "msteams"
        assert ChannelType.WEBHOOK.value == "webhook"
        assert ChannelType.SMS.value == "sms"

    def test_type_count(self):
        assert len(ChannelType) == 6


class TestEventTypeEnum:
    """Test event type enum values."""

    def test_all_types(self):
        assert EventType.THREAT_DETECTED.value == "threat_detected"
        assert EventType.INCIDENT_CREATED.value == "incident_created"
        assert EventType.ENDPOINT_OFFLINE.value == "endpoint_offline"
        assert EventType.SLA_BREACH.value == "sla_breach"
        assert EventType.PATCH_FAILED.value == "patch_failed"
        assert EventType.SELF_HEAL_FAILED.value == "self_heal_failed"
        assert EventType.BACKUP_FAILED.value == "backup_failed"
        assert EventType.COMPLIANCE_VIOLATION.value == "compliance_violation"

    def test_type_count(self):
        assert len(EventType) == 8


class TestNotificationStatusEnum:
    def test_values(self):
        assert NotificationStatus.SENT.value == "sent"
        assert NotificationStatus.FAILED.value == "failed"
        assert NotificationStatus.THROTTLED.value == "throttled"


# ============================================================
# DATACLASS TESTS
# ============================================================


class TestNotificationChannelDataclass:
    def test_defaults(self):
        ch = NotificationChannel(
            channel_id="ch-1",
            channel_type=ChannelType.SLACK,
            name="Test Slack",
        )
        assert ch.channel_id == "ch-1"
        assert ch.channel_type == ChannelType.SLACK
        assert ch.config == {}
        assert ch.is_enabled is True
        assert ch.updated_at is None


class TestNotificationRuleDataclass:
    def test_defaults(self):
        rule = NotificationRule(
            rule_id="rule-1",
            name="Test Rule",
        )
        assert rule.event_types == []
        assert rule.severity_filter == "all"
        assert rule.channels == []
        assert rule.cooldown_minutes == 5
        assert rule.last_triggered is None


class TestNotificationLogDataclass:
    def test_creation(self):
        log = NotificationLog(
            log_id="log-1",
            rule_id="rule-1",
            channel_id="ch-1",
            event_type="threat_detected",
            severity="critical",
            subject="Test",
            body="Test body",
        )
        assert log.status == "sent"
        assert log.error == ""


# ============================================================
# SERVICE INITIALIZATION TESTS
# ============================================================


class TestServiceInit:
    def test_init_no_db(self):
        svc = NotificationConnectorService()
        assert svc._use_db is False
        assert svc._channels == {}
        assert svc._rules == {}
        assert svc._logs == []

    def test_singleton_accessor(self):
        import services.integrations.notification_connector as mod
        mod._service_instance = None
        s1 = get_notification_connector()
        s2 = get_notification_connector()
        assert s1 is s2
        mod._service_instance = None


# ============================================================
# CHANNEL CRUD TESTS
# ============================================================


class TestChannelCRUD:
    def setup_method(self):
        self.svc = NotificationConnectorService()

    def test_create_channel(self):
        result = self.svc.create_channel(
            channel_type="slack",
            name="Dev Alerts",
            config={"webhook_url": "https://hooks.slack.com/test"},
        )
        assert result["channel_type"] == "slack"
        assert result["name"] == "Dev Alerts"
        assert result["is_enabled"] is True
        assert result["channel_id"].startswith("ch-")

    def test_create_channel_disabled(self):
        result = self.svc.create_channel("email", "Muted Email", is_enabled=False)
        assert result["is_enabled"] is False

    def test_list_channels_empty(self):
        channels = self.svc.list_channels()
        assert channels == []

    def test_list_channels_with_type_filter(self):
        self.svc.create_channel("slack", "Slack 1")
        self.svc.create_channel("email", "Email 1")
        self.svc.create_channel("slack", "Slack 2")

        slack_channels = self.svc.list_channels(channel_type="slack")
        assert len(slack_channels) == 2

        email_channels = self.svc.list_channels(channel_type="email")
        assert len(email_channels) == 1

    def test_list_channels_enabled_only(self):
        self.svc.create_channel("slack", "Enabled", is_enabled=True)
        self.svc.create_channel("slack", "Disabled", is_enabled=False)
        enabled = self.svc.list_channels(enabled_only=True)
        assert len(enabled) == 1

    def test_get_channel(self):
        created = self.svc.create_channel("webhook", "My Hook", config={"url": "https://example.com"})
        fetched = self.svc.get_channel(created["channel_id"])
        assert fetched is not None
        assert fetched["name"] == "My Hook"

    def test_get_channel_not_found(self):
        result = self.svc.get_channel("nonexistent")
        assert result is None

    def test_update_channel(self):
        created = self.svc.create_channel("slack", "Old Name")
        updated = self.svc.update_channel(created["channel_id"], {"name": "New Name"})
        assert updated["name"] == "New Name"

    def test_update_channel_not_found(self):
        result = self.svc.update_channel("nonexistent", {"name": "x"})
        assert result is None

    def test_delete_channel(self):
        created = self.svc.create_channel("email", "To Delete")
        assert self.svc.delete_channel(created["channel_id"]) is True
        assert self.svc.get_channel(created["channel_id"]) is None

    def test_delete_channel_not_found(self):
        assert self.svc.delete_channel("nonexistent") is False


# ============================================================
# RULE CRUD TESTS
# ============================================================


class TestRuleCRUD:
    def setup_method(self):
        self.svc = NotificationConnectorService()

    def test_create_rule(self):
        result = self.svc.create_rule(
            name="Critical Threats",
            event_types=["threat_detected"],
            channels=["ch-abc"],
            severity_filter="critical",
            cooldown_minutes=10,
        )
        assert result["rule_id"].startswith("rule-")
        assert result["name"] == "Critical Threats"
        assert result["event_types"] == ["threat_detected"]
        assert result["severity_filter"] == "critical"
        assert result["cooldown_minutes"] == 10

    def test_list_rules(self):
        self.svc.create_rule("R1", ["threat_detected"], ["ch-1"])
        self.svc.create_rule("R2", ["sla_breach"], ["ch-2"])
        rules = self.svc.list_rules()
        assert len(rules) == 2

    def test_list_rules_enabled_only(self):
        self.svc.create_rule("Enabled", ["threat_detected"], ["ch-1"], is_enabled=True)
        self.svc.create_rule("Disabled", ["sla_breach"], ["ch-2"], is_enabled=False)
        enabled = self.svc.list_rules(enabled_only=True)
        assert len(enabled) == 1

    def test_update_rule(self):
        created = self.svc.create_rule("Old", ["threat_detected"], ["ch-1"])
        updated = self.svc.update_rule(created["rule_id"], {"name": "New", "cooldown_minutes": 30})
        assert updated["name"] == "New"
        assert updated["cooldown_minutes"] == 30

    def test_update_rule_not_found(self):
        result = self.svc.update_rule("nonexistent", {"name": "x"})
        assert result is None

    def test_delete_rule(self):
        created = self.svc.create_rule("Delete Me", ["threat_detected"], ["ch-1"])
        assert self.svc.delete_rule(created["rule_id"]) is True
        assert len(self.svc.list_rules()) == 0

    def test_delete_rule_not_found(self):
        assert self.svc.delete_rule("nonexistent") is False


# ============================================================
# NOTIFICATION DISPATCH TESTS
# ============================================================


class TestSendNotification:
    def setup_method(self):
        self.svc = NotificationConnectorService()
        # Create a channel and a rule
        self.channel = self.svc.create_channel(
            "webhook", "Test Hook", config={"url": "https://example.com"}
        )
        self.rule = self.svc.create_rule(
            name="Threat Rule",
            event_types=["threat_detected"],
            channels=[self.channel["channel_id"]],
            severity_filter="all",
            cooldown_minutes=0,
        )

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_send_matches_rule_and_dispatches(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        result = self.svc.send_notification(
            event_type="threat_detected",
            severity="critical",
            subject="Malware found",
            body="Details here",
        )
        assert result["rules_matched"] == 1
        assert result["total_sent"] == 1
        mock_dispatch.assert_called_once()

    def test_send_no_matching_rules(self):
        result = self.svc.send_notification(
            event_type="backup_failed",
            severity="high",
            subject="Backup",
            body="Failed",
        )
        assert result["rules_matched"] == 0
        assert result["dispatches"] == []

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_send_severity_filter_match(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        # Update rule to only fire on critical
        self.svc.update_rule(self.rule["rule_id"], {"severity_filter": "critical"})

        result = self.svc.send_notification(
            event_type="threat_detected", severity="critical",
            subject="Test", body="Test",
        )
        assert result["rules_matched"] == 1

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_send_severity_filter_no_match(self, mock_dispatch):
        self.svc.update_rule(self.rule["rule_id"], {"severity_filter": "critical"})
        result = self.svc.send_notification(
            event_type="threat_detected", severity="low",
            subject="Test", body="Test",
        )
        assert result["rules_matched"] == 0
        mock_dispatch.assert_not_called()

    @patch.object(NotificationConnectorService, "_dispatch_webhook", side_effect=Exception("Connection refused"))
    def test_send_dispatch_failure_logged(self, mock_dispatch):
        result = self.svc.send_notification(
            event_type="threat_detected", severity="high",
            subject="Test", body="Test",
        )
        assert result["total_failed"] == 1
        assert result["total_sent"] == 0
        assert result["dispatches"][0]["status"] == "failed"
        assert "Connection refused" in result["dispatches"][0]["error"]

    def test_send_disabled_channel_skipped(self):
        self.svc.update_channel(self.channel["channel_id"], {"is_enabled": False})
        result = self.svc.send_notification(
            event_type="threat_detected", severity="high",
            subject="Test", body="Test",
        )
        # Rule matches but channel is disabled, so no dispatches
        assert result["rules_matched"] == 1
        assert result["dispatches"] == []


# ============================================================
# THROTTLING / COOLDOWN TESTS
# ============================================================


class TestThrottling:
    def setup_method(self):
        self.svc = NotificationConnectorService()
        self.channel = self.svc.create_channel("webhook", "Hook", config={"url": "https://example.com"})
        self.rule = self.svc.create_rule(
            name="Throttled Rule",
            event_types=["endpoint_offline"],
            channels=[self.channel["channel_id"]],
            cooldown_minutes=60,
        )

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_first_send_not_throttled(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        result = self.svc.send_notification(
            event_type="endpoint_offline", severity="high",
            subject="Test", body="Test",
        )
        assert result["total_sent"] == 1
        assert result["total_throttled"] == 0

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_second_send_throttled(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        # First send
        self.svc.send_notification(
            event_type="endpoint_offline", severity="high",
            subject="Test", body="Test",
        )
        # Second send within cooldown
        result = self.svc.send_notification(
            event_type="endpoint_offline", severity="high",
            subject="Test 2", body="Test 2",
        )
        assert result["total_throttled"] == 1
        assert result["total_sent"] == 0

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_send_after_cooldown_not_throttled(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        # First send
        self.svc.send_notification(
            event_type="endpoint_offline", severity="high",
            subject="Test", body="Test",
        )
        # Manually expire the cooldown
        rule = self.svc._rules[self.rule["rule_id"]]
        rule.last_triggered = datetime.now(timezone.utc) - timedelta(minutes=61)

        result = self.svc.send_notification(
            event_type="endpoint_offline", severity="high",
            subject="Test 2", body="Test 2",
        )
        assert result["total_sent"] == 1
        assert result["total_throttled"] == 0

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_zero_cooldown_never_throttled(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        self.svc.update_rule(self.rule["rule_id"], {"cooldown_minutes": 0})

        for _ in range(3):
            result = self.svc.send_notification(
                event_type="endpoint_offline", severity="high",
                subject="Test", body="Test",
            )
            assert result["total_sent"] == 1


# ============================================================
# NOTIFICATION LOG TESTS
# ============================================================


class TestNotificationLog:
    def setup_method(self):
        self.svc = NotificationConnectorService()
        ch = self.svc.create_channel("webhook", "Hook", config={"url": "https://example.com"})
        self.ch_id = ch["channel_id"]
        self.svc.create_rule(
            name="Log Rule",
            event_types=["threat_detected", "sla_breach"],
            channels=[self.ch_id],
            cooldown_minutes=0,
        )

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_log_created_on_send(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        self.svc.send_notification(
            event_type="threat_detected", severity="high",
            subject="Test", body="Body",
        )
        logs = self.svc.get_notification_log()
        assert len(logs) == 1
        assert logs[0]["event_type"] == "threat_detected"
        assert logs[0]["status"] == "sent"

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_log_filter_by_event_type(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        self.svc.send_notification("threat_detected", "high", "T1", "B1")
        self.svc.send_notification("sla_breach", "medium", "T2", "B2")
        logs = self.svc.get_notification_log(event_type="sla_breach")
        assert len(logs) == 1

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_log_filter_by_status(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        self.svc.send_notification("threat_detected", "high", "T1", "B1")
        logs = self.svc.get_notification_log(status="sent")
        assert len(logs) == 1
        logs = self.svc.get_notification_log(status="failed")
        assert len(logs) == 0

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_log_filter_by_channel(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        self.svc.send_notification("threat_detected", "high", "T1", "B1")
        logs = self.svc.get_notification_log(channel_id=self.ch_id)
        assert len(logs) == 1
        logs = self.svc.get_notification_log(channel_id="nonexistent")
        assert len(logs) == 0

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_log_limit(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        for _ in range(5):
            self.svc.send_notification("threat_detected", "high", "T", "B")
        logs = self.svc.get_notification_log(limit=3)
        assert len(logs) == 3


# ============================================================
# DASHBOARD TESTS
# ============================================================


class TestDashboard:
    def setup_method(self):
        self.svc = NotificationConnectorService()

    def test_empty_dashboard(self):
        dash = self.svc.get_dashboard()
        assert dash["total_channels"] == 0
        assert dash["total_rules"] == 0
        assert dash["total_notifications"] == 0
        assert dash["sent"] == 0
        assert dash["failed"] == 0
        assert dash["throttled"] == 0
        assert "generated_at" in dash

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_dashboard_after_activity(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}

        ch = self.svc.create_channel("webhook", "Hook", config={"url": "https://example.com"})
        self.svc.create_channel("slack", "Slack", config={"webhook_url": "https://slack.com"})
        self.svc.create_rule(
            "R1", ["threat_detected"], [ch["channel_id"]], cooldown_minutes=0,
        )

        self.svc.send_notification("threat_detected", "high", "S", "B")
        self.svc.send_notification("threat_detected", "low", "S", "B")

        dash = self.svc.get_dashboard()
        assert dash["total_channels"] == 2
        assert dash["enabled_channels"] == 2
        assert dash["total_rules"] == 1
        assert dash["sent"] == 2
        assert dash["channels_by_type"]["webhook"] == 1
        assert dash["channels_by_type"]["slack"] == 1
        assert dash["notifications_by_event"]["threat_detected"] == 2


# ============================================================
# TEST CHANNEL TESTS
# ============================================================


class TestTestChannel:
    def setup_method(self):
        self.svc = NotificationConnectorService()

    def test_test_channel_not_found(self):
        result = self.svc.test_channel("nonexistent")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @patch.object(NotificationConnectorService, "_dispatch_slack")
    def test_test_channel_success(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        ch = self.svc.create_channel("slack", "Test Slack", config={"webhook_url": "https://hooks.slack.com/x"})
        result = self.svc.test_channel(ch["channel_id"])
        assert result["success"] is True
        mock_dispatch.assert_called_once()

    @patch.object(NotificationConnectorService, "_dispatch_email", side_effect=Exception("SMTP error"))
    def test_test_channel_failure(self, mock_dispatch):
        ch = self.svc.create_channel("email", "Broken Email")
        result = self.svc.test_channel(ch["channel_id"])
        assert result["success"] is False
        assert "SMTP error" in result["error"]


# ============================================================
# DISPATCHER UNIT TESTS
# ============================================================


class TestDispatchers:
    def setup_method(self):
        self.svc = NotificationConnectorService()

    def test_get_dispatcher_invalid(self):
        with pytest.raises(ValueError, match="Unsupported channel type"):
            self.svc._get_dispatcher("carrier_pigeon")

    def test_get_dispatcher_all_types(self):
        for ct in ChannelType:
            dispatcher = self.svc._get_dispatcher(ct.value)
            assert callable(dispatcher)

    @patch("services.integrations.notification_connector.smtplib", create=True)
    def test_dispatch_email_raises_on_failure(self, mock_smtp):
        """Email dispatcher should propagate exceptions."""
        # The real smtplib import is inside the method; we test via integration
        with pytest.raises(Exception):
            self.svc._dispatch_email(
                config={"smtp_host": "bad-host", "smtp_port": 587, "to_addresses": ["a@b.com"]},
                subject="Test",
                body="Test body",
            )

    @patch("httpx.post", side_effect=Exception("Connection failed"))
    def test_dispatch_slack_raises_on_failure(self, mock_post):
        with pytest.raises(Exception, match="Connection failed"):
            self.svc._dispatch_slack(
                config={"webhook_url": "https://hooks.slack.com/bad"},
                subject="Test",
                body="Test body",
            )

    @patch("httpx.post", side_effect=Exception("PD error"))
    def test_dispatch_pagerduty_raises_on_failure(self, mock_post):
        with pytest.raises(Exception, match="PD error"):
            self.svc._dispatch_pagerduty(
                config={"routing_key": "fake-key"},
                subject="Test",
                body="Test body",
            )

    @patch("httpx.post", side_effect=Exception("Teams error"))
    def test_dispatch_msteams_raises_on_failure(self, mock_post):
        with pytest.raises(Exception, match="Teams error"):
            self.svc._dispatch_msteams(
                config={"webhook_url": "https://teams.microsoft.com/bad"},
                subject="Test",
                body="Test body",
            )

    @patch("httpx.request", side_effect=Exception("Hook error"))
    def test_dispatch_webhook_raises_on_failure(self, mock_req):
        with pytest.raises(Exception, match="Hook error"):
            self.svc._dispatch_webhook(
                config={"url": "https://example.com/hook"},
                subject="Test",
                body="Test body",
            )

    @patch("httpx.post", side_effect=Exception("Twilio error"))
    def test_dispatch_sms_raises_on_failure(self, mock_post):
        with pytest.raises(Exception, match="Twilio error"):
            self.svc._dispatch_sms(
                config={
                    "account_sid": "AC123",
                    "auth_token": "tok",
                    "from_number": "+1111",
                    "to_numbers": ["+2222"],
                },
                subject="Test",
                body="Test body",
            )


# ============================================================
# MULTI-CHANNEL / MULTI-RULE TESTS
# ============================================================


class TestMultiChannelRouting:
    def setup_method(self):
        self.svc = NotificationConnectorService()
        self.ch1 = self.svc.create_channel("webhook", "Hook 1", config={"url": "https://a.com"})
        self.ch2 = self.svc.create_channel("webhook", "Hook 2", config={"url": "https://b.com"})

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_rule_with_multiple_channels(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        self.svc.create_rule(
            "Multi-Ch",
            ["threat_detected"],
            [self.ch1["channel_id"], self.ch2["channel_id"]],
            cooldown_minutes=0,
        )
        result = self.svc.send_notification("threat_detected", "high", "S", "B")
        assert result["total_sent"] == 2
        assert mock_dispatch.call_count == 2

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_multiple_rules_same_event(self, mock_dispatch):
        mock_dispatch.return_value = {"delivered": True}
        self.svc.create_rule("R1", ["threat_detected"], [self.ch1["channel_id"]], cooldown_minutes=0)
        self.svc.create_rule("R2", ["threat_detected"], [self.ch2["channel_id"]], cooldown_minutes=0)
        result = self.svc.send_notification("threat_detected", "high", "S", "B")
        assert result["rules_matched"] == 2
        assert result["total_sent"] == 2

    @patch.object(NotificationConnectorService, "_dispatch_webhook")
    def test_disabled_rule_not_matched(self, mock_dispatch):
        self.svc.create_rule(
            "Disabled",
            ["threat_detected"],
            [self.ch1["channel_id"]],
            is_enabled=False,
            cooldown_minutes=0,
        )
        result = self.svc.send_notification("threat_detected", "high", "S", "B")
        assert result["rules_matched"] == 0
        mock_dispatch.assert_not_called()
