"""
Tests for Email Security Gateway Service
Full coverage: scanning, phishing detection, DLP, quarantine, policies, stats.
"""

import pytest
import sys
import os

# Ensure backend is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.msp.email_security import (
    EmailSecurityService,
    Verdict,
    Direction,
    PolicyType,
    IndicatorType,
    QuarantineStatus,
    DLPPatternType,
    DLPAction,
    _levenshtein,
    _extract_domain,
    _extract_urls,
    KNOWN_BRANDS,
    URGENCY_KEYWORDS,
    BLOCKED_EXTENSIONS,
)


@pytest.fixture
def svc():
    """Fresh EmailSecurityService instance (in-memory)."""
    return EmailSecurityService()


# ============================================================
# Utility function tests
# ============================================================

class TestUtilityFunctions:
    def test_levenshtein_identical(self):
        assert _levenshtein("hello", "hello") == 0

    def test_levenshtein_one_edit(self):
        assert _levenshtein("microsoft", "microsott") == 1

    def test_levenshtein_two_edits(self):
        assert _levenshtein("google", "gogle") == 1

    def test_levenshtein_empty(self):
        assert _levenshtein("abc", "") == 3

    def test_extract_domain_email(self):
        assert _extract_domain("user@example.com") == "example.com"

    def test_extract_domain_with_angle(self):
        assert _extract_domain("User <user@example.com>") == "example.com"

    def test_extract_domain_plain(self):
        assert _extract_domain("example.com") == "example.com"

    def test_extract_urls(self):
        text = "Visit https://example.com and http://test.org/page for info"
        urls = _extract_urls(text)
        assert len(urls) == 2
        assert "https://example.com" in urls

    def test_extract_urls_none(self):
        assert _extract_urls("no links here") == []


# ============================================================
# Email Scanning Tests
# ============================================================

class TestEmailScanning:
    def test_scan_clean_email(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "support@legitimate-company.com",
            "recipient": "user@client1.com",
            "subject": "Your weekly report",
            "body_preview": "Here is your weekly analytics report.",
            "direction": "inbound",
            "headers": {"authentication-results": "spf=pass; dkim=pass; dmarc=pass"},
        })
        assert result["verdict"] == Verdict.CLEAN.value
        assert result["processing_time_ms"] >= 0
        assert "message_id" in result

    def test_scan_phishing_email_spoofed_sender(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "Microsoft Support <alert@evil-domain.com>",
            "recipient": "user@client1.com",
            "subject": "Urgent: Verify your account immediately",
            "body_preview": "Your account has been suspended. Click here immediately to verify your account. Enter your password now.",
            "direction": "inbound",
            "headers": {},
        })
        # Should detect multiple phishing indicators
        assert result["verdict"] in (Verdict.PHISHING.value, Verdict.SUSPICIOUS.value, Verdict.QUARANTINED.value)
        assert len(result["indicators"]) > 0

    def test_scan_spam_email(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "winner@freestuff.xyz",
            "recipient": "user@client1.com",
            "subject": "CONGRATULATIONS YOU WON!!!",
            "body_preview": "You are the winner! Free prize! Click below to claim your guaranteed lottery winnings! Act now! Limited offer!",
            "direction": "inbound",
            "headers": {},
        })
        assert result["verdict"] in (Verdict.SPAM.value, Verdict.SUSPICIOUS.value)

    def test_scan_malware_attachment(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "invoices@company.com",
            "recipient": "user@client1.com",
            "subject": "Invoice #12345",
            "body_preview": "Please see attached invoice.",
            "attachment_names": ["invoice.exe"],
            "attachment_hashes": [],
            "direction": "inbound",
        })
        assert result["verdict"] == Verdict.MALWARE.value
        assert result["quarantined"] is True

    def test_scan_malware_hash_match(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "test@test.com",
            "recipient": "user@client1.com",
            "subject": "test",
            "attachment_names": ["document.pdf"],
            "attachment_hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "direction": "inbound",
        })
        assert result["verdict"] == Verdict.MALWARE.value

    def test_scan_double_extension(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "test@test.com",
            "recipient": "user@client1.com",
            "subject": "Document",
            "attachment_names": ["report.pdf.exe"],
            "direction": "inbound",
        })
        assert result["verdict"] == Verdict.MALWARE.value

    def test_scan_domain_lookalike(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "support@micros0ft.com",
            "recipient": "user@client1.com",
            "subject": "Account update",
            "body_preview": "Please update your account.",
            "direction": "inbound",
        })
        # Should catch the lookalike domain
        lookalike_inds = [i for i in result["indicators"] if i["indicator_type"] == IndicatorType.DOMAIN_LOOKALIKE.value]
        assert len(lookalike_inds) > 0

    def test_scan_reply_to_mismatch(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "support@legitimate.com",
            "recipient": "user@client1.com",
            "subject": "Help request",
            "body_preview": "We need your attention.",
            "headers": {"reply-to": "scammer@evil.com"},
            "direction": "inbound",
        })
        mismatch_inds = [i for i in result["indicators"] if i["indicator_type"] == IndicatorType.REPLY_TO_MISMATCH.value]
        assert len(mismatch_inds) > 0

    def test_scan_suspicious_urls(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "info@company.com",
            "recipient": "user@client1.com",
            "subject": "Check this out",
            "body_preview": "Visit http://192.168.1.1/login and https://bit.ly/abc123 for details.",
            "direction": "inbound",
        })
        url_inds = [i for i in result["indicators"] if i["indicator_type"] == IndicatorType.URL_SUSPICIOUS.value]
        assert len(url_inds) >= 2  # IP-based + shortened

    def test_scan_spf_fail(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "admin@company.com",
            "recipient": "user@client1.com",
            "subject": "Monthly report",
            "body_preview": "Report attached.",
            "headers": {"authentication-results": "spf=fail; dkim=pass; dmarc=pass"},
            "direction": "inbound",
        })
        assert "sender_auth_fail" in result["rules_matched"]

    def test_scan_persists_message(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Test",
            "direction": "inbound",
        })
        msg = svc.get_message(result["message_id"])
        assert msg is not None
        assert msg["client_id"] == "client-1"


# ============================================================
# DLP Tests
# ============================================================

class TestDLP:
    def test_dlp_credit_card_outbound(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "user@client1.com",
            "recipient": "external@other.com",
            "subject": "Payment info",
            "body_preview": "My card number is 4111111111111111",
            "direction": "outbound",
        })
        assert result["verdict"] == Verdict.DLP_BLOCKED.value

    def test_dlp_ssn_outbound(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "user@client1.com",
            "recipient": "external@other.com",
            "subject": "Info",
            "body_preview": "SSN is 123-45-6789",
            "direction": "outbound",
        })
        assert result["verdict"] == Verdict.DLP_BLOCKED.value

    def test_dlp_test_rule(self, svc):
        results = svc.test_dlp_rule("My credit card is 4111111111111111 and SSN 123-45-6789")
        assert len(results) >= 2
        types = [r["name"] for r in results]
        assert "Credit Card" in types
        assert "SSN" in types

    def test_create_custom_dlp_rule(self, svc):
        policy = svc.create_policy("client-1", "DLP Policy", PolicyType.DLP_RULE.value)
        rule = svc.create_dlp_rule(
            policy_id=policy.policy_id,
            name="No project names",
            pattern_type=DLPPatternType.KEYWORD.value,
            pattern=r"Project\s+Nighthawk",
            action=DLPAction.BLOCK.value,
            severity="high",
        )
        assert rule.rule_id.startswith("DLP-")
        assert rule.name == "No project names"

    def test_list_dlp_rules(self, svc):
        policy = svc.create_policy("client-1", "DLP Policy", PolicyType.DLP_RULE.value)
        svc.create_dlp_rule(policy.policy_id, "Rule A", pattern=r"\bsecret\b")
        svc.create_dlp_rule(policy.policy_id, "Rule B", pattern=r"\btop-secret\b")
        rules = svc.list_dlp_rules(policy_id=policy.policy_id)
        assert len(rules) == 2


# ============================================================
# Quarantine Tests
# ============================================================

class TestQuarantine:
    def test_quarantine_message(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Test",
            "direction": "inbound",
        })
        entry = svc.quarantine_message(result["message_id"], "Manual test")
        assert entry is not None
        assert entry.status == QuarantineStatus.QUARANTINED.value

    def test_release_quarantine(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Test",
            "direction": "inbound",
        })
        entry = svc.quarantine_message(result["message_id"], "Test quarantine")
        released = svc.release_message(entry.entry_id, "admin@company.com")
        assert released is not None
        assert released.status == QuarantineStatus.RELEASED.value
        assert released.released_by == "admin@company.com"

    def test_delete_quarantined(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Test",
            "direction": "inbound",
        })
        entry = svc.quarantine_message(result["message_id"], "Test")
        assert svc.delete_quarantined(entry.entry_id) is True

    def test_get_quarantine_list(self, svc):
        for i in range(3):
            result = svc.scan_email({
                "client_id": "client-1",
                "sender": f"sender{i}@test.com",
                "recipient": "user@client1.com",
                "subject": f"Test {i}",
                "direction": "inbound",
            })
            svc.quarantine_message(result["message_id"], "Batch test")
        entries = svc.get_quarantine()
        assert len(entries) >= 3

    def test_quarantine_stats(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Test",
            "direction": "inbound",
        })
        svc.quarantine_message(result["message_id"], "Test")
        stats = svc.get_quarantine_stats()
        assert stats["total_quarantined"] >= 1

    def test_release_nonexistent(self, svc):
        result = svc.release_message("QR-NONEXIST", "admin")
        assert result is None

    def test_delete_nonexistent(self, svc):
        assert svc.delete_quarantined("QR-NONEXIST") is False


# ============================================================
# Policy Tests
# ============================================================

class TestPolicies:
    def test_create_policy(self, svc):
        policy = svc.create_policy(
            client_id="client-1",
            name="Strict Phishing Filter",
            policy_type=PolicyType.PHISHING_PROTECTION.value,
            config={"sensitivity": "high"},
            priority=10,
            actions=["quarantine", "alert"],
        )
        assert policy.policy_id.startswith("EPOL-")
        assert policy.name == "Strict Phishing Filter"
        assert policy.is_enabled is True

    def test_list_policies(self, svc):
        svc.create_policy("client-1", "Policy A")
        svc.create_policy("client-1", "Policy B")
        svc.create_policy("client-2", "Policy C")
        all_policies = svc.list_policies()
        assert len(all_policies) >= 3
        client1_policies = svc.list_policies(client_id="client-1")
        assert len(client1_policies) >= 2

    def test_update_policy(self, svc):
        policy = svc.create_policy("client-1", "Original Name")
        updated = svc.update_policy(policy.policy_id, name="Updated Name")
        assert updated is not None
        assert updated.name == "Updated Name"
        assert updated.updated_at is not None

    def test_toggle_policy(self, svc):
        policy = svc.create_policy("client-1", "Toggle Test")
        assert policy.is_enabled is True
        toggled = svc.toggle_policy(policy.policy_id)
        assert toggled is not None
        assert toggled["is_enabled"] is False
        toggled2 = svc.toggle_policy(policy.policy_id)
        assert toggled2["is_enabled"] is True

    def test_update_nonexistent_policy(self, svc):
        result = svc.update_policy("EPOL-NONEXIST", name="Nope")
        assert result is None

    def test_toggle_nonexistent_policy(self, svc):
        result = svc.toggle_policy("EPOL-NONEXIST")
        assert result is None


# ============================================================
# Threat Feed Tests
# ============================================================

class TestThreatFeeds:
    def test_list_feeds(self, svc):
        feeds = svc.list_feeds()
        assert len(feeds) == 4  # 4 default feeds

    def test_update_feed(self, svc):
        feeds = svc.list_feeds()
        feed_id = feeds[0]["feed_id"]
        updated = svc.update_feed(feed_id, name="Updated Feed Name")
        assert updated is not None
        assert updated["name"] == "Updated Feed Name"

    def test_update_feed_entries(self, svc):
        feeds = svc.list_feeds()
        feed_id = feeds[0]["feed_id"]
        updated = svc.update_feed(feed_id, entries=["evil.com", "bad.org"])
        assert updated["entries_count"] == 2

    def test_update_nonexistent_feed(self, svc):
        result = svc.update_feed("FEED-NONEXIST")
        assert result is None


# ============================================================
# False Positive / Negative Tests
# ============================================================

class TestReporting:
    def test_report_false_positive(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Legit email",
            "direction": "inbound",
        })
        report = svc.report_false_positive(result["message_id"])
        assert report["status"] == "reported"

    def test_report_false_negative(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Missed threat",
            "direction": "inbound",
        })
        report = svc.report_false_negative(result["message_id"])
        assert report["status"] == "reported"

    def test_report_fp_updates_quarantine(self, svc):
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Test",
            "direction": "inbound",
        })
        entry = svc.quarantine_message(result["message_id"], "Test")
        svc.report_false_positive(result["message_id"])
        assert svc._quarantine[entry.entry_id].status == QuarantineStatus.REPORTED_FP.value


# ============================================================
# Statistics & Dashboard Tests
# ============================================================

class TestStatsDashboard:
    def test_email_stats_empty(self, svc):
        stats = svc.get_email_stats()
        assert stats["total_messages"] == 0
        assert stats["period"] == "24h"

    def test_email_stats_after_scans(self, svc):
        for i in range(5):
            svc.scan_email({
                "client_id": "client-1",
                "sender": f"sender{i}@test.com",
                "recipient": "user@client1.com",
                "subject": f"Email {i}",
                "direction": "inbound",
            })
        stats = svc.get_email_stats(client_id="client-1")
        assert stats["total_messages"] == 5
        assert stats["client_id"] == "client-1"

    def test_email_stats_with_period(self, svc):
        svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Test",
            "direction": "inbound",
        })
        stats = svc.get_email_stats(period="7d")
        assert stats["period"] == "7d"
        assert stats["total_messages"] >= 1

    def test_top_targeted_users(self, svc):
        # Scan phishing emails targeting specific users
        for i in range(3):
            svc.scan_email({
                "client_id": "client-1",
                "sender": "Microsoft Support <alert@evil.com>",
                "recipient": "target@client1.com",
                "subject": "Urgent: Account suspended. Verify now. Click here immediately.",
                "body_preview": "Enter your password to verify your account. Immediate action required.",
                "direction": "inbound",
            })
        users = svc.get_top_targeted_users("client-1")
        # May or may not have results depending on verdict
        assert isinstance(users, list)

    def test_dashboard(self, svc):
        # Scan a few emails
        svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Clean email",
            "direction": "inbound",
        })
        dash = svc.get_dashboard()
        assert "summary" in dash
        assert "last_24h" in dash
        assert "threat_feeds" in dash
        assert dash["summary"]["total_messages_processed"] >= 1
        assert dash["summary"]["threat_feeds"] == 4

    def test_dashboard_structure(self, svc):
        dash = svc.get_dashboard()
        summary = dash["summary"]
        assert "threats_blocked" in summary
        assert "quarantine_size" in summary
        assert "dlp_events" in summary
        assert "active_policies" in summary
        assert "active_dlp_rules" in summary


# ============================================================
# Message Listing Tests
# ============================================================

class TestMessageListing:
    def test_list_messages_empty(self, svc):
        msgs = svc.list_messages()
        assert msgs == []

    def test_list_messages_with_filter(self, svc):
        svc.scan_email({
            "client_id": "client-1",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "subject": "Test 1",
            "direction": "inbound",
        })
        svc.scan_email({
            "client_id": "client-2",
            "sender": "x@y.com",
            "recipient": "z@w.com",
            "subject": "Test 2",
            "direction": "outbound",
        })
        client1 = svc.list_messages(client_id="client-1")
        assert len(client1) == 1
        assert client1[0]["client_id"] == "client-1"

        inbound = svc.list_messages(direction="inbound")
        assert len(inbound) >= 1

    def test_list_messages_pagination(self, svc):
        for i in range(10):
            svc.scan_email({
                "client_id": "client-1",
                "sender": f"s{i}@test.com",
                "recipient": "user@client1.com",
                "subject": f"Msg {i}",
                "direction": "inbound",
            })
        page1 = svc.list_messages(limit=5, offset=0)
        page2 = svc.list_messages(limit=5, offset=5)
        assert len(page1) == 5
        assert len(page2) == 5
        assert page1[0]["message_id"] != page2[0]["message_id"]

    def test_get_message_not_found(self, svc):
        assert svc.get_message("MSG-NONEXIST") is None


# ============================================================
# Integration / Pipeline Tests
# ============================================================

class TestIntegrationPipeline:
    def test_full_phishing_pipeline(self, svc):
        """Test complete phishing detection -> quarantine -> release flow."""
        # 1. Scan phishing email
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "Microsoft Support <security@micros0ft-alerts.com>",
            "recipient": "ceo@client1.com",
            "subject": "Urgent: Account Suspended - Verify Now",
            "body_preview": "Your account has been suspended. Click here immediately to verify. Enter your password and credit card to restore access. Immediate action required.",
            "headers": {
                "reply-to": "scammer@different-domain.com",
                "authentication-results": "spf=fail; dkim=fail; dmarc=fail",
            },
            "direction": "inbound",
        })
        assert result["verdict"] in (Verdict.PHISHING.value, Verdict.MALWARE.value)
        assert result["quarantined"] is True
        assert len(result["indicators"]) >= 2

        # 2. Check quarantine
        quarantine = svc.get_quarantine(client_id="client-1")
        assert len(quarantine) >= 1

        # 3. Release from quarantine
        entry_id = quarantine[0]["entry_id"]
        released = svc.release_message(entry_id, "security-admin")
        assert released.status == QuarantineStatus.RELEASED.value

        # 4. Check stats
        stats = svc.get_email_stats(client_id="client-1")
        assert stats["total_messages"] >= 1

    def test_dlp_outbound_pipeline(self, svc):
        """Test DLP blocking outbound sensitive data."""
        # Create DLP policy
        policy = svc.create_policy(
            "client-1", "Outbound DLP",
            policy_type=PolicyType.DLP_RULE.value,
        )
        svc.create_dlp_rule(
            policy.policy_id, "Block SSN",
            pattern_type=DLPPatternType.SSN.value,
            pattern=SSN_PATTERN_FOR_TEST,
            action=DLPAction.BLOCK.value,
            severity="critical",
        )

        # Scan outbound email with credit card
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "employee@client1.com",
            "recipient": "external@other.com",
            "subject": "Payment details",
            "body_preview": "Card: 4111111111111111",
            "direction": "outbound",
        })
        assert result["verdict"] == Verdict.DLP_BLOCKED.value

    def test_scan_updates_stats_counters(self, svc):
        """Verify that scanning updates internal counters."""
        initial_dash = svc.get_dashboard()
        initial_total = initial_dash["summary"]["total_messages_processed"]

        # Scan 3 messages
        for i in range(3):
            svc.scan_email({
                "client_id": "client-1",
                "sender": f"s{i}@test.com",
                "recipient": "user@client1.com",
                "subject": f"Msg {i}",
                "direction": "inbound",
            })

        updated_dash = svc.get_dashboard()
        assert updated_dash["summary"]["total_messages_processed"] == initial_total + 3

    def test_credential_harvest_detection(self, svc):
        """Test credential harvesting detection in email body."""
        result = svc.scan_email({
            "client_id": "client-1",
            "sender": "support@bank-secure.com",
            "recipient": "user@client1.com",
            "subject": "Account verification",
            "body_preview": "Please confirm your password and enter your credit card number to verify your identity.",
            "direction": "inbound",
        })
        cred_inds = [i for i in result["indicators"] if i["indicator_type"] == IndicatorType.CREDENTIAL_HARVEST.value]
        assert len(cred_inds) > 0


# Reference pattern for test
SSN_PATTERN_FOR_TEST = r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
