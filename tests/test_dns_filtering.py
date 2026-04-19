"""
Tests for DNS Filtering / Content Filtering Service
Full coverage of DNSFilteringService operations.
"""

import pytest
from datetime import datetime, timezone, timedelta
from services.msp.dns_filtering import (
    DNSFilteringService,
    ContentCategory,
    QueryAction,
    DNSPolicy,
    DNSQueryLog,
    DomainCategory,
    BlocklistEntry,
    FilteringStats,
    BLOCKING_PROFILES,
    SAFE_SEARCH_REWRITES,
)


@pytest.fixture
def svc():
    """Create a fresh DNSFilteringService with no DB."""
    return DNSFilteringService(db=None)


@pytest.fixture
def svc_with_policy(svc):
    """Service with a Business Standard policy pre-created."""
    svc.create_policy(
        client_id="client-1",
        name="Business Standard",
        profile="Business Standard",
        safe_search_enforced=True,
    )
    return svc


# ==================================================================
# Dataclass / Enum tests
# ==================================================================

class TestEnums:
    def test_content_category_values(self):
        assert ContentCategory.MALWARE == "malware"
        assert ContentCategory.PHISHING == "phishing"
        assert ContentCategory.BOTNET == "botnet"
        assert ContentCategory.SOCIAL_MEDIA == "social_media"
        assert ContentCategory.HACKING == "hacking"
        assert len(ContentCategory) == 19

    def test_query_action_values(self):
        assert QueryAction.ALLOWED == "allowed"
        assert QueryAction.BLOCKED == "blocked"
        assert QueryAction.REDIRECTED == "redirected"
        assert QueryAction.SAFE_SEARCH == "safe_search"
        assert len(QueryAction) == 5


class TestDataclasses:
    def test_dns_policy_defaults(self):
        p = DNSPolicy(policy_id="p1", client_id="c1", name="Test")
        assert p.is_enabled is True
        assert p.blocked_categories == []
        assert p.safe_search_enforced is False

    def test_dns_query_log_defaults(self):
        log = DNSQueryLog(
            log_id="l1", client_id="c1", source_ip="10.0.0.1",
            device_id="d1", query_domain="example.com", query_type="A",
            category="unknown", action="allowed", policy_id="p1",
        )
        assert log.response_time_ms == 0.0
        assert log.timestamp is not None

    def test_domain_category_defaults(self):
        dc = DomainCategory(domain="example.com", category="malware")
        assert dc.confidence == 1.0
        assert dc.source == "manual"

    def test_blocklist_entry_defaults(self):
        e = BlocklistEntry(entry_id="e1", domain_pattern="*.bad.com", list_type="blocklist")
        assert e.source == "manual"
        assert e.expires_at is None

    def test_filtering_stats_defaults(self):
        s = FilteringStats(client_id="c1", period="24h")
        assert s.total_queries == 0
        assert s.top_blocked_categories == {}


# ==================================================================
# Profile tests
# ==================================================================

class TestProfiles:
    def test_profiles_defined(self):
        assert "Security Only" in BLOCKING_PROFILES
        assert "Business Standard" in BLOCKING_PROFILES
        assert "Education" in BLOCKING_PROFILES
        assert "Healthcare" in BLOCKING_PROFILES
        assert "Family Safe" in BLOCKING_PROFILES

    def test_security_only_has_core_threats(self):
        cats = BLOCKING_PROFILES["Security Only"]
        assert ContentCategory.MALWARE in cats
        assert ContentCategory.PHISHING in cats
        assert ContentCategory.BOTNET in cats
        assert ContentCategory.NEWLY_REGISTERED in cats

    def test_business_standard_extends_security(self):
        sec = set(BLOCKING_PROFILES["Security Only"])
        biz = set(BLOCKING_PROFILES["Business Standard"])
        assert sec.issubset(biz)
        assert ContentCategory.ADULT in biz
        assert ContentCategory.GAMBLING in biz

    def test_education_extends_business(self):
        biz = set(BLOCKING_PROFILES["Business Standard"])
        edu = set(BLOCKING_PROFILES["Education"])
        assert biz.issubset(edu)
        assert ContentCategory.SOCIAL_MEDIA in edu
        assert ContentCategory.GAMING in edu
        assert ContentCategory.STREAMING in edu

    def test_family_safe_is_most_restrictive(self):
        fam = BLOCKING_PROFILES["Family Safe"]
        assert len(fam) >= len(BLOCKING_PROFILES["Education"])

    def test_get_profiles_method(self, svc):
        profiles = svc.get_profiles()
        assert "Security Only" in profiles
        for cats in profiles.values():
            for c in cats:
                assert isinstance(c, str)


# ==================================================================
# Policy CRUD
# ==================================================================

class TestPolicyCRUD:
    def test_create_policy_basic(self, svc):
        result = svc.create_policy(client_id="c1", name="Test Policy")
        assert result["client_id"] == "c1"
        assert result["name"] == "Test Policy"
        assert result["policy_id"].startswith("dp-")
        assert result["is_enabled"] is True

    def test_create_policy_with_profile(self, svc):
        result = svc.create_policy(
            client_id="c1", name="Edu Policy", profile="Education",
        )
        assert ContentCategory.SOCIAL_MEDIA.value in result["blocked_categories"]
        assert ContentCategory.MALWARE.value in result["blocked_categories"]

    def test_create_policy_with_custom_categories(self, svc):
        result = svc.create_policy(
            client_id="c1", name="Custom",
            blocked_categories=["malware", "phishing"],
        )
        assert result["blocked_categories"] == ["malware", "phishing"]

    def test_list_policies(self, svc):
        svc.create_policy(client_id="c1", name="P1")
        svc.create_policy(client_id="c2", name="P2")
        all_p = svc.list_policies()
        assert len(all_p) == 2

        c1_p = svc.list_policies(client_id="c1")
        assert len(c1_p) == 1
        assert c1_p[0]["client_id"] == "c1"

    def test_get_policy(self, svc):
        created = svc.create_policy(client_id="c1", name="GetMe")
        fetched = svc.get_policy(created["policy_id"])
        assert fetched is not None
        assert fetched["name"] == "GetMe"

    def test_get_policy_not_found(self, svc):
        assert svc.get_policy("nonexistent") is None

    def test_update_policy(self, svc):
        created = svc.create_policy(client_id="c1", name="Original")
        updated = svc.update_policy(created["policy_id"], {"name": "Updated"})
        assert updated["name"] == "Updated"

    def test_update_policy_not_found(self, svc):
        with pytest.raises(ValueError):
            svc.update_policy("nonexistent", {"name": "nope"})

    def test_toggle_policy(self, svc):
        created = svc.create_policy(client_id="c1", name="Toggle")
        toggled = svc.toggle_policy(created["policy_id"], False)
        assert toggled["is_enabled"] is False
        toggled = svc.toggle_policy(created["policy_id"], True)
        assert toggled["is_enabled"] is True

    def test_delete_policy(self, svc):
        created = svc.create_policy(client_id="c1", name="DeleteMe")
        assert svc.delete_policy(created["policy_id"]) is True
        assert svc.get_policy(created["policy_id"]) is None


# ==================================================================
# Query evaluation
# ==================================================================

class TestQueryEvaluation:
    def test_no_policy_allows(self, svc):
        result = svc.evaluate_query("no-policy-client", "10.0.0.1", "example.com")
        assert result["action"] == QueryAction.ALLOWED
        assert result["reason"] == "no_policy"

    def test_blocked_category(self, svc_with_policy):
        # facebook.com is seeded as social_media; Business Standard doesn't block it
        # but malware-domain.example is seeded as malware, which IS blocked
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "malware-domain.example",
        )
        assert result["action"] == QueryAction.BLOCKED
        assert result["category"] == "malware"

    def test_allowed_domain(self, svc_with_policy):
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "microsoft.com",
        )
        assert result["action"] == QueryAction.ALLOWED

    def test_phishing_blocked(self, svc_with_policy):
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "phishing-site.example",
        )
        assert result["action"] == QueryAction.BLOCKED
        assert result["category"] == "phishing"

    def test_botnet_blocked(self, svc_with_policy):
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "botnet-c2.example",
        )
        assert result["action"] == QueryAction.BLOCKED

    def test_safe_search_enforced(self, svc_with_policy):
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "www.google.com",
        )
        assert result["action"] == QueryAction.SAFE_SEARCH
        assert result["redirect_to"] == "forcesafesearch.google.com"

    def test_safe_search_youtube(self, svc_with_policy):
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "www.youtube.com",
        )
        assert result["action"] == QueryAction.SAFE_SEARCH
        assert result["redirect_to"] == "restrict.youtube.com"

    def test_safe_search_bing(self, svc_with_policy):
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "www.bing.com",
        )
        assert result["action"] == QueryAction.SAFE_SEARCH
        assert result["redirect_to"] == "strict.bing.com"

    def test_allowlist_override(self, svc):
        svc.create_policy(
            client_id="c1", name="WithAllow",
            blocked_categories=["malware"],
            custom_allowlist=["malware-domain.example"],
        )
        result = svc.evaluate_query("c1", "10.0.0.1", "malware-domain.example")
        assert result["action"] == QueryAction.ALLOWED
        assert result["reason"] == "allowlist_match"

    def test_blocklist_match(self, svc):
        svc.create_policy(client_id="c1", name="P1")
        svc.add_to_blocklist("*.evil.com", reason="threat_intel")
        result = svc.evaluate_query("c1", "10.0.0.1", "sub.evil.com")
        assert result["action"] == QueryAction.BLOCKED
        assert result["reason"] == "blocklist_match"

    def test_newly_registered_tld(self, svc):
        svc.create_policy(
            client_id="c1", name="SecPolicy",
            profile="Security Only",
        )
        result = svc.evaluate_query("c1", "10.0.0.1", "sketchy-domain.xyz")
        assert result["action"] == QueryAction.BLOCKED
        assert result["reason"] == "newly_registered_domain"

    def test_subdomain_categorization(self, svc):
        svc.create_policy(
            client_id="c1", name="BizStd",
            blocked_categories=["social_media"],
        )
        result = svc.evaluate_query("c1", "10.0.0.1", "m.facebook.com")
        assert result["action"] == QueryAction.BLOCKED
        assert result["category"] == "social_media"

    def test_response_includes_timing(self, svc_with_policy):
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "example.com",
        )
        assert "response_time_ms" in result
        assert isinstance(result["response_time_ms"], float)

    def test_domain_normalization(self, svc_with_policy):
        result = svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "Malware-Domain.Example.",
        )
        assert result["action"] == QueryAction.BLOCKED


# ==================================================================
# Blocklist / Allowlist management
# ==================================================================

class TestBlocklistAllowlist:
    def test_add_to_blocklist(self, svc):
        entry = svc.add_to_blocklist("*.malicious.net", reason="known-bad")
        assert entry["entry_id"].startswith("bl-")
        assert entry["list_type"] == "blocklist"

    def test_remove_from_blocklist(self, svc):
        entry = svc.add_to_blocklist("bad.com")
        assert svc.remove_from_blocklist(entry["entry_id"]) is True

    def test_import_blocklist(self, svc):
        result = svc.import_blocklist([
            {"domain": "evil1.com", "reason": "threat"},
            {"domain": "evil2.com", "reason": "threat"},
            {"domain": "evil3.com"},
        ])
        assert result["imported"] == 3

    def test_get_blocklist(self, svc):
        svc.add_to_blocklist("a.com")
        svc.add_to_blocklist("b.com")
        bl = svc.get_blocklist()
        assert len(bl) == 2

    def test_add_to_allowlist(self, svc):
        entry = svc.add_to_allowlist("safe.example.com", reason="business-critical")
        assert entry["entry_id"].startswith("al-")
        assert entry["list_type"] == "allowlist"

    def test_remove_from_allowlist(self, svc):
        entry = svc.add_to_allowlist("safe.com")
        assert svc.remove_from_allowlist(entry["entry_id"]) is True

    def test_get_allowlist(self, svc):
        svc.add_to_allowlist("x.com")
        svc.add_to_allowlist("y.com")
        al = svc.get_allowlist()
        assert len(al) == 2

    def test_expired_blocklist_entry_ignored(self, svc):
        svc.create_policy(client_id="c1", name="P1")
        svc.add_to_blocklist(
            "expired.com",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        result = svc.evaluate_query("c1", "10.0.0.1", "expired.com")
        assert result["action"] == QueryAction.ALLOWED

    def test_global_allowlist_override(self, svc):
        svc.create_policy(
            client_id="c1", name="P1",
            blocked_categories=["malware"],
        )
        svc.add_to_allowlist("malware-domain.example")
        result = svc.evaluate_query("c1", "10.0.0.1", "malware-domain.example")
        assert result["action"] == QueryAction.ALLOWED


# ==================================================================
# Category management
# ==================================================================

class TestCategoryManagement:
    def test_categorize_domain(self, svc):
        result = svc.categorize_domain("badsite.com", "malware")
        assert result["domain"] == "badsite.com"
        assert result["category"] == "malware"

    def test_get_domain_category(self, svc):
        svc.categorize_domain("test.com", "gambling", subcategory="casino")
        cat = svc.get_domain_category("test.com")
        assert cat is not None
        assert cat["category"] == "gambling"
        assert cat["subcategory"] == "casino"

    def test_get_domain_category_not_found(self, svc):
        assert svc.get_domain_category("nonexistent.com") is None

    def test_bulk_categorize(self, svc):
        result = svc.bulk_categorize([
            {"domain": "a.com", "category": "adult"},
            {"domain": "b.com", "category": "gambling"},
        ])
        assert result["categorized"] == 2
        assert svc.get_domain_category("a.com")["category"] == "adult"

    def test_list_categories(self, svc):
        cats = svc.list_categories()
        assert len(cats) == 19
        names = [c["name"] for c in cats]
        assert "MALWARE" in names
        assert "PHISHING" in names

    def test_seeded_categories(self, svc):
        assert svc.get_domain_category("facebook.com")["category"] == "social_media"
        assert svc.get_domain_category("netflix.com")["category"] == "streaming"


# ==================================================================
# Logs & Analytics
# ==================================================================

class TestLogsAndAnalytics:
    def test_query_logs_recorded(self, svc_with_policy):
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "example.com")
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "malware-domain.example")
        logs = svc_with_policy.get_query_logs("client-1")
        assert len(logs) >= 2

    def test_query_logs_filter_action(self, svc_with_policy):
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "example.com")
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "malware-domain.example")
        blocked = svc_with_policy.get_query_logs("client-1", action="blocked")
        assert all(l["action"] == "blocked" for l in blocked)

    def test_query_logs_filter_domain(self, svc_with_policy):
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "google.com")
        logs = svc_with_policy.get_query_logs("client-1", domain="google")
        assert len(logs) >= 1

    def test_get_query_stats(self, svc_with_policy):
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "example.com")
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "malware-domain.example")
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "phishing-site.example")
        stats = svc_with_policy.get_query_stats("client-1", "24h")
        assert stats["total_queries"] >= 3
        assert stats["blocked_queries"] >= 2
        assert "block_rate" in stats
        assert "top_blocked_categories" in stats

    def test_top_blocked_domains(self, svc_with_policy):
        for _ in range(3):
            svc_with_policy.evaluate_query("client-1", "10.0.0.1", "malware-domain.example")
        top = svc_with_policy.get_top_blocked_domains("client-1")
        assert len(top) >= 1
        assert top[0]["domain"] == "malware-domain.example"
        assert top[0]["count"] >= 3

    def test_top_categories(self, svc_with_policy):
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "example.com")
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "malware-domain.example")
        cats = svc_with_policy.get_top_categories("client-1")
        assert len(cats) >= 1

    def test_query_volume_trend(self, svc_with_policy):
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "example.com")
        trend = svc_with_policy.get_query_volume_trend("client-1", "24h", 4)
        assert len(trend) == 4
        assert "bucket" in trend[0]
        assert "queries" in trend[0]

    def test_devices_most_blocked(self, svc_with_policy):
        svc_with_policy.evaluate_query(
            "client-1", "10.0.0.1", "malware-domain.example", device_id="dev-1",
        )
        svc_with_policy.evaluate_query(
            "client-1", "10.0.0.2", "phishing-site.example", device_id="dev-2",
        )
        devices = svc_with_policy.get_devices_most_blocked("client-1")
        assert len(devices) >= 1


# ==================================================================
# Dashboard
# ==================================================================

class TestDashboard:
    def test_dashboard_empty(self, svc):
        dash = svc.get_dashboard()
        assert dash["total_queries"] == 0
        assert "profiles_available" in dash
        assert "categories_available" in dash

    def test_dashboard_with_data(self, svc_with_policy):
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "example.com")
        svc_with_policy.evaluate_query("client-1", "10.0.0.1", "malware-domain.example")
        dash = svc_with_policy.get_dashboard()
        assert dash["total_queries"] >= 2
        assert dash["blocked_queries"] >= 1
        assert dash["block_rate"] > 0
        assert "Security Only" in dash["profiles_available"]

    def test_dashboard_policy_count(self, svc):
        svc.create_policy(client_id="c1", name="P1")
        svc.create_policy(client_id="c2", name="P2")
        dash = svc.get_dashboard()
        assert dash["active_policies"] == 2


# ==================================================================
# Edge cases
# ==================================================================

class TestEdgeCases:
    def test_safe_search_rewrites_map(self):
        assert "www.google.com" in SAFE_SEARCH_REWRITES
        assert "www.bing.com" in SAFE_SEARCH_REWRITES
        assert "www.youtube.com" in SAFE_SEARCH_REWRITES

    def test_newly_registered_suspicious_tlds(self, svc):
        svc.create_policy(client_id="c1", name="Sec", profile="Security Only")
        for tld in [".xyz", ".top", ".buzz", ".click", ".tk"]:
            result = svc.evaluate_query("c1", "10.0.0.1", f"random{tld}")
            assert result["action"] == QueryAction.BLOCKED, f"Should block {tld}"

    def test_disabled_policy_not_applied(self, svc):
        created = svc.create_policy(
            client_id="c1", name="Disabled",
            blocked_categories=["malware"],
        )
        svc.toggle_policy(created["policy_id"], False)
        result = svc.evaluate_query("c1", "10.0.0.1", "malware-domain.example")
        assert result["action"] == QueryAction.ALLOWED
        assert result["reason"] == "no_policy"

    def test_empty_domain_handled(self, svc_with_policy):
        result = svc_with_policy.evaluate_query("client-1", "10.0.0.1", "")
        assert result["action"] in (QueryAction.ALLOWED, QueryAction.BLOCKED)

    def test_multiple_policies_uses_first(self, svc):
        svc.create_policy(client_id="c1", name="P1", blocked_categories=["malware"])
        svc.create_policy(client_id="c1", name="P2", blocked_categories=[])
        result = svc.evaluate_query("c1", "10.0.0.1", "malware-domain.example")
        assert result["action"] == QueryAction.BLOCKED

    def test_period_to_hours(self, svc):
        assert svc._period_to_hours("1h") == 1
        assert svc._period_to_hours("7d") == 168
        assert svc._period_to_hours("30d") == 720
        assert svc._period_to_hours("unknown") == 24
