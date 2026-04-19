"""
AITHER Platform - DNS Filtering / Content Filtering Service
Blocks malicious domains, enforces acceptable use policies,
and provides DNS-level security for MSP clients.

Provides:
- Domain categorization and threat detection
- Policy-based query evaluation (allow/block/redirect)
- Custom blocklists and allowlists with feed import
- Safe-search enforcement for Google/Bing/YouTube
- Pre-built category blocking profiles (Security, Business, Education, etc.)
- Query logging and analytics dashboard
- Newly-registered domain detection (< 30 days)

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from collections import Counter

try:
    from sqlalchemy.orm import Session
    from models.dns_filtering import (
        DNSPolicyModel,
        DNSQueryLogModel,
        DomainCategoryModel,
        BlocklistEntryModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class ContentCategory(str, Enum):
    """Content categories for domain classification."""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    ADULT = "adult"
    GAMBLING = "gambling"
    SOCIAL_MEDIA = "social_media"
    STREAMING = "streaming"
    GAMING = "gaming"
    DRUGS = "drugs"
    WEAPONS = "weapons"
    HATE_SPEECH = "hate_speech"
    CRYPTOCURRENCY = "cryptocurrency"
    PROXY_VPN = "proxy_vpn"
    ADVERTISING = "advertising"
    TRACKING = "tracking"
    NEWLY_REGISTERED = "newly_registered"
    PARKED_DOMAINS = "parked_domains"
    FILE_SHARING = "file_sharing"
    HACKING = "hacking"


class QueryAction(str, Enum):
    """Action taken on a DNS query."""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REDIRECTED = "redirected"
    LOGGED = "logged"
    SAFE_SEARCH = "safe_search"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class DNSPolicy:
    """DNS filtering policy definition."""
    policy_id: str
    client_id: str
    name: str
    blocked_categories: List[str] = field(default_factory=list)
    allowed_overrides: List[str] = field(default_factory=list)
    custom_blocklist: List[str] = field(default_factory=list)
    custom_allowlist: List[str] = field(default_factory=list)
    safe_search_enforced: bool = False
    logging_enabled: bool = True
    block_page_url: str = ""
    is_enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class DNSQueryLog:
    """Single DNS query log entry."""
    log_id: str
    client_id: str
    source_ip: str
    device_id: str
    query_domain: str
    query_type: str
    category: str
    action: str  # allowed / blocked / redirected
    policy_id: str
    response_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DomainCategory:
    """Domain categorization record."""
    domain: str
    category: str
    subcategory: str = ""
    confidence: float = 1.0
    source: str = "manual"
    last_verified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class BlocklistEntry:
    """Blocklist or allowlist entry."""
    entry_id: str
    domain_pattern: str
    list_type: str  # blocklist / allowlist
    reason: str = ""
    source: str = "manual"  # manual / feed / threat_intel
    added_by: str = "system"
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


@dataclass
class FilteringStats:
    """Aggregated filtering statistics."""
    client_id: str
    period: str
    total_queries: int = 0
    blocked_queries: int = 0
    allowed_queries: int = 0
    top_blocked_categories: Dict[str, int] = field(default_factory=dict)
    top_blocked_domains: List[str] = field(default_factory=list)
    top_querying_devices: List[str] = field(default_factory=list)


# ============================================================
# Pre-built category blocking profiles
# ============================================================

BLOCKING_PROFILES: Dict[str, List[str]] = {
    "Security Only": [
        ContentCategory.MALWARE,
        ContentCategory.PHISHING,
        ContentCategory.BOTNET,
        ContentCategory.NEWLY_REGISTERED,
    ],
    "Business Standard": [
        ContentCategory.MALWARE,
        ContentCategory.PHISHING,
        ContentCategory.BOTNET,
        ContentCategory.NEWLY_REGISTERED,
        ContentCategory.ADULT,
        ContentCategory.GAMBLING,
        ContentCategory.DRUGS,
        ContentCategory.WEAPONS,
        ContentCategory.HATE_SPEECH,
        ContentCategory.PROXY_VPN,
    ],
    "Education": [
        ContentCategory.MALWARE,
        ContentCategory.PHISHING,
        ContentCategory.BOTNET,
        ContentCategory.NEWLY_REGISTERED,
        ContentCategory.ADULT,
        ContentCategory.GAMBLING,
        ContentCategory.DRUGS,
        ContentCategory.WEAPONS,
        ContentCategory.HATE_SPEECH,
        ContentCategory.PROXY_VPN,
        ContentCategory.SOCIAL_MEDIA,
        ContentCategory.GAMING,
        ContentCategory.STREAMING,
    ],
    "Healthcare": [
        ContentCategory.MALWARE,
        ContentCategory.PHISHING,
        ContentCategory.BOTNET,
        ContentCategory.NEWLY_REGISTERED,
        ContentCategory.ADULT,
        ContentCategory.GAMBLING,
        ContentCategory.DRUGS,
        ContentCategory.WEAPONS,
        ContentCategory.HATE_SPEECH,
        ContentCategory.PROXY_VPN,
        ContentCategory.FILE_SHARING,
        ContentCategory.CRYPTOCURRENCY,
        ContentCategory.HACKING,
    ],
    "Family Safe": [
        ContentCategory.MALWARE,
        ContentCategory.PHISHING,
        ContentCategory.BOTNET,
        ContentCategory.NEWLY_REGISTERED,
        ContentCategory.ADULT,
        ContentCategory.GAMBLING,
        ContentCategory.DRUGS,
        ContentCategory.WEAPONS,
        ContentCategory.HATE_SPEECH,
        ContentCategory.PROXY_VPN,
        ContentCategory.SOCIAL_MEDIA,
        ContentCategory.GAMING,
        ContentCategory.STREAMING,
        ContentCategory.CRYPTOCURRENCY,
        ContentCategory.FILE_SHARING,
        ContentCategory.HACKING,
        ContentCategory.PARKED_DOMAINS,
        ContentCategory.ADVERTISING,
        ContentCategory.TRACKING,
    ],
}

# Safe-search rewrite mappings
SAFE_SEARCH_REWRITES: Dict[str, str] = {
    "www.google.com": "forcesafesearch.google.com",
    "google.com": "forcesafesearch.google.com",
    "www.bing.com": "strict.bing.com",
    "bing.com": "strict.bing.com",
    "www.youtube.com": "restrict.youtube.com",
    "youtube.com": "restrict.youtube.com",
}


# ============================================================
# Service
# ============================================================

class DNSFilteringService:
    """
    DNS Filtering / Content Filtering engine.

    Evaluates DNS queries against client policies, categorizes domains,
    manages block/allow lists, and provides analytics.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback stores
        self._policies: Dict[str, DNSPolicy] = {}
        self._query_logs: List[DNSQueryLog] = []
        self._domain_categories: Dict[str, DomainCategory] = {}
        self._blocklist: Dict[str, BlocklistEntry] = {}
        self._allowlist: Dict[str, BlocklistEntry] = {}

        self._load_initial_data()
        logger.info("DNSFilteringService initialized (db=%s)", self._use_db)

    # ----------------------------------------------------------
    # Initialization
    # ----------------------------------------------------------

    def _load_initial_data(self):
        """Seed well-known domain categories for demo / fast lookup."""
        seed = {
            "malware-domain.example": (ContentCategory.MALWARE, "threat_intel"),
            "phishing-site.example": (ContentCategory.PHISHING, "threat_intel"),
            "botnet-c2.example": (ContentCategory.BOTNET, "threat_intel"),
            "facebook.com": (ContentCategory.SOCIAL_MEDIA, "curated"),
            "twitter.com": (ContentCategory.SOCIAL_MEDIA, "curated"),
            "instagram.com": (ContentCategory.SOCIAL_MEDIA, "curated"),
            "tiktok.com": (ContentCategory.SOCIAL_MEDIA, "curated"),
            "reddit.com": (ContentCategory.SOCIAL_MEDIA, "curated"),
            "netflix.com": (ContentCategory.STREAMING, "curated"),
            "youtube.com": (ContentCategory.STREAMING, "curated"),
            "twitch.tv": (ContentCategory.STREAMING, "curated"),
            "hulu.com": (ContentCategory.STREAMING, "curated"),
            "steampowered.com": (ContentCategory.GAMING, "curated"),
            "epicgames.com": (ContentCategory.GAMING, "curated"),
            "roblox.com": (ContentCategory.GAMING, "curated"),
            "doubleclick.net": (ContentCategory.ADVERTISING, "curated"),
            "googlesyndication.com": (ContentCategory.ADVERTISING, "curated"),
            "ads.yahoo.com": (ContentCategory.ADVERTISING, "curated"),
            "analytics.google.com": (ContentCategory.TRACKING, "curated"),
            "nordvpn.com": (ContentCategory.PROXY_VPN, "curated"),
            "expressvpn.com": (ContentCategory.PROXY_VPN, "curated"),
        }
        for domain, (cat, src) in seed.items():
            if domain not in self._domain_categories:
                self._domain_categories[domain] = DomainCategory(
                    domain=domain, category=cat, source=src,
                )

    # ----------------------------------------------------------
    # Query evaluation (core logic)
    # ----------------------------------------------------------

    def evaluate_query(
        self,
        client_id: str,
        source_ip: str,
        domain: str,
        query_type: str = "A",
        device_id: str = "",
    ) -> Dict[str, Any]:
        """
        Evaluate a DNS query against client policies.
        Returns action (allowed/blocked/redirected) plus metadata.
        """
        import time
        start = time.monotonic()
        domain = domain.lower().strip().rstrip(".")

        # 1. Find active policies for client
        policies = self._get_active_policies(client_id)
        if not policies:
            return self._build_result(
                client_id, source_ip, device_id, domain, query_type,
                "unknown", QueryAction.ALLOWED, "", 0.0,
                reason="no_policy",
            )

        policy = policies[0]  # primary policy

        # 2. Check custom allowlist first (overrides everything)
        if self._check_allowlist(domain, policy):
            elapsed = (time.monotonic() - start) * 1000
            return self._log_and_return(
                client_id, source_ip, device_id, domain, query_type,
                "allowlisted", QueryAction.ALLOWED, policy.policy_id, elapsed,
                reason="allowlist_match",
            )

        # 3. Check custom blocklist
        bl_match = self._check_blocklist(domain)
        if bl_match:
            elapsed = (time.monotonic() - start) * 1000
            return self._log_and_return(
                client_id, source_ip, device_id, domain, query_type,
                bl_match, QueryAction.BLOCKED, policy.policy_id, elapsed,
                reason="blocklist_match", block_page=policy.block_page_url,
            )

        # 4. Categorize domain
        category = self._categorize_domain(domain)

        # 5. Check blocked categories
        if category and category in policy.blocked_categories:
            elapsed = (time.monotonic() - start) * 1000
            return self._log_and_return(
                client_id, source_ip, device_id, domain, query_type,
                category, QueryAction.BLOCKED, policy.policy_id, elapsed,
                reason="category_blocked", block_page=policy.block_page_url,
            )

        # 6. Newly-registered domain check
        if self._is_newly_registered(domain):
            if ContentCategory.NEWLY_REGISTERED in policy.blocked_categories:
                elapsed = (time.monotonic() - start) * 1000
                return self._log_and_return(
                    client_id, source_ip, device_id, domain, query_type,
                    ContentCategory.NEWLY_REGISTERED, QueryAction.BLOCKED,
                    policy.policy_id, elapsed,
                    reason="newly_registered_domain",
                    block_page=policy.block_page_url,
                )

        # 7. Safe-search enforcement
        if policy.safe_search_enforced:
            rewrite = self._enforce_safe_search(domain)
            if rewrite:
                elapsed = (time.monotonic() - start) * 1000
                return self._log_and_return(
                    client_id, source_ip, device_id, domain, query_type,
                    category or "safe_search", QueryAction.SAFE_SEARCH,
                    policy.policy_id, elapsed,
                    reason="safe_search_rewrite", redirect_to=rewrite,
                )

        # 8. Allow
        elapsed = (time.monotonic() - start) * 1000
        return self._log_and_return(
            client_id, source_ip, device_id, domain, query_type,
            category or "uncategorized", QueryAction.ALLOWED,
            policy.policy_id, elapsed, reason="allowed",
        )

    # ----------------------------------------------------------
    # Domain classification helpers
    # ----------------------------------------------------------

    def _categorize_domain(self, domain: str) -> Optional[str]:
        """Lookup domain category from local DB / memory."""
        # Exact match first
        if self._use_db:
            try:
                row = self.db.query(DomainCategoryModel).filter(
                    DomainCategoryModel.domain == domain,
                ).first()
                if row:
                    return row.category
            except Exception:
                pass

        cat = self._domain_categories.get(domain)
        if cat:
            return cat.category

        # Check parent domain (e.g. sub.facebook.com -> facebook.com)
        parts = domain.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            cat = self._domain_categories.get(parent)
            if cat:
                return cat.category
            if self._use_db:
                try:
                    row = self.db.query(DomainCategoryModel).filter(
                        DomainCategoryModel.domain == parent,
                    ).first()
                    if row:
                        return row.category
                except Exception:
                    pass

        return None

    def _check_blocklist(self, domain: str) -> Optional[str]:
        """Check domain against custom + feed blocklists. Returns category or None."""
        now = datetime.now(timezone.utc)

        # DB check
        if self._use_db:
            try:
                rows = self.db.query(BlocklistEntryModel).filter(
                    BlocklistEntryModel.list_type == "blocklist",
                ).all()
                for row in rows:
                    if row.expires_at and row.expires_at < now:
                        continue
                    if fnmatch.fnmatch(domain, row.domain_pattern):
                        return row.reason or "blocklist"
            except Exception:
                pass

        # In-memory
        for entry in self._blocklist.values():
            if entry.expires_at and entry.expires_at < now:
                continue
            if fnmatch.fnmatch(domain, entry.domain_pattern):
                return entry.reason or "blocklist"

        return None

    def _check_allowlist(self, domain: str, policy: DNSPolicy) -> bool:
        """Check domain against policy allowlist overrides."""
        # Policy-level allowlist
        for pattern in policy.custom_allowlist:
            if fnmatch.fnmatch(domain, pattern):
                return True
        for pattern in policy.allowed_overrides:
            if fnmatch.fnmatch(domain, pattern):
                return True

        # Global allowlist
        now = datetime.now(timezone.utc)
        if self._use_db:
            try:
                rows = self.db.query(BlocklistEntryModel).filter(
                    BlocklistEntryModel.list_type == "allowlist",
                ).all()
                for row in rows:
                    if row.expires_at and row.expires_at < now:
                        continue
                    if fnmatch.fnmatch(domain, row.domain_pattern):
                        return True
            except Exception:
                pass

        for entry in self._allowlist.values():
            if entry.expires_at and entry.expires_at < now:
                continue
            if fnmatch.fnmatch(domain, entry.domain_pattern):
                return True

        return False

    def _is_newly_registered(self, domain: str) -> bool:
        """
        Check if domain was registered within the last 30 days.
        In production this would query WHOIS / threat-intel feeds.
        For now, heuristic: domains ending in suspicious TLDs or flagged in DB.
        """
        suspicious_tlds = {".xyz", ".top", ".buzz", ".click", ".gq", ".ml", ".tk", ".cf", ".ga"}
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return True

        cat = self._domain_categories.get(domain)
        if cat and cat.category == ContentCategory.NEWLY_REGISTERED:
            return True

        return False

    def _enforce_safe_search(self, domain: str) -> Optional[str]:
        """Rewrite known search/video domains to their safe-search variants."""
        return SAFE_SEARCH_REWRITES.get(domain)

    # ----------------------------------------------------------
    # Result helpers
    # ----------------------------------------------------------

    def _build_result(
        self, client_id, source_ip, device_id, domain, query_type,
        category, action, policy_id, elapsed_ms, **extra,
    ) -> Dict[str, Any]:
        return {
            "domain": domain,
            "query_type": query_type,
            "category": category,
            "action": action,
            "policy_id": policy_id,
            "response_time_ms": round(elapsed_ms, 2),
            **extra,
        }

    def _log_and_return(
        self, client_id, source_ip, device_id, domain, query_type,
        category, action, policy_id, elapsed_ms, **extra,
    ) -> Dict[str, Any]:
        """Log the query and return result dict."""
        log_entry = DNSQueryLog(
            log_id=f"ql-{uuid.uuid4().hex[:12]}",
            client_id=client_id,
            source_ip=source_ip,
            device_id=device_id,
            query_domain=domain,
            query_type=query_type,
            category=category or "unknown",
            action=action,
            policy_id=policy_id,
            response_time_ms=round(elapsed_ms, 2),
        )
        self._persist_log(log_entry)

        return self._build_result(
            client_id, source_ip, device_id, domain, query_type,
            category, action, policy_id, elapsed_ms, **extra,
        )

    def _persist_log(self, log: DNSQueryLog):
        """Write query log to DB or memory."""
        if self._use_db:
            try:
                row = DNSQueryLogModel(
                    log_id=log.log_id,
                    client_id=log.client_id,
                    source_ip=log.source_ip,
                    device_id=log.device_id,
                    query_domain=log.query_domain,
                    query_type=log.query_type,
                    category=log.category,
                    action=log.action,
                    policy_id=log.policy_id,
                    response_time_ms=log.response_time_ms,
                    timestamp=log.timestamp,
                )
                self.db.add(row)
                self.db.commit()
                return
            except Exception:
                self.db.rollback()
        self._query_logs.append(log)

    # ----------------------------------------------------------
    # Policy CRUD
    # ----------------------------------------------------------

    def _get_active_policies(self, client_id: str) -> List[DNSPolicy]:
        """Return all enabled policies for a client."""
        results = []
        if self._use_db:
            try:
                rows = self.db.query(DNSPolicyModel).filter(
                    DNSPolicyModel.client_id == client_id,
                    DNSPolicyModel.is_enabled == True,
                ).all()
                for r in rows:
                    results.append(self._model_to_policy(r))
                if results:
                    return results
            except Exception:
                pass
        return [p for p in self._policies.values()
                if p.client_id == client_id and p.is_enabled]

    @staticmethod
    def _model_to_policy(row) -> DNSPolicy:
        return DNSPolicy(
            policy_id=row.policy_id,
            client_id=row.client_id,
            name=row.name,
            blocked_categories=row.blocked_categories or [],
            allowed_overrides=row.allowed_overrides or [],
            custom_blocklist=row.custom_blocklist or [],
            custom_allowlist=row.custom_allowlist or [],
            safe_search_enforced=row.safe_search_enforced,
            logging_enabled=row.logging_enabled,
            block_page_url=row.block_page_url or "",
            is_enabled=row.is_enabled,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def create_policy(
        self,
        client_id: str,
        name: str,
        blocked_categories: List[str] = None,
        allowed_overrides: List[str] = None,
        custom_blocklist: List[str] = None,
        custom_allowlist: List[str] = None,
        safe_search_enforced: bool = False,
        logging_enabled: bool = True,
        block_page_url: str = "",
        profile: str = None,
    ) -> Dict[str, Any]:
        """Create a new DNS filtering policy. Optionally use a pre-built profile."""
        policy_id = f"dp-{uuid.uuid4().hex[:12]}"

        cats = list(blocked_categories or [])
        if profile and profile in BLOCKING_PROFILES:
            cats = [c.value if isinstance(c, Enum) else c for c in BLOCKING_PROFILES[profile]]

        policy = DNSPolicy(
            policy_id=policy_id,
            client_id=client_id,
            name=name,
            blocked_categories=cats,
            allowed_overrides=allowed_overrides or [],
            custom_blocklist=custom_blocklist or [],
            custom_allowlist=custom_allowlist or [],
            safe_search_enforced=safe_search_enforced,
            logging_enabled=logging_enabled,
            block_page_url=block_page_url,
        )

        if self._use_db:
            try:
                row = DNSPolicyModel(
                    policy_id=policy.policy_id,
                    client_id=policy.client_id,
                    name=policy.name,
                    blocked_categories=policy.blocked_categories,
                    allowed_overrides=policy.allowed_overrides,
                    custom_blocklist=policy.custom_blocklist,
                    custom_allowlist=policy.custom_allowlist,
                    safe_search_enforced=policy.safe_search_enforced,
                    logging_enabled=policy.logging_enabled,
                    block_page_url=policy.block_page_url,
                    is_enabled=policy.is_enabled,
                )
                self.db.add(row)
                self.db.commit()
            except Exception:
                self.db.rollback()

        self._policies[policy_id] = policy
        logger.info("Created DNS policy %s for client %s", policy_id, client_id)
        return self._policy_to_dict(policy)

    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing DNS policy."""
        policy = self._policies.get(policy_id)

        if self._use_db:
            try:
                row = self.db.query(DNSPolicyModel).filter(
                    DNSPolicyModel.policy_id == policy_id,
                ).first()
                if row:
                    for k, v in updates.items():
                        if hasattr(row, k):
                            setattr(row, k, v)
                    self.db.commit()
                    policy = self._model_to_policy(row)
                    self._policies[policy_id] = policy
                    return self._policy_to_dict(policy)
            except Exception:
                self.db.rollback()

        if not policy:
            raise ValueError(f"Policy {policy_id} not found")

        for k, v in updates.items():
            if hasattr(policy, k):
                setattr(policy, k, v)
        policy.updated_at = datetime.now(timezone.utc)
        return self._policy_to_dict(policy)

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Get a single policy by ID."""
        if self._use_db:
            try:
                row = self.db.query(DNSPolicyModel).filter(
                    DNSPolicyModel.policy_id == policy_id,
                ).first()
                if row:
                    return self._policy_to_dict(self._model_to_policy(row))
            except Exception:
                pass
        policy = self._policies.get(policy_id)
        return self._policy_to_dict(policy) if policy else None

    def list_policies(self, client_id: str = None) -> List[Dict[str, Any]]:
        """List policies, optionally filtered by client."""
        results = []
        if self._use_db:
            try:
                q = self.db.query(DNSPolicyModel)
                if client_id:
                    q = q.filter(DNSPolicyModel.client_id == client_id)
                for row in q.all():
                    results.append(self._policy_to_dict(self._model_to_policy(row)))
                if results:
                    return results
            except Exception:
                pass
        policies = self._policies.values()
        if client_id:
            policies = [p for p in policies if p.client_id == client_id]
        return [self._policy_to_dict(p) for p in policies]

    def toggle_policy(self, policy_id: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable a policy."""
        return self.update_policy(policy_id, {"is_enabled": enabled})

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy."""
        if self._use_db:
            try:
                row = self.db.query(DNSPolicyModel).filter(
                    DNSPolicyModel.policy_id == policy_id,
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
            except Exception:
                self.db.rollback()
        removed = self._policies.pop(policy_id, None)
        return removed is not None or True

    @staticmethod
    def _policy_to_dict(p: DNSPolicy) -> Dict[str, Any]:
        return {
            "policy_id": p.policy_id,
            "client_id": p.client_id,
            "name": p.name,
            "blocked_categories": p.blocked_categories,
            "allowed_overrides": p.allowed_overrides,
            "custom_blocklist": p.custom_blocklist,
            "custom_allowlist": p.custom_allowlist,
            "safe_search_enforced": p.safe_search_enforced,
            "logging_enabled": p.logging_enabled,
            "block_page_url": p.block_page_url,
            "is_enabled": p.is_enabled,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        }

    # ----------------------------------------------------------
    # Blocklist management
    # ----------------------------------------------------------

    def add_to_blocklist(
        self, domain_pattern: str, reason: str = "", source: str = "manual",
        added_by: str = "system", expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Add a domain pattern to the blocklist."""
        entry_id = f"bl-{uuid.uuid4().hex[:12]}"
        entry = BlocklistEntry(
            entry_id=entry_id,
            domain_pattern=domain_pattern,
            list_type="blocklist",
            reason=reason,
            source=source,
            added_by=added_by,
            expires_at=expires_at,
        )
        if self._use_db:
            try:
                row = BlocklistEntryModel(
                    entry_id=entry.entry_id,
                    domain_pattern=entry.domain_pattern,
                    list_type="blocklist",
                    reason=entry.reason,
                    source=entry.source,
                    added_by=entry.added_by,
                    added_at=entry.added_at,
                    expires_at=entry.expires_at,
                )
                self.db.add(row)
                self.db.commit()
            except Exception:
                self.db.rollback()
        self._blocklist[entry_id] = entry
        return self._entry_to_dict(entry)

    def remove_from_blocklist(self, entry_id: str) -> bool:
        """Remove an entry from the blocklist."""
        if self._use_db:
            try:
                row = self.db.query(BlocklistEntryModel).filter(
                    BlocklistEntryModel.entry_id == entry_id,
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
            except Exception:
                self.db.rollback()
        return self._blocklist.pop(entry_id, None) is not None

    def import_blocklist(self, entries: List[Dict[str, str]]) -> Dict[str, Any]:
        """Bulk import blocklist entries. Each entry: {domain, reason?, source?}."""
        imported = 0
        for e in entries:
            self.add_to_blocklist(
                domain_pattern=e.get("domain", e.get("domain_pattern", "")),
                reason=e.get("reason", ""),
                source=e.get("source", "feed"),
            )
            imported += 1
        return {"imported": imported, "total_blocklist": len(self._blocklist)}

    def get_blocklist(self) -> List[Dict[str, Any]]:
        """Return all blocklist entries."""
        if self._use_db:
            try:
                rows = self.db.query(BlocklistEntryModel).filter(
                    BlocklistEntryModel.list_type == "blocklist",
                ).all()
                if rows:
                    return [self._model_entry_to_dict(r) for r in rows]
            except Exception:
                pass
        return [self._entry_to_dict(e) for e in self._blocklist.values()]

    # ----------------------------------------------------------
    # Allowlist management
    # ----------------------------------------------------------

    def add_to_allowlist(
        self, domain_pattern: str, reason: str = "", source: str = "manual",
        added_by: str = "system", expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Add a domain pattern to the global allowlist."""
        entry_id = f"al-{uuid.uuid4().hex[:12]}"
        entry = BlocklistEntry(
            entry_id=entry_id,
            domain_pattern=domain_pattern,
            list_type="allowlist",
            reason=reason,
            source=source,
            added_by=added_by,
            expires_at=expires_at,
        )
        if self._use_db:
            try:
                row = BlocklistEntryModel(
                    entry_id=entry.entry_id,
                    domain_pattern=entry.domain_pattern,
                    list_type="allowlist",
                    reason=entry.reason,
                    source=entry.source,
                    added_by=entry.added_by,
                    added_at=entry.added_at,
                    expires_at=entry.expires_at,
                )
                self.db.add(row)
                self.db.commit()
            except Exception:
                self.db.rollback()
        self._allowlist[entry_id] = entry
        return self._entry_to_dict(entry)

    def remove_from_allowlist(self, entry_id: str) -> bool:
        """Remove an entry from the allowlist."""
        if self._use_db:
            try:
                row = self.db.query(BlocklistEntryModel).filter(
                    BlocklistEntryModel.entry_id == entry_id,
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
            except Exception:
                self.db.rollback()
        return self._allowlist.pop(entry_id, None) is not None

    def get_allowlist(self) -> List[Dict[str, Any]]:
        """Return all allowlist entries."""
        if self._use_db:
            try:
                rows = self.db.query(BlocklistEntryModel).filter(
                    BlocklistEntryModel.list_type == "allowlist",
                ).all()
                if rows:
                    return [self._model_entry_to_dict(r) for r in rows]
            except Exception:
                pass
        return [self._entry_to_dict(e) for e in self._allowlist.values()]

    @staticmethod
    def _entry_to_dict(e: BlocklistEntry) -> Dict[str, Any]:
        return {
            "entry_id": e.entry_id,
            "domain_pattern": e.domain_pattern,
            "list_type": e.list_type,
            "reason": e.reason,
            "source": e.source,
            "added_by": e.added_by,
            "added_at": e.added_at.isoformat() if e.added_at else None,
            "expires_at": e.expires_at.isoformat() if e.expires_at else None,
        }

    @staticmethod
    def _model_entry_to_dict(row) -> Dict[str, Any]:
        return {
            "entry_id": row.entry_id,
            "domain_pattern": row.domain_pattern,
            "list_type": row.list_type,
            "reason": row.reason,
            "source": row.source,
            "added_by": row.added_by,
            "added_at": row.added_at.isoformat() if row.added_at else None,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        }

    # ----------------------------------------------------------
    # Category management
    # ----------------------------------------------------------

    def categorize_domain(
        self, domain: str, category: str, subcategory: str = "",
        confidence: float = 1.0, source: str = "manual",
    ) -> Dict[str, Any]:
        """Set or update the category for a domain."""
        dc = DomainCategory(
            domain=domain, category=category, subcategory=subcategory,
            confidence=confidence, source=source,
        )
        if self._use_db:
            try:
                row = self.db.query(DomainCategoryModel).filter(
                    DomainCategoryModel.domain == domain,
                ).first()
                if row:
                    row.category = category
                    row.subcategory = subcategory
                    row.confidence = confidence
                    row.source = source
                    row.last_verified = datetime.now(timezone.utc)
                else:
                    row = DomainCategoryModel(
                        domain=domain, category=category,
                        subcategory=subcategory, confidence=confidence,
                        source=source,
                    )
                    self.db.add(row)
                self.db.commit()
            except Exception:
                self.db.rollback()
        self._domain_categories[domain] = dc
        return self._cat_to_dict(dc)

    def bulk_categorize(self, entries: List[Dict[str, Any]]) -> Dict[str, int]:
        """Bulk categorize domains. Each entry: {domain, category, subcategory?, confidence?}."""
        count = 0
        for e in entries:
            self.categorize_domain(
                domain=e["domain"],
                category=e["category"],
                subcategory=e.get("subcategory", ""),
                confidence=e.get("confidence", 1.0),
                source=e.get("source", "bulk"),
            )
            count += 1
        return {"categorized": count}

    def get_domain_category(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get the category for a specific domain."""
        if self._use_db:
            try:
                row = self.db.query(DomainCategoryModel).filter(
                    DomainCategoryModel.domain == domain,
                ).first()
                if row:
                    return {
                        "domain": row.domain, "category": row.category,
                        "subcategory": row.subcategory, "confidence": row.confidence,
                        "source": row.source,
                        "last_verified": row.last_verified.isoformat() if row.last_verified else None,
                    }
            except Exception:
                pass
        dc = self._domain_categories.get(domain)
        return self._cat_to_dict(dc) if dc else None

    def list_categories(self) -> List[Dict[str, str]]:
        """Return all available content categories."""
        return [{"name": c.name, "value": c.value} for c in ContentCategory]

    @staticmethod
    def _cat_to_dict(dc: DomainCategory) -> Dict[str, Any]:
        return {
            "domain": dc.domain,
            "category": dc.category,
            "subcategory": dc.subcategory,
            "confidence": dc.confidence,
            "source": dc.source,
            "last_verified": dc.last_verified.isoformat() if dc.last_verified else None,
        }

    # ----------------------------------------------------------
    # Query logs & analytics
    # ----------------------------------------------------------

    def get_query_logs(
        self, client_id: str, action: str = None,
        domain: str = None, limit: int = 100, offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve query logs for a client with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(DNSQueryLogModel).filter(
                    DNSQueryLogModel.client_id == client_id,
                )
                if action:
                    q = q.filter(DNSQueryLogModel.action == action)
                if domain:
                    q = q.filter(DNSQueryLogModel.query_domain.contains(domain))
                q = q.order_by(DNSQueryLogModel.timestamp.desc())
                rows = q.offset(offset).limit(limit).all()
                return [self._log_model_to_dict(r) for r in rows]
            except Exception:
                pass

        logs = [l for l in self._query_logs if l.client_id == client_id]
        if action:
            logs = [l for l in logs if l.action == action]
        if domain:
            logs = [l for l in logs if domain in l.query_domain]
        logs = sorted(logs, key=lambda x: x.timestamp, reverse=True)
        return [self._log_to_dict(l) for l in logs[offset:offset + limit]]

    def get_query_stats(self, client_id: str, period: str = "24h") -> Dict[str, Any]:
        """Get aggregated query statistics for a client."""
        logs = self._get_logs_for_period(client_id, period)

        total = len(logs)
        blocked = sum(1 for l in logs if l.get("action") == QueryAction.BLOCKED)
        allowed = sum(1 for l in logs if l.get("action") in (QueryAction.ALLOWED, QueryAction.LOGGED))

        cat_counter: Counter = Counter()
        domain_counter: Counter = Counter()
        device_counter: Counter = Counter()

        for l in logs:
            if l.get("action") == QueryAction.BLOCKED:
                cat_counter[l.get("category", "unknown")] += 1
                domain_counter[l.get("query_domain", "")] += 1
            if l.get("device_id"):
                device_counter[l["device_id"]] += 1

        return {
            "client_id": client_id,
            "period": period,
            "total_queries": total,
            "blocked_queries": blocked,
            "allowed_queries": allowed,
            "block_rate": round(blocked / total * 100, 1) if total else 0.0,
            "top_blocked_categories": dict(cat_counter.most_common(10)),
            "top_blocked_domains": [d for d, _ in domain_counter.most_common(10)],
            "top_querying_devices": [d for d, _ in device_counter.most_common(10)],
        }

    # ----------------------------------------------------------
    # Analytics helpers
    # ----------------------------------------------------------

    def get_top_blocked_domains(self, client_id: str, limit: int = 20, period: str = "24h") -> List[Dict[str, Any]]:
        """Return the most frequently blocked domains."""
        logs = self._get_logs_for_period(client_id, period)
        counter: Counter = Counter()
        for l in logs:
            if l.get("action") == QueryAction.BLOCKED:
                counter[l.get("query_domain", "")] += 1
        return [{"domain": d, "count": c} for d, c in counter.most_common(limit)]

    def get_top_categories(self, client_id: str, limit: int = 10, period: str = "24h") -> List[Dict[str, Any]]:
        """Return the most frequently hit categories."""
        logs = self._get_logs_for_period(client_id, period)
        counter: Counter = Counter()
        for l in logs:
            counter[l.get("category", "unknown")] += 1
        return [{"category": c, "count": n} for c, n in counter.most_common(limit)]

    def get_query_volume_trend(self, client_id: str, period: str = "24h", buckets: int = 24) -> List[Dict[str, Any]]:
        """Return query volume over time in equal buckets."""
        logs = self._get_logs_for_period(client_id, period)
        if not logs:
            return []

        hours = self._period_to_hours(period)
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)
        bucket_size = timedelta(hours=hours / buckets)

        trend = []
        for i in range(buckets):
            bucket_start = start + bucket_size * i
            bucket_end = bucket_start + bucket_size
            count = sum(
                1 for l in logs
                if bucket_start.isoformat() <= l.get("timestamp", "") < bucket_end.isoformat()
            )
            trend.append({
                "bucket": bucket_start.isoformat(),
                "queries": count,
            })
        return trend

    def get_devices_most_blocked(self, client_id: str, limit: int = 10, period: str = "24h") -> List[Dict[str, Any]]:
        """Return devices with the most blocked queries."""
        logs = self._get_logs_for_period(client_id, period)
        counter: Counter = Counter()
        for l in logs:
            if l.get("action") == QueryAction.BLOCKED and l.get("device_id"):
                counter[l["device_id"]] += 1
        return [{"device_id": d, "blocked_count": c} for d, c in counter.most_common(limit)]

    def get_dashboard(self) -> Dict[str, Any]:
        """Return a global dashboard summary across all clients."""
        all_logs = []
        if self._use_db:
            try:
                rows = self.db.query(DNSQueryLogModel).order_by(
                    DNSQueryLogModel.timestamp.desc(),
                ).limit(5000).all()
                all_logs = [self._log_model_to_dict(r) for r in rows]
            except Exception:
                pass
        if not all_logs:
            all_logs = [self._log_to_dict(l) for l in self._query_logs[-5000:]]

        total = len(all_logs)
        blocked = sum(1 for l in all_logs if l.get("action") == QueryAction.BLOCKED)
        block_rate = round(blocked / total * 100, 1) if total else 0.0

        cat_counter: Counter = Counter()
        for l in all_logs:
            if l.get("action") == QueryAction.BLOCKED:
                cat_counter[l.get("category", "unknown")] += 1

        policies_count = len(self._policies)
        if self._use_db:
            try:
                policies_count = self.db.query(DNSPolicyModel).count()
            except Exception:
                pass

        return {
            "total_queries": total,
            "blocked_queries": blocked,
            "allowed_queries": total - blocked,
            "block_rate": block_rate,
            "top_blocked_categories": dict(cat_counter.most_common(5)),
            "active_policies": policies_count,
            "profiles_available": list(BLOCKING_PROFILES.keys()),
            "categories_available": len(ContentCategory),
        }

    # ----------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------

    def _get_logs_for_period(self, client_id: str, period: str) -> List[Dict[str, Any]]:
        """Fetch logs for a client within a time period."""
        hours = self._period_to_hours(period)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        if self._use_db:
            try:
                rows = self.db.query(DNSQueryLogModel).filter(
                    DNSQueryLogModel.client_id == client_id,
                    DNSQueryLogModel.timestamp >= cutoff,
                ).order_by(DNSQueryLogModel.timestamp.desc()).limit(5000).all()
                if rows:
                    return [self._log_model_to_dict(r) for r in rows]
            except Exception:
                pass

        return [
            self._log_to_dict(l) for l in self._query_logs
            if l.client_id == client_id and l.timestamp >= cutoff
        ]

    @staticmethod
    def _period_to_hours(period: str) -> int:
        mapping = {"1h": 1, "6h": 6, "12h": 12, "24h": 24, "7d": 168, "30d": 720}
        return mapping.get(period, 24)

    @staticmethod
    def _log_to_dict(l: DNSQueryLog) -> Dict[str, Any]:
        return {
            "log_id": l.log_id,
            "client_id": l.client_id,
            "source_ip": l.source_ip,
            "device_id": l.device_id,
            "query_domain": l.query_domain,
            "query_type": l.query_type,
            "category": l.category,
            "action": l.action,
            "policy_id": l.policy_id,
            "response_time_ms": l.response_time_ms,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
        }

    @staticmethod
    def _log_model_to_dict(row) -> Dict[str, Any]:
        return {
            "log_id": row.log_id,
            "client_id": row.client_id,
            "source_ip": row.source_ip,
            "device_id": row.device_id,
            "query_domain": row.query_domain,
            "query_type": row.query_type,
            "category": row.category,
            "action": row.action,
            "policy_id": row.policy_id,
            "response_time_ms": row.response_time_ms,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        }

    def get_profiles(self) -> Dict[str, List[str]]:
        """Return all pre-built blocking profiles."""
        return {
            name: [c.value if isinstance(c, Enum) else c for c in cats]
            for name, cats in BLOCKING_PROFILES.items()
        }
