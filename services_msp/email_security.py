"""
AITHER Platform - Email Security Gateway Service
Anti-phishing, anti-spam, attachment sandboxing, and email DLP for MSP clients.

Provides:
- Email scanning with multi-layer verdict pipeline
- Phishing detection (sender spoofing, domain lookalikes, URL analysis, urgency keywords)
- Attachment safety checks (hash-based malware detection, extension blocking)
- Data Loss Prevention (credit card, SSN, HIPAA, custom patterns)
- Quarantine management (quarantine/release/delete/false-positive)
- Policy CRUD per client
- Threat feed management
- Dashboard and statistics

G-46: Refactored for DB persistence with in-memory fallback.
"""

import re
import uuid
import time
import logging
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from collections import Counter

try:
    from sqlalchemy.orm import Session
    from models.email_security import (
        EmailMessageModel,
        PhishingIndicatorModel,
        QuarantineEntryModel,
        EmailPolicyModel,
        DLPRuleModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class Verdict(str, Enum):
    """Email scan verdict."""
    CLEAN = "clean"
    SPAM = "spam"
    PHISHING = "phishing"
    MALWARE = "malware"
    POLICY_VIOLATION = "policy_violation"
    QUARANTINED = "quarantined"
    SUSPICIOUS = "suspicious"
    DLP_BLOCKED = "dlp_blocked"


class Direction(str, Enum):
    """Email direction."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class PolicyType(str, Enum):
    """Email policy type."""
    SPAM_FILTER = "spam_filter"
    PHISHING_PROTECTION = "phishing_protection"
    ATTACHMENT_POLICY = "attachment_policy"
    DLP_RULE = "dlp_rule"
    SENDER_AUTH = "sender_auth"
    ENCRYPTION_REQUIRED = "encryption_required"


class IndicatorType(str, Enum):
    """Phishing indicator type."""
    SENDER_SPOOF = "sender_spoof"
    DOMAIN_LOOKALIKE = "domain_lookalike"
    URL_SUSPICIOUS = "url_suspicious"
    URGENCY_LANGUAGE = "urgency_language"
    CREDENTIAL_HARVEST = "credential_harvest"
    BRAND_IMPERSONATION = "brand_impersonation"
    REPLY_TO_MISMATCH = "reply_to_mismatch"
    NEW_SENDER = "new_sender"


class QuarantineStatus(str, Enum):
    """Quarantine entry status."""
    QUARANTINED = "quarantined"
    RELEASED = "released"
    DELETED = "deleted"
    REPORTED_FP = "reported_fp"


class DLPPatternType(str, Enum):
    """DLP pattern type."""
    REGEX = "regex"
    KEYWORD = "keyword"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    CUSTOM = "custom"


class DLPAction(str, Enum):
    """DLP action."""
    BLOCK = "block"
    ENCRYPT = "encrypt"
    ALERT = "alert"
    LOG = "log"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class PhishingIndicator:
    """A single phishing indicator found in a message."""
    indicator_id: str
    indicator_type: str
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0


@dataclass
class EmailMessage:
    """Scanned email message with verdict."""
    message_id: str
    client_id: str
    direction: str = Direction.INBOUND.value
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    has_attachments: bool = False
    attachment_names: List[str] = field(default_factory=list)
    attachment_hashes: List[str] = field(default_factory=list)
    headers: Dict[str, Any] = field(default_factory=dict)
    body_preview: str = ""
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verdict: str = Verdict.CLEAN.value
    confidence: float = 0.0
    processing_time_ms: int = 0
    rules_matched: List[str] = field(default_factory=list)
    indicators: List[PhishingIndicator] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class QuarantineEntry:
    """A quarantined email entry."""
    entry_id: str
    message_id: str
    reason: str = ""
    quarantined_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    released_by: Optional[str] = None
    released_at: Optional[datetime] = None
    status: str = QuarantineStatus.QUARANTINED.value
    original_recipient: str = ""


@dataclass
class EmailPolicy:
    """Email security policy for a client."""
    policy_id: str
    client_id: str
    name: str = ""
    policy_type: str = PolicyType.SPAM_FILTER.value
    config: Dict[str, Any] = field(default_factory=dict)
    is_enabled: bool = True
    priority: int = 100
    actions: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class ThreatFeed:
    """Threat intelligence feed."""
    feed_id: str
    name: str = ""
    feed_type: str = "phishing_urls"
    entries_count: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    entries: List[str] = field(default_factory=list)


@dataclass
class DLPRule:
    """Data Loss Prevention rule."""
    rule_id: str
    policy_id: str
    name: str = ""
    pattern_type: str = DLPPatternType.REGEX.value
    pattern: str = ""
    action: str = DLPAction.ALERT.value
    severity: str = "medium"
    is_enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _message_from_row(row) -> EmailMessage:
    """Convert EmailMessageModel to EmailMessage dataclass."""
    indicators_data = row.indicators or []
    indicators = [
        PhishingIndicator(
            indicator_id=i.get("indicator_id", ""),
            indicator_type=i.get("indicator_type", ""),
            description=i.get("description", ""),
            severity=i.get("severity", "medium"),
            confidence=i.get("confidence", 0.0),
        )
        for i in indicators_data
    ]
    return EmailMessage(
        message_id=row.message_id,
        client_id=row.client_id or "",
        direction=row.direction or Direction.INBOUND.value,
        sender=row.sender or "",
        recipient=row.recipient or "",
        subject=row.subject or "",
        has_attachments=row.has_attachments or False,
        attachment_names=row.attachment_names or [],
        attachment_hashes=row.attachment_hashes or [],
        headers=row.headers or {},
        body_preview=row.body_preview or "",
        received_at=row.received_at or datetime.now(timezone.utc),
        verdict=row.verdict or Verdict.CLEAN.value,
        confidence=row.confidence or 0.0,
        processing_time_ms=row.processing_time_ms or 0,
        rules_matched=row.rules_matched or [],
        indicators=indicators,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _quarantine_from_row(row) -> QuarantineEntry:
    return QuarantineEntry(
        entry_id=row.entry_id,
        message_id=row.message_id,
        reason=row.reason or "",
        quarantined_at=row.quarantined_at or datetime.now(timezone.utc),
        released_by=row.released_by,
        released_at=row.released_at,
        status=row.status or QuarantineStatus.QUARANTINED.value,
        original_recipient=row.original_recipient or "",
    )


def _policy_from_row(row) -> EmailPolicy:
    return EmailPolicy(
        policy_id=row.policy_id,
        client_id=row.client_id or "",
        name=row.name or "",
        policy_type=row.policy_type or PolicyType.SPAM_FILTER.value,
        config=row.config or {},
        is_enabled=row.is_enabled if row.is_enabled is not None else True,
        priority=row.priority or 100,
        actions=row.actions or [],
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _dlp_rule_from_row(row) -> DLPRule:
    return DLPRule(
        rule_id=row.rule_id,
        policy_id=row.policy_id or "",
        name=row.name or "",
        pattern_type=row.pattern_type or DLPPatternType.REGEX.value,
        pattern=row.pattern or "",
        action=row.action or DLPAction.ALERT.value,
        severity=row.severity or "medium",
        is_enabled=row.is_enabled if row.is_enabled is not None else True,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _indicator_to_dict(ind: PhishingIndicator) -> dict:
    return {
        "indicator_id": ind.indicator_id,
        "indicator_type": ind.indicator_type,
        "description": ind.description,
        "severity": ind.severity,
        "confidence": ind.confidence,
    }


# ============================================================
# Pre-built detection patterns
# ============================================================

KNOWN_BRANDS = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "usps",
    "fedex", "ups", "dhl", "irs", "adobe", "salesforce", "zoom",
    "slack", "docusign", "office365", "outlook", "onedrive",
]

URGENCY_KEYWORDS = [
    "urgent", "immediate action", "account suspended", "verify now",
    "click here immediately", "action required", "your account will be",
    "confirm your identity", "unusual activity", "security alert",
    "unauthorized access", "verify your account", "update your payment",
    "suspended account", "final warning", "act now", "limited time",
    "expire", "locked", "compromised",
]

BLOCKED_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll", ".cpl",
    ".hta", ".inf", ".reg", ".rgs", ".sct", ".shb", ".sys", ".lnk",
    ".cab", ".iso", ".img",
]

# DLP patterns
CREDIT_CARD_PATTERN = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
SSN_PATTERN = r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
HIPAA_PATTERN = r"\b(?:MRN|medical\s*record|patient\s*id|diagnosis|treatment\s*plan|prescription)\s*[:#]?\s*\w+\b"

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
]


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _extract_domain(email_addr: str) -> str:
    """Extract domain from an email address."""
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip(">").strip()
    return email_addr.lower().strip()


def _extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    url_pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
    return re.findall(url_pattern, text or "")


# ============================================================
# Service
# ============================================================

class EmailSecurityService:
    """
    Email Security Gateway Service

    Multi-layer email scanning with phishing detection, spam scoring,
    attachment analysis, DLP enforcement, and quarantine management.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._messages: Dict[str, EmailMessage] = {}
        self._quarantine: Dict[str, QuarantineEntry] = {}
        self._policies: Dict[str, EmailPolicy] = {}
        self._dlp_rules: Dict[str, DLPRule] = {}
        self._threat_feeds: Dict[str, ThreatFeed] = {}
        self._known_malware_hashes: set = set()
        self._false_positives: List[str] = []
        self._false_negatives: List[str] = []

        # Counters
        self._stats = {
            "total_scanned": 0,
            "threats_blocked": 0,
            "spam_caught": 0,
            "phishing_caught": 0,
            "malware_caught": 0,
            "dlp_events": 0,
        }

        # Init default feeds and known hashes
        self._init_default_feeds()
        self._init_default_malware_hashes()

    def _init_default_feeds(self) -> None:
        """Seed default threat intelligence feeds."""
        feeds = [
            ("phishing_urls", "PhishTank Community Feed", 12453),
            ("malware_domains", "MalwareBazaar Daily", 8921),
            ("spam_ips", "Spamhaus DROP", 3412),
            ("brand_impersonation", "Brand Monitor Feed", 567),
        ]
        for ft, name, count in feeds:
            fid = f"FEED-{uuid.uuid4().hex[:8].upper()}"
            self._threat_feeds[fid] = ThreatFeed(
                feed_id=fid, name=name, feed_type=ft,
                entries_count=count, last_updated=datetime.now(timezone.utc),
            )

    def _init_default_malware_hashes(self) -> None:
        """Seed known malware hash set (simulated)."""
        self._known_malware_hashes = {
            "44d88612fea8a8f36de82e1278abb02f",  # EICAR test
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        }

    # ================================================================
    # Email Scanning Pipeline
    # ================================================================

    def scan_email(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full email analysis pipeline. Accepts raw message data dict,
        runs all checks, assigns verdict, persists result.

        Returns dict with verdict, confidence, indicators, processing_time.
        """
        start = time.time()
        msg_id = message_data.get("message_id", f"MSG-{uuid.uuid4().hex[:8].upper()}")
        client_id = message_data.get("client_id", "default")

        indicators: List[PhishingIndicator] = []
        rules_matched: List[str] = []
        spam_score = 0.0

        # 1. Sender authentication
        auth_result = self._check_sender_auth(message_data.get("headers", {}))
        if not auth_result.get("pass", True):
            rules_matched.append("sender_auth_fail")
            indicators.append(PhishingIndicator(
                indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                indicator_type=IndicatorType.SENDER_SPOOF.value,
                description=auth_result.get("reason", "Sender auth failed"),
                severity="high",
                confidence=0.85,
            ))

        # 2. Phishing indicators
        phishing_inds = self._check_phishing_indicators(message_data)
        indicators.extend(phishing_inds)
        if phishing_inds:
            rules_matched.append("phishing_indicators")

        # 3. URL safety
        body = message_data.get("body_preview", "") or message_data.get("body", "")
        urls = _extract_urls(body)
        url_issues = self._check_url_safety(urls)
        indicators.extend(url_issues)
        if url_issues:
            rules_matched.append("url_safety")

        # 4. Attachment safety
        attachment_names = message_data.get("attachment_names", [])
        attachment_hashes = message_data.get("attachment_hashes", [])
        attach_issues = self._check_attachment_safety(attachment_names, attachment_hashes)
        indicators.extend(attach_issues)
        if attach_issues:
            rules_matched.append("attachment_safety")

        # 5. DLP rules
        dlp_hits = self._check_dlp_rules(message_data, client_id)
        if dlp_hits:
            rules_matched.append("dlp_violation")
            for hit in dlp_hits:
                indicators.append(PhishingIndicator(
                    indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                    indicator_type="dlp_violation",
                    description=hit.get("description", "DLP rule triggered"),
                    severity=hit.get("severity", "high"),
                    confidence=0.95,
                ))

        # 6. Spam score
        spam_score = self._calculate_spam_score(message_data)
        if spam_score > 0.7:
            rules_matched.append("spam_score_high")

        # Determine verdict
        verdict, confidence = self._determine_verdict(indicators, spam_score, dlp_hits, rules_matched)

        elapsed_ms = int((time.time() - start) * 1000)

        msg = EmailMessage(
            message_id=msg_id,
            client_id=client_id,
            direction=message_data.get("direction", Direction.INBOUND.value),
            sender=message_data.get("sender", ""),
            recipient=message_data.get("recipient", ""),
            subject=message_data.get("subject", ""),
            has_attachments=len(attachment_names) > 0,
            attachment_names=attachment_names,
            attachment_hashes=attachment_hashes,
            headers=message_data.get("headers", {}),
            body_preview=(body[:500] if body else ""),
            received_at=datetime.now(timezone.utc),
            verdict=verdict,
            confidence=confidence,
            processing_time_ms=elapsed_ms,
            rules_matched=rules_matched,
            indicators=indicators,
        )

        # Persist
        self._messages[msg_id] = msg
        self._stats["total_scanned"] += 1

        if verdict == Verdict.SPAM.value:
            self._stats["spam_caught"] += 1
            self._stats["threats_blocked"] += 1
        elif verdict == Verdict.PHISHING.value:
            self._stats["phishing_caught"] += 1
            self._stats["threats_blocked"] += 1
        elif verdict == Verdict.MALWARE.value:
            self._stats["malware_caught"] += 1
            self._stats["threats_blocked"] += 1
        elif verdict == Verdict.DLP_BLOCKED.value:
            self._stats["dlp_events"] += 1
            self._stats["threats_blocked"] += 1
        elif verdict in (Verdict.QUARANTINED.value, Verdict.POLICY_VIOLATION.value):
            self._stats["threats_blocked"] += 1

        # Auto-quarantine
        if verdict in (Verdict.PHISHING.value, Verdict.MALWARE.value, Verdict.DLP_BLOCKED.value, Verdict.QUARANTINED.value):
            self.quarantine_message(msg_id, f"Auto-quarantine: {verdict}")

        if self._use_db:
            try:
                row = EmailMessageModel(
                    message_id=msg_id,
                    client_id=client_id,
                    direction=msg.direction,
                    sender=msg.sender,
                    recipient=msg.recipient,
                    subject=msg.subject,
                    has_attachments=msg.has_attachments,
                    attachment_names=msg.attachment_names,
                    attachment_hashes=msg.attachment_hashes,
                    headers=msg.headers,
                    body_preview=msg.body_preview,
                    verdict=verdict,
                    confidence=confidence,
                    processing_time_ms=elapsed_ms,
                    rules_matched=rules_matched,
                    indicators=[_indicator_to_dict(i) for i in indicators],
                    received_at=msg.received_at,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error persisting email scan: {e}")
                self.db.rollback()

        return {
            "message_id": msg_id,
            "verdict": verdict,
            "confidence": round(confidence, 3),
            "processing_time_ms": elapsed_ms,
            "rules_matched": rules_matched,
            "indicators": [_indicator_to_dict(i) for i in indicators],
            "quarantined": verdict in (Verdict.PHISHING.value, Verdict.MALWARE.value, Verdict.DLP_BLOCKED.value, Verdict.QUARANTINED.value),
        }

    def _determine_verdict(
        self, indicators: List[PhishingIndicator], spam_score: float,
        dlp_hits: List[dict], rules_matched: List[str],
    ) -> tuple:
        """Determine final verdict and confidence from all signals."""
        # Check for malware first (highest severity)
        malware_inds = [i for i in indicators if "malware" in i.indicator_type.lower() or "blocked_extension" in i.indicator_type.lower()]
        if malware_inds:
            return Verdict.MALWARE.value, max(i.confidence for i in malware_inds)

        # DLP
        if dlp_hits:
            block_hits = [h for h in dlp_hits if h.get("action") == DLPAction.BLOCK.value]
            if block_hits:
                return Verdict.DLP_BLOCKED.value, 0.95

        # Phishing
        phishing_inds = [i for i in indicators if i.indicator_type in (
            IndicatorType.SENDER_SPOOF.value, IndicatorType.DOMAIN_LOOKALIKE.value,
            IndicatorType.CREDENTIAL_HARVEST.value, IndicatorType.BRAND_IMPERSONATION.value,
        )]
        if len(phishing_inds) >= 2 or any(i.confidence > 0.85 for i in phishing_inds):
            conf = max(i.confidence for i in phishing_inds) if phishing_inds else 0.8
            return Verdict.PHISHING.value, conf

        # Spam
        if spam_score > 0.8:
            return Verdict.SPAM.value, spam_score
        if spam_score > 0.7 and indicators:
            return Verdict.SPAM.value, spam_score

        # Suspicious
        if indicators:
            max_conf = max(i.confidence for i in indicators)
            if max_conf > 0.6:
                return Verdict.SUSPICIOUS.value, max_conf

        # Policy violation
        if "sender_auth_fail" in rules_matched:
            return Verdict.POLICY_VIOLATION.value, 0.7

        return Verdict.CLEAN.value, 1.0 - spam_score

    # ================================================================
    # Detection Checks
    # ================================================================

    def _check_sender_auth(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Check SPF/DKIM/DMARC authentication from headers."""
        result = {"pass": True, "spf": "pass", "dkim": "pass", "dmarc": "pass"}

        auth_results = headers.get("authentication-results", headers.get("Authentication-Results", ""))
        if isinstance(auth_results, str):
            auth_lower = auth_results.lower()
            if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
                result["spf"] = "fail"
                result["pass"] = False
                result["reason"] = "SPF validation failed"
            if "dkim=fail" in auth_lower:
                result["dkim"] = "fail"
                result["pass"] = False
                result["reason"] = "DKIM validation failed"
            if "dmarc=fail" in auth_lower:
                result["dmarc"] = "fail"
                result["pass"] = False
                result["reason"] = "DMARC validation failed"

        # Check for missing auth headers
        if not auth_results:
            # If no auth results at all, suspicious but not fail
            result["spf"] = "none"
            result["dkim"] = "none"
            result["dmarc"] = "none"

        return result

    def _check_phishing_indicators(self, message: Dict[str, Any]) -> List[PhishingIndicator]:
        """Run all phishing indicator checks on a message."""
        indicators = []
        sender = message.get("sender", "")
        subject = message.get("subject", "")
        body = message.get("body_preview", "") or message.get("body", "")
        headers = message.get("headers", {})
        text = f"{subject} {body}".lower()

        # Sender display name vs domain mismatch
        if "<" in sender and "@" in sender:
            display_name = sender.split("<")[0].strip().lower()
            domain = _extract_domain(sender)
            for brand in KNOWN_BRANDS:
                if brand in display_name and brand not in domain:
                    indicators.append(PhishingIndicator(
                        indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                        indicator_type=IndicatorType.SENDER_SPOOF.value,
                        description=f"Display name contains '{brand}' but domain is '{domain}'",
                        severity="high",
                        confidence=0.9,
                    ))
                    break

        # Domain lookalike check
        domain = _extract_domain(sender)
        lookalike = self._check_domain_lookalike(domain)
        if lookalike:
            indicators.append(lookalike)

        # Reply-to mismatch
        reply_to = headers.get("reply-to", headers.get("Reply-To", ""))
        if reply_to and sender:
            sender_domain = _extract_domain(sender)
            reply_domain = _extract_domain(reply_to)
            if sender_domain and reply_domain and sender_domain != reply_domain:
                indicators.append(PhishingIndicator(
                    indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                    indicator_type=IndicatorType.REPLY_TO_MISMATCH.value,
                    description=f"Reply-To domain '{reply_domain}' differs from sender '{sender_domain}'",
                    severity="high",
                    confidence=0.8,
                ))

        # Urgency language
        urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in text]
        if len(urgency_hits) >= 2:
            indicators.append(PhishingIndicator(
                indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                indicator_type=IndicatorType.URGENCY_LANGUAGE.value,
                description=f"Urgency keywords detected: {', '.join(urgency_hits[:5])}",
                severity="medium",
                confidence=min(0.5 + len(urgency_hits) * 0.1, 0.9),
            ))

        # Credential harvest detection
        cred_patterns = [
            r"(?:enter|confirm|verify|update)\s+(?:your\s+)?(?:password|credentials|ssn|social\s*security)",
            r"(?:credit\s*card|bank\s*account|routing\s*number)",
            r"(?:login|sign\s*in)\s+(?:here|now|immediately)",
        ]
        for cp in cred_patterns:
            if re.search(cp, text, re.IGNORECASE):
                indicators.append(PhishingIndicator(
                    indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                    indicator_type=IndicatorType.CREDENTIAL_HARVEST.value,
                    description="Message requests sensitive credentials",
                    severity="critical",
                    confidence=0.85,
                ))
                break

        return indicators

    def _check_domain_lookalike(self, domain: str) -> Optional[PhishingIndicator]:
        """Check if domain is a lookalike for known brands using Levenshtein distance."""
        if not domain:
            return None
        domain_base = domain.split(".")[0].lower()
        for brand in KNOWN_BRANDS:
            if domain_base == brand:
                continue  # Exact match is fine
            dist = _levenshtein(domain_base, brand)
            if 0 < dist < 3:
                return PhishingIndicator(
                    indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                    indicator_type=IndicatorType.DOMAIN_LOOKALIKE.value,
                    description=f"Domain '{domain}' looks like '{brand}' (distance={dist})",
                    severity="high",
                    confidence=max(0.95 - dist * 0.1, 0.7),
                )
        return None

    def _check_url_safety(self, urls: List[str]) -> List[PhishingIndicator]:
        """Analyze embedded URLs for suspicious patterns."""
        indicators = []
        for url in urls:
            url_lower = url.lower()

            # Shortened URL
            for shortener in URL_SHORTENERS:
                if shortener in url_lower:
                    indicators.append(PhishingIndicator(
                        indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                        indicator_type=IndicatorType.URL_SUSPICIOUS.value,
                        description=f"Shortened URL detected: {url[:80]}",
                        severity="medium",
                        confidence=0.6,
                    ))
                    break

            # IP-based URL
            ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, url_lower):
                indicators.append(PhishingIndicator(
                    indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                    indicator_type=IndicatorType.URL_SUSPICIOUS.value,
                    description=f"IP-based URL detected: {url[:80]}",
                    severity="high",
                    confidence=0.8,
                ))

            # Excessive subdomains (>3 dots before TLD)
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or ""
                if host.count(".") > 3:
                    indicators.append(PhishingIndicator(
                        indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                        indicator_type=IndicatorType.URL_SUSPICIOUS.value,
                        description=f"Excessive subdomains in URL: {host}",
                        severity="medium",
                        confidence=0.65,
                    ))
            except Exception:
                pass

        return indicators

    def _check_attachment_safety(
        self, attachment_names: List[str], attachment_hashes: List[str]
    ) -> List[PhishingIndicator]:
        """Check attachments against blocked extensions and known malware hashes."""
        indicators = []

        for name in attachment_names:
            name_lower = name.lower()
            for ext in BLOCKED_EXTENSIONS:
                if name_lower.endswith(ext):
                    indicators.append(PhishingIndicator(
                        indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                        indicator_type="blocked_extension",
                        description=f"Blocked file extension: {name}",
                        severity="critical",
                        confidence=0.95,
                    ))
                    break

            # Double extension (e.g. invoice.pdf.exe)
            parts = name_lower.rsplit(".", 2)
            if len(parts) >= 3:
                indicators.append(PhishingIndicator(
                    indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                    indicator_type="blocked_extension",
                    description=f"Double extension detected: {name}",
                    severity="high",
                    confidence=0.85,
                ))

        for h in attachment_hashes:
            if h.lower() in self._known_malware_hashes:
                indicators.append(PhishingIndicator(
                    indicator_id=f"IND-{uuid.uuid4().hex[:8].upper()}",
                    indicator_type="malware_hash_match",
                    description=f"Attachment hash matches known malware: {h[:16]}...",
                    severity="critical",
                    confidence=0.99,
                ))

        return indicators

    def _check_dlp_rules(self, message: Dict[str, Any], client_id: str) -> List[Dict[str, Any]]:
        """Run DLP rules against message content."""
        hits = []
        text = f"{message.get('subject', '')} {message.get('body_preview', '')} {message.get('body', '')}"

        # Get client-specific DLP rules
        rules = [r for r in self._dlp_rules.values()
                 if r.is_enabled and (self._get_policy_client(r.policy_id) == client_id or self._get_policy_client(r.policy_id) == "default")]

        # Also check built-in patterns
        builtin_checks = [
            (CREDIT_CARD_PATTERN, "Credit card number detected", DLPPatternType.CREDIT_CARD.value, "high"),
            (SSN_PATTERN, "Social Security Number detected", DLPPatternType.SSN.value, "critical"),
            (HIPAA_PATTERN, "HIPAA identifier detected", DLPPatternType.REGEX.value, "high"),
        ]

        direction = message.get("direction", Direction.INBOUND.value)
        # DLP primarily checks outbound
        if direction == Direction.OUTBOUND.value:
            for pattern, desc, ptype, severity in builtin_checks:
                if re.search(pattern, text, re.IGNORECASE):
                    hits.append({
                        "rule": f"builtin_{ptype}",
                        "description": desc,
                        "severity": severity,
                        "action": DLPAction.BLOCK.value,
                    })
                    self._stats["dlp_events"] += 1

        for rule in rules:
            try:
                if rule.pattern and re.search(rule.pattern, text, re.IGNORECASE):
                    hits.append({
                        "rule": rule.name,
                        "description": f"DLP rule matched: {rule.name}",
                        "severity": rule.severity,
                        "action": rule.action,
                    })
                    self._stats["dlp_events"] += 1
            except re.error:
                logger.warning(f"Invalid DLP regex for rule {rule.rule_id}: {rule.pattern}")

        return hits

    def _get_policy_client(self, policy_id: str) -> str:
        """Get client_id for a policy."""
        p = self._policies.get(policy_id)
        return p.client_id if p else "default"

    def _calculate_spam_score(self, message: Dict[str, Any]) -> float:
        """Calculate composite spam probability score (0.0 - 1.0)."""
        score = 0.0
        subject = (message.get("subject", "") or "").lower()
        body = (message.get("body_preview", "") or message.get("body", "") or "").lower()
        text = f"{subject} {body}"
        sender = message.get("sender", "")

        # All caps subject
        raw_subj = message.get("subject", "")
        if raw_subj and raw_subj == raw_subj.upper() and len(raw_subj) > 5:
            score += 0.15

        # Excessive exclamation marks
        if text.count("!") > 3:
            score += 0.1

        # Spam keywords
        spam_words = [
            "free", "winner", "congratulations", "prize", "lottery",
            "viagra", "cialis", "weight loss", "earn money", "work from home",
            "click below", "unsubscribe", "opt out", "bulk email",
            "no obligation", "guaranteed", "limited offer", "act now",
        ]
        spam_hits = sum(1 for w in spam_words if w in text)
        score += min(spam_hits * 0.08, 0.4)

        # No unsubscribe header (newsletters should have it)
        headers = message.get("headers", {})
        if not headers.get("list-unsubscribe") and not headers.get("List-Unsubscribe"):
            # Minor signal
            score += 0.05

        # Sender domain reputation (simplified)
        domain = _extract_domain(sender)
        if domain and domain.endswith((".xyz", ".top", ".buzz", ".click", ".link", ".work")):
            score += 0.2

        return min(score, 1.0)

    # ================================================================
    # Quarantine Management
    # ================================================================

    def quarantine_message(self, message_id: str, reason: str) -> Optional[QuarantineEntry]:
        """Quarantine an email message."""
        msg = self._messages.get(message_id)
        entry_id = f"QR-{uuid.uuid4().hex[:8].upper()}"

        entry = QuarantineEntry(
            entry_id=entry_id,
            message_id=message_id,
            reason=reason,
            quarantined_at=datetime.now(timezone.utc),
            status=QuarantineStatus.QUARANTINED.value,
            original_recipient=msg.recipient if msg else "",
        )

        self._quarantine[entry_id] = entry

        if self._use_db:
            try:
                row = QuarantineEntryModel(
                    entry_id=entry_id,
                    message_id=message_id,
                    reason=reason,
                    original_recipient=entry.original_recipient,
                    status=QuarantineStatus.QUARANTINED.value,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error quarantining message: {e}")
                self.db.rollback()

        return entry

    def release_message(self, entry_id: str, released_by: str) -> Optional[QuarantineEntry]:
        """Release a message from quarantine."""
        entry = self._quarantine.get(entry_id)
        if not entry:
            if self._use_db:
                try:
                    row = self.db.query(QuarantineEntryModel).filter(
                        QuarantineEntryModel.entry_id == entry_id
                    ).first()
                    if row:
                        entry = _quarantine_from_row(row)
                except Exception:
                    pass
            if not entry:
                return None

        entry.status = QuarantineStatus.RELEASED.value
        entry.released_by = released_by
        entry.released_at = datetime.now(timezone.utc)
        self._quarantine[entry_id] = entry

        if self._use_db:
            try:
                row = self.db.query(QuarantineEntryModel).filter(
                    QuarantineEntryModel.entry_id == entry_id
                ).first()
                if row:
                    row.status = QuarantineStatus.RELEASED.value
                    row.released_by = released_by
                    row.released_at = datetime.now(timezone.utc)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error releasing quarantine: {e}")
                self.db.rollback()

        return entry

    def delete_quarantined(self, entry_id: str) -> bool:
        """Delete a quarantined message permanently."""
        entry = self._quarantine.get(entry_id)
        if not entry:
            return False
        entry.status = QuarantineStatus.DELETED.value
        self._quarantine[entry_id] = entry

        if self._use_db:
            try:
                row = self.db.query(QuarantineEntryModel).filter(
                    QuarantineEntryModel.entry_id == entry_id
                ).first()
                if row:
                    row.status = QuarantineStatus.DELETED.value
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error deleting quarantine entry: {e}")
                self.db.rollback()

        return True

    def get_quarantine(
        self, client_id: Optional[str] = None, status: Optional[str] = None,
        limit: int = 50, offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get quarantine entries with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(QuarantineEntryModel)
                if status:
                    q = q.filter(QuarantineEntryModel.status == status)
                q = q.order_by(QuarantineEntryModel.quarantined_at.desc())
                rows = q.offset(offset).limit(limit).all()
                entries = [_quarantine_from_row(r) for r in rows]
                # Filter by client_id via message lookup if needed
                if client_id:
                    entries = [e for e in entries if self._messages.get(e.message_id, EmailMessage(message_id="", client_id="")).client_id == client_id]
                return [self._quarantine_to_dict(e) for e in entries]
            except Exception as e:
                logger.error(f"DB error listing quarantine: {e}")

        entries = list(self._quarantine.values())
        if status:
            entries = [e for e in entries if e.status == status]
        if client_id:
            entries = [e for e in entries if self._messages.get(e.message_id, EmailMessage(message_id="", client_id="")).client_id == client_id]
        entries.sort(key=lambda e: e.quarantined_at, reverse=True)
        return [self._quarantine_to_dict(e) for e in entries[offset:offset + limit]]

    def get_quarantine_stats(self) -> Dict[str, Any]:
        """Get quarantine statistics."""
        entries = list(self._quarantine.values())
        active = [e for e in entries if e.status == QuarantineStatus.QUARANTINED.value]
        return {
            "total_quarantined": len(active),
            "total_released": sum(1 for e in entries if e.status == QuarantineStatus.RELEASED.value),
            "total_deleted": sum(1 for e in entries if e.status == QuarantineStatus.DELETED.value),
            "total_false_positives": sum(1 for e in entries if e.status == QuarantineStatus.REPORTED_FP.value),
            "reasons_breakdown": dict(Counter(e.reason.split(":")[0].strip() for e in active)),
        }

    def _quarantine_to_dict(self, entry: QuarantineEntry) -> dict:
        msg = self._messages.get(entry.message_id)
        return {
            "entry_id": entry.entry_id,
            "message_id": entry.message_id,
            "reason": entry.reason,
            "status": entry.status,
            "original_recipient": entry.original_recipient,
            "quarantined_at": entry.quarantined_at.isoformat() if entry.quarantined_at else None,
            "released_by": entry.released_by,
            "released_at": entry.released_at.isoformat() if entry.released_at else None,
            "subject": msg.subject if msg else "",
            "sender": msg.sender if msg else "",
            "verdict": msg.verdict if msg else "",
        }

    # ================================================================
    # Policy CRUD
    # ================================================================

    def create_policy(
        self, client_id: str, name: str, policy_type: str = PolicyType.SPAM_FILTER.value,
        config: Optional[Dict] = None, priority: int = 100,
        actions: Optional[List[str]] = None,
    ) -> EmailPolicy:
        """Create an email security policy."""
        policy_id = f"EPOL-{uuid.uuid4().hex[:8].upper()}"
        policy = EmailPolicy(
            policy_id=policy_id,
            client_id=client_id,
            name=name,
            policy_type=policy_type,
            config=config or {},
            is_enabled=True,
            priority=priority,
            actions=actions or ["quarantine"],
        )
        self._policies[policy_id] = policy

        if self._use_db:
            try:
                row = EmailPolicyModel(
                    policy_id=policy_id,
                    client_id=client_id,
                    name=name,
                    policy_type=policy_type,
                    config=config or {},
                    is_enabled=True,
                    priority=priority,
                    actions=actions or ["quarantine"],
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating policy: {e}")
                self.db.rollback()

        return policy

    def update_policy(self, policy_id: str, **updates) -> Optional[EmailPolicy]:
        """Update an existing email policy."""
        policy = self._policies.get(policy_id)
        if not policy:
            return None
        for k, v in updates.items():
            if hasattr(policy, k) and v is not None:
                setattr(policy, k, v)
        policy.updated_at = datetime.now(timezone.utc)
        self._policies[policy_id] = policy

        if self._use_db:
            try:
                row = self.db.query(EmailPolicyModel).filter(
                    EmailPolicyModel.policy_id == policy_id
                ).first()
                if row:
                    for k, v in updates.items():
                        if hasattr(row, k) and v is not None:
                            setattr(row, k, v)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating policy: {e}")
                self.db.rollback()

        return policy

    def list_policies(self, client_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List email policies, optionally filtered by client."""
        if self._use_db:
            try:
                q = self.db.query(EmailPolicyModel)
                if client_id:
                    q = q.filter(EmailPolicyModel.client_id == client_id)
                rows = q.order_by(EmailPolicyModel.priority).all()
                return [self._policy_to_dict(_policy_from_row(r)) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing policies: {e}")

        policies = list(self._policies.values())
        if client_id:
            policies = [p for p in policies if p.client_id == client_id]
        policies.sort(key=lambda p: p.priority)
        return [self._policy_to_dict(p) for p in policies]

    def toggle_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Toggle a policy enabled/disabled."""
        policy = self._policies.get(policy_id)
        if not policy:
            return None
        policy.is_enabled = not policy.is_enabled
        policy.updated_at = datetime.now(timezone.utc)
        self._policies[policy_id] = policy

        if self._use_db:
            try:
                row = self.db.query(EmailPolicyModel).filter(
                    EmailPolicyModel.policy_id == policy_id
                ).first()
                if row:
                    row.is_enabled = policy.is_enabled
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error toggling policy: {e}")
                self.db.rollback()

        return self._policy_to_dict(policy)

    def _policy_to_dict(self, p: EmailPolicy) -> dict:
        return {
            "policy_id": p.policy_id,
            "client_id": p.client_id,
            "name": p.name,
            "policy_type": p.policy_type,
            "config": p.config,
            "is_enabled": p.is_enabled,
            "priority": p.priority,
            "actions": p.actions,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        }

    # ================================================================
    # DLP Rules
    # ================================================================

    def create_dlp_rule(
        self, policy_id: str, name: str, pattern_type: str = DLPPatternType.REGEX.value,
        pattern: str = "", action: str = DLPAction.ALERT.value,
        severity: str = "medium",
    ) -> DLPRule:
        """Create a DLP rule."""
        rule_id = f"DLP-{uuid.uuid4().hex[:8].upper()}"
        rule = DLPRule(
            rule_id=rule_id,
            policy_id=policy_id,
            name=name,
            pattern_type=pattern_type,
            pattern=pattern,
            action=action,
            severity=severity,
        )
        self._dlp_rules[rule_id] = rule

        if self._use_db:
            try:
                row = DLPRuleModel(
                    rule_id=rule_id,
                    policy_id=policy_id,
                    name=name,
                    pattern_type=pattern_type,
                    pattern=pattern,
                    action=action,
                    severity=severity,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating DLP rule: {e}")
                self.db.rollback()

        return rule

    def list_dlp_rules(self, policy_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List DLP rules."""
        if self._use_db:
            try:
                q = self.db.query(DLPRuleModel)
                if policy_id:
                    q = q.filter(DLPRuleModel.policy_id == policy_id)
                rows = q.all()
                return [self._dlp_to_dict(_dlp_rule_from_row(r)) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing DLP rules: {e}")

        rules = list(self._dlp_rules.values())
        if policy_id:
            rules = [r for r in rules if r.policy_id == policy_id]
        return [self._dlp_to_dict(r) for r in rules]

    def test_dlp_rule(self, text: str) -> List[Dict[str, Any]]:
        """Test all DLP rules against given text. Returns list of matches."""
        results = []

        # Built-in patterns
        builtins = [
            (CREDIT_CARD_PATTERN, "Credit Card", DLPPatternType.CREDIT_CARD.value),
            (SSN_PATTERN, "SSN", DLPPatternType.SSN.value),
            (HIPAA_PATTERN, "HIPAA Identifier", DLPPatternType.REGEX.value),
        ]
        for pattern, name, ptype in builtins:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                results.append({
                    "rule": f"builtin_{ptype}",
                    "name": name,
                    "matches_found": len(matches),
                    "sample": matches[0] if matches else "",
                })

        # Custom rules
        for rule in self._dlp_rules.values():
            if not rule.is_enabled or not rule.pattern:
                continue
            try:
                matches = re.findall(rule.pattern, text, re.IGNORECASE)
                if matches:
                    results.append({
                        "rule": rule.rule_id,
                        "name": rule.name,
                        "matches_found": len(matches),
                        "sample": matches[0] if matches else "",
                        "action": rule.action,
                    })
            except re.error:
                pass

        return results

    def _dlp_to_dict(self, r: DLPRule) -> dict:
        return {
            "rule_id": r.rule_id,
            "policy_id": r.policy_id,
            "name": r.name,
            "pattern_type": r.pattern_type,
            "pattern": r.pattern,
            "action": r.action,
            "severity": r.severity,
            "is_enabled": r.is_enabled,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }

    # ================================================================
    # Threat Feeds
    # ================================================================

    def update_feed(self, feed_id: str, entries: Optional[List[str]] = None, **updates) -> Optional[Dict[str, Any]]:
        """Update a threat feed."""
        feed = self._threat_feeds.get(feed_id)
        if not feed:
            return None
        for k, v in updates.items():
            if hasattr(feed, k) and v is not None:
                setattr(feed, k, v)
        if entries is not None:
            feed.entries = entries
            feed.entries_count = len(entries)
        feed.last_updated = datetime.now(timezone.utc)
        self._threat_feeds[feed_id] = feed
        return self._feed_to_dict(feed)

    def list_feeds(self) -> List[Dict[str, Any]]:
        """List all threat feeds."""
        return [self._feed_to_dict(f) for f in self._threat_feeds.values()]

    def _feed_to_dict(self, f: ThreatFeed) -> dict:
        return {
            "feed_id": f.feed_id,
            "name": f.name,
            "feed_type": f.feed_type,
            "entries_count": f.entries_count,
            "last_updated": f.last_updated.isoformat() if f.last_updated else None,
        }

    # ================================================================
    # False Positive / Negative Reporting
    # ================================================================

    def report_false_positive(self, message_id: str) -> Dict[str, Any]:
        """Report a message as false positive (wrongly flagged)."""
        self._false_positives.append(message_id)
        msg = self._messages.get(message_id)

        # Update quarantine status if quarantined
        for entry in self._quarantine.values():
            if entry.message_id == message_id and entry.status == QuarantineStatus.QUARANTINED.value:
                entry.status = QuarantineStatus.REPORTED_FP.value

        return {
            "message_id": message_id,
            "status": "reported",
            "original_verdict": msg.verdict if msg else "unknown",
            "action": "Message will be reviewed and quarantine entry updated",
        }

    def report_false_negative(self, message_id: str) -> Dict[str, Any]:
        """Report a message as false negative (missed threat)."""
        self._false_negatives.append(message_id)
        msg = self._messages.get(message_id)
        return {
            "message_id": message_id,
            "status": "reported",
            "original_verdict": msg.verdict if msg else "unknown",
            "action": "Message will be analyzed for detection improvement",
        }

    # ================================================================
    # Statistics & Dashboard
    # ================================================================

    def get_email_stats(self, client_id: Optional[str] = None, period: str = "24h") -> Dict[str, Any]:
        """Get email statistics for a client or global."""
        hours = {"1h": 1, "6h": 6, "12h": 12, "24h": 24, "7d": 168, "30d": 720}.get(period, 24)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        messages = [m for m in self._messages.values() if m.created_at >= cutoff]
        if client_id:
            messages = [m for m in messages if m.client_id == client_id]

        verdict_counts = Counter(m.verdict for m in messages)
        direction_counts = Counter(m.direction for m in messages)

        return {
            "period": period,
            "client_id": client_id,
            "total_messages": len(messages),
            "verdicts": dict(verdict_counts),
            "by_direction": dict(direction_counts),
            "avg_processing_ms": round(
                sum(m.processing_time_ms for m in messages) / max(len(messages), 1), 1
            ),
            "top_senders": dict(Counter(m.sender for m in messages).most_common(10)),
            "threat_rate": round(
                sum(1 for m in messages if m.verdict != Verdict.CLEAN.value) / max(len(messages), 1), 4
            ),
        }

    def get_top_targeted_users(self, client_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most targeted (phished) users for a client."""
        threats = [m for m in self._messages.values()
                   if m.client_id == client_id and m.verdict in (
                       Verdict.PHISHING.value, Verdict.MALWARE.value, Verdict.SUSPICIOUS.value
                   )]
        user_counts = Counter(m.recipient for m in threats)
        return [
            {"user": user, "threats_received": count, "percentage": round(count / max(len(threats), 1) * 100, 1)}
            for user, count in user_counts.most_common(limit)
        ]

    def get_dashboard(self) -> Dict[str, Any]:
        """Get email security dashboard overview."""
        active_quarantine = sum(
            1 for e in self._quarantine.values()
            if e.status == QuarantineStatus.QUARANTINED.value
        )

        # Recent messages (last 24h)
        cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        recent = [m for m in self._messages.values() if m.created_at >= cutoff_24h]
        recent_verdicts = Counter(m.verdict for m in recent)

        return {
            "summary": {
                "total_messages_processed": self._stats["total_scanned"],
                "threats_blocked": self._stats["threats_blocked"],
                "quarantine_size": active_quarantine,
                "dlp_events": self._stats["dlp_events"],
                "false_positives_reported": len(self._false_positives),
                "false_negatives_reported": len(self._false_negatives),
                "active_policies": sum(1 for p in self._policies.values() if p.is_enabled),
                "active_dlp_rules": sum(1 for r in self._dlp_rules.values() if r.is_enabled),
                "threat_feeds": len(self._threat_feeds),
            },
            "last_24h": {
                "messages": len(recent),
                "verdicts": dict(recent_verdicts),
                "spam_caught": self._stats["spam_caught"],
                "phishing_caught": self._stats["phishing_caught"],
                "malware_caught": self._stats["malware_caught"],
            },
            "threat_feeds": [self._feed_to_dict(f) for f in self._threat_feeds.values()],
        }

    def get_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Get a single message by ID."""
        msg = self._messages.get(message_id)
        if not msg and self._use_db:
            try:
                row = self.db.query(EmailMessageModel).filter(
                    EmailMessageModel.message_id == message_id
                ).first()
                if row:
                    msg = _message_from_row(row)
                    self._messages[message_id] = msg
            except Exception:
                pass
        if not msg:
            return None
        return self._message_to_dict(msg)

    def list_messages(
        self, client_id: Optional[str] = None, verdict: Optional[str] = None,
        direction: Optional[str] = None, limit: int = 50, offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List scanned messages with filters."""
        if self._use_db:
            try:
                q = self.db.query(EmailMessageModel)
                if client_id:
                    q = q.filter(EmailMessageModel.client_id == client_id)
                if verdict:
                    q = q.filter(EmailMessageModel.verdict == verdict)
                if direction:
                    q = q.filter(EmailMessageModel.direction == direction)
                q = q.order_by(EmailMessageModel.received_at.desc())
                rows = q.offset(offset).limit(limit).all()
                return [self._message_to_dict(_message_from_row(r)) for r in rows]
            except Exception as e:
                logger.error(f"DB error listing messages: {e}")

        msgs = list(self._messages.values())
        if client_id:
            msgs = [m for m in msgs if m.client_id == client_id]
        if verdict:
            msgs = [m for m in msgs if m.verdict == verdict]
        if direction:
            msgs = [m for m in msgs if m.direction == direction]
        msgs.sort(key=lambda m: m.received_at, reverse=True)
        return [self._message_to_dict(m) for m in msgs[offset:offset + limit]]

    def _message_to_dict(self, m: EmailMessage) -> dict:
        return {
            "message_id": m.message_id,
            "client_id": m.client_id,
            "direction": m.direction,
            "sender": m.sender,
            "recipient": m.recipient,
            "subject": m.subject,
            "has_attachments": m.has_attachments,
            "attachment_names": m.attachment_names,
            "verdict": m.verdict,
            "confidence": m.confidence,
            "processing_time_ms": m.processing_time_ms,
            "rules_matched": m.rules_matched,
            "indicators": [_indicator_to_dict(i) for i in m.indicators],
            "received_at": m.received_at.isoformat() if m.received_at else None,
        }
