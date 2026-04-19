"""
AITHER Platform - Notification Connector Service

External alerting bridge for the Aither MSP platform.
Routes events (threat detected, SLA breach, patch failed, etc.)
to external channels: Email, Slack, PagerDuty, MS Teams, Webhooks, SMS.

Supports:
- Channel CRUD and connection testing
- Rule-based routing with severity filters
- Cooldown / throttling to prevent alert spam
- Delivery logging with error capture
- DB persistence with in-memory fallback
"""

import uuid
import logging
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.notifications import (
        NotificationChannelModel,
        NotificationRuleModel,
        NotificationLogModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class ChannelType(str, Enum):
    """Supported notification channel types"""
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    MSTEAMS = "msteams"
    WEBHOOK = "webhook"
    SMS = "sms"


class EventType(str, Enum):
    """MSP events that can trigger notifications"""
    THREAT_DETECTED = "threat_detected"
    INCIDENT_CREATED = "incident_created"
    ENDPOINT_OFFLINE = "endpoint_offline"
    SLA_BREACH = "sla_breach"
    PATCH_FAILED = "patch_failed"
    SELF_HEAL_FAILED = "self_heal_failed"
    BACKUP_FAILED = "backup_failed"
    COMPLIANCE_VIOLATION = "compliance_violation"


class NotificationStatus(str, Enum):
    """Delivery status of a notification"""
    SENT = "sent"
    FAILED = "failed"
    THROTTLED = "throttled"


class SeverityLevel(str, Enum):
    """Severity levels for filtering"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    ALL = "all"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class NotificationChannel:
    """A configured notification channel"""
    channel_id: str
    channel_type: ChannelType
    name: str
    config: Dict[str, Any] = field(default_factory=dict)
    is_enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class NotificationRule:
    """A rule that maps event types to channels"""
    rule_id: str
    name: str
    event_types: List[str] = field(default_factory=list)
    severity_filter: str = "all"
    channels: List[str] = field(default_factory=list)
    is_enabled: bool = True
    cooldown_minutes: int = 5
    last_triggered: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class NotificationLog:
    """Delivery log entry for a single notification dispatch"""
    log_id: str
    rule_id: str
    channel_id: str
    event_type: str
    severity: str
    subject: str
    body: str
    status: str = "sent"
    sent_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str = ""


# ============================================================
# Service
# ============================================================

class NotificationConnectorService:
    """
    Notification Connector - External alerting for Aither MSP.

    Routes platform events to email, Slack, PagerDuty, MS Teams,
    generic webhooks, and SMS channels.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._channels: Dict[str, NotificationChannel] = {}
        self._rules: Dict[str, NotificationRule] = {}
        self._logs: List[NotificationLog] = []

        logger.info("NotificationConnectorService initialized (db=%s)", self._use_db)

    # ----------------------------------------------------------
    # Channel CRUD
    # ----------------------------------------------------------

    def create_channel(
        self,
        channel_type: str,
        name: str,
        config: Dict[str, Any] = None,
        is_enabled: bool = True,
    ) -> Dict:
        """Create a new notification channel."""
        channel_id = f"ch-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        channel = NotificationChannel(
            channel_id=channel_id,
            channel_type=ChannelType(channel_type),
            name=name,
            config=config or {},
            is_enabled=is_enabled,
            created_at=now,
        )

        if self._use_db:
            row = NotificationChannelModel(
                channel_id=channel.channel_id,
                channel_type=channel.channel_type.value,
                name=channel.name,
                config=channel.config,
                is_enabled=channel.is_enabled,
            )
            self.db.add(row)
            self.db.commit()
        else:
            self._channels[channel_id] = channel

        logger.info("Created notification channel %s (%s)", channel_id, channel_type)
        return self._channel_to_dict(channel)

    def update_channel(self, channel_id: str, updates: Dict[str, Any]) -> Optional[Dict]:
        """Update an existing notification channel."""
        if self._use_db:
            row = (
                self.db.query(NotificationChannelModel)
                .filter(NotificationChannelModel.channel_id == channel_id)
                .first()
            )
            if not row:
                return None
            for key in ("name", "config", "is_enabled"):
                if key in updates:
                    setattr(row, key, updates[key])
            if "channel_type" in updates:
                row.channel_type = updates["channel_type"]
            self.db.commit()
            return self._row_to_channel_dict(row)

        channel = self._channels.get(channel_id)
        if not channel:
            return None
        if "name" in updates:
            channel.name = updates["name"]
        if "config" in updates:
            channel.config = updates["config"]
        if "is_enabled" in updates:
            channel.is_enabled = updates["is_enabled"]
        if "channel_type" in updates:
            channel.channel_type = ChannelType(updates["channel_type"])
        channel.updated_at = datetime.now(timezone.utc)
        return self._channel_to_dict(channel)

    def delete_channel(self, channel_id: str) -> bool:
        """Delete a notification channel."""
        if self._use_db:
            row = (
                self.db.query(NotificationChannelModel)
                .filter(NotificationChannelModel.channel_id == channel_id)
                .first()
            )
            if not row:
                return False
            self.db.delete(row)
            self.db.commit()
            return True

        if channel_id in self._channels:
            del self._channels[channel_id]
            return True
        return False

    def list_channels(self, channel_type: str = None, enabled_only: bool = False) -> List[Dict]:
        """List notification channels with optional filters."""
        if self._use_db:
            q = self.db.query(NotificationChannelModel)
            if channel_type:
                q = q.filter(NotificationChannelModel.channel_type == channel_type)
            if enabled_only:
                q = q.filter(NotificationChannelModel.is_enabled.is_(True))
            return [self._row_to_channel_dict(r) for r in q.all()]

        channels = list(self._channels.values())
        if channel_type:
            channels = [c for c in channels if c.channel_type.value == channel_type]
        if enabled_only:
            channels = [c for c in channels if c.is_enabled]
        return [self._channel_to_dict(c) for c in channels]

    def get_channel(self, channel_id: str) -> Optional[Dict]:
        """Get a single channel by ID."""
        if self._use_db:
            row = (
                self.db.query(NotificationChannelModel)
                .filter(NotificationChannelModel.channel_id == channel_id)
                .first()
            )
            return self._row_to_channel_dict(row) if row else None

        channel = self._channels.get(channel_id)
        return self._channel_to_dict(channel) if channel else None

    def test_channel(self, channel_id: str) -> Dict:
        """Send a test notification through a channel."""
        channel_dict = self.get_channel(channel_id)
        if not channel_dict:
            return {"success": False, "error": "Channel not found"}

        channel_type = channel_dict["channel_type"]
        config = channel_dict["config"]

        try:
            dispatch = self._get_dispatcher(channel_type)
            result = dispatch(
                config=config,
                subject="Aither MSP - Test Notification",
                body="This is a test notification from Aither MSP Notification Connector.",
                metadata={"test": True},
            )
            return {"success": True, "channel_id": channel_id, "result": result}
        except Exception as exc:
            logger.exception("Test notification failed for channel %s", channel_id)
            return {"success": False, "channel_id": channel_id, "error": str(exc)}

    # ----------------------------------------------------------
    # Rule CRUD
    # ----------------------------------------------------------

    def create_rule(
        self,
        name: str,
        event_types: List[str],
        channels: List[str],
        severity_filter: str = "all",
        is_enabled: bool = True,
        cooldown_minutes: int = 5,
    ) -> Dict:
        """Create a notification routing rule."""
        rule_id = f"rule-{uuid.uuid4().hex[:12]}"

        rule = NotificationRule(
            rule_id=rule_id,
            name=name,
            event_types=event_types,
            severity_filter=severity_filter,
            channels=channels,
            is_enabled=is_enabled,
            cooldown_minutes=cooldown_minutes,
        )

        if self._use_db:
            row = NotificationRuleModel(
                rule_id=rule.rule_id,
                name=rule.name,
                event_types=rule.event_types,
                severity_filter=rule.severity_filter,
                channels=rule.channels,
                is_enabled=rule.is_enabled,
                cooldown_minutes=rule.cooldown_minutes,
            )
            self.db.add(row)
            self.db.commit()
        else:
            self._rules[rule_id] = rule

        logger.info("Created notification rule %s", rule_id)
        return self._rule_to_dict(rule)

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[Dict]:
        """Update an existing notification rule."""
        if self._use_db:
            row = (
                self.db.query(NotificationRuleModel)
                .filter(NotificationRuleModel.rule_id == rule_id)
                .first()
            )
            if not row:
                return None
            for key in ("name", "event_types", "severity_filter", "channels",
                        "is_enabled", "cooldown_minutes"):
                if key in updates:
                    setattr(row, key, updates[key])
            self.db.commit()
            return self._row_to_rule_dict(row)

        rule = self._rules.get(rule_id)
        if not rule:
            return None
        for key in ("name", "event_types", "severity_filter", "channels",
                     "is_enabled", "cooldown_minutes"):
            if key in updates:
                setattr(rule, key, updates[key])
        rule.updated_at = datetime.now(timezone.utc)
        return self._rule_to_dict(rule)

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a notification rule."""
        if self._use_db:
            row = (
                self.db.query(NotificationRuleModel)
                .filter(NotificationRuleModel.rule_id == rule_id)
                .first()
            )
            if not row:
                return False
            self.db.delete(row)
            self.db.commit()
            return True

        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def list_rules(self, enabled_only: bool = False) -> List[Dict]:
        """List notification rules."""
        if self._use_db:
            q = self.db.query(NotificationRuleModel)
            if enabled_only:
                q = q.filter(NotificationRuleModel.is_enabled.is_(True))
            return [self._row_to_rule_dict(r) for r in q.all()]

        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.is_enabled]
        return [self._rule_to_dict(r) for r in rules]

    # ----------------------------------------------------------
    # Send / Dispatch
    # ----------------------------------------------------------

    def send_notification(
        self,
        event_type: str,
        severity: str,
        subject: str,
        body: str,
        metadata: Dict[str, Any] = None,
    ) -> Dict:
        """
        Route a platform event through all matching enabled rules.

        Applies severity filters, cooldown throttling, and dispatches
        to every channel referenced by each matching rule.

        Returns summary with per-channel delivery status.
        """
        metadata = metadata or {}
        results: List[Dict] = []
        rules = self._get_matching_rules(event_type, severity)

        for rule in rules:
            # Cooldown check
            if self._is_throttled(rule):
                for ch_id in (rule.channels if isinstance(rule, NotificationRule) else rule.get("channels", [])):
                    log = self._record_log(
                        rule_id=rule.rule_id if isinstance(rule, NotificationRule) else rule["rule_id"],
                        channel_id=ch_id,
                        event_type=event_type,
                        severity=severity,
                        subject=subject,
                        body=body,
                        status=NotificationStatus.THROTTLED.value,
                    )
                    results.append(self._log_to_dict(log))
                continue

            rule_id = rule.rule_id if isinstance(rule, NotificationRule) else rule["rule_id"]
            channel_ids = rule.channels if isinstance(rule, NotificationRule) else rule.get("channels", [])

            for ch_id in channel_ids:
                channel_dict = self.get_channel(ch_id)
                if not channel_dict or not channel_dict.get("is_enabled"):
                    continue

                status = NotificationStatus.SENT.value
                error = ""
                try:
                    dispatch = self._get_dispatcher(channel_dict["channel_type"])
                    dispatch(
                        config=channel_dict["config"],
                        subject=subject,
                        body=body,
                        metadata=metadata,
                    )
                except Exception as exc:
                    status = NotificationStatus.FAILED.value
                    error = str(exc)
                    logger.exception("Dispatch failed: channel=%s rule=%s", ch_id, rule_id)

                log = self._record_log(
                    rule_id=rule_id,
                    channel_id=ch_id,
                    event_type=event_type,
                    severity=severity,
                    subject=subject,
                    body=body,
                    status=status,
                    error=error,
                )
                results.append(self._log_to_dict(log))

            # Update last_triggered
            self._touch_rule(rule_id)

        return {
            "event_type": event_type,
            "severity": severity,
            "rules_matched": len(rules),
            "dispatches": results,
            "total_sent": len([r for r in results if r["status"] == "sent"]),
            "total_failed": len([r for r in results if r["status"] == "failed"]),
            "total_throttled": len([r for r in results if r["status"] == "throttled"]),
        }

    # ----------------------------------------------------------
    # Dispatchers
    # ----------------------------------------------------------

    def _get_dispatcher(self, channel_type: str):
        """Return the dispatch function for a channel type."""
        dispatchers = {
            ChannelType.EMAIL.value: self._dispatch_email,
            ChannelType.SLACK.value: self._dispatch_slack,
            ChannelType.PAGERDUTY.value: self._dispatch_pagerduty,
            ChannelType.MSTEAMS.value: self._dispatch_msteams,
            ChannelType.WEBHOOK.value: self._dispatch_webhook,
            ChannelType.SMS.value: self._dispatch_sms,
        }
        dispatch = dispatchers.get(channel_type)
        if not dispatch:
            raise ValueError(f"Unsupported channel type: {channel_type}")
        return dispatch

    def _dispatch_email(self, config: Dict, subject: str, body: str, metadata: Dict = None) -> Dict:
        """
        Send notification via email (SMTP).

        Expected config keys: smtp_host, smtp_port, smtp_user, smtp_password,
                              from_address, to_addresses (list)
        """
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg["From"] = config.get("from_address", "noreply@aither.io")
            msg["To"] = ", ".join(config.get("to_addresses", []))
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(
                config.get("smtp_host", "localhost"),
                config.get("smtp_port", 587),
                timeout=15,
            ) as server:
                if config.get("smtp_tls", True):
                    server.starttls()
                if config.get("smtp_user"):
                    server.login(config["smtp_user"], config.get("smtp_password", ""))
                server.sendmail(
                    msg["From"],
                    config.get("to_addresses", []),
                    msg.as_string(),
                )

            logger.info("Email notification sent to %s", msg["To"])
            return {"delivered": True, "to": msg["To"]}
        except Exception as exc:
            logger.error("Email dispatch failed: %s", exc)
            raise

    def _dispatch_slack(self, config: Dict, subject: str, body: str, metadata: Dict = None) -> Dict:
        """
        Send notification to Slack via incoming webhook.

        Expected config keys: webhook_url, channel (optional), username (optional)
        """
        try:
            import httpx

            payload = {
                "text": f"*{subject}*\n{body}",
            }
            if config.get("channel"):
                payload["channel"] = config["channel"]
            if config.get("username"):
                payload["username"] = config["username"]

            resp = httpx.post(
                config["webhook_url"],
                json=payload,
                timeout=15.0,
            )
            resp.raise_for_status()

            logger.info("Slack notification sent")
            return {"delivered": True, "status_code": resp.status_code}
        except Exception as exc:
            logger.error("Slack dispatch failed: %s", exc)
            raise

    def _dispatch_pagerduty(self, config: Dict, subject: str, body: str, metadata: Dict = None) -> Dict:
        """
        Trigger PagerDuty incident via Events API v2.

        Expected config keys: routing_key, severity (optional, default 'error')
        """
        try:
            import httpx

            payload = {
                "routing_key": config["routing_key"],
                "event_action": "trigger",
                "payload": {
                    "summary": subject,
                    "source": "aither-msp",
                    "severity": config.get("severity", "error"),
                    "custom_details": {
                        "body": body,
                        **(metadata or {}),
                    },
                },
            }

            resp = httpx.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=15.0,
            )
            resp.raise_for_status()

            logger.info("PagerDuty event triggered")
            return {"delivered": True, "status_code": resp.status_code, "response": resp.json()}
        except Exception as exc:
            logger.error("PagerDuty dispatch failed: %s", exc)
            raise

    def _dispatch_msteams(self, config: Dict, subject: str, body: str, metadata: Dict = None) -> Dict:
        """
        Send notification to Microsoft Teams via incoming webhook.

        Expected config keys: webhook_url
        """
        try:
            import httpx

            card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": subject,
                "themeColor": "0076D7",
                "title": subject,
                "sections": [
                    {
                        "activityTitle": "Aither MSP Alert",
                        "text": body,
                        "facts": [
                            {"name": k, "value": str(v)}
                            for k, v in (metadata or {}).items()
                        ],
                    }
                ],
            }

            resp = httpx.post(
                config["webhook_url"],
                json=card,
                timeout=15.0,
            )
            resp.raise_for_status()

            logger.info("MS Teams notification sent")
            return {"delivered": True, "status_code": resp.status_code}
        except Exception as exc:
            logger.error("MS Teams dispatch failed: %s", exc)
            raise

    def _dispatch_webhook(self, config: Dict, subject: str, body: str, metadata: Dict = None) -> Dict:
        """
        Send notification to a generic webhook endpoint.

        Expected config keys: url, method (default POST), headers (optional dict),
                              secret (optional, sent as X-Aither-Signature header)
        """
        try:
            import httpx
            import hashlib
            import hmac

            payload = {
                "subject": subject,
                "body": body,
                "metadata": metadata or {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "aither-msp",
            }

            headers = dict(config.get("headers", {}))
            headers["Content-Type"] = "application/json"

            if config.get("secret"):
                raw = json.dumps(payload, sort_keys=True).encode()
                sig = hmac.new(config["secret"].encode(), raw, hashlib.sha256).hexdigest()
                headers["X-Aither-Signature"] = sig

            method = config.get("method", "POST").upper()
            resp = httpx.request(
                method,
                config["url"],
                json=payload,
                headers=headers,
                timeout=15.0,
            )
            resp.raise_for_status()

            logger.info("Webhook notification sent to %s", config["url"])
            return {"delivered": True, "status_code": resp.status_code}
        except Exception as exc:
            logger.error("Webhook dispatch failed: %s", exc)
            raise

    def _dispatch_sms(self, config: Dict, subject: str, body: str, metadata: Dict = None) -> Dict:
        """
        Send SMS notification via Twilio API.

        Expected config keys: account_sid, auth_token, from_number, to_numbers (list)
        """
        try:
            import httpx

            message_body = f"{subject}: {body}"
            account_sid = config["account_sid"]
            results = []

            for to_number in config.get("to_numbers", []):
                resp = httpx.post(
                    f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
                    data={
                        "From": config["from_number"],
                        "To": to_number,
                        "Body": message_body[:1600],
                    },
                    auth=(account_sid, config["auth_token"]),
                    timeout=15.0,
                )
                resp.raise_for_status()
                results.append({"to": to_number, "status_code": resp.status_code})

            logger.info("SMS sent to %d recipients", len(results))
            return {"delivered": True, "results": results}
        except Exception as exc:
            logger.error("SMS dispatch failed: %s", exc)
            raise

    # ----------------------------------------------------------
    # Notification Log
    # ----------------------------------------------------------

    def get_notification_log(
        self,
        rule_id: str = None,
        channel_id: str = None,
        event_type: str = None,
        status: str = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Query notification delivery log with optional filters."""
        if self._use_db:
            q = self.db.query(NotificationLogModel)
            if rule_id:
                q = q.filter(NotificationLogModel.rule_id == rule_id)
            if channel_id:
                q = q.filter(NotificationLogModel.channel_id == channel_id)
            if event_type:
                q = q.filter(NotificationLogModel.event_type == event_type)
            if status:
                q = q.filter(NotificationLogModel.status == status)
            q = q.order_by(NotificationLogModel.sent_at.desc()).limit(limit)
            return [self._row_to_log_dict(r) for r in q.all()]

        logs = list(self._logs)
        if rule_id:
            logs = [l for l in logs if l.rule_id == rule_id]
        if channel_id:
            logs = [l for l in logs if l.channel_id == channel_id]
        if event_type:
            logs = [l for l in logs if l.event_type == event_type]
        if status:
            logs = [l for l in logs if l.status == status]
        return [self._log_to_dict(l) for l in logs[-limit:]]

    def get_dashboard(self) -> Dict:
        """Aggregate notification statistics for dashboard display."""
        channels = self.list_channels()
        rules = self.list_rules()
        logs = self.get_notification_log(limit=10000)

        sent = len([l for l in logs if l["status"] == "sent"])
        failed = len([l for l in logs if l["status"] == "failed"])
        throttled = len([l for l in logs if l["status"] == "throttled"])

        by_channel_type: Dict[str, int] = {}
        for ch in channels:
            ct = ch["channel_type"]
            by_channel_type[ct] = by_channel_type.get(ct, 0) + 1

        by_event_type: Dict[str, int] = {}
        for l in logs:
            et = l["event_type"]
            by_event_type[et] = by_event_type.get(et, 0) + 1

        return {
            "total_channels": len(channels),
            "enabled_channels": len([c for c in channels if c["is_enabled"]]),
            "total_rules": len(rules),
            "enabled_rules": len([r for r in rules if r["is_enabled"]]),
            "total_notifications": len(logs),
            "sent": sent,
            "failed": failed,
            "throttled": throttled,
            "channels_by_type": by_channel_type,
            "notifications_by_event": by_event_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ----------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------

    def _get_matching_rules(self, event_type: str, severity: str) -> list:
        """Return enabled rules whose event_types and severity_filter match."""
        matched = []
        rules = self.list_rules(enabled_only=True)
        for r in rules:
            if event_type not in r.get("event_types", []):
                continue
            sev = r.get("severity_filter", "all")
            if sev != "all" and sev != severity:
                continue
            matched.append(r)
        return matched

    def _is_throttled(self, rule) -> bool:
        """Check if a rule is within its cooldown period."""
        if isinstance(rule, NotificationRule):
            last = rule.last_triggered
            cooldown = rule.cooldown_minutes
        elif isinstance(rule, dict):
            last = rule.get("last_triggered")
            cooldown = rule.get("cooldown_minutes", 5)
        else:
            return False

        if not last:
            return False
        if isinstance(last, str):
            last = datetime.fromisoformat(last)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        return datetime.now(timezone.utc) < last + timedelta(minutes=cooldown)

    def _touch_rule(self, rule_id: str):
        """Update last_triggered timestamp on a rule."""
        now = datetime.now(timezone.utc)
        if self._use_db:
            row = (
                self.db.query(NotificationRuleModel)
                .filter(NotificationRuleModel.rule_id == rule_id)
                .first()
            )
            if row:
                row.last_triggered = now
                self.db.commit()
        else:
            rule = self._rules.get(rule_id)
            if rule:
                rule.last_triggered = now

    def _record_log(
        self,
        rule_id: str,
        channel_id: str,
        event_type: str,
        severity: str,
        subject: str,
        body: str,
        status: str,
        error: str = "",
    ) -> NotificationLog:
        """Persist a notification log entry."""
        log = NotificationLog(
            log_id=f"log-{uuid.uuid4().hex[:12]}",
            rule_id=rule_id,
            channel_id=channel_id,
            event_type=event_type,
            severity=severity,
            subject=subject,
            body=body,
            status=status,
            error=error,
        )

        if self._use_db:
            row = NotificationLogModel(
                log_id=log.log_id,
                rule_id=log.rule_id,
                channel_id=log.channel_id,
                event_type=log.event_type,
                severity=log.severity,
                subject=log.subject,
                body=log.body,
                status=log.status,
                error=log.error,
            )
            self.db.add(row)
            self.db.commit()
        else:
            self._logs.append(log)

        return log

    # ----------------------------------------------------------
    # Serialisation helpers
    # ----------------------------------------------------------

    @staticmethod
    def _channel_to_dict(channel: NotificationChannel) -> Dict:
        return {
            "channel_id": channel.channel_id,
            "channel_type": channel.channel_type.value if isinstance(channel.channel_type, ChannelType) else channel.channel_type,
            "name": channel.name,
            "config": channel.config,
            "is_enabled": channel.is_enabled,
            "created_at": channel.created_at.isoformat() if channel.created_at else None,
            "updated_at": channel.updated_at.isoformat() if channel.updated_at else None,
        }

    @staticmethod
    def _row_to_channel_dict(row) -> Dict:
        return {
            "channel_id": row.channel_id,
            "channel_type": row.channel_type,
            "name": row.name,
            "config": row.config or {},
            "is_enabled": row.is_enabled,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }

    @staticmethod
    def _rule_to_dict(rule: NotificationRule) -> Dict:
        return {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "event_types": rule.event_types,
            "severity_filter": rule.severity_filter,
            "channels": rule.channels,
            "is_enabled": rule.is_enabled,
            "cooldown_minutes": rule.cooldown_minutes,
            "last_triggered": rule.last_triggered.isoformat() if rule.last_triggered else None,
            "created_at": rule.created_at.isoformat() if rule.created_at else None,
            "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
        }

    @staticmethod
    def _row_to_rule_dict(row) -> Dict:
        return {
            "rule_id": row.rule_id,
            "name": row.name,
            "event_types": row.event_types or [],
            "severity_filter": row.severity_filter,
            "channels": row.channels or [],
            "is_enabled": row.is_enabled,
            "cooldown_minutes": row.cooldown_minutes,
            "last_triggered": row.last_triggered.isoformat() if row.last_triggered else None,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }

    @staticmethod
    def _log_to_dict(log: NotificationLog) -> Dict:
        return {
            "log_id": log.log_id,
            "rule_id": log.rule_id,
            "channel_id": log.channel_id,
            "event_type": log.event_type,
            "severity": log.severity,
            "subject": log.subject,
            "body": log.body,
            "status": log.status,
            "error": log.error,
            "sent_at": log.sent_at.isoformat() if log.sent_at else None,
        }

    @staticmethod
    def _row_to_log_dict(row) -> Dict:
        return {
            "log_id": row.log_id,
            "rule_id": row.rule_id,
            "channel_id": row.channel_id,
            "event_type": row.event_type,
            "severity": row.severity,
            "subject": row.subject,
            "body": row.body,
            "status": row.status,
            "error": row.error,
            "sent_at": row.sent_at.isoformat() if row.sent_at else None,
        }


# Global service instance (in-memory, no DB)
_service_instance: Optional[NotificationConnectorService] = None


def get_notification_connector(db: "Session" = None) -> NotificationConnectorService:
    """Get or create the global NotificationConnectorService instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = NotificationConnectorService(db=db)
    return _service_instance
