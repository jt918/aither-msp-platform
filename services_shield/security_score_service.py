"""
Aither Shield - Security Score Service

Cross-platform security scoring and recommendations.
Aggregates data from all devices and services.
"""

from typing import Dict, Optional, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid


class ScoreCategory(Enum):
    """Security score categories."""
    PROTECTION = "protection"
    SCANNING = "scanning"
    FIREWALL = "firewall"
    VPN = "vpn"
    PASSWORDS = "passwords"
    DARK_WEB = "dark_web"
    UPDATES = "updates"
    NETWORK = "network"


class RecommendationSeverity(Enum):
    """Recommendation severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class RecommendationStatus(Enum):
    """Recommendation status."""
    ACTIVE = "active"
    DISMISSED = "dismissed"
    COMPLETED = "completed"
    EXPIRED = "expired"


@dataclass
class SecurityRecommendation:
    """Security improvement recommendation."""
    id: str
    category: ScoreCategory
    severity: RecommendationSeverity
    title: str
    description: str
    impact_points: int
    action_url: Optional[str] = None
    status: RecommendationStatus = RecommendationStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.now)
    dismissed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class SecurityScore:
    """User's security score."""
    user_id: str
    overall_score: int
    category_scores: Dict[str, int]
    recommendations: List[SecurityRecommendation]
    last_calculated: datetime
    score_trend: str  # 'improving', 'stable', 'declining'
    historical_scores: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class DeviceSecurityState:
    """Security state for a single device."""
    device_id: str
    device_name: str
    device_type: str
    protection_enabled: bool
    last_scan_date: Optional[datetime]
    scan_result_clean: bool
    threats_pending: int
    firewall_enabled: bool
    vpn_enabled: bool
    app_updated: bool
    signature_updated: bool


class SecurityScoreService:
    """
    Security score calculation and recommendation service.

    Provides:
    - Unified security score across all devices
    - Category breakdown
    - Actionable recommendations
    - Historical tracking
    """

    # Category weights for overall score
    CATEGORY_WEIGHTS = {
        ScoreCategory.PROTECTION: 0.25,
        ScoreCategory.SCANNING: 0.15,
        ScoreCategory.FIREWALL: 0.15,
        ScoreCategory.VPN: 0.10,
        ScoreCategory.PASSWORDS: 0.15,
        ScoreCategory.DARK_WEB: 0.10,
        ScoreCategory.UPDATES: 0.10,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._scores: Dict[str, SecurityScore] = {}
        self._device_states: Dict[str, DeviceSecurityState] = {}
        self._recommendation_templates: List[Dict[str, Any]] = self._init_recommendations()

    def _init_recommendations(self) -> List[Dict[str, Any]]:
        """Initialize recommendation templates."""
        return [
            # Protection
            {
                "category": ScoreCategory.PROTECTION,
                "severity": RecommendationSeverity.CRITICAL,
                "check": "protection_disabled",
                "title": "Enable Real-Time Protection",
                "description": "Real-time protection is disabled on one or more devices. This leaves you vulnerable to new threats.",
                "impact_points": 20,
                "action_url": "/settings/protection",
            },
            {
                "category": ScoreCategory.PROTECTION,
                "severity": RecommendationSeverity.WARNING,
                "check": "cloud_protection_disabled",
                "title": "Enable Cloud Protection",
                "description": "Cloud-based threat detection provides additional protection against zero-day threats.",
                "impact_points": 10,
                "action_url": "/settings/protection",
            },

            # Scanning
            {
                "category": ScoreCategory.SCANNING,
                "severity": RecommendationSeverity.WARNING,
                "check": "no_recent_scan",
                "title": "Run a Security Scan",
                "description": "It's been over 7 days since your last full system scan.",
                "impact_points": 15,
                "action_url": "/scan",
            },
            {
                "category": ScoreCategory.SCANNING,
                "severity": RecommendationSeverity.CRITICAL,
                "check": "threats_pending",
                "title": "Resolve Pending Threats",
                "description": "You have unresolved threats that require action.",
                "impact_points": 25,
                "action_url": "/threats",
            },

            # Firewall
            {
                "category": ScoreCategory.FIREWALL,
                "severity": RecommendationSeverity.WARNING,
                "check": "firewall_disabled",
                "title": "Enable Firewall Protection",
                "description": "Your firewall is disabled, leaving your network vulnerable.",
                "impact_points": 15,
                "action_url": "/firewall",
            },

            # VPN
            {
                "category": ScoreCategory.VPN,
                "severity": RecommendationSeverity.INFO,
                "check": "vpn_not_used",
                "title": "Use VPN for Public Networks",
                "description": "Connect to VPN when using public WiFi for encrypted browsing.",
                "impact_points": 5,
                "action_url": "/vpn",
            },

            # Passwords
            {
                "category": ScoreCategory.PASSWORDS,
                "severity": RecommendationSeverity.WARNING,
                "check": "weak_passwords",
                "title": "Strengthen Weak Passwords",
                "description": "Some of your saved passwords are weak and easily guessable.",
                "impact_points": 10,
                "action_url": "/passwords/audit",
            },
            {
                "category": ScoreCategory.PASSWORDS,
                "severity": RecommendationSeverity.CRITICAL,
                "check": "reused_passwords",
                "title": "Fix Reused Passwords",
                "description": "Using the same password on multiple sites is a major security risk.",
                "impact_points": 15,
                "action_url": "/passwords/audit",
            },
            {
                "category": ScoreCategory.PASSWORDS,
                "severity": RecommendationSeverity.CRITICAL,
                "check": "compromised_passwords",
                "title": "Change Compromised Passwords",
                "description": "Some of your passwords have been found in data breaches.",
                "impact_points": 25,
                "action_url": "/passwords/compromised",
            },

            # Dark Web
            {
                "category": ScoreCategory.DARK_WEB,
                "severity": RecommendationSeverity.CRITICAL,
                "check": "dark_web_alerts",
                "title": "Review Dark Web Alerts",
                "description": "Your information was found on the dark web. Take action now.",
                "impact_points": 20,
                "action_url": "/darkweb",
            },

            # Updates
            {
                "category": ScoreCategory.UPDATES,
                "severity": RecommendationSeverity.WARNING,
                "check": "app_outdated",
                "title": "Update Shield App",
                "description": "A newer version of Aither Shield is available with security improvements.",
                "impact_points": 10,
                "action_url": "/settings/updates",
            },
            {
                "category": ScoreCategory.UPDATES,
                "severity": RecommendationSeverity.WARNING,
                "check": "signatures_outdated",
                "title": "Update Threat Signatures",
                "description": "Your threat signatures are outdated. Update for better protection.",
                "impact_points": 10,
                "action_url": "/settings/updates",
            },
        ]

    def calculate_score(
        self,
        user_id: str,
        devices: List[Dict[str, Any]],
        passwords: Optional[Dict[str, Any]] = None,
        dark_web: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive security score.

        Args:
            user_id: User ID
            devices: List of device security states
            passwords: Password vault statistics
            dark_web: Dark web monitoring status
        """
        # Process device states
        device_states = []
        for device in devices:
            state = DeviceSecurityState(
                device_id=device.get("device_id", ""),
                device_name=device.get("device_name", "Unknown"),
                device_type=device.get("device_type", "unknown"),
                protection_enabled=device.get("protection_enabled", False),
                last_scan_date=self._parse_date(device.get("last_scan")),
                scan_result_clean=device.get("threats_found", 0) == 0,
                threats_pending=device.get("threats_pending", 0),
                firewall_enabled=device.get("firewall_enabled", True),
                vpn_enabled=device.get("vpn_connected", False),
                app_updated=not device.get("needs_update", False),
                signature_updated=device.get("signature_updated", True),
            )
            device_states.append(state)
            self._device_states[state.device_id] = state

        # Calculate category scores
        category_scores = {
            ScoreCategory.PROTECTION.value: self._calculate_protection_score(device_states),
            ScoreCategory.SCANNING.value: self._calculate_scanning_score(device_states),
            ScoreCategory.FIREWALL.value: self._calculate_firewall_score(device_states),
            ScoreCategory.VPN.value: self._calculate_vpn_score(device_states),
            ScoreCategory.PASSWORDS.value: self._calculate_password_score(passwords),
            ScoreCategory.DARK_WEB.value: self._calculate_dark_web_score(dark_web),
            ScoreCategory.UPDATES.value: self._calculate_updates_score(device_states),
        }

        # Calculate overall score
        overall_score = self._calculate_overall_score(category_scores)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            device_states, passwords, dark_web
        )

        # Determine trend
        trend = self._calculate_trend(user_id, overall_score)

        # Create/update score record
        score = SecurityScore(
            user_id=user_id,
            overall_score=overall_score,
            category_scores=category_scores,
            recommendations=recommendations,
            last_calculated=datetime.now(),
            score_trend=trend,
        )

        # Add to historical
        if user_id in self._scores:
            old_score = self._scores[user_id]
            score.historical_scores = old_score.historical_scores[-29:]  # Keep 30 days
        score.historical_scores.append({
            "date": datetime.now().isoformat(),
            "score": overall_score,
        })

        self._scores[user_id] = score

        return {
            "overall_score": overall_score,
            "category_scores": category_scores,
            "recommendations": [self._recommendation_to_dict(r) for r in recommendations],
            "score_trend": trend,
            "last_calculated": score.last_calculated.isoformat(),
            "device_count": len(device_states),
        }

    def get_score(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user's current security score."""
        score = self._scores.get(user_id)
        if not score:
            return None

        return {
            "overall_score": score.overall_score,
            "category_scores": score.category_scores,
            "recommendations_count": len([r for r in score.recommendations
                                         if r.status == RecommendationStatus.ACTIVE]),
            "critical_count": len([r for r in score.recommendations
                                  if r.severity == RecommendationSeverity.CRITICAL
                                  and r.status == RecommendationStatus.ACTIVE]),
            "score_trend": score.score_trend,
            "last_calculated": score.last_calculated.isoformat(),
        }

    def get_recommendations(
        self,
        user_id: str,
        include_dismissed: bool = False,
    ) -> List[Dict[str, Any]]:
        """Get active recommendations for user."""
        score = self._scores.get(user_id)
        if not score:
            return []

        recommendations = score.recommendations
        if not include_dismissed:
            recommendations = [r for r in recommendations
                             if r.status == RecommendationStatus.ACTIVE]

        # Sort by severity (critical first)
        severity_order = {
            RecommendationSeverity.CRITICAL: 0,
            RecommendationSeverity.WARNING: 1,
            RecommendationSeverity.INFO: 2,
        }
        recommendations.sort(key=lambda r: severity_order.get(r.severity, 99))

        return [self._recommendation_to_dict(r) for r in recommendations]

    def dismiss_recommendation(
        self,
        user_id: str,
        recommendation_id: str,
    ) -> Dict[str, Any]:
        """Dismiss a recommendation."""
        score = self._scores.get(user_id)
        if not score:
            return {"success": False, "error": "Score not found"}

        for rec in score.recommendations:
            if rec.id == recommendation_id:
                rec.status = RecommendationStatus.DISMISSED
                rec.dismissed_at = datetime.now()
                return {"success": True, "status": "dismissed"}

        return {"success": False, "error": "Recommendation not found"}

    def complete_recommendation(
        self,
        user_id: str,
        recommendation_id: str,
    ) -> Dict[str, Any]:
        """Mark recommendation as completed."""
        score = self._scores.get(user_id)
        if not score:
            return {"success": False, "error": "Score not found"}

        for rec in score.recommendations:
            if rec.id == recommendation_id:
                rec.status = RecommendationStatus.COMPLETED
                rec.completed_at = datetime.now()
                return {
                    "success": True,
                    "status": "completed",
                    "points_gained": rec.impact_points,
                }

        return {"success": False, "error": "Recommendation not found"}

    def get_score_history(
        self,
        user_id: str,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Get score history for user."""
        score = self._scores.get(user_id)
        if not score:
            return []

        cutoff = datetime.now() - timedelta(days=days)
        history = []

        for entry in score.historical_scores:
            entry_date = datetime.fromisoformat(entry["date"])
            if entry_date >= cutoff:
                history.append(entry)

        return history

    def get_score_breakdown(self, user_id: str) -> Dict[str, Any]:
        """Get detailed score breakdown with explanations."""
        score = self._scores.get(user_id)
        if not score:
            return {"error": "Score not found"}

        breakdown = {
            "overall": {
                "score": score.overall_score,
                "grade": self._score_to_grade(score.overall_score),
                "description": self._get_score_description(score.overall_score),
            },
            "categories": {},
        }

        for category, cat_score in score.category_scores.items():
            weight = self.CATEGORY_WEIGHTS.get(ScoreCategory(category), 0)
            contribution = int(cat_score * weight)

            breakdown["categories"][category] = {
                "score": cat_score,
                "weight": weight,
                "contribution": contribution,
                "grade": self._score_to_grade(cat_score),
                "recommendations": [
                    self._recommendation_to_dict(r)
                    for r in score.recommendations
                    if r.category.value == category and r.status == RecommendationStatus.ACTIVE
                ],
            }

        return breakdown

    def _calculate_protection_score(self, devices: List[DeviceSecurityState]) -> int:
        """Calculate protection category score."""
        if not devices:
            return 0

        protected = sum(1 for d in devices if d.protection_enabled)
        clean = sum(1 for d in devices if d.scan_result_clean)
        no_threats = sum(1 for d in devices if d.threats_pending == 0)

        protection_ratio = protected / len(devices) if devices else 0
        clean_ratio = clean / len(devices) if devices else 0
        threat_free_ratio = no_threats / len(devices) if devices else 0

        score = int((protection_ratio * 50 + clean_ratio * 25 + threat_free_ratio * 25))
        return min(100, max(0, score))

    def _calculate_scanning_score(self, devices: List[DeviceSecurityState]) -> int:
        """Calculate scanning category score."""
        if not devices:
            return 0

        now = datetime.now()
        scores = []

        for device in devices:
            if not device.last_scan_date:
                scores.append(0)
            else:
                days_since_scan = (now - device.last_scan_date).days
                if days_since_scan <= 1:
                    scores.append(100)
                elif days_since_scan <= 7:
                    scores.append(80)
                elif days_since_scan <= 30:
                    scores.append(50)
                else:
                    scores.append(20)

        return int(sum(scores) / len(scores)) if scores else 0

    def _calculate_firewall_score(self, devices: List[DeviceSecurityState]) -> int:
        """Calculate firewall category score."""
        desktop_devices = [d for d in devices if d.device_type in ["windows", "mac"]]
        if not desktop_devices:
            return 100  # No desktops, N/A

        enabled = sum(1 for d in desktop_devices if d.firewall_enabled)
        return int((enabled / len(desktop_devices)) * 100)

    def _calculate_vpn_score(self, devices: List[DeviceSecurityState]) -> int:
        """Calculate VPN usage score."""
        # VPN is optional, so baseline is 70
        # Using VPN adds points
        if not devices:
            return 70

        using_vpn = sum(1 for d in devices if d.vpn_enabled)
        vpn_ratio = using_vpn / len(devices)

        return int(70 + (vpn_ratio * 30))

    def _calculate_password_score(self, passwords: Optional[Dict[str, Any]]) -> int:
        """Calculate password security score."""
        if not passwords:
            return 70  # Default if not using password manager

        total = passwords.get("total_passwords", 0)
        if total == 0:
            return 70

        weak = passwords.get("weak_count", 0)
        reused = passwords.get("reused_count", 0)
        compromised = passwords.get("compromised_count", 0)

        # Start at 100 and deduct
        score = 100
        score -= (weak / total) * 20 if total else 0
        score -= (reused / total) * 25 if total else 0
        score -= min((compromised / total) * 40, 40) if total else 0

        return int(max(0, min(100, score)))

    def _calculate_dark_web_score(self, dark_web: Optional[Dict[str, Any]]) -> int:
        """Calculate dark web monitoring score."""
        if not dark_web:
            return 80  # Not monitored

        alerts = dark_web.get("unresolved_alerts", 0)

        if alerts == 0:
            return 100
        elif alerts <= 2:
            return 70
        elif alerts <= 5:
            return 40
        else:
            return 20

    def _calculate_updates_score(self, devices: List[DeviceSecurityState]) -> int:
        """Calculate updates category score."""
        if not devices:
            return 100

        app_updated = sum(1 for d in devices if d.app_updated)
        sig_updated = sum(1 for d in devices if d.signature_updated)

        app_ratio = app_updated / len(devices)
        sig_ratio = sig_updated / len(devices)

        return int((app_ratio * 50 + sig_ratio * 50))

    def _calculate_overall_score(self, category_scores: Dict[str, int]) -> int:
        """Calculate weighted overall score."""
        total = 0
        for category, score in category_scores.items():
            weight = self.CATEGORY_WEIGHTS.get(ScoreCategory(category), 0)
            total += score * weight
        return int(total)

    def _generate_recommendations(
        self,
        devices: List[DeviceSecurityState],
        passwords: Optional[Dict[str, Any]],
        dark_web: Optional[Dict[str, Any]],
    ) -> List[SecurityRecommendation]:
        """Generate recommendations based on security state."""
        recommendations = []

        for template in self._recommendation_templates:
            check = template["check"]
            should_recommend = False

            # Check conditions
            if check == "protection_disabled":
                should_recommend = any(not d.protection_enabled for d in devices)
            elif check == "no_recent_scan":
                now = datetime.now()
                should_recommend = any(
                    not d.last_scan_date or (now - d.last_scan_date).days > 7
                    for d in devices
                )
            elif check == "threats_pending":
                should_recommend = any(d.threats_pending > 0 for d in devices)
            elif check == "firewall_disabled":
                desktop_devices = [d for d in devices if d.device_type in ["windows", "mac"]]
                should_recommend = any(not d.firewall_enabled for d in desktop_devices)
            elif check == "vpn_not_used":
                should_recommend = all(not d.vpn_enabled for d in devices)
            elif check == "weak_passwords" and passwords:
                should_recommend = passwords.get("weak_count", 0) > 0
            elif check == "reused_passwords" and passwords:
                should_recommend = passwords.get("reused_count", 0) > 0
            elif check == "compromised_passwords" and passwords:
                should_recommend = passwords.get("compromised_count", 0) > 0
            elif check == "dark_web_alerts" and dark_web:
                should_recommend = dark_web.get("unresolved_alerts", 0) > 0
            elif check == "app_outdated":
                should_recommend = any(not d.app_updated for d in devices)
            elif check == "signatures_outdated":
                should_recommend = any(not d.signature_updated for d in devices)

            if should_recommend:
                recommendations.append(SecurityRecommendation(
                    id=str(uuid.uuid4()),
                    category=template["category"],
                    severity=template["severity"],
                    title=template["title"],
                    description=template["description"],
                    impact_points=template["impact_points"],
                    action_url=template.get("action_url"),
                ))

        return recommendations

    def _calculate_trend(self, user_id: str, new_score: int) -> str:
        """Calculate score trend."""
        if user_id not in self._scores:
            return "stable"

        old_score = self._scores[user_id]
        if len(old_score.historical_scores) < 2:
            return "stable"

        recent_scores = [s["score"] for s in old_score.historical_scores[-7:]]
        avg = sum(recent_scores) / len(recent_scores)

        if new_score > avg + 5:
            return "improving"
        elif new_score < avg - 5:
            return "declining"
        return "stable"

    def _score_to_grade(self, score: int) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        return "F"

    def _get_score_description(self, score: int) -> str:
        """Get description for score range."""
        if score >= 90:
            return "Excellent! Your security is top-notch."
        elif score >= 80:
            return "Good. A few improvements will make you even safer."
        elif score >= 70:
            return "Fair. There are some areas that need attention."
        elif score >= 60:
            return "Poor. Several security issues need to be addressed."
        return "Critical. Immediate action required to secure your devices."

    def _recommendation_to_dict(self, rec: SecurityRecommendation) -> Dict[str, Any]:
        """Convert recommendation to dictionary."""
        return {
            "id": rec.id,
            "category": rec.category.value,
            "severity": rec.severity.value,
            "title": rec.title,
            "description": rec.description,
            "impact_points": rec.impact_points,
            "action_url": rec.action_url,
            "status": rec.status.value,
            "created_at": rec.created_at.isoformat(),
        }

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            return None
