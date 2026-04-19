"""
AITHER Platform - Synapse MSP Integration Service
AI-Powered MSP Command Center

Connects the Synapse AI/SME engine to MSP operations, providing:
- Intelligent ticket routing and triage via domain-specific advisors
- Threat analysis and incident response guidance
- Compliance gap detection and audit readiness
- Capacity planning and performance optimization
- Automated decision-making via event-triggered rules
- Accuracy tracking and feedback loops for continuous improvement

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.synapse_msp import (
        MSPAdvisorModel,
        AdvisoryRequestModel,
        AdvisoryResponseModel,
        MSPInsightModel,
        AutomationRuleModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ==================== Enums ====================

class AdvisorDomain(str, Enum):
    """MSP advisor domain specializations."""
    SECURITY = "security"
    COMPLIANCE = "compliance"
    INFRASTRUCTURE = "infrastructure"
    HELPDESK = "helpdesk"
    EXECUTIVE = "executive"
    NETWORK = "network"
    CLOUD = "cloud"


class RequestType(str, Enum):
    """Types of advisory requests."""
    TICKET_TRIAGE = "ticket_triage"
    THREAT_ANALYSIS = "threat_analysis"
    COMPLIANCE_CHECK = "compliance_check"
    CAPACITY_PLAN = "capacity_plan"
    INCIDENT_RESPONSE = "incident_response"
    ROOT_CAUSE_ANALYSIS = "root_cause_analysis"
    REMEDIATION_PLAN = "remediation_plan"
    PERFORMANCE_REVIEW = "performance_review"
    VENDOR_EVALUATION = "vendor_evaluation"
    BUDGET_FORECAST = "budget_forecast"


class InsightType(str, Enum):
    """Types of MSP insights."""
    TREND = "trend"
    ANOMALY = "anomaly"
    PREDICTION = "prediction"
    RECOMMENDATION = "recommendation"
    ALERT = "alert"
    OPPORTUNITY = "opportunity"


# ==================== Dataclasses ====================

@dataclass
class MSPAdvisor:
    """An AI advisor specialized in an MSP domain."""
    advisor_id: str
    name: str
    domain: str
    specializations: List[str] = field(default_factory=list)
    knowledge_base: Dict[str, Any] = field(default_factory=dict)
    confidence_threshold: float = 0.7
    decisions_made: int = 0
    accuracy_rate: float = 1.0
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class AdvisoryRequest:
    """A request for advisory guidance."""
    request_id: str
    advisor_id: str = ""
    request_type: str = "ticket_triage"
    context: Dict[str, Any] = field(default_factory=dict)
    urgency: str = "medium"
    status: str = "pending"
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class AdvisoryResponse:
    """An AI-generated advisory recommendation."""
    response_id: str
    request_id: str
    advisor_id: str
    recommendation: str = ""
    confidence: float = 0.0
    reasoning: List[str] = field(default_factory=list)
    alternative_actions: List[str] = field(default_factory=list)
    estimated_impact: str = ""
    auto_executable: bool = False
    executed: bool = False
    executed_at: Optional[str] = None
    was_helpful: Optional[bool] = None
    feedback: str = ""


@dataclass
class MSPInsight:
    """An AI-generated actionable insight."""
    insight_id: str
    insight_type: str = "recommendation"
    title: str = ""
    description: str = ""
    severity: str = "medium"
    data_points: Dict[str, Any] = field(default_factory=dict)
    affected_clients: List[str] = field(default_factory=list)
    action_required: bool = False
    generated_at: str = ""
    expires_at: Optional[str] = None

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()


@dataclass
class AutomationRule:
    """An event-triggered automation rule that invokes an advisor."""
    rule_id: str
    name: str = ""
    trigger_event: str = ""
    condition: Dict[str, Any] = field(default_factory=dict)
    advisor_domain: str = "helpdesk"
    action: Dict[str, Any] = field(default_factory=dict)
    is_enabled: bool = True
    executions: int = 0
    last_triggered: Optional[str] = None


# ==================== Request-Type to Domain Mapping ====================

_REQUEST_DOMAIN_MAP: Dict[str, str] = {
    RequestType.TICKET_TRIAGE.value: AdvisorDomain.HELPDESK.value,
    RequestType.THREAT_ANALYSIS.value: AdvisorDomain.SECURITY.value,
    RequestType.COMPLIANCE_CHECK.value: AdvisorDomain.COMPLIANCE.value,
    RequestType.CAPACITY_PLAN.value: AdvisorDomain.INFRASTRUCTURE.value,
    RequestType.INCIDENT_RESPONSE.value: AdvisorDomain.SECURITY.value,
    RequestType.ROOT_CAUSE_ANALYSIS.value: AdvisorDomain.INFRASTRUCTURE.value,
    RequestType.REMEDIATION_PLAN.value: AdvisorDomain.SECURITY.value,
    RequestType.PERFORMANCE_REVIEW.value: AdvisorDomain.EXECUTIVE.value,
    RequestType.VENDOR_EVALUATION.value: AdvisorDomain.EXECUTIVE.value,
    RequestType.BUDGET_FORECAST.value: AdvisorDomain.EXECUTIVE.value,
}


# ==================== Service ====================

class SynapseMSPService:
    """
    Synapse MSP Integration Service - AI Brain for MSP Operations

    Provides a roster of pre-built AI advisors that analyze tickets,
    threats, compliance posture, capacity, and business metrics to
    deliver actionable recommendations. Supports event-driven
    automation rules and continuous accuracy tracking via feedback.

    Integrates with:
    - ITSMService (ticket data for triage)
    - Cyber911Service (threat/incident data)
    - RMMService (endpoint/infrastructure data)
    - ComplianceFrameworks (framework controls)
    - SMEPersonaLibrary (domain knowledge inheritance)
    """

    def __init__(self, db: "Session | None" = None):
        self._db = db
        self._use_db = ORM_AVAILABLE and db is not None

        # In-memory fallback stores
        self._advisors: Dict[str, MSPAdvisor] = {}
        self._requests: Dict[str, AdvisoryRequest] = {}
        self._responses: Dict[str, AdvisoryResponse] = {}
        self._insights: Dict[str, MSPInsight] = {}
        self._rules: Dict[str, AutomationRule] = {}

        # Seed built-in advisors
        self._init_advisors()
        logger.info(
            f"SynapseMSPService initialized ({'DB' if self._use_db else 'in-memory'}) "
            f"with {len(self._advisors)} advisors"
        )

    # ------------------------------------------------------------------ #
    # Initialization
    # ------------------------------------------------------------------ #

    def _init_advisors(self) -> None:
        """Seed the 7 pre-built MSP advisors."""
        builtin = [
            MSPAdvisor(
                advisor_id="ADV-AEGIS",
                name="Aegis",
                domain=AdvisorDomain.SECURITY.value,
                specializations=[
                    "threat_analysis", "incident_triage",
                    "vulnerability_prioritization", "SOAR_playbooks",
                ],
                knowledge_base={
                    "frameworks": ["MITRE ATT&CK", "OWASP Top 10", "CVE"],
                    "auto_actions": [
                        "escalate_critical_threats",
                        "trigger_soar_playbook",
                        "isolate_compromised_host",
                    ],
                    "severity_matrix": {
                        "ransomware": "critical",
                        "phishing": "high",
                        "policy_violation": "medium",
                    },
                },
                confidence_threshold=0.8,
            ),
            MSPAdvisor(
                advisor_id="ADV-COMPLIANCE",
                name="Compliance Oracle",
                domain=AdvisorDomain.COMPLIANCE.value,
                specializations=[
                    "framework_mapping", "audit_readiness",
                    "gap_analysis", "control_assessment",
                ],
                knowledge_base={
                    "frameworks": ["HIPAA", "SOC2", "NIST 800-171", "CMMC", "PCI-DSS"],
                    "control_mappings": {
                        "HIPAA": 75,
                        "SOC2": 64,
                        "NIST": 110,
                        "CMMC": 171,
                        "PCI-DSS": 12,
                    },
                },
                confidence_threshold=0.85,
            ),
            MSPAdvisor(
                advisor_id="ADV-INFRA",
                name="Infrastructure Sage",
                domain=AdvisorDomain.INFRASTRUCTURE.value,
                specializations=[
                    "capacity_planning", "performance_optimization",
                    "architecture_review", "reliability_engineering",
                ],
                knowledge_base={
                    "patterns": [
                        "cloud_scaling", "cost_optimization",
                        "high_availability", "disaster_recovery",
                    ],
                    "thresholds": {
                        "cpu_warning": 75,
                        "cpu_critical": 90,
                        "memory_warning": 80,
                        "memory_critical": 95,
                        "disk_warning": 85,
                        "disk_critical": 95,
                    },
                },
                confidence_threshold=0.75,
            ),
            MSPAdvisor(
                advisor_id="ADV-HELPDESK",
                name="Helpdesk Mentor",
                domain=AdvisorDomain.HELPDESK.value,
                specializations=[
                    "ticket_classification", "priority_assignment",
                    "kb_suggestions", "first_response_drafting",
                ],
                knowledge_base={
                    "categories": [
                        "hardware", "software", "network", "security",
                        "email", "printer", "access", "other",
                    ],
                    "sla_rules": {
                        "P1": {"response_mins": 15, "resolution_hrs": 4},
                        "P2": {"response_mins": 30, "resolution_hrs": 8},
                        "P3": {"response_mins": 60, "resolution_hrs": 24},
                        "P4": {"response_mins": 120, "resolution_hrs": 72},
                    },
                    "common_resolutions": {
                        "password_reset": "Reset via AD admin console or self-service portal",
                        "vpn_failure": "Check certificate expiry, re-install VPN client",
                        "printer_offline": "Verify network, restart print spooler",
                        "email_sync": "Rebuild Outlook profile, verify autodiscover",
                    },
                },
                confidence_threshold=0.7,
            ),
            MSPAdvisor(
                advisor_id="ADV-EXEC",
                name="Executive Strategist",
                domain=AdvisorDomain.EXECUTIVE.value,
                specializations=[
                    "business_metrics", "client_health_analysis",
                    "revenue_optimization", "churn_prediction",
                ],
                knowledge_base={
                    "kpis": [
                        "MRR", "ARPU", "NPS", "churn_rate", "utilization",
                        "ticket_volume_trend", "SLA_compliance",
                    ],
                    "pricing_models": ["per_device", "per_user", "tiered", "value_based"],
                    "churn_indicators": [
                        "declining_ticket_satisfaction",
                        "increasing_sla_breaches",
                        "reduced_engagement",
                        "competitor_mentions",
                    ],
                },
                confidence_threshold=0.75,
            ),
            MSPAdvisor(
                advisor_id="ADV-NETWORK",
                name="Network Architect",
                domain=AdvisorDomain.NETWORK.value,
                specializations=[
                    "topology_analysis", "segmentation",
                    "performance_tuning", "firewall_review",
                ],
                knowledge_base={
                    "design_patterns": [
                        "VLAN_segmentation", "micro_segmentation",
                        "zero_trust", "SD-WAN",
                    ],
                    "qos_policies": {
                        "voice": {"dscp": 46, "bandwidth_pct": 30},
                        "video": {"dscp": 34, "bandwidth_pct": 25},
                        "critical_data": {"dscp": 26, "bandwidth_pct": 25},
                        "best_effort": {"dscp": 0, "bandwidth_pct": 20},
                    },
                },
                confidence_threshold=0.75,
            ),
            MSPAdvisor(
                advisor_id="ADV-CLOUD",
                name="Cloud Navigator",
                domain=AdvisorDomain.CLOUD.value,
                specializations=[
                    "cloud_migration", "cost_optimization",
                    "security_posture", "finops",
                ],
                knowledge_base={
                    "providers": ["AWS", "Azure", "GCP"],
                    "best_practices": [
                        "right_sizing", "reserved_instances", "spot_instances",
                        "tagging_strategy", "landing_zone", "guardrails",
                    ],
                    "finops_principles": [
                        "visibility", "optimization", "governance",
                    ],
                },
                confidence_threshold=0.75,
            ),
        ]

        for advisor in builtin:
            self._advisors[advisor.advisor_id] = advisor
            if self._use_db:
                self._persist_advisor(advisor)

    # ------------------------------------------------------------------ #
    # DB Persistence Helpers
    # ------------------------------------------------------------------ #

    def _persist_advisor(self, adv: MSPAdvisor) -> None:
        """Upsert advisor to DB."""
        if not self._use_db:
            return
        try:
            existing = (
                self._db.query(MSPAdvisorModel)
                .filter(MSPAdvisorModel.advisor_id == adv.advisor_id)
                .first()
            )
            if existing:
                existing.name = adv.name
                existing.domain = adv.domain
                existing.specializations = adv.specializations
                existing.knowledge_base = adv.knowledge_base
                existing.confidence_threshold = adv.confidence_threshold
                existing.decisions_made = adv.decisions_made
                existing.accuracy_rate = adv.accuracy_rate
            else:
                self._db.add(MSPAdvisorModel(
                    advisor_id=adv.advisor_id,
                    name=adv.name,
                    domain=adv.domain,
                    specializations=adv.specializations,
                    knowledge_base=adv.knowledge_base,
                    confidence_threshold=adv.confidence_threshold,
                    decisions_made=adv.decisions_made,
                    accuracy_rate=adv.accuracy_rate,
                ))
            self._db.commit()
        except Exception as exc:
            logger.warning(f"DB persist advisor failed: {exc}")
            self._db.rollback()

    def _persist_request(self, req: AdvisoryRequest) -> None:
        if not self._use_db:
            return
        try:
            self._db.add(AdvisoryRequestModel(
                request_id=req.request_id,
                advisor_id=req.advisor_id,
                request_type=req.request_type,
                context=req.context,
                urgency=req.urgency,
                status=req.status,
            ))
            self._db.commit()
        except Exception as exc:
            logger.warning(f"DB persist request failed: {exc}")
            self._db.rollback()

    def _persist_response(self, resp: AdvisoryResponse) -> None:
        if not self._use_db:
            return
        try:
            self._db.add(AdvisoryResponseModel(
                response_id=resp.response_id,
                request_id=resp.request_id,
                advisor_id=resp.advisor_id,
                recommendation=resp.recommendation,
                confidence=resp.confidence,
                reasoning=resp.reasoning,
                alternative_actions=resp.alternative_actions,
                estimated_impact=resp.estimated_impact,
                auto_executable=resp.auto_executable,
                executed=resp.executed,
            ))
            self._db.commit()
        except Exception as exc:
            logger.warning(f"DB persist response failed: {exc}")
            self._db.rollback()

    def _persist_insight(self, ins: MSPInsight) -> None:
        if not self._use_db:
            return
        try:
            self._db.add(MSPInsightModel(
                insight_id=ins.insight_id,
                insight_type=ins.insight_type,
                title=ins.title,
                description=ins.description,
                severity=ins.severity,
                data_points=ins.data_points,
                affected_clients=ins.affected_clients,
                action_required=ins.action_required,
            ))
            self._db.commit()
        except Exception as exc:
            logger.warning(f"DB persist insight failed: {exc}")
            self._db.rollback()

    def _persist_rule(self, rule: AutomationRule) -> None:
        if not self._use_db:
            return
        try:
            self._db.add(AutomationRuleModel(
                rule_id=rule.rule_id,
                name=rule.name,
                trigger_event=rule.trigger_event,
                condition=rule.condition,
                advisor_domain=rule.advisor_domain,
                action=rule.action,
                is_enabled=rule.is_enabled,
                executions=rule.executions,
            ))
            self._db.commit()
        except Exception as exc:
            logger.warning(f"DB persist rule failed: {exc}")
            self._db.rollback()

    # ------------------------------------------------------------------ #
    # Advisor CRUD
    # ------------------------------------------------------------------ #

    def create_advisor(
        self,
        name: str,
        domain: str,
        specializations: List[str] | None = None,
        knowledge_base: Dict[str, Any] | None = None,
        confidence_threshold: float = 0.7,
    ) -> Dict[str, Any]:
        """Create a custom MSP advisor."""
        aid = f"ADV-{uuid.uuid4().hex[:8].upper()}"
        advisor = MSPAdvisor(
            advisor_id=aid,
            name=name,
            domain=domain,
            specializations=specializations or [],
            knowledge_base=knowledge_base or {},
            confidence_threshold=confidence_threshold,
        )
        self._advisors[aid] = advisor
        self._persist_advisor(advisor)
        logger.info(f"Created advisor {aid} ({name}) domain={domain}")
        return self._advisor_to_dict(advisor)

    def get_advisor(self, advisor_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single advisor by ID."""
        adv = self._advisors.get(advisor_id)
        if adv:
            return self._advisor_to_dict(adv)
        return None

    def list_advisors(self, domain: str | None = None) -> List[Dict[str, Any]]:
        """List all advisors, optionally filtered by domain."""
        results = list(self._advisors.values())
        if domain:
            results = [a for a in results if a.domain == domain]
        return [self._advisor_to_dict(a) for a in results]

    def update_advisor(self, advisor_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update advisor fields."""
        adv = self._advisors.get(advisor_id)
        if not adv:
            return None
        for key in ("name", "domain", "specializations", "knowledge_base", "confidence_threshold"):
            if key in updates:
                setattr(adv, key, updates[key])
        self._persist_advisor(adv)
        return self._advisor_to_dict(adv)

    # ------------------------------------------------------------------ #
    # Advisory Pipeline
    # ------------------------------------------------------------------ #

    def request_advisory(
        self,
        request_type: str,
        context: Dict[str, Any],
        urgency: str = "medium",
    ) -> Dict[str, Any]:
        """
        Submit an advisory request. Routes to the appropriate advisor,
        analyzes the context, and returns a recommendation.
        """
        rid = f"REQ-{uuid.uuid4().hex[:8].upper()}"
        advisor = self._route_to_advisor(request_type)

        req = AdvisoryRequest(
            request_id=rid,
            advisor_id=advisor.advisor_id if advisor else "",
            request_type=request_type,
            context=context,
            urgency=urgency,
            status="analyzing",
        )
        self._requests[rid] = req
        self._persist_request(req)

        if not advisor:
            req.status = "deferred"
            return {
                "request_id": rid,
                "status": "deferred",
                "message": f"No advisor available for request type '{request_type}'",
            }

        # Dispatch to the appropriate analysis method
        response = self._dispatch_analysis(advisor, req)

        req.status = "completed"
        return {
            "request_id": rid,
            "advisor": self._advisor_to_dict(advisor),
            "response": self._response_to_dict(response),
            "status": "completed",
        }

    def _route_to_advisor(self, request_type: str) -> Optional[MSPAdvisor]:
        """Route a request type to the best-fit advisor by domain."""
        target_domain = _REQUEST_DOMAIN_MAP.get(request_type)
        if not target_domain:
            return None
        for adv in self._advisors.values():
            if adv.domain == target_domain:
                return adv
        return None

    def _dispatch_analysis(self, advisor: MSPAdvisor, req: AdvisoryRequest) -> AdvisoryResponse:
        """Dispatch to the correct analysis method based on request type."""
        dispatch = {
            RequestType.TICKET_TRIAGE.value: self._analyze_ticket,
            RequestType.THREAT_ANALYSIS.value: self._analyze_threat,
            RequestType.COMPLIANCE_CHECK.value: self._check_compliance,
            RequestType.CAPACITY_PLAN.value: self._plan_capacity,
            RequestType.INCIDENT_RESPONSE.value: self._analyze_threat,
            RequestType.ROOT_CAUSE_ANALYSIS.value: self._analyze_root_cause,
            RequestType.REMEDIATION_PLAN.value: self._plan_remediation,
        }
        handler = dispatch.get(req.request_type, self._generic_advisory)
        return handler(advisor, req)

    # ------------------------------------------------------------------ #
    # Analysis Methods
    # ------------------------------------------------------------------ #

    def _analyze_ticket(self, advisor: MSPAdvisor, req: AdvisoryRequest) -> AdvisoryResponse:
        """Classify ticket, suggest priority, recommend assignee, draft first response."""
        ctx = req.context
        title = ctx.get("title", "").lower()
        description = ctx.get("description", "").lower()
        combined = f"{title} {description}"

        # Category classification
        category = "other"
        category_keywords = {
            "network": ["network", "internet", "wifi", "dns", "connectivity", "vpn"],
            "security": ["security", "virus", "malware", "phishing", "breach", "suspicious"],
            "hardware": ["hardware", "laptop", "monitor", "keyboard", "mouse", "dock"],
            "software": ["software", "install", "update", "crash", "license", "application"],
            "email": ["email", "outlook", "exchange", "calendar", "teams"],
            "printer": ["printer", "print", "scanner", "fax", "toner"],
            "access": ["access", "permission", "password", "login", "account", "locked"],
        }
        for cat, keywords in category_keywords.items():
            if any(kw in combined for kw in keywords):
                category = cat
                break

        # Priority suggestion
        priority = "P3"
        if any(kw in combined for kw in ["down", "outage", "critical", "emergency", "ransomware"]):
            priority = "P1"
        elif any(kw in combined for kw in ["slow", "degraded", "multiple users", "urgent"]):
            priority = "P2"
        elif any(kw in combined for kw in ["request", "nice to have", "when possible"]):
            priority = "P4"

        # Draft first response
        kb = advisor.knowledge_base.get("common_resolutions", {})
        resolution_hint = ""
        for issue_key, resolution in kb.items():
            if issue_key.replace("_", " ") in combined:
                resolution_hint = resolution
                break

        sla = advisor.knowledge_base.get("sla_rules", {}).get(priority, {})

        recommendation = (
            f"Category: {category} | Priority: {priority} | "
            f"SLA: respond in {sla.get('response_mins', '?')}min, "
            f"resolve in {sla.get('resolution_hrs', '?')}hr"
        )
        if resolution_hint:
            recommendation += f" | Suggested resolution: {resolution_hint}"

        reasoning = [
            f"Classified category as '{category}' based on keyword analysis",
            f"Assigned priority {priority} based on impact/urgency signals",
            f"SLA targets applied from {priority} tier",
        ]
        if resolution_hint:
            reasoning.append("Matched known resolution pattern from knowledge base")

        resp = self._build_response(
            advisor=advisor,
            req=req,
            recommendation=recommendation,
            confidence=0.82,
            reasoning=reasoning,
            alternatives=[
                f"Escalate to {category} specialist team",
                "Request additional details from end-user",
            ],
            impact=f"Ticket routed to {category} queue with {priority} SLA",
            auto_executable=priority in ("P3", "P4"),
        )
        return resp

    def _analyze_threat(self, advisor: MSPAdvisor, req: AdvisoryRequest) -> AdvisoryResponse:
        """Classify threat, assess severity, recommend containment actions."""
        ctx = req.context
        threat_type = ctx.get("threat_type", "unknown")
        source_ip = ctx.get("source_ip", "unknown")
        affected_assets = ctx.get("affected_assets", [])
        indicators = ctx.get("indicators", {})

        severity_map = advisor.knowledge_base.get("severity_matrix", {})
        severity = severity_map.get(threat_type, "high")

        containment_actions = []
        if severity == "critical":
            containment_actions = [
                "Isolate affected hosts immediately",
                "Block source IP at perimeter firewall",
                "Revoke compromised credentials",
                "Trigger SOAR incident response playbook",
                "Notify SOC and executive stakeholders",
            ]
        elif severity == "high":
            containment_actions = [
                "Monitor affected systems closely",
                "Block source IP",
                "Initiate forensic log collection",
                "Alert SOC team",
            ]
        else:
            containment_actions = [
                "Log and monitor for recurrence",
                "Update threat intelligence feed",
                "Review related firewall rules",
            ]

        recommendation = (
            f"Threat: {threat_type} | Severity: {severity} | "
            f"Source: {source_ip} | Affected: {len(affected_assets)} assets | "
            f"Immediate actions: {'; '.join(containment_actions[:2])}"
        )

        resp = self._build_response(
            advisor=advisor,
            req=req,
            recommendation=recommendation,
            confidence=0.88 if severity == "critical" else 0.78,
            reasoning=[
                f"Threat type '{threat_type}' classified via MITRE ATT&CK mapping",
                f"Severity assessed as '{severity}' based on threat matrix",
                f"{len(affected_assets)} asset(s) identified in blast radius",
                "Containment actions prioritized by impact reduction",
            ],
            alternatives=containment_actions[2:] if len(containment_actions) > 2 else [],
            impact=f"Contain {threat_type} threat affecting {len(affected_assets)} assets",
            auto_executable=severity == "critical",
        )
        return resp

    def _check_compliance(self, advisor: MSPAdvisor, req: AdvisoryRequest) -> AdvisoryResponse:
        """Assess compliance status against a framework, identify gaps."""
        ctx = req.context
        framework = ctx.get("framework", "NIST")
        controls_assessed = ctx.get("controls_assessed", 0)
        controls_passing = ctx.get("controls_passing", 0)
        gaps = ctx.get("gaps", [])

        total_controls = advisor.knowledge_base.get("control_mappings", {}).get(framework, 100)
        coverage_pct = round((controls_passing / max(controls_assessed, 1)) * 100, 1)
        assessed_pct = round((controls_assessed / max(total_controls, 1)) * 100, 1)

        risk_level = "low"
        if coverage_pct < 60:
            risk_level = "critical"
        elif coverage_pct < 75:
            risk_level = "high"
        elif coverage_pct < 90:
            risk_level = "medium"

        recommendation = (
            f"Framework: {framework} | Assessed: {assessed_pct}% of controls | "
            f"Passing: {coverage_pct}% | Risk: {risk_level} | "
            f"Gaps: {len(gaps)} identified"
        )

        resp = self._build_response(
            advisor=advisor,
            req=req,
            recommendation=recommendation,
            confidence=0.85,
            reasoning=[
                f"Evaluated {controls_assessed}/{total_controls} {framework} controls",
                f"{controls_passing} controls passing ({coverage_pct}%)",
                f"Risk level classified as '{risk_level}'",
                f"{len(gaps)} gap(s) require remediation",
            ],
            alternatives=[
                f"Schedule full {framework} audit",
                "Engage third-party assessor for gap remediation",
                "Prioritize critical gaps for 30-day sprint",
            ],
            impact=f"Compliance posture: {coverage_pct}% - {'audit-ready' if risk_level == 'low' else 'needs remediation'}",
            auto_executable=False,
        )
        return resp

    def _plan_capacity(self, advisor: MSPAdvisor, req: AdvisoryRequest) -> AdvisoryResponse:
        """Forecast capacity needs and recommend scaling actions."""
        ctx = req.context
        cpu_avg = ctx.get("cpu_avg", 50)
        memory_avg = ctx.get("memory_avg", 60)
        disk_usage = ctx.get("disk_usage", 70)
        growth_rate = ctx.get("growth_rate_pct", 5)

        thresholds = advisor.knowledge_base.get("thresholds", {})
        warnings = []
        if cpu_avg >= thresholds.get("cpu_critical", 90):
            warnings.append("CPU critical - immediate scale-up needed")
        elif cpu_avg >= thresholds.get("cpu_warning", 75):
            warnings.append("CPU approaching warning threshold")

        if memory_avg >= thresholds.get("memory_critical", 95):
            warnings.append("Memory critical - risk of OOM events")
        elif memory_avg >= thresholds.get("memory_warning", 80):
            warnings.append("Memory usage elevated")

        if disk_usage >= thresholds.get("disk_critical", 95):
            warnings.append("Disk critical - expand storage immediately")
        elif disk_usage >= thresholds.get("disk_warning", 85):
            warnings.append("Disk approaching capacity limit")

        # Simple trend projection
        months_to_critical = None
        if growth_rate > 0 and disk_usage < 95:
            remaining = 95 - disk_usage
            months_to_critical = round(remaining / growth_rate, 1)

        recommendation = (
            f"CPU: {cpu_avg}% | Memory: {memory_avg}% | Disk: {disk_usage}% | "
            f"Growth: {growth_rate}%/mo | "
            f"Warnings: {len(warnings)}"
        )
        if months_to_critical:
            recommendation += f" | Disk critical in ~{months_to_critical} months"

        resp = self._build_response(
            advisor=advisor,
            req=req,
            recommendation=recommendation,
            confidence=0.80,
            reasoning=[
                f"Current utilization: CPU {cpu_avg}%, Memory {memory_avg}%, Disk {disk_usage}%",
                f"Growth rate: {growth_rate}% per month",
            ] + warnings,
            alternatives=[
                "Right-size underutilized VMs",
                "Implement auto-scaling policies",
                "Archive cold data to reduce disk pressure",
            ],
            impact=f"{len(warnings)} resource warning(s) detected",
            auto_executable=False,
        )
        return resp

    def _analyze_root_cause(self, advisor: MSPAdvisor, req: AdvisoryRequest) -> AdvisoryResponse:
        """Trace root cause through dependency chain."""
        ctx = req.context
        incident_desc = ctx.get("description", "")
        affected_services = ctx.get("affected_services", [])
        timeline = ctx.get("timeline", [])
        dependencies = ctx.get("dependencies", {})

        # Walk dependency chain to find root
        root_candidates = []
        for svc in affected_services:
            deps = dependencies.get(svc, [])
            upstream_affected = [d for d in deps if d in affected_services]
            if not upstream_affected:
                root_candidates.append(svc)

        root_cause = root_candidates[0] if root_candidates else (
            affected_services[0] if affected_services else "unknown"
        )

        recommendation = (
            f"Root cause: {root_cause} | "
            f"Affected services: {len(affected_services)} | "
            f"Dependency depth: {len(dependencies)} mappings analyzed"
        )

        resp = self._build_response(
            advisor=advisor,
            req=req,
            recommendation=recommendation,
            confidence=0.72,
            reasoning=[
                f"Analyzed {len(affected_services)} affected services",
                f"Traced {len(dependencies)} dependency relationships",
                f"Root cause candidate: '{root_cause}' (no upstream failures)",
                f"Timeline has {len(timeline)} event(s)",
            ],
            alternatives=[
                "Conduct manual post-mortem with engineering team",
                "Deploy additional monitoring on root cause service",
                "Review change log for recent deployments to root service",
            ],
            impact=f"Identified probable root cause: {root_cause}",
            auto_executable=False,
        )
        return resp

    def _plan_remediation(self, advisor: MSPAdvisor, req: AdvisoryRequest) -> AdvisoryResponse:
        """Prioritize patches, estimate effort, create remediation timeline."""
        ctx = req.context
        vulnerabilities = ctx.get("vulnerabilities", [])
        total_hosts = ctx.get("total_hosts", 1)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "low"), 4),
        )

        critical_count = sum(1 for v in sorted_vulns if v.get("severity") == "critical")
        high_count = sum(1 for v in sorted_vulns if v.get("severity") == "high")

        # Effort estimation: ~30min per critical, ~15min per high, ~5min per medium/low
        effort_hours = round(
            (critical_count * 0.5 + high_count * 0.25 +
             (len(sorted_vulns) - critical_count - high_count) * 0.083) * total_hosts,
            1,
        )

        recommendation = (
            f"Vulnerabilities: {len(sorted_vulns)} ({critical_count} critical, "
            f"{high_count} high) across {total_hosts} hosts | "
            f"Estimated effort: {effort_hours}hr | "
            f"Priority: patch critical within 24hr, high within 7d"
        )

        resp = self._build_response(
            advisor=advisor,
            req=req,
            recommendation=recommendation,
            confidence=0.83,
            reasoning=[
                f"Analyzed {len(sorted_vulns)} vulnerabilities across {total_hosts} hosts",
                f"Critical: {critical_count}, High: {high_count}",
                f"Effort estimate: {effort_hours} engineering-hours",
                "Timeline: critical 24hr, high 7d, medium 30d, low 90d",
            ],
            alternatives=[
                "Apply virtual patching via WAF rules for immediate mitigation",
                "Isolate highest-risk hosts until patched",
                "Schedule maintenance window for batch patching",
            ],
            impact=f"Remediate {critical_count} critical and {high_count} high vulnerabilities",
            auto_executable=critical_count == 0,
        )
        return resp

    def _generic_advisory(self, advisor: MSPAdvisor, req: AdvisoryRequest) -> AdvisoryResponse:
        """Fallback advisory for unmapped request types."""
        recommendation = (
            f"Advisory from {advisor.name} ({advisor.domain}): "
            f"Reviewed context for '{req.request_type}'. "
            f"Recommend detailed analysis by {advisor.domain} specialist."
        )
        return self._build_response(
            advisor=advisor,
            req=req,
            recommendation=recommendation,
            confidence=0.60,
            reasoning=[
                f"Request type '{req.request_type}' processed by {advisor.name}",
                "Generic analysis applied - specialist review recommended",
            ],
            alternatives=["Escalate to human expert for detailed review"],
            impact="Preliminary guidance provided",
            auto_executable=False,
        )

    def _build_response(
        self,
        advisor: MSPAdvisor,
        req: AdvisoryRequest,
        recommendation: str,
        confidence: float,
        reasoning: List[str],
        alternatives: List[str],
        impact: str,
        auto_executable: bool,
    ) -> AdvisoryResponse:
        """Build, store, and return an AdvisoryResponse."""
        resp_id = f"RESP-{uuid.uuid4().hex[:8].upper()}"
        resp = AdvisoryResponse(
            response_id=resp_id,
            request_id=req.request_id,
            advisor_id=advisor.advisor_id,
            recommendation=recommendation,
            confidence=confidence,
            reasoning=reasoning,
            alternative_actions=alternatives,
            estimated_impact=impact,
            auto_executable=auto_executable,
        )
        self._responses[resp_id] = resp
        self._persist_response(resp)

        advisor.decisions_made += 1
        self._persist_advisor(advisor)

        return resp

    # ------------------------------------------------------------------ #
    # Execution & Feedback
    # ------------------------------------------------------------------ #

    def execute_advisory(self, response_id: str) -> Dict[str, Any]:
        """Mark an advisory response as executed (auto-action trigger)."""
        resp = self._responses.get(response_id)
        if not resp:
            return {"error": "Response not found"}
        if not resp.auto_executable:
            return {"error": "This advisory is not auto-executable", "response_id": response_id}
        resp.executed = True
        resp.executed_at = datetime.now(timezone.utc).isoformat()
        logger.info(f"Executed advisory {response_id}")
        return {
            "response_id": response_id,
            "executed": True,
            "executed_at": resp.executed_at,
            "recommendation": resp.recommendation,
        }

    def rate_advisory(
        self,
        response_id: str,
        was_helpful: bool,
        feedback: str = "",
    ) -> Dict[str, Any]:
        """Rate an advisory response and update advisor accuracy."""
        resp = self._responses.get(response_id)
        if not resp:
            return {"error": "Response not found"}
        resp.was_helpful = was_helpful
        resp.feedback = feedback

        # Update advisor accuracy
        advisor = self._advisors.get(resp.advisor_id)
        if advisor:
            rated = [
                r for r in self._responses.values()
                if r.advisor_id == advisor.advisor_id and r.was_helpful is not None
            ]
            if rated:
                advisor.accuracy_rate = round(
                    sum(1 for r in rated if r.was_helpful) / len(rated), 3
                )
                self._persist_advisor(advisor)

        return {
            "response_id": response_id,
            "rated": True,
            "was_helpful": was_helpful,
            "advisor_accuracy": advisor.accuracy_rate if advisor else None,
        }

    def get_advisory_history(
        self,
        advisor_id: str | None = None,
        request_type: str | None = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Retrieve past advisory responses with optional filters."""
        results = list(self._responses.values())
        if advisor_id:
            results = [r for r in results if r.advisor_id == advisor_id]
        if request_type:
            matching_reqs = {
                rid for rid, req in self._requests.items()
                if req.request_type == request_type
            }
            results = [r for r in results if r.request_id in matching_reqs]
        results = results[-limit:]
        return [self._response_to_dict(r) for r in results]

    def get_advisor_accuracy(self) -> Dict[str, Any]:
        """Per-advisor accuracy metrics."""
        metrics = {}
        for adv in self._advisors.values():
            rated = [
                r for r in self._responses.values()
                if r.advisor_id == adv.advisor_id and r.was_helpful is not None
            ]
            total = len([r for r in self._responses.values() if r.advisor_id == adv.advisor_id])
            metrics[adv.advisor_id] = {
                "name": adv.name,
                "domain": adv.domain,
                "decisions_made": adv.decisions_made,
                "total_responses": total,
                "rated_responses": len(rated),
                "accuracy_rate": adv.accuracy_rate,
                "helpful": sum(1 for r in rated if r.was_helpful),
                "not_helpful": sum(1 for r in rated if not r.was_helpful),
            }
        return metrics

    # ------------------------------------------------------------------ #
    # Insights
    # ------------------------------------------------------------------ #

    def generate_insights(self, client_id: str) -> List[Dict[str, Any]]:
        """Scan data sources and produce actionable insights for a client."""
        insights = []

        # Anomaly detection insight (simulated)
        insights.append(self._create_insight(
            insight_type=InsightType.ANOMALY.value,
            title=f"Unusual login pattern detected for {client_id}",
            description=(
                f"Client {client_id} shows 3x normal after-hours login activity "
                f"in the past 7 days. Recommend review of access logs."
            ),
            severity="high",
            data_points={"after_hours_logins": 47, "baseline": 15, "deviation": "3.1x"},
            affected_clients=[client_id],
            action_required=True,
        ))

        # Trend insight
        insights.append(self._create_insight(
            insight_type=InsightType.TREND.value,
            title=f"Ticket volume trending up for {client_id}",
            description=(
                f"Ticket submissions for {client_id} increased 22% month-over-month. "
                f"Top categories: network (35%), software (28%), access (20%)."
            ),
            severity="medium",
            data_points={"this_month": 45, "last_month": 37, "growth_pct": 22},
            affected_clients=[client_id],
            action_required=False,
        ))

        # Opportunity insight
        insights.append(self._create_insight(
            insight_type=InsightType.OPPORTUNITY.value,
            title=f"Upsell opportunity: endpoint protection for {client_id}",
            description=(
                f"Client {client_id} has 12 endpoints without advanced threat protection. "
                f"Estimated incremental MRR: $360/mo."
            ),
            severity="low",
            data_points={"unprotected_endpoints": 12, "monthly_revenue": 360},
            affected_clients=[client_id],
            action_required=False,
        ))

        # Prediction insight
        insights.append(self._create_insight(
            insight_type=InsightType.PREDICTION.value,
            title=f"Storage capacity forecast for {client_id}",
            description=(
                f"At current growth rate, {client_id} file server will reach 95% capacity "
                f"in approximately 4.2 months. Recommend proactive expansion."
            ),
            severity="medium",
            data_points={"current_usage_pct": 78, "growth_rate": 4.1, "months_to_critical": 4.2},
            affected_clients=[client_id],
            action_required=True,
        ))

        return [self._insight_to_dict(i) for i in insights]

    def _create_insight(self, **kwargs) -> MSPInsight:
        iid = f"INS-{uuid.uuid4().hex[:8].upper()}"
        insight = MSPInsight(insight_id=iid, **kwargs)
        self._insights[iid] = insight
        self._persist_insight(insight)
        return insight

    def _detect_anomalies(self, metrics: List[float]) -> Dict[str, Any]:
        """Statistical anomaly detection on a metric series."""
        if len(metrics) < 3:
            return {"anomalies": [], "status": "insufficient_data"}
        mean = statistics.mean(metrics)
        stdev = statistics.stdev(metrics) if len(metrics) > 1 else 0
        threshold = mean + 2 * stdev
        anomalies = [
            {"index": i, "value": v, "deviation": round((v - mean) / max(stdev, 0.001), 2)}
            for i, v in enumerate(metrics) if v > threshold
        ]
        return {"mean": round(mean, 2), "stdev": round(stdev, 2), "anomalies": anomalies}

    def _predict_trends(self, historical_data: List[float]) -> Dict[str, Any]:
        """Simple linear trend projection."""
        if len(historical_data) < 2:
            return {"trend": "insufficient_data"}
        n = len(historical_data)
        x_mean = (n - 1) / 2
        y_mean = statistics.mean(historical_data)
        numerator = sum((i - x_mean) * (y - y_mean) for i, y in enumerate(historical_data))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        slope = numerator / max(denominator, 0.001)
        direction = "increasing" if slope > 0.01 else ("decreasing" if slope < -0.01 else "stable")
        projected_next = round(historical_data[-1] + slope, 2)
        return {
            "direction": direction,
            "slope": round(slope, 4),
            "projected_next": projected_next,
            "data_points": n,
        }

    def _identify_opportunities(self, client_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify upsell/cross-sell opportunities for MSP revenue."""
        opportunities = []
        services = client_data.get("current_services", [])
        endpoints = client_data.get("endpoint_count", 0)

        if "advanced_threat_protection" not in services and endpoints > 5:
            opportunities.append({
                "type": "upsell",
                "service": "Advanced Threat Protection",
                "estimated_mrr": endpoints * 30,
                "rationale": f"{endpoints} endpoints without ATP coverage",
            })
        if "backup" not in services:
            opportunities.append({
                "type": "cross_sell",
                "service": "Managed Backup & DR",
                "estimated_mrr": endpoints * 15,
                "rationale": "No backup service detected - compliance risk",
            })
        if "compliance_monitoring" not in services and client_data.get("industry") in (
            "healthcare", "finance", "government"
        ):
            opportunities.append({
                "type": "cross_sell",
                "service": "Continuous Compliance Monitoring",
                "estimated_mrr": 500,
                "rationale": f"Regulated industry ({client_data.get('industry')}) without compliance monitoring",
            })
        return opportunities

    # ------------------------------------------------------------------ #
    # Automation Rules
    # ------------------------------------------------------------------ #

    def create_automation_rule(
        self,
        name: str,
        trigger_event: str,
        condition: Dict[str, Any],
        advisor_domain: str,
        action: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create an event-triggered automation rule."""
        rid = f"RULE-{uuid.uuid4().hex[:8].upper()}"
        rule = AutomationRule(
            rule_id=rid,
            name=name,
            trigger_event=trigger_event,
            condition=condition,
            advisor_domain=advisor_domain,
            action=action,
        )
        self._rules[rid] = rule
        self._persist_rule(rule)
        logger.info(f"Created automation rule {rid}: {name}")
        return self._rule_to_dict(rule)

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update an existing automation rule."""
        rule = self._rules.get(rule_id)
        if not rule:
            return None
        for key in ("name", "trigger_event", "condition", "advisor_domain", "action", "is_enabled"):
            if key in updates:
                setattr(rule, key, updates[key])
        return self._rule_to_dict(rule)

    def list_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """List all automation rules."""
        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.is_enabled]
        return [self._rule_to_dict(r) for r in rules]

    def toggle_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Toggle an automation rule on/off."""
        rule = self._rules.get(rule_id)
        if not rule:
            return None
        rule.is_enabled = not rule.is_enabled
        return self._rule_to_dict(rule)

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check automation rules against an incoming event. Trigger advisor if matched."""
        event_type = event.get("event_type", "")
        triggered = []

        for rule in self._rules.values():
            if not rule.is_enabled:
                continue
            if rule.trigger_event != event_type:
                continue
            # Check conditions
            if not self._evaluate_condition(rule.condition, event):
                continue

            # Trigger advisory
            result = self.request_advisory(
                request_type=rule.action.get("request_type", RequestType.TICKET_TRIAGE.value),
                context=event.get("data", {}),
                urgency=rule.action.get("urgency", "medium"),
            )
            rule.executions += 1
            rule.last_triggered = datetime.now(timezone.utc).isoformat()
            triggered.append({
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "advisory_result": result,
            })

        return triggered

    def _evaluate_condition(self, condition: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Evaluate a rule condition against an event. Simple key-value matching."""
        if not condition:
            return True
        data = event.get("data", {})
        for key, expected in condition.items():
            actual = data.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    # ------------------------------------------------------------------ #
    # Dashboard
    # ------------------------------------------------------------------ #

    def get_dashboard(self) -> Dict[str, Any]:
        """Aggregate dashboard: advisors, insights, automation stats, accuracy."""
        total_advisories = len(self._responses)
        executed = sum(1 for r in self._responses.values() if r.executed)
        rated = sum(1 for r in self._responses.values() if r.was_helpful is not None)
        helpful = sum(1 for r in self._responses.values() if r.was_helpful is True)

        return {
            "advisors": {
                "total": len(self._advisors),
                "by_domain": self._count_by(self._advisors.values(), "domain"),
            },
            "advisories": {
                "total": total_advisories,
                "executed": executed,
                "pending": len([r for r in self._requests.values() if r.status == "pending"]),
                "completed": len([r for r in self._requests.values() if r.status == "completed"]),
            },
            "accuracy": {
                "rated": rated,
                "helpful": helpful,
                "overall_rate": round(helpful / max(rated, 1), 3),
            },
            "insights": {
                "total": len(self._insights),
                "action_required": sum(1 for i in self._insights.values() if i.action_required),
            },
            "automation": {
                "total_rules": len(self._rules),
                "enabled_rules": sum(1 for r in self._rules.values() if r.is_enabled),
                "total_executions": sum(r.executions for r in self._rules.values()),
            },
        }

    # ------------------------------------------------------------------ #
    # Serialization Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _count_by(items, attr: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for item in items:
            val = getattr(item, attr, "unknown")
            counts[val] = counts.get(val, 0) + 1
        return counts

    @staticmethod
    def _advisor_to_dict(a: MSPAdvisor) -> Dict[str, Any]:
        return {
            "advisor_id": a.advisor_id,
            "name": a.name,
            "domain": a.domain,
            "specializations": a.specializations,
            "knowledge_base": a.knowledge_base,
            "confidence_threshold": a.confidence_threshold,
            "decisions_made": a.decisions_made,
            "accuracy_rate": a.accuracy_rate,
            "created_at": a.created_at,
        }

    @staticmethod
    def _response_to_dict(r: AdvisoryResponse) -> Dict[str, Any]:
        return {
            "response_id": r.response_id,
            "request_id": r.request_id,
            "advisor_id": r.advisor_id,
            "recommendation": r.recommendation,
            "confidence": r.confidence,
            "reasoning": r.reasoning,
            "alternative_actions": r.alternative_actions,
            "estimated_impact": r.estimated_impact,
            "auto_executable": r.auto_executable,
            "executed": r.executed,
            "executed_at": r.executed_at,
            "was_helpful": r.was_helpful,
            "feedback": r.feedback,
        }

    @staticmethod
    def _insight_to_dict(i: MSPInsight) -> Dict[str, Any]:
        return {
            "insight_id": i.insight_id,
            "insight_type": i.insight_type,
            "title": i.title,
            "description": i.description,
            "severity": i.severity,
            "data_points": i.data_points,
            "affected_clients": i.affected_clients,
            "action_required": i.action_required,
            "generated_at": i.generated_at,
            "expires_at": i.expires_at,
        }

    @staticmethod
    def _rule_to_dict(r: AutomationRule) -> Dict[str, Any]:
        return {
            "rule_id": r.rule_id,
            "name": r.name,
            "trigger_event": r.trigger_event,
            "condition": r.condition,
            "advisor_domain": r.advisor_domain,
            "action": r.action,
            "is_enabled": r.is_enabled,
            "executions": r.executions,
            "last_triggered": r.last_triggered,
        }
