"""
AITHER Platform - ITIL Problem Management Service
Tracks recurring incidents to root causes, maintains Known Error Database (KEDB),
and prevents repeat issues.

Provides:
- Problem record CRUD with full lifecycle workflow
- Root cause analysis (Five Whys, Fishbone, Fault Tree, Timeline)
- Known Error Database (KEDB) with symptom-based search
- Incident-to-known-error matching
- Recurring incident detection
- Problem trend analytics and dashboard

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.problem_management import (
        ProblemRecordModel,
        KnownErrorModel,
        RootCauseAnalysisModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class ProblemStatus(str, Enum):
    LOGGED = "logged"
    UNDER_INVESTIGATION = "under_investigation"
    ROOT_CAUSE_IDENTIFIED = "root_cause_identified"
    KNOWN_ERROR = "known_error"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ProblemPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProblemCategory(str, Enum):
    HARDWARE = "hardware"
    SOFTWARE = "software"
    NETWORK = "network"
    SECURITY = "security"
    PRINTER = "printer"
    EMAIL = "email"
    DATABASE = "database"
    CLOUD = "cloud"
    OTHER = "other"


class RCAMethod(str, Enum):
    FIVE_WHYS = "five_whys"
    FISHBONE = "fishbone"
    FAULT_TREE = "fault_tree"
    TIMELINE = "timeline"


class FixStatus(str, Enum):
    IDENTIFIED = "identified"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class ProblemRecord:
    """ITIL problem record."""
    problem_id: str
    client_id: str
    title: str
    description: str
    status: ProblemStatus = ProblemStatus.LOGGED
    priority: ProblemPriority = ProblemPriority.MEDIUM
    category: ProblemCategory = ProblemCategory.OTHER
    root_cause: str = ""
    workaround: str = ""
    resolution: str = ""
    affected_services: List[str] = field(default_factory=list)
    related_incidents: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    impact_assessment: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None


@dataclass
class KnownError:
    """Known Error Database entry."""
    ke_id: str
    problem_id: str
    title: str
    error_description: str
    root_cause: str
    workaround: str
    permanent_fix_status: FixStatus = FixStatus.IDENTIFIED
    symptoms: List[str] = field(default_factory=list)
    affected_cis: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RootCauseAnalysis:
    """Root cause analysis record."""
    rca_id: str
    problem_id: str
    method: RCAMethod = RCAMethod.FIVE_WHYS
    analysis_data: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    contributing_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analyzed_by: str = ""
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ProblemTrend:
    """Problem trend data point."""
    category: str
    count: int
    trend_direction: str  # "up", "down", "stable"
    avg_resolution_days: float


# ============================================================
# Row-to-dataclass converters
# ============================================================

def _problem_from_row(row) -> ProblemRecord:
    return ProblemRecord(
        problem_id=row.problem_id,
        client_id=row.client_id or "",
        title=row.title,
        description=row.description or "",
        status=ProblemStatus(row.status) if row.status else ProblemStatus.LOGGED,
        priority=ProblemPriority(row.priority) if row.priority else ProblemPriority.MEDIUM,
        category=ProblemCategory(row.category) if row.category else ProblemCategory.OTHER,
        root_cause=row.root_cause or "",
        workaround=row.workaround or "",
        resolution=row.resolution or "",
        affected_services=row.affected_services or [],
        related_incidents=row.related_incidents or [],
        assigned_to=row.assigned_to,
        impact_assessment=row.impact_assessment or "",
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at or datetime.now(timezone.utc),
        resolved_at=row.resolved_at,
    )


def _ke_from_row(row) -> KnownError:
    return KnownError(
        ke_id=row.ke_id,
        problem_id=row.problem_id or "",
        title=row.title,
        error_description=row.error_description or "",
        root_cause=row.root_cause or "",
        workaround=row.workaround or "",
        permanent_fix_status=FixStatus(row.permanent_fix_status) if row.permanent_fix_status else FixStatus.IDENTIFIED,
        symptoms=row.symptoms or [],
        affected_cis=row.affected_cis or [],
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _rca_from_row(row) -> RootCauseAnalysis:
    return RootCauseAnalysis(
        rca_id=row.rca_id,
        problem_id=row.problem_id or "",
        method=RCAMethod(row.method) if row.method else RCAMethod.FIVE_WHYS,
        analysis_data=row.analysis_data or {},
        findings=row.findings or [],
        contributing_factors=row.contributing_factors or [],
        recommendations=row.recommendations or [],
        analyzed_by=row.analyzed_by or "",
        analyzed_at=row.analyzed_at or datetime.now(timezone.utc),
    )


# ============================================================
# Pre-seeded Known Errors
# ============================================================

DEFAULT_KNOWN_ERRORS: List[Dict[str, Any]] = [
    {
        "ke_id": "KE-00001",
        "problem_id": "PRB-SEED-001",
        "title": "Print Spooler Service Crash",
        "error_description": "Windows Print Spooler service stops unexpectedly causing all print jobs to fail.",
        "root_cause": "Corrupted print driver or accumulated stale print jobs overflow the spooler memory.",
        "workaround": "Restart the Print Spooler service (net stop spooler && net start spooler) and clear the C:\\Windows\\System32\\spool\\PRINTERS folder.",
        "permanent_fix_status": "implemented",
        "symptoms": ["print jobs stuck", "printer offline", "spooler crash", "cannot print", "print queue frozen"],
        "affected_cis": ["print_server", "workstation_printers"],
    },
    {
        "ke_id": "KE-00002",
        "problem_id": "PRB-SEED-002",
        "title": "DNS Resolution Failure",
        "error_description": "Intermittent DNS resolution failures causing websites and internal services to become unreachable.",
        "root_cause": "DNS cache poisoning or upstream DNS forwarder timeout due to misconfigured TTL values.",
        "workaround": "Flush DNS cache (ipconfig /flushdns) and switch to backup DNS servers (8.8.8.8 / 1.1.1.1).",
        "permanent_fix_status": "implemented",
        "symptoms": ["cannot resolve hostname", "website unreachable", "DNS timeout", "name resolution failure", "nslookup fails"],
        "affected_cis": ["dns_server", "domain_controller", "network_firewall"],
    },
    {
        "ke_id": "KE-00003",
        "problem_id": "PRB-SEED-003",
        "title": "VPN Connection Timeout",
        "error_description": "VPN connections drop or fail to establish after 30 seconds, affecting remote workers.",
        "root_cause": "MTU mismatch between VPN tunnel and ISP gateway causes fragmented packets to be dropped.",
        "workaround": "Reduce VPN client MTU to 1400 (netsh interface ipv4 set subinterface <interface> mtu=1400).",
        "permanent_fix_status": "planned",
        "symptoms": ["VPN timeout", "VPN disconnects", "cannot connect to VPN", "remote access failure", "tunnel drops"],
        "affected_cis": ["vpn_concentrator", "firewall", "remote_access_gateway"],
    },
    {
        "ke_id": "KE-00004",
        "problem_id": "PRB-SEED-004",
        "title": "Disk Space Exhaustion on Application Servers",
        "error_description": "Application servers run out of disk space due to unrotated log files and temp data.",
        "root_cause": "Log rotation policy not enforced; application writes verbose debug logs without size caps.",
        "workaround": "Manually purge logs older than 7 days and temporary files. Schedule weekly cleanup script.",
        "permanent_fix_status": "in_progress",
        "symptoms": ["disk full", "low disk space", "application error", "write failed", "server unresponsive", "out of space"],
        "affected_cis": ["app_server", "file_server", "database_server"],
    },
    {
        "ke_id": "KE-00005",
        "problem_id": "PRB-SEED-005",
        "title": "SSL/TLS Certificate Expiry",
        "error_description": "SSL certificates expire without warning, causing browser security errors and service outages.",
        "root_cause": "No automated certificate renewal or monitoring. Manual tracking via spreadsheet missed renewal dates.",
        "workaround": "Manually renew the certificate and restart the affected service. Set calendar reminders for 30 days before expiry.",
        "permanent_fix_status": "identified",
        "symptoms": ["certificate expired", "SSL error", "browser security warning", "HTTPS not working", "ERR_CERT_DATE_INVALID"],
        "affected_cis": ["web_server", "load_balancer", "mail_server", "api_gateway"],
    },
]


# ============================================================
# Service
# ============================================================

class ProblemManagementService:
    """
    ITIL Problem Management Service.

    Tracks recurring incidents to root causes, maintains a Known Error
    Database (KEDB), and prevents repeat issues through proactive
    trend analysis and incident matching.

    Accepts optional db: Session for PostgreSQL persistence.
    Falls back to in-memory storage when DB is unavailable.
    """

    def __init__(self, db=None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE
        self.problems: Dict[str, ProblemRecord] = {}
        self.known_errors: Dict[str, KnownError] = {}
        self.rcas: Dict[str, RootCauseAnalysis] = {}
        self._next_problem_num = 1
        self._next_ke_num = 6  # after seed data
        self._next_rca_num = 1

        if self._use_db:
            self._hydrate_from_db()
        else:
            self._seed_known_errors()

    # ----------------------------------------------------------
    # Hydration & persistence helpers
    # ----------------------------------------------------------

    def _hydrate_from_db(self):
        """Load all data from DB into memory."""
        try:
            for row in self.db.query(ProblemRecordModel).all():
                pr = _problem_from_row(row)
                self.problems[pr.problem_id] = pr
                num = self._extract_num(pr.problem_id, "PRB-")
                if num >= self._next_problem_num:
                    self._next_problem_num = num + 1

            for row in self.db.query(KnownErrorModel).all():
                ke = _ke_from_row(row)
                self.known_errors[ke.ke_id] = ke
                num = self._extract_num(ke.ke_id, "KE-")
                if num >= self._next_ke_num:
                    self._next_ke_num = num + 1

            for row in self.db.query(RootCauseAnalysisModel).all():
                rca = _rca_from_row(row)
                self.rcas[rca.rca_id] = rca
                num = self._extract_num(rca.rca_id, "RCA-")
                if num >= self._next_rca_num:
                    self._next_rca_num = num + 1

            if not self.known_errors:
                self._seed_known_errors()
        except Exception as e:
            logger.error(f"DB hydration error: {e}")
            self._seed_known_errors()

    def _seed_known_errors(self):
        """Load the 5 pre-built known errors."""
        for kdata in DEFAULT_KNOWN_ERRORS:
            ke = KnownError(
                ke_id=kdata["ke_id"],
                problem_id=kdata["problem_id"],
                title=kdata["title"],
                error_description=kdata["error_description"],
                root_cause=kdata["root_cause"],
                workaround=kdata["workaround"],
                permanent_fix_status=FixStatus(kdata["permanent_fix_status"]),
                symptoms=kdata["symptoms"],
                affected_cis=kdata.get("affected_cis", []),
            )
            self.known_errors[ke.ke_id] = ke
            self._persist_known_error(ke)

    @staticmethod
    def _extract_num(record_id: str, prefix: str = "PRB-") -> int:
        try:
            return int(record_id.replace(prefix, "").lstrip("0") or "0")
        except (IndexError, ValueError):
            return 0

    def _gen_problem_id(self) -> str:
        pid = f"PRB-{str(self._next_problem_num).zfill(5)}"
        self._next_problem_num += 1
        return pid

    def _gen_ke_id(self) -> str:
        kid = f"KE-{str(self._next_ke_num).zfill(5)}"
        self._next_ke_num += 1
        return kid

    def _gen_rca_id(self) -> str:
        rid = f"RCA-{str(self._next_rca_num).zfill(5)}"
        self._next_rca_num += 1
        return rid

    # --- DB persist helpers ---

    def _persist_problem(self, pr: ProblemRecord):
        if not self._use_db:
            return
        try:
            existing = self.db.query(ProblemRecordModel).filter(
                ProblemRecordModel.problem_id == pr.problem_id
            ).first()
            data = {
                "problem_id": pr.problem_id,
                "client_id": pr.client_id,
                "title": pr.title,
                "description": pr.description,
                "status": pr.status.value,
                "priority": pr.priority.value,
                "category": pr.category.value,
                "root_cause": pr.root_cause,
                "workaround": pr.workaround,
                "resolution": pr.resolution,
                "affected_services": pr.affected_services,
                "related_incidents": pr.related_incidents,
                "assigned_to": pr.assigned_to,
                "impact_assessment": pr.impact_assessment,
                "resolved_at": pr.resolved_at,
            }
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
            else:
                self.db.add(ProblemRecordModel(**data))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist problem error: {e}")
            self.db.rollback()

    def _persist_known_error(self, ke: KnownError):
        if not self._use_db:
            return
        try:
            existing = self.db.query(KnownErrorModel).filter(
                KnownErrorModel.ke_id == ke.ke_id
            ).first()
            data = {
                "ke_id": ke.ke_id,
                "problem_id": ke.problem_id,
                "title": ke.title,
                "error_description": ke.error_description,
                "root_cause": ke.root_cause,
                "workaround": ke.workaround,
                "permanent_fix_status": ke.permanent_fix_status.value,
                "symptoms": ke.symptoms,
                "affected_cis": ke.affected_cis,
            }
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
            else:
                self.db.add(KnownErrorModel(**data))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist known error: {e}")
            self.db.rollback()

    def _persist_rca(self, rca: RootCauseAnalysis):
        if not self._use_db:
            return
        try:
            existing = self.db.query(RootCauseAnalysisModel).filter(
                RootCauseAnalysisModel.rca_id == rca.rca_id
            ).first()
            data = {
                "rca_id": rca.rca_id,
                "problem_id": rca.problem_id,
                "method": rca.method.value,
                "analysis_data": rca.analysis_data,
                "findings": rca.findings,
                "contributing_factors": rca.contributing_factors,
                "recommendations": rca.recommendations,
                "analyzed_by": rca.analyzed_by,
                "analyzed_at": rca.analyzed_at,
            }
            if existing:
                for k, v in data.items():
                    setattr(existing, k, v)
            else:
                self.db.add(RootCauseAnalysisModel(**data))
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist RCA error: {e}")
            self.db.rollback()

    def _delete_problem_db(self, problem_id: str):
        if not self._use_db:
            return
        try:
            self.db.query(ProblemRecordModel).filter(
                ProblemRecordModel.problem_id == problem_id
            ).delete()
            self.db.commit()
        except Exception as e:
            logger.error(f"DB delete problem error: {e}")
            self.db.rollback()

    # ----------------------------------------------------------
    # Problem CRUD
    # ----------------------------------------------------------

    def create_problem(
        self,
        client_id: str,
        title: str,
        description: str,
        priority: ProblemPriority = ProblemPriority.MEDIUM,
        category: ProblemCategory = ProblemCategory.OTHER,
        affected_services: Optional[List[str]] = None,
        related_incidents: Optional[List[str]] = None,
        assigned_to: Optional[str] = None,
        impact_assessment: str = "",
    ) -> ProblemRecord:
        """Create a new problem record."""
        pr = ProblemRecord(
            problem_id=self._gen_problem_id(),
            client_id=client_id,
            title=title,
            description=description,
            priority=priority,
            category=category,
            affected_services=affected_services or [],
            related_incidents=related_incidents or [],
            assigned_to=assigned_to,
            impact_assessment=impact_assessment,
        )
        self.problems[pr.problem_id] = pr
        self._persist_problem(pr)
        logger.info(f"Problem created: {pr.problem_id} - {pr.title}")
        return pr

    def get_problem(self, problem_id: str) -> Optional[ProblemRecord]:
        """Retrieve a problem by ID."""
        return self.problems.get(problem_id)

    def list_problems(
        self,
        client_id: Optional[str] = None,
        status: Optional[ProblemStatus] = None,
        priority: Optional[ProblemPriority] = None,
        category: Optional[ProblemCategory] = None,
    ) -> List[ProblemRecord]:
        """List problems with optional filters."""
        results = list(self.problems.values())
        if client_id:
            results = [p for p in results if p.client_id == client_id]
        if status:
            results = [p for p in results if p.status == status]
        if priority:
            results = [p for p in results if p.priority == priority]
        if category:
            results = [p for p in results if p.category == category]
        return sorted(results, key=lambda p: p.created_at, reverse=True)

    def update_problem(self, problem_id: str, **kwargs) -> Optional[ProblemRecord]:
        """Update fields on a problem record."""
        pr = self.problems.get(problem_id)
        if not pr:
            return None
        for key, val in kwargs.items():
            if hasattr(pr, key) and val is not None:
                setattr(pr, key, val)
        pr.updated_at = datetime.now(timezone.utc)
        self._persist_problem(pr)
        return pr

    def delete_problem(self, problem_id: str) -> bool:
        """Delete a problem record."""
        if problem_id not in self.problems:
            return False
        del self.problems[problem_id]
        self._delete_problem_db(problem_id)
        return True

    # ----------------------------------------------------------
    # Investigation workflow
    # ----------------------------------------------------------

    def investigate(self, problem_id: str) -> Optional[ProblemRecord]:
        """Move a problem to under_investigation status."""
        pr = self.problems.get(problem_id)
        if not pr:
            return None
        if pr.status == ProblemStatus.LOGGED:
            pr.status = ProblemStatus.UNDER_INVESTIGATION
            pr.updated_at = datetime.now(timezone.utc)
            self._persist_problem(pr)
            logger.info(f"Problem {problem_id} now under investigation")
        return pr

    def identify_root_cause(
        self,
        problem_id: str,
        root_cause: str,
        method: RCAMethod = RCAMethod.FIVE_WHYS,
    ) -> Optional[ProblemRecord]:
        """Record the root cause for a problem."""
        pr = self.problems.get(problem_id)
        if not pr:
            return None
        pr.root_cause = root_cause
        pr.status = ProblemStatus.ROOT_CAUSE_IDENTIFIED
        pr.updated_at = datetime.now(timezone.utc)
        self._persist_problem(pr)
        logger.info(f"Root cause identified for {problem_id}: {root_cause[:80]}")
        return pr

    def create_known_error(
        self,
        problem_id: str,
        workaround: str,
        symptoms: Optional[List[str]] = None,
        affected_cis: Optional[List[str]] = None,
    ) -> Optional[KnownError]:
        """Create a Known Error entry from a problem with identified root cause."""
        pr = self.problems.get(problem_id)
        if not pr:
            return None
        if not pr.root_cause:
            logger.warning(f"Cannot create KE for {problem_id}: no root cause identified")
            return None

        ke = KnownError(
            ke_id=self._gen_ke_id(),
            problem_id=problem_id,
            title=pr.title,
            error_description=pr.description,
            root_cause=pr.root_cause,
            workaround=workaround,
            symptoms=symptoms or [],
            affected_cis=affected_cis or [],
        )
        self.known_errors[ke.ke_id] = ke

        # Update problem status
        pr.status = ProblemStatus.KNOWN_ERROR
        pr.workaround = workaround
        pr.updated_at = datetime.now(timezone.utc)
        self._persist_problem(pr)
        self._persist_known_error(ke)
        logger.info(f"Known error {ke.ke_id} created from {problem_id}")
        return ke

    def resolve_problem(
        self,
        problem_id: str,
        resolution: str,
    ) -> Optional[ProblemRecord]:
        """Resolve a problem with a permanent fix."""
        pr = self.problems.get(problem_id)
        if not pr:
            return None
        pr.status = ProblemStatus.RESOLVED
        pr.resolution = resolution
        pr.resolved_at = datetime.now(timezone.utc)
        pr.updated_at = datetime.now(timezone.utc)
        self._persist_problem(pr)
        logger.info(f"Problem {problem_id} resolved")
        return pr

    def close_problem(self, problem_id: str) -> Optional[ProblemRecord]:
        """Close a resolved problem."""
        pr = self.problems.get(problem_id)
        if not pr:
            return None
        pr.status = ProblemStatus.CLOSED
        pr.updated_at = datetime.now(timezone.utc)
        self._persist_problem(pr)
        logger.info(f"Problem {problem_id} closed")
        return pr

    def link_incident(self, problem_id: str, incident_id: str) -> Optional[ProblemRecord]:
        """Link an incident to a problem record."""
        pr = self.problems.get(problem_id)
        if not pr:
            return None
        if incident_id not in pr.related_incidents:
            pr.related_incidents.append(incident_id)
            pr.updated_at = datetime.now(timezone.utc)
            self._persist_problem(pr)
        return pr

    # ----------------------------------------------------------
    # Root Cause Analysis
    # ----------------------------------------------------------

    def perform_rca(
        self,
        problem_id: str,
        method: RCAMethod = RCAMethod.FIVE_WHYS,
        analysis_data: Optional[Dict[str, Any]] = None,
        findings: Optional[List[str]] = None,
        contributing_factors: Optional[List[str]] = None,
        recommendations: Optional[List[str]] = None,
        analyzed_by: str = "",
    ) -> Optional[RootCauseAnalysis]:
        """Perform and record a root cause analysis for a problem."""
        pr = self.problems.get(problem_id)
        if not pr:
            return None

        rca = RootCauseAnalysis(
            rca_id=self._gen_rca_id(),
            problem_id=problem_id,
            method=method,
            analysis_data=analysis_data or {},
            findings=findings or [],
            contributing_factors=contributing_factors or [],
            recommendations=recommendations or [],
            analyzed_by=analyzed_by,
        )
        self.rcas[rca.rca_id] = rca
        self._persist_rca(rca)
        logger.info(f"RCA {rca.rca_id} recorded for {problem_id} using {method.value}")
        return rca

    def get_rca(self, rca_id: str) -> Optional[RootCauseAnalysis]:
        """Retrieve an RCA by ID."""
        return self.rcas.get(rca_id)

    def list_rcas_for_problem(self, problem_id: str) -> List[RootCauseAnalysis]:
        """List all RCAs for a given problem."""
        return [r for r in self.rcas.values() if r.problem_id == problem_id]

    # ----------------------------------------------------------
    # Known Error Database (KEDB)
    # ----------------------------------------------------------

    def get_known_error(self, ke_id: str) -> Optional[KnownError]:
        """Retrieve a known error by ID."""
        return self.known_errors.get(ke_id)

    def list_known_errors(
        self,
        fix_status: Optional[FixStatus] = None,
    ) -> List[KnownError]:
        """List all known errors, optionally filtered by fix status."""
        results = list(self.known_errors.values())
        if fix_status:
            results = [ke for ke in results if ke.permanent_fix_status == fix_status]
        return results

    def search_known_errors(self, symptoms: List[str]) -> List[Dict[str, Any]]:
        """Search the KEDB by symptom keywords. Returns matches ranked by relevance."""
        if not symptoms:
            return []

        search_terms = [s.lower() for s in symptoms]
        matches = []

        for ke in self.known_errors.values():
            score = 0
            ke_symptoms_lower = [s.lower() for s in ke.symptoms]
            ke_desc_lower = ke.error_description.lower()
            ke_title_lower = ke.title.lower()

            for term in search_terms:
                # Exact symptom match
                for ks in ke_symptoms_lower:
                    if term in ks:
                        score += 3
                # Description match
                if term in ke_desc_lower:
                    score += 1
                # Title match
                if term in ke_title_lower:
                    score += 2

            if score > 0:
                matches.append({
                    "ke_id": ke.ke_id,
                    "title": ke.title,
                    "workaround": ke.workaround,
                    "root_cause": ke.root_cause,
                    "permanent_fix_status": ke.permanent_fix_status.value,
                    "relevance_score": score,
                })

        matches.sort(key=lambda m: m["relevance_score"], reverse=True)
        return matches

    def match_incident_to_known_error(
        self,
        incident_data: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Attempt to match incident data to a known error.
        incident_data should contain 'title', 'description', and/or 'symptoms'.
        Returns the best match or None.
        """
        search_terms = []
        if "symptoms" in incident_data:
            search_terms.extend(incident_data["symptoms"])
        if "title" in incident_data:
            search_terms.extend(incident_data["title"].split())
        if "description" in incident_data:
            # Take key words from description
            desc_words = incident_data["description"].lower().split()
            # Filter short words
            search_terms.extend([w for w in desc_words if len(w) > 3])

        matches = self.search_known_errors(search_terms)
        if matches:
            return matches[0]
        return None

    # ----------------------------------------------------------
    # Analytics
    # ----------------------------------------------------------

    def get_recurring_incidents(self, threshold: int = 3) -> List[Dict[str, Any]]:
        """
        Identify problems linked to many incidents (recurring pattern).
        Returns problems with related_incidents count >= threshold.
        """
        recurring = []
        for pr in self.problems.values():
            if len(pr.related_incidents) >= threshold:
                recurring.append({
                    "problem_id": pr.problem_id,
                    "title": pr.title,
                    "incident_count": len(pr.related_incidents),
                    "status": pr.status.value,
                    "priority": pr.priority.value,
                    "related_incidents": pr.related_incidents,
                })
        recurring.sort(key=lambda r: r["incident_count"], reverse=True)
        return recurring

    def get_problem_trends(self) -> List[ProblemTrend]:
        """Analyze problem trends by category."""
        category_stats: Dict[str, Dict[str, Any]] = {}

        for pr in self.problems.values():
            cat = pr.category.value
            if cat not in category_stats:
                category_stats[cat] = {"count": 0, "resolution_days": [], "recent": 0, "older": 0}
            category_stats[cat]["count"] += 1

            # Calculate resolution time
            if pr.resolved_at and pr.created_at:
                delta = (pr.resolved_at - pr.created_at).total_seconds() / 86400
                category_stats[cat]["resolution_days"].append(delta)

            # Trend: compare last 30 days vs prior 30 days
            now = datetime.now(timezone.utc)
            age = (now - pr.created_at).days
            if age <= 30:
                category_stats[cat]["recent"] += 1
            elif age <= 60:
                category_stats[cat]["older"] += 1

        trends = []
        for cat, stats in category_stats.items():
            avg_days = (
                sum(stats["resolution_days"]) / len(stats["resolution_days"])
                if stats["resolution_days"]
                else 0.0
            )
            if stats["recent"] > stats["older"]:
                direction = "up"
            elif stats["recent"] < stats["older"]:
                direction = "down"
            else:
                direction = "stable"

            trends.append(ProblemTrend(
                category=cat,
                count=stats["count"],
                trend_direction=direction,
                avg_resolution_days=round(avg_days, 1),
            ))

        trends.sort(key=lambda t: t.count, reverse=True)
        return trends

    def get_top_root_causes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the most common root causes across problems."""
        cause_counts: Dict[str, int] = {}
        for pr in self.problems.values():
            if pr.root_cause:
                rc = pr.root_cause.strip()
                cause_counts[rc] = cause_counts.get(rc, 0) + 1

        sorted_causes = sorted(cause_counts.items(), key=lambda x: x[1], reverse=True)
        return [
            {"root_cause": cause, "count": count}
            for cause, count in sorted_causes[:limit]
        ]

    def get_dashboard(self) -> Dict[str, Any]:
        """Return a comprehensive problem management dashboard."""
        total = len(self.problems)
        status_counts: Dict[str, int] = {}
        priority_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        open_count = 0
        avg_age_days = 0.0

        now = datetime.now(timezone.utc)
        ages = []

        for pr in self.problems.values():
            status_counts[pr.status.value] = status_counts.get(pr.status.value, 0) + 1
            priority_counts[pr.priority.value] = priority_counts.get(pr.priority.value, 0) + 1
            category_counts[pr.category.value] = category_counts.get(pr.category.value, 0) + 1

            if pr.status not in (ProblemStatus.RESOLVED, ProblemStatus.CLOSED):
                open_count += 1
                ages.append((now - pr.created_at).days)

        if ages:
            avg_age_days = round(sum(ages) / len(ages), 1)

        return {
            "total_problems": total,
            "open_problems": open_count,
            "avg_open_age_days": avg_age_days,
            "total_known_errors": len(self.known_errors),
            "total_rcas": len(self.rcas),
            "by_status": status_counts,
            "by_priority": priority_counts,
            "by_category": category_counts,
            "trends": [
                {
                    "category": t.category,
                    "count": t.count,
                    "trend_direction": t.trend_direction,
                    "avg_resolution_days": t.avg_resolution_days,
                }
                for t in self.get_problem_trends()
            ],
            "top_root_causes": self.get_top_root_causes(5),
            "recurring_incidents": self.get_recurring_incidents(3),
        }
