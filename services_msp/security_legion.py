"""
AITHER Platform - Security Legion Service
Red Team / Blue Team / Purple Team Persona Management

Purpose:
- Spawn specialized security personas for offensive/defensive exercises
- Organize personas into Red, Blue, and Purple teams
- Deploy teams against digital twins of customer networks
- Execute simulated attack/defense missions with MITRE ATT&CK mapping
- Generate after-action reports with risk scoring and recommendations
- Track persona growth, technique mastery, and leaderboard rankings

Integrates with:
- Legion Forge (persona spawning infrastructure)
- Digital Twin (simulated network targets)
- SOAR Playbook Engine (defensive playbook triggers)
- Cyber-911 (incident response integration)

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)

try:
    from sqlalchemy.orm import Session
    from models.security_legion import (
        SecurityPersonaModel,
        SecurityTeamModel,
        SecurityMissionModel,
        AfterActionReportModel,
        MITRETechniqueModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None


# ============================================================
# Enums
# ============================================================

class TeamType(str, Enum):
    """Security team classification"""
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"


class RedRole(str, Enum):
    """Red team specialization roles"""
    RECON_SPECIALIST = "recon_specialist"
    EXPLOIT_DEVELOPER = "exploit_developer"
    SOCIAL_ENGINEER = "social_engineer"
    LATERAL_MOVEMENT_EXPERT = "lateral_movement_expert"
    PERSISTENCE_SPECIALIST = "persistence_specialist"
    C2_OPERATOR = "c2_operator"
    PHYSICAL_SECURITY = "physical_security"
    CLOUD_ATTACKER = "cloud_attacker"


class BlueRole(str, Enum):
    """Blue team specialization roles"""
    SOC_ANALYST = "soc_analyst"
    INCIDENT_RESPONDER = "incident_responder"
    FORENSICS_ANALYST = "forensics_analyst"
    THREAT_HUNTER = "threat_hunter"
    VULN_MANAGER = "vuln_manager"
    COMPLIANCE_AUDITOR = "compliance_auditor"
    DECEPTION_ENGINEER = "deception_engineer"
    MALWARE_ANALYST = "malware_analyst"


class PersonaStatus(str, Enum):
    """Security persona operational status"""
    AVAILABLE = "available"
    DEPLOYED = "deployed"
    RESTING = "resting"
    TRAINING = "training"
    RETIRED = "retired"


class MissionStatus(str, Enum):
    """Mission lifecycle status"""
    PLANNING = "planning"
    EXECUTING = "executing"
    COMPLETED = "completed"
    ABORTED = "aborted"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class TechniqueProfile:
    """MITRE ATT&CK technique reference"""
    technique_id: str
    mitre_id: str
    name: str
    tactic: str
    description: str = ""
    difficulty: float = 0.5
    detection_difficulty: float = 0.5
    persona_skill_required: float = 0.5


@dataclass
class SecurityPersona:
    """A specialized security team persona"""
    persona_id: str
    name: str
    team: str  # red / blue / purple
    role: str
    specialization: str = ""
    skill_level: float = 0.5
    experience_points: int = 0
    missions_completed: int = 0
    missions_success_rate: float = 0.0
    techniques_mastered: List[str] = field(default_factory=list)
    certifications: List[str] = field(default_factory=list)
    status: PersonaStatus = PersonaStatus.AVAILABLE
    current_assignment: Optional[str] = None
    team_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SecurityTeam:
    """A coordinated security team"""
    team_id: str
    name: str
    team_type: TeamType
    client_id: str
    personas: List[str] = field(default_factory=list)
    mission_count: int = 0
    avg_score: float = 0.0
    status: str = "standby"  # standby / deployed / debriefing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SecurityMission:
    """A mission / exercise record"""
    mission_id: str
    team_id: str
    twin_id: str
    mission_type: str  # red_team / blue_team / purple_team
    objective: str = ""
    status: MissionStatus = MissionStatus.PLANNING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    score: float = 0.0
    after_action_report: Optional[str] = None  # report_id


@dataclass
class AfterActionReport:
    """Detailed post-mission report"""
    report_id: str
    mission_id: str
    executive_summary: str = ""
    attack_narrative: List[str] = field(default_factory=list)
    vulnerabilities_exploited: List[str] = field(default_factory=list)
    defensive_gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_score_before: float = 0.0
    risk_score_after: float = 0.0
    lessons_learned: List[str] = field(default_factory=list)


# ============================================================
# Helpers
# ============================================================

def _gen_id(prefix: str = "SL") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _persona_to_dict(p: SecurityPersona) -> Dict[str, Any]:
    return {
        "persona_id": p.persona_id,
        "name": p.name,
        "team": p.team,
        "role": p.role,
        "specialization": p.specialization,
        "skill_level": p.skill_level,
        "experience_points": p.experience_points,
        "missions_completed": p.missions_completed,
        "missions_success_rate": p.missions_success_rate,
        "techniques_mastered": p.techniques_mastered,
        "certifications": p.certifications,
        "status": p.status.value if isinstance(p.status, PersonaStatus) else p.status,
        "current_assignment": p.current_assignment,
        "team_id": p.team_id,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def _team_to_dict(t: SecurityTeam) -> Dict[str, Any]:
    return {
        "team_id": t.team_id,
        "name": t.name,
        "team_type": t.team_type.value if isinstance(t.team_type, TeamType) else t.team_type,
        "client_id": t.client_id,
        "personas": t.personas,
        "mission_count": t.mission_count,
        "avg_score": t.avg_score,
        "status": t.status,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def _mission_to_dict(m: SecurityMission) -> Dict[str, Any]:
    return {
        "mission_id": m.mission_id,
        "team_id": m.team_id,
        "twin_id": m.twin_id,
        "mission_type": m.mission_type,
        "objective": m.objective,
        "status": m.status.value if isinstance(m.status, MissionStatus) else m.status,
        "started_at": m.started_at.isoformat() if m.started_at else None,
        "completed_at": m.completed_at.isoformat() if m.completed_at else None,
        "findings_count": m.findings_count,
        "score": m.score,
        "after_action_report": m.after_action_report,
    }


def _aar_to_dict(a: AfterActionReport) -> Dict[str, Any]:
    return {
        "report_id": a.report_id,
        "mission_id": a.mission_id,
        "executive_summary": a.executive_summary,
        "attack_narrative": a.attack_narrative,
        "vulnerabilities_exploited": a.vulnerabilities_exploited,
        "defensive_gaps": a.defensive_gaps,
        "recommendations": a.recommendations,
        "risk_score_before": a.risk_score_before,
        "risk_score_after": a.risk_score_after,
        "lessons_learned": a.lessons_learned,
    }


def _technique_to_dict(t: TechniqueProfile) -> Dict[str, Any]:
    return {
        "technique_id": t.technique_id,
        "mitre_id": t.mitre_id,
        "name": t.name,
        "tactic": t.tactic,
        "description": t.description,
        "difficulty": t.difficulty,
        "detection_difficulty": t.detection_difficulty,
        "persona_skill_required": t.persona_skill_required,
    }


# ============================================================
# Service
# ============================================================

class SecurityLegionService:
    """
    Red Team / Blue Team / Purple Team Legion Persona Service

    Spawns specialized security personas, organises them into teams,
    deploys them against digital twins, executes simulated missions,
    and generates comprehensive after-action reports with MITRE ATT&CK
    technique mapping.

    Integrates with:
    - Legion Forge (persona spawning)
    - Digital Twin infrastructure (simulated targets)
    - SOAR Playbook Engine (defensive automation)
    - Cyber-911 (incident response)
    """

    def __init__(self, db: "Session | None" = None):
        self.db = db
        self._personas: Dict[str, SecurityPersona] = {}
        self._teams: Dict[str, SecurityTeam] = {}
        self._missions: Dict[str, SecurityMission] = {}
        self._reports: Dict[str, AfterActionReport] = {}
        self._techniques: Dict[str, TechniqueProfile] = {}

        self._init_mitre_techniques()
        self._init_prebuilt_personas()

        logger.info(
            "SecurityLegionService initialized — %d techniques, %d personas",
            len(self._techniques),
            len(self._personas),
        )

    # ------------------------------------------------------------------ init
    def _init_mitre_techniques(self):
        """Pre-load MITRE ATT&CK technique catalogue."""
        techniques = [
            TechniqueProfile("T-001", "T1595", "Active Scanning", "Reconnaissance", "Scanning IP ranges and ports to identify live hosts and services", 0.3, 0.4, 0.3),
            TechniqueProfile("T-002", "T1589", "Gather Victim Identity Info", "Reconnaissance", "Collecting employee names, emails, credentials from OSINT sources", 0.3, 0.2, 0.3),
            TechniqueProfile("T-003", "T1590", "Gather Victim Network Info", "Reconnaissance", "Enumerating DNS, WHOIS, BGP, and network topology", 0.3, 0.3, 0.3),
            TechniqueProfile("T-004", "T1591", "Gather Victim Org Info", "Reconnaissance", "Business relationships, org charts, technology stack", 0.2, 0.1, 0.2),
            TechniqueProfile("T-005", "T1566", "Phishing", "Initial Access", "Spear-phishing emails with malicious attachments or links", 0.4, 0.5, 0.4),
            TechniqueProfile("T-006", "T1190", "Exploit Public-Facing App", "Initial Access", "Exploiting vulnerabilities in web applications and services", 0.7, 0.6, 0.7),
            TechniqueProfile("T-007", "T1133", "External Remote Services", "Initial Access", "Abusing VPN, RDP, Citrix, or SSH for initial entry", 0.5, 0.5, 0.5),
            TechniqueProfile("T-008", "T1078", "Valid Accounts", "Persistence", "Using compromised credentials for persistent access", 0.4, 0.7, 0.4),
            TechniqueProfile("T-009", "T1053", "Scheduled Task/Job", "Execution", "Creating scheduled tasks or cron jobs for code execution", 0.4, 0.5, 0.4),
            TechniqueProfile("T-010", "T1059", "Command and Scripting Interpreter", "Execution", "Using PowerShell, Bash, Python for command execution", 0.3, 0.4, 0.3),
            TechniqueProfile("T-011", "T1547", "Boot or Logon Autostart", "Persistence", "Registry run keys, startup folders, login scripts", 0.5, 0.5, 0.5),
            TechniqueProfile("T-012", "T1546", "Event Triggered Execution", "Persistence", "WMI subscriptions, AppInit DLLs, accessibility features", 0.6, 0.6, 0.6),
            TechniqueProfile("T-013", "T1548", "Abuse Elevation Control", "Privilege Escalation", "UAC bypass, sudo exploitation, setuid/setgid abuse", 0.6, 0.6, 0.6),
            TechniqueProfile("T-014", "T1134", "Access Token Manipulation", "Privilege Escalation", "Token impersonation, SID-History injection, runas", 0.7, 0.7, 0.7),
            TechniqueProfile("T-015", "T1070", "Indicator Removal", "Defense Evasion", "Log deletion, timestomping, file wiping", 0.5, 0.8, 0.5),
            TechniqueProfile("T-016", "T1027", "Obfuscated Files or Info", "Defense Evasion", "Encoding, encryption, packing of payloads and scripts", 0.5, 0.7, 0.5),
            TechniqueProfile("T-017", "T1055", "Process Injection", "Defense Evasion", "DLL injection, process hollowing, thread hijacking", 0.8, 0.8, 0.8),
            TechniqueProfile("T-018", "T1003", "OS Credential Dumping", "Credential Access", "LSASS memory, SAM database, DCSync, Kerberoasting", 0.7, 0.6, 0.7),
            TechniqueProfile("T-019", "T1110", "Brute Force", "Credential Access", "Password spraying, credential stuffing, dictionary attacks", 0.3, 0.3, 0.3),
            TechniqueProfile("T-020", "T1021", "Remote Services", "Lateral Movement", "RDP, SMB, SSH, WinRM for lateral movement", 0.5, 0.5, 0.5),
            TechniqueProfile("T-021", "T1570", "Lateral Tool Transfer", "Lateral Movement", "Transferring tools between compromised hosts", 0.4, 0.5, 0.4),
            TechniqueProfile("T-022", "T1560", "Archive Collected Data", "Collection", "Compressing and encrypting data before exfiltration", 0.3, 0.4, 0.3),
            TechniqueProfile("T-023", "T1071", "Application Layer Protocol", "Command and Control", "HTTP/S, DNS, SMTP for C2 communication", 0.5, 0.7, 0.5),
            TechniqueProfile("T-024", "T1105", "Ingress Tool Transfer", "Command and Control", "Downloading additional tools to compromised host", 0.3, 0.4, 0.3),
            TechniqueProfile("T-025", "T1572", "Protocol Tunneling", "Command and Control", "DNS tunneling, ICMP tunneling, SSH tunneling", 0.6, 0.7, 0.6),
            TechniqueProfile("T-026", "T1486", "Data Encrypted for Impact", "Impact", "Ransomware encryption of files and systems", 0.6, 0.3, 0.6),
            TechniqueProfile("T-027", "T1567", "Exfiltration Over Web Service", "Exfiltration", "Using cloud storage, paste sites, or web services for data theft", 0.4, 0.6, 0.4),
            TechniqueProfile("T-028", "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "DNS, ICMP, or custom protocol exfiltration", 0.6, 0.7, 0.6),
            TechniqueProfile("T-029", "T1098", "Account Manipulation", "Persistence", "Adding credentials, modifying permissions, creating accounts", 0.5, 0.5, 0.5),
            TechniqueProfile("T-030", "T1219", "Remote Access Software", "Command and Control", "TeamViewer, AnyDesk, or other RATs for persistent access", 0.3, 0.4, 0.3),
            TechniqueProfile("T-031", "T1036", "Masquerading", "Defense Evasion", "Renaming executables, mimicking legitimate processes", 0.4, 0.6, 0.4),
            TechniqueProfile("T-032", "T1562", "Impair Defenses", "Defense Evasion", "Disabling AV, EDR, firewalls, logging services", 0.6, 0.5, 0.6),
        ]
        for t in techniques:
            self._techniques[t.technique_id] = t

    def _init_prebuilt_personas(self):
        """Spawn the 16 pre-built security personas (8 red, 8 blue)."""
        red_defs = [
            ("Ghost", RedRole.RECON_SPECIALIST, 0.9,
             ["T-001", "T-002", "T-003", "T-004"],
             ["OSINT", "network mapping", "service enumeration"],
             ["OSCP", "CEH"]),
            ("Viper", RedRole.EXPLOIT_DEVELOPER, 0.95,
             ["T-006", "T-007", "T-017"],
             ["CVE exploitation", "0-day research", "payload crafting"],
             ["OSCP", "OSCE", "GXPN"]),
            ("Siren", RedRole.SOCIAL_ENGINEER, 0.85,
             ["T-005", "T-004"],
             ["phishing campaigns", "pretexting", "vishing"],
             ["CEH", "SEPP"]),
            ("Shadow", RedRole.LATERAL_MOVEMENT_EXPERT, 0.9,
             ["T-018", "T-020", "T-021", "T-014"],
             ["credential harvesting", "pass-the-hash", "pivoting"],
             ["OSCP", "CRTO"]),
            ("Anchor", RedRole.PERSISTENCE_SPECIALIST, 0.85,
             ["T-008", "T-009", "T-011", "T-012", "T-029"],
             ["backdoors", "rootkits", "scheduled tasks", "registry"],
             ["OSCP", "GPEN"]),
            ("Puppet", RedRole.C2_OPERATOR, 0.9,
             ["T-023", "T-024", "T-025", "T-030"],
             ["command & control", "data staging", "exfiltration"],
             ["OSCP", "CRTO"]),
            ("Locksmith", RedRole.PHYSICAL_SECURITY, 0.8,
             ["T-005"],
             ["badge cloning", "tailgating", "USB drops"],
             ["CPP", "PSP"]),
            ("Nimbus", RedRole.CLOUD_ATTACKER, 0.85,
             ["T-078", "T-006", "T-008"],
             ["AWS/Azure/GCP misconfig", "IAM exploitation"],
             ["AWS-SAA", "AZ-500", "CCSP"]),
        ]
        for name, role, skill, techs, specs, certs in red_defs:
            pid = _gen_id("RED")
            self._personas[pid] = SecurityPersona(
                persona_id=pid, name=name, team="red",
                role=role.value, specialization=", ".join(specs),
                skill_level=skill, techniques_mastered=techs,
                certifications=certs,
            )

        blue_defs = [
            ("Sentinel", BlueRole.SOC_ANALYST, 0.85,
             ["T-001", "T-023", "T-010"],
             ["log analysis", "alert triage", "SIEM correlation"],
             ["CySA+", "GCDA"]),
            ("Phoenix", BlueRole.INCIDENT_RESPONDER, 0.9,
             ["T-018", "T-055", "T-070"],
             ["containment", "eradication", "recovery"],
             ["GCIH", "ECIH"]),
            ("Sherlock", BlueRole.FORENSICS_ANALYST, 0.9,
             ["T-003", "T-022", "T-015"],
             ["disk/memory/network forensics", "chain of custody"],
             ["GCFE", "EnCE", "CHFI"]),
            ("Hawk", BlueRole.THREAT_HUNTER, 0.85,
             ["T-017", "T-016", "T-031"],
             ["hypothesis-driven hunting", "IOC sweeping"],
             ["GCTI", "CTIA"]),
            ("Patcher", BlueRole.VULN_MANAGER, 0.8,
             ["T-006", "T-007"],
             ["CVE tracking", "patch prioritization", "risk scoring"],
             ["CySA+", "CEH"]),
            ("Auditor", BlueRole.COMPLIANCE_AUDITOR, 0.85,
             ["T-008", "T-029"],
             ["HIPAA/SOC2/NIST mapping", "evidence collection"],
             ["CISA", "CISM", "CISSP"]),
            ("Mirage", BlueRole.DECEPTION_ENGINEER, 0.8,
             ["T-012", "T-032"],
             ["honeypots", "honeytokens", "canary files"],
             ["GCDA", "CEH"]),
            ("Scalpel", BlueRole.MALWARE_ANALYST, 0.9,
             ["T-016", "T-017", "T-027"],
             ["static/dynamic analysis", "sandboxing", "YARA rules"],
             ["GREM", "CREA"]),
        ]
        for name, role, skill, techs, specs, certs in blue_defs:
            pid = _gen_id("BLU")
            self._personas[pid] = SecurityPersona(
                persona_id=pid, name=name, team="blue",
                role=role.value, specialization=", ".join(specs),
                skill_level=skill, techniques_mastered=techs,
                certifications=certs,
            )

    # ================================================================
    # Team Management
    # ================================================================

    def spawn_red_team(self, client_id: str, size: int = 4) -> Dict[str, Any]:
        """Create a red team from pre-built red personas."""
        red_available = [
            p for p in self._personas.values()
            if p.team == "red" and p.status == PersonaStatus.AVAILABLE
        ]
        selected = red_available[:min(size, len(red_available))]
        if not selected:
            return {"error": "No available red personas"}
        return self._assemble_team(client_id, TeamType.RED_TEAM, selected, f"Red Team - {client_id}")

    def spawn_blue_team(self, client_id: str, size: int = 4) -> Dict[str, Any]:
        """Create a blue team from pre-built blue personas."""
        blue_available = [
            p for p in self._personas.values()
            if p.team == "blue" and p.status == PersonaStatus.AVAILABLE
        ]
        selected = blue_available[:min(size, len(blue_available))]
        if not selected:
            return {"error": "No available blue personas"}
        return self._assemble_team(client_id, TeamType.BLUE_TEAM, selected, f"Blue Team - {client_id}")

    def spawn_purple_team(self, client_id: str) -> Dict[str, Any]:
        """Create a combined purple team with both red and blue personas."""
        red_avail = [p for p in self._personas.values() if p.team == "red" and p.status == PersonaStatus.AVAILABLE]
        blue_avail = [p for p in self._personas.values() if p.team == "blue" and p.status == PersonaStatus.AVAILABLE]
        selected = red_avail[:4] + blue_avail[:4]
        if len(selected) < 2:
            return {"error": "Insufficient personas for purple team"}
        return self._assemble_team(client_id, TeamType.PURPLE_TEAM, selected, f"Purple Team - {client_id}")

    def spawn_custom_team(self, client_id: str, team_type: str, persona_configs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a custom team from explicit persona configurations."""
        tt = TeamType(team_type)
        personas: List[SecurityPersona] = []
        for cfg in persona_configs:
            pid = _gen_id("CUS")
            p = SecurityPersona(
                persona_id=pid,
                name=cfg.get("name", f"Agent-{pid[-4:]}"),
                team=cfg.get("team", "red"),
                role=cfg.get("role", "recon_specialist"),
                specialization=cfg.get("specialization", ""),
                skill_level=cfg.get("skill_level", 0.7),
                techniques_mastered=cfg.get("techniques_mastered", []),
                certifications=cfg.get("certifications", []),
            )
            self._personas[pid] = p
            personas.append(p)
        return self._assemble_team(client_id, tt, personas, f"Custom {tt.value} - {client_id}")

    def _assemble_team(self, client_id: str, team_type: TeamType, personas: List[SecurityPersona], name: str) -> Dict[str, Any]:
        """Internal helper to assemble a team from personas."""
        tid = _gen_id("TM")
        pids = [p.persona_id for p in personas]
        team = SecurityTeam(
            team_id=tid, name=name, team_type=team_type,
            client_id=client_id, personas=pids,
        )
        self._teams[tid] = team
        for p in personas:
            p.status = PersonaStatus.AVAILABLE
            p.team_id = tid
        self._persist_team(team)
        for p in personas:
            self._persist_persona(p)
        logger.info("Assembled %s with %d personas for client %s", team_type.value, len(pids), client_id)
        return _team_to_dict(team)

    def get_team(self, team_id: str) -> Optional[Dict[str, Any]]:
        """Get a single team by ID."""
        team = self._teams.get(team_id)
        if team:
            return _team_to_dict(team)
        return None

    def list_teams(self, client_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all teams, optionally filtered by client."""
        teams = list(self._teams.values())
        if client_id:
            teams = [t for t in teams if t.client_id == client_id]
        return [_team_to_dict(t) for t in teams]

    def disband_team(self, team_id: str) -> Dict[str, Any]:
        """Disband a team and release all personas."""
        team = self._teams.get(team_id)
        if not team:
            return {"error": f"Team {team_id} not found"}
        for pid in team.personas:
            p = self._personas.get(pid)
            if p:
                p.status = PersonaStatus.AVAILABLE
                p.team_id = None
                p.current_assignment = None
                self._persist_persona(p)
        del self._teams[team_id]
        self._delete_team(team_id)
        return {"status": "disbanded", "team_id": team_id}

    # ================================================================
    # Persona Management
    # ================================================================

    def get_persona(self, persona_id: str) -> Optional[Dict[str, Any]]:
        """Get a single persona by ID."""
        p = self._personas.get(persona_id)
        if p:
            return _persona_to_dict(p)
        return None

    def list_personas(self, team: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List personas with optional filters."""
        result = list(self._personas.values())
        if team:
            result = [p for p in result if p.team == team]
        if status:
            result = [p for p in result if (p.status.value if isinstance(p.status, PersonaStatus) else p.status) == status]
        return [_persona_to_dict(p) for p in result]

    def retire_persona(self, persona_id: str) -> Dict[str, Any]:
        """Retire a persona from active duty."""
        p = self._personas.get(persona_id)
        if not p:
            return {"error": f"Persona {persona_id} not found"}
        p.status = PersonaStatus.RETIRED
        p.current_assignment = None
        self._persist_persona(p)
        return {"status": "retired", "persona_id": persona_id, "name": p.name}

    def promote_persona(self, persona_id: str) -> Dict[str, Any]:
        """Promote a high-performing persona (85%+ success rate, 5+ missions)."""
        p = self._personas.get(persona_id)
        if not p:
            return {"error": f"Persona {persona_id} not found"}
        if p.missions_completed < 5:
            return {"error": f"Requires 5+ missions, has {p.missions_completed}"}
        if p.missions_success_rate < 0.85:
            return {"error": f"Requires 85%+ success rate, has {p.missions_success_rate:.0%}"}
        old_skill = p.skill_level
        p.skill_level = min(1.0, p.skill_level + 0.05)
        p.experience_points += 500
        p.certifications.append("Elite Operator")
        self._persist_persona(p)
        return {
            "status": "promoted",
            "persona_id": persona_id,
            "name": p.name,
            "skill_level_before": old_skill,
            "skill_level_after": p.skill_level,
        }

    def assign_training(self, persona_id: str, technique_id: str) -> Dict[str, Any]:
        """Train a persona on a new MITRE technique."""
        p = self._personas.get(persona_id)
        if not p:
            return {"error": f"Persona {persona_id} not found"}
        tech = self._techniques.get(technique_id)
        if not tech:
            return {"error": f"Technique {technique_id} not found"}
        if technique_id in p.techniques_mastered:
            return {"error": f"Persona already mastered {technique_id}"}
        if p.skill_level < tech.persona_skill_required:
            return {"error": f"Skill {p.skill_level:.2f} below required {tech.persona_skill_required:.2f}"}
        p.techniques_mastered.append(technique_id)
        p.experience_points += int(tech.difficulty * 100)
        p.status = PersonaStatus.TRAINING
        self._persist_persona(p)
        # Training completes immediately in simulation
        p.status = PersonaStatus.AVAILABLE
        self._persist_persona(p)
        return {
            "status": "trained",
            "persona_id": persona_id,
            "technique": tech.name,
            "mitre_id": tech.mitre_id,
            "xp_gained": int(tech.difficulty * 100),
        }

    # ================================================================
    # Mission Lifecycle
    # ================================================================

    def deploy_team(self, team_id: str, twin_id: str, mission_objective: str) -> Dict[str, Any]:
        """Deploy a team to a digital twin for a mission."""
        team = self._teams.get(team_id)
        if not team:
            return {"error": f"Team {team_id} not found"}
        if team.status == "deployed":
            return {"error": f"Team {team_id} already deployed"}

        mission_type = team.team_type.value
        mid = _gen_id("MSN")
        mission = SecurityMission(
            mission_id=mid, team_id=team_id, twin_id=twin_id,
            mission_type=mission_type, objective=mission_objective,
            status=MissionStatus.PLANNING,
            started_at=datetime.now(timezone.utc),
        )
        self._missions[mid] = mission
        team.status = "deployed"
        team.mission_count += 1
        for pid in team.personas:
            p = self._personas.get(pid)
            if p:
                p.status = PersonaStatus.DEPLOYED
                p.current_assignment = mid
                self._persist_persona(p)
        self._persist_team(team)
        self._persist_mission(mission)
        logger.info("Deployed team %s to twin %s — mission %s", team_id, twin_id, mid)
        return _mission_to_dict(mission)

    def execute_mission(self, mission_id: str) -> Dict[str, Any]:
        """Execute a planned mission simulation."""
        mission = self._missions.get(mission_id)
        if not mission:
            return {"error": f"Mission {mission_id} not found"}
        if mission.status != MissionStatus.PLANNING:
            return {"error": f"Mission status is {mission.status.value}, expected planning"}

        team = self._teams.get(mission.team_id)
        if not team:
            return {"error": "Team not found for mission"}

        mission.status = MissionStatus.EXECUTING

        if team.team_type == TeamType.RED_TEAM:
            result = self._execute_red_mission(mission, team)
        elif team.team_type == TeamType.BLUE_TEAM:
            result = self._execute_blue_mission(mission, team)
        else:
            result = self._execute_purple_mission(mission, team)

        mission.status = MissionStatus.COMPLETED
        mission.completed_at = datetime.now(timezone.utc)
        mission.findings_count = result.get("findings_count", 0)
        mission.score = result.get("score", 0.0)
        self._persist_mission(mission)

        # Update persona stats
        for pid in team.personas:
            p = self._personas.get(pid)
            if p:
                p.missions_completed += 1
                success = mission.score >= 70.0
                total = p.missions_completed
                old_rate = p.missions_success_rate
                p.missions_success_rate = ((old_rate * (total - 1)) + (1.0 if success else 0.0)) / total
                p.experience_points += int(mission.score * 10)
                p.status = PersonaStatus.RESTING
                p.current_assignment = None
                self._persist_persona(p)

        team.status = "debriefing"
        scores = [m.score for m in self._missions.values() if m.team_id == team.team_id and m.status == MissionStatus.COMPLETED]
        team.avg_score = sum(scores) / len(scores) if scores else 0.0
        self._persist_team(team)

        return {
            "mission_id": mission_id,
            "status": "completed",
            "score": mission.score,
            "findings_count": mission.findings_count,
            **result,
        }

    def _execute_red_mission(self, mission: SecurityMission, team: SecurityTeam) -> Dict[str, Any]:
        """Simulate red team attacking the digital twin."""
        personas = [self._personas[pid] for pid in team.personas if pid in self._personas]
        all_techniques = set()
        for p in personas:
            all_techniques.update(p.techniques_mastered)

        findings = []
        narrative = []
        vulns = []
        total_skill = sum(p.skill_level for p in personas) / max(len(personas), 1)

        # Simulate attack phases mapped to MITRE tactics
        phases = [
            ("Reconnaissance", ["T-001", "T-002", "T-003", "T-004"]),
            ("Initial Access", ["T-005", "T-006", "T-007"]),
            ("Execution", ["T-009", "T-010"]),
            ("Persistence", ["T-008", "T-011", "T-012", "T-029"]),
            ("Privilege Escalation", ["T-013", "T-014"]),
            ("Defense Evasion", ["T-015", "T-016", "T-017", "T-031", "T-032"]),
            ("Credential Access", ["T-018", "T-019"]),
            ("Lateral Movement", ["T-020", "T-021"]),
            ("Collection", ["T-022"]),
            ("Command and Control", ["T-023", "T-024", "T-025", "T-030"]),
            ("Exfiltration", ["T-027", "T-028"]),
            ("Impact", ["T-026"]),
        ]

        for phase_name, phase_techs in phases:
            applicable = [t for t in phase_techs if t in all_techniques]
            if applicable:
                tech_id = random.choice(applicable)
                tech = self._techniques.get(tech_id)
                if tech:
                    success_chance = total_skill - tech.difficulty * 0.5
                    succeeded = random.random() < max(0.3, min(0.95, success_chance))
                    if succeeded:
                        narrative.append(f"[{phase_name}] Executed {tech.name} ({tech.mitre_id}) — SUCCESS")
                        findings.append(f"{tech.mitre_id}: {tech.name} exploitable")
                        vulns.append(tech.mitre_id)
                    else:
                        narrative.append(f"[{phase_name}] Attempted {tech.name} ({tech.mitre_id}) — BLOCKED")
            else:
                narrative.append(f"[{phase_name}] No applicable techniques — SKIPPED")

        score = min(100.0, (len(findings) / max(len(phases), 1)) * 100)
        return {
            "findings_count": len(findings),
            "score": round(score, 1),
            "narrative": narrative,
            "vulnerabilities": vulns,
            "findings": findings,
        }

    def _execute_blue_mission(self, mission: SecurityMission, team: SecurityTeam, red_findings: Optional[List[str]] = None) -> Dict[str, Any]:
        """Simulate blue team defending the digital twin."""
        personas = [self._personas[pid] for pid in team.personas if pid in self._personas]
        total_skill = sum(p.skill_level for p in personas) / max(len(personas), 1)

        # Simulate attacker actions that blue team must detect/respond to
        attack_scenarios = red_findings or [
            "T1595: Active scanning detected",
            "T1566: Phishing email delivered",
            "T1078: Valid account login from anomalous IP",
            "T1021: Lateral RDP session",
            "T1486: Ransomware encryption started",
        ]

        detections = []
        gaps = []
        narrative = []

        for scenario in attack_scenarios:
            detect_chance = total_skill * 0.9
            detected = random.random() < max(0.3, min(0.95, detect_chance))
            if detected:
                detections.append(f"DETECTED: {scenario}")
                narrative.append(f"[Detection] {scenario} — CAUGHT")
            else:
                gaps.append(f"MISSED: {scenario}")
                narrative.append(f"[Detection] {scenario} — MISSED")

        # Response effectiveness
        contained = 0
        for d in detections:
            if random.random() < total_skill:
                contained += 1
                narrative.append(f"[Response] Contained threat — SUCCESS")
            else:
                narrative.append(f"[Response] Containment attempted — PARTIAL")

        score = min(100.0, (len(detections) / max(len(attack_scenarios), 1)) * 70 + (contained / max(len(detections), 1)) * 30)
        return {
            "findings_count": len(gaps),
            "score": round(score, 1),
            "narrative": narrative,
            "detections": detections,
            "gaps": gaps,
        }

    def _execute_purple_mission(self, mission: SecurityMission, team: SecurityTeam) -> Dict[str, Any]:
        """Combined red/blue exercise — red attacks, blue defends in real-time."""
        red_personas = [self._personas[pid] for pid in team.personas if pid in self._personas and self._personas[pid].team == "red"]
        blue_personas = [self._personas[pid] for pid in team.personas if pid in self._personas and self._personas[pid].team == "blue"]

        # Run red simulation first
        red_team_stub = SecurityTeam(
            team_id="temp-red", name="temp", team_type=TeamType.RED_TEAM,
            client_id="", personas=[p.persona_id for p in red_personas],
        )
        red_result = self._execute_red_mission(mission, red_team_stub)

        # Blue defends against red findings
        blue_team_stub = SecurityTeam(
            team_id="temp-blue", name="temp", team_type=TeamType.BLUE_TEAM,
            client_id="", personas=[p.persona_id for p in blue_personas],
        )
        blue_result = self._execute_blue_mission(mission, blue_team_stub, red_result.get("findings", []))

        combined_score = (red_result.get("score", 0) + blue_result.get("score", 0)) / 2
        return {
            "findings_count": red_result.get("findings_count", 0) + blue_result.get("findings_count", 0),
            "score": round(combined_score, 1),
            "narrative": red_result.get("narrative", []) + ["--- BLUE TEAM RESPONSE ---"] + blue_result.get("narrative", []),
            "red_score": red_result.get("score", 0),
            "blue_score": blue_result.get("score", 0),
            "vulnerabilities": red_result.get("vulnerabilities", []),
            "detections": blue_result.get("detections", []),
            "gaps": blue_result.get("gaps", []),
        }

    def complete_mission(self, mission_id: str) -> Dict[str, Any]:
        """Finalize mission and release team back to standby."""
        mission = self._missions.get(mission_id)
        if not mission:
            return {"error": f"Mission {mission_id} not found"}
        team = self._teams.get(mission.team_id)
        if team:
            team.status = "standby"
            for pid in team.personas:
                p = self._personas.get(pid)
                if p:
                    p.status = PersonaStatus.AVAILABLE
                    self._persist_persona(p)
            self._persist_team(team)
        return {"status": "finalized", "mission_id": mission_id}

    def abort_mission(self, mission_id: str) -> Dict[str, Any]:
        """Abort an active or planned mission."""
        mission = self._missions.get(mission_id)
        if not mission:
            return {"error": f"Mission {mission_id} not found"}
        mission.status = MissionStatus.ABORTED
        mission.completed_at = datetime.now(timezone.utc)
        self._persist_mission(mission)
        # Release team
        return self.complete_mission(mission_id)

    # ================================================================
    # After-Action Reports
    # ================================================================

    def generate_after_action_report(self, mission_id: str) -> Dict[str, Any]:
        """Generate a detailed after-action report for a completed mission."""
        mission = self._missions.get(mission_id)
        if not mission:
            return {"error": f"Mission {mission_id} not found"}
        if mission.status not in (MissionStatus.COMPLETED, MissionStatus.ABORTED):
            return {"error": "Mission must be completed or aborted to generate AAR"}

        team = self._teams.get(mission.team_id)
        team_name = team.name if team else "Unknown"
        risk_before = round(random.uniform(60, 95), 1)
        risk_after = round(max(10, risk_before - mission.score * 0.5 + random.uniform(-5, 5)), 1)

        rid = _gen_id("AAR")
        aar = AfterActionReport(
            report_id=rid,
            mission_id=mission_id,
            executive_summary=(
                f"Security exercise completed by {team_name} against digital twin {mission.twin_id}. "
                f"Mission type: {mission.mission_type}. Overall score: {mission.score}/100. "
                f"Risk posture improved from {risk_before} to {risk_after}."
            ),
            attack_narrative=[
                f"Phase 1: Reconnaissance and target enumeration",
                f"Phase 2: Initial access attempts via identified attack vectors",
                f"Phase 3: Privilege escalation and lateral movement",
                f"Phase 4: Objective execution and data access validation",
                f"Phase 5: Cleanup and evidence collection",
            ],
            vulnerabilities_exploited=[
                "Unpatched CVE on public-facing web server",
                "Weak password policy allowing credential stuffing",
                "Missing network segmentation between DMZ and internal network",
                "Overly permissive IAM roles in cloud environment",
            ][:max(1, mission.findings_count)],
            defensive_gaps=[
                "SIEM alert fatigue — high-priority alerts buried in noise",
                "Insufficient endpoint detection on legacy systems",
                "No deception technology deployed in critical segments",
                "Incident response playbook missing ransomware scenario",
            ][:max(1, int(4 - mission.score / 30))],
            recommendations=[
                "Implement network micro-segmentation for critical assets",
                "Deploy honeytokens in Active Directory and file shares",
                "Enforce MFA on all privileged accounts and VPN access",
                "Conduct quarterly tabletop exercises for IR team",
                "Upgrade EDR coverage to include all Linux and legacy endpoints",
                "Tune SIEM correlation rules to reduce false positive rate below 5%",
            ],
            risk_score_before=risk_before,
            risk_score_after=risk_after,
            lessons_learned=[
                "Credential harvesting remains the highest-ROI attack vector",
                "Blue team detection time improved 40% over previous exercise",
                "Cloud IAM misconfigurations are expanding the attack surface",
                "Deception technology significantly increases attacker dwell time",
            ],
        )
        self._reports[rid] = aar
        mission.after_action_report = rid
        self._persist_mission(mission)
        self._persist_aar(aar)
        return _aar_to_dict(aar)

    def get_report(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Get the after-action report for a mission."""
        mission = self._missions.get(mission_id)
        if not mission or not mission.after_action_report:
            return None
        aar = self._reports.get(mission.after_action_report)
        return _aar_to_dict(aar) if aar else None

    # ================================================================
    # Techniques & Coverage
    # ================================================================

    def list_techniques(self) -> List[Dict[str, Any]]:
        """List all MITRE ATT&CK techniques in the catalogue."""
        return [_technique_to_dict(t) for t in self._techniques.values()]

    def get_technique_coverage(self, team_id: str) -> Dict[str, Any]:
        """Determine which MITRE techniques a team can execute."""
        team = self._teams.get(team_id)
        if not team:
            return {"error": f"Team {team_id} not found"}
        covered = set()
        for pid in team.personas:
            p = self._personas.get(pid)
            if p:
                covered.update(p.techniques_mastered)
        all_ids = set(self._techniques.keys())
        return {
            "team_id": team_id,
            "covered": sorted(covered),
            "uncovered": sorted(all_ids - covered),
            "coverage_pct": round(len(covered) / max(len(all_ids), 1) * 100, 1),
            "total_techniques": len(all_ids),
        }

    # ================================================================
    # Leaderboard & Dashboard
    # ================================================================

    def get_leaderboard(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Top performers across all personas, ranked by XP and success rate."""
        ranked = sorted(
            self._personas.values(),
            key=lambda p: (p.experience_points, p.missions_success_rate, p.skill_level),
            reverse=True,
        )
        return [
            {
                "rank": i + 1,
                "persona_id": p.persona_id,
                "name": p.name,
                "team": p.team,
                "role": p.role,
                "skill_level": p.skill_level,
                "xp": p.experience_points,
                "missions": p.missions_completed,
                "success_rate": p.missions_success_rate,
                "techniques": len(p.techniques_mastered),
            }
            for i, p in enumerate(ranked[:limit])
        ]

    def get_dashboard(self, client_id: str) -> Dict[str, Any]:
        """Aggregated dashboard for a client's security posture."""
        client_teams = [t for t in self._teams.values() if t.client_id == client_id]
        team_ids = {t.team_id for t in client_teams}
        client_missions = [m for m in self._missions.values() if m.team_id in team_ids]
        completed = [m for m in client_missions if m.status == MissionStatus.COMPLETED]
        active = [m for m in client_missions if m.status in (MissionStatus.PLANNING, MissionStatus.EXECUTING)]

        avg_score = sum(m.score for m in completed) / max(len(completed), 1)
        total_findings = sum(m.findings_count for m in completed)

        # Risk trend from AARs
        risk_trend = []
        for m in completed[-10:]:
            aar = self._reports.get(m.after_action_report) if m.after_action_report else None
            if aar:
                risk_trend.append({
                    "mission_id": m.mission_id,
                    "risk_before": aar.risk_score_before,
                    "risk_after": aar.risk_score_after,
                })

        return {
            "client_id": client_id,
            "teams": [_team_to_dict(t) for t in client_teams],
            "team_count": len(client_teams),
            "active_missions": [_mission_to_dict(m) for m in active],
            "completed_missions": len(completed),
            "avg_mission_score": round(avg_score, 1),
            "total_findings": total_findings,
            "risk_trend": risk_trend,
            "top_personas": self.get_leaderboard(5),
        }

    # ================================================================
    # Mission listing
    # ================================================================

    def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Get a single mission by ID."""
        m = self._missions.get(mission_id)
        return _mission_to_dict(m) if m else None

    def list_missions(self, team_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List missions with optional filters."""
        result = list(self._missions.values())
        if team_id:
            result = [m for m in result if m.team_id == team_id]
        if status:
            result = [m for m in result if (m.status.value if isinstance(m.status, MissionStatus) else m.status) == status]
        return [_mission_to_dict(m) for m in result]

    # ================================================================
    # DB Persistence Helpers
    # ================================================================

    def _persist_persona(self, p: SecurityPersona):
        if not self.db or not ORM_AVAILABLE:
            return
        try:
            row = self.db.query(SecurityPersonaModel).filter_by(persona_id=p.persona_id).first()
            if row:
                row.name = p.name
                row.team = p.team
                row.role = p.role
                row.specialization = p.specialization
                row.skill_level = p.skill_level
                row.experience_points = p.experience_points
                row.missions_completed = p.missions_completed
                row.missions_success_rate = p.missions_success_rate
                row.techniques_mastered = p.techniques_mastered
                row.certifications = p.certifications
                row.status = p.status.value if isinstance(p.status, PersonaStatus) else p.status
                row.current_assignment = p.current_assignment
                row.team_id = p.team_id
            else:
                row = SecurityPersonaModel(
                    persona_id=p.persona_id, name=p.name, team=p.team,
                    role=p.role, specialization=p.specialization,
                    skill_level=p.skill_level, experience_points=p.experience_points,
                    missions_completed=p.missions_completed,
                    missions_success_rate=p.missions_success_rate,
                    techniques_mastered=p.techniques_mastered,
                    certifications=p.certifications,
                    status=p.status.value if isinstance(p.status, PersonaStatus) else p.status,
                    current_assignment=p.current_assignment,
                    team_id=p.team_id,
                )
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.debug("Persona persist skipped: %s", exc)

    def _persist_team(self, t: SecurityTeam):
        if not self.db or not ORM_AVAILABLE:
            return
        try:
            row = self.db.query(SecurityTeamModel).filter_by(team_id=t.team_id).first()
            if row:
                row.name = t.name
                row.team_type = t.team_type.value if isinstance(t.team_type, TeamType) else t.team_type
                row.client_id = t.client_id
                row.personas = t.personas
                row.mission_count = t.mission_count
                row.avg_score = t.avg_score
                row.status = t.status
            else:
                row = SecurityTeamModel(
                    team_id=t.team_id, name=t.name,
                    team_type=t.team_type.value if isinstance(t.team_type, TeamType) else t.team_type,
                    client_id=t.client_id, personas=t.personas,
                    mission_count=t.mission_count, avg_score=t.avg_score,
                    status=t.status,
                )
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.debug("Team persist skipped: %s", exc)

    def _delete_team(self, team_id: str):
        if not self.db or not ORM_AVAILABLE:
            return
        try:
            self.db.query(SecurityTeamModel).filter_by(team_id=team_id).delete()
            self.db.commit()
        except Exception as exc:
            logger.debug("Team delete skipped: %s", exc)

    def _persist_mission(self, m: SecurityMission):
        if not self.db or not ORM_AVAILABLE:
            return
        try:
            row = self.db.query(SecurityMissionModel).filter_by(mission_id=m.mission_id).first()
            if row:
                row.status = m.status.value if isinstance(m.status, MissionStatus) else m.status
                row.completed_at = m.completed_at
                row.findings_count = m.findings_count
                row.score = m.score
                row.after_action_report = {"report_id": m.after_action_report} if m.after_action_report else {}
            else:
                row = SecurityMissionModel(
                    mission_id=m.mission_id, team_id=m.team_id,
                    twin_id=m.twin_id, mission_type=m.mission_type,
                    objective=m.objective,
                    status=m.status.value if isinstance(m.status, MissionStatus) else m.status,
                    started_at=m.started_at, completed_at=m.completed_at,
                    findings_count=m.findings_count, score=m.score,
                    after_action_report={"report_id": m.after_action_report} if m.after_action_report else {},
                )
                self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.debug("Mission persist skipped: %s", exc)

    def _persist_aar(self, a: AfterActionReport):
        if not self.db or not ORM_AVAILABLE:
            return
        try:
            row = AfterActionReportModel(
                report_id=a.report_id, mission_id=a.mission_id,
                executive_summary=a.executive_summary,
                attack_narrative=a.attack_narrative,
                vulnerabilities_exploited=a.vulnerabilities_exploited,
                defensive_gaps=a.defensive_gaps,
                recommendations=a.recommendations,
                risk_score_before=a.risk_score_before,
                risk_score_after=a.risk_score_after,
                lessons_learned=a.lessons_learned,
            )
            self.db.add(row)
            self.db.commit()
        except Exception as exc:
            logger.debug("AAR persist skipped: %s", exc)
