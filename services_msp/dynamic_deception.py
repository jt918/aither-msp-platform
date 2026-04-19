"""
AITHER Platform - Dynamic Honeypot & Canary Deployment Service

Auto-deploys deception assets based on real-time threat scoring.
When an IP/user gets a high threat score, the system dynamically
redirects them to honeypots, plants breadcrumbs, and captures
attacker intelligence for IOC extraction and TTP mapping.

Provides:
- Deception asset lifecycle (honeypots, canary tokens, honeyfiles, breadcrumbs)
- Automated rule-based deployment triggered by threat scores
- Full interaction capture and intelligence extraction
- MITRE ATT&CK TTP mapping from observed behavior
- Attacker profiling and campaign attribution

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import secrets
import hashlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

try:
    from sqlalchemy.orm import Session
    from models.dynamic_deception import (
        DeceptionAssetModel,
        HoneypotServiceModel,
        CanaryTokenModel as CanaryTokenDBModel,
        DeceptionRuleModel,
        InteractionLogModel,
        IntelligenceReportModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class DeceptionAsset:
    """A deception asset deployed to detect and track attackers."""
    asset_id: str
    asset_type: str  # honeypot/canary_token/honeyfile/honeyfolder/honey_credential/honey_service/honey_network/honey_database/breadcrumb
    name: str
    description: str = ""
    deployment_target: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    status: str = "staged"  # staged/deployed/active/triggered/compromised/retired
    interaction_count: int = 0
    last_interaction_at: Optional[datetime] = None
    intelligence_gathered: List[Dict[str, Any]] = field(default_factory=list)
    deployed_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class HoneypotService:
    """A fake service exposed by a honeypot asset."""
    honeypot_id: str
    asset_id: str
    service_type: str  # ssh/rdp/http/https/ftp/smb/telnet/mysql/mssql/smtp/dns/snmp/ldap/redis/elasticsearch
    listen_port: int
    listen_ip: str = "0.0.0.0"
    banner: str = ""
    credentials: List[Dict[str, str]] = field(default_factory=list)
    response_templates: Dict[str, Any] = field(default_factory=dict)
    capture_level: str = "auth_capture"  # banner_only/auth_capture/full_interaction/sandbox
    max_sessions: int = 10


@dataclass
class CanaryToken:
    """A planted canary token that alerts when accessed."""
    token_id: str
    asset_id: str
    token_type: str  # aws_key/api_key/database_cred/document/url/dns/email/file_share/registry_key/env_variable
    token_value: str
    deployment_location: str = ""
    trigger_webhook: str = ""
    triggered_count: int = 0
    last_triggered_at: Optional[datetime] = None
    triggered_by: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class DeceptionRule:
    """Automated rule that deploys deception based on threat conditions."""
    rule_id: str
    name: str
    description: str = ""
    trigger_condition: Dict[str, Any] = field(default_factory=dict)
    risk_threshold: float = 7.0
    target_entity_type: str = "ip"
    action: str = "deploy_honeypot"  # deploy_honeypot/redirect_to_honeypot/plant_canary/enable_full_capture/alert_soc
    deception_asset_id: Optional[str] = None
    cooldown_minutes: int = 60
    is_enabled: bool = True
    executions: int = 0


@dataclass
class InteractionLog:
    """Captured interaction with a deception asset."""
    log_id: str
    asset_id: str
    source_ip: Optional[str] = None
    source_user: Optional[str] = None
    interaction_type: str = "connection"  # connection/auth_attempt/command/file_access/data_upload/reconnaissance
    raw_data: Dict[str, Any] = field(default_factory=dict)
    credentials_used: Optional[str] = None
    commands_executed: List[str] = field(default_factory=list)
    files_accessed: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    intelligence_value: str = "low"  # low/medium/high/critical
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IntelligenceReport:
    """Intelligence report extracted from deception interactions."""
    report_id: str
    asset_id: str
    report_type: str  # attacker_profile/ttp_analysis/ioc_extraction/campaign_attribution
    title: str = ""
    findings: Dict[str, Any] = field(default_factory=dict)
    iocs_extracted: List[str] = field(default_factory=list)
    ttps_observed: List[str] = field(default_factory=list)
    attacker_profile: Dict[str, Any] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Pre-built deception asset templates
# ---------------------------------------------------------------------------

PREBUILT_ASSETS: List[Dict[str, Any]] = [
    {
        "asset_type": "honeypot",
        "name": "SSH Honeypot",
        "description": "Fake SSH server capturing credentials and commands",
        "config": {
            "service": "ssh",
            "port": 2222,
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            "fake_creds": [
                {"username": "admin", "password": "P@ssw0rd123"},
                {"username": "root", "password": "toor"},
                {"username": "deploy", "password": "d3pl0y!"},
            ],
            "capture": "full_interaction",
            "fake_filesystem": True,
        },
    },
    {
        "asset_type": "honeypot",
        "name": "RDP Honeypot",
        "description": "Fake RDP login portal capturing credentials",
        "config": {
            "service": "rdp",
            "port": 3389,
            "banner": "Microsoft Terminal Services",
            "fake_creds": [
                {"username": "Administrator", "password": "Welcome1!"},
                {"username": "svc_backup", "password": "Backup2026!"},
            ],
            "capture": "auth_capture",
            "nla_enabled": False,
        },
    },
    {
        "asset_type": "honeypot",
        "name": "HTTP Honeypot",
        "description": "Fake web application capturing credentials, XSS, and SQLi attempts",
        "config": {
            "service": "http",
            "port": 8080,
            "server_header": "Apache/2.4.52 (Ubuntu)",
            "login_page": True,
            "fake_admin_panel": True,
            "capture": "full_interaction",
            "detect_sqli": True,
            "detect_xss": True,
            "fake_creds": [
                {"username": "admin", "password": "admin123"},
            ],
        },
    },
    {
        "asset_type": "honeypot",
        "name": "SMB Honeypot",
        "description": "Fake file share with enticing folder names (Finance, HR, Passwords)",
        "config": {
            "service": "smb",
            "port": 445,
            "share_name": "INTERNAL$",
            "folders": ["Finance", "HR", "Passwords", "Executive_Docs", "IT_Admin"],
            "fake_files": [
                "Finance/Budget_2026_FINAL.xlsx",
                "HR/Salary_Review_Confidential.docx",
                "Passwords/service_accounts.txt",
                "Executive_Docs/M&A_Target_List.pdf",
                "IT_Admin/vpn_credentials.csv",
            ],
            "capture": "full_interaction",
        },
    },
    {
        "asset_type": "honeypot",
        "name": "MySQL Honeypot",
        "description": "Fake MySQL database server logging all queries",
        "config": {
            "service": "mysql",
            "port": 3306,
            "banner": "5.7.42-0ubuntu0.18.04.1",
            "fake_databases": ["production", "customers", "billing", "hr_data"],
            "fake_tables": {
                "customers": ["users", "credit_cards", "orders"],
                "hr_data": ["employees", "salaries", "ssn_records"],
            },
            "capture": "full_interaction",
            "fake_creds": [
                {"username": "dbadmin", "password": "mysql@dm1n"},
            ],
        },
    },
    {
        "asset_type": "canary_token",
        "name": "AWS Key Canary",
        "description": "Fake AWS_ACCESS_KEY_ID planted in config files and environment variables",
        "config": {
            "token_type": "aws_key",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "plant_locations": [".env", ".aws/credentials", "docker-compose.yml"],
        },
    },
    {
        "asset_type": "canary_token",
        "name": "API Key Canary",
        "description": "Fake API key planted in configuration files",
        "config": {
            "token_type": "api_key",
            "api_key": f"sk-aither-{secrets.token_hex(24)}",
            "plant_locations": ["config.yaml", ".env.production", "settings.json"],
            "service_label": "Aither Platform API",
        },
    },
    {
        "asset_type": "canary_token",
        "name": "Document Canary - Salary Review 2026",
        "description": "Fake salary spreadsheet that alerts on open",
        "config": {
            "token_type": "document",
            "filename": "Salary_Review_2026.xlsx",
            "file_format": "xlsx",
            "tracking_pixel": True,
            "macro_beacon": True,
            "plant_locations": ["\\\\fileserver\\HR\\Compensation\\"],
        },
    },
    {
        "asset_type": "canary_token",
        "name": "DNS Canary",
        "description": "Unique subdomain that alerts when DNS resolution is attempted",
        "config": {
            "token_type": "dns",
            "subdomain": f"canary-{secrets.token_hex(8)}.internal.aither.local",
            "resolution_alert": True,
            "plant_locations": ["hosts file entries", "internal wiki links", "shared docs"],
        },
    },
    {
        "asset_type": "breadcrumb",
        "name": "Breadcrumb Trail",
        "description": "Fake credentials scattered in memory, registry, and temp files to lure attackers",
        "config": {
            "breadcrumb_type": "credential_trail",
            "items": [
                {"type": "registry_key", "path": "HKLM\\SOFTWARE\\AitherBackup\\Credentials", "username": "backup_svc", "password": "B@ckup2026!"},
                {"type": "memory_artifact", "process": "lsass.exe", "username": "domain_admin", "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee"},
                {"type": "temp_file", "path": "C:\\Users\\admin\\AppData\\Local\\Temp\\vpn_creds.txt", "content": "vpn.aither.com|admin|Vpn$ecure1"},
                {"type": "browser_saved", "url": "https://admin.aither.com", "username": "superadmin", "password": "Sup3r@dmin!"},
                {"type": "env_variable", "name": "DB_PASSWORD", "value": "Pr0duct10n_DB_2026!"},
            ],
            "trail_leads_to": "honeypot_ssh",
        },
    },
]

# MITRE ATT&CK technique mapping for observed behaviors
MITRE_TTP_MAP: Dict[str, Dict[str, str]] = {
    "ssh_brute_force": {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "rdp_brute_force": {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "credential_stuffing": {"id": "T1110.004", "name": "Brute Force: Credential Stuffing", "tactic": "Credential Access"},
    "port_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "smb_enumeration": {"id": "T1135", "name": "Network Share Discovery", "tactic": "Discovery"},
    "sql_injection": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "xss_attempt": {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
    "file_exfiltration": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "lateral_movement": {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    "privilege_escalation": {"id": "T1078", "name": "Valid Accounts", "tactic": "Privilege Escalation"},
    "command_execution": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "data_staging": {"id": "T1074", "name": "Data Staged", "tactic": "Collection"},
    "credential_dumping": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    "registry_query": {"id": "T1012", "name": "Query Registry", "tactic": "Discovery"},
    "dns_resolution": {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
    "data_upload": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
}


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class DynamicDeceptionService:
    """
    Dynamic Honeypot & Canary Deployment Engine.

    Auto-deploys deception assets based on real-time threat scoring.
    When an IP/user crosses a risk threshold, the engine dynamically
    redirects them to honeypots, plants breadcrumbs, and captures
    full attacker intelligence for SOC analysis.

    Integrates with:
    - Canary Trap (existing deception layer)
    - IP Sentinel (threat intelligence feeds)
    - Kill Switch (emergency isolation)
    - Pattern of Life (behavioral baselines)
    - SOAR Playbook (automated response)
    """

    def __init__(self, db: "Session | None" = None):
        self.db = db
        self._use_db = ORM_AVAILABLE and db is not None
        # In-memory fallback stores
        self._assets: Dict[str, DeceptionAsset] = {}
        self._honeypots: Dict[str, HoneypotService] = {}
        self._tokens: Dict[str, CanaryToken] = {}
        self._rules: Dict[str, DeceptionRule] = {}
        self._interactions: Dict[str, InteractionLog] = {}
        self._reports: Dict[str, IntelligenceReport] = {}
        # Token value index for fast lookups
        self._token_index: Dict[str, str] = {}  # token_value -> token_id
        # Redirect table: source_ip -> honeypot_id
        self._redirects: Dict[str, str] = {}
        self._initialized = False
        self._initialize()

    def _initialize(self):
        """Initialize the service and seed pre-built assets if empty."""
        if self._use_db:
            try:
                count = self.db.query(DeceptionAssetModel).count()
                if count == 0:
                    self._seed_prebuilt_assets()
            except Exception as exc:
                logger.warning("DB init check failed, using in-memory: %s", exc)
                self._use_db = False
        if not self._assets and not self._use_db:
            self._seed_prebuilt_assets()
        self._initialized = True
        logger.info("DynamicDeceptionService initialized (db=%s)", self._use_db)

    def _seed_prebuilt_assets(self):
        """Seed the 10 pre-built deception assets."""
        for tpl in PREBUILT_ASSETS:
            self.create_asset(
                asset_type=tpl["asset_type"],
                name=tpl["name"],
                description=tpl["description"],
                config=tpl["config"],
            )

    # ==================== Asset CRUD ====================

    def create_asset(
        self,
        asset_type: str,
        name: str,
        description: str = "",
        deployment_target: str = "",
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new deception asset."""
        asset_id = f"DA-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(timezone.utc)
        if self._use_db:
            try:
                row = DeceptionAssetModel(
                    asset_id=asset_id,
                    asset_type=asset_type,
                    name=name,
                    description=description,
                    deployment_target=deployment_target,
                    config=config or {},
                    status="staged",
                    created_at=now,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
                return self._asset_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB create_asset failed: %s", exc)
        asset = DeceptionAsset(
            asset_id=asset_id,
            asset_type=asset_type,
            name=name,
            description=description,
            deployment_target=deployment_target,
            config=config or {},
            created_at=now,
        )
        self._assets[asset_id] = asset
        return self._asset_to_dict(asset)

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get a deception asset by ID."""
        if self._use_db:
            try:
                row = self.db.query(DeceptionAssetModel).filter(DeceptionAssetModel.asset_id == asset_id).first()
                return self._asset_row_to_dict(row) if row else None
            except Exception:
                pass
        a = self._assets.get(asset_id)
        return self._asset_to_dict(a) if a else None

    def list_assets(self, asset_type: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List deception assets with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(DeceptionAssetModel)
                if asset_type:
                    q = q.filter(DeceptionAssetModel.asset_type == asset_type)
                if status:
                    q = q.filter(DeceptionAssetModel.status == status)
                return [self._asset_row_to_dict(r) for r in q.all()]
            except Exception:
                pass
        results = list(self._assets.values())
        if asset_type:
            results = [a for a in results if a.asset_type == asset_type]
        if status:
            results = [a for a in results if a.status == status]
        return [self._asset_to_dict(a) for a in results]

    def update_asset(self, asset_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update an existing deception asset."""
        allowed = {"name", "description", "deployment_target", "config", "status"}
        if self._use_db:
            try:
                row = self.db.query(DeceptionAssetModel).filter(DeceptionAssetModel.asset_id == asset_id).first()
                if not row:
                    return None
                for k, v in updates.items():
                    if k in allowed:
                        setattr(row, k, v)
                self.db.commit()
                self.db.refresh(row)
                return self._asset_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB update_asset failed: %s", exc)
        a = self._assets.get(asset_id)
        if not a:
            return None
        for k, v in updates.items():
            if k in allowed and hasattr(a, k):
                setattr(a, k, v)
        return self._asset_to_dict(a)

    def retire_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retire a deception asset."""
        return self.update_asset(asset_id, {"status": "retired"})

    # ==================== Deployment ====================

    def deploy_asset(self, asset_id: str, target: str = "") -> Optional[Dict[str, Any]]:
        """Deploy (activate) a deception asset to its target."""
        now = datetime.now(timezone.utc)
        if self._use_db:
            try:
                row = self.db.query(DeceptionAssetModel).filter(DeceptionAssetModel.asset_id == asset_id).first()
                if not row:
                    return None
                row.status = "deployed"
                row.deployed_at = now
                if target:
                    row.deployment_target = target
                self.db.commit()
                self.db.refresh(row)
                logger.info("Deployed deception asset %s -> %s", asset_id, target or row.deployment_target)
                return self._asset_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB deploy_asset failed: %s", exc)
        a = self._assets.get(asset_id)
        if not a:
            return None
        a.status = "deployed"
        a.deployed_at = now
        if target:
            a.deployment_target = target
        logger.info("Deployed deception asset %s -> %s", asset_id, target or a.deployment_target)
        return self._asset_to_dict(a)

    def undeploy_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Undeploy (deactivate) a deception asset."""
        return self.update_asset(asset_id, {"status": "staged"})

    # ==================== Honeypot Services ====================

    def create_honeypot_service(
        self,
        asset_id: str,
        service_type: str,
        listen_port: int,
        listen_ip: str = "0.0.0.0",
        banner: str = "",
        credentials: Optional[List[Dict[str, str]]] = None,
        response_templates: Optional[Dict[str, Any]] = None,
        capture_level: str = "auth_capture",
        max_sessions: int = 10,
    ) -> Dict[str, Any]:
        """Create a honeypot service bound to an asset."""
        honeypot_id = f"HP-{uuid.uuid4().hex[:12].upper()}"
        if self._use_db:
            try:
                row = HoneypotServiceModel(
                    honeypot_id=honeypot_id,
                    asset_id=asset_id,
                    service_type=service_type,
                    listen_port=listen_port,
                    listen_ip=listen_ip,
                    banner=banner,
                    credentials=credentials or [],
                    response_templates=response_templates or {},
                    capture_level=capture_level,
                    max_sessions=max_sessions,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
                return self._honeypot_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB create_honeypot_service failed: %s", exc)
        hp = HoneypotService(
            honeypot_id=honeypot_id,
            asset_id=asset_id,
            service_type=service_type,
            listen_port=listen_port,
            listen_ip=listen_ip,
            banner=banner,
            credentials=credentials or [],
            response_templates=response_templates or {},
            capture_level=capture_level,
            max_sessions=max_sessions,
        )
        self._honeypots[honeypot_id] = hp
        return self._honeypot_to_dict(hp)

    def list_honeypot_services(self, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List honeypot services, optionally filtered by asset."""
        if self._use_db:
            try:
                q = self.db.query(HoneypotServiceModel)
                if asset_id:
                    q = q.filter(HoneypotServiceModel.asset_id == asset_id)
                return [self._honeypot_row_to_dict(r) for r in q.all()]
            except Exception:
                pass
        results = list(self._honeypots.values())
        if asset_id:
            results = [h for h in results if h.asset_id == asset_id]
        return [self._honeypot_to_dict(h) for h in results]

    # ==================== Canary Tokens ====================

    def create_canary_token(
        self,
        asset_id: str,
        token_type: str,
        deployment_location: str = "",
        trigger_webhook: str = "",
    ) -> Dict[str, Any]:
        """Create and plant a canary token."""
        token_id = f"CT-{uuid.uuid4().hex[:12].upper()}"
        # Generate a realistic-looking token value based on type
        token_value = self._generate_token_value(token_type)
        if self._use_db:
            try:
                row = CanaryTokenDBModel(
                    token_id=token_id,
                    asset_id=asset_id,
                    token_type=token_type,
                    token_value=token_value,
                    deployment_location=deployment_location,
                    trigger_webhook=trigger_webhook,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
                return self._token_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB create_canary_token failed: %s", exc)
        ct = CanaryToken(
            token_id=token_id,
            asset_id=asset_id,
            token_type=token_type,
            token_value=token_value,
            deployment_location=deployment_location,
            trigger_webhook=trigger_webhook,
        )
        self._tokens[token_id] = ct
        self._token_index[token_value] = token_id
        return self._token_to_dict(ct)

    def check_token(self, token_value: str) -> Optional[Dict[str, Any]]:
        """Check if a token value matches a canary token (returns alert if triggered)."""
        if self._use_db:
            try:
                row = self.db.query(CanaryTokenDBModel).filter(CanaryTokenDBModel.token_value == token_value).first()
                if row:
                    return {"triggered": True, "token_id": row.token_id, "token_type": row.token_type, "asset_id": row.asset_id}
                return None
            except Exception:
                pass
        tid = self._token_index.get(token_value)
        if tid and tid in self._tokens:
            ct = self._tokens[tid]
            return {"triggered": True, "token_id": ct.token_id, "token_type": ct.token_type, "asset_id": ct.asset_id}
        return None

    def record_token_trigger(self, token_id: str, source_ip: str, source_user: str = "") -> Optional[Dict[str, Any]]:
        """Record that a canary token was triggered."""
        now = datetime.now(timezone.utc)
        trigger_info = {"source_ip": source_ip, "source_user": source_user, "timestamp": now.isoformat()}
        if self._use_db:
            try:
                row = self.db.query(CanaryTokenDBModel).filter(CanaryTokenDBModel.token_id == token_id).first()
                if not row:
                    return None
                row.triggered_count = (row.triggered_count or 0) + 1
                row.last_triggered_at = now
                triggered = list(row.triggered_by or [])
                triggered.append(trigger_info)
                row.triggered_by = triggered
                self.db.commit()
                self.db.refresh(row)
                logger.warning("CANARY TOKEN TRIGGERED: %s by %s from %s", token_id, source_user, source_ip)
                return self._token_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB record_token_trigger failed: %s", exc)
        ct = self._tokens.get(token_id)
        if not ct:
            return None
        ct.triggered_count += 1
        ct.last_triggered_at = now
        ct.triggered_by.append(trigger_info)
        logger.warning("CANARY TOKEN TRIGGERED: %s by %s from %s", token_id, source_user, source_ip)
        return self._token_to_dict(ct)

    def _generate_token_value(self, token_type: str) -> str:
        """Generate a realistic-looking token value."""
        if token_type == "aws_key":
            return f"AKIA{secrets.token_hex(8).upper()}"
        elif token_type == "api_key":
            return f"sk-aither-{secrets.token_hex(24)}"
        elif token_type == "database_cred":
            return f"postgres://dbuser:{secrets.token_hex(12)}@db.internal:5432/production"
        elif token_type == "dns":
            return f"canary-{secrets.token_hex(8)}.internal.aither.local"
        elif token_type == "url":
            return f"https://api.aither.internal/v1/health?token={secrets.token_hex(16)}"
        elif token_type == "email":
            return f"alert-{secrets.token_hex(4)}@canary.aither.local"
        elif token_type == "registry_key":
            return f"HKLM\\SOFTWARE\\AitherCanary\\{secrets.token_hex(8)}"
        elif token_type == "env_variable":
            return f"AITHER_SECRET_{secrets.token_hex(6).upper()}={secrets.token_hex(16)}"
        else:
            return f"canary-{secrets.token_hex(16)}"

    # ==================== Rules ====================

    def create_rule(
        self,
        name: str,
        action: str,
        risk_threshold: float = 7.0,
        description: str = "",
        trigger_condition: Optional[Dict[str, Any]] = None,
        target_entity_type: str = "ip",
        deception_asset_id: Optional[str] = None,
        cooldown_minutes: int = 60,
    ) -> Dict[str, Any]:
        """Create an automated deception rule."""
        rule_id = f"DR-{uuid.uuid4().hex[:12].upper()}"
        if self._use_db:
            try:
                row = DeceptionRuleModel(
                    rule_id=rule_id,
                    name=name,
                    description=description,
                    trigger_condition=trigger_condition or {},
                    risk_threshold=risk_threshold,
                    target_entity_type=target_entity_type,
                    action=action,
                    deception_asset_id=deception_asset_id,
                    cooldown_minutes=cooldown_minutes,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
                return self._rule_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB create_rule failed: %s", exc)
        rule = DeceptionRule(
            rule_id=rule_id,
            name=name,
            description=description,
            trigger_condition=trigger_condition or {},
            risk_threshold=risk_threshold,
            target_entity_type=target_entity_type,
            action=action,
            deception_asset_id=deception_asset_id,
            cooldown_minutes=cooldown_minutes,
        )
        self._rules[rule_id] = rule
        return self._rule_to_dict(rule)

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update an existing deception rule."""
        allowed = {"name", "description", "trigger_condition", "risk_threshold",
                    "target_entity_type", "action", "deception_asset_id", "cooldown_minutes", "is_enabled"}
        if self._use_db:
            try:
                row = self.db.query(DeceptionRuleModel).filter(DeceptionRuleModel.rule_id == rule_id).first()
                if not row:
                    return None
                for k, v in updates.items():
                    if k in allowed:
                        setattr(row, k, v)
                self.db.commit()
                self.db.refresh(row)
                return self._rule_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB update_rule failed: %s", exc)
        rule = self._rules.get(rule_id)
        if not rule:
            return None
        for k, v in updates.items():
            if k in allowed and hasattr(rule, k):
                setattr(rule, k, v)
        return self._rule_to_dict(rule)

    def list_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """List deception rules."""
        if self._use_db:
            try:
                q = self.db.query(DeceptionRuleModel)
                if enabled_only:
                    q = q.filter(DeceptionRuleModel.is_enabled.is_(True))
                return [self._rule_row_to_dict(r) for r in q.all()]
            except Exception:
                pass
        results = list(self._rules.values())
        if enabled_only:
            results = [r for r in results if r.is_enabled]
        return [self._rule_to_dict(r) for r in results]

    def toggle_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Toggle a rule's enabled state."""
        if self._use_db:
            try:
                row = self.db.query(DeceptionRuleModel).filter(DeceptionRuleModel.rule_id == rule_id).first()
                if not row:
                    return None
                row.is_enabled = not row.is_enabled
                self.db.commit()
                self.db.refresh(row)
                return self._rule_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB toggle_rule failed: %s", exc)
        rule = self._rules.get(rule_id)
        if not rule:
            return None
        rule.is_enabled = not rule.is_enabled
        return self._rule_to_dict(rule)

    # ==================== Dynamic Threat Evaluation ====================

    def evaluate_threat_and_deploy(
        self,
        entity_type: str,
        entity_value: str,
        threat_score: float,
    ) -> Dict[str, Any]:
        """
        Evaluate a threat score and automatically deploy deception assets.

        When the score crosses a rule's threshold, the configured action fires:
        - deploy_honeypot: spin up a new honeypot targeting the entity
        - redirect_to_honeypot: route the entity's traffic to an existing honeypot
        - plant_canary: scatter canary tokens in the entity's path
        - enable_full_capture: upgrade an existing asset to full interaction capture
        - alert_soc: log a high-priority alert for SOC review
        """
        actions_taken: List[Dict[str, Any]] = []
        rules = self.list_rules(enabled_only=True)

        for rule_dict in rules:
            threshold = rule_dict.get("risk_threshold", 7.0)
            rule_entity = rule_dict.get("target_entity_type", "ip")
            action = rule_dict.get("action", "alert_soc")
            rule_id = rule_dict["rule_id"]

            if threat_score < threshold:
                continue
            if rule_entity != entity_type and rule_entity != "any":
                continue

            # Cooldown check
            last_exec = rule_dict.get("last_executed_at")
            cooldown = rule_dict.get("cooldown_minutes", 60)
            if last_exec:
                if isinstance(last_exec, str):
                    try:
                        last_exec = datetime.fromisoformat(last_exec)
                    except Exception:
                        last_exec = None
                if last_exec and (datetime.now(timezone.utc) - last_exec).total_seconds() < cooldown * 60:
                    continue

            # Execute action
            result = self._execute_rule_action(action, entity_type, entity_value, threat_score, rule_dict)
            actions_taken.append({
                "rule_id": rule_id,
                "rule_name": rule_dict.get("name", ""),
                "action": action,
                "result": result,
            })

            # Update execution count
            self._record_rule_execution(rule_id)

        return {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "threat_score": threat_score,
            "rules_evaluated": len(rules),
            "actions_taken": actions_taken,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _execute_rule_action(
        self, action: str, entity_type: str, entity_value: str, threat_score: float, rule: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a specific rule action."""
        if action == "deploy_honeypot":
            asset = self.create_asset(
                asset_type="honeypot",
                name=f"Auto-HP-{entity_value[:20]}",
                description=f"Auto-deployed honeypot for {entity_type}={entity_value} (score={threat_score})",
                config={"trigger_score": threat_score, "target_entity": entity_value},
            )
            self.deploy_asset(asset["asset_id"], target=entity_value)
            return {"deployed_asset_id": asset["asset_id"]}

        elif action == "redirect_to_honeypot":
            asset_id = rule.get("deception_asset_id")
            if asset_id:
                self._redirect_to_honeypot(entity_value, asset_id)
                return {"redirected_to": asset_id, "source": entity_value}
            # If no specific asset, find first active honeypot
            active = self.list_assets(asset_type="honeypot", status="deployed")
            if active:
                target = active[0]["asset_id"]
                self._redirect_to_honeypot(entity_value, target)
                return {"redirected_to": target, "source": entity_value}
            return {"error": "no_honeypot_available"}

        elif action == "plant_canary":
            return self._plant_breadcrumbs(entity_value)

        elif action == "enable_full_capture":
            asset_id = rule.get("deception_asset_id")
            if asset_id:
                self.update_asset(asset_id, {"config": {"capture_level": "full_interaction", "target": entity_value}})
                return {"full_capture_enabled": asset_id}
            return {"error": "no_asset_specified"}

        elif action == "alert_soc":
            logger.critical(
                "SOC ALERT: High-threat %s=%s (score=%.1f) — deception recommended",
                entity_type, entity_value, threat_score,
            )
            return {"alert_sent": True, "severity": "critical" if threat_score >= 9.0 else "high"}

        return {"error": f"unknown_action: {action}"}

    def _redirect_to_honeypot(self, source_ip: str, honeypot_asset_id: str):
        """Register a redirect from source IP to a honeypot asset."""
        self._redirects[source_ip] = honeypot_asset_id
        logger.warning("REDIRECT: %s -> honeypot %s", source_ip, honeypot_asset_id)

    def _plant_breadcrumbs(self, target_network: str) -> Dict[str, Any]:
        """Plant breadcrumb trails in a target network segment."""
        planted = []
        breadcrumb_types = ["registry_key", "env_variable", "temp_file", "browser_saved"]
        for bt in breadcrumb_types:
            token = self.create_canary_token(
                asset_id=f"breadcrumb-{target_network[:20]}",
                token_type=bt,
                deployment_location=target_network,
            )
            planted.append(token["token_id"])
        logger.info("Planted %d breadcrumbs in network %s", len(planted), target_network)
        return {"breadcrumbs_planted": len(planted), "token_ids": planted, "target": target_network}

    def _record_rule_execution(self, rule_id: str):
        """Increment execution counter and record last execution time."""
        now = datetime.now(timezone.utc)
        if self._use_db:
            try:
                row = self.db.query(DeceptionRuleModel).filter(DeceptionRuleModel.rule_id == rule_id).first()
                if row:
                    row.executions = (row.executions or 0) + 1
                    row.last_executed_at = now
                    self.db.commit()
                    return
            except Exception as exc:
                self.db.rollback()
                logger.error("DB _record_rule_execution failed: %s", exc)
        rule = self._rules.get(rule_id)
        if rule:
            rule.executions += 1

    # ==================== Interaction Recording ====================

    def record_interaction(
        self,
        asset_id: str,
        source_ip: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Record an attacker interaction with a deception asset."""
        log_id = f"IL-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(timezone.utc)
        interaction_type = data.get("interaction_type", "connection")
        commands = data.get("commands_executed", [])
        files = data.get("files_accessed", [])
        creds = data.get("credentials_used", "")
        duration = data.get("duration_seconds", 0.0)
        intel_value = self._assess_intelligence_value(data)

        if self._use_db:
            try:
                row = InteractionLogModel(
                    log_id=log_id,
                    asset_id=asset_id,
                    source_ip=source_ip,
                    source_user=data.get("source_user", ""),
                    interaction_type=interaction_type,
                    raw_data=data,
                    credentials_used=creds,
                    commands_executed=commands,
                    files_accessed=files,
                    duration_seconds=duration,
                    intelligence_value=intel_value,
                    timestamp=now,
                )
                self.db.add(row)
                # Update parent asset
                asset = self.db.query(DeceptionAssetModel).filter(DeceptionAssetModel.asset_id == asset_id).first()
                if asset:
                    asset.interaction_count = (asset.interaction_count or 0) + 1
                    asset.last_interaction_at = now
                    if asset.status == "deployed":
                        asset.status = "active"
                self.db.commit()
                self.db.refresh(row)
                return self._interaction_row_to_dict(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB record_interaction failed: %s", exc)

        log = InteractionLog(
            log_id=log_id,
            asset_id=asset_id,
            source_ip=source_ip,
            source_user=data.get("source_user", ""),
            interaction_type=interaction_type,
            raw_data=data,
            credentials_used=creds,
            commands_executed=commands,
            files_accessed=files,
            duration_seconds=duration,
            intelligence_value=intel_value,
            timestamp=now,
        )
        self._interactions[log_id] = log
        # Update in-memory asset
        a = self._assets.get(asset_id)
        if a:
            a.interaction_count += 1
            a.last_interaction_at = now
            if a.status == "deployed":
                a.status = "active"
        return self._interaction_to_dict(log)

    def _assess_intelligence_value(self, data: Dict[str, Any]) -> str:
        """Assess the intelligence value of an interaction."""
        score = 0
        if data.get("credentials_used"):
            score += 2
        if data.get("commands_executed"):
            score += len(data["commands_executed"])
        if data.get("files_accessed"):
            score += len(data["files_accessed"])
        if data.get("interaction_type") in ("command", "data_upload", "file_access"):
            score += 3
        if data.get("duration_seconds", 0) > 300:
            score += 2
        if score >= 8:
            return "critical"
        elif score >= 5:
            return "high"
        elif score >= 2:
            return "medium"
        return "low"

    # ==================== Intelligence ====================

    def generate_intelligence_report(self, asset_id: str) -> Dict[str, Any]:
        """Generate a full intelligence report from interactions with an asset."""
        report_id = f"IR-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(timezone.utc)

        # Gather interactions
        interactions = self._get_interactions_for_asset(asset_id)
        if not interactions:
            return {"error": "no_interactions_found", "asset_id": asset_id}

        iocs = self._extract_iocs(interactions)
        ttps = self._analyze_ttps(interactions)
        profile = self._profile_attacker(interactions)

        findings = {
            "total_interactions": len(interactions),
            "unique_source_ips": len(set(i.get("source_ip", "") for i in interactions)),
            "time_span": self._calc_time_span(interactions),
            "interaction_types": dict(Counter(i.get("interaction_type", "unknown") for i in interactions)),
            "intelligence_values": dict(Counter(i.get("intelligence_value", "low") for i in interactions)),
        }

        report_data = {
            "report_id": report_id,
            "asset_id": asset_id,
            "report_type": "ttp_analysis",
            "title": f"Intelligence Report - Asset {asset_id}",
            "findings": findings,
            "iocs_extracted": iocs,
            "ttps_observed": ttps,
            "attacker_profile": profile,
            "generated_at": now.isoformat(),
        }

        if self._use_db:
            try:
                row = IntelligenceReportModel(
                    report_id=report_id,
                    asset_id=asset_id,
                    report_type="ttp_analysis",
                    title=report_data["title"],
                    findings=findings,
                    iocs_extracted=iocs,
                    ttps_observed=ttps,
                    attacker_profile=profile,
                    generated_at=now,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB generate_intelligence_report failed: %s", exc)
        else:
            report = IntelligenceReport(
                report_id=report_id,
                asset_id=asset_id,
                report_type="ttp_analysis",
                title=report_data["title"],
                findings=findings,
                iocs_extracted=iocs,
                ttps_observed=ttps,
                attacker_profile=profile,
                generated_at=now,
            )
            self._reports[report_id] = report

        return report_data

    def _get_interactions_for_asset(self, asset_id: str) -> List[Dict[str, Any]]:
        """Get all interactions for an asset."""
        if self._use_db:
            try:
                rows = self.db.query(InteractionLogModel).filter(
                    InteractionLogModel.asset_id == asset_id
                ).order_by(InteractionLogModel.timestamp).all()
                return [self._interaction_row_to_dict(r) for r in rows]
            except Exception:
                pass
        return [self._interaction_to_dict(i) for i in self._interactions.values() if i.asset_id == asset_id]

    def _extract_iocs(self, interactions: List[Dict[str, Any]]) -> List[str]:
        """Extract Indicators of Compromise from interactions."""
        iocs = set()
        for i in interactions:
            ip = i.get("source_ip", "")
            if ip:
                iocs.add(f"ip:{ip}")
            creds = i.get("credentials_used", "")
            if creds:
                iocs.add(f"credential:{hashlib.sha256(creds.encode()).hexdigest()[:16]}")
            for cmd in i.get("commands_executed", []):
                # Extract domains, IPs, hashes from commands
                if "wget " in cmd or "curl " in cmd:
                    iocs.add(f"command:{cmd[:80]}")
                if "powershell" in cmd.lower():
                    iocs.add(f"powershell_command:{hashlib.sha256(cmd.encode()).hexdigest()[:16]}")
            for f in i.get("files_accessed", []):
                iocs.add(f"file:{f}")
            raw = i.get("raw_data", {})
            ua = raw.get("user_agent", "")
            if ua:
                iocs.add(f"user_agent:{ua[:60]}")
        return sorted(iocs)

    def _analyze_ttps(self, interactions: List[Dict[str, Any]]) -> List[str]:
        """Map observed behaviors to MITRE ATT&CK TTPs."""
        ttps = set()
        for i in interactions:
            itype = i.get("interaction_type", "")
            raw = i.get("raw_data", {})
            commands = i.get("commands_executed", [])

            if itype == "auth_attempt":
                service = raw.get("service", "ssh")
                ttps.add(MITRE_TTP_MAP.get(f"{service}_brute_force", {}).get("id", "T1110"))
            if itype == "reconnaissance":
                ttps.add("T1046")  # Network Service Discovery
            if itype == "command":
                ttps.add("T1059")  # Command and Scripting Interpreter
                for cmd in commands:
                    if "net share" in cmd.lower() or "smbclient" in cmd.lower():
                        ttps.add("T1135")
                    if "reg query" in cmd.lower():
                        ttps.add("T1012")
                    if "mimikatz" in cmd.lower() or "sekurlsa" in cmd.lower():
                        ttps.add("T1003")
                    if "wget" in cmd.lower() or "curl" in cmd.lower() or "certutil" in cmd.lower():
                        ttps.add("T1105")
                    if "powershell" in cmd.lower():
                        ttps.add("T1059.001")
            if itype == "file_access":
                ttps.add("T1083")  # File and Directory Discovery
            if itype == "data_upload":
                ttps.add("T1105")  # Ingress Tool Transfer
            if raw.get("sql_injection"):
                ttps.add("T1190")
            if raw.get("xss_attempt"):
                ttps.add("T1189")

        return sorted(ttps)

    def _profile_attacker(self, interactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build an attacker profile from interaction data."""
        ips = [i.get("source_ip", "") for i in interactions if i.get("source_ip")]
        users = [i.get("source_user", "") for i in interactions if i.get("source_user")]
        creds = [i.get("credentials_used", "") for i in interactions if i.get("credentials_used")]
        types = [i.get("interaction_type", "") for i in interactions]

        # Determine sophistication level
        unique_commands = set()
        for i in interactions:
            for cmd in i.get("commands_executed", []):
                unique_commands.add(cmd)
        if len(unique_commands) > 20:
            sophistication = "advanced"
        elif len(unique_commands) > 5:
            sophistication = "intermediate"
        else:
            sophistication = "basic"

        # Determine intent
        has_exfil = any(t == "data_upload" for t in types)
        has_recon = any(t == "reconnaissance" for t in types)
        has_cred = any(t == "auth_attempt" for t in types)
        if has_exfil:
            likely_intent = "data_theft"
        elif has_cred and len(set(creds)) > 3:
            likely_intent = "credential_harvesting"
        elif has_recon:
            likely_intent = "reconnaissance"
        else:
            likely_intent = "unknown"

        total_duration = sum(i.get("duration_seconds", 0) for i in interactions)

        return {
            "source_ips": list(set(ips)),
            "usernames_tried": list(set(users)),
            "credentials_attempted": len(set(creds)),
            "sophistication": sophistication,
            "likely_intent": likely_intent,
            "unique_commands": len(unique_commands),
            "total_session_duration_seconds": total_duration,
            "first_seen": min((i.get("timestamp", "") for i in interactions), default=""),
            "last_seen": max((i.get("timestamp", "") for i in interactions), default=""),
            "interaction_count": len(interactions),
        }

    def _calc_time_span(self, interactions: List[Dict[str, Any]]) -> str:
        """Calculate time span of interactions."""
        timestamps = []
        for i in interactions:
            ts = i.get("timestamp", "")
            if ts:
                if isinstance(ts, str):
                    try:
                        timestamps.append(datetime.fromisoformat(ts))
                    except Exception:
                        pass
                elif isinstance(ts, datetime):
                    timestamps.append(ts)
        if len(timestamps) < 2:
            return "single_event"
        delta = max(timestamps) - min(timestamps)
        hours = delta.total_seconds() / 3600
        if hours < 1:
            return f"{int(delta.total_seconds() / 60)} minutes"
        elif hours < 24:
            return f"{hours:.1f} hours"
        return f"{hours / 24:.1f} days"

    # ==================== Analytics ====================

    def get_most_triggered_assets(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get assets with the most interactions."""
        if self._use_db:
            try:
                rows = self.db.query(DeceptionAssetModel).filter(
                    DeceptionAssetModel.interaction_count > 0
                ).order_by(DeceptionAssetModel.interaction_count.desc()).limit(limit).all()
                return [self._asset_row_to_dict(r) for r in rows]
            except Exception:
                pass
        sorted_assets = sorted(self._assets.values(), key=lambda a: a.interaction_count, reverse=True)
        return [self._asset_to_dict(a) for a in sorted_assets[:limit] if a.interaction_count > 0]

    def get_attacker_origins(self) -> Dict[str, int]:
        """Get count of interactions by source IP."""
        if self._use_db:
            try:
                rows = self.db.query(InteractionLogModel.source_ip).all()
                counter = Counter(r.source_ip for r in rows if r.source_ip)
                return dict(counter.most_common(50))
            except Exception:
                pass
        counter = Counter(i.source_ip for i in self._interactions.values() if i.source_ip)
        return dict(counter.most_common(50))

    def get_credential_attempts(self) -> List[Dict[str, Any]]:
        """Get all credential attempts across deception assets."""
        if self._use_db:
            try:
                rows = self.db.query(InteractionLogModel).filter(
                    InteractionLogModel.interaction_type == "auth_attempt"
                ).order_by(InteractionLogModel.timestamp.desc()).limit(100).all()
                return [self._interaction_row_to_dict(r) for r in rows]
            except Exception:
                pass
        results = [i for i in self._interactions.values() if i.interaction_type == "auth_attempt"]
        results.sort(key=lambda x: x.timestamp, reverse=True)
        return [self._interaction_to_dict(i) for i in results[:100]]

    def get_deception_coverage(self, client_id: str = "") -> Dict[str, Any]:
        """Get deception coverage metrics."""
        assets = self.list_assets()
        active = [a for a in assets if a.get("status") in ("deployed", "active")]
        triggered = [a for a in assets if a.get("status") == "triggered"]
        by_type = Counter(a.get("asset_type", "") for a in assets)
        return {
            "client_id": client_id,
            "total_assets": len(assets),
            "active_assets": len(active),
            "triggered_assets": len(triggered),
            "assets_by_type": dict(by_type),
            "coverage_score": min(100.0, len(active) * 10.0),
            "honeypots_deployed": by_type.get("honeypot", 0),
            "canary_tokens_planted": by_type.get("canary_token", 0),
            "breadcrumbs_active": by_type.get("breadcrumb", 0),
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Get full deception dashboard data."""
        assets = self.list_assets()
        rules = self.list_rules()
        coverage = self.get_deception_coverage()
        origins = self.get_attacker_origins()
        most_triggered = self.get_most_triggered_assets(limit=5)

        total_interactions = 0
        if self._use_db:
            try:
                total_interactions = self.db.query(InteractionLogModel).count()
            except Exception:
                pass
        else:
            total_interactions = len(self._interactions)

        active_redirects = len(self._redirects)

        return {
            "summary": {
                "total_assets": len(assets),
                "active_assets": len([a for a in assets if a.get("status") in ("deployed", "active")]),
                "total_rules": len(rules),
                "enabled_rules": len([r for r in rules if r.get("is_enabled")]),
                "total_interactions": total_interactions,
                "active_redirects": active_redirects,
            },
            "coverage": coverage,
            "most_triggered_assets": most_triggered,
            "attacker_origins": origins,
            "asset_status_breakdown": dict(Counter(a.get("status", "unknown") for a in assets)),
            "asset_type_breakdown": dict(Counter(a.get("asset_type", "unknown") for a in assets)),
            "rules_summary": [
                {"rule_id": r["rule_id"], "name": r.get("name", ""), "action": r.get("action", ""), "executions": r.get("executions", 0)}
                for r in rules
            ],
        }

    # ==================== Serialization Helpers ====================

    @staticmethod
    def _asset_to_dict(a: DeceptionAsset) -> Dict[str, Any]:
        return {
            "asset_id": a.asset_id,
            "asset_type": a.asset_type,
            "name": a.name,
            "description": a.description,
            "deployment_target": a.deployment_target,
            "config": a.config,
            "status": a.status,
            "interaction_count": a.interaction_count,
            "last_interaction_at": a.last_interaction_at.isoformat() if a.last_interaction_at else None,
            "intelligence_gathered": a.intelligence_gathered,
            "deployed_at": a.deployed_at.isoformat() if a.deployed_at else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }

    @staticmethod
    def _asset_row_to_dict(r) -> Dict[str, Any]:
        return {
            "asset_id": r.asset_id,
            "asset_type": r.asset_type,
            "name": r.name,
            "description": r.description,
            "deployment_target": r.deployment_target,
            "config": r.config or {},
            "status": r.status,
            "interaction_count": r.interaction_count or 0,
            "last_interaction_at": r.last_interaction_at.isoformat() if r.last_interaction_at else None,
            "intelligence_gathered": r.intelligence_gathered or [],
            "deployed_at": r.deployed_at.isoformat() if r.deployed_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }

    @staticmethod
    def _honeypot_to_dict(h: HoneypotService) -> Dict[str, Any]:
        return {
            "honeypot_id": h.honeypot_id,
            "asset_id": h.asset_id,
            "service_type": h.service_type,
            "listen_port": h.listen_port,
            "listen_ip": h.listen_ip,
            "banner": h.banner,
            "credentials": h.credentials,
            "response_templates": h.response_templates,
            "capture_level": h.capture_level,
            "max_sessions": h.max_sessions,
        }

    @staticmethod
    def _honeypot_row_to_dict(r) -> Dict[str, Any]:
        return {
            "honeypot_id": r.honeypot_id,
            "asset_id": r.asset_id,
            "service_type": r.service_type,
            "listen_port": r.listen_port,
            "listen_ip": r.listen_ip,
            "banner": r.banner,
            "credentials": r.credentials or [],
            "response_templates": r.response_templates or {},
            "capture_level": r.capture_level,
            "max_sessions": r.max_sessions,
        }

    @staticmethod
    def _token_to_dict(ct: CanaryToken) -> Dict[str, Any]:
        return {
            "token_id": ct.token_id,
            "asset_id": ct.asset_id,
            "token_type": ct.token_type,
            "token_value": ct.token_value,
            "deployment_location": ct.deployment_location,
            "trigger_webhook": ct.trigger_webhook,
            "triggered_count": ct.triggered_count,
            "last_triggered_at": ct.last_triggered_at.isoformat() if ct.last_triggered_at else None,
            "triggered_by": ct.triggered_by,
        }

    @staticmethod
    def _token_row_to_dict(r) -> Dict[str, Any]:
        return {
            "token_id": r.token_id,
            "asset_id": r.asset_id,
            "token_type": r.token_type,
            "token_value": r.token_value,
            "deployment_location": r.deployment_location,
            "trigger_webhook": r.trigger_webhook,
            "triggered_count": r.triggered_count or 0,
            "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
            "triggered_by": r.triggered_by or [],
        }

    @staticmethod
    def _rule_to_dict(r: DeceptionRule) -> Dict[str, Any]:
        return {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "trigger_condition": r.trigger_condition,
            "risk_threshold": r.risk_threshold,
            "target_entity_type": r.target_entity_type,
            "action": r.action,
            "deception_asset_id": r.deception_asset_id,
            "cooldown_minutes": r.cooldown_minutes,
            "is_enabled": r.is_enabled,
            "executions": r.executions,
            "last_executed_at": None,
        }

    @staticmethod
    def _rule_row_to_dict(r) -> Dict[str, Any]:
        return {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "trigger_condition": r.trigger_condition or {},
            "risk_threshold": r.risk_threshold,
            "target_entity_type": r.target_entity_type,
            "action": r.action,
            "deception_asset_id": r.deception_asset_id,
            "cooldown_minutes": r.cooldown_minutes,
            "is_enabled": r.is_enabled,
            "executions": r.executions or 0,
            "last_executed_at": r.last_executed_at.isoformat() if r.last_executed_at else None,
        }

    @staticmethod
    def _interaction_to_dict(i: InteractionLog) -> Dict[str, Any]:
        return {
            "log_id": i.log_id,
            "asset_id": i.asset_id,
            "source_ip": i.source_ip,
            "source_user": i.source_user,
            "interaction_type": i.interaction_type,
            "raw_data": i.raw_data,
            "credentials_used": i.credentials_used,
            "commands_executed": i.commands_executed,
            "files_accessed": i.files_accessed,
            "duration_seconds": i.duration_seconds,
            "intelligence_value": i.intelligence_value,
            "timestamp": i.timestamp.isoformat() if i.timestamp else None,
        }

    @staticmethod
    def _interaction_row_to_dict(r) -> Dict[str, Any]:
        return {
            "log_id": r.log_id,
            "asset_id": r.asset_id,
            "source_ip": r.source_ip,
            "source_user": r.source_user,
            "interaction_type": r.interaction_type,
            "raw_data": r.raw_data or {},
            "credentials_used": r.credentials_used,
            "commands_executed": r.commands_executed or [],
            "files_accessed": r.files_accessed or [],
            "duration_seconds": r.duration_seconds or 0.0,
            "intelligence_value": r.intelligence_value,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
