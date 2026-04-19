"""
AITHER Platform - RMM Agent Communication Protocol Service

Defines the server-side protocol for RMM agent binary communication:
- Agent registration and authentication
- Heartbeat / check-in processing
- Command queue management
- Agent update distribution
- Configuration management
- Fleet dashboard statistics

G-46 pattern: DB persistence with in-memory fallback.
"""

import uuid
import secrets
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.agent_protocol import (
        RegisteredAgentModel,
        AgentCommandQueueModel,
        AgentUpdateModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class AgentStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    STALE = "stale"


class CommandType(str, Enum):
    SHELL = "shell"
    POWERSHELL = "powershell"
    SCRIPT = "script"
    UPDATE = "update"
    RESTART = "restart"
    UNINSTALL = "uninstall"
    COLLECT_LOGS = "collect_logs"
    RUN_SCAN = "run_scan"


class CommandPriority(str, Enum):
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class CommandQueueStatus(str, Enum):
    QUEUED = "queued"
    SENT = "sent"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class OSType(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class Architecture(str, Enum):
    X64 = "x64"
    X86 = "x86"
    ARM64 = "arm64"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class AgentRegistration:
    """Agent registration record."""
    agent_id: str
    endpoint_id: str
    hostname: str
    os_type: str           # windows/linux/macos
    os_version: str = ""
    arch: str = "x64"      # x64/x86/arm64
    agent_version: str = ""
    install_path: str = ""
    api_key_hash: str = ""
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_checkin: Optional[datetime] = None


@dataclass
class AgentCheckin:
    """Agent heartbeat check-in payload."""
    agent_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    system_metrics: Dict[str, Any] = field(default_factory=dict)
    running_services: List[str] = field(default_factory=list)
    installed_updates: List[str] = field(default_factory=list)
    pending_commands: List[Dict[str, Any]] = field(default_factory=list)
    agent_status: str = "healthy"


@dataclass
class AgentCommand:
    """Command queued for an agent."""
    command_id: str
    agent_id: str
    command_type: str       # shell/powershell/script/update/restart/uninstall/collect_logs/run_scan
    payload: Dict[str, Any] = field(default_factory=dict)
    priority: str = "normal"  # normal/high/urgent
    status: str = "queued"
    queued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


@dataclass
class AgentCommandResponse:
    """Result of a command execution from the agent."""
    command_id: str
    agent_id: str
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: int = 0
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AgentUpdate:
    """Available agent update."""
    version: str
    platform: str
    download_url: str
    checksum_sha256: str
    release_notes: str = ""
    is_mandatory: bool = False


@dataclass
class AgentConfig:
    """Runtime configuration pushed to agents."""
    checkin_interval_seconds: int = 60
    command_poll_interval_seconds: int = 15
    log_level: str = "info"
    features_enabled: List[str] = field(default_factory=lambda: ["metrics", "services", "updates"])
    proxy_config: Optional[Dict[str, str]] = None
    bandwidth_limit: Optional[int] = None  # bytes/sec, None = unlimited


# ============================================================
# Conversion helpers
# ============================================================

def _agent_from_row(row) -> AgentRegistration:
    return AgentRegistration(
        agent_id=row.agent_id,
        endpoint_id=row.endpoint_id,
        hostname=row.hostname,
        os_type=row.os_type,
        os_version=row.os_version or "",
        arch=row.arch or "x64",
        agent_version=row.agent_version or "",
        install_path=row.install_path or "",
        api_key_hash=row.api_key_hash,
        registered_at=row.registered_at or datetime.now(timezone.utc),
        last_checkin=row.last_checkin_at,
    )


def _command_from_row(row) -> AgentCommand:
    return AgentCommand(
        command_id=row.command_id,
        agent_id=row.agent_id,
        command_type=row.command_type,
        payload=row.payload or {},
        priority=row.priority or "normal",
        status=row.status or "queued",
        queued_at=row.queued_at or datetime.now(timezone.utc),
        expires_at=row.expires_at,
    )


def _hash_key(api_key: str) -> str:
    """SHA-256 hash of an API key."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _generate_api_key() -> str:
    """Generate a cryptographically secure API key."""
    return secrets.token_urlsafe(32)


# ============================================================
# Service
# ============================================================

class AgentProtocolService:
    """
    RMM Agent Communication Protocol - Server Side

    Handles agent registration, authentication, heartbeat processing,
    command queuing, update distribution, and fleet management.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._agents: Dict[str, AgentRegistration] = {}
        self._api_keys: Dict[str, str] = {}             # agent_id -> key_hash
        self._commands: Dict[str, AgentCommand] = {}     # command_id -> command
        self._configs: Dict[str, AgentConfig] = {}       # agent_id -> config
        self._updates: List[AgentUpdate] = []
        self._checkin_metrics: Dict[str, Dict] = {}      # agent_id -> latest metrics

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_agent(self, registration_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register a new agent. Generates an API key, stores its hash,
        and returns the plaintext key (once) plus default config.
        """
        agent_id = f"AGT-{uuid.uuid4().hex[:12].upper()}"
        api_key = _generate_api_key()
        key_hash = _hash_key(api_key)
        now = datetime.now(timezone.utc)

        hostname = registration_data.get("hostname", "unknown")
        os_type = registration_data.get("os_type", "windows")
        os_version = registration_data.get("os_version", "")
        arch = registration_data.get("arch", "x64")
        agent_version = registration_data.get("agent_version", "")
        install_path = registration_data.get("install_path", "")
        endpoint_id = registration_data.get("endpoint_id", f"EP-{uuid.uuid4().hex[:8].upper()}")

        default_config = AgentConfig()

        if self._use_db:
            try:
                row = RegisteredAgentModel(
                    agent_id=agent_id,
                    endpoint_id=endpoint_id,
                    hostname=hostname,
                    os_type=os_type,
                    os_version=os_version,
                    arch=arch,
                    agent_version=agent_version,
                    api_key_hash=key_hash,
                    install_path=install_path,
                    config={
                        "checkin_interval_seconds": default_config.checkin_interval_seconds,
                        "command_poll_interval_seconds": default_config.command_poll_interval_seconds,
                        "log_level": default_config.log_level,
                        "features_enabled": default_config.features_enabled,
                    },
                    status=AgentStatus.ACTIVE.value,
                    registered_at=now,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Agent %s registered (DB) for host %s", agent_id, hostname)
            except Exception as exc:
                self.db.rollback()
                logger.error("DB register_agent failed: %s — falling back", exc)
                self._store_agent_memory(agent_id, endpoint_id, hostname, os_type,
                                         os_version, arch, agent_version, install_path,
                                         key_hash, now, default_config)
        else:
            self._store_agent_memory(agent_id, endpoint_id, hostname, os_type,
                                     os_version, arch, agent_version, install_path,
                                     key_hash, now, default_config)

        return {
            "agent_id": agent_id,
            "endpoint_id": endpoint_id,
            "api_key": api_key,        # returned only once at registration
            "config": {
                "checkin_interval_seconds": default_config.checkin_interval_seconds,
                "command_poll_interval_seconds": default_config.command_poll_interval_seconds,
                "log_level": default_config.log_level,
                "features_enabled": default_config.features_enabled,
            },
        }

    def _store_agent_memory(self, agent_id, endpoint_id, hostname, os_type,
                            os_version, arch, agent_version, install_path,
                            key_hash, now, config):
        reg = AgentRegistration(
            agent_id=agent_id,
            endpoint_id=endpoint_id,
            hostname=hostname,
            os_type=os_type,
            os_version=os_version,
            arch=arch,
            agent_version=agent_version,
            install_path=install_path,
            api_key_hash=key_hash,
            registered_at=now,
        )
        self._agents[agent_id] = reg
        self._api_keys[agent_id] = key_hash
        self._configs[agent_id] = config

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate_agent(self, agent_id: str, api_key: str) -> bool:
        """Validate agent identity by comparing key hash."""
        key_hash = _hash_key(api_key)

        if self._use_db:
            try:
                row = (self.db.query(RegisteredAgentModel)
                       .filter_by(agent_id=agent_id, status=AgentStatus.ACTIVE.value)
                       .first())
                if row and row.api_key_hash == key_hash:
                    return True
                return False
            except Exception as exc:
                logger.error("DB authenticate_agent failed: %s", exc)

        # In-memory fallback
        stored = self._api_keys.get(agent_id)
        if stored and stored == key_hash:
            agent = self._agents.get(agent_id)
            if agent and agent_id in self._agents:
                return True
        return False

    # ------------------------------------------------------------------
    # Check-in / Heartbeat
    # ------------------------------------------------------------------

    def agent_checkin(self, agent_id: str, checkin_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process heartbeat from agent. Updates last-seen timestamp,
        stores metrics, and returns any pending commands.
        """
        now = datetime.now(timezone.utc)
        metrics = checkin_data.get("system_metrics", {})
        running_services = checkin_data.get("running_services", [])
        agent_status = checkin_data.get("agent_status", "healthy")

        if self._use_db:
            try:
                row = (self.db.query(RegisteredAgentModel)
                       .filter_by(agent_id=agent_id)
                       .first())
                if row:
                    row.last_checkin_at = now
                    row.status = AgentStatus.ACTIVE.value
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.error("DB agent_checkin failed: %s", exc)

        # In-memory update
        if agent_id in self._agents:
            self._agents[agent_id].last_checkin = now

        self._checkin_metrics[agent_id] = {
            "system_metrics": metrics,
            "running_services": running_services,
            "agent_status": agent_status,
            "timestamp": now.isoformat(),
        }

        pending = self.get_pending_commands(agent_id)
        return {
            "status": "ok",
            "server_time": now.isoformat(),
            "pending_commands": [self._command_to_dict(c) for c in pending],
        }

    # ------------------------------------------------------------------
    # Command Queue
    # ------------------------------------------------------------------

    def get_pending_commands(self, agent_id: str) -> List[AgentCommand]:
        """Return queued commands for an agent, ordered by priority."""
        priority_order = {"urgent": 0, "high": 1, "normal": 2}
        now = datetime.now(timezone.utc)

        if self._use_db:
            try:
                rows = (self.db.query(AgentCommandQueueModel)
                        .filter_by(agent_id=agent_id, status=CommandQueueStatus.QUEUED.value)
                        .all())
                commands = []
                for r in rows:
                    if r.expires_at and r.expires_at < now:
                        r.status = CommandQueueStatus.EXPIRED.value
                        continue
                    commands.append(_command_from_row(r))
                    r.status = CommandQueueStatus.SENT.value
                self.db.commit()
                commands.sort(key=lambda c: priority_order.get(c.priority, 2))
                return commands
            except Exception as exc:
                self.db.rollback()
                logger.error("DB get_pending_commands failed: %s", exc)

        # In-memory
        commands = []
        for cmd in list(self._commands.values()):
            if cmd.agent_id != agent_id or cmd.status != "queued":
                continue
            if cmd.expires_at and cmd.expires_at < now:
                cmd.status = "expired"
                continue
            commands.append(cmd)
            cmd.status = "sent"
        commands.sort(key=lambda c: priority_order.get(c.priority, 2))
        return commands

    def queue_command(self, agent_id: str, command_type: str, payload: Dict[str, Any],
                      priority: str = "normal", expires_in_seconds: int = 3600) -> AgentCommand:
        """Queue a command for an agent."""
        command_id = f"CMD-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=expires_in_seconds)

        cmd = AgentCommand(
            command_id=command_id,
            agent_id=agent_id,
            command_type=command_type,
            payload=payload,
            priority=priority,
            queued_at=now,
            expires_at=expires,
        )

        if self._use_db:
            try:
                row = AgentCommandQueueModel(
                    command_id=command_id,
                    agent_id=agent_id,
                    command_type=command_type,
                    payload=payload,
                    priority=priority,
                    status=CommandQueueStatus.QUEUED.value,
                    queued_at=now,
                    expires_at=expires,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Command %s queued for agent %s", command_id, agent_id)
                return cmd
            except Exception as exc:
                self.db.rollback()
                logger.error("DB queue_command failed: %s", exc)

        self._commands[command_id] = cmd
        return cmd

    def submit_command_result(self, agent_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Receive command execution results from agent."""
        command_id = result.get("command_id", "")
        exit_code = result.get("exit_code", -1)
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        execution_time_ms = result.get("execution_time_ms", 0)
        now = datetime.now(timezone.utc)

        status = CommandQueueStatus.COMPLETED.value if exit_code == 0 else CommandQueueStatus.FAILED.value

        if self._use_db:
            try:
                row = (self.db.query(AgentCommandQueueModel)
                       .filter_by(command_id=command_id, agent_id=agent_id)
                       .first())
                if row:
                    row.status = status
                    row.exit_code = exit_code
                    row.stdout = stdout
                    row.stderr = stderr
                    row.execution_time_ms = execution_time_ms
                    row.completed_at = now
                    self.db.commit()
                    return {"command_id": command_id, "status": status}
                return {"error": "command not found"}
            except Exception as exc:
                self.db.rollback()
                logger.error("DB submit_command_result failed: %s", exc)

        # In-memory
        cmd = self._commands.get(command_id)
        if cmd and cmd.agent_id == agent_id:
            cmd.status = status
            return {"command_id": command_id, "status": status}
        return {"error": "command not found"}

    # ------------------------------------------------------------------
    # Update Management
    # ------------------------------------------------------------------

    def check_for_update(self, agent_id: str, current_version: str) -> Optional[Dict[str, Any]]:
        """Check if a newer agent version is available for the agent's platform."""
        agent = self._get_agent(agent_id)
        if not agent:
            return None

        platform = agent.os_type

        if self._use_db:
            try:
                row = (self.db.query(AgentUpdateModel)
                       .filter_by(platform=platform)
                       .order_by(AgentUpdateModel.published_at.desc())
                       .first())
                if row and row.version != current_version:
                    return {
                        "version": row.version,
                        "platform": row.platform,
                        "download_url": row.download_url,
                        "checksum_sha256": row.checksum,
                        "release_notes": row.release_notes or "",
                        "is_mandatory": row.is_mandatory or False,
                    }
                return None
            except Exception as exc:
                logger.error("DB check_for_update failed: %s", exc)

        # In-memory
        for upd in sorted(self._updates, key=lambda u: u.version, reverse=True):
            if upd.platform == platform and upd.version != current_version:
                return {
                    "version": upd.version,
                    "platform": upd.platform,
                    "download_url": upd.download_url,
                    "checksum_sha256": upd.checksum_sha256,
                    "release_notes": upd.release_notes,
                    "is_mandatory": upd.is_mandatory,
                }
        return None

    def publish_update(self, version: str, platform: str, download_url: str,
                       checksum: str, release_notes: str = "",
                       is_mandatory: bool = False) -> AgentUpdate:
        """Publish a new agent update."""
        upd = AgentUpdate(
            version=version,
            platform=platform,
            download_url=download_url,
            checksum_sha256=checksum,
            release_notes=release_notes,
            is_mandatory=is_mandatory,
        )

        if self._use_db:
            try:
                row = AgentUpdateModel(
                    version=version,
                    platform=platform,
                    download_url=download_url,
                    checksum=checksum,
                    release_notes=release_notes,
                    is_mandatory=is_mandatory,
                )
                self.db.add(row)
                self.db.commit()
                return upd
            except Exception as exc:
                self.db.rollback()
                logger.error("DB publish_update failed: %s", exc)

        self._updates.append(upd)
        return upd

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def get_agent_config(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Return agent configuration."""
        if self._use_db:
            try:
                row = (self.db.query(RegisteredAgentModel)
                       .filter_by(agent_id=agent_id)
                       .first())
                if row:
                    return row.config or self._default_config_dict()
            except Exception as exc:
                logger.error("DB get_agent_config failed: %s", exc)

        cfg = self._configs.get(agent_id)
        if cfg:
            return {
                "checkin_interval_seconds": cfg.checkin_interval_seconds,
                "command_poll_interval_seconds": cfg.command_poll_interval_seconds,
                "log_level": cfg.log_level,
                "features_enabled": cfg.features_enabled,
                "proxy_config": cfg.proxy_config,
                "bandwidth_limit": cfg.bandwidth_limit,
            }
        return self._default_config_dict()

    def update_agent_config(self, agent_id: str, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Push configuration changes to an agent."""
        if self._use_db:
            try:
                row = (self.db.query(RegisteredAgentModel)
                       .filter_by(agent_id=agent_id)
                       .first())
                if row:
                    existing = row.config or {}
                    existing.update(config_data)
                    row.config = existing
                    self.db.commit()
                    return existing
            except Exception as exc:
                self.db.rollback()
                logger.error("DB update_agent_config failed: %s", exc)

        cfg = self._configs.get(agent_id, AgentConfig())
        for key, val in config_data.items():
            if hasattr(cfg, key):
                setattr(cfg, key, val)
        self._configs[agent_id] = cfg
        return self.get_agent_config(agent_id) or {}

    # ------------------------------------------------------------------
    # Agent Lifecycle
    # ------------------------------------------------------------------

    def revoke_agent(self, agent_id: str) -> bool:
        """Deactivate an agent (revoke its API key)."""
        if self._use_db:
            try:
                row = (self.db.query(RegisteredAgentModel)
                       .filter_by(agent_id=agent_id)
                       .first())
                if row:
                    row.status = AgentStatus.REVOKED.value
                    self.db.commit()
                    return True
                return False
            except Exception as exc:
                self.db.rollback()
                logger.error("DB revoke_agent failed: %s", exc)

        if agent_id in self._agents:
            del self._agents[agent_id]
            self._api_keys.pop(agent_id, None)
            self._configs.pop(agent_id, None)
            return True
        return False

    def rotate_api_key(self, agent_id: str) -> Optional[str]:
        """
        Rotate an agent's API key. Returns the new plaintext key (once).
        The old key is immediately invalidated.
        """
        new_key = _generate_api_key()
        new_hash = _hash_key(new_key)

        if self._use_db:
            try:
                row = (self.db.query(RegisteredAgentModel)
                       .filter_by(agent_id=agent_id, status=AgentStatus.ACTIVE.value)
                       .first())
                if row:
                    row.api_key_hash = new_hash
                    self.db.commit()
                    logger.info("API key rotated for agent %s", agent_id)
                    return new_key
                return None
            except Exception as exc:
                self.db.rollback()
                logger.error("DB rotate_api_key failed: %s", exc)

        if agent_id in self._api_keys:
            self._api_keys[agent_id] = new_hash
            if agent_id in self._agents:
                self._agents[agent_id].api_key_hash = new_hash
            return new_key
        return None

    # ------------------------------------------------------------------
    # Listing / Queries
    # ------------------------------------------------------------------

    def list_agents(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """List registered agents with optional filters."""
        filters = filters or {}
        status_filter = filters.get("status")
        os_filter = filters.get("os_type")
        hostname_filter = filters.get("hostname")

        if self._use_db:
            try:
                q = self.db.query(RegisteredAgentModel)
                if status_filter:
                    q = q.filter_by(status=status_filter)
                if os_filter:
                    q = q.filter_by(os_type=os_filter)
                if hostname_filter:
                    q = q.filter(RegisteredAgentModel.hostname.ilike(f"%{hostname_filter}%"))
                rows = q.order_by(RegisteredAgentModel.registered_at.desc()).all()
                return [self._agent_row_to_dict(r) for r in rows]
            except Exception as exc:
                logger.error("DB list_agents failed: %s", exc)

        results = []
        for agent in self._agents.values():
            if status_filter and status_filter != AgentStatus.ACTIVE.value:
                continue
            if os_filter and agent.os_type != os_filter:
                continue
            if hostname_filter and hostname_filter.lower() not in agent.hostname.lower():
                continue
            results.append(self._agent_to_dict(agent))
        return results

    def get_agent_detail(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed info for a specific agent."""
        agent = self._get_agent(agent_id)
        if not agent:
            return None
        detail = self._agent_to_dict(agent)
        detail["config"] = self.get_agent_config(agent_id)
        detail["latest_metrics"] = self._checkin_metrics.get(agent_id, {})
        return detail

    def get_agent_health(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Return agent-specific health metrics."""
        agent = self._get_agent(agent_id)
        if not agent:
            return None

        now = datetime.now(timezone.utc)
        last = agent.last_checkin
        stale = False
        if last:
            stale = (now - last).total_seconds() > 300  # 5 minutes
        metrics = self._checkin_metrics.get(agent_id, {})

        return {
            "agent_id": agent_id,
            "hostname": agent.hostname,
            "status": "stale" if stale else "healthy",
            "last_checkin": last.isoformat() if last else None,
            "seconds_since_checkin": int((now - last).total_seconds()) if last else None,
            "system_metrics": metrics.get("system_metrics", {}),
            "agent_status": metrics.get("agent_status", "unknown"),
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Fleet dashboard: agents by version, OS, status, stale agents."""
        agents = self.list_agents()
        now = datetime.now(timezone.utc)
        stale_threshold = timedelta(minutes=5)

        by_version: Dict[str, int] = {}
        by_os: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        stale_agents = []

        for a in agents:
            ver = a.get("agent_version", "unknown") or "unknown"
            by_version[ver] = by_version.get(ver, 0) + 1

            os_t = a.get("os_type", "unknown") or "unknown"
            by_os[os_t] = by_os.get(os_t, 0) + 1

            st = a.get("status", "unknown") or "unknown"
            by_status[st] = by_status.get(st, 0) + 1

            last_str = a.get("last_checkin")
            if last_str:
                try:
                    last_dt = datetime.fromisoformat(last_str) if isinstance(last_str, str) else last_str
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=timezone.utc)
                    if now - last_dt > stale_threshold:
                        stale_agents.append({"agent_id": a["agent_id"], "hostname": a.get("hostname"), "last_checkin": last_str})
                except Exception:
                    pass

        return {
            "total_agents": len(agents),
            "by_version": by_version,
            "by_os": by_os,
            "by_status": by_status,
            "stale_agents": stale_agents,
            "stale_count": len(stale_agents),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_agent(self, agent_id: str) -> Optional[AgentRegistration]:
        if self._use_db:
            try:
                row = (self.db.query(RegisteredAgentModel)
                       .filter_by(agent_id=agent_id)
                       .first())
                if row:
                    return _agent_from_row(row)
            except Exception as exc:
                logger.error("DB _get_agent failed: %s", exc)
        return self._agents.get(agent_id)

    def _agent_to_dict(self, agent: AgentRegistration) -> Dict[str, Any]:
        return {
            "agent_id": agent.agent_id,
            "endpoint_id": agent.endpoint_id,
            "hostname": agent.hostname,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "arch": agent.arch,
            "agent_version": agent.agent_version,
            "install_path": agent.install_path,
            "status": AgentStatus.ACTIVE.value,
            "registered_at": agent.registered_at.isoformat() if agent.registered_at else None,
            "last_checkin": agent.last_checkin.isoformat() if agent.last_checkin else None,
        }

    def _agent_row_to_dict(self, row) -> Dict[str, Any]:
        return {
            "agent_id": row.agent_id,
            "endpoint_id": row.endpoint_id,
            "hostname": row.hostname,
            "os_type": row.os_type,
            "os_version": row.os_version or "",
            "arch": row.arch or "x64",
            "agent_version": row.agent_version or "",
            "install_path": row.install_path or "",
            "status": row.status or "active",
            "registered_at": row.registered_at.isoformat() if row.registered_at else None,
            "last_checkin": row.last_checkin_at.isoformat() if row.last_checkin_at else None,
        }

    def _command_to_dict(self, cmd: AgentCommand) -> Dict[str, Any]:
        return {
            "command_id": cmd.command_id,
            "command_type": cmd.command_type,
            "payload": cmd.payload,
            "priority": cmd.priority,
        }

    @staticmethod
    def _default_config_dict() -> Dict[str, Any]:
        cfg = AgentConfig()
        return {
            "checkin_interval_seconds": cfg.checkin_interval_seconds,
            "command_poll_interval_seconds": cfg.command_poll_interval_seconds,
            "log_level": cfg.log_level,
            "features_enabled": cfg.features_enabled,
            "proxy_config": cfg.proxy_config,
            "bandwidth_limit": cfg.bandwidth_limit,
        }
