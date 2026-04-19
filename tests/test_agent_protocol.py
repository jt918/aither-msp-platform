"""
Tests for RMM Agent Communication Protocol Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.agent_protocol import (
    AgentProtocolService,
    AgentRegistration,
    AgentCheckin,
    AgentCommand,
    AgentCommandResponse,
    AgentUpdate,
    AgentConfig,
    AgentStatus,
    CommandType,
    CommandPriority,
    CommandQueueStatus,
    _hash_key,
    _generate_api_key,
)


class TestAgentProtocolService:
    """Tests for AgentProtocolService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = AgentProtocolService()

    # ========== Registration Tests ==========

    def test_register_agent_basic(self):
        """Test basic agent registration"""
        result = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })

        assert result is not None
        assert result["agent_id"].startswith("AGT-")
        assert result["endpoint_id"].startswith("EP-")
        assert "api_key" in result
        assert len(result["api_key"]) > 20
        assert "config" in result
        assert result["config"]["checkin_interval_seconds"] == 60

    def test_register_agent_full(self):
        """Test agent registration with all fields"""
        result = self.service.register_agent({
            "hostname": "SRV-DC01",
            "os_type": "windows",
            "os_version": "Server 2022",
            "arch": "x64",
            "agent_version": "1.0.0",
            "install_path": "C:\\Program Files\\Aither\\Agent",
            "endpoint_id": "EP-CUSTOM01",
        })

        assert result["agent_id"].startswith("AGT-")
        assert result["endpoint_id"] == "EP-CUSTOM01"
        assert "api_key" in result

    def test_register_multiple_agents(self):
        """Test registering multiple agents"""
        r1 = self.service.register_agent({"hostname": "WKS-001", "os_type": "windows"})
        r2 = self.service.register_agent({"hostname": "SRV-001", "os_type": "linux"})
        r3 = self.service.register_agent({"hostname": "MAC-001", "os_type": "macos"})

        assert r1["agent_id"] != r2["agent_id"]
        assert r2["agent_id"] != r3["agent_id"]
        assert r1["api_key"] != r2["api_key"]

    # ========== Authentication Tests ==========

    def test_authenticate_valid(self):
        """Test valid agent authentication"""
        result = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = result["agent_id"]
        api_key = result["api_key"]

        assert self.service.authenticate_agent(agent_id, api_key) is True

    def test_authenticate_invalid_key(self):
        """Test authentication with wrong key"""
        result = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = result["agent_id"]

        assert self.service.authenticate_agent(agent_id, "wrong-key") is False

    def test_authenticate_unknown_agent(self):
        """Test authentication with unknown agent ID"""
        assert self.service.authenticate_agent("AGT-NONEXISTENT", "some-key") is False

    def test_authenticate_revoked_agent(self):
        """Test that revoked agents cannot authenticate"""
        result = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = result["agent_id"]
        api_key = result["api_key"]

        self.service.revoke_agent(agent_id)
        assert self.service.authenticate_agent(agent_id, api_key) is False

    # ========== Check-in Tests ==========

    def test_checkin_basic(self):
        """Test basic agent check-in"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        result = self.service.agent_checkin(agent_id, {
            "system_metrics": {"cpu_percent": 45.0, "memory_percent": 60.0},
            "running_services": ["svchost", "aither-agent"],
            "agent_status": "healthy",
        })

        assert result["status"] == "ok"
        assert "server_time" in result
        assert "pending_commands" in result

    def test_checkin_updates_last_seen(self):
        """Test that check-in updates last_checkin timestamp"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        self.service.agent_checkin(agent_id, {"agent_status": "healthy"})
        agent = self.service._agents.get(agent_id)
        assert agent is not None
        assert agent.last_checkin is not None

    def test_checkin_returns_pending_commands(self):
        """Test that check-in returns pending commands"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        self.service.queue_command(agent_id, "shell", {"cmd": "hostname"})

        result = self.service.agent_checkin(agent_id, {"agent_status": "healthy"})
        assert len(result["pending_commands"]) == 1
        assert result["pending_commands"][0]["command_type"] == "shell"

    # ========== Command Queue Tests ==========

    def test_queue_command(self):
        """Test queuing a command for an agent"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        cmd = self.service.queue_command(agent_id, "powershell", {"script": "Get-Process"}, priority="high")

        assert cmd.command_id.startswith("CMD-")
        assert cmd.agent_id == agent_id
        assert cmd.command_type == "powershell"
        assert cmd.priority == "high"

    def test_get_pending_commands_priority_order(self):
        """Test that commands are returned in priority order"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        self.service.queue_command(agent_id, "shell", {"cmd": "low"}, priority="normal")
        self.service.queue_command(agent_id, "shell", {"cmd": "urgent"}, priority="urgent")
        self.service.queue_command(agent_id, "shell", {"cmd": "high"}, priority="high")

        commands = self.service.get_pending_commands(agent_id)
        assert len(commands) == 3
        assert commands[0].priority == "urgent"
        assert commands[1].priority == "high"
        assert commands[2].priority == "normal"

    def test_expired_commands_filtered(self):
        """Test that expired commands are not returned"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        cmd = self.service.queue_command(agent_id, "shell", {"cmd": "test"}, expires_in_seconds=0)
        # Force expiration
        self.service._commands[cmd.command_id].expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

        commands = self.service.get_pending_commands(agent_id)
        assert len(commands) == 0

    def test_submit_command_result_success(self):
        """Test submitting a successful command result"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]
        cmd = self.service.queue_command(agent_id, "shell", {"cmd": "hostname"})

        result = self.service.submit_command_result(agent_id, {
            "command_id": cmd.command_id,
            "exit_code": 0,
            "stdout": "WKS-001",
            "stderr": "",
            "execution_time_ms": 150,
        })

        assert result["status"] == "completed"

    def test_submit_command_result_failure(self):
        """Test submitting a failed command result"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]
        cmd = self.service.queue_command(agent_id, "shell", {"cmd": "bad-command"})

        result = self.service.submit_command_result(agent_id, {
            "command_id": cmd.command_id,
            "exit_code": 1,
            "stdout": "",
            "stderr": "command not found",
            "execution_time_ms": 50,
        })

        assert result["status"] == "failed"

    def test_submit_result_unknown_command(self):
        """Test submitting result for unknown command"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })

        result = self.service.submit_command_result(reg["agent_id"], {
            "command_id": "CMD-NONEXISTENT",
            "exit_code": 0,
        })
        assert "error" in result

    # ========== Configuration Tests ==========

    def test_get_default_config(self):
        """Test getting default agent config"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })

        config = self.service.get_agent_config(reg["agent_id"])
        assert config is not None
        assert config["checkin_interval_seconds"] == 60
        assert config["command_poll_interval_seconds"] == 15
        assert config["log_level"] == "info"

    def test_update_config(self):
        """Test updating agent config"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        result = self.service.update_agent_config(agent_id, {
            "checkin_interval_seconds": 120,
            "log_level": "debug",
        })

        assert result["checkin_interval_seconds"] == 120
        assert result["log_level"] == "debug"

    # ========== Key Rotation Tests ==========

    def test_rotate_api_key(self):
        """Test API key rotation"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]
        old_key = reg["api_key"]

        new_key = self.service.rotate_api_key(agent_id)
        assert new_key is not None
        assert new_key != old_key

        # Old key should no longer work
        assert self.service.authenticate_agent(agent_id, old_key) is False
        # New key should work
        assert self.service.authenticate_agent(agent_id, new_key) is True

    def test_rotate_key_unknown_agent(self):
        """Test rotating key for unknown agent"""
        result = self.service.rotate_api_key("AGT-NONEXISTENT")
        assert result is None

    # ========== Update Check Tests ==========

    def test_no_update_available(self):
        """Test when no update is available"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
            "agent_version": "1.0.0",
        })

        result = self.service.check_for_update(reg["agent_id"], "1.0.0")
        assert result is None

    def test_update_available(self):
        """Test when an update is available"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
            "agent_version": "1.0.0",
        })

        self.service.publish_update(
            version="2.0.0",
            platform="windows",
            download_url="https://updates.aither.io/agent/2.0.0/windows/agent.exe",
            checksum="abc123def456",
            release_notes="Major update",
            is_mandatory=True,
        )

        result = self.service.check_for_update(reg["agent_id"], "1.0.0")
        assert result is not None
        assert result["version"] == "2.0.0"
        assert result["is_mandatory"] is True

    # ========== Agent Lifecycle Tests ==========

    def test_revoke_agent(self):
        """Test revoking an agent"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        assert self.service.revoke_agent(agent_id) is True
        assert self.service.authenticate_agent(agent_id, reg["api_key"]) is False

    def test_revoke_unknown_agent(self):
        """Test revoking unknown agent"""
        assert self.service.revoke_agent("AGT-NONEXISTENT") is False

    # ========== Listing / Dashboard Tests ==========

    def test_list_agents_empty(self):
        """Test listing agents when none registered"""
        agents = self.service.list_agents()
        assert agents == []

    def test_list_agents(self):
        """Test listing registered agents"""
        self.service.register_agent({"hostname": "WKS-001", "os_type": "windows"})
        self.service.register_agent({"hostname": "SRV-001", "os_type": "linux"})

        agents = self.service.list_agents()
        assert len(agents) == 2

    def test_list_agents_filter_os(self):
        """Test filtering agents by OS type"""
        self.service.register_agent({"hostname": "WKS-001", "os_type": "windows"})
        self.service.register_agent({"hostname": "SRV-001", "os_type": "linux"})

        agents = self.service.list_agents({"os_type": "linux"})
        assert len(agents) == 1
        assert agents[0]["os_type"] == "linux"

    def test_get_agent_detail(self):
        """Test getting agent detail"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })

        detail = self.service.get_agent_detail(reg["agent_id"])
        assert detail is not None
        assert detail["hostname"] == "WKS-001"
        assert "config" in detail

    def test_get_agent_health(self):
        """Test getting agent health"""
        reg = self.service.register_agent({
            "hostname": "WKS-001",
            "os_type": "windows",
        })
        agent_id = reg["agent_id"]

        self.service.agent_checkin(agent_id, {
            "system_metrics": {"cpu_percent": 45.0},
            "agent_status": "healthy",
        })

        health = self.service.get_agent_health(agent_id)
        assert health is not None
        assert health["hostname"] == "WKS-001"
        assert health["status"] == "healthy"

    def test_get_dashboard(self):
        """Test fleet dashboard"""
        self.service.register_agent({"hostname": "WKS-001", "os_type": "windows", "agent_version": "1.0.0"})
        self.service.register_agent({"hostname": "SRV-001", "os_type": "linux", "agent_version": "1.0.0"})
        self.service.register_agent({"hostname": "MAC-001", "os_type": "macos", "agent_version": "2.0.0"})

        dashboard = self.service.get_dashboard()
        assert dashboard["total_agents"] == 3
        assert dashboard["by_os"]["windows"] == 1
        assert dashboard["by_os"]["linux"] == 1
        assert dashboard["by_os"]["macos"] == 1
        assert dashboard["by_version"]["1.0.0"] == 2
        assert dashboard["by_version"]["2.0.0"] == 1


class TestKeyManagement:
    """Tests for API key generation and hashing"""

    def test_generate_api_key_length(self):
        key = _generate_api_key()
        assert len(key) > 20

    def test_generate_api_key_unique(self):
        keys = {_generate_api_key() for _ in range(100)}
        assert len(keys) == 100

    def test_hash_key_deterministic(self):
        key = "test-key-12345"
        assert _hash_key(key) == _hash_key(key)

    def test_hash_key_different_for_different_keys(self):
        assert _hash_key("key-a") != _hash_key("key-b")


class TestDataclasses:
    """Tests for protocol dataclasses"""

    def test_agent_registration(self):
        reg = AgentRegistration(
            agent_id="AGT-TEST",
            endpoint_id="EP-TEST",
            hostname="WKS-001",
            os_type="windows",
        )
        assert reg.agent_id == "AGT-TEST"
        assert reg.arch == "x64"

    def test_agent_config_defaults(self):
        cfg = AgentConfig()
        assert cfg.checkin_interval_seconds == 60
        assert cfg.command_poll_interval_seconds == 15
        assert cfg.log_level == "info"
        assert "metrics" in cfg.features_enabled

    def test_agent_command(self):
        cmd = AgentCommand(
            command_id="CMD-TEST",
            agent_id="AGT-TEST",
            command_type="shell",
            payload={"cmd": "hostname"},
            priority="urgent",
        )
        assert cmd.command_id == "CMD-TEST"
        assert cmd.priority == "urgent"

    def test_agent_command_response(self):
        resp = AgentCommandResponse(
            command_id="CMD-TEST",
            agent_id="AGT-TEST",
            exit_code=0,
            stdout="output",
            execution_time_ms=100,
        )
        assert resp.exit_code == 0
        assert resp.execution_time_ms == 100

    def test_agent_update(self):
        upd = AgentUpdate(
            version="2.0.0",
            platform="windows",
            download_url="https://example.com/agent.exe",
            checksum_sha256="abcdef1234567890",
        )
        assert upd.version == "2.0.0"
        assert upd.is_mandatory is False
