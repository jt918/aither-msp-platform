"""
Tests for RMM (Remote Monitoring & Management) Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.rmm import (
    RMMService,
    EndpointStatus,
    AlertSeverity,
    AlertCategory,
    CommandStatus,
    PatchStatus,
    PolicyType,
    SystemMetrics,
    SystemInfo,
    Endpoint,
    Alert,
    Command,
    Patch,
    Software,
    AutomationPolicy,
    PolicyExecution
)


class TestRMMService:
    """Tests for RMMService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = RMMService()

    # ========== Endpoint Management Tests ==========

    def test_register_endpoint_basic(self):
        """Test basic endpoint registration"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        assert endpoint is not None
        assert endpoint.endpoint_id.startswith("EP-")
        assert endpoint.hostname == "WKS-001"
        assert endpoint.ip_address == "192.168.1.100"
        assert endpoint.status == EndpointStatus.ONLINE
        assert endpoint.last_seen is not None

    def test_register_endpoint_full(self):
        """Test endpoint registration with all options"""
        system_info = {
            "os_name": "Windows",
            "os_version": "11",
            "hostname": "WKS-001",
            "cpu_cores": 8,
            "ram_total_gb": 16.0
        }

        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100",
            mac_address="00:11:22:33:44:55",
            client_id="CL-001",
            client_name="Acme Corp",
            agent_version="3.2.1",
            system_info=system_info,
            tags=["workstation", "sales"],
            groups=["sales-dept"]
        )

        assert endpoint.mac_address == "00:11:22:33:44:55"
        assert endpoint.client_id == "CL-001"
        assert endpoint.client_name == "Acme Corp"
        assert endpoint.agent_version == "3.2.1"
        assert endpoint.system_info.os_name == "Windows"
        assert endpoint.system_info.cpu_cores == 8
        assert "workstation" in endpoint.tags
        assert "sales-dept" in endpoint.groups

    def test_update_endpoint(self):
        """Test endpoint update"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        updated = self.service.update_endpoint(
            endpoint.endpoint_id,
            hostname="WKS-001-NEW",
            status=EndpointStatus.WARNING
        )

        assert updated is not None
        assert updated.hostname == "WKS-001-NEW"
        assert updated.status == EndpointStatus.WARNING
        assert updated.updated_at is not None

    def test_update_endpoint_not_found(self):
        """Test update non-existent endpoint"""
        result = self.service.update_endpoint("EP-INVALID", hostname="test")
        assert result is None

    def test_heartbeat(self):
        """Test endpoint heartbeat"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        result = self.service.heartbeat(
            endpoint.endpoint_id,
            metrics={
                "cpu": 45.0,
                "memory": 60.0,
                "disk": 70.0,
                "network_in": 1000000,
                "network_out": 500000,
                "processes": 150,
                "uptime": 86400
            }
        )

        assert result["success"] is True

        # Check metrics were updated
        updated = self.service.get_endpoint(endpoint.endpoint_id)
        assert updated.metrics.cpu_percent == 45.0
        assert updated.metrics.memory_percent == 60.0
        assert updated.metrics.disk_percent == 70.0
        assert updated.status == EndpointStatus.ONLINE

    def test_heartbeat_generates_alerts(self):
        """Test that heartbeat generates alerts for high metrics"""
        endpoint = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )

        # Get initial alert count (may have default policies)
        initial_alert_count = len(self.service.list_alerts())

        result = self.service.heartbeat(
            endpoint.endpoint_id,
            metrics={
                "cpu": 96.0,  # Above critical threshold
                "memory": 50.0,
                "disk": 50.0
            }
        )

        assert result["success"] is True
        assert result["alerts_generated"] > 0

        # Verify alert was created
        alerts = self.service.list_alerts(endpoint_id=endpoint.endpoint_id)
        assert len(alerts) > 0
        critical_alerts = [a for a in alerts if a.severity == AlertSeverity.CRITICAL]
        assert len(critical_alerts) > 0

    def test_heartbeat_not_found(self):
        """Test heartbeat for non-existent endpoint"""
        result = self.service.heartbeat("EP-INVALID", metrics={"cpu": 50})
        assert result["success"] is False
        assert "not found" in result["error"]

    def test_get_endpoint(self):
        """Test get endpoint by ID"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        fetched = self.service.get_endpoint(endpoint.endpoint_id)
        assert fetched is not None
        assert fetched.endpoint_id == endpoint.endpoint_id

    def test_get_endpoint_by_hostname(self):
        """Test get endpoint by hostname"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-UNIQUE-001",
            ip_address="192.168.1.100"
        )

        fetched = self.service.get_endpoint_by_hostname("WKS-UNIQUE-001")
        assert fetched is not None
        assert fetched.endpoint_id == endpoint.endpoint_id

        # Case insensitive
        fetched_lower = self.service.get_endpoint_by_hostname("wks-unique-001")
        assert fetched_lower is not None

    def test_delete_endpoint(self):
        """Test delete endpoint"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-DELETE",
            ip_address="192.168.1.100"
        )

        result = self.service.delete_endpoint(endpoint.endpoint_id)
        assert result is True

        # Verify deleted
        fetched = self.service.get_endpoint(endpoint.endpoint_id)
        assert fetched is None

    def test_list_endpoints(self):
        """Test list endpoints with filters"""
        # Create multiple endpoints
        self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.101",
            client_id="CL-001",
            groups=["sales"]
        )
        self.service.register_endpoint(
            hostname="WKS-002",
            ip_address="192.168.1.102",
            client_id="CL-001",
            groups=["marketing"]
        )
        self.service.register_endpoint(
            hostname="WKS-003",
            ip_address="192.168.1.103",
            client_id="CL-002",
            tags=["priority"]
        )

        # Test filters
        all_endpoints = self.service.list_endpoints()
        assert len(all_endpoints) >= 3

        by_client = self.service.list_endpoints(client_id="CL-001")
        assert len(by_client) == 2

        by_group = self.service.list_endpoints(group="sales")
        assert len(by_group) == 1

        by_tag = self.service.list_endpoints(tag="priority")
        assert len(by_tag) == 1

    def test_set_maintenance_mode(self):
        """Test setting maintenance mode"""
        endpoint = self.service.register_endpoint(
            hostname="SRV-MAINT",
            ip_address="192.168.1.10"
        )

        result = self.service.set_maintenance_mode(
            endpoint.endpoint_id,
            enabled=True,
            reason="Scheduled maintenance"
        )

        assert result is True
        updated = self.service.get_endpoint(endpoint.endpoint_id)
        assert updated.status == EndpointStatus.MAINTENANCE

        # Disable maintenance
        result = self.service.set_maintenance_mode(endpoint.endpoint_id, enabled=False)
        assert result is True
        updated = self.service.get_endpoint(endpoint.endpoint_id)
        assert updated.status == EndpointStatus.UNKNOWN

    # ========== Alert Management Tests ==========

    def test_create_alert(self):
        """Test creating an alert"""
        endpoint = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )

        alert = self.service.create_alert(
            endpoint_id=endpoint.endpoint_id,
            severity=AlertSeverity.HIGH,
            category=AlertCategory.PERFORMANCE,
            title="High CPU Usage",
            message="CPU usage exceeds 85%",
            metric_name="cpu_percent",
            metric_value=87.5,
            threshold=85.0
        )

        assert alert is not None
        assert alert.alert_id.startswith("ALR-")
        assert alert.severity == AlertSeverity.HIGH
        assert alert.category == AlertCategory.PERFORMANCE
        assert alert.hostname == "SRV-001"
        assert alert.acknowledged is False
        assert alert.resolved is False

    def test_acknowledge_alert(self):
        """Test acknowledging an alert"""
        endpoint = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )

        alert = self.service.create_alert(
            endpoint_id=endpoint.endpoint_id,
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.CONNECTIVITY,
            title="Endpoint Offline",
            message="No heartbeat received"
        )

        result = self.service.acknowledge_alert(
            alert.alert_id,
            acknowledged_by="admin@company.com",
            notes="Looking into it"
        )

        assert result is True
        updated = self.service.get_alert(alert.alert_id)
        assert updated.acknowledged is True
        assert updated.acknowledged_by == "admin@company.com"
        assert updated.acknowledged_at is not None
        assert updated.notes == "Looking into it"

    def test_resolve_alert(self):
        """Test resolving an alert"""
        endpoint = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )

        alert = self.service.create_alert(
            endpoint_id=endpoint.endpoint_id,
            severity=AlertSeverity.MEDIUM,
            category=AlertCategory.SOFTWARE,
            title="Service Stopped",
            message="Critical service has stopped"
        )

        initial_count = endpoint.alerts_count

        result = self.service.resolve_alert(alert.alert_id)

        assert result is True
        updated = self.service.get_alert(alert.alert_id)
        assert updated.resolved is True
        assert updated.resolved_at is not None

        # Check endpoint alert count decreased
        updated_endpoint = self.service.get_endpoint(endpoint.endpoint_id)
        assert updated_endpoint.alerts_count == initial_count - 1

    def test_list_alerts(self):
        """Test listing alerts with filters"""
        endpoint1 = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )
        endpoint2 = self.service.register_endpoint(
            hostname="SRV-002",
            ip_address="192.168.1.11"
        )

        # Create alerts
        alert1 = self.service.create_alert(
            endpoint_id=endpoint1.endpoint_id,
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.SECURITY,
            title="Security Alert",
            message="Suspicious activity detected"
        )
        alert2 = self.service.create_alert(
            endpoint_id=endpoint2.endpoint_id,
            severity=AlertSeverity.LOW,
            category=AlertCategory.PERFORMANCE,
            title="Low Priority",
            message="Minor performance issue"
        )

        # Acknowledge one
        self.service.acknowledge_alert(alert1.alert_id, "admin")

        # Test filters
        critical_alerts = self.service.list_alerts(severity=AlertSeverity.CRITICAL)
        assert any(a.alert_id == alert1.alert_id for a in critical_alerts)

        unacknowledged = self.service.list_alerts(acknowledged=False)
        assert any(a.alert_id == alert2.alert_id for a in unacknowledged)

        by_endpoint = self.service.list_alerts(endpoint_id=endpoint1.endpoint_id)
        assert all(a.endpoint_id == endpoint1.endpoint_id for a in by_endpoint)

    def test_delete_alert(self):
        """Test deleting an alert"""
        endpoint = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )

        alert = self.service.create_alert(
            endpoint_id=endpoint.endpoint_id,
            severity=AlertSeverity.INFO,
            category=AlertCategory.CUSTOM,
            title="Test Alert",
            message="Test"
        )

        result = self.service.delete_alert(alert.alert_id)
        assert result is True

        fetched = self.service.get_alert(alert.alert_id)
        assert fetched is None

    # ========== Command Management Tests ==========

    def test_queue_command(self):
        """Test queuing a command"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        command = self.service.queue_command(
            endpoint_id=endpoint.endpoint_id,
            command_type="shell",
            command="ipconfig /all",
            queued_by="admin@company.com",
            timeout_seconds=60
        )

        assert command is not None
        assert command.command_id.startswith("CMD-")
        assert command.status == CommandStatus.QUEUED
        assert command.command_type == "shell"
        assert command.command == "ipconfig /all"
        assert command.timeout_seconds == 60

    def test_update_command_status(self):
        """Test updating command status"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        command = self.service.queue_command(
            endpoint_id=endpoint.endpoint_id,
            command_type="shell",
            command="dir"
        )

        # Start command
        result = self.service.update_command_status(
            command.command_id,
            status=CommandStatus.RUNNING
        )
        assert result is True

        updated = self.service.get_command(command.command_id)
        assert updated.status == CommandStatus.RUNNING
        assert updated.started_at is not None

        # Complete command
        result = self.service.update_command_status(
            command.command_id,
            status=CommandStatus.COMPLETED,
            output="Directory listing...",
            exit_code=0
        )
        assert result is True

        updated = self.service.get_command(command.command_id)
        assert updated.status == CommandStatus.COMPLETED
        assert updated.output == "Directory listing..."
        assert updated.exit_code == 0
        assert updated.completed_at is not None

    def test_cancel_command(self):
        """Test cancelling a command"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        command = self.service.queue_command(
            endpoint_id=endpoint.endpoint_id,
            command_type="shell",
            command="long-running-task"
        )

        result = self.service.cancel_command(command.command_id)
        assert result is True

        updated = self.service.get_command(command.command_id)
        assert updated.status == CommandStatus.CANCELLED

    def test_cancel_running_command_fails(self):
        """Test that cancelling a running command fails"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        command = self.service.queue_command(
            endpoint_id=endpoint.endpoint_id,
            command_type="shell",
            command="task"
        )

        # Start it
        self.service.update_command_status(
            command.command_id,
            status=CommandStatus.RUNNING
        )

        # Try to cancel
        result = self.service.cancel_command(command.command_id)
        assert result is False

    def test_list_commands(self):
        """Test listing commands"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        cmd1 = self.service.queue_command(
            endpoint_id=endpoint.endpoint_id,
            command_type="shell",
            command="cmd1"
        )
        cmd2 = self.service.queue_command(
            endpoint_id=endpoint.endpoint_id,
            command_type="powershell",
            command="cmd2"
        )

        # Complete one
        self.service.update_command_status(
            cmd1.command_id,
            status=CommandStatus.COMPLETED,
            exit_code=0
        )

        # List by status
        queued = self.service.list_commands(status=CommandStatus.QUEUED)
        assert any(c.command_id == cmd2.command_id for c in queued)

        completed = self.service.list_commands(status=CommandStatus.COMPLETED)
        assert any(c.command_id == cmd1.command_id for c in completed)

    # ========== Patch Management Tests ==========

    def test_add_patch(self):
        """Test adding a patch"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        initial_pending = endpoint.patches_pending

        patch = self.service.add_patch(
            endpoint_id=endpoint.endpoint_id,
            kb_id="KB5001234",
            title="Cumulative Update for Windows 11",
            description="Security updates",
            severity="critical",
            size_mb=150.5,
            requires_reboot=True
        )

        assert patch is not None
        assert patch.patch_id.startswith("PAT-")
        assert patch.kb_id == "KB5001234"
        assert patch.status == PatchStatus.AVAILABLE
        assert patch.requires_reboot is True

        # Check endpoint patches pending increased
        updated = self.service.get_endpoint(endpoint.endpoint_id)
        assert updated.patches_pending == initial_pending + 1

    def test_update_patch_status(self):
        """Test updating patch status"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        patch = self.service.add_patch(
            endpoint_id=endpoint.endpoint_id,
            kb_id="KB5001234",
            title="Test Patch"
        )

        # Downloading
        result = self.service.update_patch_status(
            patch.patch_id,
            status=PatchStatus.DOWNLOADING
        )
        assert result is True

        # Install
        result = self.service.update_patch_status(
            patch.patch_id,
            status=PatchStatus.INSTALLED
        )
        assert result is True

        updated = self.service.get_patch(patch.patch_id)
        assert updated.status == PatchStatus.INSTALLED
        assert updated.installed_at is not None

        # Check endpoint patches pending decreased
        updated_endpoint = self.service.get_endpoint(endpoint.endpoint_id)
        assert updated_endpoint.patches_pending == 0

    def test_list_patches(self):
        """Test listing patches"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        patch1 = self.service.add_patch(
            endpoint_id=endpoint.endpoint_id,
            kb_id="KB001",
            title="Patch 1"
        )
        patch2 = self.service.add_patch(
            endpoint_id=endpoint.endpoint_id,
            kb_id="KB002",
            title="Patch 2"
        )

        # Install one
        self.service.update_patch_status(patch1.patch_id, PatchStatus.INSTALLED)

        # List by status
        available = self.service.list_patches(
            endpoint_id=endpoint.endpoint_id,
            status=PatchStatus.AVAILABLE
        )
        assert any(p.patch_id == patch2.patch_id for p in available)

        installed = self.service.list_patches(status=PatchStatus.INSTALLED)
        assert any(p.patch_id == patch1.patch_id for p in installed)

    # ========== Software Inventory Tests ==========

    def test_update_software_inventory(self):
        """Test updating software inventory"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        software_list = [
            {"name": "Microsoft Office", "version": "365", "publisher": "Microsoft"},
            {"name": "Google Chrome", "version": "120.0", "publisher": "Google"},
            {"name": "Visual Studio Code", "version": "1.85", "publisher": "Microsoft"}
        ]

        count = self.service.update_software_inventory(
            endpoint.endpoint_id,
            software_list
        )

        assert count == 3

        inventory = self.service.get_software_inventory(endpoint.endpoint_id)
        assert len(inventory) == 3
        assert any(s.name == "Microsoft Office" for s in inventory)

    def test_search_software(self):
        """Test searching software across endpoints"""
        endpoint1 = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.101"
        )
        endpoint2 = self.service.register_endpoint(
            hostname="WKS-002",
            ip_address="192.168.1.102"
        )

        self.service.update_software_inventory(
            endpoint1.endpoint_id,
            [{"name": "Microsoft Office", "version": "365", "publisher": "Microsoft"}]
        )
        self.service.update_software_inventory(
            endpoint2.endpoint_id,
            [{"name": "Google Chrome", "version": "120.0", "publisher": "Google"}]
        )

        # Search by name
        results = self.service.search_software(name="Office")
        assert endpoint1.endpoint_id in results

        # Search by publisher
        results = self.service.search_software(publisher="Google")
        assert endpoint2.endpoint_id in results

    # ========== Automation Policy Tests ==========

    def test_create_policy(self):
        """Test creating a policy"""
        policy = self.service.create_policy(
            name="CPU Alert Policy",
            description="Alert when CPU is high",
            policy_type=PolicyType.THRESHOLD,
            trigger_conditions={"metric": "cpu_percent", "operator": ">", "value": 85},
            actions=[{"type": "alert", "severity": "warning"}],
            target_groups=["servers"],
            cooldown_minutes=10
        )

        assert policy is not None
        assert policy.policy_id.startswith("POL-")
        assert policy.name == "CPU Alert Policy"
        assert policy.policy_type == PolicyType.THRESHOLD
        assert policy.enabled is True
        assert policy.cooldown_minutes == 10

    def test_update_policy(self):
        """Test updating a policy"""
        policy = self.service.create_policy(
            name="Test Policy",
            policy_type=PolicyType.SCHEDULE
        )

        updated = self.service.update_policy(
            policy.policy_id,
            name="Updated Policy",
            enabled=False,
            schedule="0 0 * * *"
        )

        assert updated is not None
        assert updated.name == "Updated Policy"
        assert updated.enabled is False
        assert updated.schedule == "0 0 * * *"
        assert updated.updated_at is not None

    def test_enable_disable_policy(self):
        """Test enabling/disabling policy"""
        policy = self.service.create_policy(
            name="Toggle Policy",
            policy_type=PolicyType.EVENT
        )

        # Disable
        result = self.service.enable_policy(policy.policy_id, enabled=False)
        assert result is True

        updated = self.service.get_policy(policy.policy_id)
        assert updated.enabled is False

        # Enable
        result = self.service.enable_policy(policy.policy_id, enabled=True)
        assert result is True

        updated = self.service.get_policy(policy.policy_id)
        assert updated.enabled is True

    def test_delete_policy(self):
        """Test deleting a policy"""
        policy = self.service.create_policy(
            name="Delete Me",
            policy_type=PolicyType.CONDITION
        )

        result = self.service.delete_policy(policy.policy_id)
        assert result is True

        fetched = self.service.get_policy(policy.policy_id)
        assert fetched is None

    def test_list_policies(self):
        """Test listing policies with filters"""
        policy1 = self.service.create_policy(
            name="Threshold Policy",
            policy_type=PolicyType.THRESHOLD
        )
        policy2 = self.service.create_policy(
            name="Schedule Policy",
            policy_type=PolicyType.SCHEDULE
        )

        # Disable one
        self.service.enable_policy(policy2.policy_id, enabled=False)

        # List by type
        threshold_policies = self.service.list_policies(policy_type=PolicyType.THRESHOLD)
        assert any(p.policy_id == policy1.policy_id for p in threshold_policies)

        # List enabled only
        enabled_policies = self.service.list_policies(enabled_only=True)
        assert all(p.enabled for p in enabled_policies)

    def test_record_policy_execution(self):
        """Test recording policy execution"""
        policy = self.service.create_policy(
            name="Test Policy",
            policy_type=PolicyType.THRESHOLD
        )
        endpoint = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )

        initial_count = policy.execution_count

        execution = self.service.record_policy_execution(
            policy_id=policy.policy_id,
            endpoint_id=endpoint.endpoint_id,
            triggered_by="cpu_percent > 90",
            actions_taken=["Created alert", "Sent notification"],
            success=True
        )

        assert execution is not None
        assert execution.execution_id.startswith("EXE-")
        assert execution.success is True
        assert len(execution.actions_taken) == 2

        # Check policy execution count increased
        updated = self.service.get_policy(policy.policy_id)
        assert updated.execution_count == initial_count + 1
        assert updated.last_triggered is not None

    def test_get_policy_executions(self):
        """Test getting policy executions"""
        policy = self.service.create_policy(
            name="Test Policy",
            policy_type=PolicyType.THRESHOLD
        )
        endpoint = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )

        # Record multiple executions
        for i in range(3):
            self.service.record_policy_execution(
                policy_id=policy.policy_id,
                endpoint_id=endpoint.endpoint_id,
                triggered_by=f"condition_{i}",
                actions_taken=["action"]
            )

        executions = self.service.get_policy_executions(
            policy_id=policy.policy_id,
            limit=10
        )
        assert len(executions) >= 3

    # ========== Dashboard & Analytics Tests ==========

    def test_get_dashboard(self):
        """Test getting dashboard data"""
        # Create some data
        endpoint1 = self.service.register_endpoint(
            hostname="WKS-001",
            ip_address="192.168.1.101",
            client_name="Acme Corp"
        )
        endpoint2 = self.service.register_endpoint(
            hostname="WKS-002",
            ip_address="192.168.1.102",
            client_name="Acme Corp"
        )

        self.service.create_alert(
            endpoint_id=endpoint1.endpoint_id,
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.SECURITY,
            title="Test Alert",
            message="Test"
        )

        dashboard = self.service.get_dashboard()

        assert "endpoints" in dashboard
        assert "alerts" in dashboard
        assert "policies" in dashboard
        assert "commands" in dashboard
        assert "clients" in dashboard
        assert "timestamp" in dashboard

        assert dashboard["endpoints"]["total"] >= 2
        assert dashboard["alerts"]["total"] >= 1
        assert "Acme Corp" in dashboard["clients"]

    def test_get_endpoint_health_summary(self):
        """Test getting endpoint health summary"""
        endpoint = self.service.register_endpoint(
            hostname="SRV-001",
            ip_address="192.168.1.10"
        )

        # Add some data
        self.service.heartbeat(
            endpoint.endpoint_id,
            metrics={"cpu": 45, "memory": 60, "disk": 70, "uptime": 86400}
        )
        self.service.create_alert(
            endpoint_id=endpoint.endpoint_id,
            severity=AlertSeverity.LOW,
            category=AlertCategory.PERFORMANCE,
            title="Low Alert",
            message="Minor issue"
        )

        health = self.service.get_endpoint_health_summary(endpoint.endpoint_id)

        assert health["endpoint_id"] == endpoint.endpoint_id
        assert health["hostname"] == "SRV-001"
        assert "health_score" in health
        assert 0 <= health["health_score"] <= 100
        assert "metrics" in health
        assert health["metrics"]["cpu"] == 45

    def test_get_endpoint_health_summary_not_found(self):
        """Test health summary for non-existent endpoint"""
        health = self.service.get_endpoint_health_summary("EP-INVALID")
        assert health == {}

    def test_health_score_calculation(self):
        """Test that health score decreases with issues"""
        endpoint = self.service.register_endpoint(
            hostname="SRV-UNHEALTHY",
            ip_address="192.168.1.10"
        )

        # Good health initially
        self.service.heartbeat(
            endpoint.endpoint_id,
            metrics={"cpu": 30, "memory": 40, "disk": 50}
        )

        good_health = self.service.get_endpoint_health_summary(endpoint.endpoint_id)

        # Add multiple alerts
        for i in range(5):
            self.service.create_alert(
                endpoint_id=endpoint.endpoint_id,
                severity=AlertSeverity.HIGH,
                category=AlertCategory.SECURITY,
                title=f"Alert {i}",
                message="Issue"
            )

        # High resource usage
        self.service.heartbeat(
            endpoint.endpoint_id,
            metrics={"cpu": 95, "memory": 95, "disk": 95}
        )

        bad_health = self.service.get_endpoint_health_summary(endpoint.endpoint_id)

        assert bad_health["health_score"] < good_health["health_score"]

    # ========== Default Policy Tests ==========

    def test_default_policies_created(self):
        """Test that default policies are created on initialization"""
        policies = self.service.list_policies()

        # Should have at least the 3 default policies
        assert len(policies) >= 3

        # Check for expected policies
        policy_names = [p.name for p in policies]
        assert "High CPU Alert" in policy_names
        assert "Critical Memory Alert" in policy_names
        assert "Disk Space Critical" in policy_names

    # ========== Offline Detection Tests ==========

    def test_check_offline_endpoints(self):
        """Test detecting offline endpoints"""
        endpoint = self.service.register_endpoint(
            hostname="WKS-OFFLINE",
            ip_address="192.168.1.100"
        )

        # Set last_seen to past the threshold
        endpoint.last_seen = datetime.now(timezone.utc) - timedelta(minutes=10)

        alerts = self.service.check_offline_endpoints()

        # Should have generated an offline alert
        assert len(alerts) > 0

        # Check endpoint status changed
        updated = self.service.get_endpoint(endpoint.endpoint_id)
        assert updated.status == EndpointStatus.OFFLINE


class TestDataClasses:
    """Tests for dataclasses"""

    def test_system_metrics_defaults(self):
        """Test SystemMetrics default values"""
        metrics = SystemMetrics()

        assert metrics.cpu_percent == 0.0
        assert metrics.memory_percent == 0.0
        assert metrics.disk_percent == 0.0
        assert metrics.network_in_bytes == 0
        assert metrics.timestamp is not None

    def test_system_info_defaults(self):
        """Test SystemInfo default values"""
        info = SystemInfo()

        assert info.os_name == ""
        assert info.cpu_cores == 0
        assert info.ram_total_gb == 0.0

    def test_endpoint_creation(self):
        """Test Endpoint dataclass"""
        endpoint = Endpoint(
            endpoint_id="EP-001",
            hostname="WKS-001",
            ip_address="192.168.1.100"
        )

        assert endpoint.status == EndpointStatus.UNKNOWN
        assert endpoint.alerts_count == 0
        assert endpoint.patches_pending == 0
        assert endpoint.created_at is not None

    def test_alert_creation(self):
        """Test Alert dataclass"""
        alert = Alert(
            alert_id="ALR-001",
            endpoint_id="EP-001",
            hostname="WKS-001",
            severity=AlertSeverity.HIGH,
            category=AlertCategory.SECURITY,
            title="Security Alert",
            message="Suspicious activity"
        )

        assert alert.acknowledged is False
        assert alert.resolved is False
        assert alert.created_at is not None

    def test_command_creation(self):
        """Test Command dataclass"""
        command = Command(
            command_id="CMD-001",
            endpoint_id="EP-001",
            command_type="shell",
            command="dir"
        )

        assert command.status == CommandStatus.QUEUED
        assert command.timeout_seconds == 300
        assert command.exit_code is None

    def test_patch_creation(self):
        """Test Patch dataclass"""
        patch = Patch(
            patch_id="PAT-001",
            endpoint_id="EP-001"
        )

        assert patch.status == PatchStatus.AVAILABLE
        assert patch.requires_reboot is False

    def test_automation_policy_creation(self):
        """Test AutomationPolicy dataclass"""
        policy = AutomationPolicy(
            policy_id="POL-001",
            name="Test Policy"
        )

        assert policy.policy_type == PolicyType.THRESHOLD
        assert policy.enabled is True
        assert policy.cooldown_minutes == 15
        assert policy.execution_count == 0


class TestEnums:
    """Tests for enums"""

    def test_endpoint_status_values(self):
        """Test EndpointStatus enum values"""
        assert EndpointStatus.ONLINE.value == "online"
        assert EndpointStatus.OFFLINE.value == "offline"
        assert EndpointStatus.WARNING.value == "warning"
        assert EndpointStatus.MAINTENANCE.value == "maintenance"
        assert EndpointStatus.DEGRADED.value == "degraded"

    def test_alert_severity_values(self):
        """Test AlertSeverity enum values"""
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.INFO.value == "info"

    def test_alert_category_values(self):
        """Test AlertCategory enum values"""
        assert AlertCategory.PERFORMANCE.value == "performance"
        assert AlertCategory.SECURITY.value == "security"
        assert AlertCategory.CONNECTIVITY.value == "connectivity"
        assert AlertCategory.HARDWARE.value == "hardware"
        assert AlertCategory.SOFTWARE.value == "software"

    def test_command_status_values(self):
        """Test CommandStatus enum values"""
        assert CommandStatus.QUEUED.value == "queued"
        assert CommandStatus.RUNNING.value == "running"
        assert CommandStatus.COMPLETED.value == "completed"
        assert CommandStatus.FAILED.value == "failed"
        assert CommandStatus.CANCELLED.value == "cancelled"

    def test_patch_status_values(self):
        """Test PatchStatus enum values"""
        assert PatchStatus.AVAILABLE.value == "available"
        assert PatchStatus.DOWNLOADING.value == "downloading"
        assert PatchStatus.PENDING.value == "pending"
        assert PatchStatus.INSTALLED.value == "installed"
        assert PatchStatus.FAILED.value == "failed"

    def test_policy_type_values(self):
        """Test PolicyType enum values"""
        assert PolicyType.THRESHOLD.value == "threshold"
        assert PolicyType.SCHEDULE.value == "schedule"
        assert PolicyType.EVENT.value == "event"
        assert PolicyType.CONDITION.value == "condition"
