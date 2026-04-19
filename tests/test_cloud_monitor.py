"""
Tests for Cloud Infrastructure Monitoring Service
Covers accounts, resources, costs, security, alerts, FinOps, and dashboards.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.cloud_monitor import (
    CloudMonitorService,
    CloudProvider,
    ResourceType,
    FindingType,
    AlertType,
    AccountStatus,
    ResourceStatus,
    Severity,
    CloudAccount,
    CloudResource,
    CloudCostEntry,
    CloudSecurityFinding,
    CloudAlert,
    SECURITY_CHECKS,
)


@pytest.fixture
def svc():
    """Fresh in-memory CloudMonitorService."""
    return CloudMonitorService()


@pytest.fixture
def svc_with_account(svc):
    """Service with one registered AWS account."""
    acct = svc.register_account(
        client_id="CLIENT-001",
        provider="aws",
        account_name="Production AWS",
        account_identifier="123456789012",
        region="us-east-1",
        credentials_ref="vault://aws/prod",
    )
    return svc, acct


@pytest.fixture
def svc_synced(svc_with_account):
    """Service with an account that has been synced (resources populated)."""
    svc, acct = svc_with_account
    svc.sync_resources(acct.account_id)
    return svc, acct


# ============================================================
# Account Management
# ============================================================

class TestAccountManagement:
    def test_register_account(self, svc):
        acct = svc.register_account(
            client_id="C1",
            provider="aws",
            account_name="Test AWS",
            account_identifier="111222333444",
        )
        assert acct.account_id.startswith("CLD-")
        assert acct.provider == CloudProvider.AWS
        assert acct.client_id == "C1"
        assert acct.status == AccountStatus.DISCONNECTED  # no creds

    def test_register_account_with_creds_is_connected(self, svc):
        acct = svc.register_account(
            client_id="C1",
            provider="azure",
            account_name="Azure Sub",
            account_identifier="sub-abc",
            credentials_ref="vault://azure/sub-abc",
        )
        assert acct.status == AccountStatus.CONNECTED

    def test_get_account(self, svc_with_account):
        svc, acct = svc_with_account
        fetched = svc.get_account(acct.account_id)
        assert fetched is not None
        assert fetched.account_id == acct.account_id

    def test_get_account_not_found(self, svc):
        assert svc.get_account("NOPE") is None

    def test_list_accounts(self, svc):
        svc.register_account("C1", "aws", "AWS Prod", "111")
        svc.register_account("C1", "azure", "Azure Dev", "222")
        svc.register_account("C2", "gcp", "GCP Staging", "333")
        assert len(svc.list_accounts()) == 3
        assert len(svc.list_accounts(client_id="C1")) == 2
        assert len(svc.list_accounts(provider="gcp")) == 1

    def test_update_account(self, svc_with_account):
        svc, acct = svc_with_account
        updated = svc.update_account(acct.account_id, account_name="Renamed")
        assert updated.account_name == "Renamed"

    def test_update_account_not_found(self, svc):
        assert svc.update_account("NOPE", account_name="x") is None

    def test_test_connection_with_creds(self, svc_with_account):
        svc, acct = svc_with_account
        result = svc.test_connection(acct.account_id)
        assert result["success"] is True
        assert "latency_ms" in result

    def test_test_connection_without_creds(self, svc):
        acct = svc.register_account("C1", "aws", "No Creds", "111")
        result = svc.test_connection(acct.account_id)
        assert result["success"] is False

    def test_test_connection_not_found(self, svc):
        result = svc.test_connection("NOPE")
        assert result["success"] is False


# ============================================================
# Resource Sync & Management
# ============================================================

class TestResourceManagement:
    def test_sync_resources(self, svc_with_account):
        svc, acct = svc_with_account
        result = svc.sync_resources(acct.account_id)
        assert result["success"] is True
        assert result["resources_synced"] > 0
        assert result["provider"] == "aws"

    def test_sync_not_found(self, svc):
        result = svc.sync_resources("NOPE")
        assert result["success"] is False

    def test_list_resources_after_sync(self, svc_synced):
        svc, acct = svc_synced
        resources = svc.list_resources(account_id=acct.account_id)
        assert len(resources) > 0

    def test_list_resources_by_type(self, svc_synced):
        svc, acct = svc_synced
        instances = svc.list_resources(
            account_id=acct.account_id,
            resource_type="compute_instance",
        )
        assert all(r.resource_type == ResourceType.COMPUTE_INSTANCE for r in instances)

    def test_list_resources_pagination(self, svc_synced):
        svc, acct = svc_synced
        page1 = svc.list_resources(account_id=acct.account_id, limit=3, offset=0)
        page2 = svc.list_resources(account_id=acct.account_id, limit=3, offset=3)
        assert len(page1) <= 3
        if page2:
            assert page1[0].resource_id != page2[0].resource_id

    def test_get_resource(self, svc_synced):
        svc, acct = svc_synced
        resources = svc.list_resources(account_id=acct.account_id, limit=1)
        assert len(resources) > 0
        res = svc.get_resource(resources[0].resource_id)
        assert res is not None
        assert res.resource_id == resources[0].resource_id

    def test_get_resource_not_found(self, svc):
        assert svc.get_resource("NOPE") is None

    def test_search_resources(self, svc_synced):
        svc, acct = svc_synced
        results = svc.search_resources("web-server", account_id=acct.account_id)
        assert all("web-server" in r.resource_name for r in results)

    def test_get_resource_metrics(self, svc_synced):
        svc, acct = svc_synced
        resources = svc.list_resources(account_id=acct.account_id, limit=1)
        metrics = svc.get_resource_metrics(resources[0].resource_id)
        assert "timestamp" in metrics
        assert "cpu_percent" in metrics

    def test_get_resource_metrics_not_found(self, svc):
        assert svc.get_resource_metrics("NOPE") == {}

    def test_account_updated_after_sync(self, svc_with_account):
        svc, acct = svc_with_account
        svc.sync_resources(acct.account_id)
        updated = svc.get_account(acct.account_id)
        assert updated.resources_count > 0
        assert updated.monthly_cost > 0
        assert updated.last_sync_at is not None
        assert updated.status == AccountStatus.CONNECTED


# ============================================================
# Cost Management
# ============================================================

class TestCostManagement:
    def test_record_cost(self, svc_with_account):
        svc, acct = svc_with_account
        now = datetime.now(timezone.utc)
        entry = svc.record_cost(
            account_id=acct.account_id,
            service_name="EC2",
            cost_amount=150.0,
            period_start=now.replace(day=1),
            period_end=now,
        )
        assert entry.cost_id.startswith("CST-")
        assert entry.cost_amount == 150.0

    def test_get_costs(self, svc_synced):
        svc, acct = svc_synced
        costs = svc.get_costs(acct.account_id)
        assert len(costs) > 0

    def test_get_cost_breakdown(self, svc_synced):
        svc, acct = svc_synced
        breakdown = svc.get_cost_breakdown(acct.account_id)
        assert "total" in breakdown
        assert "breakdown" in breakdown
        assert len(breakdown["breakdown"]) > 0

    def test_get_cost_trend(self, svc_with_account):
        svc, acct = svc_with_account
        trend = svc.get_cost_trend(acct.account_id, months=6)
        assert len(trend) == 6
        assert all("month" in t and "cost" in t for t in trend)

    def test_get_cost_forecast(self, svc_with_account):
        svc, acct = svc_with_account
        forecast = svc.get_cost_forecast(acct.account_id)
        assert "forecast" in forecast
        assert len(forecast["forecast"]) == 3

    def test_cost_entries_generated_on_sync(self, svc_synced):
        svc, acct = svc_synced
        costs = svc.get_costs(acct.account_id, period="current")
        assert len(costs) > 0
        total = sum(c.cost_amount for c in costs)
        assert total > 0


# ============================================================
# Security
# ============================================================

class TestSecurity:
    def test_security_checks_defined(self):
        assert len(SECURITY_CHECKS) == 15

    def test_run_security_scan_no_resources(self, svc_with_account):
        svc, acct = svc_with_account
        result = svc.run_security_scan(acct.account_id)
        assert result["findings"] == 0

    def test_run_security_scan(self, svc_synced):
        svc, acct = svc_synced
        result = svc.run_security_scan(acct.account_id)
        assert "total_findings" in result
        assert "by_severity" in result
        assert result["checks_run"] == 15
        assert result["scanned_resources"] > 0

    def test_get_findings(self, svc_synced):
        svc, acct = svc_synced
        svc.run_security_scan(acct.account_id)
        findings = svc.get_findings(account_id=acct.account_id)
        # May be 0 if random didn't fire, but the method should work
        assert isinstance(findings, list)

    def test_get_findings_filter_severity(self, svc_synced):
        svc, acct = svc_synced
        svc.run_security_scan(acct.account_id)
        critical = svc.get_findings(account_id=acct.account_id, severity="critical")
        assert all(f.severity == Severity.CRITICAL for f in critical)

    def test_get_findings_filter_resolved(self, svc_synced):
        svc, acct = svc_synced
        svc.run_security_scan(acct.account_id)
        unresolved = svc.get_findings(account_id=acct.account_id, is_resolved=False)
        assert all(not f.is_resolved for f in unresolved)

    def test_resolve_finding(self, svc_synced):
        svc, acct = svc_synced
        svc.run_security_scan(acct.account_id)
        findings = svc.get_findings(account_id=acct.account_id, is_resolved=False)
        if findings:
            resolved = svc.resolve_finding(findings[0].finding_id)
            assert resolved is not None
            assert resolved.is_resolved is True
            assert resolved.resolved_at is not None

    def test_resolve_finding_not_found(self, svc):
        assert svc.resolve_finding("NOPE") is None

    def test_get_security_posture(self, svc_synced):
        svc, acct = svc_synced
        posture = svc.get_security_posture(acct.account_id)
        assert "score" in posture
        assert "grade" in posture
        assert posture["score"] >= 0
        assert posture["score"] <= 100
        assert posture["grade"] in ["A", "B", "C", "D", "F"]

    def test_security_posture_perfect_when_no_findings(self, svc_with_account):
        svc, acct = svc_with_account
        posture = svc.get_security_posture(acct.account_id)
        assert posture["score"] == 100
        assert posture["grade"] == "A"


# ============================================================
# Alerts
# ============================================================

class TestAlerts:
    def test_create_alert(self, svc_with_account):
        svc, acct = svc_with_account
        alert = svc.create_alert(
            account_id=acct.account_id,
            alert_type="cost_spike",
            severity="high",
            title="Test Alert",
            description="Test description",
            threshold_value=1000.0,
            actual_value=1500.0,
        )
        assert alert.alert_id.startswith("ALR-")
        assert alert.alert_type == AlertType.COST_SPIKE
        assert alert.severity == Severity.HIGH
        assert not alert.is_acknowledged

    def test_get_alerts(self, svc_with_account):
        svc, acct = svc_with_account
        svc.create_alert(acct.account_id, "cost_spike", "high", "Alert 1")
        svc.create_alert(acct.account_id, "resource_down", "critical", "Alert 2")
        alerts = svc.get_alerts(account_id=acct.account_id)
        assert len(alerts) == 2

    def test_get_alerts_filter_type(self, svc_with_account):
        svc, acct = svc_with_account
        svc.create_alert(acct.account_id, "cost_spike", "high", "A1")
        svc.create_alert(acct.account_id, "resource_down", "critical", "A2")
        cost_alerts = svc.get_alerts(alert_type="cost_spike")
        assert all(a.alert_type == AlertType.COST_SPIKE for a in cost_alerts)

    def test_get_alerts_filter_acknowledged(self, svc_with_account):
        svc, acct = svc_with_account
        alert = svc.create_alert(acct.account_id, "anomaly", "medium", "A")
        svc.acknowledge_alert(alert.alert_id)
        unacked = svc.get_alerts(is_acknowledged=False)
        assert all(not a.is_acknowledged for a in unacked)

    def test_acknowledge_alert(self, svc_with_account):
        svc, acct = svc_with_account
        alert = svc.create_alert(acct.account_id, "anomaly", "low", "Test")
        acked = svc.acknowledge_alert(alert.alert_id)
        assert acked.is_acknowledged is True
        assert acked.acknowledged_at is not None

    def test_acknowledge_alert_not_found(self, svc):
        assert svc.acknowledge_alert("NOPE") is None


# ============================================================
# FinOps
# ============================================================

class TestFinOps:
    def test_get_optimization_recommendations(self, svc_synced):
        svc, acct = svc_synced
        result = svc.get_optimization_recommendations(acct.account_id)
        assert "total_potential_savings" in result
        assert "recommendations" in result
        assert isinstance(result["recommendations"], list)

    def test_recommendations_sorted_by_savings(self, svc_synced):
        svc, acct = svc_synced
        result = svc.get_optimization_recommendations(acct.account_id)
        recs = result["recommendations"]
        if len(recs) >= 2:
            assert recs[0]["potential_savings"] >= recs[1]["potential_savings"]


# ============================================================
# Dashboard & Multi-Cloud
# ============================================================

class TestDashboard:
    def test_get_multi_cloud_summary_empty(self, svc):
        summary = svc.get_multi_cloud_summary()
        assert summary["total_accounts"] == 0

    def test_get_multi_cloud_summary(self, svc):
        svc.register_account("C1", "aws", "AWS", "111", credentials_ref="x")
        svc.register_account("C1", "azure", "Azure", "222", credentials_ref="y")
        summary = svc.get_multi_cloud_summary()
        assert summary["total_accounts"] == 2
        assert "aws" in summary["by_provider"]
        assert "azure" in summary["by_provider"]

    def test_get_dashboard(self, svc_synced):
        svc, acct = svc_synced
        dashboard = svc.get_dashboard(acct.client_id)
        assert dashboard["client_id"] == acct.client_id
        assert "accounts" in dashboard
        assert "total_resources" in dashboard
        assert "total_monthly_cost" in dashboard
        assert "security_score" in dashboard
        assert dashboard["total_resources"] > 0

    def test_get_dashboard_empty_client(self, svc):
        dashboard = svc.get_dashboard("NOBODY")
        assert dashboard["total_resources"] == 0
        assert dashboard["security_score"] == 100


# ============================================================
# Enum Coverage
# ============================================================

class TestEnums:
    def test_cloud_provider_values(self):
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.AZURE.value == "azure"
        assert CloudProvider.GCP.value == "gcp"

    def test_resource_type_count(self):
        assert len(ResourceType) == 20

    def test_finding_type_count(self):
        assert len(FindingType) == 10

    def test_alert_type_values(self):
        assert AlertType.COST_SPIKE.value == "cost_spike"
        assert AlertType.RESOURCE_DOWN.value == "resource_down"

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"


# ============================================================
# Dataclass Construction
# ============================================================

class TestDataclasses:
    def test_cloud_account_defaults(self):
        acct = CloudAccount(
            account_id="CLD-TEST",
            client_id="C1",
            provider=CloudProvider.AWS,
            account_name="Test",
            account_identifier="111",
        )
        assert acct.status == AccountStatus.DISCONNECTED
        assert acct.resources_count == 0
        assert acct.monthly_cost == 0.0

    def test_cloud_resource_defaults(self):
        res = CloudResource(
            resource_id="RES-TEST",
            account_id="CLD-TEST",
            provider=CloudProvider.GCP,
            resource_type=ResourceType.COMPUTE_INSTANCE,
            resource_name="test-vm",
            resource_identifier="projects/x/instances/test-vm",
        )
        assert res.status == ResourceStatus.RUNNING
        assert res.tags == {}
        assert res.monthly_cost == 0.0

    def test_cloud_cost_entry_defaults(self):
        entry = CloudCostEntry(cost_id="CST-TEST", account_id="CLD-TEST", service_name="EC2")
        assert entry.currency == "USD"
        assert entry.cost_amount == 0.0

    def test_cloud_security_finding_defaults(self):
        finding = CloudSecurityFinding(finding_id="FND-TEST", account_id="CLD-TEST")
        assert finding.is_resolved is False
        assert finding.severity == Severity.MEDIUM

    def test_cloud_alert_defaults(self):
        alert = CloudAlert(alert_id="ALR-TEST", account_id="CLD-TEST")
        assert alert.is_acknowledged is False
        assert alert.alert_type == AlertType.ANOMALY


# ============================================================
# Multi-Provider Sync
# ============================================================

class TestMultiProvider:
    def test_azure_sync(self, svc):
        acct = svc.register_account("C1", "azure", "Azure Sub", "sub-123", credentials_ref="x")
        result = svc.sync_resources(acct.account_id)
        assert result["success"] is True
        assert result["provider"] == "azure"
        resources = svc.list_resources(account_id=acct.account_id)
        assert len(resources) > 0
        assert all(r.provider == CloudProvider.AZURE for r in resources)

    def test_gcp_sync(self, svc):
        acct = svc.register_account("C1", "gcp", "GCP Project", "proj-456", credentials_ref="y")
        result = svc.sync_resources(acct.account_id)
        assert result["success"] is True
        assert result["provider"] == "gcp"
        resources = svc.list_resources(account_id=acct.account_id)
        assert all(r.provider == CloudProvider.GCP for r in resources)

    def test_multi_cloud_dashboard_aggregation(self, svc):
        a1 = svc.register_account("C1", "aws", "AWS", "111", credentials_ref="x")
        a2 = svc.register_account("C1", "azure", "Azure", "222", credentials_ref="y")
        svc.sync_resources(a1.account_id)
        svc.sync_resources(a2.account_id)
        dashboard = svc.get_dashboard("C1")
        assert len(dashboard["accounts"]) == 2
        assert dashboard["total_resources"] > 0
        assert dashboard["total_monthly_cost"] > 0
