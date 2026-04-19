"""
Tests for FinOps / IT Cost Optimization Engine Service.
Full coverage: cost centers, entries, contracts, opportunities,
forecasts, alerts, analytics, and dashboard.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.finops_engine import (
    FinOpsEngineService,
    CostCenter,
    CostEntry,
    SavingsOpportunity,
    BudgetForecast,
    VendorContract,
    CostAlert,
    CostCategory,
    OpportunityCategory,
    EffortLevel,
    center_to_dict,
    entry_to_dict,
    opportunity_to_dict,
    forecast_to_dict,
    contract_to_dict,
    alert_to_dict,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def svc():
    """In-memory FinOpsEngineService."""
    return FinOpsEngineService()


@pytest.fixture
def populated_svc(svc):
    """Service with sample data pre-loaded."""
    # Create cost centers
    c1 = svc.create_center(
        client_id="CLIENT-001",
        name="Cloud Infrastructure",
        category=CostCategory.CLOUD.value,
        budget_monthly=5000.0,
        owner="John Doe",
        department="IT",
    )
    c2 = svc.create_center(
        client_id="CLIENT-001",
        name="Software Licenses",
        category=CostCategory.SOFTWARE.value,
        budget_monthly=3000.0,
        owner="Jane Smith",
        department="IT",
    )

    # Record costs
    svc.record_cost(
        center_id=c1.center_id,
        client_id="CLIENT-001",
        description="AWS EC2 Instances",
        vendor="AWS",
        amount=2500.0,
        period="2026-04",
        entry_type="recurring",
    )
    svc.record_cost(
        center_id=c1.center_id,
        client_id="CLIENT-001",
        description="Azure Storage",
        vendor="Microsoft",
        amount=800.0,
        period="2026-04",
        entry_type="usage_based",
    )
    svc.record_cost(
        center_id=c2.center_id,
        client_id="CLIENT-001",
        description="Microsoft 365",
        vendor="Microsoft",
        amount=1200.0,
        period="2026-04",
        entry_type="recurring",
    )

    # Add contracts
    svc.add_contract(
        client_id="CLIENT-001",
        vendor_name="Microsoft",
        service_description="Microsoft 365 E3",
        monthly_cost=1200.0,
        seats_purchased=100,
        seats_used=40,
        contract_end=datetime.now(timezone.utc) + timedelta(days=45),
        auto_renew=True,
    )
    svc.add_contract(
        client_id="CLIENT-001",
        vendor_name="Slack",
        service_description="Slack Business+",
        monthly_cost=600.0,
        seats_purchased=80,
        seats_used=75,
        contract_end=datetime.now(timezone.utc) + timedelta(days=200),
    )
    svc.add_contract(
        client_id="CLIENT-001",
        vendor_name="Zoom",
        service_description="Zoom Enterprise",
        monthly_cost=400.0,
        seats_purchased=50,
        seats_used=10,
        contract_end=datetime.now(timezone.utc) + timedelta(days=30),
    )

    return svc


# ============================================================
# Enum Tests
# ============================================================

class TestEnums:
    def test_cost_category_values(self):
        assert CostCategory.INFRASTRUCTURE == "infrastructure"
        assert CostCategory.SOFTWARE == "software"
        assert CostCategory.CLOUD == "cloud"
        assert CostCategory.TELECOM == "telecom"
        assert CostCategory.SECURITY == "security"
        assert CostCategory.BACKUP == "backup"
        assert CostCategory.OTHER == "other"

    def test_opportunity_category_values(self):
        assert OpportunityCategory.UNUSED_LICENSES == "unused_licenses"
        assert OpportunityCategory.RIGHTSIZING == "rightsizing"
        assert OpportunityCategory.CONSOLIDATION == "consolidation"
        assert OpportunityCategory.RENEGOTIATION == "renegotiation"
        assert OpportunityCategory.RESERVED_INSTANCES == "reserved_instances"

    def test_effort_level_values(self):
        assert EffortLevel.LOW == "low"
        assert EffortLevel.MEDIUM == "medium"
        assert EffortLevel.HIGH == "high"


# ============================================================
# Cost Center Tests
# ============================================================

class TestCostCenters:
    def test_create_center(self, svc):
        center = svc.create_center(
            client_id="C1",
            name="Cloud Infra",
            category="cloud",
            budget_monthly=5000.0,
            owner="Admin",
            department="IT",
        )
        assert center.center_id.startswith("CC-")
        assert center.client_id == "C1"
        assert center.name == "Cloud Infra"
        assert center.category == "cloud"
        assert center.budget_monthly == 5000.0

    def test_get_center(self, svc):
        center = svc.create_center(client_id="C1", name="Test")
        fetched = svc.get_center(center.center_id)
        assert fetched is not None
        assert fetched.center_id == center.center_id

    def test_get_center_not_found(self, svc):
        assert svc.get_center("NONEXISTENT") is None

    def test_list_centers(self, svc):
        svc.create_center(client_id="C1", name="A", category="cloud")
        svc.create_center(client_id="C1", name="B", category="software")
        svc.create_center(client_id="C2", name="C", category="cloud")

        all_centers = svc.list_centers()
        assert len(all_centers) == 3

        c1_centers = svc.list_centers(client_id="C1")
        assert len(c1_centers) == 2

        cloud_centers = svc.list_centers(category="cloud")
        assert len(cloud_centers) == 2

    def test_update_center(self, svc):
        center = svc.create_center(client_id="C1", name="Old Name")
        updated = svc.update_center(center.center_id, name="New Name", budget_monthly=9999.0)
        assert updated.name == "New Name"
        assert updated.budget_monthly == 9999.0

    def test_update_center_not_found(self, svc):
        assert svc.update_center("NONEXISTENT", name="Fail") is None


# ============================================================
# Cost Entry Tests
# ============================================================

class TestCostEntries:
    def test_record_cost(self, svc):
        center = svc.create_center(client_id="C1", name="Infra", budget_monthly=5000.0)
        entry = svc.record_cost(
            center_id=center.center_id,
            client_id="C1",
            description="Server hosting",
            vendor="AWS",
            amount=1500.0,
            period="2026-04",
            entry_type="recurring",
        )
        assert entry.entry_id.startswith("CE-")
        assert entry.amount == 1500.0
        assert entry.vendor == "AWS"

    def test_record_cost_updates_center_actual(self, svc):
        center = svc.create_center(client_id="C1", name="Infra", budget_monthly=5000.0)
        svc.record_cost(center_id=center.center_id, client_id="C1", amount=1000.0)
        svc.record_cost(center_id=center.center_id, client_id="C1", amount=2000.0)

        updated = svc.get_center(center.center_id)
        assert updated.actual_monthly == 3000.0
        assert updated.variance == 2000.0  # 5000 - 3000

    def test_get_costs_filters(self, svc):
        center = svc.create_center(client_id="C1", name="Infra")
        svc.record_cost(center_id=center.center_id, client_id="C1", vendor="AWS", period="2026-04")
        svc.record_cost(center_id=center.center_id, client_id="C1", vendor="Azure", period="2026-04")
        svc.record_cost(center_id=center.center_id, client_id="C1", vendor="AWS", period="2026-03")

        assert len(svc.get_costs(client_id="C1")) == 3
        assert len(svc.get_costs(vendor="AWS")) == 2
        assert len(svc.get_costs(period="2026-04")) == 2

    def test_get_cost_breakdown(self, populated_svc):
        breakdown = populated_svc.get_cost_breakdown("CLIENT-001")
        assert breakdown["total"] > 0
        assert "by_category" in breakdown
        assert "by_vendor" in breakdown
        assert breakdown["entry_count"] == 3


# ============================================================
# Vendor Contract Tests
# ============================================================

class TestVendorContracts:
    def test_add_contract(self, svc):
        contract = svc.add_contract(
            client_id="C1",
            vendor_name="Microsoft",
            service_description="M365",
            monthly_cost=1200.0,
            seats_purchased=100,
            seats_used=60,
        )
        assert contract.contract_id.startswith("VC-")
        assert contract.utilization_pct == 60.0
        assert contract.annual_cost == 14400.0

    def test_get_contracts(self, svc):
        svc.add_contract(client_id="C1", vendor_name="V1")
        svc.add_contract(client_id="C2", vendor_name="V2")
        assert len(svc.get_contracts()) == 2
        assert len(svc.get_contracts(client_id="C1")) == 1

    def test_update_contract(self, svc):
        c = svc.add_contract(client_id="C1", vendor_name="V1", seats_purchased=100, seats_used=50)
        updated = svc.update_contract(c.contract_id, seats_used=80)
        assert updated.seats_used == 80
        assert updated.utilization_pct == 80.0

    def test_update_contract_not_found(self, svc):
        assert svc.update_contract("NONEXISTENT", seats_used=1) is None

    def test_get_expiring_contracts(self, svc):
        svc.add_contract(
            client_id="C1",
            vendor_name="Expiring",
            contract_end=datetime.now(timezone.utc) + timedelta(days=30),
        )
        svc.add_contract(
            client_id="C1",
            vendor_name="Not Expiring",
            contract_end=datetime.now(timezone.utc) + timedelta(days=365),
        )
        expiring = svc.get_expiring_contracts(days=60)
        assert len(expiring) == 1
        assert expiring[0].vendor_name == "Expiring"

    def test_utilization_zero_seats(self, svc):
        c = svc.add_contract(client_id="C1", vendor_name="V", seats_purchased=0, seats_used=0)
        assert c.utilization_pct == 0.0

    def test_calculate_utilization(self, svc):
        assert svc._calculate_utilization_raw(100, 75) == 75.0
        assert svc._calculate_utilization_raw(0, 0) == 0.0
        assert svc._calculate_utilization_raw(200, 200) == 100.0


# ============================================================
# Savings Opportunity Tests
# ============================================================

class TestSavingsOpportunities:
    def test_identify_unused_licenses(self, populated_svc):
        opps = populated_svc._find_unused_licenses("CLIENT-001")
        # Microsoft at 40%, Zoom at 20% => both < 50%
        assert len(opps) >= 2
        for o in opps:
            assert o.category == "unused_licenses"
            assert o.estimated_monthly_savings > 0

    def test_identify_rightsizing(self, populated_svc):
        opps = populated_svc._find_rightsizing("CLIENT-001")
        # Cloud center has actual spending
        for o in opps:
            assert o.category == "rightsizing"

    def test_identify_consolidation(self, svc):
        svc.add_contract(client_id="C1", vendor_name="V1", service_description="email", monthly_cost=500)
        svc.add_contract(client_id="C1", vendor_name="V2", service_description="email", monthly_cost=300)
        opps = svc._find_consolidation("C1")
        assert len(opps) == 1
        assert opps[0].category == "consolidation"
        # total_cost(800) - cheapest(300) = 500
        assert opps[0].estimated_monthly_savings == 500.0

    def test_identify_contract_renegotiation(self, populated_svc):
        opps = populated_svc._find_contract_renegotiation("CLIENT-001")
        # Contracts expiring within 120 days
        assert len(opps) >= 1
        for o in opps:
            assert o.category == "renegotiation"

    def test_identify_all_opportunities(self, populated_svc):
        opps = populated_svc.identify_savings_opportunities("CLIENT-001")
        assert len(opps) > 0

    def test_get_opportunities(self, svc):
        svc._create_opportunity(
            client_id="C1", title="Test", description="Desc",
            category="unused_licenses", estimated_monthly_savings=100.0,
        )
        opps = svc.get_opportunities(client_id="C1")
        assert len(opps) == 1
        assert opps[0].estimated_annual_savings == 1200.0

    def test_update_opportunity_status(self, svc):
        opp = svc._create_opportunity(
            client_id="C1", title="Test", description="D",
            category="unused_licenses", estimated_monthly_savings=100.0,
        )
        updated = svc.update_opportunity_status(opp.opportunity_id, "in_progress")
        assert updated.status == "in_progress"

    def test_implement_opportunity(self, svc):
        opp = svc._create_opportunity(
            client_id="C1", title="Test", description="D",
            category="unused_licenses", estimated_monthly_savings=100.0,
        )
        implemented = svc.implement_opportunity(opp.opportunity_id)
        assert implemented.status == "implemented"
        assert implemented.implemented_at is not None

    def test_update_opportunity_not_found(self, svc):
        assert svc.update_opportunity_status("NONEXISTENT", "dismissed") is None


# ============================================================
# Budget Forecast Tests
# ============================================================

class TestBudgetForecasts:
    def test_create_forecast(self, svc):
        forecast = svc.create_forecast(
            client_id="C1",
            period="2026-04",
            category="cloud",
            forecasted_amount=5000.0,
        )
        assert forecast.forecast_id.startswith("BF-")
        assert forecast.forecasted_amount == 5000.0

    def test_get_forecasts(self, svc):
        svc.create_forecast(client_id="C1", period="2026-04")
        svc.create_forecast(client_id="C1", period="2026-05")
        svc.create_forecast(client_id="C2", period="2026-04")

        assert len(svc.get_forecasts()) == 3
        assert len(svc.get_forecasts(client_id="C1")) == 2
        assert len(svc.get_forecasts(period="2026-04")) == 2

    def test_compare_budget_to_actual(self, populated_svc):
        result = populated_svc.compare_budget_to_actual("CLIENT-001")
        assert result["client_id"] == "CLIENT-001"
        assert result["total_budget"] > 0
        assert len(result["centers"]) == 2

    def test_determine_trend(self, svc):
        entries = [CostEntry(entry_id=f"E{i}", center_id="C", client_id="X", amount=float(i * 100))
                   for i in range(1, 11)]
        assert svc._determine_trend(entries) == "increasing"

        entries_dec = [CostEntry(entry_id=f"E{i}", center_id="C", client_id="X", amount=float((11 - i) * 100))
                       for i in range(1, 11)]
        assert svc._determine_trend(entries_dec) == "decreasing"

        assert svc._determine_trend([]) == "stable"


# ============================================================
# Alert Tests
# ============================================================

class TestAlerts:
    def test_check_budgets_over(self, svc):
        center = svc.create_center(client_id="C1", name="Test", budget_monthly=1000.0)
        svc.record_cost(center_id=center.center_id, client_id="C1", amount=1500.0)
        alerts = svc.check_budgets()
        assert len(alerts) >= 1
        assert alerts[0].alert_type == "over_budget"
        assert alerts[0].severity == "high"

    def test_check_budgets_approaching(self, svc):
        center = svc.create_center(client_id="C1", name="Test", budget_monthly=1000.0)
        svc.record_cost(center_id=center.center_id, client_id="C1", amount=950.0)
        alerts = svc.check_budgets()
        assert len(alerts) >= 1
        assert alerts[0].severity == "medium"

    def test_generate_alerts(self, populated_svc):
        alerts = populated_svc.generate_alerts("CLIENT-001")
        # Should include contract expiry and unused service alerts
        alert_types = {a.alert_type for a in alerts}
        assert len(alerts) > 0
        # Zoom at 20% utilization should trigger unused_service
        assert "unused_service" in alert_types

    def test_acknowledge_alert(self, svc):
        alert = svc._create_alert(
            client_id="C1", alert_type="over_budget", title="Test Alert"
        )
        assert not alert.is_acknowledged
        ack = svc.acknowledge_alert(alert.alert_id)
        assert ack.is_acknowledged

    def test_acknowledge_not_found(self, svc):
        assert svc.acknowledge_alert("NONEXISTENT") is None

    def test_get_alerts_filters(self, svc):
        svc._create_alert(client_id="C1", alert_type="over_budget", title="A")
        svc._create_alert(client_id="C1", alert_type="contract_expiring", title="B")
        svc._create_alert(client_id="C2", alert_type="over_budget", title="C")

        assert len(svc.get_alerts()) == 3
        assert len(svc.get_alerts(client_id="C1")) == 2
        assert len(svc.get_alerts(alert_type="over_budget")) == 2
        assert len(svc.get_alerts(acknowledged=False)) == 3


# ============================================================
# Analytics Tests
# ============================================================

class TestAnalytics:
    def test_cost_trend(self, populated_svc):
        result = populated_svc.get_cost_trend("CLIENT-001")
        assert result["client_id"] == "CLIENT-001"
        assert "periods" in result
        assert "trend" in result

    def test_cost_per_endpoint(self, populated_svc):
        result = populated_svc.get_cost_per_endpoint("CLIENT-001")
        assert result["total_monthly_cost"] > 0
        assert result["cost_per_endpoint"] > 0

    def test_vendor_spend_analysis(self, populated_svc):
        result = populated_svc.get_vendor_spend_analysis(client_id="CLIENT-001")
        assert result["vendor_count"] >= 2
        assert result["total_monthly_spend"] > 0

    def test_category_breakdown(self, populated_svc):
        result = populated_svc.get_category_breakdown("CLIENT-001")
        assert result["total"] > 0
        assert len(result["categories"]) >= 1

    def test_yoy_comparison(self, populated_svc):
        result = populated_svc.get_yoy_comparison("CLIENT-001")
        assert "current_year" in result
        assert "previous_year" in result
        assert "change_pct" in result


# ============================================================
# Savings Totals Tests
# ============================================================

class TestSavingsTotals:
    def test_savings_implemented(self, svc):
        opp = svc._create_opportunity(
            client_id="C1", title="Impl", description="D",
            category="unused_licenses", estimated_monthly_savings=500.0,
        )
        svc.implement_opportunity(opp.opportunity_id)
        result = svc.get_total_savings_implemented(client_id="C1")
        assert result["monthly_savings"] == 500.0
        assert result["annual_savings"] == 6000.0
        assert result["count"] == 1

    def test_savings_available(self, svc):
        svc._create_opportunity(
            client_id="C1", title="Avail1", description="D",
            category="unused_licenses", estimated_monthly_savings=200.0,
        )
        svc._create_opportunity(
            client_id="C1", title="Avail2", description="D",
            category="rightsizing", estimated_monthly_savings=300.0,
        )
        result = svc.get_total_savings_available(client_id="C1")
        assert result["monthly_savings"] == 500.0
        assert result["count"] == 2


# ============================================================
# Dashboard Tests
# ============================================================

class TestDashboard:
    def test_dashboard(self, populated_svc):
        populated_svc.identify_savings_opportunities("CLIENT-001")
        dashboard = populated_svc.get_dashboard(client_id="CLIENT-001")

        assert dashboard["total_monthly_spend"] > 0
        assert "savings_implemented" in dashboard
        assert "savings_available" in dashboard
        assert "top_opportunities" in dashboard
        assert "budget_health" in dashboard
        assert "contracts" in dashboard
        assert dashboard["contracts"]["total"] >= 2

    def test_dashboard_no_data(self, svc):
        dashboard = svc.get_dashboard()
        assert dashboard["total_monthly_spend"] == 0.0
        assert dashboard["active_alerts"] == 0


# ============================================================
# Serialization Tests
# ============================================================

class TestSerialization:
    def test_center_to_dict(self):
        c = CostCenter(center_id="CC-1", client_id="C1", name="Test")
        d = center_to_dict(c)
        assert d["center_id"] == "CC-1"
        assert d["client_id"] == "C1"
        assert "created_at" in d

    def test_entry_to_dict(self):
        e = CostEntry(entry_id="CE-1", center_id="CC-1", client_id="C1", amount=100.0)
        d = entry_to_dict(e)
        assert d["entry_id"] == "CE-1"
        assert d["amount"] == 100.0

    def test_opportunity_to_dict(self):
        o = SavingsOpportunity(
            opportunity_id="SO-1", client_id="C1", title="Save",
            estimated_monthly_savings=100.0, estimated_annual_savings=1200.0,
        )
        d = opportunity_to_dict(o)
        assert d["opportunity_id"] == "SO-1"
        assert d["estimated_annual_savings"] == 1200.0

    def test_forecast_to_dict(self):
        f = BudgetForecast(forecast_id="BF-1", client_id="C1", period="2026-04")
        d = forecast_to_dict(f)
        assert d["forecast_id"] == "BF-1"
        assert d["period"] == "2026-04"

    def test_contract_to_dict(self):
        vc = VendorContract(
            contract_id="VC-1", client_id="C1", vendor_name="Microsoft",
            monthly_cost=500.0, seats_purchased=100, seats_used=60,
        )
        d = contract_to_dict(vc)
        assert d["contract_id"] == "VC-1"
        assert d["vendor_name"] == "Microsoft"

    def test_alert_to_dict(self):
        a = CostAlert(alert_id="CA-1", client_id="C1", alert_type="over_budget", title="Over")
        d = alert_to_dict(a)
        assert d["alert_id"] == "CA-1"
        assert d["alert_type"] == "over_budget"
        assert d["is_acknowledged"] is False
