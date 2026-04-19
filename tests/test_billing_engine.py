"""
Tests for MSP Billing Engine Service
Full coverage for plans, accounts, invoices, usage, payments, and analytics.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.billing_engine import (
    BillingEngineService,
    BillingModel,
    BillingCycle,
    AccountStatus,
    InvoiceStatus,
    LineItemType,
    PaymentStatus,
    BillingPlan,
    BillingAccount,
    Invoice,
    LineItem,
    UsageRecord,
    PaymentRecord,
    plan_to_dict,
    account_to_dict,
    invoice_to_dict,
    usage_to_dict,
    payment_to_dict,
)


class TestBillingEngineService:
    """Tests for BillingEngineService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = BillingEngineService()

    # ========== Plan Management Tests ==========

    def test_default_plans_seeded(self):
        """Test that default pricing tiers are pre-populated"""
        plans = self.service.list_plans()
        assert len(plans) >= 6
        names = [p.name for p in plans]
        assert "Starter" in names
        assert "Professional" in names
        assert "Enterprise" in names
        assert "Shield Consumer - Personal" in names
        assert "Shield Consumer - Family" in names
        assert "Shield Consumer - Pro" in names

    def test_starter_plan_pricing(self):
        """Test Starter plan has correct pricing"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        assert starter.per_unit_price == 2.50
        assert starter.included_units == 100
        assert starter.overage_price == 3.00
        assert starter.billing_model == "per_endpoint"

    def test_professional_plan_pricing(self):
        """Test Professional plan has correct pricing"""
        plans = self.service.list_plans()
        pro = next(p for p in plans if p.name == "Professional")
        assert pro.per_unit_price == 4.00
        assert pro.included_units == 500
        assert pro.overage_price == 4.50

    def test_enterprise_plan_pricing(self):
        """Test Enterprise plan has correct pricing"""
        plans = self.service.list_plans()
        ent = next(p for p in plans if p.name == "Enterprise")
        assert ent.per_unit_price == 6.00
        assert ent.included_units == 999999
        assert ent.overage_price == 0.0

    def test_shield_personal_pricing(self):
        """Test Shield Consumer Personal pricing"""
        plans = self.service.list_plans()
        personal = next(p for p in plans if p.name == "Shield Consumer - Personal")
        assert personal.base_price == 4.99
        assert personal.billing_model == "per_user"

    def test_shield_family_pricing(self):
        """Test Shield Consumer Family pricing"""
        plans = self.service.list_plans()
        family = next(p for p in plans if p.name == "Shield Consumer - Family")
        assert family.base_price == 9.99
        assert family.included_units == 5

    def test_shield_pro_pricing(self):
        """Test Shield Consumer Pro pricing"""
        plans = self.service.list_plans()
        pro = next(p for p in plans if p.name == "Shield Consumer - Pro")
        assert pro.base_price == 14.99

    def test_create_custom_plan(self):
        """Test creating a custom billing plan"""
        plan = self.service.create_plan(
            name="Custom MSP",
            description="Custom plan for testing",
            billing_model="per_endpoint",
            base_price=100.0,
            per_unit_price=5.00,
            included_units=200,
            overage_price=6.00,
            billing_cycle="monthly",
            features=["monitoring", "patching"],
        )

        assert plan is not None
        assert plan.plan_id.startswith("PLN-")
        assert plan.name == "Custom MSP"
        assert plan.base_price == 100.0
        assert plan.per_unit_price == 5.00
        assert plan.included_units == 200
        assert plan.overage_price == 6.00
        assert "monitoring" in plan.features
        assert plan.is_active is True

    def test_update_plan(self):
        """Test updating a billing plan"""
        plan = self.service.create_plan(
            name="Test Plan",
            per_unit_price=3.00,
        )
        updated = self.service.update_plan(plan.plan_id, per_unit_price=3.50, description="Updated")
        assert updated is not None
        assert updated.per_unit_price == 3.50
        assert updated.description == "Updated"

    def test_update_plan_not_found(self):
        """Test updating a non-existent plan returns None"""
        result = self.service.update_plan("PLN-NONEXIST", name="Nope")
        assert result is None

    def test_get_plan(self):
        """Test retrieving a specific plan"""
        plan = self.service.create_plan(name="Lookup Test")
        found = self.service.get_plan(plan.plan_id)
        assert found is not None
        assert found.name == "Lookup Test"

    def test_get_plan_not_found(self):
        """Test retrieving a non-existent plan"""
        result = self.service.get_plan("PLN-DOESNOTEXIST")
        assert result is None

    def test_list_plans_active_only(self):
        """Test filtering plans by active status"""
        plan = self.service.create_plan(name="Inactive Plan", is_active=False)
        active_plans = self.service.list_plans(active_only=True)
        inactive_ids = [p.plan_id for p in active_plans]
        assert plan.plan_id not in inactive_ids

    # ========== Account Management Tests ==========

    def test_create_account(self):
        """Test creating a billing account"""
        plans = self.service.list_plans()
        plan = plans[0]

        acct = self.service.create_account(
            tenant_id="TENANT-001",
            company_name="Acme Corp",
            plan_id=plan.plan_id,
            billing_email="billing@acme.com",
            billing_address="123 Main St",
        )

        assert acct is not None
        assert acct.account_id.startswith("ACCT-")
        assert acct.tenant_id == "TENANT-001"
        assert acct.company_name == "Acme Corp"
        assert acct.plan_id == plan.plan_id
        assert acct.status == "active"
        assert acct.next_billing_date is not None

    def test_update_account(self):
        """Test updating a billing account"""
        plans = self.service.list_plans()
        acct = self.service.create_account(
            tenant_id="TENANT-002",
            company_name="Beta Inc",
            plan_id=plans[0].plan_id,
        )

        updated = self.service.update_account(acct.account_id, company_name="Beta Corp", billing_email="new@beta.com")
        assert updated is not None
        assert updated.company_name == "Beta Corp"
        assert updated.billing_email == "new@beta.com"

    def test_update_account_not_found(self):
        """Test updating a non-existent account"""
        result = self.service.update_account("ACCT-NONEXIST", company_name="Nope")
        assert result is None

    def test_get_account(self):
        """Test retrieving a specific account"""
        plans = self.service.list_plans()
        acct = self.service.create_account(
            tenant_id="TENANT-003",
            company_name="Gamma LLC",
            plan_id=plans[0].plan_id,
        )

        found = self.service.get_account(acct.account_id)
        assert found is not None
        assert found.company_name == "Gamma LLC"

    def test_get_account_not_found(self):
        """Test retrieving a non-existent account"""
        result = self.service.get_account("ACCT-DOESNOTEXIST")
        assert result is None

    def test_list_accounts(self):
        """Test listing all accounts"""
        plans = self.service.list_plans()
        self.service.create_account(tenant_id="T-1", company_name="A", plan_id=plans[0].plan_id)
        self.service.create_account(tenant_id="T-2", company_name="B", plan_id=plans[0].plan_id)

        accounts = self.service.list_accounts()
        assert len(accounts) >= 2

    def test_list_accounts_by_status(self):
        """Test listing accounts filtered by status"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-S", company_name="Suspended Co", plan_id=plans[0].plan_id)
        self.service.suspend_account(acct.account_id)

        suspended = self.service.list_accounts(status="suspended")
        assert any(a.account_id == acct.account_id for a in suspended)

    def test_suspend_account(self):
        """Test suspending an account"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-X", company_name="Suspend Me", plan_id=plans[0].plan_id)
        result = self.service.suspend_account(acct.account_id)
        assert result is not None
        assert result.status == "suspended"

    def test_reactivate_account(self):
        """Test reactivating a suspended account"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-R", company_name="Reactivate Me", plan_id=plans[0].plan_id)
        self.service.suspend_account(acct.account_id)
        result = self.service.reactivate_account(acct.account_id)
        assert result is not None
        assert result.status == "active"

    # ========== Usage Tracking Tests ==========

    def test_record_usage_endpoints(self):
        """Test recording endpoint usage"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-U1", company_name="Usage Test", plan_id=plans[0].plan_id)

        rec = self.service.record_usage(acct.account_id, "endpoints", 150)
        assert rec is not None
        assert rec.record_id.startswith("USG-")
        assert rec.metric == "endpoints"
        assert rec.count == 150

        # Account should be updated
        updated_acct = self.service.get_account(acct.account_id)
        assert updated_acct.current_endpoints == 150

    def test_record_usage_users(self):
        """Test recording user usage"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-U2", company_name="User Test", plan_id=plans[0].plan_id)

        rec = self.service.record_usage(acct.account_id, "users", 25)
        assert rec.metric == "users"
        assert rec.count == 25

        updated_acct = self.service.get_account(acct.account_id)
        assert updated_acct.current_users == 25

    def test_get_usage(self):
        """Test retrieving usage records"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-U3", company_name="GetUsage", plan_id=plans[0].plan_id)

        self.service.record_usage(acct.account_id, "endpoints", 100)
        self.service.record_usage(acct.account_id, "scans", 50)

        all_records = self.service.get_usage(acct.account_id)
        assert len(all_records) == 2

        endpoint_records = self.service.get_usage(acct.account_id, metric="endpoints")
        assert len(endpoint_records) == 1
        assert endpoint_records[0].metric == "endpoints"

    # ========== Invoice Generation Tests ==========

    def test_generate_invoice_basic(self):
        """Test basic invoice generation"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-I1", company_name="Invoice Test", plan_id=starter.plan_id)

        # Record 80 endpoints (within included 100)
        self.service.record_usage(acct.account_id, "endpoints", 80)

        inv = self.service.generate_invoice(acct.account_id)
        assert inv is not None
        assert inv.invoice_id.startswith("INV-")
        assert inv.account_id == acct.account_id
        assert inv.status == "draft"
        assert inv.subtotal == 80 * 2.50  # 80 endpoints at $2.50
        assert inv.total == 200.0
        assert inv.due_date is not None
        assert len(inv.line_items) >= 1

    def test_generate_invoice_with_overage(self):
        """Test invoice generation with overage charges"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-I2", company_name="Overage Test", plan_id=starter.plan_id)

        # Record 120 endpoints (20 over the 100 included)
        self.service.record_usage(acct.account_id, "endpoints", 120)

        inv = self.service.generate_invoice(acct.account_id)
        assert inv is not None
        # 100 included at $2.50 + 20 overage at $3.00
        expected = (100 * 2.50) + (20 * 3.00)
        assert inv.subtotal == expected
        assert inv.total == expected

        # Should have line items for included + overage
        overage_items = [li for li in inv.line_items if li.get("item_type") == "overage"]
        assert len(overage_items) == 1
        assert overage_items[0]["quantity"] == 20

    def test_generate_invoice_nonexistent_account(self):
        """Test invoice generation with non-existent account"""
        result = self.service.generate_invoice("ACCT-NOEXIST")
        assert result is None

    def test_generate_invoice_with_discount(self):
        """Test invoice generation with account discount"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-I3", company_name="Discount Test", plan_id=starter.plan_id)

        self.service.record_usage(acct.account_id, "endpoints", 100)
        self.service.apply_discount(acct.account_id, percentage=10.0, reason="Loyalty")

        inv = self.service.generate_invoice(acct.account_id)
        assert inv is not None
        assert inv.subtotal == 100 * 2.50
        assert inv.discount == 25.0  # 10% of $250
        assert inv.total == 225.0

    def test_generate_invoice_shield_user_plan(self):
        """Test invoice generation for per-user Shield plan"""
        plans = self.service.list_plans()
        personal = next(p for p in plans if p.name == "Shield Consumer - Personal")
        acct = self.service.create_account(tenant_id="T-I4", company_name="Shield User", plan_id=personal.plan_id)

        self.service.record_usage(acct.account_id, "users", 1)

        inv = self.service.generate_invoice(acct.account_id)
        assert inv is not None
        # base_price $4.99 + 1 user at $4.99
        assert inv.subtotal == 4.99 + (1 * 4.99)

    # ========== Invoice CRUD Tests ==========

    def test_get_invoice(self):
        """Test retrieving a specific invoice"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-GI", company_name="Get Inv", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)

        inv = self.service.generate_invoice(acct.account_id)
        found = self.service.get_invoice(inv.invoice_id)
        assert found is not None
        assert found.invoice_id == inv.invoice_id

    def test_get_invoice_not_found(self):
        """Test retrieving a non-existent invoice"""
        result = self.service.get_invoice("INV-NOEXIST")
        assert result is None

    def test_list_invoices(self):
        """Test listing invoices"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-LI", company_name="List Inv", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)
        self.service.generate_invoice(acct.account_id)
        self.service.generate_invoice(acct.account_id)

        invoices = self.service.list_invoices(account_id=acct.account_id)
        assert len(invoices) >= 2

    def test_list_invoices_by_status(self):
        """Test listing invoices filtered by status"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-LIS", company_name="Status Inv", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)
        self.service.generate_invoice(acct.account_id)

        drafts = self.service.list_invoices(status="draft")
        assert len(drafts) >= 1

    def test_void_invoice(self):
        """Test voiding an invoice"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-VI", company_name="Void Inv", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)

        inv = self.service.generate_invoice(acct.account_id)
        voided = self.service.void_invoice(inv.invoice_id)
        assert voided is not None
        assert voided.status == "void"

    def test_mark_paid(self):
        """Test marking an invoice as paid"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-MP", company_name="Mark Paid", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)

        inv = self.service.generate_invoice(acct.account_id)
        paid = self.service.mark_paid(inv.invoice_id, payment_reference="CHK-12345")
        assert paid is not None
        assert paid.status == "paid"
        assert paid.paid_at is not None
        assert paid.payment_reference == "CHK-12345"

    # ========== Payment Tests ==========

    def test_record_payment(self):
        """Test recording a payment"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-PAY", company_name="Pay Test", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)

        inv = self.service.generate_invoice(acct.account_id)
        payment = self.service.record_payment(
            account_id=acct.account_id,
            invoice_id=inv.invoice_id,
            amount=inv.total,
            method="card",
        )

        assert payment is not None
        assert payment.payment_id.startswith("PAY-")
        assert payment.amount == inv.total
        assert payment.method == "card"
        assert payment.status == "completed"
        assert payment.processed_at is not None

        # Invoice should be marked paid
        paid_inv = self.service.get_invoice(inv.invoice_id)
        assert paid_inv.status == "paid"

    def test_payment_reactivates_past_due(self):
        """Test that payment reactivates a past-due account"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-PDR", company_name="Past Due", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)
        self.service.update_account(acct.account_id, status="past_due")

        inv = self.service.generate_invoice(acct.account_id)
        self.service.record_payment(
            account_id=acct.account_id,
            invoice_id=inv.invoice_id,
            amount=inv.total,
        )

        updated = self.service.get_account(acct.account_id)
        assert updated.status == "active"

    # ========== Revenue Analytics Tests ==========

    def test_calculate_mrr(self):
        """Test MRR calculation"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-MRR", company_name="MRR Test", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)

        mrr = self.service.calculate_mrr()
        assert mrr > 0
        # 50 endpoints at $2.50 = $125
        assert mrr >= 125.0

    def test_calculate_arr(self):
        """Test ARR calculation"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-ARR", company_name="ARR Test", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)

        arr = self.service.calculate_arr()
        mrr = self.service.calculate_mrr()
        assert arr == round(mrr * 12, 2)

    def test_get_revenue_forecast(self):
        """Test revenue forecasting"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-FC", company_name="Forecast Test", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 100)

        forecast = self.service.get_revenue_forecast(months=6)
        assert len(forecast) == 6
        assert forecast[0]["month"] == 1
        assert forecast[-1]["month"] == 6
        assert forecast[0]["projected_mrr"] > 0
        assert forecast[-1]["cumulative_revenue"] > forecast[0]["cumulative_revenue"]

    def test_get_churn_rate_no_churn(self):
        """Test churn rate with no cancelled accounts"""
        plans = self.service.list_plans()
        self.service.create_account(tenant_id="T-NC", company_name="No Churn", plan_id=plans[0].plan_id)

        rate = self.service.get_churn_rate()
        assert rate == 0.0

    def test_get_churn_rate_with_churn(self):
        """Test churn rate with cancelled accounts"""
        plans = self.service.list_plans()
        acct1 = self.service.create_account(tenant_id="T-C1", company_name="Active", plan_id=plans[0].plan_id)
        acct2 = self.service.create_account(tenant_id="T-C2", company_name="Cancelled", plan_id=plans[0].plan_id)
        self.service.update_account(acct2.account_id, status="cancelled")

        rate = self.service.get_churn_rate()
        assert rate > 0
        # 1 cancelled out of 2 = 50%
        assert rate == 50.0

    def test_get_arpa(self):
        """Test Average Revenue Per Account"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")

        acct1 = self.service.create_account(tenant_id="T-A1", company_name="ARPA A", plan_id=starter.plan_id)
        acct2 = self.service.create_account(tenant_id="T-A2", company_name="ARPA B", plan_id=starter.plan_id)
        self.service.record_usage(acct1.account_id, "endpoints", 100)
        self.service.record_usage(acct2.account_id, "endpoints", 100)

        arpa = self.service.get_arpa()
        assert arpa > 0

    def test_get_arpa_no_accounts(self):
        """Test ARPA with no accounts returns 0"""
        # Fresh service with no accounts added (only default plans)
        service = BillingEngineService()
        arpa = service.get_arpa()
        assert arpa == 0.0

    def test_get_billing_dashboard(self):
        """Test billing dashboard data"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        pro = next(p for p in plans if p.name == "Professional")

        acct1 = self.service.create_account(tenant_id="T-D1", company_name="Dash A", plan_id=starter.plan_id)
        acct2 = self.service.create_account(tenant_id="T-D2", company_name="Dash B", plan_id=pro.plan_id)
        self.service.record_usage(acct1.account_id, "endpoints", 80)
        self.service.record_usage(acct2.account_id, "endpoints", 200)

        dashboard = self.service.get_billing_dashboard()
        assert "mrr" in dashboard
        assert "arr" in dashboard
        assert "churn_rate" in dashboard
        assert "arpa" in dashboard
        assert "total_accounts" in dashboard
        assert "active_accounts" in dashboard
        assert "total_endpoints" in dashboard
        assert "revenue_by_plan" in dashboard
        assert dashboard["mrr"] > 0
        assert dashboard["total_endpoints"] == 280
        assert dashboard["active_accounts"] >= 2

    def test_check_overdue_invoices(self):
        """Test overdue invoice detection"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-OD", company_name="Overdue", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)

        inv = self.service.generate_invoice(acct.account_id)
        # Manually set due date to the past
        inv.due_date = datetime.now(timezone.utc) - timedelta(days=5)
        # Update in memory store
        self.service._invoices[inv.invoice_id] = inv

        overdue = self.service.check_overdue_invoices()
        assert len(overdue) >= 1

        # Account should be flagged past_due
        updated = self.service.get_account(acct.account_id)
        assert updated.status == "past_due"

    # ========== Discount Tests ==========

    def test_apply_discount(self):
        """Test applying a discount to an account"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-DC", company_name="Discount Co", plan_id=plans[0].plan_id)

        expires = datetime.now(timezone.utc) + timedelta(days=90)
        result = self.service.apply_discount(acct.account_id, percentage=15.0, reason="Early adopter", expires_at=expires)
        assert result is not None
        assert result.discount_percentage == 15.0
        assert result.discount_reason == "Early adopter"
        assert result.discount_expires_at is not None

    def test_apply_discount_not_found(self):
        """Test applying discount to non-existent account"""
        result = self.service.apply_discount("ACCT-NOEXIST", percentage=10.0)
        assert result is None

    # ========== Serialization Tests ==========

    def test_plan_to_dict(self):
        """Test plan serialization"""
        plan = self.service.create_plan(name="Serialize Plan", per_unit_price=5.0)
        d = plan_to_dict(plan)
        assert d["name"] == "Serialize Plan"
        assert d["per_unit_price"] == 5.0
        assert "plan_id" in d
        assert "created_at" in d

    def test_account_to_dict(self):
        """Test account serialization"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-SD", company_name="Serialize", plan_id=plans[0].plan_id)
        d = account_to_dict(acct)
        assert d["company_name"] == "Serialize"
        assert d["status"] == "active"
        assert "account_id" in d

    def test_invoice_to_dict(self):
        """Test invoice serialization"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-SI", company_name="Serialize Inv", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)
        inv = self.service.generate_invoice(acct.account_id)
        d = invoice_to_dict(inv)
        assert d["status"] == "draft"
        assert d["total"] > 0
        assert "invoice_id" in d

    def test_usage_to_dict(self):
        """Test usage record serialization"""
        plans = self.service.list_plans()
        acct = self.service.create_account(tenant_id="T-SU", company_name="Serialize Usage", plan_id=plans[0].plan_id)
        rec = self.service.record_usage(acct.account_id, "endpoints", 42)
        d = usage_to_dict(rec)
        assert d["metric"] == "endpoints"
        assert d["count"] == 42

    def test_payment_to_dict(self):
        """Test payment record serialization"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-SP", company_name="Serialize Pay", plan_id=starter.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 50)
        inv = self.service.generate_invoice(acct.account_id)
        pay = self.service.record_payment(acct.account_id, inv.invoice_id, inv.total, "card")
        d = payment_to_dict(pay)
        assert d["status"] == "completed"
        assert d["amount"] > 0

    # ========== Enum Tests ==========

    def test_billing_model_enum(self):
        """Test BillingModel enum values"""
        assert BillingModel.PER_ENDPOINT == "per_endpoint"
        assert BillingModel.PER_USER == "per_user"
        assert BillingModel.PER_DEVICE == "per_device"
        assert BillingModel.FLAT == "flat"

    def test_billing_cycle_enum(self):
        """Test BillingCycle enum values"""
        assert BillingCycle.MONTHLY == "monthly"
        assert BillingCycle.ANNUAL == "annual"

    def test_account_status_enum(self):
        """Test AccountStatus enum values"""
        assert AccountStatus.ACTIVE == "active"
        assert AccountStatus.SUSPENDED == "suspended"
        assert AccountStatus.CANCELLED == "cancelled"
        assert AccountStatus.PAST_DUE == "past_due"

    def test_invoice_status_enum(self):
        """Test InvoiceStatus enum values"""
        assert InvoiceStatus.DRAFT == "draft"
        assert InvoiceStatus.SENT == "sent"
        assert InvoiceStatus.PAID == "paid"
        assert InvoiceStatus.OVERDUE == "overdue"
        assert InvoiceStatus.VOID == "void"

    def test_line_item_type_enum(self):
        """Test LineItemType enum values"""
        assert LineItemType.BASE == "base"
        assert LineItemType.ENDPOINT == "endpoint"
        assert LineItemType.USER == "user"
        assert LineItemType.OVERAGE == "overage"
        assert LineItemType.ADDON == "addon"

    def test_payment_status_enum(self):
        """Test PaymentStatus enum values"""
        assert PaymentStatus.PENDING == "pending"
        assert PaymentStatus.COMPLETED == "completed"
        assert PaymentStatus.FAILED == "failed"
        assert PaymentStatus.REFUNDED == "refunded"

    # ========== Edge Case Tests ==========

    def test_enterprise_no_overage(self):
        """Test Enterprise plan generates no overage even with high count"""
        plans = self.service.list_plans()
        enterprise = next(p for p in plans if p.name == "Enterprise")
        acct = self.service.create_account(tenant_id="T-ENT", company_name="BigCorp", plan_id=enterprise.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 10000)

        inv = self.service.generate_invoice(acct.account_id)
        assert inv is not None
        overage_items = [li for li in inv.line_items if li.get("item_type") == "overage"]
        assert len(overage_items) == 0

    def test_flat_plan_no_unit_charges(self):
        """Test flat billing model has no unit-based charges"""
        plan = self.service.create_plan(
            name="Flat Test",
            billing_model="flat",
            base_price=500.0,
        )
        acct = self.service.create_account(tenant_id="T-FLT", company_name="Flat Co", plan_id=plan.plan_id)
        self.service.record_usage(acct.account_id, "endpoints", 999)

        inv = self.service.generate_invoice(acct.account_id)
        assert inv is not None
        assert inv.total == 500.0

    def test_zero_usage_invoice(self):
        """Test invoice with zero usage"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-ZU", company_name="Zero", plan_id=starter.plan_id)

        inv = self.service.generate_invoice(acct.account_id)
        assert inv is not None
        assert inv.total == 0.0

    def test_multiple_usage_updates(self):
        """Test multiple usage recordings update to latest count"""
        plans = self.service.list_plans()
        starter = next(p for p in plans if p.name == "Starter")
        acct = self.service.create_account(tenant_id="T-MU", company_name="Multi Usage", plan_id=starter.plan_id)

        self.service.record_usage(acct.account_id, "endpoints", 50)
        self.service.record_usage(acct.account_id, "endpoints", 75)
        self.service.record_usage(acct.account_id, "endpoints", 120)

        updated = self.service.get_account(acct.account_id)
        assert updated.current_endpoints == 120

    def test_revenue_forecast_length(self):
        """Test forecast returns correct number of months"""
        forecast = self.service.get_revenue_forecast(months=24)
        assert len(forecast) == 24

    def test_churn_rate_empty(self):
        """Test churn rate with no accounts"""
        service = BillingEngineService()
        rate = service.get_churn_rate()
        assert rate == 0.0
