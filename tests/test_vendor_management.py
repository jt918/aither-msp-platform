"""
Tests for Vendor Management Service
Full coverage: vendor CRUD, contract lifecycle, reviews, procurement workflow,
risk management, analytics, and dashboard.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.vendor_management import (
    VendorManagementService,
    VendorCategory,
    VendorStatus,
    ContractType,
    ContractStatus,
    ProcurementStatus,
    RiskType,
    RiskSeverity,
    RiskStatus,
    _vendor_to_dict,
    _contract_to_dict,
    _review_to_dict,
    _procurement_to_dict,
    _risk_to_dict,
)


@pytest.fixture
def svc():
    """Fresh VendorManagementService instance (in-memory mode)."""
    return VendorManagementService()


@pytest.fixture
def svc_with_vendor(svc):
    """Service with one vendor already created."""
    svc.create_vendor(
        name="Acme Cloud Inc",
        category=VendorCategory.CLOUD.value,
        contact_name="Jane Doe",
        contact_email="jane@acmecloud.com",
        contact_phone="555-0100",
        website="https://acmecloud.com",
        account_number="ACC-12345",
        account_rep="John Rep",
        payment_terms="net30",
    )
    return svc


@pytest.fixture
def svc_with_data(svc):
    """Service with vendors, contracts, reviews, procurement, and risks."""
    v1 = svc.create_vendor(name="CloudPro", category="cloud", total_spend_ytd=50000.0)
    v2 = svc.create_vendor(name="SecureTech", category="security", total_spend_ytd=30000.0)
    v3 = svc.create_vendor(name="HardCorp", category="hardware", total_spend_ytd=20000.0)
    # Contracts
    svc.create_contract(
        v1.vendor_id, "Cloud Hosting", "subscription",
        client_id="CLIENT-001", value_monthly=2000.0, value_annual=24000.0,
        start_date=datetime.now(timezone.utc) - timedelta(days=180),
        end_date=datetime.now(timezone.utc) + timedelta(days=15),
        status=ContractStatus.ACTIVE.value,
    )
    svc.create_contract(
        v2.vendor_id, "Security Suite", "license",
        client_id="CLIENT-001", value_monthly=1500.0, value_annual=18000.0,
        start_date=datetime.now(timezone.utc) - timedelta(days=90),
        end_date=datetime.now(timezone.utc) + timedelta(days=90),
        status=ContractStatus.ACTIVE.value,
    )
    svc.create_contract(
        v1.vendor_id, "Backup Service", "subscription",
        client_id="CLIENT-002", value_monthly=500.0, value_annual=6000.0,
        start_date=datetime.now(timezone.utc) - timedelta(days=30),
        end_date=datetime.now(timezone.utc) + timedelta(days=335),
        status=ContractStatus.ACTIVE.value,
    )
    return svc


# ============================================================
# Vendor CRUD
# ============================================================

class TestVendorCRUD:
    def test_create_vendor(self, svc):
        vendor = svc.create_vendor(name="TestVendor", category="software")
        assert vendor.vendor_id.startswith("VND-")
        assert vendor.name == "TestVendor"
        assert vendor.category == "software"
        assert vendor.status == "active"

    def test_create_vendor_all_fields(self, svc):
        vendor = svc.create_vendor(
            name="Full Vendor", category="telecom",
            contact_name="Bob", contact_email="bob@vendor.com",
            contact_phone="555-1234", website="https://vendor.com",
            account_number="V-999", account_rep="Alice",
            risk_tier="medium", payment_terms="net60", notes="Important vendor",
        )
        assert vendor.contact_name == "Bob"
        assert vendor.contact_email == "bob@vendor.com"
        assert vendor.risk_tier == "medium"
        assert vendor.payment_terms == "net60"

    def test_get_vendor(self, svc):
        v = svc.create_vendor(name="GetMe")
        fetched = svc.get_vendor(v.vendor_id)
        assert fetched is not None
        assert fetched.name == "GetMe"

    def test_get_vendor_not_found(self, svc):
        assert svc.get_vendor("NONEXISTENT") is None

    def test_update_vendor(self, svc):
        v = svc.create_vendor(name="Original")
        updated = svc.update_vendor(v.vendor_id, name="Updated", risk_tier="high")
        assert updated.name == "Updated"
        assert updated.risk_tier == "high"

    def test_update_vendor_not_found(self, svc):
        assert svc.update_vendor("NONEXISTENT", name="X") is None

    def test_delete_vendor(self, svc):
        v = svc.create_vendor(name="ToDelete")
        assert svc.delete_vendor(v.vendor_id) is True
        assert svc.get_vendor(v.vendor_id) is None

    def test_delete_vendor_not_found(self, svc):
        assert svc.delete_vendor("NONEXISTENT") is False

    def test_list_vendors(self, svc):
        svc.create_vendor(name="V1", category="software")
        svc.create_vendor(name="V2", category="hardware")
        svc.create_vendor(name="V3", category="software")
        assert len(svc.list_vendors()) == 3
        assert len(svc.list_vendors(category="software")) == 2
        assert len(svc.list_vendors(category="hardware")) == 1

    def test_list_vendors_by_status(self, svc):
        svc.create_vendor(name="Active1")
        svc.create_vendor(name="Blocked1", status="blocked")
        assert len(svc.list_vendors(status="active")) == 1
        assert len(svc.list_vendors(status="blocked")) == 1

    def test_search_vendors(self, svc):
        svc.create_vendor(name="Acme Cloud Services")
        svc.create_vendor(name="TechCorp Solutions")
        svc.create_vendor(name="Acme Security")
        results = svc.search_vendors("Acme")
        assert len(results) == 2

    def test_search_vendors_case_insensitive(self, svc):
        svc.create_vendor(name="CloudPro Inc")
        results = svc.search_vendors("cloudpro")
        assert len(results) == 1


# ============================================================
# Vendor serialisation
# ============================================================

class TestVendorSerialisation:
    def test_vendor_to_dict(self, svc):
        v = svc.create_vendor(name="Serialise Me", category="cloud")
        d = _vendor_to_dict(v)
        assert d["name"] == "Serialise Me"
        assert d["category"] == "cloud"
        assert "vendor_id" in d
        assert "created_at" in d


# ============================================================
# Contract CRUD
# ============================================================

class TestContractCRUD:
    def test_create_contract(self, svc_with_vendor):
        vendors = svc_with_vendor.list_vendors()
        vid = vendors[0].vendor_id
        contract = svc_with_vendor.create_contract(
            vid, "Cloud Hosting", "subscription",
            value_monthly=2000.0, value_annual=24000.0,
        )
        assert contract.contract_id.startswith("VCTR-")
        assert contract.vendor_id == vid
        assert contract.title == "Cloud Hosting"
        assert contract.value_annual == 24000.0

    def test_get_contract(self, svc):
        v = svc.create_vendor(name="V1")
        c = svc.create_contract(v.vendor_id, "Test Contract")
        fetched = svc.get_contract(c.contract_id)
        assert fetched is not None
        assert fetched.title == "Test Contract"

    def test_get_contract_not_found(self, svc):
        assert svc.get_contract("NONEXISTENT") is None

    def test_update_contract(self, svc):
        v = svc.create_vendor(name="V1")
        c = svc.create_contract(v.vendor_id, "Original")
        updated = svc.update_contract(c.contract_id, title="Updated", value_monthly=5000.0)
        assert updated.title == "Updated"
        assert updated.value_monthly == 5000.0

    def test_update_contract_not_found(self, svc):
        assert svc.update_contract("NONEXISTENT", title="X") is None

    def test_delete_contract(self, svc):
        v = svc.create_vendor(name="V1")
        c = svc.create_contract(v.vendor_id, "ToDelete")
        assert svc.delete_contract(c.contract_id) is True
        assert svc.get_contract(c.contract_id) is None

    def test_delete_contract_not_found(self, svc):
        assert svc.delete_contract("NONEXISTENT") is False

    def test_list_contracts(self, svc):
        v1 = svc.create_vendor(name="V1")
        v2 = svc.create_vendor(name="V2")
        svc.create_contract(v1.vendor_id, "C1")
        svc.create_contract(v1.vendor_id, "C2")
        svc.create_contract(v2.vendor_id, "C3")
        assert len(svc.list_contracts()) == 3
        assert len(svc.list_contracts(vendor_id=v1.vendor_id)) == 2

    def test_list_contracts_by_status(self, svc):
        v = svc.create_vendor(name="V1")
        svc.create_contract(v.vendor_id, "Active", status="active")
        svc.create_contract(v.vendor_id, "Draft", status="draft")
        assert len(svc.list_contracts(status="active")) == 1
        assert len(svc.list_contracts(status="draft")) == 1

    def test_get_expiring_contracts(self, svc):
        v = svc.create_vendor(name="V1")
        svc.create_contract(
            v.vendor_id, "Expiring Soon", status="active",
            end_date=datetime.now(timezone.utc) + timedelta(days=10),
        )
        svc.create_contract(
            v.vendor_id, "Not Expiring", status="active",
            end_date=datetime.now(timezone.utc) + timedelta(days=180),
        )
        expiring = svc.get_expiring_contracts(30)
        assert len(expiring) == 1
        assert expiring[0].title == "Expiring Soon"

    def test_contract_to_dict(self, svc):
        v = svc.create_vendor(name="V1")
        c = svc.create_contract(v.vendor_id, "Serialise", value_annual=12000.0)
        d = _contract_to_dict(c)
        assert d["title"] == "Serialise"
        assert d["value_annual"] == 12000.0

    def test_contract_links_to_vendor(self, svc):
        v = svc.create_vendor(name="V1")
        c = svc.create_contract(v.vendor_id, "Linked")
        vendor = svc.get_vendor(v.vendor_id)
        assert c.contract_id in vendor.contracts


# ============================================================
# Reviews
# ============================================================

class TestReviews:
    def test_create_review(self, svc):
        v = svc.create_vendor(name="Reviewed")
        review = svc.create_review(
            v.vendor_id,
            review_period="Q1 2026",
            quality_score=90.0,
            delivery_score=85.0,
            communication_score=80.0,
            value_score=75.0,
            strengths=["Reliable", "Good support"],
            weaknesses=["Slow invoicing"],
            recommendation="Continue partnership",
            reviewed_by="admin",
        )
        assert review.review_id.startswith("VREV-")
        assert review.overall_score == 82.5  # (90+85+80+75)/4

    def test_get_reviews(self, svc):
        v = svc.create_vendor(name="V1")
        svc.create_review(v.vendor_id, quality_score=80.0, delivery_score=80.0,
                          communication_score=80.0, value_score=80.0)
        svc.create_review(v.vendor_id, quality_score=90.0, delivery_score=90.0,
                          communication_score=90.0, value_score=90.0)
        reviews = svc.get_reviews(v.vendor_id)
        assert len(reviews) == 2

    def test_calculate_vendor_score(self, svc):
        v = svc.create_vendor(name="Scored")
        svc.create_review(v.vendor_id, quality_score=80.0, delivery_score=80.0,
                          communication_score=80.0, value_score=80.0)
        score = svc.calculate_vendor_score(v.vendor_id)
        assert score == 80.0

    def test_calculate_vendor_score_no_reviews(self, svc):
        v = svc.create_vendor(name="Unreviewed")
        assert svc.calculate_vendor_score(v.vendor_id) == 0.0

    def test_review_updates_vendor_performance(self, svc):
        v = svc.create_vendor(name="AutoScored")
        svc.create_review(v.vendor_id, quality_score=90.0, delivery_score=90.0,
                          communication_score=90.0, value_score=90.0)
        vendor = svc.get_vendor(v.vendor_id)
        assert vendor.performance_score == 90.0

    def test_review_to_dict(self, svc):
        v = svc.create_vendor(name="V1")
        r = svc.create_review(v.vendor_id, quality_score=85.0, delivery_score=85.0,
                              communication_score=85.0, value_score=85.0)
        d = _review_to_dict(r)
        assert d["overall_score"] == 85.0
        assert "review_id" in d

    def test_compare_vendors(self, svc):
        v1 = svc.create_vendor(name="V1", total_spend_ytd=50000.0)
        v2 = svc.create_vendor(name="V2", total_spend_ytd=30000.0)
        svc.create_review(v1.vendor_id, quality_score=90.0, delivery_score=90.0,
                          communication_score=90.0, value_score=90.0)
        svc.create_review(v2.vendor_id, quality_score=70.0, delivery_score=70.0,
                          communication_score=70.0, value_score=70.0)
        comparison = svc.compare_vendors([v1.vendor_id, v2.vendor_id])
        assert len(comparison) == 2
        # V1 should rank higher
        assert comparison[0]["vendor_id"] == v1.vendor_id
        assert comparison[0]["performance_score"] == 90.0


# ============================================================
# Procurement
# ============================================================

class TestProcurement:
    def test_submit_request(self, svc):
        v = svc.create_vendor(name="Supplier")
        req = svc.submit_request(
            v.vendor_id, "10x Laptops",
            client_id="CLIENT-001",
            description="Dell Latitude fleet refresh",
            items=[{"name": "Dell Latitude 5540", "qty": 10, "unit_price": 1200.0}],
            estimated_cost=12000.0,
            requested_by="admin",
        )
        assert req.request_id.startswith("PROC-")
        assert req.status == ProcurementStatus.SUBMITTED.value

    def test_approve_request(self, svc):
        v = svc.create_vendor(name="V1")
        req = svc.submit_request(v.vendor_id, "Switches")
        approved = svc.approve_request(req.request_id, approved_by="manager")
        assert approved.status == ProcurementStatus.APPROVED.value
        assert approved.approved_by == "manager"

    def test_mark_ordered(self, svc):
        v = svc.create_vendor(name="V1")
        req = svc.submit_request(v.vendor_id, "Firewalls")
        svc.approve_request(req.request_id)
        ordered = svc.mark_ordered(req.request_id, po_number="PO-2026-001")
        assert ordered.status == ProcurementStatus.ORDERED.value
        assert ordered.po_number == "PO-2026-001"
        assert ordered.ordered_at is not None

    def test_mark_received(self, svc):
        v = svc.create_vendor(name="V1")
        req = svc.submit_request(v.vendor_id, "Cables")
        svc.approve_request(req.request_id)
        svc.mark_ordered(req.request_id)
        received = svc.mark_received(req.request_id)
        assert received.status == ProcurementStatus.RECEIVED.value
        assert received.received_at is not None

    def test_get_request(self, svc):
        v = svc.create_vendor(name="V1")
        req = svc.submit_request(v.vendor_id, "Monitors")
        fetched = svc.get_request(req.request_id)
        assert fetched is not None
        assert fetched.title == "Monitors"

    def test_get_request_not_found(self, svc):
        assert svc.get_request("NONEXISTENT") is None

    def test_get_requests_filtered(self, svc):
        v1 = svc.create_vendor(name="V1")
        v2 = svc.create_vendor(name="V2")
        svc.submit_request(v1.vendor_id, "R1", client_id="C1")
        svc.submit_request(v1.vendor_id, "R2", client_id="C2")
        svc.submit_request(v2.vendor_id, "R3", client_id="C1")
        assert len(svc.get_requests()) == 3
        assert len(svc.get_requests(vendor_id=v1.vendor_id)) == 2
        assert len(svc.get_requests(client_id="C1")) == 2

    def test_approve_not_found(self, svc):
        assert svc.approve_request("NONEXISTENT") is None

    def test_procurement_to_dict(self, svc):
        v = svc.create_vendor(name="V1")
        req = svc.submit_request(v.vendor_id, "Dict Test")
        d = _procurement_to_dict(req)
        assert d["title"] == "Dict Test"
        assert d["status"] == "submitted"


# ============================================================
# Risk Management
# ============================================================

class TestRiskManagement:
    def test_add_risk(self, svc):
        v = svc.create_vendor(name="Risky")
        risk = svc.add_risk(
            v.vendor_id,
            risk_type=RiskType.SECURITY.value,
            severity=RiskSeverity.HIGH.value,
            description="No SOC2 certification",
            mitigation="Request audit timeline",
        )
        assert risk.risk_id.startswith("VRSK-")
        assert risk.risk_type == "security"
        assert risk.severity == "high"

    def test_get_risks(self, svc):
        v = svc.create_vendor(name="V1")
        svc.add_risk(v.vendor_id, "financial", "medium", "Cash flow concerns")
        svc.add_risk(v.vendor_id, "compliance", "low", "Minor doc gap")
        risks = svc.get_risks(v.vendor_id)
        assert len(risks) == 2

    def test_update_risk(self, svc):
        v = svc.create_vendor(name="V1")
        risk = svc.add_risk(v.vendor_id, "operational", "medium", "Single point of contact")
        updated = svc.update_risk(risk.risk_id, status=RiskStatus.MITIGATING.value, mitigation="Added backup contact")
        assert updated.status == "mitigating"
        assert updated.mitigation == "Added backup contact"

    def test_update_risk_not_found(self, svc):
        assert svc.update_risk("NONEXISTENT", status="resolved") is None

    def test_get_high_risk_vendors(self, svc):
        svc.create_vendor(name="Safe", risk_tier="low")
        svc.create_vendor(name="Dangerous", risk_tier="high")
        svc.create_vendor(name="Critical", risk_tier="critical")
        high_risk = svc.get_high_risk_vendors()
        assert len(high_risk) == 2
        names = {v.name for v in high_risk}
        assert "Dangerous" in names
        assert "Critical" in names

    def test_risk_to_dict(self, svc):
        v = svc.create_vendor(name="V1")
        r = svc.add_risk(v.vendor_id, "security", "high", "Test risk")
        d = _risk_to_dict(r)
        assert d["risk_type"] == "security"
        assert d["severity"] == "high"


# ============================================================
# Analytics & Reporting
# ============================================================

class TestAnalytics:
    def test_vendor_spend_report(self, svc_with_data):
        report = svc_with_data.get_vendor_spend_report()
        assert report["total_spend_ytd"] == 100000.0
        assert report["vendor_count"] == 3
        assert "cloud" in report["spend_by_category"]
        assert len(report["top_vendors"]) <= 10

    def test_category_breakdown(self, svc_with_data):
        breakdown = svc_with_data.get_category_breakdown()
        assert "cloud" in breakdown
        assert "security" in breakdown
        assert "hardware" in breakdown
        assert breakdown["cloud"]["count"] == 1
        assert breakdown["cloud"]["total_spend"] == 50000.0

    def test_renewal_calendar(self, svc_with_data):
        calendar = svc_with_data.get_renewal_calendar(months=1)
        # Should have the contract expiring in 15 days
        assert len(calendar) >= 1

    def test_concentration_risk(self, svc_with_data):
        result = svc_with_data.get_concentration_risk("CLIENT-001")
        assert result["client_id"] == "CLIENT-001"
        assert result["vendor_count"] == 2
        assert result["total_annual_spend"] == 42000.0
        # CloudPro has 24000/42000 = 57%, so risk_level should be high
        assert result["risk_level"] in ("high", "medium")
        assert len(result["vendors"]) == 2

    def test_concentration_risk_no_contracts(self, svc):
        result = svc.get_concentration_risk("GHOST-CLIENT")
        assert result["risk_level"] == "none"
        assert result["total_annual_spend"] == 0.0

    def test_concentration_risk_critical(self, svc):
        v = svc.create_vendor(name="Monopoly")
        svc.create_contract(
            v.vendor_id, "Everything", "subscription",
            client_id="C1", value_annual=100000.0, status="active",
        )
        result = svc.get_concentration_risk("C1")
        assert result["risk_level"] == "critical"
        assert result["vendors"][0]["spend_percentage"] == 100.0


# ============================================================
# Dashboard
# ============================================================

class TestDashboard:
    def test_dashboard(self, svc_with_data):
        dash = svc_with_data.get_dashboard()
        assert dash["total_vendors"] == 3
        assert dash["active_vendors"] == 3
        assert dash["total_contracts"] == 3
        assert dash["active_contracts"] == 3
        assert dash["expiring_contracts_30d"] >= 1
        assert dash["total_monthly_value"] > 0
        assert dash["total_annual_value"] > 0
        assert "performance_distribution" in dash
        assert "category_breakdown" in dash
        assert "spend_report" in dash

    def test_dashboard_empty(self, svc):
        dash = svc.get_dashboard()
        assert dash["total_vendors"] == 0
        assert dash["total_contracts"] == 0
        assert dash["total_monthly_value"] == 0.0


# ============================================================
# Enum Values
# ============================================================

class TestEnums:
    def test_vendor_categories(self):
        assert VendorCategory.HARDWARE.value == "hardware"
        assert VendorCategory.SOFTWARE.value == "software"
        assert VendorCategory.CLOUD.value == "cloud"
        assert VendorCategory.TELECOM.value == "telecom"
        assert VendorCategory.SECURITY.value == "security"
        assert VendorCategory.MANAGED_SERVICES.value == "managed_services"
        assert VendorCategory.CONSULTING.value == "consulting"
        assert VendorCategory.SUPPORT.value == "support"

    def test_vendor_statuses(self):
        assert VendorStatus.ACTIVE.value == "active"
        assert VendorStatus.INACTIVE.value == "inactive"
        assert VendorStatus.UNDER_REVIEW.value == "under_review"
        assert VendorStatus.BLOCKED.value == "blocked"

    def test_contract_types(self):
        assert ContractType.SUBSCRIPTION.value == "subscription"
        assert ContractType.LICENSE.value == "license"
        assert ContractType.SUPPORT.value == "support"
        assert ContractType.MAINTENANCE.value == "maintenance"
        assert ContractType.PROJECT.value == "project"
        assert ContractType.LEASE.value == "lease"

    def test_contract_statuses(self):
        assert ContractStatus.DRAFT.value == "draft"
        assert ContractStatus.ACTIVE.value == "active"
        assert ContractStatus.EXPIRING.value == "expiring"
        assert ContractStatus.EXPIRED.value == "expired"
        assert ContractStatus.CANCELLED.value == "cancelled"

    def test_risk_types(self):
        assert RiskType.FINANCIAL.value == "financial"
        assert RiskType.SECURITY.value == "security"
        assert RiskType.COMPLIANCE.value == "compliance"
        assert RiskType.OPERATIONAL.value == "operational"
        assert RiskType.CONCENTRATION.value == "concentration"

    def test_procurement_statuses(self):
        assert ProcurementStatus.DRAFT.value == "draft"
        assert ProcurementStatus.SUBMITTED.value == "submitted"
        assert ProcurementStatus.APPROVED.value == "approved"
        assert ProcurementStatus.ORDERED.value == "ordered"
        assert ProcurementStatus.RECEIVED.value == "received"
        assert ProcurementStatus.CANCELLED.value == "cancelled"
