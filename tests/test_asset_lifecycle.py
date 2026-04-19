"""
Tests for IT Asset Lifecycle Management Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.asset_lifecycle import (
    AssetLifecycleService,
    AssetCategory,
    LifecycleStatus,
    LicenseType,
    DepreciationMethod,
    DisposalMethod,
    ITAsset,
    SoftwareLicense,
    MaintenanceRecord,
    DepreciationSchedule,
    AssetRequest,
    DisposalRecord,
    _asset_to_dict,
    _license_to_dict,
    _maintenance_to_dict,
    _depreciation_to_dict,
    _request_to_dict,
    _disposal_to_dict,
)


class TestAssetLifecycleEnums:
    """Tests for enum definitions."""

    def test_asset_category_values(self):
        assert AssetCategory.HARDWARE.value == "hardware"
        assert AssetCategory.SOFTWARE.value == "software"
        assert AssetCategory.LICENSE.value == "license"
        assert AssetCategory.PERIPHERAL.value == "peripheral"
        assert AssetCategory.NETWORK_DEVICE.value == "network_device"

    def test_lifecycle_status_values(self):
        assert LifecycleStatus.ORDERED.value == "ordered"
        assert LifecycleStatus.RECEIVED.value == "received"
        assert LifecycleStatus.DEPLOYED.value == "deployed"
        assert LifecycleStatus.IN_STORAGE.value == "in_storage"
        assert LifecycleStatus.MAINTENANCE.value == "maintenance"
        assert LifecycleStatus.RETIRED.value == "retired"
        assert LifecycleStatus.DISPOSED.value == "disposed"

    def test_license_type_values(self):
        assert LicenseType.PER_SEAT.value == "per_seat"
        assert LicenseType.PER_DEVICE.value == "per_device"
        assert LicenseType.SITE.value == "site"
        assert LicenseType.ENTERPRISE.value == "enterprise"
        assert LicenseType.SUBSCRIPTION.value == "subscription"
        assert LicenseType.PERPETUAL.value == "perpetual"

    def test_depreciation_method_values(self):
        assert DepreciationMethod.STRAIGHT_LINE.value == "straight_line"
        assert DepreciationMethod.DECLINING_BALANCE.value == "declining_balance"

    def test_disposal_method_values(self):
        assert DisposalMethod.RECYCLE.value == "recycle"
        assert DisposalMethod.DONATE.value == "donate"
        assert DisposalMethod.SELL.value == "sell"
        assert DisposalMethod.DESTROY.value == "destroy"
        assert DisposalMethod.RETURN_TO_VENDOR.value == "return_to_vendor"


class TestAssetLifecycleService:
    """Tests for AssetLifecycleService class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = AssetLifecycleService()

    # ========== Asset CRUD ==========

    def test_create_asset_basic(self):
        """Test basic asset creation."""
        asset = self.service.create_asset(name="Test Laptop")
        assert asset is not None
        assert asset.asset_id.startswith("AST-")
        assert asset.name == "Test Laptop"
        assert asset.category == AssetCategory.HARDWARE
        assert asset.lifecycle_status == LifecycleStatus.ORDERED

    def test_create_asset_full(self):
        """Test asset creation with all fields."""
        now = datetime.now(timezone.utc)
        warranty = now + timedelta(days=365 * 3)

        asset = self.service.create_asset(
            name="MacBook Pro 16",
            category="hardware",
            asset_type="laptop",
            client_id="CLI-001",
            asset_tag="TAG-001",
            manufacturer="Apple",
            model="MacBook Pro 16 M3",
            serial_number="SN12345",
            purchase_date=now,
            purchase_price=3499.99,
            vendor="Apple Store",
            warranty_expires=warranty,
            assigned_to="John Doe",
            location="HQ Floor 3",
            department="Engineering",
            notes="Executive laptop",
            custom_fields={"color": "space_gray"},
        )

        assert asset.name == "MacBook Pro 16"
        assert asset.category == AssetCategory.HARDWARE
        assert asset.asset_type == "laptop"
        assert asset.client_id == "CLI-001"
        assert asset.asset_tag == "TAG-001"
        assert asset.manufacturer == "Apple"
        assert asset.model == "MacBook Pro 16 M3"
        assert asset.serial_number == "SN12345"
        assert asset.purchase_price == 3499.99
        assert asset.vendor == "Apple Store"
        assert asset.assigned_to == "John Doe"
        assert asset.location == "HQ Floor 3"
        assert asset.department == "Engineering"
        assert asset.notes == "Executive laptop"
        assert asset.custom_fields == {"color": "space_gray"}

    def test_create_asset_software_category(self):
        """Test creating a software category asset."""
        asset = self.service.create_asset(
            name="Windows 11 Pro",
            category="software",
            asset_type="license",
        )
        assert asset.category == AssetCategory.SOFTWARE

    def test_get_asset(self):
        """Test retrieving a specific asset."""
        created = self.service.create_asset(name="Test Server")
        fetched = self.service.get_asset(created.asset_id)
        assert fetched is not None
        assert fetched.asset_id == created.asset_id
        assert fetched.name == "Test Server"

    def test_get_asset_not_found(self):
        """Test retrieving a non-existent asset."""
        result = self.service.get_asset("NONEXISTENT")
        assert result is None

    def test_list_assets(self):
        """Test listing all assets."""
        self.service.create_asset(name="Laptop 1", category="hardware")
        self.service.create_asset(name="Laptop 2", category="hardware")
        self.service.create_asset(name="Switch 1", category="network_device")

        all_assets = self.service.list_assets()
        assert len(all_assets) == 3

    def test_list_assets_filter_category(self):
        """Test filtering assets by category."""
        self.service.create_asset(name="Laptop 1", category="hardware")
        self.service.create_asset(name="Switch 1", category="network_device")

        hw = self.service.list_assets(category="hardware")
        assert len(hw) == 1
        assert hw[0].name == "Laptop 1"

    def test_list_assets_filter_status(self):
        """Test filtering assets by lifecycle status."""
        a1 = self.service.create_asset(name="Laptop 1")
        self.service.create_asset(name="Laptop 2")
        self.service.deploy_asset(a1.asset_id, assigned_to="User1")

        deployed = self.service.list_assets(status="deployed")
        assert len(deployed) == 1

    def test_list_assets_filter_department(self):
        """Test filtering assets by department."""
        self.service.create_asset(name="L1", department="Engineering")
        self.service.create_asset(name="L2", department="Sales")

        eng = self.service.list_assets(department="Engineering")
        assert len(eng) == 1
        assert eng[0].name == "L1"

    def test_list_assets_filter_client(self):
        """Test filtering assets by client ID."""
        self.service.create_asset(name="L1", client_id="C1")
        self.service.create_asset(name="L2", client_id="C2")

        c1 = self.service.list_assets(client_id="C1")
        assert len(c1) == 1

    def test_update_asset(self):
        """Test updating an asset."""
        asset = self.service.create_asset(name="Old Name")
        updated = self.service.update_asset(asset.asset_id, name="New Name", location="Warehouse")
        assert updated is not None
        assert updated.name == "New Name"
        assert updated.location == "Warehouse"
        assert updated.updated_at is not None

    def test_update_asset_not_found(self):
        """Test updating a non-existent asset."""
        result = self.service.update_asset("NONEXISTENT", name="test")
        assert result is None

    def test_search_assets_by_name(self):
        """Test searching assets by name."""
        self.service.create_asset(name="MacBook Pro")
        self.service.create_asset(name="Dell XPS")

        results = self.service.search_assets("MacBook")
        assert len(results) == 1
        assert results[0].name == "MacBook Pro"

    def test_search_assets_by_serial(self):
        """Test searching assets by serial number."""
        self.service.create_asset(name="Server", serial_number="SN-UNIQUE-123")
        results = self.service.search_assets("UNIQUE")
        assert len(results) == 1

    def test_search_assets_by_manufacturer(self):
        """Test searching assets by manufacturer."""
        self.service.create_asset(name="Laptop", manufacturer="Lenovo")
        results = self.service.search_assets("lenovo")
        assert len(results) == 1

    def test_search_assets_case_insensitive(self):
        """Test case-insensitive search."""
        self.service.create_asset(name="UPPERCASE NAME")
        results = self.service.search_assets("uppercase")
        assert len(results) == 1

    # ========== Lifecycle Transitions ==========

    def test_receive_asset(self):
        """Test receiving an asset."""
        asset = self.service.create_asset(name="New Server")
        received = self.service.receive_asset(asset.asset_id, location="Warehouse A")
        assert received.lifecycle_status == LifecycleStatus.RECEIVED
        assert received.location == "Warehouse A"

    def test_deploy_asset(self):
        """Test deploying an asset."""
        asset = self.service.create_asset(name="Laptop")
        deployed = self.service.deploy_asset(
            asset.asset_id,
            assigned_to="Jane Smith",
            location="Office 201",
            department="Marketing",
        )
        assert deployed.lifecycle_status == LifecycleStatus.DEPLOYED
        assert deployed.assigned_to == "Jane Smith"
        assert deployed.location == "Office 201"
        assert deployed.department == "Marketing"

    def test_store_asset(self):
        """Test moving asset to storage."""
        asset = self.service.create_asset(name="Monitor", assigned_to="User1")
        stored = self.service.store_asset(asset.asset_id, location="Storage Room B")
        assert stored.lifecycle_status == LifecycleStatus.IN_STORAGE
        assert stored.assigned_to is None
        assert stored.location == "Storage Room B"

    def test_send_to_maintenance(self):
        """Test sending asset to maintenance."""
        asset = self.service.create_asset(name="Printer")
        maintained = self.service.send_to_maintenance(asset.asset_id, notes="Fuser needs replacement")
        assert maintained.lifecycle_status == LifecycleStatus.MAINTENANCE
        assert maintained.notes == "Fuser needs replacement"

    def test_retire_asset(self):
        """Test retiring an asset."""
        asset = self.service.create_asset(name="Old Desktop", assigned_to="User1")
        retired = self.service.retire_asset(asset.asset_id)
        assert retired.lifecycle_status == LifecycleStatus.RETIRED
        assert retired.assigned_to is None

    def test_dispose_asset(self):
        """Test disposing an asset."""
        asset = self.service.create_asset(name="Broken Laptop")
        disposed = self.service.dispose_asset(asset.asset_id)
        assert disposed.lifecycle_status == LifecycleStatus.DISPOSED
        assert disposed.assigned_to is None

    def test_full_lifecycle(self):
        """Test complete lifecycle: ordered -> received -> deployed -> maintenance -> storage -> retired -> disposed."""
        asset = self.service.create_asset(name="Full Lifecycle Test")
        assert asset.lifecycle_status == LifecycleStatus.ORDERED

        asset = self.service.receive_asset(asset.asset_id)
        assert asset.lifecycle_status == LifecycleStatus.RECEIVED

        asset = self.service.deploy_asset(asset.asset_id, assigned_to="User")
        assert asset.lifecycle_status == LifecycleStatus.DEPLOYED

        asset = self.service.send_to_maintenance(asset.asset_id)
        assert asset.lifecycle_status == LifecycleStatus.MAINTENANCE

        asset = self.service.store_asset(asset.asset_id)
        assert asset.lifecycle_status == LifecycleStatus.IN_STORAGE

        asset = self.service.retire_asset(asset.asset_id)
        assert asset.lifecycle_status == LifecycleStatus.RETIRED

        asset = self.service.dispose_asset(asset.asset_id)
        assert asset.lifecycle_status == LifecycleStatus.DISPOSED

    def test_lifecycle_transition_not_found(self):
        """Test lifecycle transition on non-existent asset."""
        result = self.service.receive_asset("NONEXISTENT")
        assert result is None

    # ========== Software Licenses ==========

    def test_create_license(self):
        """Test creating a software license."""
        lic = self.service.create_license(
            software_name="Microsoft Office 365",
            license_type="per_seat",
            seats_purchased=50,
            annual_cost=12000.0,
            vendor="Microsoft",
        )
        assert lic.license_id.startswith("LIC-")
        assert lic.software_name == "Microsoft Office 365"
        assert lic.license_type == LicenseType.PER_SEAT
        assert lic.seats_purchased == 50
        assert lic.seats_used == 0
        assert lic.is_compliant is True

    def test_create_license_linked_to_asset(self):
        """Test creating a license linked to an asset."""
        asset = self.service.create_asset(name="Server", category="software")
        lic = self.service.create_license(
            software_name="Windows Server 2022",
            asset_id=asset.asset_id,
        )
        assert lic.asset_id == asset.asset_id

    def test_get_license(self):
        """Test retrieving a license."""
        created = self.service.create_license(software_name="Slack")
        fetched = self.service.get_license(created.license_id)
        assert fetched is not None
        assert fetched.license_id == created.license_id

    def test_get_license_not_found(self):
        """Test retrieving a non-existent license."""
        result = self.service.get_license("NONEXISTENT")
        assert result is None

    def test_list_licenses(self):
        """Test listing all licenses."""
        self.service.create_license(software_name="App A")
        self.service.create_license(software_name="App B")
        lics = self.service.list_licenses()
        assert len(lics) == 2

    def test_list_licenses_by_asset(self):
        """Test listing licenses filtered by asset."""
        self.service.create_license(software_name="A", asset_id="AST-1")
        self.service.create_license(software_name="B", asset_id="AST-2")
        filtered = self.service.list_licenses(asset_id="AST-1")
        assert len(filtered) == 1
        assert filtered[0].software_name == "A"

    def test_assign_seat(self):
        """Test assigning a seat."""
        lic = self.service.create_license(software_name="Tool", seats_purchased=5)
        updated = self.service.assign_seat(lic.license_id)
        assert updated.seats_used == 1
        assert updated.is_compliant is True

    def test_assign_seat_exceeds_purchased(self):
        """Test assigning more seats than purchased creates non-compliance."""
        lic = self.service.create_license(software_name="Tool", seats_purchased=1)
        self.service.assign_seat(lic.license_id)
        updated = self.service.assign_seat(lic.license_id)
        assert updated.seats_used == 2
        assert updated.is_compliant is False

    def test_release_seat(self):
        """Test releasing a seat."""
        lic = self.service.create_license(software_name="Tool", seats_purchased=5)
        self.service.assign_seat(lic.license_id)
        self.service.assign_seat(lic.license_id)
        released = self.service.release_seat(lic.license_id)
        assert released.seats_used == 1

    def test_release_seat_floor_zero(self):
        """Test releasing a seat doesn't go below zero."""
        lic = self.service.create_license(software_name="Tool")
        released = self.service.release_seat(lic.license_id)
        assert released.seats_used == 0

    def test_release_seat_not_found(self):
        """Test releasing seat on non-existent license."""
        result = self.service.release_seat("NONEXISTENT")
        assert result is None

    def test_check_compliance_all_compliant(self):
        """Test compliance check when all licenses are compliant."""
        self.service.create_license(software_name="A", seats_purchased=10)
        self.service.create_license(software_name="B", seats_purchased=10)
        non_compliant = self.service.check_compliance()
        assert len(non_compliant) == 0

    def test_check_compliance_non_compliant(self):
        """Test compliance check with non-compliant licenses."""
        lic = self.service.create_license(software_name="Tool", seats_purchased=1)
        self.service.assign_seat(lic.license_id)
        self.service.assign_seat(lic.license_id)
        non_compliant = self.service.check_compliance()
        assert len(non_compliant) == 1

    def test_check_compliance_specific_license(self):
        """Test compliance check for a specific license."""
        lic = self.service.create_license(software_name="Tool", seats_purchased=1)
        result = self.service.check_compliance(license_id=lic.license_id)
        assert len(result) == 0  # compliant

    # ========== Maintenance ==========

    def test_schedule_maintenance(self):
        """Test scheduling maintenance."""
        asset = self.service.create_asset(name="Printer")
        rec = self.service.schedule_maintenance(
            asset_id=asset.asset_id,
            maintenance_type="repair",
            description="Replace drum unit",
            cost=250.0,
            performed_by="HP Support",
        )
        assert rec.record_id.startswith("MNT-")
        assert rec.asset_id == asset.asset_id
        assert rec.maintenance_type == "repair"
        assert rec.description == "Replace drum unit"
        assert rec.cost == 250.0

    def test_complete_maintenance(self):
        """Test completing maintenance."""
        asset = self.service.create_asset(name="Server")
        rec = self.service.schedule_maintenance(
            asset_id=asset.asset_id,
            maintenance_type="upgrade",
            description="RAM upgrade",
        )
        completed = self.service.complete_maintenance(rec.record_id, cost=500.0)
        assert completed is not None
        assert completed.completed_date is not None
        assert completed.cost == 500.0

    def test_complete_maintenance_not_found(self):
        """Test completing non-existent maintenance."""
        result = self.service.complete_maintenance("NONEXISTENT")
        assert result is None

    def test_get_maintenance_history(self):
        """Test getting maintenance history."""
        asset = self.service.create_asset(name="Server")
        self.service.schedule_maintenance(asset_id=asset.asset_id, description="M1")
        self.service.schedule_maintenance(asset_id=asset.asset_id, description="M2")

        history = self.service.get_maintenance_history(asset.asset_id)
        assert len(history) == 2

    def test_get_maintenance_history_empty(self):
        """Test maintenance history for asset with no records."""
        history = self.service.get_maintenance_history("NO-ASSET")
        assert len(history) == 0

    def test_get_upcoming_maintenance(self):
        """Test getting upcoming maintenance."""
        asset = self.service.create_asset(name="Server")
        future = datetime.now(timezone.utc) + timedelta(days=7)
        self.service.schedule_maintenance(
            asset_id=asset.asset_id,
            description="Upcoming",
            scheduled_date=future,
        )
        upcoming = self.service.get_upcoming_maintenance(days_ahead=30)
        assert len(upcoming) == 1

    def test_get_upcoming_maintenance_past_excluded(self):
        """Test that past maintenance is excluded from upcoming."""
        asset = self.service.create_asset(name="Server")
        past = datetime.now(timezone.utc) - timedelta(days=7)
        self.service.schedule_maintenance(
            asset_id=asset.asset_id,
            description="Past",
            scheduled_date=past,
        )
        upcoming = self.service.get_upcoming_maintenance(days_ahead=30)
        assert len(upcoming) == 0

    # ========== Depreciation ==========

    def test_create_depreciation_straight_line(self):
        """Test creating straight-line depreciation schedule."""
        now = datetime.now(timezone.utc)
        asset = self.service.create_asset(
            name="Server",
            purchase_price=10000.0,
            purchase_date=now,
        )
        sched = self.service.create_depreciation_schedule(
            asset_id=asset.asset_id,
            method="straight_line",
            useful_life_years=5,
            salvage_value=500.0,
        )
        assert sched is not None
        assert sched.schedule_id.startswith("DEP-")
        assert sched.method == DepreciationMethod.STRAIGHT_LINE
        assert sched.useful_life_years == 5
        assert sched.salvage_value == 500.0
        assert sched.depreciation_per_period == 1900.0  # (10000-500)/5
        assert sched.current_book_value == 10000.0  # brand new

    def test_create_depreciation_declining_balance(self):
        """Test creating declining balance depreciation schedule."""
        now = datetime.now(timezone.utc)
        asset = self.service.create_asset(
            name="Equipment",
            purchase_price=20000.0,
            purchase_date=now,
        )
        sched = self.service.create_depreciation_schedule(
            asset_id=asset.asset_id,
            method="declining_balance",
            useful_life_years=5,
            salvage_value=2000.0,
        )
        assert sched is not None
        assert sched.method == DepreciationMethod.DECLINING_BALANCE
        assert sched.current_book_value == 20000.0

    def test_create_depreciation_nonexistent_asset(self):
        """Test depreciation for non-existent asset."""
        result = self.service.create_depreciation_schedule(asset_id="NONEXISTENT")
        assert result is None

    def test_calculate_current_value(self):
        """Test calculating current book value."""
        now = datetime.now(timezone.utc)
        asset = self.service.create_asset(
            name="Laptop",
            purchase_price=2000.0,
            purchase_date=now,
        )
        self.service.create_depreciation_schedule(
            asset_id=asset.asset_id,
            useful_life_years=4,
        )
        value = self.service.calculate_current_value(asset.asset_id)
        assert value is not None
        assert value == 2000.0  # brand new, no depreciation yet

    def test_calculate_current_value_no_schedule(self):
        """Test value calculation falls back to purchase price."""
        asset = self.service.create_asset(name="Keyboard", purchase_price=100.0)
        value = self.service.calculate_current_value(asset.asset_id)
        assert value == 100.0

    def test_get_depreciation_report(self):
        """Test getting depreciation report."""
        now = datetime.now(timezone.utc)
        asset = self.service.create_asset(
            name="Server",
            purchase_price=15000.0,
            purchase_date=now,
        )
        self.service.create_depreciation_schedule(
            asset_id=asset.asset_id,
            useful_life_years=5,
            salvage_value=1000.0,
        )
        report = self.service.get_depreciation_report(asset.asset_id)
        assert report is not None
        assert report["asset_id"] == asset.asset_id
        assert report["asset_name"] == "Server"
        assert report["purchase_price"] == 15000.0
        assert "total_depreciation" in report

    def test_get_depreciation_report_no_schedule(self):
        """Test depreciation report when no schedule exists."""
        result = self.service.get_depreciation_report("NO-ASSET")
        assert result is None

    # ========== Asset Requests ==========

    def test_submit_request(self):
        """Test submitting an asset request."""
        req = self.service.submit_request(
            requester_name="Alice",
            asset_type="laptop",
            client_id="CLI-001",
            justification="New hire",
            quantity=1,
            estimated_cost=1500.0,
        )
        assert req.request_id.startswith("REQ-")
        assert req.requester_name == "Alice"
        assert req.asset_type == "laptop"
        assert req.status == "submitted"
        assert req.quantity == 1
        assert req.estimated_cost == 1500.0

    def test_approve_request(self):
        """Test approving an asset request."""
        req = self.service.submit_request(requester_name="Bob", asset_type="desktop")
        approved = self.service.approve_request(req.request_id, approved_by="Manager1")
        assert approved is not None
        assert approved.status == "approved"
        assert approved.approved_by == "Manager1"
        assert approved.approved_at is not None

    def test_deny_request(self):
        """Test denying an asset request."""
        req = self.service.submit_request(requester_name="Charlie", asset_type="server")
        denied = self.service.deny_request(req.request_id, denied_by="Director1")
        assert denied is not None
        assert denied.status == "denied"
        assert denied.approved_by == "Director1"

    def test_approve_request_not_found(self):
        """Test approving non-existent request."""
        result = self.service.approve_request("NONEXISTENT")
        assert result is None

    def test_deny_request_not_found(self):
        """Test denying non-existent request."""
        result = self.service.deny_request("NONEXISTENT")
        assert result is None

    def test_list_requests(self):
        """Test listing requests."""
        self.service.submit_request(requester_name="A", asset_type="laptop")
        self.service.submit_request(requester_name="B", asset_type="desktop")
        reqs = self.service.list_requests()
        assert len(reqs) == 2

    def test_list_requests_filter_status(self):
        """Test filtering requests by status."""
        req = self.service.submit_request(requester_name="A", asset_type="laptop")
        self.service.submit_request(requester_name="B", asset_type="desktop")
        self.service.approve_request(req.request_id)

        approved = self.service.list_requests(status="approved")
        assert len(approved) == 1

    def test_list_requests_filter_client(self):
        """Test filtering requests by client."""
        self.service.submit_request(requester_name="A", asset_type="laptop", client_id="C1")
        self.service.submit_request(requester_name="B", asset_type="desktop", client_id="C2")
        c1 = self.service.list_requests(client_id="C1")
        assert len(c1) == 1

    # ========== Disposal ==========

    def test_create_disposal_record(self):
        """Test creating a disposal record."""
        asset = self.service.create_asset(name="Old PC")
        rec = self.service.create_disposal_record(
            asset_id=asset.asset_id,
            disposal_method="recycle",
            data_wiped=True,
            wiped_method="DoD 5220.22-M",
            certificate_of_destruction="CERT-001",
        )
        assert rec is not None
        assert rec.disposal_id.startswith("DSP-")
        assert rec.disposal_method == DisposalMethod.RECYCLE
        assert rec.data_wiped is True
        assert rec.wiped_method == "DoD 5220.22-M"
        assert rec.certificate_of_destruction == "CERT-001"

        # Verify asset is now disposed
        asset = self.service.get_asset(asset.asset_id)
        assert asset.lifecycle_status == LifecycleStatus.DISPOSED

    def test_create_disposal_with_proceeds(self):
        """Test disposal record with sell proceeds."""
        asset = self.service.create_asset(name="Server", purchase_price=10000)
        rec = self.service.create_disposal_record(
            asset_id=asset.asset_id,
            disposal_method="sell",
            proceeds=2500.0,
        )
        assert rec.disposal_method == DisposalMethod.SELL
        assert rec.proceeds == 2500.0

    def test_create_disposal_nonexistent_asset(self):
        """Test disposal for non-existent asset."""
        result = self.service.create_disposal_record(asset_id="NONEXISTENT")
        assert result is None

    def test_get_disposal_records(self):
        """Test getting disposal records."""
        a1 = self.service.create_asset(name="PC1")
        a2 = self.service.create_asset(name="PC2")
        self.service.create_disposal_record(asset_id=a1.asset_id)
        self.service.create_disposal_record(asset_id=a2.asset_id)

        all_records = self.service.get_disposal_records()
        assert len(all_records) == 2

    def test_get_disposal_records_by_asset(self):
        """Test getting disposal records for a specific asset."""
        a1 = self.service.create_asset(name="PC1")
        a2 = self.service.create_asset(name="PC2")
        self.service.create_disposal_record(asset_id=a1.asset_id)
        self.service.create_disposal_record(asset_id=a2.asset_id)

        filtered = self.service.get_disposal_records(asset_id=a1.asset_id)
        assert len(filtered) == 1

    # ========== Warranty ==========

    def test_get_expiring_warranties(self):
        """Test getting assets with expiring warranties."""
        now = datetime.now(timezone.utc)
        self.service.create_asset(
            name="Laptop A",
            warranty_expires=now + timedelta(days=30),
        )
        self.service.create_asset(
            name="Laptop B",
            warranty_expires=now + timedelta(days=200),
        )

        expiring = self.service.get_expiring_warranties(days_ahead=90)
        assert len(expiring) == 1
        assert expiring[0]["name"] == "Laptop A"

    def test_get_expiring_warranties_excludes_disposed(self):
        """Test that disposed assets are excluded from warranty alerts."""
        now = datetime.now(timezone.utc)
        asset = self.service.create_asset(
            name="Disposed Laptop",
            warranty_expires=now + timedelta(days=30),
        )
        self.service.dispose_asset(asset.asset_id)

        expiring = self.service.get_expiring_warranties(days_ahead=90)
        assert len(expiring) == 0

    def test_get_warranty_status_active(self):
        """Test warranty status for active warranty."""
        now = datetime.now(timezone.utc)
        asset = self.service.create_asset(
            name="Server",
            warranty_expires=now + timedelta(days=365),
        )
        status = self.service.get_warranty_status(asset.asset_id)
        assert status is not None
        assert status["warranty_active"] is True
        assert status["days_remaining"] > 0

    def test_get_warranty_status_expired(self):
        """Test warranty status for expired warranty."""
        now = datetime.now(timezone.utc)
        asset = self.service.create_asset(
            name="Old Printer",
            warranty_expires=now - timedelta(days=30),
        )
        status = self.service.get_warranty_status(asset.asset_id)
        assert status["warranty_active"] is False
        assert status["days_remaining"] == 0

    def test_get_warranty_status_no_warranty(self):
        """Test warranty status when no warranty date set."""
        asset = self.service.create_asset(name="Generic Item")
        status = self.service.get_warranty_status(asset.asset_id)
        assert status["warranty_active"] is False

    def test_get_warranty_status_not_found(self):
        """Test warranty status for non-existent asset."""
        result = self.service.get_warranty_status("NONEXISTENT")
        assert result is None

    # ========== Reports ==========

    def test_get_asset_inventory(self):
        """Test inventory report."""
        self.service.create_asset(name="L1", category="hardware", department="IT")
        self.service.create_asset(name="S1", category="software", department="IT")
        self.service.create_asset(name="L2", category="hardware", department="Sales")

        report = self.service.get_asset_inventory()
        assert report["total_assets"] == 3
        assert report["by_category"]["hardware"] == 2
        assert report["by_category"]["software"] == 1
        assert report["by_department"]["IT"] == 2
        assert report["by_department"]["Sales"] == 1

    def test_get_asset_inventory_by_client(self):
        """Test inventory report filtered by client."""
        self.service.create_asset(name="L1", client_id="C1")
        self.service.create_asset(name="L2", client_id="C2")
        report = self.service.get_asset_inventory(client_id="C1")
        assert report["total_assets"] == 1

    def test_get_total_asset_value(self):
        """Test total value report."""
        self.service.create_asset(name="L1", purchase_price=1000.0)
        self.service.create_asset(name="L2", purchase_price=2000.0)
        report = self.service.get_total_asset_value()
        assert report["total_purchase_value"] == 3000.0
        assert report["asset_count"] == 2

    def test_get_license_compliance_report(self):
        """Test license compliance report."""
        lic1 = self.service.create_license(
            software_name="A", seats_purchased=10, annual_cost=5000,
        )
        lic2 = self.service.create_license(
            software_name="B", seats_purchased=1, annual_cost=500,
        )
        self.service.assign_seat(lic1.license_id)
        self.service.assign_seat(lic2.license_id)
        self.service.assign_seat(lic2.license_id)  # over-licensed

        report = self.service.get_license_compliance_report()
        assert report["total_licenses"] == 2
        assert report["compliant"] == 1
        assert report["non_compliant"] == 1
        assert report["total_annual_cost"] == 5500.0
        assert report["total_seats"] == 11
        assert report["used_seats"] == 3

    def test_get_lifecycle_summary(self):
        """Test lifecycle summary report."""
        a1 = self.service.create_asset(name="L1")
        a2 = self.service.create_asset(name="L2")
        a3 = self.service.create_asset(name="L3")
        self.service.deploy_asset(a1.asset_id)
        self.service.store_asset(a2.asset_id)

        summary = self.service.get_lifecycle_summary()
        assert summary["total"] == 3
        assert summary["active"] == 1
        assert summary["in_storage"] == 1

    # ========== Dashboard ==========

    def test_get_dashboard(self):
        """Test dashboard returns all expected keys."""
        self.service.create_asset(name="L1", category="hardware", purchase_price=1000)
        self.service.create_asset(name="L2", category="software", purchase_price=500)

        dashboard = self.service.get_dashboard()
        assert "total_assets" in dashboard
        assert "by_status" in dashboard
        assert "by_category" in dashboard
        assert "total_value" in dashboard
        assert "warranties_expiring_90d" in dashboard
        assert "licenses_non_compliant" in dashboard
        assert "upcoming_maintenance" in dashboard
        assert dashboard["total_assets"] == 2
        assert dashboard["total_value"] == 1500.0

    def test_get_dashboard_empty(self):
        """Test dashboard with no data."""
        dashboard = self.service.get_dashboard()
        assert dashboard["total_assets"] == 0
        assert dashboard["total_value"] == 0.0

    # ========== Serialization Helpers ==========

    def test_asset_to_dict(self):
        """Test asset serialization."""
        asset = self.service.create_asset(name="Test", manufacturer="Dell")
        d = _asset_to_dict(asset)
        assert d["name"] == "Test"
        assert d["manufacturer"] == "Dell"
        assert d["asset_id"].startswith("AST-")
        assert "created_at" in d

    def test_license_to_dict(self):
        """Test license serialization."""
        lic = self.service.create_license(software_name="App", annual_cost=100)
        d = _license_to_dict(lic)
        assert d["software_name"] == "App"
        assert d["annual_cost"] == 100

    def test_maintenance_to_dict(self):
        """Test maintenance record serialization."""
        asset = self.service.create_asset(name="Server")
        rec = self.service.schedule_maintenance(asset_id=asset.asset_id, description="Test")
        d = _maintenance_to_dict(rec)
        assert d["description"] == "Test"
        assert d["record_id"].startswith("MNT-")

    def test_depreciation_to_dict(self):
        """Test depreciation schedule serialization."""
        asset = self.service.create_asset(name="X", purchase_price=5000, purchase_date=datetime.now(timezone.utc))
        sched = self.service.create_depreciation_schedule(asset_id=asset.asset_id)
        d = _depreciation_to_dict(sched)
        assert d["method"] == "straight_line"
        assert "current_book_value" in d

    def test_request_to_dict(self):
        """Test request serialization."""
        req = self.service.submit_request(requester_name="User", asset_type="laptop")
        d = _request_to_dict(req)
        assert d["requester_name"] == "User"
        assert d["status"] == "submitted"

    def test_disposal_to_dict(self):
        """Test disposal record serialization."""
        asset = self.service.create_asset(name="PC")
        rec = self.service.create_disposal_record(asset_id=asset.asset_id, disposal_method="destroy")
        d = _disposal_to_dict(rec)
        assert d["disposal_method"] == "destroy"
        assert "disposal_id" in d
