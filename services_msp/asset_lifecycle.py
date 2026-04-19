"""
AITHER Platform - IT Asset Lifecycle Management Service
Comprehensive asset tracking from procurement through disposal
with financial tracking, warranty management, and compliance.

Provides:
- Full asset CRUD and search
- Lifecycle state transitions (ordered -> received -> deployed -> retired -> disposed)
- Software license management and compliance checking
- Maintenance scheduling and history
- Depreciation calculations (straight-line, declining balance)
- Procurement request workflow
- Disposal tracking with data-wipe certification
- Warranty expiration alerts
- Inventory, value, and compliance reports
- Dashboard with aggregated metrics

G-47: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.asset_lifecycle import (
        ITAssetModel,
        SoftwareLicenseModel,
        MaintenanceRecordModel,
        DepreciationScheduleModel,
        AssetRequestModel,
        DisposalRecordModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class AssetCategory(str, Enum):
    HARDWARE = "hardware"
    SOFTWARE = "software"
    LICENSE = "license"
    PERIPHERAL = "peripheral"
    NETWORK_DEVICE = "network_device"


class LifecycleStatus(str, Enum):
    ORDERED = "ordered"
    RECEIVED = "received"
    DEPLOYED = "deployed"
    IN_STORAGE = "in_storage"
    MAINTENANCE = "maintenance"
    RETIRED = "retired"
    DISPOSED = "disposed"


class LicenseType(str, Enum):
    PER_SEAT = "per_seat"
    PER_DEVICE = "per_device"
    SITE = "site"
    ENTERPRISE = "enterprise"
    SUBSCRIPTION = "subscription"
    PERPETUAL = "perpetual"


class DepreciationMethod(str, Enum):
    STRAIGHT_LINE = "straight_line"
    DECLINING_BALANCE = "declining_balance"


class DisposalMethod(str, Enum):
    RECYCLE = "recycle"
    DONATE = "donate"
    SELL = "sell"
    DESTROY = "destroy"
    RETURN_TO_VENDOR = "return_to_vendor"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class ITAsset:
    asset_id: str
    client_id: str = ""
    asset_tag: str = ""
    name: str = ""
    category: AssetCategory = AssetCategory.HARDWARE
    asset_type: str = "laptop"
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    purchase_date: Optional[datetime] = None
    purchase_price: float = 0.0
    vendor: str = ""
    warranty_expires: Optional[datetime] = None
    lifecycle_status: LifecycleStatus = LifecycleStatus.ORDERED
    assigned_to: Optional[str] = None
    location: str = ""
    department: str = ""
    notes: str = ""
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class SoftwareLicense:
    license_id: str
    asset_id: Optional[str] = None
    software_name: str = ""
    license_key: str = ""
    license_type: LicenseType = LicenseType.PER_SEAT
    seats_purchased: int = 1
    seats_used: int = 0
    renewal_date: Optional[datetime] = None
    annual_cost: float = 0.0
    vendor: str = ""
    is_compliant: bool = True


@dataclass
class MaintenanceRecord:
    record_id: str
    asset_id: str
    maintenance_type: str = "repair"
    description: str = ""
    cost: float = 0.0
    performed_by: str = ""
    scheduled_date: Optional[datetime] = None
    completed_date: Optional[datetime] = None
    next_maintenance: Optional[datetime] = None


@dataclass
class DepreciationSchedule:
    schedule_id: str
    asset_id: str
    method: DepreciationMethod = DepreciationMethod.STRAIGHT_LINE
    useful_life_years: int = 5
    salvage_value: float = 0.0
    current_book_value: float = 0.0
    depreciation_per_period: float = 0.0
    periods_remaining: int = 0


@dataclass
class AssetRequest:
    request_id: str
    client_id: str = ""
    requester_name: str = ""
    asset_type: str = ""
    justification: str = ""
    quantity: int = 1
    estimated_cost: float = 0.0
    status: str = "submitted"
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DisposalRecord:
    disposal_id: str
    asset_id: str
    disposal_method: DisposalMethod = DisposalMethod.RECYCLE
    disposal_date: Optional[datetime] = None
    certificate_of_destruction: str = ""
    data_wiped: bool = False
    wiped_method: str = ""
    proceeds: float = 0.0


# ============================================================
# ORM <-> Dataclass conversion helpers
# ============================================================

def _asset_from_row(row) -> ITAsset:
    return ITAsset(
        asset_id=row.asset_id,
        client_id=row.client_id or "",
        asset_tag=row.asset_tag or "",
        name=row.name or "",
        category=AssetCategory(row.category) if row.category else AssetCategory.HARDWARE,
        asset_type=row.asset_type or "laptop",
        manufacturer=row.manufacturer or "",
        model=row.model or "",
        serial_number=row.serial_number or "",
        purchase_date=row.purchase_date,
        purchase_price=row.purchase_price or 0.0,
        vendor=row.vendor or "",
        warranty_expires=row.warranty_expires,
        lifecycle_status=LifecycleStatus(row.lifecycle_status) if row.lifecycle_status else LifecycleStatus.ORDERED,
        assigned_to=row.assigned_to,
        location=row.location or "",
        department=row.department or "",
        notes=row.notes or "",
        custom_fields=row.custom_fields or {},
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _license_from_row(row) -> SoftwareLicense:
    return SoftwareLicense(
        license_id=row.license_id,
        asset_id=row.asset_id,
        software_name=row.software_name or "",
        license_key=row.license_key or "",
        license_type=LicenseType(row.license_type) if row.license_type else LicenseType.PER_SEAT,
        seats_purchased=row.seats_purchased or 1,
        seats_used=row.seats_used or 0,
        renewal_date=row.renewal_date,
        annual_cost=row.annual_cost or 0.0,
        vendor=row.vendor or "",
        is_compliant=row.is_compliant if row.is_compliant is not None else True,
    )


def _maintenance_from_row(row) -> MaintenanceRecord:
    return MaintenanceRecord(
        record_id=row.record_id,
        asset_id=row.asset_id,
        maintenance_type=row.maintenance_type or "repair",
        description=row.description or "",
        cost=row.cost or 0.0,
        performed_by=row.performed_by or "",
        scheduled_date=row.scheduled_date,
        completed_date=row.completed_date,
        next_maintenance=row.next_maintenance,
    )


def _depreciation_from_row(row) -> DepreciationSchedule:
    return DepreciationSchedule(
        schedule_id=row.schedule_id,
        asset_id=row.asset_id,
        method=DepreciationMethod(row.method) if row.method else DepreciationMethod.STRAIGHT_LINE,
        useful_life_years=row.useful_life_years or 5,
        salvage_value=row.salvage_value or 0.0,
        current_book_value=row.current_book_value or 0.0,
        depreciation_per_period=row.depreciation_per_period or 0.0,
        periods_remaining=row.periods_remaining or 0,
    )


def _request_from_row(row) -> AssetRequest:
    return AssetRequest(
        request_id=row.request_id,
        client_id=row.client_id or "",
        requester_name=row.requester_name or "",
        asset_type=row.asset_type or "",
        justification=row.justification or "",
        quantity=row.quantity or 1,
        estimated_cost=row.estimated_cost or 0.0,
        status=row.status or "submitted",
        approved_by=row.approved_by,
        approved_at=row.approved_at,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _disposal_from_row(row) -> DisposalRecord:
    return DisposalRecord(
        disposal_id=row.disposal_id,
        asset_id=row.asset_id,
        disposal_method=DisposalMethod(row.disposal_method) if row.disposal_method else DisposalMethod.RECYCLE,
        disposal_date=row.disposal_date,
        certificate_of_destruction=row.certificate_of_destruction or "",
        data_wiped=row.data_wiped or False,
        wiped_method=row.wiped_method or "",
        proceeds=row.proceeds or 0.0,
    )


def _asset_to_dict(a: ITAsset) -> dict:
    return {
        "asset_id": a.asset_id,
        "client_id": a.client_id,
        "asset_tag": a.asset_tag,
        "name": a.name,
        "category": a.category.value if isinstance(a.category, AssetCategory) else a.category,
        "asset_type": a.asset_type,
        "manufacturer": a.manufacturer,
        "model": a.model,
        "serial_number": a.serial_number,
        "purchase_date": a.purchase_date.isoformat() if a.purchase_date else None,
        "purchase_price": a.purchase_price,
        "vendor": a.vendor,
        "warranty_expires": a.warranty_expires.isoformat() if a.warranty_expires else None,
        "lifecycle_status": a.lifecycle_status.value if isinstance(a.lifecycle_status, LifecycleStatus) else a.lifecycle_status,
        "assigned_to": a.assigned_to,
        "location": a.location,
        "department": a.department,
        "notes": a.notes,
        "custom_fields": a.custom_fields,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


def _license_to_dict(l: SoftwareLicense) -> dict:
    return {
        "license_id": l.license_id,
        "asset_id": l.asset_id,
        "software_name": l.software_name,
        "license_key": l.license_key,
        "license_type": l.license_type.value if isinstance(l.license_type, LicenseType) else l.license_type,
        "seats_purchased": l.seats_purchased,
        "seats_used": l.seats_used,
        "renewal_date": l.renewal_date.isoformat() if l.renewal_date else None,
        "annual_cost": l.annual_cost,
        "vendor": l.vendor,
        "is_compliant": l.is_compliant,
    }


def _maintenance_to_dict(m: MaintenanceRecord) -> dict:
    return {
        "record_id": m.record_id,
        "asset_id": m.asset_id,
        "maintenance_type": m.maintenance_type,
        "description": m.description,
        "cost": m.cost,
        "performed_by": m.performed_by,
        "scheduled_date": m.scheduled_date.isoformat() if m.scheduled_date else None,
        "completed_date": m.completed_date.isoformat() if m.completed_date else None,
        "next_maintenance": m.next_maintenance.isoformat() if m.next_maintenance else None,
    }


def _depreciation_to_dict(d: DepreciationSchedule) -> dict:
    return {
        "schedule_id": d.schedule_id,
        "asset_id": d.asset_id,
        "method": d.method.value if isinstance(d.method, DepreciationMethod) else d.method,
        "useful_life_years": d.useful_life_years,
        "salvage_value": d.salvage_value,
        "current_book_value": d.current_book_value,
        "depreciation_per_period": d.depreciation_per_period,
        "periods_remaining": d.periods_remaining,
    }


def _request_to_dict(r: AssetRequest) -> dict:
    return {
        "request_id": r.request_id,
        "client_id": r.client_id,
        "requester_name": r.requester_name,
        "asset_type": r.asset_type,
        "justification": r.justification,
        "quantity": r.quantity,
        "estimated_cost": r.estimated_cost,
        "status": r.status,
        "approved_by": r.approved_by,
        "approved_at": r.approved_at.isoformat() if r.approved_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _disposal_to_dict(d: DisposalRecord) -> dict:
    return {
        "disposal_id": d.disposal_id,
        "asset_id": d.asset_id,
        "disposal_method": d.disposal_method.value if isinstance(d.disposal_method, DisposalMethod) else d.disposal_method,
        "disposal_date": d.disposal_date.isoformat() if d.disposal_date else None,
        "certificate_of_destruction": d.certificate_of_destruction,
        "data_wiped": d.data_wiped,
        "wiped_method": d.wiped_method,
        "proceeds": d.proceeds,
    }


# ============================================================
# Service
# ============================================================

class AssetLifecycleService:
    """
    IT Asset Lifecycle Management Service.

    Tracks hardware and software assets from procurement through disposal
    with financial tracking, warranty management, and compliance reporting.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._assets: Dict[str, ITAsset] = {}
        self._licenses: Dict[str, SoftwareLicense] = {}
        self._maintenance: Dict[str, List[MaintenanceRecord]] = {}  # asset_id -> records
        self._depreciation: Dict[str, DepreciationSchedule] = {}  # asset_id -> schedule
        self._requests: Dict[str, AssetRequest] = {}
        self._disposals: Dict[str, DisposalRecord] = {}  # asset_id -> record

    # ============================================================
    # Asset CRUD
    # ============================================================

    def create_asset(
        self,
        name: str,
        category: str = "hardware",
        asset_type: str = "laptop",
        client_id: str = "",
        asset_tag: str = "",
        manufacturer: str = "",
        model: str = "",
        serial_number: str = "",
        purchase_date: Optional[datetime] = None,
        purchase_price: float = 0.0,
        vendor: str = "",
        warranty_expires: Optional[datetime] = None,
        assigned_to: Optional[str] = None,
        location: str = "",
        department: str = "",
        notes: str = "",
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> ITAsset:
        """Create a new IT asset."""
        asset_id = f"AST-{uuid.uuid4().hex[:8].upper()}"
        cat = AssetCategory(category) if category in [e.value for e in AssetCategory] else AssetCategory.HARDWARE

        asset = ITAsset(
            asset_id=asset_id,
            client_id=client_id,
            asset_tag=asset_tag or asset_id,
            name=name,
            category=cat,
            asset_type=asset_type,
            manufacturer=manufacturer,
            model=model,
            serial_number=serial_number,
            purchase_date=purchase_date,
            purchase_price=purchase_price,
            vendor=vendor,
            warranty_expires=warranty_expires,
            lifecycle_status=LifecycleStatus.ORDERED,
            assigned_to=assigned_to,
            location=location,
            department=department,
            notes=notes,
            custom_fields=custom_fields or {},
        )

        if self._use_db:
            try:
                row = ITAssetModel(
                    asset_id=asset_id,
                    client_id=client_id,
                    asset_tag=asset.asset_tag,
                    name=name,
                    category=cat.value,
                    asset_type=asset_type,
                    manufacturer=manufacturer,
                    model=model,
                    serial_number=serial_number,
                    purchase_date=purchase_date,
                    purchase_price=purchase_price,
                    vendor=vendor,
                    warranty_expires=warranty_expires,
                    lifecycle_status=LifecycleStatus.ORDERED.value,
                    assigned_to=assigned_to,
                    location=location,
                    department=department,
                    notes=notes,
                    custom_fields=custom_fields or {},
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating asset: {e}")
                self.db.rollback()

        self._assets[asset_id] = asset
        return asset

    def get_asset(self, asset_id: str) -> Optional[ITAsset]:
        """Retrieve a single asset by ID."""
        if self._use_db:
            try:
                row = self.db.query(ITAssetModel).filter(ITAssetModel.asset_id == asset_id).first()
                if row:
                    asset = _asset_from_row(row)
                    self._assets[asset_id] = asset
                    return asset
            except Exception as e:
                logger.error(f"DB error getting asset: {e}")
        return self._assets.get(asset_id)

    def list_assets(
        self,
        client_id: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[ITAsset]:
        """List assets with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(ITAssetModel)
                if client_id:
                    q = q.filter(ITAssetModel.client_id == client_id)
                if category:
                    q = q.filter(ITAssetModel.category == category)
                if status:
                    q = q.filter(ITAssetModel.lifecycle_status == status)
                if department:
                    q = q.filter(ITAssetModel.department == department)
                rows = q.all()
                assets = [_asset_from_row(r) for r in rows]
                for a in assets:
                    self._assets[a.asset_id] = a
                return assets
            except Exception as e:
                logger.error(f"DB error listing assets: {e}")

        results = list(self._assets.values())
        if client_id:
            results = [a for a in results if a.client_id == client_id]
        if category:
            results = [a for a in results if (a.category.value if isinstance(a.category, AssetCategory) else a.category) == category]
        if status:
            results = [a for a in results if (a.lifecycle_status.value if isinstance(a.lifecycle_status, LifecycleStatus) else a.lifecycle_status) == status]
        if department:
            results = [a for a in results if a.department.lower() == department.lower()]
        return results

    def update_asset(self, asset_id: str, **updates) -> Optional[ITAsset]:
        """Update asset fields."""
        asset = self.get_asset(asset_id)
        if not asset:
            return None

        for key, value in updates.items():
            if hasattr(asset, key) and key not in ("asset_id", "created_at"):
                setattr(asset, key, value)
        asset.updated_at = datetime.now(timezone.utc)
        self._assets[asset_id] = asset

        if self._use_db:
            try:
                row = self.db.query(ITAssetModel).filter(ITAssetModel.asset_id == asset_id).first()
                if row:
                    for key, value in updates.items():
                        if hasattr(row, key) and key not in ("asset_id", "id", "created_at"):
                            if isinstance(value, Enum):
                                value = value.value
                            setattr(row, key, value)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating asset: {e}")
                self.db.rollback()

        return asset

    def search_assets(self, query: str) -> List[ITAsset]:
        """Search assets by name, serial number, asset tag, or manufacturer."""
        q_lower = query.lower()
        if self._use_db:
            try:
                rows = self.db.query(ITAssetModel).filter(
                    (ITAssetModel.name.ilike(f"%{query}%"))
                    | (ITAssetModel.serial_number.ilike(f"%{query}%"))
                    | (ITAssetModel.asset_tag.ilike(f"%{query}%"))
                    | (ITAssetModel.manufacturer.ilike(f"%{query}%"))
                ).all()
                return [_asset_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error searching assets: {e}")

        return [
            a for a in self._assets.values()
            if q_lower in a.name.lower()
            or q_lower in a.serial_number.lower()
            or q_lower in a.asset_tag.lower()
            or q_lower in a.manufacturer.lower()
        ]

    # ============================================================
    # Lifecycle Transitions
    # ============================================================

    def _transition(self, asset_id: str, new_status: LifecycleStatus, **extra) -> Optional[ITAsset]:
        """Internal helper for lifecycle state transitions."""
        updates = {"lifecycle_status": new_status, **extra}
        return self.update_asset(asset_id, **updates)

    def receive_asset(self, asset_id: str, location: str = "") -> Optional[ITAsset]:
        """Mark asset as received."""
        extra = {}
        if location:
            extra["location"] = location
        return self._transition(asset_id, LifecycleStatus.RECEIVED, **extra)

    def deploy_asset(self, asset_id: str, assigned_to: str = "", location: str = "", department: str = "") -> Optional[ITAsset]:
        """Deploy asset to a user/location."""
        extra: Dict[str, Any] = {}
        if assigned_to:
            extra["assigned_to"] = assigned_to
        if location:
            extra["location"] = location
        if department:
            extra["department"] = department
        return self._transition(asset_id, LifecycleStatus.DEPLOYED, **extra)

    def store_asset(self, asset_id: str, location: str = "") -> Optional[ITAsset]:
        """Move asset to storage."""
        extra: Dict[str, Any] = {"assigned_to": None}
        if location:
            extra["location"] = location
        return self._transition(asset_id, LifecycleStatus.IN_STORAGE, **extra)

    def send_to_maintenance(self, asset_id: str, notes: str = "") -> Optional[ITAsset]:
        """Send asset for maintenance."""
        extra: Dict[str, Any] = {}
        if notes:
            extra["notes"] = notes
        return self._transition(asset_id, LifecycleStatus.MAINTENANCE, **extra)

    def retire_asset(self, asset_id: str) -> Optional[ITAsset]:
        """Retire an asset (pre-disposal)."""
        return self._transition(asset_id, LifecycleStatus.RETIRED, assigned_to=None)

    def dispose_asset(self, asset_id: str) -> Optional[ITAsset]:
        """Mark asset as disposed."""
        return self._transition(asset_id, LifecycleStatus.DISPOSED, assigned_to=None)

    # ============================================================
    # Software Licenses
    # ============================================================

    def create_license(
        self,
        software_name: str,
        asset_id: Optional[str] = None,
        license_key: str = "",
        license_type: str = "per_seat",
        seats_purchased: int = 1,
        renewal_date: Optional[datetime] = None,
        annual_cost: float = 0.0,
        vendor: str = "",
    ) -> SoftwareLicense:
        """Create a new software license."""
        license_id = f"LIC-{uuid.uuid4().hex[:8].upper()}"
        lt = LicenseType(license_type) if license_type in [e.value for e in LicenseType] else LicenseType.PER_SEAT

        lic = SoftwareLicense(
            license_id=license_id,
            asset_id=asset_id,
            software_name=software_name,
            license_key=license_key,
            license_type=lt,
            seats_purchased=seats_purchased,
            seats_used=0,
            renewal_date=renewal_date,
            annual_cost=annual_cost,
            vendor=vendor,
            is_compliant=True,
        )

        if self._use_db:
            try:
                row = SoftwareLicenseModel(
                    license_id=license_id,
                    asset_id=asset_id,
                    software_name=software_name,
                    license_key=license_key,
                    license_type=lt.value,
                    seats_purchased=seats_purchased,
                    seats_used=0,
                    renewal_date=renewal_date,
                    annual_cost=annual_cost,
                    vendor=vendor,
                    is_compliant=True,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating license: {e}")
                self.db.rollback()

        self._licenses[license_id] = lic
        return lic

    def get_license(self, license_id: str) -> Optional[SoftwareLicense]:
        """Retrieve a software license by ID."""
        if self._use_db:
            try:
                row = self.db.query(SoftwareLicenseModel).filter(SoftwareLicenseModel.license_id == license_id).first()
                if row:
                    lic = _license_from_row(row)
                    self._licenses[license_id] = lic
                    return lic
            except Exception as e:
                logger.error(f"DB error getting license: {e}")
        return self._licenses.get(license_id)

    def list_licenses(self, asset_id: Optional[str] = None) -> List[SoftwareLicense]:
        """List all software licenses, optionally filtered by asset."""
        if self._use_db:
            try:
                q = self.db.query(SoftwareLicenseModel)
                if asset_id:
                    q = q.filter(SoftwareLicenseModel.asset_id == asset_id)
                return [_license_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error listing licenses: {e}")

        results = list(self._licenses.values())
        if asset_id:
            results = [l for l in results if l.asset_id == asset_id]
        return results

    def assign_seat(self, license_id: str) -> Optional[SoftwareLicense]:
        """Assign one seat on a license."""
        lic = self.get_license(license_id)
        if not lic:
            return None
        lic.seats_used += 1
        lic.is_compliant = lic.seats_used <= lic.seats_purchased
        self._licenses[license_id] = lic

        if self._use_db:
            try:
                row = self.db.query(SoftwareLicenseModel).filter(SoftwareLicenseModel.license_id == license_id).first()
                if row:
                    row.seats_used = lic.seats_used
                    row.is_compliant = lic.is_compliant
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error assigning seat: {e}")
                self.db.rollback()
        return lic

    def release_seat(self, license_id: str) -> Optional[SoftwareLicense]:
        """Release one seat on a license."""
        lic = self.get_license(license_id)
        if not lic:
            return None
        lic.seats_used = max(0, lic.seats_used - 1)
        lic.is_compliant = lic.seats_used <= lic.seats_purchased
        self._licenses[license_id] = lic

        if self._use_db:
            try:
                row = self.db.query(SoftwareLicenseModel).filter(SoftwareLicenseModel.license_id == license_id).first()
                if row:
                    row.seats_used = lic.seats_used
                    row.is_compliant = lic.is_compliant
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error releasing seat: {e}")
                self.db.rollback()
        return lic

    def check_compliance(self, license_id: Optional[str] = None) -> List[SoftwareLicense]:
        """Return non-compliant licenses. If license_id given, check just that one."""
        if license_id:
            lic = self.get_license(license_id)
            return [lic] if lic and not lic.is_compliant else []
        all_lics = self.list_licenses()
        return [l for l in all_lics if not l.is_compliant]

    # ============================================================
    # Maintenance
    # ============================================================

    def schedule_maintenance(
        self,
        asset_id: str,
        maintenance_type: str = "repair",
        description: str = "",
        cost: float = 0.0,
        performed_by: str = "",
        scheduled_date: Optional[datetime] = None,
        next_maintenance: Optional[datetime] = None,
    ) -> MaintenanceRecord:
        """Schedule a maintenance event for an asset."""
        record_id = f"MNT-{uuid.uuid4().hex[:8].upper()}"

        rec = MaintenanceRecord(
            record_id=record_id,
            asset_id=asset_id,
            maintenance_type=maintenance_type,
            description=description,
            cost=cost,
            performed_by=performed_by,
            scheduled_date=scheduled_date or datetime.now(timezone.utc),
            next_maintenance=next_maintenance,
        )

        if self._use_db:
            try:
                row = MaintenanceRecordModel(
                    record_id=record_id,
                    asset_id=asset_id,
                    maintenance_type=maintenance_type,
                    description=description,
                    cost=cost,
                    performed_by=performed_by,
                    scheduled_date=rec.scheduled_date,
                    next_maintenance=next_maintenance,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error scheduling maintenance: {e}")
                self.db.rollback()

        self._maintenance.setdefault(asset_id, []).append(rec)
        return rec

    def complete_maintenance(self, record_id: str, cost: Optional[float] = None) -> Optional[MaintenanceRecord]:
        """Mark a maintenance record as completed."""
        rec = None
        for records in self._maintenance.values():
            for r in records:
                if r.record_id == record_id:
                    rec = r
                    break

        if not rec and self._use_db:
            try:
                row = self.db.query(MaintenanceRecordModel).filter(MaintenanceRecordModel.record_id == record_id).first()
                if row:
                    rec = _maintenance_from_row(row)
            except Exception as e:
                logger.error(f"DB error finding maintenance: {e}")

        if not rec:
            return None

        rec.completed_date = datetime.now(timezone.utc)
        if cost is not None:
            rec.cost = cost

        if self._use_db:
            try:
                row = self.db.query(MaintenanceRecordModel).filter(MaintenanceRecordModel.record_id == record_id).first()
                if row:
                    row.completed_date = rec.completed_date
                    if cost is not None:
                        row.cost = cost
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error completing maintenance: {e}")
                self.db.rollback()

        return rec

    def get_maintenance_history(self, asset_id: str) -> List[MaintenanceRecord]:
        """Get all maintenance records for an asset."""
        if self._use_db:
            try:
                rows = self.db.query(MaintenanceRecordModel).filter(MaintenanceRecordModel.asset_id == asset_id).all()
                return [_maintenance_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error getting maintenance history: {e}")
        return self._maintenance.get(asset_id, [])

    def get_upcoming_maintenance(self, days_ahead: int = 30) -> List[MaintenanceRecord]:
        """Get maintenance records scheduled in the next N days."""
        cutoff = datetime.now(timezone.utc) + timedelta(days=days_ahead)
        now = datetime.now(timezone.utc)

        if self._use_db:
            try:
                rows = self.db.query(MaintenanceRecordModel).filter(
                    MaintenanceRecordModel.scheduled_date <= cutoff,
                    MaintenanceRecordModel.scheduled_date >= now,
                    MaintenanceRecordModel.completed_date.is_(None),
                ).all()
                return [_maintenance_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error getting upcoming maintenance: {e}")

        results = []
        for records in self._maintenance.values():
            for r in records:
                if r.completed_date is None and r.scheduled_date:
                    sd = r.scheduled_date
                    if hasattr(sd, 'tzinfo') and sd.tzinfo is None:
                        sd = sd.replace(tzinfo=timezone.utc)
                    if now <= sd <= cutoff:
                        results.append(r)
        return results

    # ============================================================
    # Depreciation
    # ============================================================

    def create_depreciation_schedule(
        self,
        asset_id: str,
        method: str = "straight_line",
        useful_life_years: int = 5,
        salvage_value: float = 0.0,
    ) -> Optional[DepreciationSchedule]:
        """Create a depreciation schedule for an asset."""
        asset = self.get_asset(asset_id)
        if not asset:
            return None

        schedule_id = f"DEP-{uuid.uuid4().hex[:8].upper()}"
        dep_method = DepreciationMethod(method) if method in [e.value for e in DepreciationMethod] else DepreciationMethod.STRAIGHT_LINE

        purchase_price = asset.purchase_price
        depreciable = purchase_price - salvage_value

        if dep_method == DepreciationMethod.STRAIGHT_LINE:
            per_period = depreciable / useful_life_years if useful_life_years > 0 else 0
        else:
            # Declining balance: double the straight-line rate applied to book value
            rate = (2.0 / useful_life_years) if useful_life_years > 0 else 0
            per_period = purchase_price * rate

        # Calculate elapsed periods
        periods_elapsed = 0
        if asset.purchase_date:
            now = datetime.now(timezone.utc)
            pd = asset.purchase_date
            if hasattr(pd, 'tzinfo') and pd.tzinfo is None:
                pd = pd.replace(tzinfo=timezone.utc)
            years_elapsed = (now - pd).days / 365.25
            periods_elapsed = min(int(years_elapsed), useful_life_years)

        periods_remaining = max(0, useful_life_years - periods_elapsed)

        if dep_method == DepreciationMethod.STRAIGHT_LINE:
            current_book = max(salvage_value, purchase_price - (per_period * periods_elapsed))
        else:
            rate = (2.0 / useful_life_years) if useful_life_years > 0 else 0
            current_book = purchase_price
            for _ in range(periods_elapsed):
                current_book = max(salvage_value, current_book - (current_book * rate))
            per_period = current_book * rate

        sched = DepreciationSchedule(
            schedule_id=schedule_id,
            asset_id=asset_id,
            method=dep_method,
            useful_life_years=useful_life_years,
            salvage_value=salvage_value,
            current_book_value=round(current_book, 2),
            depreciation_per_period=round(per_period, 2),
            periods_remaining=periods_remaining,
        )

        if self._use_db:
            try:
                row = DepreciationScheduleModel(
                    schedule_id=schedule_id,
                    asset_id=asset_id,
                    method=dep_method.value,
                    useful_life_years=useful_life_years,
                    salvage_value=salvage_value,
                    current_book_value=sched.current_book_value,
                    depreciation_per_period=sched.depreciation_per_period,
                    periods_remaining=periods_remaining,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating depreciation: {e}")
                self.db.rollback()

        self._depreciation[asset_id] = sched
        return sched

    def calculate_current_value(self, asset_id: str) -> Optional[float]:
        """Calculate the current book value of an asset."""
        sched = self._depreciation.get(asset_id)
        if not sched and self._use_db:
            try:
                row = self.db.query(DepreciationScheduleModel).filter(DepreciationScheduleModel.asset_id == asset_id).first()
                if row:
                    sched = _depreciation_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting depreciation: {e}")
        if sched:
            return sched.current_book_value
        # Fallback: use purchase price
        asset = self.get_asset(asset_id)
        return asset.purchase_price if asset else None

    def get_depreciation_report(self, asset_id: str) -> Optional[dict]:
        """Get full depreciation report for an asset."""
        sched = self._depreciation.get(asset_id)
        if not sched and self._use_db:
            try:
                row = self.db.query(DepreciationScheduleModel).filter(DepreciationScheduleModel.asset_id == asset_id).first()
                if row:
                    sched = _depreciation_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting depreciation: {e}")
        if not sched:
            return None
        asset = self.get_asset(asset_id)
        return {
            "asset_id": asset_id,
            "asset_name": asset.name if asset else "",
            "purchase_price": asset.purchase_price if asset else 0,
            **_depreciation_to_dict(sched),
            "total_depreciation": round((asset.purchase_price if asset else 0) - sched.current_book_value, 2),
        }

    # ============================================================
    # Asset Requests
    # ============================================================

    def submit_request(
        self,
        requester_name: str,
        asset_type: str,
        client_id: str = "",
        justification: str = "",
        quantity: int = 1,
        estimated_cost: float = 0.0,
    ) -> AssetRequest:
        """Submit an asset procurement request."""
        request_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"

        req = AssetRequest(
            request_id=request_id,
            client_id=client_id,
            requester_name=requester_name,
            asset_type=asset_type,
            justification=justification,
            quantity=quantity,
            estimated_cost=estimated_cost,
            status="submitted",
        )

        if self._use_db:
            try:
                row = AssetRequestModel(
                    request_id=request_id,
                    client_id=client_id,
                    requester_name=requester_name,
                    asset_type=asset_type,
                    justification=justification,
                    quantity=quantity,
                    estimated_cost=estimated_cost,
                    status="submitted",
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error submitting request: {e}")
                self.db.rollback()

        self._requests[request_id] = req
        return req

    def approve_request(self, request_id: str, approved_by: str = "") -> Optional[AssetRequest]:
        """Approve an asset request."""
        req = self._requests.get(request_id)
        if not req and self._use_db:
            try:
                row = self.db.query(AssetRequestModel).filter(AssetRequestModel.request_id == request_id).first()
                if row:
                    req = _request_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting request: {e}")
        if not req:
            return None

        req.status = "approved"
        req.approved_by = approved_by
        req.approved_at = datetime.now(timezone.utc)
        self._requests[request_id] = req

        if self._use_db:
            try:
                row = self.db.query(AssetRequestModel).filter(AssetRequestModel.request_id == request_id).first()
                if row:
                    row.status = "approved"
                    row.approved_by = approved_by
                    row.approved_at = req.approved_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error approving request: {e}")
                self.db.rollback()
        return req

    def deny_request(self, request_id: str, denied_by: str = "") -> Optional[AssetRequest]:
        """Deny an asset request."""
        req = self._requests.get(request_id)
        if not req and self._use_db:
            try:
                row = self.db.query(AssetRequestModel).filter(AssetRequestModel.request_id == request_id).first()
                if row:
                    req = _request_from_row(row)
            except Exception as e:
                logger.error(f"DB error getting request: {e}")
        if not req:
            return None

        req.status = "denied"
        req.approved_by = denied_by
        req.approved_at = datetime.now(timezone.utc)
        self._requests[request_id] = req

        if self._use_db:
            try:
                row = self.db.query(AssetRequestModel).filter(AssetRequestModel.request_id == request_id).first()
                if row:
                    row.status = "denied"
                    row.approved_by = denied_by
                    row.approved_at = req.approved_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error denying request: {e}")
                self.db.rollback()
        return req

    def list_requests(self, client_id: Optional[str] = None, status: Optional[str] = None) -> List[AssetRequest]:
        """List asset requests."""
        if self._use_db:
            try:
                q = self.db.query(AssetRequestModel)
                if client_id:
                    q = q.filter(AssetRequestModel.client_id == client_id)
                if status:
                    q = q.filter(AssetRequestModel.status == status)
                return [_request_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error listing requests: {e}")

        results = list(self._requests.values())
        if client_id:
            results = [r for r in results if r.client_id == client_id]
        if status:
            results = [r for r in results if r.status == status]
        return results

    # ============================================================
    # Disposal
    # ============================================================

    def create_disposal_record(
        self,
        asset_id: str,
        disposal_method: str = "recycle",
        disposal_date: Optional[datetime] = None,
        certificate_of_destruction: str = "",
        data_wiped: bool = False,
        wiped_method: str = "",
        proceeds: float = 0.0,
    ) -> Optional[DisposalRecord]:
        """Create a disposal record and mark asset as disposed."""
        asset = self.get_asset(asset_id)
        if not asset:
            return None

        disposal_id = f"DSP-{uuid.uuid4().hex[:8].upper()}"
        dm = DisposalMethod(disposal_method) if disposal_method in [e.value for e in DisposalMethod] else DisposalMethod.RECYCLE

        rec = DisposalRecord(
            disposal_id=disposal_id,
            asset_id=asset_id,
            disposal_method=dm,
            disposal_date=disposal_date or datetime.now(timezone.utc),
            certificate_of_destruction=certificate_of_destruction,
            data_wiped=data_wiped,
            wiped_method=wiped_method,
            proceeds=proceeds,
        )

        if self._use_db:
            try:
                row = DisposalRecordModel(
                    disposal_id=disposal_id,
                    asset_id=asset_id,
                    disposal_method=dm.value,
                    disposal_date=rec.disposal_date,
                    certificate_of_destruction=certificate_of_destruction,
                    data_wiped=data_wiped,
                    wiped_method=wiped_method,
                    proceeds=proceeds,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating disposal: {e}")
                self.db.rollback()

        self._disposals[asset_id] = rec
        # Also transition asset to disposed
        self.dispose_asset(asset_id)
        return rec

    def get_disposal_records(self, asset_id: Optional[str] = None) -> List[DisposalRecord]:
        """Get disposal records, optionally filtered by asset."""
        if self._use_db:
            try:
                q = self.db.query(DisposalRecordModel)
                if asset_id:
                    q = q.filter(DisposalRecordModel.asset_id == asset_id)
                return [_disposal_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error getting disposals: {e}")

        records = list(self._disposals.values())
        if asset_id:
            records = [r for r in records if r.asset_id == asset_id]
        return records

    # ============================================================
    # Warranty
    # ============================================================

    def get_expiring_warranties(self, days_ahead: int = 90) -> List[dict]:
        """Get assets with warranties expiring in the next N days."""
        now = datetime.now(timezone.utc)
        cutoff = now + timedelta(days=days_ahead)
        results = []

        assets = self.list_assets()
        for a in assets:
            if a.lifecycle_status in (LifecycleStatus.DISPOSED, LifecycleStatus.RETIRED):
                continue
            if a.warranty_expires:
                we = a.warranty_expires
                if hasattr(we, 'tzinfo') and we.tzinfo is None:
                    we = we.replace(tzinfo=timezone.utc)
                if now <= we <= cutoff:
                    results.append({
                        **_asset_to_dict(a),
                        "days_until_expiry": (we - now).days,
                    })

        results.sort(key=lambda x: x.get("days_until_expiry", 999))
        return results

    def get_warranty_status(self, asset_id: str) -> Optional[dict]:
        """Get warranty status for a specific asset."""
        asset = self.get_asset(asset_id)
        if not asset:
            return None

        now = datetime.now(timezone.utc)
        warranty_active = False
        days_remaining = 0

        if asset.warranty_expires:
            we = asset.warranty_expires
            if hasattr(we, 'tzinfo') and we.tzinfo is None:
                we = we.replace(tzinfo=timezone.utc)
            warranty_active = we > now
            days_remaining = max(0, (we - now).days) if warranty_active else 0

        return {
            "asset_id": asset_id,
            "warranty_expires": asset.warranty_expires.isoformat() if asset.warranty_expires else None,
            "warranty_active": warranty_active,
            "days_remaining": days_remaining,
        }

    # ============================================================
    # Reports
    # ============================================================

    def get_asset_inventory(self, client_id: Optional[str] = None) -> dict:
        """Get full inventory report."""
        assets = self.list_assets(client_id=client_id)
        by_category: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        by_department: Dict[str, int] = {}

        for a in assets:
            cat = a.category.value if isinstance(a.category, AssetCategory) else a.category
            st = a.lifecycle_status.value if isinstance(a.lifecycle_status, LifecycleStatus) else a.lifecycle_status
            by_category[cat] = by_category.get(cat, 0) + 1
            by_status[st] = by_status.get(st, 0) + 1
            by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
            if a.department:
                by_department[a.department] = by_department.get(a.department, 0) + 1

        return {
            "total_assets": len(assets),
            "by_category": by_category,
            "by_status": by_status,
            "by_type": by_type,
            "by_department": by_department,
        }

    def get_total_asset_value(self, client_id: Optional[str] = None) -> dict:
        """Get total value of all assets."""
        assets = self.list_assets(client_id=client_id)
        total_purchase = sum(a.purchase_price for a in assets)
        total_current = 0.0
        for a in assets:
            val = self.calculate_current_value(a.asset_id)
            if val is not None:
                total_current += val

        return {
            "total_purchase_value": round(total_purchase, 2),
            "total_current_value": round(total_current, 2),
            "total_depreciation": round(total_purchase - total_current, 2),
            "asset_count": len(assets),
        }

    def get_license_compliance_report(self) -> dict:
        """Get license compliance report."""
        licenses = self.list_licenses()
        compliant = [l for l in licenses if l.is_compliant]
        non_compliant = [l for l in licenses if not l.is_compliant]
        total_annual = sum(l.annual_cost for l in licenses)
        total_seats = sum(l.seats_purchased for l in licenses)
        used_seats = sum(l.seats_used for l in licenses)

        return {
            "total_licenses": len(licenses),
            "compliant": len(compliant),
            "non_compliant": len(non_compliant),
            "non_compliant_licenses": [_license_to_dict(l) for l in non_compliant],
            "total_annual_cost": round(total_annual, 2),
            "total_seats": total_seats,
            "used_seats": used_seats,
            "utilization_pct": round((used_seats / total_seats * 100) if total_seats > 0 else 0, 1),
        }

    def get_lifecycle_summary(self) -> dict:
        """Get lifecycle distribution summary."""
        assets = self.list_assets()
        by_status: Dict[str, int] = {}
        for a in assets:
            st = a.lifecycle_status.value if isinstance(a.lifecycle_status, LifecycleStatus) else a.lifecycle_status
            by_status[st] = by_status.get(st, 0) + 1

        return {
            "total": len(assets),
            "by_status": by_status,
            "active": by_status.get("deployed", 0),
            "in_storage": by_status.get("in_storage", 0),
            "in_maintenance": by_status.get("maintenance", 0),
            "retired": by_status.get("retired", 0),
            "disposed": by_status.get("disposed", 0),
        }

    def get_dashboard(self) -> dict:
        """Dashboard summary with aggregated metrics."""
        assets = self.list_assets()

        # By status
        by_status: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        total_value = 0.0

        for a in assets:
            st = a.lifecycle_status.value if isinstance(a.lifecycle_status, LifecycleStatus) else a.lifecycle_status
            cat = a.category.value if isinstance(a.category, AssetCategory) else a.category
            by_status[st] = by_status.get(st, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1
            total_value += a.purchase_price

        # Expiring warranties (next 90 days)
        expiring = self.get_expiring_warranties(90)

        # Non-compliant licenses
        non_compliant = self.check_compliance()

        return {
            "total_assets": len(assets),
            "by_status": by_status,
            "by_category": by_category,
            "total_value": round(total_value, 2),
            "warranties_expiring_90d": len(expiring),
            "licenses_non_compliant": len(non_compliant),
            "upcoming_maintenance": len(self.get_upcoming_maintenance(30)),
        }
