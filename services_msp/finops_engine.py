"""
AITHER Platform - FinOps / IT Cost Optimization Engine Service
Tracks IT spending across all MSP services, identifies waste,
and recommends cost savings for managed clients.

Provides:
- Cost center management (infrastructure, software, cloud, telecom, etc.)
- Cost entry recording and breakdown
- Vendor contract tracking with utilization analysis
- Automated savings opportunity identification
- Budget forecasting and variance analysis
- Cost alerts (over-budget, spikes, contract expiry)
- Analytics: trends, per-endpoint cost, vendor spend, YoY comparison
- Dashboard: total spend, savings found/implemented, budget health

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.finops import (
        CostCenterModel,
        CostEntryModel,
        SavingsOpportunityModel,
        BudgetForecastModel,
        VendorContractModel,
        CostAlertModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class CostCategory(str, Enum):
    """Cost center categories"""
    INFRASTRUCTURE = "infrastructure"
    SOFTWARE = "software"
    SERVICES = "services"
    CLOUD = "cloud"
    TELECOM = "telecom"
    PRINTING = "printing"
    SECURITY = "security"
    BACKUP = "backup"
    OTHER = "other"


class OpportunityCategory(str, Enum):
    """Savings opportunity categories"""
    UNUSED_LICENSES = "unused_licenses"
    RIGHTSIZING = "rightsizing"
    CONSOLIDATION = "consolidation"
    RENEGOTIATION = "renegotiation"
    AUTOMATION = "automation"
    ELIMINATION = "elimination"
    ALTERNATIVE_VENDOR = "alternative_vendor"
    RESERVED_INSTANCES = "reserved_instances"


class EffortLevel(str, Enum):
    """Implementation effort level"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class CostCenter:
    """IT cost center"""
    center_id: str
    client_id: str
    name: str
    category: str = "other"
    budget_monthly: float = 0.0
    actual_monthly: float = 0.0
    variance: float = 0.0
    owner: str = ""
    department: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class CostEntry:
    """Individual cost line item"""
    entry_id: str
    center_id: str
    client_id: str
    description: str = ""
    vendor: str = ""
    amount: float = 0.0
    currency: str = "USD"
    period: str = ""
    entry_type: str = "recurring"
    is_committed: bool = False
    contract_end_date: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class SavingsOpportunity:
    """Identified cost optimization opportunity"""
    opportunity_id: str
    client_id: str
    title: str
    description: str = ""
    category: str = "unused_licenses"
    estimated_monthly_savings: float = 0.0
    estimated_annual_savings: float = 0.0
    effort_level: str = "medium"
    confidence: float = 0.5
    status: str = "identified"
    identified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    implemented_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class BudgetForecast:
    """Budget forecast record"""
    forecast_id: str
    client_id: str
    period: str
    category: str = ""
    forecasted_amount: float = 0.0
    actual_amount: float = 0.0
    variance: float = 0.0
    trend: str = "stable"
    confidence: float = 0.5
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class VendorContract:
    """Vendor contract with utilization tracking"""
    contract_id: str
    client_id: str
    vendor_name: str
    service_description: str = ""
    monthly_cost: float = 0.0
    annual_cost: float = 0.0
    contract_start: Optional[datetime] = None
    contract_end: Optional[datetime] = None
    auto_renew: bool = False
    notice_period_days: int = 30
    seats_purchased: int = 0
    seats_used: int = 0
    utilization_pct: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class CostAlert:
    """Cost-related alert"""
    alert_id: str
    client_id: str
    alert_type: str
    severity: str = "medium"
    title: str = ""
    description: str = ""
    amount: float = 0.0
    threshold: float = 0.0
    is_acknowledged: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


# ============================================================
# ORM row -> dataclass converters
# ============================================================

def _center_from_row(row) -> CostCenter:
    return CostCenter(
        center_id=row.center_id,
        client_id=row.client_id,
        name=row.name,
        category=row.category or "other",
        budget_monthly=row.budget_monthly or 0.0,
        actual_monthly=row.actual_monthly or 0.0,
        variance=row.variance or 0.0,
        owner=row.owner or "",
        department=row.department or "",
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _entry_from_row(row) -> CostEntry:
    return CostEntry(
        entry_id=row.entry_id,
        center_id=row.center_id,
        client_id=row.client_id,
        description=row.description or "",
        vendor=row.vendor or "",
        amount=row.amount or 0.0,
        currency=row.currency or "USD",
        period=row.period or "",
        entry_type=row.entry_type or "recurring",
        is_committed=row.is_committed if row.is_committed is not None else False,
        contract_end_date=row.contract_end_date,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _opportunity_from_row(row) -> SavingsOpportunity:
    return SavingsOpportunity(
        opportunity_id=row.opportunity_id,
        client_id=row.client_id,
        title=row.title,
        description=row.description or "",
        category=row.category or "unused_licenses",
        estimated_monthly_savings=row.estimated_monthly_savings or 0.0,
        estimated_annual_savings=row.estimated_annual_savings or 0.0,
        effort_level=row.effort_level or "medium",
        confidence=row.confidence or 0.5,
        status=row.status or "identified",
        identified_at=row.identified_at or datetime.now(timezone.utc),
        implemented_at=row.implemented_at,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _forecast_from_row(row) -> BudgetForecast:
    return BudgetForecast(
        forecast_id=row.forecast_id,
        client_id=row.client_id,
        period=row.period,
        category=row.category or "",
        forecasted_amount=row.forecasted_amount or 0.0,
        actual_amount=row.actual_amount or 0.0,
        variance=row.variance or 0.0,
        trend=row.trend or "stable",
        confidence=row.confidence or 0.5,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _contract_from_row(row) -> VendorContract:
    return VendorContract(
        contract_id=row.contract_id,
        client_id=row.client_id,
        vendor_name=row.vendor_name,
        service_description=row.service_description or "",
        monthly_cost=row.monthly_cost or 0.0,
        annual_cost=row.annual_cost or 0.0,
        contract_start=row.contract_start,
        contract_end=row.contract_end,
        auto_renew=row.auto_renew if row.auto_renew is not None else False,
        notice_period_days=row.notice_period_days or 30,
        seats_purchased=row.seats_purchased or 0,
        seats_used=row.seats_used or 0,
        utilization_pct=row.utilization_pct or 0.0,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _alert_from_row(row) -> CostAlert:
    return CostAlert(
        alert_id=row.alert_id,
        client_id=row.client_id,
        alert_type=row.alert_type,
        severity=row.severity or "medium",
        title=row.title or "",
        description=row.description or "",
        amount=row.amount or 0.0,
        threshold=row.threshold or 0.0,
        is_acknowledged=row.is_acknowledged if row.is_acknowledged is not None else False,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


# ============================================================
# Serialization helpers
# ============================================================

def center_to_dict(c: CostCenter) -> dict:
    return {
        "center_id": c.center_id,
        "client_id": c.client_id,
        "name": c.name,
        "category": c.category,
        "budget_monthly": c.budget_monthly,
        "actual_monthly": c.actual_monthly,
        "variance": c.variance,
        "owner": c.owner,
        "department": c.department,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def entry_to_dict(e: CostEntry) -> dict:
    return {
        "entry_id": e.entry_id,
        "center_id": e.center_id,
        "client_id": e.client_id,
        "description": e.description,
        "vendor": e.vendor,
        "amount": e.amount,
        "currency": e.currency,
        "period": e.period,
        "entry_type": e.entry_type,
        "is_committed": e.is_committed,
        "contract_end_date": e.contract_end_date.isoformat() if e.contract_end_date else None,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "updated_at": e.updated_at.isoformat() if e.updated_at else None,
    }


def opportunity_to_dict(o: SavingsOpportunity) -> dict:
    return {
        "opportunity_id": o.opportunity_id,
        "client_id": o.client_id,
        "title": o.title,
        "description": o.description,
        "category": o.category,
        "estimated_monthly_savings": o.estimated_monthly_savings,
        "estimated_annual_savings": o.estimated_annual_savings,
        "effort_level": o.effort_level,
        "confidence": o.confidence,
        "status": o.status,
        "identified_at": o.identified_at.isoformat() if o.identified_at else None,
        "implemented_at": o.implemented_at.isoformat() if o.implemented_at else None,
        "created_at": o.created_at.isoformat() if o.created_at else None,
        "updated_at": o.updated_at.isoformat() if o.updated_at else None,
    }


def forecast_to_dict(f: BudgetForecast) -> dict:
    return {
        "forecast_id": f.forecast_id,
        "client_id": f.client_id,
        "period": f.period,
        "category": f.category,
        "forecasted_amount": f.forecasted_amount,
        "actual_amount": f.actual_amount,
        "variance": f.variance,
        "trend": f.trend,
        "confidence": f.confidence,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
    }


def contract_to_dict(vc: VendorContract) -> dict:
    return {
        "contract_id": vc.contract_id,
        "client_id": vc.client_id,
        "vendor_name": vc.vendor_name,
        "service_description": vc.service_description,
        "monthly_cost": vc.monthly_cost,
        "annual_cost": vc.annual_cost,
        "contract_start": vc.contract_start.isoformat() if vc.contract_start else None,
        "contract_end": vc.contract_end.isoformat() if vc.contract_end else None,
        "auto_renew": vc.auto_renew,
        "notice_period_days": vc.notice_period_days,
        "seats_purchased": vc.seats_purchased,
        "seats_used": vc.seats_used,
        "utilization_pct": vc.utilization_pct,
        "created_at": vc.created_at.isoformat() if vc.created_at else None,
        "updated_at": vc.updated_at.isoformat() if vc.updated_at else None,
    }


def alert_to_dict(a: CostAlert) -> dict:
    return {
        "alert_id": a.alert_id,
        "client_id": a.client_id,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "title": a.title,
        "description": a.description,
        "amount": a.amount,
        "threshold": a.threshold,
        "is_acknowledged": a.is_acknowledged,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


# ============================================================
# FinOpsEngineService
# ============================================================

class FinOpsEngineService:
    """
    FinOps / IT Cost Optimization Engine

    Tracks IT spending across all MSP services, identifies waste,
    and recommends cost savings for managed clients.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._centers: Dict[str, CostCenter] = {}
        self._entries: Dict[str, CostEntry] = {}
        self._opportunities: Dict[str, SavingsOpportunity] = {}
        self._forecasts: Dict[str, BudgetForecast] = {}
        self._contracts: Dict[str, VendorContract] = {}
        self._alerts: Dict[str, CostAlert] = {}

    # ================================================================
    # Cost Center Management
    # ================================================================

    def create_center(
        self,
        client_id: str,
        name: str,
        category: str = "other",
        budget_monthly: float = 0.0,
        owner: str = "",
        department: str = "",
    ) -> CostCenter:
        """Create a new cost center."""
        center_id = f"CC-{uuid.uuid4().hex[:8].upper()}"
        center = CostCenter(
            center_id=center_id,
            client_id=client_id,
            name=name,
            category=category,
            budget_monthly=budget_monthly,
            owner=owner,
            department=department,
        )

        if self._use_db:
            try:
                row = CostCenterModel(
                    center_id=center_id,
                    client_id=client_id,
                    name=name,
                    category=category,
                    budget_monthly=budget_monthly,
                    actual_monthly=0.0,
                    variance=0.0,
                    owner=owner,
                    department=department,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("Created cost center %s (DB)", center_id)
                return center
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for cost center: %s", exc)

        self._centers[center_id] = center
        logger.info("Created cost center %s (memory)", center_id)
        return center

    def get_center(self, center_id: str) -> Optional[CostCenter]:
        """Get a cost center by ID."""
        if self._use_db:
            try:
                row = self.db.query(CostCenterModel).filter(
                    CostCenterModel.center_id == center_id
                ).first()
                return _center_from_row(row) if row else None
            except Exception as exc:
                logger.warning("DB read failed: %s", exc)
        return self._centers.get(center_id)

    def list_centers(self, client_id: Optional[str] = None, category: Optional[str] = None) -> List[CostCenter]:
        """List cost centers with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(CostCenterModel)
                if client_id:
                    q = q.filter(CostCenterModel.client_id == client_id)
                if category:
                    q = q.filter(CostCenterModel.category == category)
                return [_center_from_row(r) for r in q.all()]
            except Exception as exc:
                logger.warning("DB read failed: %s", exc)

        results = list(self._centers.values())
        if client_id:
            results = [c for c in results if c.client_id == client_id]
        if category:
            results = [c for c in results if c.category == category]
        return results

    def update_center(self, center_id: str, **kwargs) -> Optional[CostCenter]:
        """Update a cost center."""
        if self._use_db:
            try:
                row = self.db.query(CostCenterModel).filter(
                    CostCenterModel.center_id == center_id
                ).first()
                if not row:
                    return None
                for k, v in kwargs.items():
                    if hasattr(row, k):
                        setattr(row, k, v)
                self.db.commit()
                return _center_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed: %s", exc)

        center = self._centers.get(center_id)
        if not center:
            return None
        for k, v in kwargs.items():
            if hasattr(center, k):
                setattr(center, k, v)
        center.updated_at = datetime.now(timezone.utc)
        return center

    # ================================================================
    # Cost Entry Management
    # ================================================================

    def record_cost(
        self,
        center_id: str,
        client_id: str,
        description: str = "",
        vendor: str = "",
        amount: float = 0.0,
        currency: str = "USD",
        period: str = "",
        entry_type: str = "recurring",
        is_committed: bool = False,
        contract_end_date: Optional[datetime] = None,
    ) -> CostEntry:
        """Record a cost entry."""
        entry_id = f"CE-{uuid.uuid4().hex[:8].upper()}"
        entry = CostEntry(
            entry_id=entry_id,
            center_id=center_id,
            client_id=client_id,
            description=description,
            vendor=vendor,
            amount=amount,
            currency=currency,
            period=period,
            entry_type=entry_type,
            is_committed=is_committed,
            contract_end_date=contract_end_date,
        )

        if self._use_db:
            try:
                row = CostEntryModel(
                    entry_id=entry_id,
                    center_id=center_id,
                    client_id=client_id,
                    description=description,
                    vendor=vendor,
                    amount=amount,
                    currency=currency,
                    period=period,
                    entry_type=entry_type,
                    is_committed=is_committed,
                    contract_end_date=contract_end_date,
                )
                self.db.add(row)
                self.db.commit()
                # Update center actual
                self._update_center_actual(center_id)
                return entry
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for cost entry: %s", exc)

        self._entries[entry_id] = entry
        self._update_center_actual_memory(center_id)
        return entry

    def _update_center_actual(self, center_id: str) -> None:
        """Recalculate center actual_monthly from DB entries."""
        if not self._use_db:
            return
        try:
            from sqlalchemy import func
            total = self.db.query(func.sum(CostEntryModel.amount)).filter(
                CostEntryModel.center_id == center_id
            ).scalar() or 0.0
            row = self.db.query(CostCenterModel).filter(
                CostCenterModel.center_id == center_id
            ).first()
            if row:
                row.actual_monthly = total
                row.variance = row.budget_monthly - total
                self.db.commit()
        except Exception:
            pass

    def _update_center_actual_memory(self, center_id: str) -> None:
        """Recalculate center actual_monthly from in-memory entries."""
        center = self._centers.get(center_id)
        if not center:
            return
        total = sum(e.amount for e in self._entries.values() if e.center_id == center_id)
        center.actual_monthly = total
        center.variance = center.budget_monthly - total

    def get_costs(
        self,
        client_id: Optional[str] = None,
        center_id: Optional[str] = None,
        vendor: Optional[str] = None,
        period: Optional[str] = None,
        entry_type: Optional[str] = None,
    ) -> List[CostEntry]:
        """Get cost entries with filters."""
        if self._use_db:
            try:
                q = self.db.query(CostEntryModel)
                if client_id:
                    q = q.filter(CostEntryModel.client_id == client_id)
                if center_id:
                    q = q.filter(CostEntryModel.center_id == center_id)
                if vendor:
                    q = q.filter(CostEntryModel.vendor == vendor)
                if period:
                    q = q.filter(CostEntryModel.period == period)
                if entry_type:
                    q = q.filter(CostEntryModel.entry_type == entry_type)
                return [_entry_from_row(r) for r in q.all()]
            except Exception as exc:
                logger.warning("DB read failed: %s", exc)

        results = list(self._entries.values())
        if client_id:
            results = [e for e in results if e.client_id == client_id]
        if center_id:
            results = [e for e in results if e.center_id == center_id]
        if vendor:
            results = [e for e in results if e.vendor == vendor]
        if period:
            results = [e for e in results if e.period == period]
        if entry_type:
            results = [e for e in results if e.entry_type == entry_type]
        return results

    def get_cost_breakdown(self, client_id: str, period: Optional[str] = None) -> Dict[str, Any]:
        """Get cost breakdown by category for a client."""
        entries = self.get_costs(client_id=client_id, period=period)
        centers = self.list_centers(client_id=client_id)
        center_map = {c.center_id: c for c in centers}

        by_category: Dict[str, float] = {}
        by_vendor: Dict[str, float] = {}
        by_type: Dict[str, float] = {}
        total = 0.0

        for e in entries:
            total += e.amount
            cat = center_map.get(e.center_id, CostCenter(center_id="", client_id="", name="")).category
            by_category[cat] = by_category.get(cat, 0.0) + e.amount
            if e.vendor:
                by_vendor[e.vendor] = by_vendor.get(e.vendor, 0.0) + e.amount
            by_type[e.entry_type] = by_type.get(e.entry_type, 0.0) + e.amount

        return {
            "client_id": client_id,
            "period": period,
            "total": total,
            "by_category": by_category,
            "by_vendor": by_vendor,
            "by_type": by_type,
            "entry_count": len(entries),
        }

    # ================================================================
    # Vendor Contract Management
    # ================================================================

    def add_contract(
        self,
        client_id: str,
        vendor_name: str,
        service_description: str = "",
        monthly_cost: float = 0.0,
        annual_cost: float = 0.0,
        contract_start: Optional[datetime] = None,
        contract_end: Optional[datetime] = None,
        auto_renew: bool = False,
        notice_period_days: int = 30,
        seats_purchased: int = 0,
        seats_used: int = 0,
    ) -> VendorContract:
        """Add a vendor contract."""
        contract_id = f"VC-{uuid.uuid4().hex[:8].upper()}"
        util_pct = self._calculate_utilization_raw(seats_purchased, seats_used)

        contract = VendorContract(
            contract_id=contract_id,
            client_id=client_id,
            vendor_name=vendor_name,
            service_description=service_description,
            monthly_cost=monthly_cost,
            annual_cost=annual_cost or (monthly_cost * 12),
            contract_start=contract_start,
            contract_end=contract_end,
            auto_renew=auto_renew,
            notice_period_days=notice_period_days,
            seats_purchased=seats_purchased,
            seats_used=seats_used,
            utilization_pct=util_pct,
        )

        if self._use_db:
            try:
                row = VendorContractModel(
                    contract_id=contract_id,
                    client_id=client_id,
                    vendor_name=vendor_name,
                    service_description=service_description,
                    monthly_cost=monthly_cost,
                    annual_cost=annual_cost or (monthly_cost * 12),
                    contract_start=contract_start,
                    contract_end=contract_end,
                    auto_renew=auto_renew,
                    notice_period_days=notice_period_days,
                    seats_purchased=seats_purchased,
                    seats_used=seats_used,
                    utilization_pct=util_pct,
                )
                self.db.add(row)
                self.db.commit()
                return contract
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for vendor contract: %s", exc)

        self._contracts[contract_id] = contract
        return contract

    def get_contracts(self, client_id: Optional[str] = None) -> List[VendorContract]:
        """List vendor contracts."""
        if self._use_db:
            try:
                q = self.db.query(VendorContractModel)
                if client_id:
                    q = q.filter(VendorContractModel.client_id == client_id)
                return [_contract_from_row(r) for r in q.all()]
            except Exception as exc:
                logger.warning("DB read failed: %s", exc)

        results = list(self._contracts.values())
        if client_id:
            results = [c for c in results if c.client_id == client_id]
        return results

    def update_contract(self, contract_id: str, **kwargs) -> Optional[VendorContract]:
        """Update a vendor contract."""
        if self._use_db:
            try:
                row = self.db.query(VendorContractModel).filter(
                    VendorContractModel.contract_id == contract_id
                ).first()
                if not row:
                    return None
                for k, v in kwargs.items():
                    if hasattr(row, k):
                        setattr(row, k, v)
                # Recalculate utilization
                row.utilization_pct = self._calculate_utilization_raw(
                    row.seats_purchased, row.seats_used
                )
                self.db.commit()
                return _contract_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed: %s", exc)

        contract = self._contracts.get(contract_id)
        if not contract:
            return None
        for k, v in kwargs.items():
            if hasattr(contract, k):
                setattr(contract, k, v)
        contract.utilization_pct = self._calculate_utilization_raw(
            contract.seats_purchased, contract.seats_used
        )
        contract.updated_at = datetime.now(timezone.utc)
        return contract

    def get_expiring_contracts(self, days: int = 90) -> List[VendorContract]:
        """Get contracts expiring within N days."""
        cutoff = datetime.now(timezone.utc) + timedelta(days=days)
        now = datetime.now(timezone.utc)

        if self._use_db:
            try:
                rows = self.db.query(VendorContractModel).filter(
                    VendorContractModel.contract_end != None,  # noqa: E711
                    VendorContractModel.contract_end <= cutoff,
                    VendorContractModel.contract_end >= now,
                ).all()
                return [_contract_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB read failed: %s", exc)

        return [
            c for c in self._contracts.values()
            if c.contract_end and now <= c.contract_end <= cutoff
        ]

    def _calculate_utilization(self, contract: VendorContract) -> float:
        """Calculate utilization percentage for a contract."""
        return self._calculate_utilization_raw(contract.seats_purchased, contract.seats_used)

    @staticmethod
    def _calculate_utilization_raw(seats_purchased: int, seats_used: int) -> float:
        """Calculate utilization from raw seat counts."""
        if not seats_purchased or seats_purchased <= 0:
            return 0.0
        return round((seats_used / seats_purchased) * 100.0, 1)

    # ================================================================
    # Savings Opportunity Engine
    # ================================================================

    def identify_savings_opportunities(self, client_id: str) -> List[SavingsOpportunity]:
        """Auto-scan for waste and savings across all categories."""
        opportunities: List[SavingsOpportunity] = []

        opportunities.extend(self._find_unused_licenses(client_id))
        opportunities.extend(self._find_rightsizing(client_id))
        opportunities.extend(self._find_consolidation(client_id))
        opportunities.extend(self._find_contract_renegotiation(client_id))

        logger.info("Identified %d savings opportunities for client %s",
                     len(opportunities), client_id)
        return opportunities

    def _find_unused_licenses(self, client_id: str) -> List[SavingsOpportunity]:
        """Find contracts with <50% utilization (unused licenses)."""
        contracts = self.get_contracts(client_id=client_id)
        opps = []
        for c in contracts:
            if c.seats_purchased > 0 and c.utilization_pct < 50.0:
                unused_seats = c.seats_purchased - c.seats_used
                per_seat_cost = c.monthly_cost / c.seats_purchased if c.seats_purchased else 0
                monthly_savings = unused_seats * per_seat_cost
                opp = self._create_opportunity(
                    client_id=client_id,
                    title=f"Unused licenses: {c.vendor_name} - {c.service_description}",
                    description=(
                        f"Only {c.seats_used} of {c.seats_purchased} seats used "
                        f"({c.utilization_pct:.0f}% utilization). "
                        f"Reduce by {unused_seats} seats to save ${monthly_savings:.2f}/mo."
                    ),
                    category=OpportunityCategory.UNUSED_LICENSES.value,
                    estimated_monthly_savings=monthly_savings,
                    effort_level=EffortLevel.LOW.value,
                    confidence=0.9,
                )
                opps.append(opp)
        return opps

    def _find_rightsizing(self, client_id: str) -> List[SavingsOpportunity]:
        """Find oversized resources (cloud/infra with low utilization)."""
        entries = self.get_costs(client_id=client_id)
        centers = self.list_centers(client_id=client_id)
        opps = []

        for center in centers:
            if center.category in (CostCategory.CLOUD.value, CostCategory.INFRASTRUCTURE.value):
                if center.budget_monthly > 0 and center.actual_monthly > center.budget_monthly * 0.5:
                    potential = center.actual_monthly * 0.2  # Assume 20% rightsizing potential
                    opp = self._create_opportunity(
                        client_id=client_id,
                        title=f"Rightsizing: {center.name}",
                        description=(
                            f"Cost center '{center.name}' spending ${center.actual_monthly:.2f}/mo. "
                            f"Rightsizing analysis suggests ~20% reduction potential."
                        ),
                        category=OpportunityCategory.RIGHTSIZING.value,
                        estimated_monthly_savings=potential,
                        effort_level=EffortLevel.MEDIUM.value,
                        confidence=0.6,
                    )
                    opps.append(opp)
        return opps

    def _find_consolidation(self, client_id: str) -> List[SavingsOpportunity]:
        """Find duplicate services from different vendors."""
        contracts = self.get_contracts(client_id=client_id)
        opps = []

        # Group by service description keywords
        svc_groups: Dict[str, List[VendorContract]] = {}
        for c in contracts:
            key = c.service_description.lower().strip()
            if key:
                svc_groups.setdefault(key, []).append(c)

        for svc_key, group in svc_groups.items():
            if len(group) > 1:
                total_cost = sum(c.monthly_cost for c in group)
                cheapest = min(c.monthly_cost for c in group)
                savings = total_cost - cheapest
                vendors = ", ".join(c.vendor_name for c in group)
                opp = self._create_opportunity(
                    client_id=client_id,
                    title=f"Consolidation: {svc_key} ({len(group)} vendors)",
                    description=(
                        f"Multiple vendors for '{svc_key}': {vendors}. "
                        f"Consolidate to save up to ${savings:.2f}/mo."
                    ),
                    category=OpportunityCategory.CONSOLIDATION.value,
                    estimated_monthly_savings=savings,
                    effort_level=EffortLevel.HIGH.value,
                    confidence=0.7,
                )
                opps.append(opp)
        return opps

    def _find_contract_renegotiation(self, client_id: str) -> List[SavingsOpportunity]:
        """Find expiring contracts with renegotiation leverage."""
        expiring = self.get_expiring_contracts(days=120)
        opps = []
        for c in expiring:
            if c.client_id != client_id:
                continue
            potential = c.monthly_cost * 0.15  # Assume 15% negotiation leverage
            opp = self._create_opportunity(
                client_id=client_id,
                title=f"Renegotiate: {c.vendor_name}",
                description=(
                    f"Contract with {c.vendor_name} expires "
                    f"{c.contract_end.strftime('%Y-%m-%d') if c.contract_end else 'soon'}. "
                    f"Renegotiate for ~15% savings (${potential:.2f}/mo)."
                ),
                category=OpportunityCategory.RENEGOTIATION.value,
                estimated_monthly_savings=potential,
                effort_level=EffortLevel.MEDIUM.value,
                confidence=0.65,
            )
            opps.append(opp)
        return opps

    def _create_opportunity(
        self,
        client_id: str,
        title: str,
        description: str,
        category: str,
        estimated_monthly_savings: float,
        effort_level: str = "medium",
        confidence: float = 0.5,
    ) -> SavingsOpportunity:
        """Create and persist a savings opportunity."""
        opp_id = f"SO-{uuid.uuid4().hex[:8].upper()}"
        opp = SavingsOpportunity(
            opportunity_id=opp_id,
            client_id=client_id,
            title=title,
            description=description,
            category=category,
            estimated_monthly_savings=estimated_monthly_savings,
            estimated_annual_savings=estimated_monthly_savings * 12,
            effort_level=effort_level,
            confidence=confidence,
        )

        if self._use_db:
            try:
                row = SavingsOpportunityModel(
                    opportunity_id=opp_id,
                    client_id=client_id,
                    title=title,
                    description=description,
                    category=category,
                    estimated_monthly_savings=estimated_monthly_savings,
                    estimated_annual_savings=estimated_monthly_savings * 12,
                    effort_level=effort_level,
                    confidence=confidence,
                )
                self.db.add(row)
                self.db.commit()
                return opp
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for opportunity: %s", exc)

        self._opportunities[opp_id] = opp
        return opp

    def get_opportunities(
        self,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[SavingsOpportunity]:
        """Get savings opportunities with filters."""
        if self._use_db:
            try:
                q = self.db.query(SavingsOpportunityModel)
                if client_id:
                    q = q.filter(SavingsOpportunityModel.client_id == client_id)
                if status:
                    q = q.filter(SavingsOpportunityModel.status == status)
                if category:
                    q = q.filter(SavingsOpportunityModel.category == category)
                return [_opportunity_from_row(r) for r in q.all()]
            except Exception as exc:
                logger.warning("DB read failed: %s", exc)

        results = list(self._opportunities.values())
        if client_id:
            results = [o for o in results if o.client_id == client_id]
        if status:
            results = [o for o in results if o.status == status]
        if category:
            results = [o for o in results if o.category == category]
        return results

    def update_opportunity_status(self, opportunity_id: str, status: str) -> Optional[SavingsOpportunity]:
        """Update opportunity status."""
        if self._use_db:
            try:
                row = self.db.query(SavingsOpportunityModel).filter(
                    SavingsOpportunityModel.opportunity_id == opportunity_id
                ).first()
                if not row:
                    return None
                row.status = status
                if status == "implemented":
                    row.implemented_at = datetime.now(timezone.utc)
                self.db.commit()
                return _opportunity_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed: %s", exc)

        opp = self._opportunities.get(opportunity_id)
        if not opp:
            return None
        opp.status = status
        if status == "implemented":
            opp.implemented_at = datetime.now(timezone.utc)
        opp.updated_at = datetime.now(timezone.utc)
        return opp

    def implement_opportunity(self, opportunity_id: str) -> Optional[SavingsOpportunity]:
        """Mark an opportunity as implemented."""
        return self.update_opportunity_status(opportunity_id, "implemented")

    # ================================================================
    # Budget Forecasting
    # ================================================================

    def create_forecast(
        self,
        client_id: str,
        period: str,
        category: str = "",
        forecasted_amount: float = 0.0,
    ) -> BudgetForecast:
        """Create a budget forecast."""
        forecast_id = f"BF-{uuid.uuid4().hex[:8].upper()}"

        # Determine trend from cost entries
        entries = self.get_costs(client_id=client_id)
        trend = self._determine_trend(entries)

        # Calculate actual from entries for this period
        period_entries = [e for e in entries if e.period == period]
        actual = sum(e.amount for e in period_entries)
        variance = forecasted_amount - actual

        forecast = BudgetForecast(
            forecast_id=forecast_id,
            client_id=client_id,
            period=period,
            category=category,
            forecasted_amount=forecasted_amount,
            actual_amount=actual,
            variance=variance,
            trend=trend,
            confidence=0.7,
        )

        if self._use_db:
            try:
                row = BudgetForecastModel(
                    forecast_id=forecast_id,
                    client_id=client_id,
                    period=period,
                    category=category,
                    forecasted_amount=forecasted_amount,
                    actual_amount=actual,
                    variance=variance,
                    trend=trend,
                    confidence=0.7,
                )
                self.db.add(row)
                self.db.commit()
                return forecast
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for forecast: %s", exc)

        self._forecasts[forecast_id] = forecast
        return forecast

    def get_forecasts(self, client_id: Optional[str] = None, period: Optional[str] = None) -> List[BudgetForecast]:
        """Get budget forecasts."""
        if self._use_db:
            try:
                q = self.db.query(BudgetForecastModel)
                if client_id:
                    q = q.filter(BudgetForecastModel.client_id == client_id)
                if period:
                    q = q.filter(BudgetForecastModel.period == period)
                return [_forecast_from_row(r) for r in q.all()]
            except Exception as exc:
                logger.warning("DB read failed: %s", exc)

        results = list(self._forecasts.values())
        if client_id:
            results = [f for f in results if f.client_id == client_id]
        if period:
            results = [f for f in results if f.period == period]
        return results

    def compare_budget_to_actual(self, client_id: str) -> Dict[str, Any]:
        """Compare budget vs actual spending by cost center."""
        centers = self.list_centers(client_id=client_id)
        comparisons = []
        total_budget = 0.0
        total_actual = 0.0

        for c in centers:
            total_budget += c.budget_monthly
            total_actual += c.actual_monthly
            comparisons.append({
                "center_id": c.center_id,
                "name": c.name,
                "category": c.category,
                "budget": c.budget_monthly,
                "actual": c.actual_monthly,
                "variance": c.variance,
                "pct_used": round((c.actual_monthly / c.budget_monthly * 100), 1) if c.budget_monthly > 0 else 0.0,
            })

        return {
            "client_id": client_id,
            "total_budget": total_budget,
            "total_actual": total_actual,
            "total_variance": total_budget - total_actual,
            "centers": comparisons,
        }

    @staticmethod
    def _determine_trend(entries: List[CostEntry]) -> str:
        """Determine spending trend from entries."""
        if len(entries) < 2:
            return "stable"
        # Simple: compare first half vs second half
        mid = len(entries) // 2
        first_half = sum(e.amount for e in entries[:mid])
        second_half = sum(e.amount for e in entries[mid:])
        if second_half > first_half * 1.1:
            return "increasing"
        elif second_half < first_half * 0.9:
            return "decreasing"
        return "stable"

    # ================================================================
    # Alerts
    # ================================================================

    def check_budgets(self) -> List[CostAlert]:
        """Check all cost centers for budget overruns and generate alerts."""
        alerts = []
        centers = self.list_centers()
        for c in centers:
            if c.budget_monthly > 0 and c.actual_monthly > c.budget_monthly:
                alert = self._create_alert(
                    client_id=c.client_id,
                    alert_type="over_budget",
                    severity="high",
                    title=f"Over budget: {c.name}",
                    description=(
                        f"Cost center '{c.name}' is over budget: "
                        f"${c.actual_monthly:.2f} / ${c.budget_monthly:.2f} "
                        f"(${abs(c.variance):.2f} over)"
                    ),
                    amount=c.actual_monthly,
                    threshold=c.budget_monthly,
                )
                alerts.append(alert)
            elif c.budget_monthly > 0 and c.actual_monthly > c.budget_monthly * 0.9:
                alert = self._create_alert(
                    client_id=c.client_id,
                    alert_type="over_budget",
                    severity="medium",
                    title=f"Approaching budget: {c.name}",
                    description=(
                        f"Cost center '{c.name}' at {(c.actual_monthly / c.budget_monthly * 100):.0f}% "
                        f"of budget (${c.actual_monthly:.2f} / ${c.budget_monthly:.2f})"
                    ),
                    amount=c.actual_monthly,
                    threshold=c.budget_monthly,
                )
                alerts.append(alert)
        return alerts

    def generate_alerts(self, client_id: str) -> List[CostAlert]:
        """Generate all types of alerts for a client."""
        alerts = []

        # Budget alerts
        centers = self.list_centers(client_id=client_id)
        for c in centers:
            if c.budget_monthly > 0 and c.actual_monthly > c.budget_monthly:
                alerts.append(self._create_alert(
                    client_id=client_id,
                    alert_type="over_budget",
                    severity="high",
                    title=f"Over budget: {c.name}",
                    description=f"Spending ${c.actual_monthly:.2f} vs ${c.budget_monthly:.2f} budget",
                    amount=c.actual_monthly,
                    threshold=c.budget_monthly,
                ))

        # Contract expiry alerts
        expiring = self.get_expiring_contracts(days=60)
        for c in expiring:
            if c.client_id == client_id:
                alerts.append(self._create_alert(
                    client_id=client_id,
                    alert_type="contract_expiring",
                    severity="medium",
                    title=f"Contract expiring: {c.vendor_name}",
                    description=(
                        f"Contract with {c.vendor_name} expires "
                        f"{c.contract_end.strftime('%Y-%m-%d') if c.contract_end else 'soon'}"
                    ),
                    amount=c.monthly_cost,
                ))

        # Unused service alerts (low utilization)
        contracts = self.get_contracts(client_id=client_id)
        for c in contracts:
            if c.seats_purchased > 0 and c.utilization_pct < 25.0:
                alerts.append(self._create_alert(
                    client_id=client_id,
                    alert_type="unused_service",
                    severity="medium",
                    title=f"Low utilization: {c.vendor_name}",
                    description=(
                        f"{c.vendor_name} at {c.utilization_pct:.0f}% utilization "
                        f"({c.seats_used}/{c.seats_purchased} seats)"
                    ),
                    amount=c.monthly_cost,
                ))

        return alerts

    def _create_alert(
        self,
        client_id: str,
        alert_type: str,
        severity: str = "medium",
        title: str = "",
        description: str = "",
        amount: float = 0.0,
        threshold: float = 0.0,
    ) -> CostAlert:
        """Create and persist a cost alert."""
        alert_id = f"CA-{uuid.uuid4().hex[:8].upper()}"
        alert = CostAlert(
            alert_id=alert_id,
            client_id=client_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            amount=amount,
            threshold=threshold,
        )

        if self._use_db:
            try:
                row = CostAlertModel(
                    alert_id=alert_id,
                    client_id=client_id,
                    alert_type=alert_type,
                    severity=severity,
                    title=title,
                    description=description,
                    amount=amount,
                    threshold=threshold,
                )
                self.db.add(row)
                self.db.commit()
                return alert
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for alert: %s", exc)

        self._alerts[alert_id] = alert
        return alert

    def acknowledge_alert(self, alert_id: str) -> Optional[CostAlert]:
        """Acknowledge a cost alert."""
        if self._use_db:
            try:
                row = self.db.query(CostAlertModel).filter(
                    CostAlertModel.alert_id == alert_id
                ).first()
                if not row:
                    return None
                row.is_acknowledged = True
                self.db.commit()
                return _alert_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed: %s", exc)

        alert = self._alerts.get(alert_id)
        if not alert:
            return None
        alert.is_acknowledged = True
        alert.updated_at = datetime.now(timezone.utc)
        return alert

    def get_alerts(
        self,
        client_id: Optional[str] = None,
        alert_type: Optional[str] = None,
        acknowledged: Optional[bool] = None,
    ) -> List[CostAlert]:
        """Get cost alerts with filters."""
        if self._use_db:
            try:
                q = self.db.query(CostAlertModel)
                if client_id:
                    q = q.filter(CostAlertModel.client_id == client_id)
                if alert_type:
                    q = q.filter(CostAlertModel.alert_type == alert_type)
                if acknowledged is not None:
                    q = q.filter(CostAlertModel.is_acknowledged == acknowledged)
                return [_alert_from_row(r) for r in q.all()]
            except Exception as exc:
                logger.warning("DB read failed: %s", exc)

        results = list(self._alerts.values())
        if client_id:
            results = [a for a in results if a.client_id == client_id]
        if alert_type:
            results = [a for a in results if a.alert_type == alert_type]
        if acknowledged is not None:
            results = [a for a in results if a.is_acknowledged == acknowledged]
        return results

    # ================================================================
    # Analytics
    # ================================================================

    def get_cost_trend(self, client_id: str, months: int = 6) -> Dict[str, Any]:
        """Get cost trend over N months."""
        entries = self.get_costs(client_id=client_id)
        # Group by period
        by_period: Dict[str, float] = {}
        for e in entries:
            period_key = e.period or "unknown"
            by_period[period_key] = by_period.get(period_key, 0.0) + e.amount

        sorted_periods = sorted(by_period.items())[-months:]
        amounts = [v for _, v in sorted_periods]
        trend = self._determine_trend(entries)

        return {
            "client_id": client_id,
            "months": months,
            "periods": [{"period": k, "total": v} for k, v in sorted_periods],
            "trend": trend,
            "average_monthly": sum(amounts) / len(amounts) if amounts else 0.0,
        }

    def get_cost_per_endpoint(self, client_id: str) -> Dict[str, Any]:
        """Calculate cost per managed endpoint."""
        entries = self.get_costs(client_id=client_id)
        total_cost = sum(e.amount for e in entries)
        # Estimate endpoint count from contracts
        contracts = self.get_contracts(client_id=client_id)
        total_endpoints = sum(c.seats_used for c in contracts) or 1

        return {
            "client_id": client_id,
            "total_monthly_cost": total_cost,
            "total_endpoints": total_endpoints,
            "cost_per_endpoint": round(total_cost / total_endpoints, 2) if total_endpoints else 0.0,
        }

    def get_vendor_spend_analysis(self, client_id: Optional[str] = None) -> Dict[str, Any]:
        """Analyze spending by vendor."""
        contracts = self.get_contracts(client_id=client_id)
        vendor_spend: Dict[str, Dict[str, Any]] = {}

        for c in contracts:
            if c.vendor_name not in vendor_spend:
                vendor_spend[c.vendor_name] = {
                    "vendor": c.vendor_name,
                    "monthly_total": 0.0,
                    "annual_total": 0.0,
                    "contract_count": 0,
                    "total_seats": 0,
                    "used_seats": 0,
                }
            vs = vendor_spend[c.vendor_name]
            vs["monthly_total"] += c.monthly_cost
            vs["annual_total"] += c.annual_cost
            vs["contract_count"] += 1
            vs["total_seats"] += c.seats_purchased
            vs["used_seats"] += c.seats_used

        vendors = sorted(vendor_spend.values(), key=lambda x: x["monthly_total"], reverse=True)
        total = sum(v["monthly_total"] for v in vendors)

        return {
            "client_id": client_id,
            "total_monthly_spend": total,
            "vendor_count": len(vendors),
            "vendors": vendors,
        }

    def get_category_breakdown(self, client_id: str) -> Dict[str, Any]:
        """Get spending breakdown by cost category."""
        centers = self.list_centers(client_id=client_id)
        by_cat: Dict[str, float] = {}
        total = 0.0
        for c in centers:
            by_cat[c.category] = by_cat.get(c.category, 0.0) + c.actual_monthly
            total += c.actual_monthly

        breakdown = [
            {
                "category": cat,
                "amount": amt,
                "pct": round(amt / total * 100, 1) if total > 0 else 0.0,
            }
            for cat, amt in sorted(by_cat.items(), key=lambda x: x[1], reverse=True)
        ]

        return {
            "client_id": client_id,
            "total": total,
            "categories": breakdown,
        }

    def get_yoy_comparison(self, client_id: str) -> Dict[str, Any]:
        """Get year-over-year cost comparison."""
        entries = self.get_costs(client_id=client_id)
        now = datetime.now(timezone.utc)
        current_year = str(now.year)
        prev_year = str(now.year - 1)

        current_total = sum(e.amount for e in entries if current_year in e.period)
        prev_total = sum(e.amount for e in entries if prev_year in e.period)

        if prev_total > 0:
            change_pct = round(((current_total - prev_total) / prev_total) * 100, 1)
        else:
            change_pct = 0.0

        return {
            "client_id": client_id,
            "current_year": current_year,
            "current_total": current_total,
            "previous_year": prev_year,
            "previous_total": prev_total,
            "change_amount": current_total - prev_total,
            "change_pct": change_pct,
        }

    # ================================================================
    # Savings Totals
    # ================================================================

    def get_total_savings_implemented(self, client_id: Optional[str] = None) -> Dict[str, float]:
        """Get total savings from implemented opportunities."""
        opps = self.get_opportunities(client_id=client_id, status="implemented")
        monthly = sum(o.estimated_monthly_savings for o in opps)
        return {
            "monthly_savings": monthly,
            "annual_savings": monthly * 12,
            "count": len(opps),
        }

    def get_total_savings_available(self, client_id: Optional[str] = None) -> Dict[str, float]:
        """Get total savings from identified (not yet implemented) opportunities."""
        opps = self.get_opportunities(client_id=client_id, status="identified")
        monthly = sum(o.estimated_monthly_savings for o in opps)
        return {
            "monthly_savings": monthly,
            "annual_savings": monthly * 12,
            "count": len(opps),
        }

    # ================================================================
    # Dashboard
    # ================================================================

    def get_dashboard(self, client_id: Optional[str] = None) -> Dict[str, Any]:
        """Get FinOps dashboard summary."""
        # Total spend
        entries = self.get_costs(client_id=client_id)
        total_spend = sum(e.amount for e in entries)

        # Savings
        implemented = self.get_total_savings_implemented(client_id)
        available = self.get_total_savings_available(client_id)

        # Top opportunities
        all_opps = self.get_opportunities(client_id=client_id, status="identified")
        top_opps = sorted(all_opps, key=lambda o: o.estimated_monthly_savings, reverse=True)[:5]

        # Budget health
        centers = self.list_centers(client_id=client_id)
        over_budget = [c for c in centers if c.budget_monthly > 0 and c.actual_monthly > c.budget_monthly]
        total_budget = sum(c.budget_monthly for c in centers if c.budget_monthly > 0)
        total_actual = sum(c.actual_monthly for c in centers)

        # Contracts
        contracts = self.get_contracts(client_id=client_id)
        expiring_soon = self.get_expiring_contracts(days=60)
        if client_id:
            expiring_soon = [c for c in expiring_soon if c.client_id == client_id]

        # Alerts
        active_alerts = self.get_alerts(client_id=client_id, acknowledged=False)

        return {
            "total_monthly_spend": total_spend,
            "savings_implemented": implemented,
            "savings_available": available,
            "top_opportunities": [opportunity_to_dict(o) for o in top_opps],
            "budget_health": {
                "total_budget": total_budget,
                "total_actual": total_actual,
                "variance": total_budget - total_actual,
                "over_budget_count": len(over_budget),
                "center_count": len(centers),
            },
            "contracts": {
                "total": len(contracts),
                "expiring_soon": len(expiring_soon),
                "total_monthly_cost": sum(c.monthly_cost for c in contracts),
            },
            "active_alerts": len(active_alerts),
            "client_id": client_id,
        }
