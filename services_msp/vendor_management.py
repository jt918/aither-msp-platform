"""
AITHER Platform - Vendor Management Service
Comprehensive vendor lifecycle management for MSP operations

Provides:
- Vendor CRUD with category/status tracking
- Contract management with renewal monitoring
- Vendor performance reviews and scoring
- Procurement request workflow (submit/approve/order/receive)
- Vendor risk assessment and tracking
- Spend analytics and concentration risk analysis
- Renewal calendar and expiring contract alerts
- Consolidated vendor dashboard

G-46 pattern: DB persistence with in-memory fallback.
"""

import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.vendor_management import (
        VendorModel,
        VendorContractModel,
        VendorReviewModel,
        ProcurementRequestModel,
        VendorRiskModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class VendorCategory(str, Enum):
    """Vendor category classification."""
    HARDWARE = "hardware"
    SOFTWARE = "software"
    CLOUD = "cloud"
    TELECOM = "telecom"
    SECURITY = "security"
    MANAGED_SERVICES = "managed_services"
    CONSULTING = "consulting"
    SUPPORT = "support"


class VendorStatus(str, Enum):
    """Vendor operational status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNDER_REVIEW = "under_review"
    BLOCKED = "blocked"


class ContractType(str, Enum):
    """Contract type classification."""
    SUBSCRIPTION = "subscription"
    LICENSE = "license"
    SUPPORT = "support"
    MAINTENANCE = "maintenance"
    PROJECT = "project"
    LEASE = "lease"


class ContractStatus(str, Enum):
    """Contract lifecycle status."""
    DRAFT = "draft"
    ACTIVE = "active"
    EXPIRING = "expiring"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ProcurementStatus(str, Enum):
    """Procurement request status."""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    ORDERED = "ordered"
    RECEIVED = "received"
    CANCELLED = "cancelled"


class RiskType(str, Enum):
    """Vendor risk type classification."""
    FINANCIAL = "financial"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    CONCENTRATION = "concentration"


class RiskSeverity(str, Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskStatus(str, Enum):
    """Risk tracking status."""
    IDENTIFIED = "identified"
    MITIGATING = "mitigating"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class Vendor:
    """Technology vendor record."""
    vendor_id: str
    name: str
    category: str = VendorCategory.SOFTWARE.value
    contact_name: str = ""
    contact_email: str = ""
    contact_phone: str = ""
    website: str = ""
    account_number: str = ""
    account_rep: str = ""
    status: str = VendorStatus.ACTIVE.value
    risk_tier: str = "low"
    performance_score: float = 0.0
    contracts: List[str] = field(default_factory=list)
    total_spend_ytd: float = 0.0
    payment_terms: str = "net30"
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class VendorContract:
    """Vendor contract record."""
    contract_id: str
    vendor_id: str
    client_id: str = ""
    title: str = ""
    contract_type: str = ContractType.SUBSCRIPTION.value
    value_monthly: float = 0.0
    value_annual: float = 0.0
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    auto_renew: bool = False
    cancellation_notice_days: int = 30
    sla_terms: Dict[str, Any] = field(default_factory=dict)
    deliverables: List[str] = field(default_factory=list)
    status: str = ContractStatus.DRAFT.value
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class VendorReview:
    """Vendor performance review."""
    review_id: str
    vendor_id: str
    review_period: str = ""
    quality_score: float = 0.0
    delivery_score: float = 0.0
    communication_score: float = 0.0
    value_score: float = 0.0
    overall_score: float = 0.0
    strengths: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    recommendation: str = ""
    reviewed_by: str = ""
    reviewed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ProcurementRequest:
    """Procurement request record."""
    request_id: str
    client_id: str = ""
    vendor_id: str = ""
    title: str = ""
    description: str = ""
    items: List[Dict[str, Any]] = field(default_factory=list)
    estimated_cost: float = 0.0
    status: str = ProcurementStatus.DRAFT.value
    requested_by: str = ""
    approved_by: str = ""
    po_number: str = ""
    ordered_at: Optional[datetime] = None
    received_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class VendorRisk:
    """Vendor risk assessment."""
    risk_id: str
    vendor_id: str
    risk_type: str = RiskType.OPERATIONAL.value
    severity: str = RiskSeverity.MEDIUM.value
    description: str = ""
    mitigation: str = ""
    status: str = RiskStatus.IDENTIFIED.value
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _vendor_from_row(row) -> Vendor:
    return Vendor(
        vendor_id=row.vendor_id,
        name=row.name,
        category=row.category or VendorCategory.SOFTWARE.value,
        contact_name=row.contact_name or "",
        contact_email=row.contact_email or "",
        contact_phone=row.contact_phone or "",
        website=row.website or "",
        account_number=row.account_number or "",
        account_rep=row.account_rep or "",
        status=row.status or VendorStatus.ACTIVE.value,
        risk_tier=row.risk_tier or "low",
        performance_score=row.performance_score or 0.0,
        total_spend_ytd=row.total_spend_ytd or 0.0,
        payment_terms=row.payment_terms or "net30",
        notes=row.notes or "",
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _contract_from_row(row) -> VendorContract:
    return VendorContract(
        contract_id=row.contract_id,
        vendor_id=row.vendor_id,
        client_id=row.client_id or "",
        title=row.title or "",
        contract_type=row.contract_type or ContractType.SUBSCRIPTION.value,
        value_monthly=row.value_monthly or 0.0,
        value_annual=row.value_annual or 0.0,
        start_date=row.start_date,
        end_date=row.end_date,
        auto_renew=row.auto_renew if row.auto_renew is not None else False,
        cancellation_notice_days=row.cancellation_notice_days or 30,
        sla_terms=row.sla_terms or {},
        deliverables=row.deliverables or [],
        status=row.status or ContractStatus.DRAFT.value,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _review_from_row(row) -> VendorReview:
    return VendorReview(
        review_id=row.review_id,
        vendor_id=row.vendor_id,
        review_period=row.review_period or "",
        quality_score=row.quality_score or 0.0,
        delivery_score=row.delivery_score or 0.0,
        communication_score=row.communication_score or 0.0,
        value_score=row.value_score or 0.0,
        overall_score=row.overall_score or 0.0,
        strengths=row.strengths or [],
        weaknesses=row.weaknesses or [],
        recommendation=row.recommendation or "",
        reviewed_by=row.reviewed_by or "",
        reviewed_at=row.reviewed_at or datetime.now(timezone.utc),
    )


def _procurement_from_row(row) -> ProcurementRequest:
    return ProcurementRequest(
        request_id=row.request_id,
        client_id=row.client_id or "",
        vendor_id=row.vendor_id,
        title=row.title or "",
        description=row.description or "",
        items=row.items or [],
        estimated_cost=row.estimated_cost or 0.0,
        status=row.status or ProcurementStatus.DRAFT.value,
        requested_by=row.requested_by or "",
        approved_by=row.approved_by or "",
        po_number=row.po_number or "",
        ordered_at=row.ordered_at,
        received_at=row.received_at,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _risk_from_row(row) -> VendorRisk:
    return VendorRisk(
        risk_id=row.risk_id,
        vendor_id=row.vendor_id,
        risk_type=row.risk_type or RiskType.OPERATIONAL.value,
        severity=row.severity or RiskSeverity.MEDIUM.value,
        description=row.description or "",
        mitigation=row.mitigation or "",
        status=row.status or RiskStatus.IDENTIFIED.value,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


# ============================================================
# Serialisation helpers (dataclass -> dict for API responses)
# ============================================================

def _vendor_to_dict(v: Vendor) -> dict:
    return {
        "vendor_id": v.vendor_id,
        "name": v.name,
        "category": v.category,
        "contact_name": v.contact_name,
        "contact_email": v.contact_email,
        "contact_phone": v.contact_phone,
        "website": v.website,
        "account_number": v.account_number,
        "account_rep": v.account_rep,
        "status": v.status,
        "risk_tier": v.risk_tier,
        "performance_score": v.performance_score,
        "contracts": v.contracts,
        "total_spend_ytd": v.total_spend_ytd,
        "payment_terms": v.payment_terms,
        "notes": v.notes,
        "created_at": v.created_at.isoformat() if v.created_at else None,
        "updated_at": v.updated_at.isoformat() if v.updated_at else None,
    }


def _contract_to_dict(c: VendorContract) -> dict:
    return {
        "contract_id": c.contract_id,
        "vendor_id": c.vendor_id,
        "client_id": c.client_id,
        "title": c.title,
        "contract_type": c.contract_type,
        "value_monthly": c.value_monthly,
        "value_annual": c.value_annual,
        "start_date": c.start_date.isoformat() if c.start_date else None,
        "end_date": c.end_date.isoformat() if c.end_date else None,
        "auto_renew": c.auto_renew,
        "cancellation_notice_days": c.cancellation_notice_days,
        "sla_terms": c.sla_terms,
        "deliverables": c.deliverables,
        "status": c.status,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _review_to_dict(r: VendorReview) -> dict:
    return {
        "review_id": r.review_id,
        "vendor_id": r.vendor_id,
        "review_period": r.review_period,
        "quality_score": r.quality_score,
        "delivery_score": r.delivery_score,
        "communication_score": r.communication_score,
        "value_score": r.value_score,
        "overall_score": r.overall_score,
        "strengths": r.strengths,
        "weaknesses": r.weaknesses,
        "recommendation": r.recommendation,
        "reviewed_by": r.reviewed_by,
        "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
    }


def _procurement_to_dict(p: ProcurementRequest) -> dict:
    return {
        "request_id": p.request_id,
        "client_id": p.client_id,
        "vendor_id": p.vendor_id,
        "title": p.title,
        "description": p.description,
        "items": p.items,
        "estimated_cost": p.estimated_cost,
        "status": p.status,
        "requested_by": p.requested_by,
        "approved_by": p.approved_by,
        "po_number": p.po_number,
        "ordered_at": p.ordered_at.isoformat() if p.ordered_at else None,
        "received_at": p.received_at.isoformat() if p.received_at else None,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _risk_to_dict(r: VendorRisk) -> dict:
    return {
        "risk_id": r.risk_id,
        "vendor_id": r.vendor_id,
        "risk_type": r.risk_type,
        "severity": r.severity,
        "description": r.description,
        "mitigation": r.mitigation,
        "status": r.status,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


# ============================================================
# Service
# ============================================================

class VendorManagementService:
    """
    Vendor Management Service

    Tracks technology vendors, manages contracts, evaluates performance,
    and handles procurement workflows for MSP operations.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._vendors: Dict[str, Vendor] = {}
        self._contracts: Dict[str, VendorContract] = {}
        self._reviews: Dict[str, VendorReview] = {}
        self._procurement: Dict[str, ProcurementRequest] = {}
        self._risks: Dict[str, VendorRisk] = {}

    # ----------------------------------------------------------
    # ID helpers
    # ----------------------------------------------------------

    @staticmethod
    def _gen_id(prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:12]}"

    # ==========================================================
    # Vendor CRUD
    # ==========================================================

    def create_vendor(self, name: str, category: str = "software", **kwargs) -> Vendor:
        """Register a new technology vendor."""
        vid = self._gen_id("VND")
        vendor = Vendor(
            vendor_id=vid,
            name=name,
            category=category,
            contact_name=kwargs.get("contact_name", ""),
            contact_email=kwargs.get("contact_email", ""),
            contact_phone=kwargs.get("contact_phone", ""),
            website=kwargs.get("website", ""),
            account_number=kwargs.get("account_number", ""),
            account_rep=kwargs.get("account_rep", ""),
            status=kwargs.get("status", VendorStatus.ACTIVE.value),
            risk_tier=kwargs.get("risk_tier", "low"),
            performance_score=kwargs.get("performance_score", 0.0),
            total_spend_ytd=kwargs.get("total_spend_ytd", 0.0),
            payment_terms=kwargs.get("payment_terms", "net30"),
            notes=kwargs.get("notes", ""),
        )
        if self._use_db:
            row = VendorModel(
                vendor_id=vid, name=name, category=category,
                contact_name=vendor.contact_name, contact_email=vendor.contact_email,
                contact_phone=vendor.contact_phone, website=vendor.website,
                account_number=vendor.account_number, account_rep=vendor.account_rep,
                status=vendor.status, risk_tier=vendor.risk_tier,
                performance_score=vendor.performance_score,
                total_spend_ytd=vendor.total_spend_ytd,
                payment_terms=vendor.payment_terms, notes=vendor.notes,
            )
            self.db.add(row)
            self.db.commit()
            logger.info("Vendor %s persisted to DB", vid)
        else:
            self._vendors[vid] = vendor
        return vendor

    def get_vendor(self, vendor_id: str) -> Optional[Vendor]:
        """Retrieve a vendor by ID."""
        if self._use_db:
            row = self.db.query(VendorModel).filter(VendorModel.vendor_id == vendor_id).first()
            if row:
                v = _vendor_from_row(row)
                # Attach contract IDs
                contracts = self.db.query(VendorContractModel.contract_id).filter(
                    VendorContractModel.vendor_id == vendor_id
                ).all()
                v.contracts = [c[0] for c in contracts]
                return v
            return None
        return self._vendors.get(vendor_id)

    def update_vendor(self, vendor_id: str, **kwargs) -> Optional[Vendor]:
        """Update vendor fields."""
        if self._use_db:
            row = self.db.query(VendorModel).filter(VendorModel.vendor_id == vendor_id).first()
            if not row:
                return None
            for k, v in kwargs.items():
                if hasattr(row, k):
                    setattr(row, k, v)
            self.db.commit()
            return _vendor_from_row(row)
        vendor = self._vendors.get(vendor_id)
        if not vendor:
            return None
        for k, v in kwargs.items():
            if hasattr(vendor, k):
                setattr(vendor, k, v)
        vendor.updated_at = datetime.now(timezone.utc)
        return vendor

    def delete_vendor(self, vendor_id: str) -> bool:
        """Remove a vendor record."""
        if self._use_db:
            row = self.db.query(VendorModel).filter(VendorModel.vendor_id == vendor_id).first()
            if not row:
                return False
            self.db.delete(row)
            self.db.commit()
            return True
        return self._vendors.pop(vendor_id, None) is not None

    def list_vendors(self, category: str = None, status: str = None) -> List[Vendor]:
        """List vendors with optional filters."""
        if self._use_db:
            q = self.db.query(VendorModel)
            if category:
                q = q.filter(VendorModel.category == category)
            if status:
                q = q.filter(VendorModel.status == status)
            return [_vendor_from_row(r) for r in q.all()]
        results = list(self._vendors.values())
        if category:
            results = [v for v in results if v.category == category]
        if status:
            results = [v for v in results if v.status == status]
        return results

    def search_vendors(self, query: str) -> List[Vendor]:
        """Search vendors by name or notes (case-insensitive)."""
        q_lower = query.lower()
        if self._use_db:
            rows = self.db.query(VendorModel).filter(
                VendorModel.name.ilike(f"%{query}%")
            ).all()
            return [_vendor_from_row(r) for r in rows]
        return [
            v for v in self._vendors.values()
            if q_lower in v.name.lower() or q_lower in v.notes.lower()
        ]

    # ==========================================================
    # Contract CRUD
    # ==========================================================

    def create_contract(self, vendor_id: str, title: str, contract_type: str = "subscription", **kwargs) -> VendorContract:
        """Create a new vendor contract."""
        cid = self._gen_id("VCTR")
        contract = VendorContract(
            contract_id=cid,
            vendor_id=vendor_id,
            client_id=kwargs.get("client_id", ""),
            title=title,
            contract_type=contract_type,
            value_monthly=kwargs.get("value_monthly", 0.0),
            value_annual=kwargs.get("value_annual", 0.0),
            start_date=kwargs.get("start_date"),
            end_date=kwargs.get("end_date"),
            auto_renew=kwargs.get("auto_renew", False),
            cancellation_notice_days=kwargs.get("cancellation_notice_days", 30),
            sla_terms=kwargs.get("sla_terms", {}),
            deliverables=kwargs.get("deliverables", []),
            status=kwargs.get("status", ContractStatus.ACTIVE.value),
        )
        if self._use_db:
            row = VendorContractModel(
                contract_id=cid, vendor_id=vendor_id,
                client_id=contract.client_id, title=title,
                contract_type=contract_type,
                value_monthly=contract.value_monthly,
                value_annual=contract.value_annual,
                start_date=contract.start_date, end_date=contract.end_date,
                auto_renew=contract.auto_renew,
                cancellation_notice_days=contract.cancellation_notice_days,
                sla_terms=contract.sla_terms, deliverables=contract.deliverables,
                status=contract.status,
            )
            self.db.add(row)
            self.db.commit()
            logger.info("Contract %s persisted to DB", cid)
        else:
            self._contracts[cid] = contract
            # Link to vendor
            vendor = self._vendors.get(vendor_id)
            if vendor:
                vendor.contracts.append(cid)
        return contract

    def get_contract(self, contract_id: str) -> Optional[VendorContract]:
        """Retrieve a contract by ID."""
        if self._use_db:
            row = self.db.query(VendorContractModel).filter(
                VendorContractModel.contract_id == contract_id
            ).first()
            return _contract_from_row(row) if row else None
        return self._contracts.get(contract_id)

    def update_contract(self, contract_id: str, **kwargs) -> Optional[VendorContract]:
        """Update contract fields."""
        if self._use_db:
            row = self.db.query(VendorContractModel).filter(
                VendorContractModel.contract_id == contract_id
            ).first()
            if not row:
                return None
            for k, v in kwargs.items():
                if hasattr(row, k):
                    setattr(row, k, v)
            self.db.commit()
            return _contract_from_row(row)
        contract = self._contracts.get(contract_id)
        if not contract:
            return None
        for k, v in kwargs.items():
            if hasattr(contract, k):
                setattr(contract, k, v)
        contract.updated_at = datetime.now(timezone.utc)
        return contract

    def delete_contract(self, contract_id: str) -> bool:
        """Remove a contract record."""
        if self._use_db:
            row = self.db.query(VendorContractModel).filter(
                VendorContractModel.contract_id == contract_id
            ).first()
            if not row:
                return False
            self.db.delete(row)
            self.db.commit()
            return True
        return self._contracts.pop(contract_id, None) is not None

    def list_contracts(self, vendor_id: str = None, status: str = None) -> List[VendorContract]:
        """List contracts with optional filters."""
        if self._use_db:
            q = self.db.query(VendorContractModel)
            if vendor_id:
                q = q.filter(VendorContractModel.vendor_id == vendor_id)
            if status:
                q = q.filter(VendorContractModel.status == status)
            return [_contract_from_row(r) for r in q.all()]
        results = list(self._contracts.values())
        if vendor_id:
            results = [c for c in results if c.vendor_id == vendor_id]
        if status:
            results = [c for c in results if c.status == status]
        return results

    def get_expiring_contracts(self, days: int = 30) -> List[VendorContract]:
        """Find contracts expiring within the given number of days."""
        cutoff = datetime.now(timezone.utc) + timedelta(days=days)
        now = datetime.now(timezone.utc)
        if self._use_db:
            rows = self.db.query(VendorContractModel).filter(
                VendorContractModel.end_date <= cutoff,
                VendorContractModel.end_date >= now,
                VendorContractModel.status == ContractStatus.ACTIVE.value,
            ).all()
            return [_contract_from_row(r) for r in rows]
        return [
            c for c in self._contracts.values()
            if c.end_date and now <= c.end_date <= cutoff
            and c.status == ContractStatus.ACTIVE.value
        ]

    # ==========================================================
    # Vendor Reviews
    # ==========================================================

    def create_review(self, vendor_id: str, **kwargs) -> VendorReview:
        """Create a vendor performance review."""
        rid = self._gen_id("VREV")
        quality = kwargs.get("quality_score", 0.0)
        delivery = kwargs.get("delivery_score", 0.0)
        communication = kwargs.get("communication_score", 0.0)
        value = kwargs.get("value_score", 0.0)
        overall = (quality + delivery + communication + value) / 4.0 if any([quality, delivery, communication, value]) else 0.0

        review = VendorReview(
            review_id=rid,
            vendor_id=vendor_id,
            review_period=kwargs.get("review_period", ""),
            quality_score=quality,
            delivery_score=delivery,
            communication_score=communication,
            value_score=value,
            overall_score=round(overall, 2),
            strengths=kwargs.get("strengths", []),
            weaknesses=kwargs.get("weaknesses", []),
            recommendation=kwargs.get("recommendation", ""),
            reviewed_by=kwargs.get("reviewed_by", ""),
        )
        if self._use_db:
            row = VendorReviewModel(
                review_id=rid, vendor_id=vendor_id,
                review_period=review.review_period,
                quality_score=review.quality_score,
                delivery_score=review.delivery_score,
                communication_score=review.communication_score,
                value_score=review.value_score,
                overall_score=review.overall_score,
                strengths=review.strengths, weaknesses=review.weaknesses,
                recommendation=review.recommendation,
                reviewed_by=review.reviewed_by,
            )
            self.db.add(row)
            self.db.commit()
            # Update vendor performance score
            self._update_vendor_performance(vendor_id)
        else:
            self._reviews[rid] = review
            self._update_vendor_performance(vendor_id)
        return review

    def get_reviews(self, vendor_id: str) -> List[VendorReview]:
        """Get all reviews for a vendor."""
        if self._use_db:
            rows = self.db.query(VendorReviewModel).filter(
                VendorReviewModel.vendor_id == vendor_id
            ).order_by(VendorReviewModel.reviewed_at.desc()).all()
            return [_review_from_row(r) for r in rows]
        return [r for r in self._reviews.values() if r.vendor_id == vendor_id]

    def calculate_vendor_score(self, vendor_id: str) -> float:
        """Calculate weighted average performance score from reviews."""
        reviews = self.get_reviews(vendor_id)
        if not reviews:
            return 0.0
        # Weight recent reviews more heavily
        total_weight = 0.0
        weighted_sum = 0.0
        for i, review in enumerate(reviews):
            weight = 1.0 / (i + 1)  # most recent has highest weight
            weighted_sum += review.overall_score * weight
            total_weight += weight
        return round(weighted_sum / total_weight, 2) if total_weight > 0 else 0.0

    def _update_vendor_performance(self, vendor_id: str):
        """Recalculate and persist vendor performance score."""
        score = self.calculate_vendor_score(vendor_id)
        self.update_vendor(vendor_id, performance_score=score)

    def compare_vendors(self, vendor_ids: List[str]) -> List[dict]:
        """Compare multiple vendors side-by-side on key metrics."""
        results = []
        for vid in vendor_ids:
            vendor = self.get_vendor(vid)
            if not vendor:
                continue
            contracts = self.list_contracts(vendor_id=vid)
            reviews = self.get_reviews(vid)
            risks = self.get_risks(vid)
            results.append({
                "vendor_id": vid,
                "name": vendor.name,
                "category": vendor.category,
                "status": vendor.status,
                "performance_score": vendor.performance_score,
                "risk_tier": vendor.risk_tier,
                "total_spend_ytd": vendor.total_spend_ytd,
                "active_contracts": len([c for c in contracts if c.status == ContractStatus.ACTIVE.value]),
                "total_annual_value": sum(c.value_annual for c in contracts if c.status == ContractStatus.ACTIVE.value),
                "review_count": len(reviews),
                "avg_review_score": round(sum(r.overall_score for r in reviews) / len(reviews), 2) if reviews else 0.0,
                "open_risks": len([r for r in risks if r.status != RiskStatus.RESOLVED.value]),
            })
        return sorted(results, key=lambda x: x["performance_score"], reverse=True)

    # ==========================================================
    # Procurement
    # ==========================================================

    def submit_request(self, vendor_id: str, title: str, **kwargs) -> ProcurementRequest:
        """Submit a new procurement request."""
        rid = self._gen_id("PROC")
        req = ProcurementRequest(
            request_id=rid,
            vendor_id=vendor_id,
            client_id=kwargs.get("client_id", ""),
            title=title,
            description=kwargs.get("description", ""),
            items=kwargs.get("items", []),
            estimated_cost=kwargs.get("estimated_cost", 0.0),
            status=ProcurementStatus.SUBMITTED.value,
            requested_by=kwargs.get("requested_by", ""),
        )
        if self._use_db:
            row = ProcurementRequestModel(
                request_id=rid, vendor_id=vendor_id,
                client_id=req.client_id, title=title,
                description=req.description, items=req.items,
                estimated_cost=req.estimated_cost,
                status=req.status, requested_by=req.requested_by,
            )
            self.db.add(row)
            self.db.commit()
        else:
            self._procurement[rid] = req
        return req

    def approve_request(self, request_id: str, approved_by: str = "") -> Optional[ProcurementRequest]:
        """Approve a procurement request."""
        return self._update_procurement_status(
            request_id, ProcurementStatus.APPROVED.value, approved_by=approved_by
        )

    def mark_ordered(self, request_id: str, po_number: str = "") -> Optional[ProcurementRequest]:
        """Mark a procurement request as ordered."""
        return self._update_procurement_status(
            request_id, ProcurementStatus.ORDERED.value, po_number=po_number,
            ordered_at=datetime.now(timezone.utc),
        )

    def mark_received(self, request_id: str) -> Optional[ProcurementRequest]:
        """Mark a procurement request as received."""
        return self._update_procurement_status(
            request_id, ProcurementStatus.RECEIVED.value,
            received_at=datetime.now(timezone.utc),
        )

    def _update_procurement_status(self, request_id: str, status: str, **kwargs) -> Optional[ProcurementRequest]:
        """Internal helper to update procurement request."""
        if self._use_db:
            row = self.db.query(ProcurementRequestModel).filter(
                ProcurementRequestModel.request_id == request_id
            ).first()
            if not row:
                return None
            row.status = status
            for k, v in kwargs.items():
                if hasattr(row, k):
                    setattr(row, k, v)
            self.db.commit()
            return _procurement_from_row(row)
        req = self._procurement.get(request_id)
        if not req:
            return None
        req.status = status
        for k, v in kwargs.items():
            if hasattr(req, k):
                setattr(req, k, v)
        req.updated_at = datetime.now(timezone.utc)
        return req

    def get_request(self, request_id: str) -> Optional[ProcurementRequest]:
        """Retrieve a procurement request by ID."""
        if self._use_db:
            row = self.db.query(ProcurementRequestModel).filter(
                ProcurementRequestModel.request_id == request_id
            ).first()
            return _procurement_from_row(row) if row else None
        return self._procurement.get(request_id)

    def get_requests(self, vendor_id: str = None, status: str = None, client_id: str = None) -> List[ProcurementRequest]:
        """List procurement requests with optional filters."""
        if self._use_db:
            q = self.db.query(ProcurementRequestModel)
            if vendor_id:
                q = q.filter(ProcurementRequestModel.vendor_id == vendor_id)
            if status:
                q = q.filter(ProcurementRequestModel.status == status)
            if client_id:
                q = q.filter(ProcurementRequestModel.client_id == client_id)
            return [_procurement_from_row(r) for r in q.all()]
        results = list(self._procurement.values())
        if vendor_id:
            results = [r for r in results if r.vendor_id == vendor_id]
        if status:
            results = [r for r in results if r.status == status]
        if client_id:
            results = [r for r in results if r.client_id == client_id]
        return results

    # ==========================================================
    # Risk Management
    # ==========================================================

    def add_risk(self, vendor_id: str, risk_type: str, severity: str, description: str, **kwargs) -> VendorRisk:
        """Record a vendor risk assessment."""
        rid = self._gen_id("VRSK")
        risk = VendorRisk(
            risk_id=rid,
            vendor_id=vendor_id,
            risk_type=risk_type,
            severity=severity,
            description=description,
            mitigation=kwargs.get("mitigation", ""),
            status=kwargs.get("status", RiskStatus.IDENTIFIED.value),
        )
        if self._use_db:
            row = VendorRiskModel(
                risk_id=rid, vendor_id=vendor_id,
                risk_type=risk_type, severity=severity,
                description=description, mitigation=risk.mitigation,
                status=risk.status,
            )
            self.db.add(row)
            self.db.commit()
        else:
            self._risks[rid] = risk
        return risk

    def get_risks(self, vendor_id: str) -> List[VendorRisk]:
        """Get all risks for a vendor."""
        if self._use_db:
            rows = self.db.query(VendorRiskModel).filter(
                VendorRiskModel.vendor_id == vendor_id
            ).all()
            return [_risk_from_row(r) for r in rows]
        return [r for r in self._risks.values() if r.vendor_id == vendor_id]

    def update_risk(self, risk_id: str, **kwargs) -> Optional[VendorRisk]:
        """Update a risk assessment."""
        if self._use_db:
            row = self.db.query(VendorRiskModel).filter(
                VendorRiskModel.risk_id == risk_id
            ).first()
            if not row:
                return None
            for k, v in kwargs.items():
                if hasattr(row, k):
                    setattr(row, k, v)
            self.db.commit()
            return _risk_from_row(row)
        risk = self._risks.get(risk_id)
        if not risk:
            return None
        for k, v in kwargs.items():
            if hasattr(risk, k):
                setattr(risk, k, v)
        risk.updated_at = datetime.now(timezone.utc)
        return risk

    def get_high_risk_vendors(self) -> List[Vendor]:
        """Get vendors with high or critical risk tier."""
        if self._use_db:
            rows = self.db.query(VendorModel).filter(
                VendorModel.risk_tier.in_(["high", "critical"])
            ).all()
            return [_vendor_from_row(r) for r in rows]
        return [v for v in self._vendors.values() if v.risk_tier in ("high", "critical")]

    # ==========================================================
    # Analytics & Reporting
    # ==========================================================

    def get_vendor_spend_report(self) -> Dict[str, Any]:
        """Generate vendor spend analytics."""
        vendors = self.list_vendors()
        total_spend = sum(v.total_spend_ytd for v in vendors)
        by_category: Dict[str, float] = {}
        for v in vendors:
            by_category[v.category] = by_category.get(v.category, 0.0) + v.total_spend_ytd
        top_vendors = sorted(vendors, key=lambda x: x.total_spend_ytd, reverse=True)[:10]
        return {
            "total_spend_ytd": round(total_spend, 2),
            "vendor_count": len(vendors),
            "spend_by_category": by_category,
            "top_vendors": [
                {"vendor_id": v.vendor_id, "name": v.name, "spend": v.total_spend_ytd}
                for v in top_vendors
            ],
            "average_spend": round(total_spend / len(vendors), 2) if vendors else 0.0,
        }

    def get_category_breakdown(self) -> Dict[str, Any]:
        """Get vendor count and spend breakdown by category."""
        vendors = self.list_vendors()
        breakdown: Dict[str, dict] = {}
        for v in vendors:
            cat = v.category
            if cat not in breakdown:
                breakdown[cat] = {"count": 0, "total_spend": 0.0, "avg_performance": 0.0, "scores": []}
            breakdown[cat]["count"] += 1
            breakdown[cat]["total_spend"] += v.total_spend_ytd
            if v.performance_score > 0:
                breakdown[cat]["scores"].append(v.performance_score)
        for cat, data in breakdown.items():
            scores = data.pop("scores")
            data["avg_performance"] = round(sum(scores) / len(scores), 2) if scores else 0.0
            data["total_spend"] = round(data["total_spend"], 2)
        return breakdown

    def get_renewal_calendar(self, months: int = 6) -> List[dict]:
        """Get contracts expiring in the next N months grouped by month."""
        cutoff = datetime.now(timezone.utc) + timedelta(days=months * 30)
        now = datetime.now(timezone.utc)
        if self._use_db:
            rows = self.db.query(VendorContractModel).filter(
                VendorContractModel.end_date <= cutoff,
                VendorContractModel.end_date >= now,
                VendorContractModel.status.in_([ContractStatus.ACTIVE.value, ContractStatus.EXPIRING.value]),
            ).order_by(VendorContractModel.end_date).all()
            contracts = [_contract_from_row(r) for r in rows]
        else:
            contracts = sorted(
                [c for c in self._contracts.values()
                 if c.end_date and now <= c.end_date <= cutoff
                 and c.status in (ContractStatus.ACTIVE.value, ContractStatus.EXPIRING.value)],
                key=lambda c: c.end_date,
            )
        # Group by month
        calendar: Dict[str, list] = {}
        for c in contracts:
            month_key = c.end_date.strftime("%Y-%m")
            if month_key not in calendar:
                calendar[month_key] = []
            calendar[month_key].append(_contract_to_dict(c))
        return [{"month": k, "contracts": v, "count": len(v)} for k, v in sorted(calendar.items())]

    def get_concentration_risk(self, client_id: str) -> Dict[str, Any]:
        """Analyse single-vendor dependency for a client."""
        if self._use_db:
            contracts = self.db.query(VendorContractModel).filter(
                VendorContractModel.client_id == client_id,
                VendorContractModel.status == ContractStatus.ACTIVE.value,
            ).all()
            contracts = [_contract_from_row(r) for r in contracts]
        else:
            contracts = [
                c for c in self._contracts.values()
                if c.client_id == client_id and c.status == ContractStatus.ACTIVE.value
            ]

        if not contracts:
            return {"client_id": client_id, "risk_level": "none", "vendors": [], "total_annual_spend": 0.0}

        vendor_spend: Dict[str, float] = {}
        for c in contracts:
            vendor_spend[c.vendor_id] = vendor_spend.get(c.vendor_id, 0.0) + c.value_annual
        total_spend = sum(vendor_spend.values())

        concentration = []
        for vid, spend in vendor_spend.items():
            pct = round((spend / total_spend) * 100, 2) if total_spend > 0 else 0
            vendor = self.get_vendor(vid)
            concentration.append({
                "vendor_id": vid,
                "vendor_name": vendor.name if vendor else "Unknown",
                "annual_spend": spend,
                "spend_percentage": pct,
                "is_concentrated": pct > 40,
            })

        max_pct = max(c["spend_percentage"] for c in concentration)
        if max_pct > 60:
            risk_level = "critical"
        elif max_pct > 40:
            risk_level = "high"
        elif max_pct > 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "client_id": client_id,
            "risk_level": risk_level,
            "total_annual_spend": round(total_spend, 2),
            "vendor_count": len(concentration),
            "vendors": sorted(concentration, key=lambda x: x["annual_spend"], reverse=True),
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Consolidated vendor management dashboard."""
        vendors = self.list_vendors()
        active = [v for v in vendors if v.status == VendorStatus.ACTIVE.value]
        contracts = self.list_contracts()
        active_contracts = [c for c in contracts if c.status == ContractStatus.ACTIVE.value]
        expiring_30 = self.get_expiring_contracts(30)
        high_risk = self.get_high_risk_vendors()

        total_monthly = sum(c.value_monthly for c in active_contracts)
        total_annual = sum(c.value_annual for c in active_contracts)

        # Procurement summary
        if self._use_db:
            all_proc = self.db.query(ProcurementRequestModel).all()
            proc_list = [_procurement_from_row(r) for r in all_proc]
        else:
            proc_list = list(self._procurement.values())
        pending_proc = [p for p in proc_list if p.status in (ProcurementStatus.SUBMITTED.value, ProcurementStatus.APPROVED.value)]

        # Performance distribution
        perf_dist = {"excellent": 0, "good": 0, "average": 0, "poor": 0, "unscored": 0}
        for v in active:
            score = v.performance_score
            if score == 0:
                perf_dist["unscored"] += 1
            elif score >= 85:
                perf_dist["excellent"] += 1
            elif score >= 70:
                perf_dist["good"] += 1
            elif score >= 50:
                perf_dist["average"] += 1
            else:
                perf_dist["poor"] += 1

        return {
            "total_vendors": len(vendors),
            "active_vendors": len(active),
            "total_contracts": len(contracts),
            "active_contracts": len(active_contracts),
            "expiring_contracts_30d": len(expiring_30),
            "high_risk_vendors": len(high_risk),
            "total_monthly_value": round(total_monthly, 2),
            "total_annual_value": round(total_annual, 2),
            "pending_procurement": len(pending_proc),
            "performance_distribution": perf_dist,
            "category_breakdown": self.get_category_breakdown(),
            "spend_report": self.get_vendor_spend_report(),
        }
