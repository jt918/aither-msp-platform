"""
AITHER Platform - CMDB (Configuration Management Database) Service
Single source of truth for all IT configuration items and their relationships.

Provides:
- Configuration Item (CI) lifecycle management
- CI relationship mapping and dependency graphing
- Configuration baselines and drift detection
- Change tracking and audit trail
- Impact analysis via recursive dependency traversal
- RMM / network discovery sync
- Topology visualization and dashboards

G-46: DB persistence with in-memory fallback.
"""

import uuid
import json
import logging
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.cmdb import (
        ConfigurationItemModel,
        CIRelationshipModel,
        ConfigurationBaselineModel,
        ConfigurationChangeModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class CIType(str, Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    NETWORK_SWITCH = "network_switch"
    ROUTER = "router"
    FIREWALL = "firewall"
    ACCESS_POINT = "access_point"
    PRINTER = "printer"
    UPS = "ups"
    STORAGE = "storage"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    DATABASE = "database"
    APPLICATION = "application"
    SERVICE = "service"
    LOAD_BALANCER = "load_balancer"
    VPN_CONCENTRATOR = "vpn_concentrator"
    PHONE_SYSTEM = "phone_system"
    SECURITY_APPLIANCE = "security_appliance"
    CLOUD_INSTANCE = "cloud_instance"


class CIStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    PLANNED = "planned"
    MAINTENANCE = "maintenance"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    DR = "dr"
    TEST = "test"


class RelationshipType(str, Enum):
    DEPENDS_ON = "depends_on"
    HOSTS = "hosts"
    CONNECTS_TO = "connects_to"
    BACKED_UP_BY = "backed_up_by"
    MONITORED_BY = "monitored_by"
    LICENSED_BY = "licensed_by"
    MANAGED_BY = "managed_by"
    MEMBER_OF = "member_of"
    RUNS_ON = "runs_on"
    COMMUNICATES_WITH = "communicates_with"


class ChangeType(str, Enum):
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    BASELINE_DRIFT = "baseline_drift"


class ChangeSource(str, Enum):
    MANUAL = "manual"
    AUTO_DISCOVERY = "auto_discovery"
    RMM_SYNC = "rmm_sync"
    API = "api"


class ImpactType(str, Enum):
    OUTAGE = "outage"
    CHANGE = "change"
    DECOMMISSION = "decommission"


class ImpactLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class ConfigurationItem:
    ci_id: str
    client_id: str
    ci_type: CIType
    name: str
    description: str = ""
    status: CIStatus = CIStatus.ACTIVE
    environment: Environment = Environment.PRODUCTION
    location: str = ""
    owner: str = ""
    department: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    serial_number: str = ""
    asset_tag: str = ""
    ip_address: str = ""
    mac_address: str = ""
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    configuration_data: Dict[str, Any] = field(default_factory=dict)
    last_audit_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class CIRelationship:
    relationship_id: str
    source_ci_id: str
    target_ci_id: str
    relationship_type: RelationshipType
    description: str = ""
    is_bidirectional: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ConfigurationBaseline:
    baseline_id: str
    ci_id: str
    baseline_name: str
    baseline_data: Dict[str, Any] = field(default_factory=dict)
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    captured_by: str = ""
    is_current: bool = True


@dataclass
class ConfigurationChange:
    change_id: str
    ci_id: str
    change_type: ChangeType
    field_changed: str = ""
    old_value: str = ""
    new_value: str = ""
    changed_by: str = "system"
    change_source: ChangeSource = ChangeSource.MANUAL
    changed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    change_ticket_id: str = ""


@dataclass
class ImpactAnalysis:
    analysis_id: str
    ci_id: str
    impact_type: ImpactType
    affected_cis: List[str] = field(default_factory=list)
    impact_level: ImpactLevel = ImpactLevel.NONE
    analysis_details: Dict[str, Any] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# ORM <-> dataclass conversion helpers
# ============================================================

def _ci_from_row(row) -> ConfigurationItem:
    return ConfigurationItem(
        ci_id=row.ci_id,
        client_id=row.client_id or "",
        ci_type=CIType(row.ci_type) if row.ci_type else CIType.SERVER,
        name=row.name,
        description=row.description or "",
        status=CIStatus(row.status) if row.status else CIStatus.ACTIVE,
        environment=Environment(row.environment) if row.environment else Environment.PRODUCTION,
        location=row.location or "",
        owner=row.owner or "",
        department=row.department or "",
        attributes=row.attributes or {},
        tags=row.tags or [],
        serial_number=row.serial_number or "",
        asset_tag=row.asset_tag or "",
        ip_address=row.ip_address or "",
        mac_address=row.mac_address or "",
        manufacturer=row.manufacturer or "",
        model=row.model or "",
        firmware_version=row.firmware_version or "",
        configuration_data=row.configuration_data or {},
        last_audit_at=row.last_audit_at,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _rel_from_row(row) -> CIRelationship:
    return CIRelationship(
        relationship_id=row.relationship_id,
        source_ci_id=row.source_ci_id,
        target_ci_id=row.target_ci_id,
        relationship_type=RelationshipType(row.relationship_type) if row.relationship_type else RelationshipType.DEPENDS_ON,
        description=row.description or "",
        is_bidirectional=row.is_bidirectional or False,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


def _baseline_from_row(row) -> ConfigurationBaseline:
    return ConfigurationBaseline(
        baseline_id=row.baseline_id,
        ci_id=row.ci_id,
        baseline_name=row.baseline_name,
        baseline_data=row.baseline_data or {},
        captured_at=row.captured_at or datetime.now(timezone.utc),
        captured_by=row.captured_by or "",
        is_current=row.is_current if row.is_current is not None else True,
    )


def _change_from_row(row) -> ConfigurationChange:
    return ConfigurationChange(
        change_id=row.change_id,
        ci_id=row.ci_id,
        change_type=ChangeType(row.change_type) if row.change_type else ChangeType.UPDATED,
        field_changed=row.field_changed or "",
        old_value=row.old_value or "",
        new_value=row.new_value or "",
        changed_by=row.changed_by or "system",
        change_source=ChangeSource(row.change_source) if row.change_source else ChangeSource.MANUAL,
        changed_at=row.changed_at or datetime.now(timezone.utc),
        change_ticket_id=row.change_ticket_id or "",
    )


# ============================================================
# Service
# ============================================================

class CMDBService:
    """
    CMDB Service - Configuration Management Database

    Single source of truth for all IT configuration items (CIs),
    their relationships, baselines, and change history.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._cis: Dict[str, ConfigurationItem] = {}
        self._relationships: Dict[str, CIRelationship] = {}
        self._baselines: Dict[str, ConfigurationBaseline] = {}
        self._changes: Dict[str, ConfigurationChange] = {}

    # ================================================================
    # CI CRUD
    # ================================================================

    def create_ci(
        self,
        client_id: str,
        ci_type: CIType,
        name: str,
        description: str = "",
        status: CIStatus = CIStatus.ACTIVE,
        environment: Environment = Environment.PRODUCTION,
        location: str = "",
        owner: str = "",
        department: str = "",
        attributes: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        serial_number: str = "",
        asset_tag: str = "",
        ip_address: str = "",
        mac_address: str = "",
        manufacturer: str = "",
        model: str = "",
        firmware_version: str = "",
        configuration_data: Optional[Dict[str, Any]] = None,
    ) -> ConfigurationItem:
        """Create a new Configuration Item."""
        ci_id = f"CI-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)

        ci = ConfigurationItem(
            ci_id=ci_id,
            client_id=client_id,
            ci_type=ci_type,
            name=name,
            description=description,
            status=status,
            environment=environment,
            location=location,
            owner=owner,
            department=department,
            attributes=attributes or {},
            tags=tags or [],
            serial_number=serial_number,
            asset_tag=asset_tag,
            ip_address=ip_address,
            mac_address=mac_address,
            manufacturer=manufacturer,
            model=model,
            firmware_version=firmware_version,
            configuration_data=configuration_data or {},
            created_at=now,
        )

        if self._use_db:
            try:
                row = ConfigurationItemModel(
                    ci_id=ci.ci_id,
                    client_id=ci.client_id,
                    ci_type=ci.ci_type.value,
                    name=ci.name,
                    description=ci.description,
                    status=ci.status.value,
                    environment=ci.environment.value,
                    location=ci.location,
                    owner=ci.owner,
                    department=ci.department,
                    attributes=ci.attributes,
                    tags=ci.tags,
                    serial_number=ci.serial_number,
                    asset_tag=ci.asset_tag,
                    ip_address=ci.ip_address,
                    mac_address=ci.mac_address,
                    manufacturer=ci.manufacturer,
                    model=ci.model,
                    firmware_version=ci.firmware_version,
                    configuration_data=ci.configuration_data,
                )
                self.db.add(row)
                self.db.commit()
                logger.info("CMDB CI %s persisted to DB", ci_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB persist failed for CI %s: %s", ci_id, exc)

        self._cis[ci_id] = ci

        # Record creation change
        self.record_change(ci_id, ChangeType.CREATED, change_source=ChangeSource.MANUAL)

        return ci

    def get_ci(self, ci_id: str) -> Optional[ConfigurationItem]:
        """Get a Configuration Item by ID."""
        if ci_id in self._cis:
            return self._cis[ci_id]

        if self._use_db:
            try:
                row = self.db.query(ConfigurationItemModel).filter(
                    ConfigurationItemModel.ci_id == ci_id
                ).first()
                if row:
                    ci = _ci_from_row(row)
                    self._cis[ci_id] = ci
                    return ci
            except Exception as exc:
                logger.warning("DB query failed for CI %s: %s", ci_id, exc)

        return None

    def list_cis(
        self,
        client_id: Optional[str] = None,
        ci_type: Optional[CIType] = None,
        status: Optional[CIStatus] = None,
        environment: Optional[Environment] = None,
    ) -> List[ConfigurationItem]:
        """List CIs with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(ConfigurationItemModel)
                if client_id:
                    q = q.filter(ConfigurationItemModel.client_id == client_id)
                if ci_type:
                    q = q.filter(ConfigurationItemModel.ci_type == ci_type.value)
                if status:
                    q = q.filter(ConfigurationItemModel.status == status.value)
                if environment:
                    q = q.filter(ConfigurationItemModel.environment == environment.value)
                rows = q.order_by(ConfigurationItemModel.name).all()
                results = [_ci_from_row(r) for r in rows]
                for ci in results:
                    self._cis[ci.ci_id] = ci
                return results
            except Exception as exc:
                logger.warning("DB list_cis failed: %s", exc)

        cis = list(self._cis.values())
        if client_id:
            cis = [c for c in cis if c.client_id == client_id]
        if ci_type:
            cis = [c for c in cis if c.ci_type == ci_type]
        if status:
            cis = [c for c in cis if c.status == status]
        if environment:
            cis = [c for c in cis if c.environment == environment]
        return sorted(cis, key=lambda c: c.name)

    def update_ci(self, ci_id: str, **kwargs) -> Optional[ConfigurationItem]:
        """Update a CI. Tracks changes automatically."""
        ci = self.get_ci(ci_id)
        if not ci:
            return None

        now = datetime.now(timezone.utc)
        changed_by = kwargs.pop("changed_by", "system")
        change_source = kwargs.pop("change_source", ChangeSource.MANUAL)

        for key, value in kwargs.items():
            if hasattr(ci, key):
                old_val = getattr(ci, key)
                if old_val != value:
                    # Record the change
                    self.record_change(
                        ci_id,
                        ChangeType.UPDATED,
                        field_changed=key,
                        old_value=str(old_val),
                        new_value=str(value),
                        changed_by=changed_by,
                        change_source=change_source,
                    )
                    setattr(ci, key, value)

        ci.updated_at = now
        self._cis[ci_id] = ci

        if self._use_db:
            try:
                row = self.db.query(ConfigurationItemModel).filter(
                    ConfigurationItemModel.ci_id == ci_id
                ).first()
                if row:
                    for key, value in kwargs.items():
                        col_val = value.value if isinstance(value, Enum) else value
                        if hasattr(row, key):
                            setattr(row, key, col_val)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for CI %s: %s", ci_id, exc)

        return ci

    def delete_ci(self, ci_id: str) -> bool:
        """Soft-delete a CI by setting status to decommissioned."""
        ci = self.get_ci(ci_id)
        if not ci:
            return False

        self.record_change(ci_id, ChangeType.DELETED, change_source=ChangeSource.MANUAL)
        ci.status = CIStatus.DECOMMISSIONED
        ci.updated_at = datetime.now(timezone.utc)
        self._cis[ci_id] = ci

        if self._use_db:
            try:
                row = self.db.query(ConfigurationItemModel).filter(
                    ConfigurationItemModel.ci_id == ci_id
                ).first()
                if row:
                    row.status = CIStatus.DECOMMISSIONED.value
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete failed for CI %s: %s", ci_id, exc)

        return True

    def search_cis(self, query: str, filters: Optional[Dict[str, Any]] = None) -> List[ConfigurationItem]:
        """Search CIs by name, description, IP, serial number, or asset tag."""
        q_lower = query.lower()
        filters = filters or {}

        cis = self.list_cis(
            client_id=filters.get("client_id"),
            ci_type=CIType(filters["ci_type"]) if filters.get("ci_type") else None,
            status=CIStatus(filters["status"]) if filters.get("status") else None,
            environment=Environment(filters["environment"]) if filters.get("environment") else None,
        )

        return [
            c for c in cis
            if q_lower in c.name.lower()
            or q_lower in c.description.lower()
            or q_lower in c.ip_address.lower()
            or q_lower in c.serial_number.lower()
            or q_lower in c.asset_tag.lower()
            or q_lower in c.manufacturer.lower()
            or q_lower in c.model.lower()
            or any(q_lower in t.lower() for t in c.tags)
        ]

    # ================================================================
    # Relationships
    # ================================================================

    def create_relationship(
        self,
        source_ci_id: str,
        target_ci_id: str,
        relationship_type: RelationshipType,
        description: str = "",
        is_bidirectional: bool = False,
    ) -> Optional[CIRelationship]:
        """Create a relationship between two CIs."""
        # Validate both CIs exist
        if not self.get_ci(source_ci_id) or not self.get_ci(target_ci_id):
            return None

        rel_id = f"REL-{uuid.uuid4().hex[:8].upper()}"
        rel = CIRelationship(
            relationship_id=rel_id,
            source_ci_id=source_ci_id,
            target_ci_id=target_ci_id,
            relationship_type=relationship_type,
            description=description,
            is_bidirectional=is_bidirectional,
        )

        if self._use_db:
            try:
                row = CIRelationshipModel(
                    relationship_id=rel.relationship_id,
                    source_ci_id=rel.source_ci_id,
                    target_ci_id=rel.target_ci_id,
                    relationship_type=rel.relationship_type.value,
                    description=rel.description,
                    is_bidirectional=rel.is_bidirectional,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB persist failed for relationship %s: %s", rel_id, exc)

        self._relationships[rel_id] = rel
        return rel

    def get_relationships(self, ci_id: str) -> List[CIRelationship]:
        """Get all relationships involving a CI (as source or target)."""
        if self._use_db:
            try:
                rows = self.db.query(CIRelationshipModel).filter(
                    (CIRelationshipModel.source_ci_id == ci_id) |
                    (CIRelationshipModel.target_ci_id == ci_id)
                ).all()
                results = [_rel_from_row(r) for r in rows]
                for rel in results:
                    self._relationships[rel.relationship_id] = rel
                return results
            except Exception as exc:
                logger.warning("DB get_relationships failed: %s", exc)

        return [
            r for r in self._relationships.values()
            if r.source_ci_id == ci_id or r.target_ci_id == ci_id
        ]

    def delete_relationship(self, relationship_id: str) -> bool:
        """Delete a CI relationship."""
        if self._use_db:
            try:
                row = self.db.query(CIRelationshipModel).filter(
                    CIRelationshipModel.relationship_id == relationship_id
                ).first()
                if row:
                    self.db.delete(row)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete relationship failed: %s", exc)

        if relationship_id in self._relationships:
            del self._relationships[relationship_id]
            return True
        return False

    def get_dependency_tree(self, ci_id: str) -> Dict[str, Any]:
        """Build a recursive dependency graph from a CI."""
        visited: Set[str] = set()
        tree = self._traverse_dependencies(ci_id, visited)
        return tree

    def _traverse_dependencies(self, ci_id: str, visited: Set[str]) -> Dict[str, Any]:
        """Recursive BFS through relationships to build dependency tree."""
        if ci_id in visited:
            return {"ci_id": ci_id, "circular_reference": True, "children": []}

        visited.add(ci_id)
        ci = self.get_ci(ci_id)
        if not ci:
            return {"ci_id": ci_id, "not_found": True, "children": []}

        rels = self.get_relationships(ci_id)
        children = []
        for rel in rels:
            # Follow outgoing dependencies
            target = rel.target_ci_id if rel.source_ci_id == ci_id else None
            if rel.is_bidirectional and rel.target_ci_id == ci_id:
                target = rel.source_ci_id
            if target and target not in visited:
                child_tree = self._traverse_dependencies(target, visited)
                child_tree["relationship_type"] = rel.relationship_type.value
                children.append(child_tree)

        return {
            "ci_id": ci_id,
            "name": ci.name,
            "ci_type": ci.ci_type.value,
            "status": ci.status.value,
            "children": children,
        }

    # ================================================================
    # Baselines
    # ================================================================

    def capture_baseline(
        self, ci_id: str, baseline_name: Optional[str] = None, captured_by: str = "system"
    ) -> Optional[ConfigurationBaseline]:
        """Capture a baseline snapshot of a CI's current configuration."""
        ci = self.get_ci(ci_id)
        if not ci:
            return None

        baseline_id = f"BL-{uuid.uuid4().hex[:8].upper()}"
        name = baseline_name or f"Baseline {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"

        # Mark previous baselines as not current
        for bl in self._baselines.values():
            if bl.ci_id == ci_id and bl.is_current:
                bl.is_current = False

        if self._use_db:
            try:
                self.db.query(ConfigurationBaselineModel).filter(
                    ConfigurationBaselineModel.ci_id == ci_id,
                    ConfigurationBaselineModel.is_current == True,
                ).update({"is_current": False})
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB baseline update failed: %s", exc)

        baseline_data = {
            "name": ci.name,
            "ci_type": ci.ci_type.value,
            "status": ci.status.value,
            "environment": ci.environment.value,
            "ip_address": ci.ip_address,
            "mac_address": ci.mac_address,
            "manufacturer": ci.manufacturer,
            "model": ci.model,
            "firmware_version": ci.firmware_version,
            "configuration_data": ci.configuration_data,
            "attributes": ci.attributes,
            "tags": ci.tags,
        }

        baseline = ConfigurationBaseline(
            baseline_id=baseline_id,
            ci_id=ci_id,
            baseline_name=name,
            baseline_data=baseline_data,
            captured_by=captured_by,
            is_current=True,
        )

        if self._use_db:
            try:
                row = ConfigurationBaselineModel(
                    baseline_id=baseline.baseline_id,
                    ci_id=baseline.ci_id,
                    baseline_name=baseline.baseline_name,
                    baseline_data=baseline.baseline_data,
                    captured_by=baseline.captured_by,
                    is_current=True,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB baseline persist failed: %s", exc)

        self._baselines[baseline_id] = baseline
        return baseline

    def get_baselines(self, ci_id: str) -> List[ConfigurationBaseline]:
        """Get all baselines for a CI."""
        if self._use_db:
            try:
                rows = self.db.query(ConfigurationBaselineModel).filter(
                    ConfigurationBaselineModel.ci_id == ci_id
                ).order_by(ConfigurationBaselineModel.captured_at.desc()).all()
                results = [_baseline_from_row(r) for r in rows]
                for bl in results:
                    self._baselines[bl.baseline_id] = bl
                return results
            except Exception as exc:
                logger.warning("DB get_baselines failed: %s", exc)

        return sorted(
            [bl for bl in self._baselines.values() if bl.ci_id == ci_id],
            key=lambda b: b.captured_at,
            reverse=True,
        )

    def compare_to_baseline(self, ci_id: str) -> Dict[str, Any]:
        """Compare current CI state to its current baseline - drift detection."""
        ci = self.get_ci(ci_id)
        if not ci:
            return {"error": "CI not found", "ci_id": ci_id}

        baselines = self.get_baselines(ci_id)
        current_bl = next((bl for bl in baselines if bl.is_current), None)
        if not current_bl:
            return {"error": "No current baseline", "ci_id": ci_id}

        drifts = []
        current_state = {
            "name": ci.name,
            "ci_type": ci.ci_type.value,
            "status": ci.status.value,
            "environment": ci.environment.value,
            "ip_address": ci.ip_address,
            "mac_address": ci.mac_address,
            "manufacturer": ci.manufacturer,
            "model": ci.model,
            "firmware_version": ci.firmware_version,
            "configuration_data": ci.configuration_data,
            "attributes": ci.attributes,
            "tags": ci.tags,
        }

        for key, baseline_val in current_bl.baseline_data.items():
            current_val = current_state.get(key)
            if current_val != baseline_val:
                drifts.append({
                    "field": key,
                    "baseline_value": baseline_val,
                    "current_value": current_val,
                })

        has_drift = len(drifts) > 0
        if has_drift:
            self.record_change(
                ci_id,
                ChangeType.BASELINE_DRIFT,
                field_changed="multiple" if len(drifts) > 1 else drifts[0]["field"],
                change_source=ChangeSource.MANUAL,
            )

        return {
            "ci_id": ci_id,
            "baseline_id": current_bl.baseline_id,
            "baseline_name": current_bl.baseline_name,
            "captured_at": current_bl.captured_at.isoformat() if current_bl.captured_at else None,
            "has_drift": has_drift,
            "drift_count": len(drifts),
            "drifts": drifts,
        }

    # ================================================================
    # Change Tracking
    # ================================================================

    def record_change(
        self,
        ci_id: str,
        change_type: ChangeType,
        field_changed: str = "",
        old_value: str = "",
        new_value: str = "",
        changed_by: str = "system",
        change_source: ChangeSource = ChangeSource.MANUAL,
        change_ticket_id: str = "",
    ) -> ConfigurationChange:
        """Record a change to a CI."""
        change_id = f"CHG-{uuid.uuid4().hex[:8].upper()}"

        change = ConfigurationChange(
            change_id=change_id,
            ci_id=ci_id,
            change_type=change_type,
            field_changed=field_changed,
            old_value=old_value,
            new_value=new_value,
            changed_by=changed_by,
            change_source=change_source,
            change_ticket_id=change_ticket_id,
        )

        if self._use_db:
            try:
                row = ConfigurationChangeModel(
                    change_id=change.change_id,
                    ci_id=change.ci_id,
                    change_type=change.change_type.value,
                    field_changed=change.field_changed,
                    old_value=change.old_value,
                    new_value=change.new_value,
                    changed_by=change.changed_by,
                    change_source=change.change_source.value,
                    change_ticket_id=change.change_ticket_id,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB change persist failed: %s", exc)

        self._changes[change_id] = change
        return change

    def get_change_history(self, ci_id: str, limit: int = 50) -> List[ConfigurationChange]:
        """Get change history for a CI."""
        if self._use_db:
            try:
                rows = self.db.query(ConfigurationChangeModel).filter(
                    ConfigurationChangeModel.ci_id == ci_id
                ).order_by(ConfigurationChangeModel.changed_at.desc()).limit(limit).all()
                return [_change_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB get_change_history failed: %s", exc)

        changes = [c for c in self._changes.values() if c.ci_id == ci_id]
        return sorted(changes, key=lambda c: c.changed_at, reverse=True)[:limit]

    def get_recent_changes(self, client_id: Optional[str] = None, limit: int = 50) -> List[ConfigurationChange]:
        """Get recent changes across all CIs, optionally filtered by client."""
        if self._use_db and client_id:
            try:
                ci_ids = [r.ci_id for r in self.db.query(ConfigurationItemModel.ci_id).filter(
                    ConfigurationItemModel.client_id == client_id
                ).all()]
                if ci_ids:
                    rows = self.db.query(ConfigurationChangeModel).filter(
                        ConfigurationChangeModel.ci_id.in_(ci_ids)
                    ).order_by(ConfigurationChangeModel.changed_at.desc()).limit(limit).all()
                    return [_change_from_row(r) for r in rows]
                return []
            except Exception as exc:
                logger.warning("DB get_recent_changes failed: %s", exc)

        changes = list(self._changes.values())
        if client_id:
            client_ci_ids = {c.ci_id for c in self._cis.values() if c.client_id == client_id}
            changes = [c for c in changes if c.ci_id in client_ci_ids]
        return sorted(changes, key=lambda c: c.changed_at, reverse=True)[:limit]

    # ================================================================
    # Impact Analysis
    # ================================================================

    def analyze_impact(self, ci_id: str, impact_type: ImpactType) -> ImpactAnalysis:
        """Trace dependencies to find all CIs affected by an impact event."""
        analysis_id = f"IMP-{uuid.uuid4().hex[:8].upper()}"

        affected_ids: Set[str] = set()
        self._collect_affected(ci_id, affected_ids)
        affected_ids.discard(ci_id)  # Don't include the source CI itself

        # Determine impact level based on count and types
        affected_cis_data = []
        critical_count = 0
        for aid in affected_ids:
            aci = self.get_ci(aid)
            if aci:
                affected_cis_data.append({
                    "ci_id": aid,
                    "name": aci.name,
                    "ci_type": aci.ci_type.value,
                    "status": aci.status.value,
                    "environment": aci.environment.value,
                })
                if aci.environment == Environment.PRODUCTION:
                    critical_count += 1

        if not affected_ids:
            level = ImpactLevel.NONE
        elif critical_count >= 5 or len(affected_ids) >= 10:
            level = ImpactLevel.CRITICAL
        elif critical_count >= 3 or len(affected_ids) >= 5:
            level = ImpactLevel.HIGH
        elif critical_count >= 1 or len(affected_ids) >= 2:
            level = ImpactLevel.MEDIUM
        else:
            level = ImpactLevel.LOW

        analysis = ImpactAnalysis(
            analysis_id=analysis_id,
            ci_id=ci_id,
            impact_type=impact_type,
            affected_cis=list(affected_ids),
            impact_level=level,
            analysis_details={
                "source_ci": ci_id,
                "impact_type": impact_type.value,
                "total_affected": len(affected_ids),
                "production_affected": critical_count,
                "affected_items": affected_cis_data,
            },
        )

        return analysis

    def _collect_affected(self, ci_id: str, visited: Set[str]) -> None:
        """BFS to collect all CIs reachable via relationships from source."""
        queue = deque([ci_id])
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            rels = self.get_relationships(current)
            for rel in rels:
                # Follow outgoing and bidirectional relationships
                neighbor = None
                if rel.source_ci_id == current:
                    neighbor = rel.target_ci_id
                elif rel.is_bidirectional and rel.target_ci_id == current:
                    neighbor = rel.source_ci_id
                if neighbor and neighbor not in visited:
                    queue.append(neighbor)

    # ================================================================
    # Sync
    # ================================================================

    def sync_from_rmm(self, client_id: str) -> Dict[str, Any]:
        """Import/update CIs from RMM endpoint data.

        In a live deployment this would query the RMMService for all
        endpoints belonging to the client and upsert corresponding CIs.
        """
        created, updated, errors = 0, 0, 0

        try:
            from services.msp.rmm import RMMService
            rmm = RMMService(db=self.db)
            endpoints = rmm.list_endpoints(client_id=client_id)

            for ep in endpoints:
                existing = None
                # Check if a CI already exists for this endpoint
                for ci in self._cis.values():
                    if ci.client_id == client_id and ci.ip_address == ep.ip_address and ci.name == ep.hostname:
                        existing = ci
                        break

                if not existing and self._use_db:
                    try:
                        row = self.db.query(ConfigurationItemModel).filter(
                            ConfigurationItemModel.client_id == client_id,
                            ConfigurationItemModel.ip_address == ep.ip_address,
                            ConfigurationItemModel.name == ep.hostname,
                        ).first()
                        if row:
                            existing = _ci_from_row(row)
                            self._cis[existing.ci_id] = existing
                    except Exception:
                        pass

                ci_type = CIType.SERVER
                hostname_lower = ep.hostname.lower()
                if "wks" in hostname_lower or "desktop" in hostname_lower:
                    ci_type = CIType.WORKSTATION
                elif "laptop" in hostname_lower or "nb-" in hostname_lower:
                    ci_type = CIType.LAPTOP
                elif "vm" in hostname_lower:
                    ci_type = CIType.VIRTUAL_MACHINE
                elif "fw" in hostname_lower or "firewall" in hostname_lower:
                    ci_type = CIType.FIREWALL
                elif "sw" in hostname_lower or "switch" in hostname_lower:
                    ci_type = CIType.NETWORK_SWITCH

                try:
                    if existing:
                        self.update_ci(
                            existing.ci_id,
                            ip_address=ep.ip_address,
                            mac_address=ep.mac_address,
                            manufacturer=getattr(ep.system_info, "manufacturer", ""),
                            model=getattr(ep.system_info, "model", ""),
                            serial_number=getattr(ep.system_info, "serial_number", ""),
                            change_source=ChangeSource.RMM_SYNC,
                        )
                        updated += 1
                    else:
                        self.create_ci(
                            client_id=client_id,
                            ci_type=ci_type,
                            name=ep.hostname,
                            ip_address=ep.ip_address,
                            mac_address=ep.mac_address,
                            manufacturer=getattr(ep.system_info, "manufacturer", ""),
                            model=getattr(ep.system_info, "model", ""),
                            serial_number=getattr(ep.system_info, "serial_number", ""),
                            tags=ep.tags,
                        )
                        created += 1
                except Exception as exc:
                    errors += 1
                    logger.warning("RMM sync error for %s: %s", ep.hostname, exc)

        except ImportError:
            logger.info("RMMService not available for sync")
        except Exception as exc:
            logger.warning("RMM sync failed: %s", exc)
            errors += 1

        return {
            "client_id": client_id,
            "source": "rmm",
            "created": created,
            "updated": updated,
            "errors": errors,
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }

    def sync_from_discovery(self, client_id: str) -> Dict[str, Any]:
        """Import CIs from network discovery scan results.

        In a live deployment this would pull from the NetworkDiscoveryService.
        """
        created, updated, errors = 0, 0, 0

        try:
            from services.msp.network_discovery import NetworkDiscoveryService
            nds = NetworkDiscoveryService(db=self.db)
            devices = nds.list_devices(client_id=client_id) if hasattr(nds, "list_devices") else []

            for dev in devices:
                dev_name = getattr(dev, "hostname", None) or getattr(dev, "name", "Unknown")
                dev_ip = getattr(dev, "ip_address", "")
                dev_mac = getattr(dev, "mac_address", "")

                existing = None
                for ci in self._cis.values():
                    if ci.client_id == client_id and ci.ip_address == dev_ip:
                        existing = ci
                        break

                try:
                    if existing:
                        self.update_ci(
                            existing.ci_id,
                            ip_address=dev_ip,
                            mac_address=dev_mac,
                            change_source=ChangeSource.AUTO_DISCOVERY,
                        )
                        updated += 1
                    else:
                        self.create_ci(
                            client_id=client_id,
                            ci_type=CIType.SERVER,
                            name=dev_name,
                            ip_address=dev_ip,
                            mac_address=dev_mac,
                        )
                        created += 1
                except Exception as exc:
                    errors += 1
                    logger.warning("Discovery sync error for %s: %s", dev_name, exc)

        except ImportError:
            logger.info("NetworkDiscoveryService not available for sync")
        except Exception as exc:
            logger.warning("Discovery sync failed: %s", exc)
            errors += 1

        return {
            "client_id": client_id,
            "source": "network_discovery",
            "created": created,
            "updated": updated,
            "errors": errors,
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }

    # ================================================================
    # Audit
    # ================================================================

    def get_stale_cis(self, days: int = 90) -> List[ConfigurationItem]:
        """Get CIs that have not been audited within the specified number of days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        if self._use_db:
            try:
                rows = self.db.query(ConfigurationItemModel).filter(
                    ConfigurationItemModel.status == CIStatus.ACTIVE.value,
                    (ConfigurationItemModel.last_audit_at == None) |
                    (ConfigurationItemModel.last_audit_at < cutoff),
                ).all()
                return [_ci_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB get_stale_cis failed: %s", exc)

        return [
            ci for ci in self._cis.values()
            if ci.status == CIStatus.ACTIVE
            and (ci.last_audit_at is None or ci.last_audit_at < cutoff)
        ]

    def mark_audited(self, ci_id: str) -> bool:
        """Mark a CI as recently audited."""
        ci = self.get_ci(ci_id)
        if not ci:
            return False

        now = datetime.now(timezone.utc)
        ci.last_audit_at = now
        ci.updated_at = now
        self._cis[ci_id] = ci

        if self._use_db:
            try:
                row = self.db.query(ConfigurationItemModel).filter(
                    ConfigurationItemModel.ci_id == ci_id
                ).first()
                if row:
                    row.last_audit_at = now
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB mark_audited failed: %s", exc)

        return True

    # ================================================================
    # Visualization / Dashboard
    # ================================================================

    def get_topology_map(self, client_id: str) -> Dict[str, Any]:
        """Return CIs and relationships as a graph structure for visualization."""
        cis = self.list_cis(client_id=client_id)
        ci_ids = {c.ci_id for c in cis}

        nodes = [
            {
                "id": ci.ci_id,
                "name": ci.name,
                "type": ci.ci_type.value,
                "status": ci.status.value,
                "environment": ci.environment.value,
                "ip_address": ci.ip_address,
            }
            for ci in cis
        ]

        edges = []
        seen_rels: Set[str] = set()
        for ci in cis:
            rels = self.get_relationships(ci.ci_id)
            for rel in rels:
                if rel.relationship_id not in seen_rels:
                    if rel.source_ci_id in ci_ids and rel.target_ci_id in ci_ids:
                        edges.append({
                            "id": rel.relationship_id,
                            "source": rel.source_ci_id,
                            "target": rel.target_ci_id,
                            "type": rel.relationship_type.value,
                            "bidirectional": rel.is_bidirectional,
                        })
                        seen_rels.add(rel.relationship_id)

        return {
            "client_id": client_id,
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

    def get_ci_count_by_type(self, client_id: Optional[str] = None) -> Dict[str, int]:
        """Count CIs grouped by type."""
        cis = self.list_cis(client_id=client_id)
        counts: Dict[str, int] = {}
        for ci in cis:
            key = ci.ci_type.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def get_ci_count_by_status(self, client_id: Optional[str] = None) -> Dict[str, int]:
        """Count CIs grouped by status."""
        cis = self.list_cis(client_id=client_id)
        counts: Dict[str, int] = {}
        for ci in cis:
            key = ci.status.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def get_dashboard(self) -> Dict[str, Any]:
        """Aggregate dashboard: total CIs, by type, by status, recent changes, stale count, relationship count."""
        all_cis = self.list_cis()
        total = len(all_cis)

        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for ci in all_cis:
            by_type[ci.ci_type.value] = by_type.get(ci.ci_type.value, 0) + 1
            by_status[ci.status.value] = by_status.get(ci.status.value, 0) + 1

        recent = self.get_recent_changes(limit=10)
        stale = self.get_stale_cis(days=90)

        # Count relationships
        if self._use_db:
            try:
                rel_count = self.db.query(CIRelationshipModel).count()
            except Exception:
                rel_count = len(self._relationships)
        else:
            rel_count = len(self._relationships)

        return {
            "total_cis": total,
            "by_type": by_type,
            "by_status": by_status,
            "recent_changes": [
                {
                    "change_id": c.change_id,
                    "ci_id": c.ci_id,
                    "change_type": c.change_type.value if isinstance(c.change_type, Enum) else c.change_type,
                    "field_changed": c.field_changed,
                    "changed_by": c.changed_by,
                    "changed_at": c.changed_at.isoformat() if c.changed_at else None,
                }
                for c in recent
            ],
            "stale_count": len(stale),
            "relationship_count": rel_count,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
