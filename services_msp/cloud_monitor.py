"""
AITHER Platform - Cloud Infrastructure Monitoring Service
Multi-cloud (AWS/Azure/GCP) resource monitoring, cost tracking, and security posture
management for MSP clients.

Provides:
- Cloud account registration and connection management
- Resource discovery and inventory syncing
- Cost tracking, breakdown, trend analysis, and forecasting
- Security posture scanning (15 pre-built checks)
- FinOps optimization recommendations
- Alert management (cost spikes, outages, security findings)
- Multi-cloud aggregated dashboards

G-46: DB persistence with in-memory fallback.
"""

import uuid
import math
import random
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.cloud_monitor import (
        CloudAccountModel,
        CloudResourceModel,
        CloudCostEntryModel,
        CloudSecurityFindingModel,
        CloudAlertModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class ResourceType(str, Enum):
    COMPUTE_INSTANCE = "compute_instance"
    DATABASE = "database"
    STORAGE_BUCKET = "storage_bucket"
    LOAD_BALANCER = "load_balancer"
    VPC = "vpc"
    SUBNET = "subnet"
    SECURITY_GROUP = "security_group"
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    LAMBDA_FUNCTION = "lambda_function"
    CONTAINER = "container"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    CDN = "cdn"
    DNS_ZONE = "dns_zone"
    QUEUE = "queue"
    CACHE = "cache"
    VPN_GATEWAY = "vpn_gateway"
    FIREWALL_RULE = "firewall_rule"
    KEY_VAULT = "key_vault"
    LOG_GROUP = "log_group"


class FindingType(str, Enum):
    PUBLIC_ACCESS = "public_access"
    UNENCRYPTED = "unencrypted"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    UNUSED_RESOURCE = "unused_resource"
    MISSING_MFA = "missing_mfa"
    OPEN_PORT = "open_port"
    NO_LOGGING = "no_logging"
    NO_BACKUP = "no_backup"
    OUTDATED_IMAGE = "outdated_image"
    WEAK_ENCRYPTION = "weak_encryption"


class AlertType(str, Enum):
    COST_SPIKE = "cost_spike"
    RESOURCE_DOWN = "resource_down"
    SECURITY_FINDING = "security_finding"
    QUOTA_APPROACHING = "quota_approaching"
    ANOMALY = "anomaly"


class AccountStatus(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class ResourceStatus(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    TERMINATED = "terminated"
    DEGRADED = "degraded"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class CloudAccount:
    account_id: str
    client_id: str
    provider: CloudProvider
    account_name: str
    account_identifier: str
    region: str = "us-east-1"
    credentials_ref: str = ""
    status: AccountStatus = AccountStatus.DISCONNECTED
    last_sync_at: Optional[datetime] = None
    resources_count: int = 0
    monthly_cost: float = 0.0
    cost_trend: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class CloudResource:
    resource_id: str
    account_id: str
    provider: CloudProvider
    resource_type: ResourceType
    resource_name: str
    resource_identifier: str
    region: str = ""
    status: ResourceStatus = ResourceStatus.RUNNING
    tags: Dict[str, str] = field(default_factory=dict)
    monthly_cost: float = 0.0
    metrics: Dict[str, Any] = field(default_factory=dict)
    security_findings: List[str] = field(default_factory=list)
    compliance_status: str = "unknown"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: Optional[datetime] = None


@dataclass
class CloudCostEntry:
    cost_id: str
    account_id: str
    service_name: str
    resource_id: str = ""
    cost_amount: float = 0.0
    currency: str = "USD"
    period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    usage_quantity: float = 0.0
    usage_unit: str = ""


@dataclass
class CloudSecurityFinding:
    finding_id: str
    account_id: str
    resource_id: str = ""
    finding_type: FindingType = FindingType.PUBLIC_ACCESS
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    recommendation: str = ""
    compliance_frameworks: List[str] = field(default_factory=list)
    is_resolved: bool = False
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None


@dataclass
class CloudAlert:
    alert_id: str
    account_id: str
    alert_type: AlertType = AlertType.ANOMALY
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    threshold_value: Optional[float] = None
    actual_value: Optional[float] = None
    is_acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# ORM <-> Dataclass Converters
# ============================================================

def _account_from_row(row) -> CloudAccount:
    return CloudAccount(
        account_id=row.account_id,
        client_id=row.client_id,
        provider=CloudProvider(row.provider),
        account_name=row.account_name,
        account_identifier=row.account_identifier,
        region=row.region or "us-east-1",
        credentials_ref=row.credentials_ref or "",
        status=AccountStatus(row.status) if row.status else AccountStatus.DISCONNECTED,
        last_sync_at=row.last_sync_at,
        resources_count=row.resources_count or 0,
        monthly_cost=row.monthly_cost or 0.0,
        cost_trend=row.cost_trend or 0.0,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _resource_from_row(row) -> CloudResource:
    return CloudResource(
        resource_id=row.resource_id,
        account_id=row.account_id,
        provider=CloudProvider(row.provider),
        resource_type=ResourceType(row.resource_type),
        resource_name=row.resource_name,
        resource_identifier=row.resource_identifier,
        region=row.region or "",
        status=ResourceStatus(row.status) if row.status else ResourceStatus.RUNNING,
        tags=row.tags or {},
        monthly_cost=row.monthly_cost or 0.0,
        metrics=row.metrics or {},
        security_findings=row.security_findings or [],
        compliance_status=row.compliance_status or "unknown",
        created_at=row.created_at or datetime.now(timezone.utc),
        last_seen=row.last_seen,
    )


def _cost_from_row(row) -> CloudCostEntry:
    return CloudCostEntry(
        cost_id=row.cost_id,
        account_id=row.account_id,
        service_name=row.service_name,
        resource_id=row.resource_id or "",
        cost_amount=row.cost_amount or 0.0,
        currency=row.currency or "USD",
        period_start=row.period_start,
        period_end=row.period_end,
        usage_quantity=row.usage_quantity or 0.0,
        usage_unit=row.usage_unit or "",
    )


def _finding_from_row(row) -> CloudSecurityFinding:
    return CloudSecurityFinding(
        finding_id=row.finding_id,
        account_id=row.account_id,
        resource_id=row.resource_id or "",
        finding_type=FindingType(row.finding_type) if row.finding_type else FindingType.PUBLIC_ACCESS,
        severity=Severity(row.severity) if row.severity else Severity.MEDIUM,
        title=row.title,
        description=row.description or "",
        recommendation=row.recommendation or "",
        compliance_frameworks=row.compliance_frameworks or [],
        is_resolved=row.is_resolved or False,
        detected_at=row.detected_at or datetime.now(timezone.utc),
        resolved_at=row.resolved_at,
    )


def _alert_from_row(row) -> CloudAlert:
    return CloudAlert(
        alert_id=row.alert_id,
        account_id=row.account_id,
        alert_type=AlertType(row.alert_type) if row.alert_type else AlertType.ANOMALY,
        severity=Severity(row.severity) if row.severity else Severity.MEDIUM,
        title=row.title,
        description=row.description or "",
        threshold_value=row.threshold_value,
        actual_value=row.actual_value,
        is_acknowledged=row.is_acknowledged or False,
        acknowledged_at=row.acknowledged_at,
        created_at=row.created_at or datetime.now(timezone.utc),
    )


# ============================================================
# Security Check Definitions (15 pre-built)
# ============================================================

SECURITY_CHECKS = [
    {
        "id": "SC-01",
        "name": "S3/Blob Public Access",
        "finding_type": FindingType.PUBLIC_ACCESS,
        "severity": Severity.CRITICAL,
        "resource_types": [ResourceType.STORAGE_BUCKET],
        "description": "Storage bucket has public access enabled",
        "recommendation": "Disable public access on storage buckets unless explicitly required. Use pre-signed URLs for temporary access.",
        "frameworks": ["CIS", "SOC2", "HIPAA"],
    },
    {
        "id": "SC-02",
        "name": "Unencrypted Storage Volumes",
        "finding_type": FindingType.UNENCRYPTED,
        "severity": Severity.HIGH,
        "resource_types": [ResourceType.COMPUTE_INSTANCE, ResourceType.DATABASE],
        "description": "Storage volume is not encrypted at rest",
        "recommendation": "Enable encryption at rest using provider-managed or customer-managed keys.",
        "frameworks": ["CIS", "SOC2", "HIPAA", "PCI-DSS"],
    },
    {
        "id": "SC-03",
        "name": "IAM Users Without MFA",
        "finding_type": FindingType.MISSING_MFA,
        "severity": Severity.CRITICAL,
        "resource_types": [ResourceType.IAM_USER],
        "description": "IAM user does not have multi-factor authentication enabled",
        "recommendation": "Enable MFA for all IAM users, especially those with console access.",
        "frameworks": ["CIS", "SOC2", "NIST"],
    },
    {
        "id": "SC-04",
        "name": "Open Security Groups (0.0.0.0/0)",
        "finding_type": FindingType.OPEN_PORT,
        "severity": Severity.CRITICAL,
        "resource_types": [ResourceType.SECURITY_GROUP],
        "description": "Security group allows inbound traffic from 0.0.0.0/0 on sensitive ports (22, 3389, 3306, 5432)",
        "recommendation": "Restrict inbound rules to specific IP ranges or security groups.",
        "frameworks": ["CIS", "SOC2", "PCI-DSS"],
    },
    {
        "id": "SC-05",
        "name": "Unused Elastic/Static IPs",
        "finding_type": FindingType.UNUSED_RESOURCE,
        "severity": Severity.LOW,
        "resource_types": [ResourceType.VPC],
        "description": "Elastic IP or static IP address is allocated but not associated with any resource",
        "recommendation": "Release unused IP addresses to avoid unnecessary charges.",
        "frameworks": ["FinOps"],
    },
    {
        "id": "SC-06",
        "name": "Publicly Accessible Databases",
        "finding_type": FindingType.PUBLIC_ACCESS,
        "severity": Severity.CRITICAL,
        "resource_types": [ResourceType.DATABASE],
        "description": "Database instance is publicly accessible from the internet",
        "recommendation": "Place databases in private subnets and use VPN or bastion hosts for access.",
        "frameworks": ["CIS", "SOC2", "HIPAA", "PCI-DSS"],
    },
    {
        "id": "SC-07",
        "name": "CloudTrail/Activity Log Disabled",
        "finding_type": FindingType.NO_LOGGING,
        "severity": Severity.HIGH,
        "resource_types": [ResourceType.LOG_GROUP],
        "description": "Cloud audit logging (CloudTrail/Activity Log/Audit Log) is not enabled",
        "recommendation": "Enable audit logging in all regions and send logs to a centralized bucket.",
        "frameworks": ["CIS", "SOC2", "HIPAA", "NIST"],
    },
    {
        "id": "SC-08",
        "name": "Resources Without Backups",
        "finding_type": FindingType.NO_BACKUP,
        "severity": Severity.HIGH,
        "resource_types": [ResourceType.DATABASE, ResourceType.COMPUTE_INSTANCE],
        "description": "Critical resource does not have automated backups configured",
        "recommendation": "Enable automated backups with appropriate retention periods.",
        "frameworks": ["CIS", "SOC2", "HIPAA"],
    },
    {
        "id": "SC-09",
        "name": "Outdated AMIs/Images (>90 days)",
        "finding_type": FindingType.OUTDATED_IMAGE,
        "severity": Severity.MEDIUM,
        "resource_types": [ResourceType.COMPUTE_INSTANCE],
        "description": "Instance is running on a machine image older than 90 days",
        "recommendation": "Update to the latest approved machine image to include security patches.",
        "frameworks": ["CIS", "NIST"],
    },
    {
        "id": "SC-10",
        "name": "Over-Privileged IAM Roles",
        "finding_type": FindingType.EXCESSIVE_PERMISSIONS,
        "severity": Severity.HIGH,
        "resource_types": [ResourceType.IAM_ROLE],
        "description": "IAM role has overly broad permissions (e.g., *:* or AdministratorAccess)",
        "recommendation": "Apply least-privilege principle. Scope permissions to specific services and actions.",
        "frameworks": ["CIS", "SOC2", "NIST"],
    },
    {
        "id": "SC-11",
        "name": "Unattached Storage Volumes",
        "finding_type": FindingType.UNUSED_RESOURCE,
        "severity": Severity.LOW,
        "resource_types": [ResourceType.STORAGE_BUCKET],
        "description": "EBS volume / managed disk is not attached to any instance",
        "recommendation": "Delete or snapshot unattached volumes to save costs.",
        "frameworks": ["FinOps"],
    },
    {
        "id": "SC-12",
        "name": "Instances Without Monitoring",
        "finding_type": FindingType.NO_LOGGING,
        "severity": Severity.MEDIUM,
        "resource_types": [ResourceType.COMPUTE_INSTANCE],
        "description": "Compute instance does not have detailed monitoring enabled",
        "recommendation": "Enable CloudWatch detailed monitoring / Azure Monitor / Cloud Monitoring agent.",
        "frameworks": ["CIS", "SOC2"],
    },
    {
        "id": "SC-13",
        "name": "Default VPC In Use",
        "finding_type": FindingType.WEAK_ENCRYPTION,
        "severity": Severity.MEDIUM,
        "resource_types": [ResourceType.VPC],
        "description": "Resources are deployed in the default VPC which lacks hardened network controls",
        "recommendation": "Create custom VPCs with proper subnet segmentation and NACLs.",
        "frameworks": ["CIS", "NIST"],
    },
    {
        "id": "SC-14",
        "name": "Root Account Usage",
        "finding_type": FindingType.EXCESSIVE_PERMISSIONS,
        "severity": Severity.CRITICAL,
        "resource_types": [ResourceType.IAM_USER],
        "description": "Root/owner account has been used for day-to-day operations",
        "recommendation": "Use IAM users or roles for daily tasks. Reserve root for account-level operations only.",
        "frameworks": ["CIS", "SOC2", "NIST"],
    },
    {
        "id": "SC-15",
        "name": "Cross-Account Access Without Conditions",
        "finding_type": FindingType.EXCESSIVE_PERMISSIONS,
        "severity": Severity.HIGH,
        "resource_types": [ResourceType.IAM_ROLE],
        "description": "Cross-account trust policy lacks conditional constraints (e.g., ExternalId)",
        "recommendation": "Add condition keys (ExternalId, MFA, source IP) to cross-account trust policies.",
        "frameworks": ["CIS", "SOC2"],
    },
]


# ============================================================
# Service
# ============================================================

class CloudMonitorService:
    """
    Cloud Infrastructure Monitoring Service

    Multi-cloud monitoring, cost tracking, and security posture management
    for MSP client cloud environments (AWS, Azure, GCP).

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback
        self._accounts: Dict[str, CloudAccount] = {}
        self._resources: Dict[str, CloudResource] = {}
        self._costs: Dict[str, CloudCostEntry] = {}
        self._findings: Dict[str, CloudSecurityFinding] = {}
        self._alerts: Dict[str, CloudAlert] = {}

    # ========== Account Management ==========

    def register_account(
        self,
        client_id: str,
        provider: str,
        account_name: str,
        account_identifier: str,
        region: str = "us-east-1",
        credentials_ref: str = "",
    ) -> CloudAccount:
        """Register a new cloud provider account for an MSP client."""
        account_id = f"CLD-{uuid.uuid4().hex[:8].upper()}"
        acct = CloudAccount(
            account_id=account_id,
            client_id=client_id,
            provider=CloudProvider(provider),
            account_name=account_name,
            account_identifier=account_identifier,
            region=region,
            credentials_ref=credentials_ref,
            status=AccountStatus.CONNECTED if credentials_ref else AccountStatus.DISCONNECTED,
        )

        if self._use_db:
            try:
                row = CloudAccountModel(
                    account_id=account_id,
                    client_id=client_id,
                    provider=provider,
                    account_name=account_name,
                    account_identifier=account_identifier,
                    region=region,
                    credentials_ref=credentials_ref,
                    status=acct.status.value,
                    resources_count=0,
                    monthly_cost=0.0,
                    cost_trend=0.0,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error registering cloud account: {e}")
                self.db.rollback()

        self._accounts[account_id] = acct
        return acct

    def get_account(self, account_id: str) -> Optional[CloudAccount]:
        """Retrieve a cloud account by ID."""
        if self._use_db:
            try:
                row = self.db.query(CloudAccountModel).filter(
                    CloudAccountModel.account_id == account_id
                ).first()
                if row:
                    return _account_from_row(row)
            except Exception as e:
                logger.error(f"DB error fetching account: {e}")
        return self._accounts.get(account_id)

    def list_accounts(self, client_id: str = None, provider: str = None) -> List[CloudAccount]:
        """List cloud accounts with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(CloudAccountModel)
                if client_id:
                    q = q.filter(CloudAccountModel.client_id == client_id)
                if provider:
                    q = q.filter(CloudAccountModel.provider == provider)
                return [_account_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error listing accounts: {e}")

        results = list(self._accounts.values())
        if client_id:
            results = [a for a in results if a.client_id == client_id]
        if provider:
            results = [a for a in results if a.provider.value == provider]
        return results

    def update_account(self, account_id: str, **updates) -> Optional[CloudAccount]:
        """Update cloud account properties."""
        acct = self.get_account(account_id)
        if not acct:
            return None

        for key, value in updates.items():
            if hasattr(acct, key):
                setattr(acct, key, value)
        acct.updated_at = datetime.now(timezone.utc)

        if self._use_db:
            try:
                row = self.db.query(CloudAccountModel).filter(
                    CloudAccountModel.account_id == account_id
                ).first()
                if row:
                    for key, value in updates.items():
                        if hasattr(row, key):
                            v = value.value if isinstance(value, Enum) else value
                            setattr(row, key, v)
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error updating account: {e}")
                self.db.rollback()

        self._accounts[account_id] = acct
        return acct

    def test_connection(self, account_id: str) -> Dict[str, Any]:
        """Test connectivity to a cloud provider account.

        In production this would use the credentials_ref to authenticate
        against the provider API.  For now it simulates a connection test.
        """
        acct = self.get_account(account_id)
        if not acct:
            return {"success": False, "error": "Account not found"}

        # Simulate connection test
        success = acct.credentials_ref != ""
        if success:
            self.update_account(account_id, status=AccountStatus.CONNECTED)
        else:
            self.update_account(account_id, status=AccountStatus.ERROR)

        return {
            "success": success,
            "provider": acct.provider.value,
            "account_identifier": acct.account_identifier,
            "latency_ms": random.randint(45, 200),
            "message": "Connection successful" if success else "No credentials configured",
        }

    def sync_resources(self, account_id: str) -> Dict[str, Any]:
        """Sync resources from the cloud provider.

        Delegates to _simulate_sync which generates realistic mock resources.
        Replace _simulate_sync internals with real API calls when credentials
        are wired up.
        """
        acct = self.get_account(account_id)
        if not acct:
            return {"success": False, "error": "Account not found"}

        result = self._simulate_sync(account_id)

        # Update account metadata
        resource_count = len([r for r in self._resources.values() if r.account_id == account_id])
        total_cost = sum(r.monthly_cost for r in self._resources.values() if r.account_id == account_id)
        self.update_account(
            account_id,
            status=AccountStatus.CONNECTED,
            last_sync_at=datetime.now(timezone.utc),
            resources_count=resource_count,
            monthly_cost=round(total_cost, 2),
        )

        return result

    # ========== Resource Management ==========

    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Get a single cloud resource."""
        if self._use_db:
            try:
                row = self.db.query(CloudResourceModel).filter(
                    CloudResourceModel.resource_id == resource_id
                ).first()
                if row:
                    return _resource_from_row(row)
            except Exception as e:
                logger.error(f"DB error fetching resource: {e}")
        return self._resources.get(resource_id)

    def list_resources(
        self,
        account_id: str = None,
        resource_type: str = None,
        status: str = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[CloudResource]:
        """List cloud resources with filters."""
        if self._use_db:
            try:
                q = self.db.query(CloudResourceModel)
                if account_id:
                    q = q.filter(CloudResourceModel.account_id == account_id)
                if resource_type:
                    q = q.filter(CloudResourceModel.resource_type == resource_type)
                if status:
                    q = q.filter(CloudResourceModel.status == status)
                return [_resource_from_row(r) for r in q.offset(offset).limit(limit).all()]
            except Exception as e:
                logger.error(f"DB error listing resources: {e}")

        results = list(self._resources.values())
        if account_id:
            results = [r for r in results if r.account_id == account_id]
        if resource_type:
            results = [r for r in results if r.resource_type.value == resource_type]
        if status:
            results = [r for r in results if r.status.value == status]
        return results[offset:offset + limit]

    def search_resources(self, query: str, account_id: str = None) -> List[CloudResource]:
        """Search resources by name or identifier."""
        q_lower = query.lower()
        all_res = self.list_resources(account_id=account_id, limit=10000)
        return [
            r for r in all_res
            if q_lower in r.resource_name.lower()
            or q_lower in r.resource_identifier.lower()
            or q_lower in r.resource_type.value.lower()
        ]

    def get_resource_metrics(self, resource_id: str) -> Dict[str, Any]:
        """Get current metrics for a resource."""
        res = self.get_resource(resource_id)
        if not res:
            return {}
        # Return stored metrics plus some simulated real-time values
        metrics = dict(res.metrics)
        metrics.setdefault("cpu_percent", round(random.uniform(5, 85), 1))
        metrics.setdefault("memory_percent", round(random.uniform(20, 90), 1))
        metrics.setdefault("network_in_mbps", round(random.uniform(0.1, 100), 2))
        metrics.setdefault("network_out_mbps", round(random.uniform(0.1, 50), 2))
        metrics.setdefault("disk_read_iops", random.randint(10, 5000))
        metrics.setdefault("disk_write_iops", random.randint(10, 3000))
        metrics["timestamp"] = datetime.now(timezone.utc).isoformat()
        return metrics

    # ========== Simulated Sync ==========

    def _simulate_sync(self, account_id: str) -> Dict[str, Any]:
        """Generate realistic mock cloud resources for an account.

        This is the integration seam: replace the body of this method with
        real boto3 / azure-mgmt / google-cloud SDK calls when credentials
        are configured.
        """
        acct = self.get_account(account_id)
        if not acct:
            return {"success": False, "error": "Account not found"}

        provider = acct.provider
        region = acct.region
        now = datetime.now(timezone.utc)

        # Provider-specific naming
        _prefixes = {
            CloudProvider.AWS: {"compute": "i-", "bucket": "s3://", "db": "rds-", "arn": "arn:aws"},
            CloudProvider.AZURE: {"compute": "vm-", "bucket": "blob://", "db": "sql-", "arn": "/subscriptions"},
            CloudProvider.GCP: {"compute": "gce-", "bucket": "gs://", "db": "cloudsql-", "arn": "projects/"},
        }
        pfx = _prefixes.get(provider, _prefixes[CloudProvider.AWS])

        resources_created = []

        # Compute instances
        for i in range(random.randint(3, 8)):
            rid = f"RES-{uuid.uuid4().hex[:8].upper()}"
            name = f"{pfx['compute']}web-server-{i+1:02d}"
            status = random.choice([ResourceStatus.RUNNING] * 8 + [ResourceStatus.STOPPED, ResourceStatus.DEGRADED])
            res = CloudResource(
                resource_id=rid,
                account_id=account_id,
                provider=provider,
                resource_type=ResourceType.COMPUTE_INSTANCE,
                resource_name=name,
                resource_identifier=f"{pfx['arn']}:ec2:{region}:instance/{name}",
                region=region,
                status=status,
                tags={"Environment": random.choice(["prod", "staging", "dev"]), "Team": "engineering"},
                monthly_cost=round(random.uniform(20, 450), 2),
                metrics={
                    "cpu_percent": round(random.uniform(5, 85), 1),
                    "memory_percent": round(random.uniform(20, 90), 1),
                    "network_in_mbps": round(random.uniform(1, 100), 2),
                    "disk_used_percent": round(random.uniform(10, 80), 1),
                },
                last_seen=now,
            )
            self._persist_resource(res)
            resources_created.append(rid)

        # Databases
        for i in range(random.randint(1, 3)):
            rid = f"RES-{uuid.uuid4().hex[:8].upper()}"
            name = f"{pfx['db']}app-db-{i+1:02d}"
            res = CloudResource(
                resource_id=rid,
                account_id=account_id,
                provider=provider,
                resource_type=ResourceType.DATABASE,
                resource_name=name,
                resource_identifier=f"{pfx['arn']}:rds:{region}:db/{name}",
                region=region,
                status=ResourceStatus.RUNNING,
                tags={"Environment": "prod", "Backup": "enabled"},
                monthly_cost=round(random.uniform(50, 800), 2),
                metrics={"connections": random.randint(5, 200), "iops": random.randint(100, 5000)},
                last_seen=now,
            )
            self._persist_resource(res)
            resources_created.append(rid)

        # Storage buckets
        for i in range(random.randint(2, 5)):
            rid = f"RES-{uuid.uuid4().hex[:8].upper()}"
            name = f"{pfx['bucket']}data-bucket-{i+1:02d}"
            res = CloudResource(
                resource_id=rid,
                account_id=account_id,
                provider=provider,
                resource_type=ResourceType.STORAGE_BUCKET,
                resource_name=name,
                resource_identifier=f"{pfx['arn']}:s3:::{name}",
                region=region,
                status=ResourceStatus.RUNNING,
                tags={"Classification": random.choice(["public", "private", "confidential"])},
                monthly_cost=round(random.uniform(1, 50), 2),
                metrics={"size_gb": round(random.uniform(1, 500), 1), "objects": random.randint(100, 50000)},
                last_seen=now,
            )
            self._persist_resource(res)
            resources_created.append(rid)

        # Security groups
        for i in range(random.randint(2, 4)):
            rid = f"RES-{uuid.uuid4().hex[:8].upper()}"
            name = f"sg-{uuid.uuid4().hex[:8]}"
            res = CloudResource(
                resource_id=rid,
                account_id=account_id,
                provider=provider,
                resource_type=ResourceType.SECURITY_GROUP,
                resource_name=name,
                resource_identifier=f"{pfx['arn']}:ec2:{region}:sg/{name}",
                region=region,
                status=ResourceStatus.RUNNING,
                tags={"Purpose": random.choice(["web", "db", "internal", "bastion"])},
                monthly_cost=0.0,
                last_seen=now,
            )
            self._persist_resource(res)
            resources_created.append(rid)

        # IAM users/roles
        for i in range(random.randint(3, 6)):
            rid = f"RES-{uuid.uuid4().hex[:8].upper()}"
            is_role = random.random() > 0.5
            rt = ResourceType.IAM_ROLE if is_role else ResourceType.IAM_USER
            name = f"{'role' if is_role else 'user'}-{['admin','deploy','readonly','service','backup','audit'][i % 6]}"
            res = CloudResource(
                resource_id=rid,
                account_id=account_id,
                provider=provider,
                resource_type=rt,
                resource_name=name,
                resource_identifier=f"{pfx['arn']}:iam::{name}",
                region="global",
                status=ResourceStatus.RUNNING,
                tags={},
                monthly_cost=0.0,
                last_seen=now,
            )
            self._persist_resource(res)
            resources_created.append(rid)

        # Lambda/Functions
        for i in range(random.randint(1, 3)):
            rid = f"RES-{uuid.uuid4().hex[:8].upper()}"
            name = f"fn-{random.choice(['api-handler','cron-job','event-processor','data-pipeline'])}-{i+1}"
            res = CloudResource(
                resource_id=rid,
                account_id=account_id,
                provider=provider,
                resource_type=ResourceType.LAMBDA_FUNCTION,
                resource_name=name,
                resource_identifier=f"{pfx['arn']}:lambda:{region}:function:{name}",
                region=region,
                status=ResourceStatus.RUNNING,
                tags={"Runtime": random.choice(["python3.11", "nodejs18", "go1.21"])},
                monthly_cost=round(random.uniform(0.5, 30), 2),
                metrics={"invocations_24h": random.randint(10, 10000), "avg_duration_ms": random.randint(50, 3000)},
                last_seen=now,
            )
            self._persist_resource(res)
            resources_created.append(rid)

        # Generate cost entries for this sync
        self._generate_cost_entries(account_id)

        return {
            "success": True,
            "account_id": account_id,
            "provider": provider.value,
            "resources_synced": len(resources_created),
            "synced_at": now.isoformat(),
        }

    def _persist_resource(self, res: CloudResource) -> None:
        """Persist a resource to DB and in-memory store."""
        self._resources[res.resource_id] = res
        if self._use_db:
            try:
                row = CloudResourceModel(
                    resource_id=res.resource_id,
                    account_id=res.account_id,
                    provider=res.provider.value,
                    resource_type=res.resource_type.value,
                    resource_name=res.resource_name,
                    resource_identifier=res.resource_identifier,
                    region=res.region,
                    status=res.status.value,
                    tags=res.tags,
                    monthly_cost=res.monthly_cost,
                    metrics=res.metrics,
                    security_findings=res.security_findings,
                    compliance_status=res.compliance_status,
                    last_seen=res.last_seen,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error persisting resource: {e}")
                self.db.rollback()

    def _generate_cost_entries(self, account_id: str) -> None:
        """Generate realistic cost entries for the current billing period."""
        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        period_end = (period_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)

        services = {
            CloudProvider.AWS: ["EC2", "RDS", "S3", "Lambda", "CloudFront", "ELB", "Route53", "EBS"],
            CloudProvider.AZURE: ["Virtual Machines", "SQL Database", "Blob Storage", "Functions", "CDN", "Load Balancer", "DNS", "Managed Disks"],
            CloudProvider.GCP: ["Compute Engine", "Cloud SQL", "Cloud Storage", "Cloud Functions", "Cloud CDN", "Cloud Load Balancing", "Cloud DNS", "Persistent Disk"],
        }

        acct = self.get_account(account_id)
        provider_services = services.get(acct.provider, services[CloudProvider.AWS]) if acct else services[CloudProvider.AWS]

        for svc in provider_services:
            cost_id = f"CST-{uuid.uuid4().hex[:8].upper()}"
            entry = CloudCostEntry(
                cost_id=cost_id,
                account_id=account_id,
                service_name=svc,
                cost_amount=round(random.uniform(5, 500), 2),
                currency="USD",
                period_start=period_start,
                period_end=period_end,
                usage_quantity=round(random.uniform(10, 10000), 2),
                usage_unit=random.choice(["hours", "GB", "requests", "GB-months"]),
            )
            self._costs[cost_id] = entry
            if self._use_db:
                try:
                    row = CloudCostEntryModel(
                        cost_id=cost_id,
                        account_id=account_id,
                        service_name=svc,
                        cost_amount=entry.cost_amount,
                        currency=entry.currency,
                        period_start=entry.period_start,
                        period_end=entry.period_end,
                        usage_quantity=entry.usage_quantity,
                        usage_unit=entry.usage_unit,
                    )
                    self.db.add(row)
                    self.db.commit()
                except Exception as e:
                    logger.error(f"DB error persisting cost entry: {e}")
                    self.db.rollback()

    # ========== Cost Management ==========

    def record_cost(
        self,
        account_id: str,
        service_name: str,
        cost_amount: float,
        period_start: datetime,
        period_end: datetime,
        resource_id: str = "",
        currency: str = "USD",
        usage_quantity: float = 0.0,
        usage_unit: str = "",
    ) -> CloudCostEntry:
        """Manually record a cost entry."""
        cost_id = f"CST-{uuid.uuid4().hex[:8].upper()}"
        entry = CloudCostEntry(
            cost_id=cost_id,
            account_id=account_id,
            service_name=service_name,
            resource_id=resource_id,
            cost_amount=cost_amount,
            currency=currency,
            period_start=period_start,
            period_end=period_end,
            usage_quantity=usage_quantity,
            usage_unit=usage_unit,
        )
        self._costs[cost_id] = entry

        if self._use_db:
            try:
                row = CloudCostEntryModel(
                    cost_id=cost_id,
                    account_id=account_id,
                    service_name=service_name,
                    resource_id=resource_id,
                    cost_amount=cost_amount,
                    currency=currency,
                    period_start=period_start,
                    period_end=period_end,
                    usage_quantity=usage_quantity,
                    usage_unit=usage_unit,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error recording cost: {e}")
                self.db.rollback()

        # Check for anomalies after recording
        self._detect_cost_anomalies(account_id)
        return entry

    def get_costs(self, account_id: str, period: str = "current") -> List[CloudCostEntry]:
        """Get cost entries for an account.  period: 'current', 'last', or 'YYYY-MM'."""
        now = datetime.now(timezone.utc)
        if period == "current":
            start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        elif period == "last":
            first_this = now.replace(day=1)
            start = (first_this - timedelta(days=1)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else:
            try:
                parts = period.split("-")
                start = datetime(int(parts[0]), int(parts[1]), 1, tzinfo=timezone.utc)
            except Exception:
                start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        if self._use_db:
            try:
                rows = self.db.query(CloudCostEntryModel).filter(
                    CloudCostEntryModel.account_id == account_id,
                    CloudCostEntryModel.period_start >= start,
                ).all()
                return [_cost_from_row(r) for r in rows]
            except Exception as e:
                logger.error(f"DB error fetching costs: {e}")

        return [c for c in self._costs.values() if c.account_id == account_id and c.period_start >= start]

    def get_cost_breakdown(self, account_id: str) -> Dict[str, Any]:
        """Breakdown of current-period costs by service."""
        costs = self.get_costs(account_id, "current")
        by_service: Dict[str, float] = {}
        total = 0.0
        for c in costs:
            by_service[c.service_name] = by_service.get(c.service_name, 0) + c.cost_amount
            total += c.cost_amount

        breakdown = sorted(
            [{"service": k, "cost": round(v, 2), "percent": round(v / total * 100, 1) if total else 0}
             for k, v in by_service.items()],
            key=lambda x: x["cost"],
            reverse=True,
        )
        return {"account_id": account_id, "total": round(total, 2), "currency": "USD", "breakdown": breakdown}

    def get_cost_trend(self, account_id: str, months: int = 6) -> List[Dict[str, Any]]:
        """Monthly cost trend (simulated historical data for demo)."""
        now = datetime.now(timezone.utc)
        trend = []
        base = random.uniform(800, 3000)
        for i in range(months - 1, -1, -1):
            month_dt = (now - timedelta(days=30 * i)).replace(day=1)
            cost = round(base * (1 + random.uniform(-0.15, 0.20)), 2)
            base = cost
            trend.append({
                "month": month_dt.strftime("%Y-%m"),
                "cost": cost,
                "currency": "USD",
            })
        return trend

    def get_cost_forecast(self, account_id: str) -> Dict[str, Any]:
        """Simple linear cost forecast for next 3 months."""
        trend = self.get_cost_trend(account_id, months=6)
        if len(trend) < 2:
            return {"forecast": []}

        costs = [t["cost"] for t in trend]
        avg_growth = sum((costs[i] - costs[i-1]) / costs[i-1] for i in range(1, len(costs))) / (len(costs) - 1)
        last_cost = costs[-1]
        now = datetime.now(timezone.utc)

        forecast = []
        for i in range(1, 4):
            month_dt = (now + timedelta(days=30 * i)).replace(day=1)
            projected = round(last_cost * (1 + avg_growth) ** i, 2)
            forecast.append({
                "month": month_dt.strftime("%Y-%m"),
                "projected_cost": projected,
                "currency": "USD",
                "confidence": round(max(0.5, 0.95 - 0.1 * i), 2),
            })
        return {
            "account_id": account_id,
            "current_monthly": last_cost,
            "avg_monthly_growth": round(avg_growth * 100, 2),
            "forecast": forecast,
        }

    def _detect_cost_anomalies(self, account_id: str) -> List[CloudAlert]:
        """Flag unusual spending spikes (>30% above rolling average)."""
        costs = self.get_costs(account_id, "current")
        if not costs:
            return []

        total_current = sum(c.cost_amount for c in costs)
        trend = self.get_cost_trend(account_id, months=3)
        if len(trend) < 2:
            return []

        avg_prev = sum(t["cost"] for t in trend[:-1]) / (len(trend) - 1)
        alerts = []
        if avg_prev > 0 and total_current > avg_prev * 1.3:
            alert = self.create_alert(
                account_id=account_id,
                alert_type=AlertType.COST_SPIKE.value,
                severity=Severity.HIGH.value,
                title=f"Cost spike detected: ${total_current:,.2f} vs ${avg_prev:,.2f} avg",
                description=f"Current period spend is {((total_current/avg_prev)-1)*100:.1f}% above the rolling average.",
                threshold_value=avg_prev * 1.3,
                actual_value=total_current,
            )
            alerts.append(alert)
        return alerts

    # ========== Security ==========

    def run_security_scan(self, account_id: str) -> Dict[str, Any]:
        """Run all 15 security checks against resources in the account."""
        resources = self.list_resources(account_id=account_id, limit=10000)
        if not resources:
            return {"account_id": account_id, "findings": 0, "message": "No resources to scan. Run sync first."}

        findings_created = []
        for check in SECURITY_CHECKS:
            target_resources = [r for r in resources if r.resource_type in check["resource_types"]]
            for res in target_resources:
                # Simulate a probability that the check fires (30% chance per resource)
                if random.random() < 0.30:
                    finding = self._create_finding(
                        account_id=account_id,
                        resource_id=res.resource_id,
                        finding_type=check["finding_type"],
                        severity=check["severity"],
                        title=f"{check['name']}: {res.resource_name}",
                        description=check["description"],
                        recommendation=check["recommendation"],
                        compliance_frameworks=check["frameworks"],
                    )
                    findings_created.append(finding)

        # Create an alert if critical findings were found
        critical_count = sum(1 for f in findings_created if f.severity == Severity.CRITICAL)
        if critical_count > 0:
            self.create_alert(
                account_id=account_id,
                alert_type=AlertType.SECURITY_FINDING.value,
                severity=Severity.CRITICAL.value,
                title=f"{critical_count} critical security findings detected",
                description=f"Security scan found {critical_count} critical and {len(findings_created)} total findings.",
            )

        return {
            "account_id": account_id,
            "total_findings": len(findings_created),
            "by_severity": {
                "critical": sum(1 for f in findings_created if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in findings_created if f.severity == Severity.HIGH),
                "medium": sum(1 for f in findings_created if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in findings_created if f.severity == Severity.LOW),
            },
            "scanned_resources": len(resources),
            "checks_run": len(SECURITY_CHECKS),
        }

    def _create_finding(
        self,
        account_id: str,
        resource_id: str,
        finding_type: FindingType,
        severity: Severity,
        title: str,
        description: str,
        recommendation: str,
        compliance_frameworks: List[str],
    ) -> CloudSecurityFinding:
        """Internal helper to create and persist a security finding."""
        finding_id = f"FND-{uuid.uuid4().hex[:8].upper()}"
        finding = CloudSecurityFinding(
            finding_id=finding_id,
            account_id=account_id,
            resource_id=resource_id,
            finding_type=finding_type,
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
            compliance_frameworks=compliance_frameworks,
        )
        self._findings[finding_id] = finding

        if self._use_db:
            try:
                row = CloudSecurityFindingModel(
                    finding_id=finding_id,
                    account_id=account_id,
                    resource_id=resource_id,
                    finding_type=finding_type.value,
                    severity=severity.value,
                    title=title,
                    description=description,
                    recommendation=recommendation,
                    compliance_frameworks=compliance_frameworks,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating finding: {e}")
                self.db.rollback()

        return finding

    def get_findings(
        self,
        account_id: str = None,
        severity: str = None,
        finding_type: str = None,
        is_resolved: bool = None,
    ) -> List[CloudSecurityFinding]:
        """Get security findings with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(CloudSecurityFindingModel)
                if account_id:
                    q = q.filter(CloudSecurityFindingModel.account_id == account_id)
                if severity:
                    q = q.filter(CloudSecurityFindingModel.severity == severity)
                if finding_type:
                    q = q.filter(CloudSecurityFindingModel.finding_type == finding_type)
                if is_resolved is not None:
                    q = q.filter(CloudSecurityFindingModel.is_resolved == is_resolved)
                return [_finding_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error fetching findings: {e}")

        results = list(self._findings.values())
        if account_id:
            results = [f for f in results if f.account_id == account_id]
        if severity:
            results = [f for f in results if f.severity.value == severity]
        if finding_type:
            results = [f for f in results if f.finding_type.value == finding_type]
        if is_resolved is not None:
            results = [f for f in results if f.is_resolved == is_resolved]
        return results

    def resolve_finding(self, finding_id: str) -> Optional[CloudSecurityFinding]:
        """Mark a finding as resolved."""
        finding = self._findings.get(finding_id)
        if not finding:
            if self._use_db:
                try:
                    row = self.db.query(CloudSecurityFindingModel).filter(
                        CloudSecurityFindingModel.finding_id == finding_id
                    ).first()
                    if row:
                        finding = _finding_from_row(row)
                except Exception:
                    pass
        if not finding:
            return None

        finding.is_resolved = True
        finding.resolved_at = datetime.now(timezone.utc)
        self._findings[finding_id] = finding

        if self._use_db:
            try:
                row = self.db.query(CloudSecurityFindingModel).filter(
                    CloudSecurityFindingModel.finding_id == finding_id
                ).first()
                if row:
                    row.is_resolved = True
                    row.resolved_at = finding.resolved_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error resolving finding: {e}")
                self.db.rollback()

        return finding

    def get_security_posture(self, account_id: str) -> Dict[str, Any]:
        """Compute an overall security posture score for an account."""
        findings = self.get_findings(account_id=account_id, is_resolved=False)
        total = len(findings)
        if total == 0:
            score = 100
        else:
            severity_weights = {Severity.CRITICAL: 10, Severity.HIGH: 5, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
            penalty = sum(severity_weights.get(f.severity, 1) for f in findings)
            score = max(0, 100 - penalty)

        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for f in findings:
            by_type[f.finding_type.value] = by_type.get(f.finding_type.value, 0) + 1
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

        return {
            "account_id": account_id,
            "score": score,
            "grade": grade,
            "open_findings": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "compliance_gaps": list({fw for f in findings for fw in f.compliance_frameworks}),
        }

    # ========== Alerts ==========

    def create_alert(
        self,
        account_id: str,
        alert_type: str,
        severity: str,
        title: str,
        description: str = "",
        threshold_value: float = None,
        actual_value: float = None,
    ) -> CloudAlert:
        """Create a cloud infrastructure alert."""
        alert_id = f"ALR-{uuid.uuid4().hex[:8].upper()}"
        alert = CloudAlert(
            alert_id=alert_id,
            account_id=account_id,
            alert_type=AlertType(alert_type),
            severity=Severity(severity),
            title=title,
            description=description,
            threshold_value=threshold_value,
            actual_value=actual_value,
        )
        self._alerts[alert_id] = alert

        if self._use_db:
            try:
                row = CloudAlertModel(
                    alert_id=alert_id,
                    account_id=account_id,
                    alert_type=alert_type,
                    severity=severity,
                    title=title,
                    description=description,
                    threshold_value=threshold_value,
                    actual_value=actual_value,
                )
                self.db.add(row)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB error creating alert: {e}")
                self.db.rollback()

        return alert

    def get_alerts(
        self,
        account_id: str = None,
        alert_type: str = None,
        is_acknowledged: bool = None,
    ) -> List[CloudAlert]:
        """Get alerts with optional filters."""
        if self._use_db:
            try:
                q = self.db.query(CloudAlertModel)
                if account_id:
                    q = q.filter(CloudAlertModel.account_id == account_id)
                if alert_type:
                    q = q.filter(CloudAlertModel.alert_type == alert_type)
                if is_acknowledged is not None:
                    q = q.filter(CloudAlertModel.is_acknowledged == is_acknowledged)
                return [_alert_from_row(r) for r in q.all()]
            except Exception as e:
                logger.error(f"DB error fetching alerts: {e}")

        results = list(self._alerts.values())
        if account_id:
            results = [a for a in results if a.account_id == account_id]
        if alert_type:
            results = [a for a in results if a.alert_type.value == alert_type]
        if is_acknowledged is not None:
            results = [a for a in results if a.is_acknowledged == is_acknowledged]
        return results

    def acknowledge_alert(self, alert_id: str) -> Optional[CloudAlert]:
        """Acknowledge a cloud alert."""
        alert = self._alerts.get(alert_id)
        if not alert:
            if self._use_db:
                try:
                    row = self.db.query(CloudAlertModel).filter(
                        CloudAlertModel.alert_id == alert_id
                    ).first()
                    if row:
                        alert = _alert_from_row(row)
                except Exception:
                    pass
        if not alert:
            return None

        alert.is_acknowledged = True
        alert.acknowledged_at = datetime.now(timezone.utc)
        self._alerts[alert_id] = alert

        if self._use_db:
            try:
                row = self.db.query(CloudAlertModel).filter(
                    CloudAlertModel.alert_id == alert_id
                ).first()
                if row:
                    row.is_acknowledged = True
                    row.acknowledged_at = alert.acknowledged_at
                    self.db.commit()
            except Exception as e:
                logger.error(f"DB error acknowledging alert: {e}")
                self.db.rollback()

        return alert

    # ========== FinOps ==========

    def get_optimization_recommendations(self, account_id: str) -> List[Dict[str, Any]]:
        """Generate FinOps optimization recommendations.

        Identifies unused resources, rightsizing opportunities, and
        reserved-instance suggestions.
        """
        resources = self.list_resources(account_id=account_id, limit=10000)
        recommendations = []

        for res in resources:
            # Unused / stopped instances still costing money
            if res.resource_type == ResourceType.COMPUTE_INSTANCE and res.status == ResourceStatus.STOPPED and res.monthly_cost > 0:
                recommendations.append({
                    "type": "terminate_stopped",
                    "resource_id": res.resource_id,
                    "resource_name": res.resource_name,
                    "potential_savings": res.monthly_cost,
                    "severity": "medium",
                    "recommendation": f"Instance '{res.resource_name}' is stopped but still incurring ${res.monthly_cost}/mo in storage costs. Consider terminating or snapshotting.",
                })

            # Under-utilized compute
            if res.resource_type == ResourceType.COMPUTE_INSTANCE and res.status == ResourceStatus.RUNNING:
                cpu = res.metrics.get("cpu_percent", 50)
                if cpu < 15:
                    savings = round(res.monthly_cost * 0.4, 2)
                    recommendations.append({
                        "type": "rightsize",
                        "resource_id": res.resource_id,
                        "resource_name": res.resource_name,
                        "potential_savings": savings,
                        "severity": "low",
                        "recommendation": f"Instance '{res.resource_name}' averages {cpu}% CPU. Consider downsizing to save ~${savings}/mo.",
                    })

            # Reserved instance opportunity for high-cost compute
            if res.resource_type == ResourceType.COMPUTE_INSTANCE and res.monthly_cost > 200:
                savings = round(res.monthly_cost * 0.35, 2)
                recommendations.append({
                    "type": "reserved_instance",
                    "resource_id": res.resource_id,
                    "resource_name": res.resource_name,
                    "potential_savings": savings,
                    "severity": "info",
                    "recommendation": f"Instance '{res.resource_name}' costs ${res.monthly_cost}/mo on-demand. A 1-year reserved instance could save ~${savings}/mo.",
                })

            # Unattached storage
            if res.resource_type == ResourceType.STORAGE_BUCKET and res.monthly_cost > 0:
                size = res.metrics.get("size_gb", 0)
                objects = res.metrics.get("objects", 0)
                if objects == 0 and size < 1:
                    recommendations.append({
                        "type": "delete_empty_storage",
                        "resource_id": res.resource_id,
                        "resource_name": res.resource_name,
                        "potential_savings": res.monthly_cost,
                        "severity": "low",
                        "recommendation": f"Storage '{res.resource_name}' appears empty. Consider deleting to save ${res.monthly_cost}/mo.",
                    })

        total_savings = sum(r["potential_savings"] for r in recommendations)
        recommendations.sort(key=lambda x: x["potential_savings"], reverse=True)

        return {
            "account_id": account_id,
            "total_potential_savings": round(total_savings, 2),
            "recommendation_count": len(recommendations),
            "recommendations": recommendations,
        }

    # ========== Aggregation & Dashboard ==========

    def get_multi_cloud_summary(self) -> Dict[str, Any]:
        """Aggregate stats across all cloud providers."""
        accounts = self.list_accounts()
        summary = {
            "total_accounts": len(accounts),
            "total_resources": 0,
            "total_monthly_cost": 0.0,
            "by_provider": {},
            "connected": 0,
            "disconnected": 0,
            "error": 0,
        }

        for acct in accounts:
            prov = acct.provider.value
            if prov not in summary["by_provider"]:
                summary["by_provider"][prov] = {"accounts": 0, "resources": 0, "monthly_cost": 0.0}
            summary["by_provider"][prov]["accounts"] += 1
            summary["by_provider"][prov]["resources"] += acct.resources_count
            summary["by_provider"][prov]["monthly_cost"] += acct.monthly_cost
            summary["total_resources"] += acct.resources_count
            summary["total_monthly_cost"] += acct.monthly_cost

            if acct.status == AccountStatus.CONNECTED:
                summary["connected"] += 1
            elif acct.status == AccountStatus.ERROR:
                summary["error"] += 1
            else:
                summary["disconnected"] += 1

        summary["total_monthly_cost"] = round(summary["total_monthly_cost"], 2)
        for prov in summary["by_provider"]:
            summary["by_provider"][prov]["monthly_cost"] = round(summary["by_provider"][prov]["monthly_cost"], 2)

        return summary

    def get_dashboard(self, client_id: str) -> Dict[str, Any]:
        """Comprehensive dashboard for a specific MSP client."""
        accounts = self.list_accounts(client_id=client_id)
        all_findings = []
        all_alerts = []
        total_cost = 0.0
        total_resources = 0

        for acct in accounts:
            total_cost += acct.monthly_cost
            total_resources += acct.resources_count
            all_findings.extend(self.get_findings(account_id=acct.account_id, is_resolved=False))
            all_alerts.extend(self.get_alerts(account_id=acct.account_id, is_acknowledged=False))

        # Security score across all accounts
        if all_findings:
            severity_weights = {Severity.CRITICAL: 10, Severity.HIGH: 5, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
            penalty = sum(severity_weights.get(f.severity, 1) for f in all_findings)
            score = max(0, 100 - penalty)
        else:
            score = 100

        return {
            "client_id": client_id,
            "accounts": [
                {
                    "account_id": a.account_id,
                    "provider": a.provider.value,
                    "account_name": a.account_name,
                    "status": a.status.value,
                    "resources_count": a.resources_count,
                    "monthly_cost": a.monthly_cost,
                    "last_sync_at": a.last_sync_at.isoformat() if a.last_sync_at else None,
                }
                for a in accounts
            ],
            "total_resources": total_resources,
            "total_monthly_cost": round(total_cost, 2),
            "security_score": score,
            "open_findings": len(all_findings),
            "unacknowledged_alerts": len(all_alerts),
            "top_findings": [
                {"finding_id": f.finding_id, "severity": f.severity.value, "title": f.title}
                for f in sorted(all_findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity.value, 5))[:5]
            ],
            "top_alerts": [
                {"alert_id": a.alert_id, "severity": a.severity.value, "title": a.title}
                for a in sorted(all_alerts, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity.value, 5))[:5]
            ],
        }
