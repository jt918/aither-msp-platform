"""
Tests for CMDB (Configuration Management Database) Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.cmdb import (
    CMDBService,
    CIType,
    CIStatus,
    Environment,
    RelationshipType,
    ChangeType,
    ChangeSource,
    ImpactType,
    ImpactLevel,
    ConfigurationItem,
    CIRelationship,
    ConfigurationBaseline,
    ConfigurationChange,
    ImpactAnalysis,
)


class TestCMDBService:
    """Tests for CMDBService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = CMDBService()

    # ========== CI CRUD Tests ==========

    def test_create_ci_basic(self):
        """Test basic CI creation"""
        ci = self.service.create_ci(
            client_id="client-001",
            ci_type=CIType.SERVER,
            name="PROD-WEB-01",
        )
        assert ci is not None
        assert ci.ci_id.startswith("CI-")
        assert ci.client_id == "client-001"
        assert ci.ci_type == CIType.SERVER
        assert ci.name == "PROD-WEB-01"
        assert ci.status == CIStatus.ACTIVE
        assert ci.environment == Environment.PRODUCTION

    def test_create_ci_full(self):
        """Test CI creation with all fields"""
        ci = self.service.create_ci(
            client_id="client-002",
            ci_type=CIType.FIREWALL,
            name="FW-EDGE-01",
            description="Edge firewall for HQ",
            status=CIStatus.ACTIVE,
            environment=Environment.PRODUCTION,
            location="HQ Rack A3",
            owner="network-team",
            department="IT",
            attributes={"throughput": "10Gbps"},
            tags=["edge", "security"],
            serial_number="SN-FW-12345",
            asset_tag="AT-FW-001",
            ip_address="10.0.0.1",
            mac_address="AA:BB:CC:DD:EE:FF",
            manufacturer="Palo Alto",
            model="PA-5250",
            firmware_version="10.2.3",
            configuration_data={"ha_mode": "active-passive"},
        )
        assert ci.description == "Edge firewall for HQ"
        assert ci.location == "HQ Rack A3"
        assert ci.serial_number == "SN-FW-12345"
        assert ci.manufacturer == "Palo Alto"
        assert ci.ip_address == "10.0.0.1"
        assert "edge" in ci.tags

    def test_get_ci(self):
        """Test retrieving a CI by ID"""
        ci = self.service.create_ci(
            client_id="client-001",
            ci_type=CIType.WORKSTATION,
            name="WKS-001",
        )
        retrieved = self.service.get_ci(ci.ci_id)
        assert retrieved is not None
        assert retrieved.ci_id == ci.ci_id
        assert retrieved.name == "WKS-001"

    def test_get_ci_not_found(self):
        """Test retrieving a non-existent CI"""
        result = self.service.get_ci("CI-NONEXISTENT")
        assert result is None

    def test_list_cis(self):
        """Test listing CIs"""
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        self.service.create_ci(client_id="c1", ci_type=CIType.WORKSTATION, name="WKS-01")
        self.service.create_ci(client_id="c2", ci_type=CIType.SERVER, name="SRV-02")

        all_cis = self.service.list_cis()
        assert len(all_cis) == 3

        client1 = self.service.list_cis(client_id="c1")
        assert len(client1) == 2

        servers = self.service.list_cis(ci_type=CIType.SERVER)
        assert len(servers) == 2

    def test_list_cis_with_filters(self):
        """Test listing CIs with multiple filters"""
        self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="SRV-PROD",
            status=CIStatus.ACTIVE, environment=Environment.PRODUCTION,
        )
        self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="SRV-DEV",
            status=CIStatus.ACTIVE, environment=Environment.DEVELOPMENT,
        )

        prod_cis = self.service.list_cis(client_id="c1", environment=Environment.PRODUCTION)
        assert len(prod_cis) == 1
        assert prod_cis[0].name == "SRV-PROD"

    def test_update_ci(self):
        """Test updating a CI"""
        ci = self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="SRV-01",
            ip_address="10.0.0.10",
        )
        updated = self.service.update_ci(ci.ci_id, ip_address="10.0.0.20", owner="ops-team")
        assert updated is not None
        assert updated.ip_address == "10.0.0.20"
        assert updated.owner == "ops-team"
        assert updated.updated_at is not None

    def test_update_ci_not_found(self):
        """Test updating a non-existent CI"""
        result = self.service.update_ci("CI-NONEXISTENT", name="ghost")
        assert result is None

    def test_update_ci_tracks_changes(self):
        """Test that updates automatically record changes"""
        ci = self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="SRV-01",
            ip_address="10.0.0.10",
        )
        self.service.update_ci(ci.ci_id, ip_address="10.0.0.20")
        changes = self.service.get_change_history(ci.ci_id)

        # Should have at least 2 changes: created + updated
        assert len(changes) >= 2
        update_changes = [c for c in changes if c.change_type == ChangeType.UPDATED]
        assert len(update_changes) >= 1
        assert update_changes[0].field_changed == "ip_address"

    def test_delete_ci(self):
        """Test soft-deleting a CI"""
        ci = self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="SRV-DELETE",
        )
        success = self.service.delete_ci(ci.ci_id)
        assert success is True

        deleted = self.service.get_ci(ci.ci_id)
        assert deleted.status == CIStatus.DECOMMISSIONED

    def test_delete_ci_not_found(self):
        """Test deleting a non-existent CI"""
        result = self.service.delete_ci("CI-NONEXISTENT")
        assert result is False

    def test_search_cis(self):
        """Test searching CIs"""
        self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="PROD-WEB-01",
            ip_address="10.0.1.10", tags=["web", "production"],
        )
        self.service.create_ci(
            client_id="c1", ci_type=CIType.DATABASE, name="PROD-DB-01",
            ip_address="10.0.1.20", manufacturer="Dell",
        )
        self.service.create_ci(
            client_id="c1", ci_type=CIType.WORKSTATION, name="DEV-WKS-01",
        )

        results = self.service.search_cis("PROD")
        assert len(results) == 2

        results = self.service.search_cis("web")
        assert len(results) >= 1

        results = self.service.search_cis("10.0.1.20")
        assert len(results) == 1

        results = self.service.search_cis("Dell")
        assert len(results) == 1

    # ========== Relationship Tests ==========

    def test_create_relationship(self):
        """Test creating a relationship between CIs"""
        ci1 = self.service.create_ci(client_id="c1", ci_type=CIType.APPLICATION, name="WebApp")
        ci2 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="AppServer")

        rel = self.service.create_relationship(
            source_ci_id=ci1.ci_id,
            target_ci_id=ci2.ci_id,
            relationship_type=RelationshipType.RUNS_ON,
            description="WebApp runs on AppServer",
        )
        assert rel is not None
        assert rel.relationship_id.startswith("REL-")
        assert rel.source_ci_id == ci1.ci_id
        assert rel.target_ci_id == ci2.ci_id
        assert rel.relationship_type == RelationshipType.RUNS_ON

    def test_create_relationship_invalid_ci(self):
        """Test creating a relationship with non-existent CI"""
        ci1 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        rel = self.service.create_relationship(
            source_ci_id=ci1.ci_id,
            target_ci_id="CI-NONEXISTENT",
            relationship_type=RelationshipType.DEPENDS_ON,
        )
        assert rel is None

    def test_get_relationships(self):
        """Test getting relationships for a CI"""
        ci1 = self.service.create_ci(client_id="c1", ci_type=CIType.APPLICATION, name="App")
        ci2 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="Server")
        ci3 = self.service.create_ci(client_id="c1", ci_type=CIType.DATABASE, name="Database")

        self.service.create_relationship(ci1.ci_id, ci2.ci_id, RelationshipType.RUNS_ON)
        self.service.create_relationship(ci1.ci_id, ci3.ci_id, RelationshipType.DEPENDS_ON)

        rels = self.service.get_relationships(ci1.ci_id)
        assert len(rels) == 2

    def test_delete_relationship(self):
        """Test deleting a relationship"""
        ci1 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="S1")
        ci2 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="S2")
        rel = self.service.create_relationship(ci1.ci_id, ci2.ci_id, RelationshipType.CONNECTS_TO)

        success = self.service.delete_relationship(rel.relationship_id)
        assert success is True

        rels = self.service.get_relationships(ci1.ci_id)
        assert len(rels) == 0

    def test_get_dependency_tree(self):
        """Test recursive dependency tree"""
        ci_app = self.service.create_ci(client_id="c1", ci_type=CIType.APPLICATION, name="WebApp")
        ci_srv = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="AppServer")
        ci_db = self.service.create_ci(client_id="c1", ci_type=CIType.DATABASE, name="MySQL")
        ci_storage = self.service.create_ci(client_id="c1", ci_type=CIType.STORAGE, name="SAN")

        self.service.create_relationship(ci_app.ci_id, ci_srv.ci_id, RelationshipType.RUNS_ON)
        self.service.create_relationship(ci_app.ci_id, ci_db.ci_id, RelationshipType.DEPENDS_ON)
        self.service.create_relationship(ci_db.ci_id, ci_storage.ci_id, RelationshipType.RUNS_ON)

        tree = self.service.get_dependency_tree(ci_app.ci_id)
        assert tree["ci_id"] == ci_app.ci_id
        assert tree["name"] == "WebApp"
        assert len(tree["children"]) == 2

    def test_dependency_tree_handles_circular(self):
        """Test that dependency tree handles circular references"""
        ci1 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVICE, name="SvcA")
        ci2 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVICE, name="SvcB")

        self.service.create_relationship(ci1.ci_id, ci2.ci_id, RelationshipType.DEPENDS_ON)
        self.service.create_relationship(ci2.ci_id, ci1.ci_id, RelationshipType.DEPENDS_ON)

        # Should not loop infinitely
        tree = self.service.get_dependency_tree(ci1.ci_id)
        assert tree is not None

    # ========== Baseline Tests ==========

    def test_capture_baseline(self):
        """Test capturing a baseline"""
        ci = self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="SRV-01",
            ip_address="10.0.0.1", firmware_version="1.0",
        )
        bl = self.service.capture_baseline(ci.ci_id, baseline_name="Initial")
        assert bl is not None
        assert bl.baseline_id.startswith("BL-")
        assert bl.ci_id == ci.ci_id
        assert bl.baseline_name == "Initial"
        assert bl.is_current is True
        assert bl.baseline_data["ip_address"] == "10.0.0.1"

    def test_capture_baseline_not_found(self):
        """Test capturing baseline for non-existent CI"""
        result = self.service.capture_baseline("CI-NONEXISTENT")
        assert result is None

    def test_get_baselines(self):
        """Test getting baselines for a CI"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        self.service.capture_baseline(ci.ci_id, baseline_name="v1")
        self.service.capture_baseline(ci.ci_id, baseline_name="v2")

        baselines = self.service.get_baselines(ci.ci_id)
        assert len(baselines) == 2

    def test_new_baseline_replaces_current(self):
        """Test that new baseline marks old one as not current"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        bl1 = self.service.capture_baseline(ci.ci_id, baseline_name="v1")
        bl2 = self.service.capture_baseline(ci.ci_id, baseline_name="v2")

        baselines = self.service.get_baselines(ci.ci_id)
        current = [bl for bl in baselines if bl.is_current]
        assert len(current) == 1
        assert current[0].baseline_name == "v2"

    def test_compare_to_baseline_no_drift(self):
        """Test drift detection with no drift"""
        ci = self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="SRV-01",
            ip_address="10.0.0.1",
        )
        self.service.capture_baseline(ci.ci_id)

        result = self.service.compare_to_baseline(ci.ci_id)
        assert result["has_drift"] is False
        assert result["drift_count"] == 0

    def test_compare_to_baseline_with_drift(self):
        """Test drift detection after a change"""
        ci = self.service.create_ci(
            client_id="c1", ci_type=CIType.SERVER, name="SRV-01",
            ip_address="10.0.0.1", firmware_version="1.0",
        )
        self.service.capture_baseline(ci.ci_id)

        # Make changes
        self.service.update_ci(ci.ci_id, ip_address="10.0.0.99", firmware_version="2.0")

        result = self.service.compare_to_baseline(ci.ci_id)
        assert result["has_drift"] is True
        assert result["drift_count"] >= 2
        drift_fields = [d["field"] for d in result["drifts"]]
        assert "ip_address" in drift_fields
        assert "firmware_version" in drift_fields

    def test_compare_to_baseline_no_baseline(self):
        """Test drift detection when no baseline exists"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        result = self.service.compare_to_baseline(ci.ci_id)
        assert "error" in result

    # ========== Change Tracking Tests ==========

    def test_record_change(self):
        """Test manual change recording"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        change = self.service.record_change(
            ci_id=ci.ci_id,
            change_type=ChangeType.UPDATED,
            field_changed="firmware_version",
            old_value="1.0",
            new_value="2.0",
            changed_by="admin",
        )
        assert change.change_id.startswith("CHG-")
        assert change.field_changed == "firmware_version"

    def test_get_change_history(self):
        """Test getting change history"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        # CI creation already records a change
        history = self.service.get_change_history(ci.ci_id)
        assert len(history) >= 1
        assert history[0].change_type == ChangeType.CREATED

    def test_get_recent_changes(self):
        """Test getting recent changes across CIs"""
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-02")

        changes = self.service.get_recent_changes(client_id="c1")
        assert len(changes) >= 2

    def test_get_recent_changes_all_clients(self):
        """Test getting recent changes without client filter"""
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        self.service.create_ci(client_id="c2", ci_type=CIType.SERVER, name="SRV-02")

        changes = self.service.get_recent_changes()
        assert len(changes) >= 2

    # ========== Impact Analysis Tests ==========

    def test_analyze_impact_no_deps(self):
        """Test impact analysis on CI with no dependencies"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="Standalone")
        analysis = self.service.analyze_impact(ci.ci_id, ImpactType.OUTAGE)
        assert analysis.impact_level == ImpactLevel.NONE
        assert len(analysis.affected_cis) == 0

    def test_analyze_impact_with_deps(self):
        """Test impact analysis on CI with dependencies"""
        ci_db = self.service.create_ci(client_id="c1", ci_type=CIType.DATABASE, name="PrimaryDB")
        ci_app1 = self.service.create_ci(client_id="c1", ci_type=CIType.APPLICATION, name="App1")
        ci_app2 = self.service.create_ci(client_id="c1", ci_type=CIType.APPLICATION, name="App2")

        self.service.create_relationship(ci_db.ci_id, ci_app1.ci_id, RelationshipType.HOSTS)
        self.service.create_relationship(ci_db.ci_id, ci_app2.ci_id, RelationshipType.HOSTS)

        analysis = self.service.analyze_impact(ci_db.ci_id, ImpactType.OUTAGE)
        assert len(analysis.affected_cis) == 2
        assert analysis.impact_level != ImpactLevel.NONE

    def test_analyze_impact_cascading(self):
        """Test cascading impact analysis"""
        ci_storage = self.service.create_ci(client_id="c1", ci_type=CIType.STORAGE, name="SAN")
        ci_db = self.service.create_ci(client_id="c1", ci_type=CIType.DATABASE, name="DB")
        ci_app = self.service.create_ci(client_id="c1", ci_type=CIType.APPLICATION, name="App")
        ci_svc = self.service.create_ci(client_id="c1", ci_type=CIType.SERVICE, name="API")

        self.service.create_relationship(ci_storage.ci_id, ci_db.ci_id, RelationshipType.HOSTS)
        self.service.create_relationship(ci_db.ci_id, ci_app.ci_id, RelationshipType.HOSTS)
        self.service.create_relationship(ci_app.ci_id, ci_svc.ci_id, RelationshipType.HOSTS)

        analysis = self.service.analyze_impact(ci_storage.ci_id, ImpactType.OUTAGE)
        assert len(analysis.affected_cis) == 3

    # ========== Sync Tests ==========

    def test_sync_from_rmm(self):
        """Test RMM sync returns expected structure"""
        result = self.service.sync_from_rmm("client-001")
        assert "client_id" in result
        assert "source" in result
        assert result["source"] == "rmm"
        assert "created" in result
        assert "updated" in result
        assert "errors" in result

    def test_sync_from_discovery(self):
        """Test network discovery sync returns expected structure"""
        result = self.service.sync_from_discovery("client-001")
        assert "client_id" in result
        assert result["source"] == "network_discovery"

    # ========== Audit Tests ==========

    def test_get_stale_cis(self):
        """Test finding stale CIs (never audited)"""
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        stale = self.service.get_stale_cis(days=90)
        assert len(stale) >= 1

    def test_mark_audited(self):
        """Test marking a CI as audited"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        assert ci.last_audit_at is None

        success = self.service.mark_audited(ci.ci_id)
        assert success is True

        updated = self.service.get_ci(ci.ci_id)
        assert updated.last_audit_at is not None

    def test_mark_audited_not_found(self):
        """Test marking non-existent CI as audited"""
        result = self.service.mark_audited("CI-NONEXISTENT")
        assert result is False

    def test_stale_after_audit(self):
        """Test that audited CI is no longer stale"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        self.service.mark_audited(ci.ci_id)

        stale = self.service.get_stale_cis(days=90)
        stale_ids = [s.ci_id for s in stale]
        assert ci.ci_id not in stale_ids

    # ========== Visualization/Dashboard Tests ==========

    def test_get_topology_map(self):
        """Test topology map generation"""
        ci1 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        ci2 = self.service.create_ci(client_id="c1", ci_type=CIType.DATABASE, name="DB-01")
        self.service.create_relationship(ci1.ci_id, ci2.ci_id, RelationshipType.HOSTS)

        topology = self.service.get_topology_map("c1")
        assert topology["client_id"] == "c1"
        assert topology["node_count"] == 2
        assert topology["edge_count"] == 1
        assert len(topology["nodes"]) == 2
        assert len(topology["edges"]) == 1

    def test_get_ci_count_by_type(self):
        """Test CI count by type"""
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-02")
        self.service.create_ci(client_id="c1", ci_type=CIType.WORKSTATION, name="WKS-01")

        counts = self.service.get_ci_count_by_type(client_id="c1")
        assert counts["server"] == 2
        assert counts["workstation"] == 1

    def test_get_ci_count_by_status(self):
        """Test CI count by status"""
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        ci2 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-02")
        self.service.delete_ci(ci2.ci_id)

        counts = self.service.get_ci_count_by_status(client_id="c1")
        assert counts.get("active", 0) >= 1
        assert counts.get("decommissioned", 0) >= 1

    def test_get_dashboard(self):
        """Test dashboard aggregation"""
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        self.service.create_ci(client_id="c1", ci_type=CIType.WORKSTATION, name="WKS-01")

        dashboard = self.service.get_dashboard()
        assert dashboard["total_cis"] == 2
        assert "by_type" in dashboard
        assert "by_status" in dashboard
        assert "recent_changes" in dashboard
        assert "stale_count" in dashboard
        assert "relationship_count" in dashboard
        assert "generated_at" in dashboard

    # ========== Enum Tests ==========

    def test_ci_type_enum(self):
        """Test CIType enum values"""
        assert CIType.SERVER.value == "server"
        assert CIType.FIREWALL.value == "firewall"
        assert CIType.CLOUD_INSTANCE.value == "cloud_instance"
        assert len(CIType) == 20

    def test_ci_status_enum(self):
        """Test CIStatus enum values"""
        assert CIStatus.ACTIVE.value == "active"
        assert CIStatus.DECOMMISSIONED.value == "decommissioned"
        assert CIStatus.MAINTENANCE.value == "maintenance"
        assert len(CIStatus) == 5

    def test_environment_enum(self):
        """Test Environment enum values"""
        assert Environment.PRODUCTION.value == "production"
        assert Environment.DR.value == "dr"
        assert Environment.TEST.value == "test"
        assert len(Environment) == 5

    def test_relationship_type_enum(self):
        """Test RelationshipType enum values"""
        assert RelationshipType.DEPENDS_ON.value == "depends_on"
        assert RelationshipType.COMMUNICATES_WITH.value == "communicates_with"
        assert len(RelationshipType) == 10

    # ========== Dataclass Tests ==========

    def test_configuration_item_defaults(self):
        """Test ConfigurationItem dataclass defaults"""
        ci = ConfigurationItem(
            ci_id="CI-TEST",
            client_id="c1",
            ci_type=CIType.SERVER,
            name="Test",
        )
        assert ci.status == CIStatus.ACTIVE
        assert ci.environment == Environment.PRODUCTION
        assert ci.attributes == {}
        assert ci.tags == []
        assert ci.last_audit_at is None

    def test_ci_relationship_defaults(self):
        """Test CIRelationship dataclass defaults"""
        rel = CIRelationship(
            relationship_id="REL-TEST",
            source_ci_id="CI-1",
            target_ci_id="CI-2",
            relationship_type=RelationshipType.DEPENDS_ON,
        )
        assert rel.is_bidirectional is False
        assert rel.description == ""

    def test_impact_analysis_defaults(self):
        """Test ImpactAnalysis dataclass defaults"""
        analysis = ImpactAnalysis(
            analysis_id="IMP-TEST",
            ci_id="CI-1",
            impact_type=ImpactType.OUTAGE,
        )
        assert analysis.affected_cis == []
        assert analysis.impact_level == ImpactLevel.NONE
        assert analysis.analysis_details == {}

    # ========== Edge Cases ==========

    def test_search_cis_empty_query(self):
        """Test search with empty query returns all"""
        self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        results = self.service.search_cis("")
        assert len(results) >= 1

    def test_bidirectional_relationship(self):
        """Test bidirectional relationship traversal"""
        ci1 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="S1")
        ci2 = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="S2")

        self.service.create_relationship(
            ci1.ci_id, ci2.ci_id,
            RelationshipType.COMMUNICATES_WITH,
            is_bidirectional=True,
        )

        rels_from_ci2 = self.service.get_relationships(ci2.ci_id)
        assert len(rels_from_ci2) == 1

    def test_multiple_baselines(self):
        """Test multiple baselines only one is current"""
        ci = self.service.create_ci(client_id="c1", ci_type=CIType.SERVER, name="SRV-01")
        self.service.capture_baseline(ci.ci_id, baseline_name="v1")
        self.service.capture_baseline(ci.ci_id, baseline_name="v2")
        self.service.capture_baseline(ci.ci_id, baseline_name="v3")

        baselines = self.service.get_baselines(ci.ci_id)
        current = [bl for bl in baselines if bl.is_current]
        assert len(current) == 1
        assert current[0].baseline_name == "v3"

    def test_delete_nonexistent_relationship(self):
        """Test deleting a relationship that doesn't exist"""
        result = self.service.delete_relationship("REL-NONEXISTENT")
        assert result is False
