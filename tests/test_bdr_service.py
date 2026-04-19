"""
Tests for Backup & Disaster Recovery (BDR) Service
Full coverage: policy lifecycle, job management, restore, verification,
DR plans, alerts, analytics, and dashboard.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.bdr_service import (
    BDRService,
    BackupType,
    JobStatus,
    RestoreType,
    DestinationType,
    Compression,
    AlertSeverity,
    _policy_to_dict,
    _job_to_dict,
    _restore_to_dict,
    _alert_to_dict,
    _dr_plan_to_dict,
    _storage_to_dict,
)


@pytest.fixture
def svc():
    """Fresh BDRService instance (in-memory mode)."""
    return BDRService()


@pytest.fixture
def svc_with_policy(svc):
    """Service with one policy already created."""
    svc.create_policy(
        name="Nightly Full Image",
        client_id="CLIENT-001",
        target_type=BackupType.FULL_IMAGE.value,
        schedule_cron="0 2 * * *",
        retention_days=30,
        retention_count=10,
    )
    return svc


# ============================================================
# Policy CRUD
# ============================================================

class TestPolicyCRUD:
    def test_create_policy(self, svc):
        policy = svc.create_policy(name="Test Policy", client_id="C1")
        assert policy.policy_id.startswith("POL-")
        assert policy.name == "Test Policy"
        assert policy.client_id == "C1"
        assert policy.is_enabled is True

    def test_get_policy(self, svc):
        p = svc.create_policy(name="Get Me")
        fetched = svc.get_policy(p.policy_id)
        assert fetched is not None
        assert fetched.name == "Get Me"

    def test_get_policy_not_found(self, svc):
        assert svc.get_policy("NONEXISTENT") is None

    def test_list_policies(self, svc):
        svc.create_policy(name="P1", client_id="C1")
        svc.create_policy(name="P2", client_id="C2")
        svc.create_policy(name="P3", client_id="C1")
        assert len(svc.list_policies()) == 3
        assert len(svc.list_policies(client_id="C1")) == 2

    def test_update_policy(self, svc):
        p = svc.create_policy(name="Original")
        updated = svc.update_policy(p.policy_id, name="Updated", retention_days=60)
        assert updated.name == "Updated"
        assert updated.retention_days == 60

    def test_update_policy_not_found(self, svc):
        assert svc.update_policy("NOPE", name="X") is None

    def test_delete_policy(self, svc):
        p = svc.create_policy(name="Deletable")
        assert svc.delete_policy(p.policy_id) is True
        assert svc.get_policy(p.policy_id) is None

    def test_delete_policy_not_found(self, svc):
        assert svc.delete_policy("NOPE") is False

    def test_policy_to_dict(self, svc):
        p = svc.create_policy(name="Dict Test", compression="lz4")
        d = _policy_to_dict(p)
        assert d["name"] == "Dict Test"
        assert d["compression"] == "lz4"
        assert "policy_id" in d

    def test_policy_all_fields(self, svc):
        p = svc.create_policy(
            name="Full",
            client_id="C99",
            target_type=BackupType.DATABASE.value,
            schedule_cron="0 3 * * 0",
            retention_days=90,
            retention_count=5,
            compression=Compression.ZSTD.value,
            encryption="aes256",
            destination_type=DestinationType.S3.value,
            destination_config={"bucket": "my-backups"},
            pre_script="echo pre",
            post_script="echo post",
            bandwidth_limit_mbps=100.0,
            is_enabled=False,
        )
        assert p.target_type == "database"
        assert p.destination_config == {"bucket": "my-backups"}
        assert p.bandwidth_limit_mbps == 100.0
        assert p.is_enabled is False


# ============================================================
# Job Management
# ============================================================

class TestJobManagement:
    def test_start_backup(self, svc_with_policy):
        svc = svc_with_policy
        policy = svc.list_policies()[0]
        job = svc.start_backup(
            policy_id=policy.policy_id,
            endpoint_id="EP-001",
            client_id="CLIENT-001",
        )
        assert job.job_id.startswith("BKP-")
        assert job.status == JobStatus.RUNNING.value
        assert job.started_at is not None

    def test_start_backup_no_policy(self, svc):
        """Should still create job even if policy doesn't exist."""
        job = svc.start_backup(policy_id="FAKE", endpoint_id="EP-001")
        assert job is not None
        assert job.job_id.startswith("BKP-")

    def test_get_job(self, svc_with_policy):
        svc = svc_with_policy
        policy = svc.list_policies()[0]
        job = svc.start_backup(policy_id=policy.policy_id, endpoint_id="EP-001")
        fetched = svc.get_job(job.job_id)
        assert fetched is not None
        assert fetched.job_id == job.job_id

    def test_get_job_not_found(self, svc):
        assert svc.get_job("NONEXISTENT") is None

    def test_list_jobs(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.start_backup(policy_id=pid, endpoint_id="EP-002")
        assert len(svc.list_jobs()) == 2
        assert len(svc.list_jobs(endpoint_id="EP-001")) == 1

    def test_list_jobs_filter_status(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        j1 = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(j1.job_id, status=JobStatus.COMPLETED.value)
        svc.start_backup(policy_id=pid, endpoint_id="EP-002")
        assert len(svc.list_jobs(status=JobStatus.COMPLETED.value)) == 1
        assert len(svc.list_jobs(status=JobStatus.RUNNING.value)) == 1

    def test_cancel_job(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        cancelled = svc.cancel_job(job.job_id)
        assert cancelled.status == JobStatus.CANCELLED.value
        assert cancelled.completed_at is not None

    def test_cancel_completed_job_noop(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(job.job_id, status=JobStatus.COMPLETED.value)
        result = svc.cancel_job(job.job_id)
        assert result.status == JobStatus.COMPLETED.value

    def test_update_job_progress(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        updated = svc.update_job_progress(
            job.job_id,
            files_processed=500,
            size_bytes=1_000_000,
            size_compressed_bytes=600_000,
            transfer_speed_mbps=50.5,
        )
        assert updated.files_processed == 500
        assert updated.size_bytes == 1_000_000
        assert updated.size_compressed_bytes == 600_000
        assert updated.transfer_speed_mbps == 50.5

    def test_update_job_progress_completed(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        updated = svc.update_job_progress(
            job.job_id, status=JobStatus.COMPLETED.value, size_bytes=5_000_000
        )
        assert updated.status == JobStatus.COMPLETED.value
        assert updated.completed_at is not None

    def test_update_job_progress_not_found(self, svc):
        assert svc.update_job_progress("NOPE") is None

    def test_job_to_dict(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        d = _job_to_dict(job)
        assert d["job_id"] == job.job_id
        assert d["status"] == "running"

    def test_incremental_backup(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        parent = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        child = svc.start_backup(
            policy_id=pid,
            endpoint_id="EP-001",
            is_incremental=True,
            parent_job_id=parent.job_id,
        )
        assert child.is_incremental is True
        assert child.parent_job_id == parent.job_id


# ============================================================
# Restore
# ============================================================

class TestRestore:
    def test_start_restore(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        restore = svc.start_restore(
            backup_job_id=job.job_id,
            endpoint_id="EP-001",
        )
        assert restore.restore_id.startswith("RST-")
        assert restore.status == JobStatus.RUNNING.value

    def test_start_restore_not_found(self, svc):
        result = svc.start_restore(backup_job_id="FAKE", endpoint_id="EP-001")
        assert result is None

    def test_get_restore(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        restore = svc.start_restore(backup_job_id=job.job_id, endpoint_id="EP-001")
        fetched = svc.get_restore(restore.restore_id)
        assert fetched is not None

    def test_list_restores(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        j1 = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        j2 = svc.start_backup(policy_id=pid, endpoint_id="EP-002")
        svc.start_restore(backup_job_id=j1.job_id, endpoint_id="EP-001")
        svc.start_restore(backup_job_id=j2.job_id, endpoint_id="EP-002")
        assert len(svc.list_restores()) == 2
        assert len(svc.list_restores(endpoint_id="EP-001")) == 1

    def test_restore_to_dict(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        restore = svc.start_restore(
            backup_job_id=job.job_id,
            endpoint_id="EP-001",
            restore_type=RestoreType.GRANULAR.value,
            target_path="/restore/target",
        )
        d = _restore_to_dict(restore)
        assert d["restore_type"] == "granular"
        assert d["target_path"] == "/restore/target"


# ============================================================
# Verification
# ============================================================

class TestVerification:
    def test_verify_completed_backup(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(job.job_id, status=JobStatus.COMPLETED.value, size_bytes=10000)
        result = svc.verify_backup(job.job_id)
        assert result["verification_status"] == "passed"
        assert len(result["verification_hash"]) == 64  # SHA-256

    def test_verify_not_found(self, svc):
        result = svc.verify_backup("NOPE")
        assert result["status"] == "failed"

    def test_verify_incomplete_job(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        result = svc.verify_backup(job.job_id)
        assert result["status"] == "skipped"


# ============================================================
# Storage Usage
# ============================================================

class TestStorageUsage:
    def test_storage_usage_empty(self, svc):
        usage = svc.get_storage_usage("EP-001")
        assert usage.total_bytes == 0
        assert usage.backup_count == 0

    def test_storage_usage_with_jobs(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        j1 = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(
            j1.job_id, status=JobStatus.COMPLETED.value,
            size_bytes=1_000_000, size_compressed_bytes=600_000,
        )
        j2 = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(
            j2.job_id, status=JobStatus.COMPLETED.value,
            size_bytes=900_000, size_compressed_bytes=500_000,
        )
        usage = svc.get_storage_usage("EP-001")
        assert usage.backup_count == 2
        assert usage.total_bytes == 1_100_000  # compressed totals

    def test_storage_usage_all(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        j1 = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(j1.job_id, status=JobStatus.COMPLETED.value, size_bytes=1000)
        j2 = svc.start_backup(policy_id=pid, endpoint_id="EP-002")
        svc.update_job_progress(j2.job_id, status=JobStatus.COMPLETED.value, size_bytes=2000)
        all_usage = svc.get_storage_usage_all()
        assert len(all_usage) == 2

    def test_storage_to_dict(self, svc):
        usage = svc.get_storage_usage("EP-001")
        d = _storage_to_dict(usage)
        assert d["endpoint_id"] == "EP-001"
        assert d["total_bytes"] == 0


# ============================================================
# Alerts
# ============================================================

class TestAlerts:
    def test_create_and_get_alerts(self, svc):
        svc._create_alert(
            alert_type="backup_failed",
            severity=AlertSeverity.HIGH.value,
            message="Backup failed on EP-001",
            endpoint_id="EP-001",
        )
        alerts = svc.get_alerts()
        assert len(alerts) == 1
        assert alerts[0].alert_type == "backup_failed"

    def test_acknowledge_alert(self, svc):
        alert = svc._create_alert(
            alert_type="backup_failed",
            severity=AlertSeverity.CRITICAL.value,
            message="Critical failure",
        )
        result = svc.acknowledge_alert(alert.alert_id)
        assert result.is_acknowledged is True

    def test_acknowledge_alert_not_found(self, svc):
        assert svc.acknowledge_alert("NOPE") is None

    def test_filter_alerts(self, svc):
        svc._create_alert(alert_type="backup_failed", severity="high", message="Fail")
        svc._create_alert(alert_type="storage_low", severity="medium", message="Low space")
        a = svc._create_alert(alert_type="backup_failed", severity="high", message="Fail 2")
        svc.acknowledge_alert(a.alert_id)

        assert len(svc.get_alerts(acknowledged=False)) == 2
        assert len(svc.get_alerts(acknowledged=True)) == 1
        assert len(svc.get_alerts(alert_type="storage_low")) == 1

    def test_check_missed_backups(self, svc):
        svc.create_policy(name="Old Policy", client_id="C1")
        alerts = svc.check_missed_backups()
        assert len(alerts) >= 1
        assert alerts[0].alert_type == "backup_missed"

    def test_alert_to_dict(self, svc):
        alert = svc._create_alert(
            alert_type="verification_failed", severity="medium", message="Hash mismatch"
        )
        d = _alert_to_dict(alert)
        assert d["alert_type"] == "verification_failed"
        assert d["is_acknowledged"] is False


# ============================================================
# DR Plans
# ============================================================

class TestDRPlans:
    def test_create_dr_plan(self, svc):
        plan = svc.create_dr_plan(
            name="Primary DR",
            client_id="C1",
            rto_minutes=120,
            rpo_minutes=30,
            priority_systems=["DC-01", "DB-01", "APP-01"],
            runbook_steps=[
                {"step": 1, "action": "Failover DNS"},
                {"step": 2, "action": "Restore DB from latest backup"},
            ],
            contacts=[{"name": "Dan", "phone": "555-0100"}],
        )
        assert plan.plan_id.startswith("DRP-")
        assert plan.rto_minutes == 120
        assert len(plan.priority_systems) == 3

    def test_get_dr_plan(self, svc):
        plan = svc.create_dr_plan(name="Get Test")
        fetched = svc.get_dr_plan(plan.plan_id)
        assert fetched is not None

    def test_list_dr_plans(self, svc):
        svc.create_dr_plan(name="Plan A", client_id="C1")
        svc.create_dr_plan(name="Plan B", client_id="C2")
        assert len(svc.list_dr_plans()) == 2
        assert len(svc.list_dr_plans(client_id="C1")) == 1

    def test_update_dr_plan(self, svc):
        plan = svc.create_dr_plan(name="Before", rto_minutes=240)
        updated = svc.update_dr_plan(plan.plan_id, name="After", rto_minutes=60)
        assert updated.name == "After"
        assert updated.rto_minutes == 60

    def test_update_dr_plan_not_found(self, svc):
        assert svc.update_dr_plan("NOPE", name="X") is None

    def test_delete_dr_plan(self, svc):
        plan = svc.create_dr_plan(name="Deletable")
        assert svc.delete_dr_plan(plan.plan_id) is True
        assert svc.get_dr_plan(plan.plan_id) is None

    def test_delete_dr_plan_not_found(self, svc):
        assert svc.delete_dr_plan("NOPE") is False

    def test_test_dr_plan_passes(self, svc):
        svc.create_policy(name="Server Backup", client_id="C1")
        plan = svc.create_dr_plan(
            name="Full DR",
            client_id="C1",
            rto_minutes=120,
            rpo_minutes=30,
            priority_systems=["DC-01"],
            runbook_steps=[{"step": 1, "action": "Failover"}],
            contacts=[{"name": "Admin"}],
        )
        result = svc.test_dr_plan(plan.plan_id)
        assert result["test_result"] == "passed"
        assert len(result["issues"]) == 0

    def test_test_dr_plan_fails(self, svc):
        plan = svc.create_dr_plan(name="Empty DR", client_id="NOBODY")
        result = svc.test_dr_plan(plan.plan_id)
        assert result["test_result"] == "failed"
        assert len(result["issues"]) > 0

    def test_test_dr_plan_not_found(self, svc):
        result = svc.test_dr_plan("NOPE")
        assert "error" in result

    def test_dr_plan_to_dict(self, svc):
        plan = svc.create_dr_plan(name="Dict Test", rpo_minutes=15)
        d = _dr_plan_to_dict(plan)
        assert d["name"] == "Dict Test"
        assert d["rpo_minutes"] == 15


# ============================================================
# Analytics
# ============================================================

class TestAnalytics:
    def test_success_rate_empty(self, svc):
        result = svc.get_backup_success_rate()
        assert result["success_rate_pct"] == 100.0
        assert result["total_jobs"] == 0

    def test_success_rate_with_jobs(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        j1 = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(j1.job_id, status=JobStatus.COMPLETED.value)
        j2 = svc.start_backup(policy_id=pid, endpoint_id="EP-002")
        svc.update_job_progress(j2.job_id, status=JobStatus.FAILED.value)
        result = svc.get_backup_success_rate()
        assert result["total_jobs"] == 2
        assert result["completed"] == 1
        assert result["failed"] == 1
        assert result["success_rate_pct"] == 50.0

    def test_average_duration_empty(self, svc):
        result = svc.get_average_backup_duration()
        assert result["average_seconds"] == 0
        assert result["job_count"] == 0

    def test_average_duration_with_jobs(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        job = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(job.job_id, status=JobStatus.COMPLETED.value)
        result = svc.get_average_backup_duration()
        assert result["job_count"] == 1
        assert result["average_seconds"] >= 0

    def test_storage_growth_trend(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        j = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(j.job_id, status=JobStatus.COMPLETED.value, size_bytes=50000)
        result = svc.get_storage_growth_trend()
        assert result["new_bytes"] == 50000
        assert result["total_bytes"] == 50000
        assert result["new_backups"] == 1


# ============================================================
# Dashboard
# ============================================================

class TestDashboard:
    def test_dashboard_empty(self, svc):
        dash = svc.get_dashboard()
        assert dash["jobs_today"] == 0
        assert dash["total_policies"] == 0
        assert dash["unacknowledged_alerts"] == 0

    def test_dashboard_with_data(self, svc_with_policy):
        svc = svc_with_policy
        pid = svc.list_policies()[0].policy_id
        j = svc.start_backup(policy_id=pid, endpoint_id="EP-001")
        svc.update_job_progress(j.job_id, status=JobStatus.COMPLETED.value, size_bytes=1000)
        svc._create_alert(alert_type="backup_failed", severity="high", message="Error")
        svc.create_dr_plan(name="DR Test", client_id="CLIENT-001")

        dash = svc.get_dashboard()
        assert dash["jobs_today"] >= 1
        assert dash["total_policies"] == 1
        assert dash["enabled_policies"] == 1
        assert dash["unacknowledged_alerts"] == 1
        assert dash["dr_plans_total"] == 1
        assert dash["total_storage_bytes"] == 1000


# ============================================================
# Enum values
# ============================================================

class TestEnums:
    def test_backup_type_values(self):
        assert BackupType.FULL_IMAGE.value == "full_image"
        assert BackupType.SQL_SERVER.value == "sql_server"

    def test_job_status_values(self):
        assert JobStatus.VERIFYING.value == "verifying"
        assert JobStatus.CANCELLED.value == "cancelled"

    def test_restore_type_values(self):
        assert RestoreType.BARE_METAL.value == "bare_metal"
        assert RestoreType.CLOUD.value == "cloud"

    def test_destination_type_values(self):
        assert DestinationType.AZURE_BLOB.value == "azure_blob"
        assert DestinationType.GCS.value == "gcs"

    def test_compression_values(self):
        assert Compression.ZSTD.value == "zstd"
        assert Compression.NONE.value == "none"

    def test_alert_severity_values(self):
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.INFO.value == "info"
