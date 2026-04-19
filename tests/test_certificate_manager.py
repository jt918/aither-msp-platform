"""
Tests for Certificate Lifecycle Management Service.
Full coverage of CRUD, scanning, expiration, renewal, alerts, analytics.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.certificate_manager import (
    CertificateManagerService,
    Certificate,
    CertificateAlert,
    RenewalRequest,
    CertificateScan,
    CABundle,
    CertType,
    CertStatus,
    AlertType,
    AlertSeverity,
    ScanGrade,
    RenewalStatus,
)


@pytest.fixture
def svc():
    """Create a fresh in-memory CertificateManagerService."""
    return CertificateManagerService()


@pytest.fixture
def sample_cert(svc):
    """Add a sample certificate and return it."""
    return svc.add_certificate(
        common_name="example.com",
        client_id="CLIENT-001",
        san_names=["example.com", "www.example.com"],
        issuer="Let's Encrypt Authority X3",
        key_algorithm="RSA",
        key_size=2048,
        valid_from=datetime.now(timezone.utc) - timedelta(days=30),
        valid_to=datetime.now(timezone.utc) + timedelta(days=335),
        cert_type="dv",
        installed_on=["web-01:443", "web-02:443"],
        auto_renew=True,
        renewal_provider="lets_encrypt",
    )


@pytest.fixture
def expiring_cert(svc):
    """Add a certificate expiring in 5 days."""
    return svc.add_certificate(
        common_name="expiring.example.com",
        client_id="CLIENT-001",
        valid_to=datetime.now(timezone.utc) + timedelta(days=5),
        cert_type="dv",
    )


@pytest.fixture
def expired_cert(svc):
    """Add an already-expired certificate."""
    return svc.add_certificate(
        common_name="old.example.com",
        client_id="CLIENT-002",
        valid_to=datetime.now(timezone.utc) - timedelta(days=10),
        cert_type="dv",
    )


# ============================================================
# Enum Tests
# ============================================================

class TestEnums:
    def test_cert_type_values(self):
        assert CertType.DV.value == "dv"
        assert CertType.EV.value == "ev"
        assert CertType.WILDCARD.value == "wildcard"
        assert CertType.CODE_SIGNING.value == "code_signing"
        assert CertType.CLIENT.value == "client"

    def test_cert_status_values(self):
        assert CertStatus.ACTIVE.value == "active"
        assert CertStatus.EXPIRING_SOON.value == "expiring_soon"
        assert CertStatus.EXPIRED.value == "expired"
        assert CertStatus.REVOKED.value == "revoked"
        assert CertStatus.PENDING_RENEWAL.value == "pending_renewal"

    def test_alert_type_values(self):
        assert AlertType.EXPIRING_30D.value == "expiring_30d"
        assert AlertType.WEAK_KEY.value == "weak_key"
        assert AlertType.CHAIN_INCOMPLETE.value == "chain_incomplete"
        assert AlertType.PROTOCOL_OUTDATED.value == "protocol_outdated"

    def test_scan_grade_values(self):
        assert ScanGrade.A_PLUS.value == "A+"
        assert ScanGrade.A.value == "A"
        assert ScanGrade.F.value == "F"

    def test_renewal_status_values(self):
        assert RenewalStatus.PENDING.value == "pending"
        assert RenewalStatus.IN_PROGRESS.value == "in_progress"
        assert RenewalStatus.COMPLETED.value == "completed"
        assert RenewalStatus.FAILED.value == "failed"


# ============================================================
# Dataclass Tests
# ============================================================

class TestDataclasses:
    def test_certificate_defaults(self):
        c = Certificate(cert_id="CERT-TEST")
        assert c.cert_id == "CERT-TEST"
        assert c.status == CertStatus.ACTIVE
        assert c.cert_type == CertType.DV
        assert c.key_algorithm == "RSA"
        assert c.key_size == 2048
        assert c.auto_renew is False
        assert c.san_names == []
        assert c.installed_on == []

    def test_certificate_alert_defaults(self):
        a = CertificateAlert(
            alert_id="ALRT-1", cert_id="CERT-1",
            alert_type=AlertType.EXPIRED, severity=AlertSeverity.CRITICAL,
        )
        assert a.is_acknowledged is False
        assert a.message == ""

    def test_renewal_request_defaults(self):
        r = RenewalRequest(renewal_id="REN-1", cert_id="CERT-1")
        assert r.status == RenewalStatus.PENDING
        assert r.new_cert_id is None
        assert r.error_message == ""

    def test_certificate_scan_defaults(self):
        s = CertificateScan(scan_id="SCAN-1", target_host="example.com")
        assert s.port == 443
        assert s.cert_found is False
        assert s.chain_valid is True
        assert s.issues == []

    def test_ca_bundle_defaults(self):
        b = CABundle(bundle_id="BUN-1", name="Default")
        assert b.is_default is False
        assert b.certificates == []


# ============================================================
# Service Init
# ============================================================

class TestServiceInit:
    def test_create_service_no_db(self):
        svc = CertificateManagerService()
        assert svc.db is None
        assert svc._use_db is False

    def test_internal_stores_empty(self):
        svc = CertificateManagerService()
        assert len(svc._certificates) == 0
        assert len(svc._alerts) == 0
        assert len(svc._renewals) == 0
        assert len(svc._scans) == 0


# ============================================================
# Certificate CRUD
# ============================================================

class TestCertificateCRUD:
    def test_add_certificate(self, svc, sample_cert):
        assert sample_cert.cert_id.startswith("CERT-")
        assert sample_cert.common_name == "example.com"
        assert sample_cert.client_id == "CLIENT-001"
        assert sample_cert.key_algorithm == "RSA"
        assert sample_cert.key_size == 2048
        assert sample_cert.auto_renew is True
        assert sample_cert.renewal_provider == "lets_encrypt"
        assert len(sample_cert.san_names) == 2
        assert len(sample_cert.installed_on) == 2
        assert sample_cert.status == CertStatus.ACTIVE
        assert sample_cert.fingerprint_sha256 != ""

    def test_add_certificate_auto_expired(self, svc, expired_cert):
        assert expired_cert.status == CertStatus.EXPIRED
        assert expired_cert.days_until_expiry == 0

    def test_add_certificate_auto_expiring_soon(self, svc, expiring_cert):
        assert expiring_cert.status == CertStatus.EXPIRING_SOON
        assert 0 < expiring_cert.days_until_expiry <= 30

    def test_get_certificate(self, svc, sample_cert):
        fetched = svc.get_certificate(sample_cert.cert_id)
        assert fetched is not None
        assert fetched.cert_id == sample_cert.cert_id

    def test_get_certificate_not_found(self, svc):
        assert svc.get_certificate("CERT-NONEXISTENT") is None

    def test_list_certificates(self, svc, sample_cert):
        certs = svc.list_certificates()
        assert len(certs) >= 1
        ids = [c.cert_id for c in certs]
        assert sample_cert.cert_id in ids

    def test_list_certificates_filter_client(self, svc, sample_cert, expired_cert):
        certs = svc.list_certificates(client_id="CLIENT-001")
        assert all(c.client_id == "CLIENT-001" for c in certs)

    def test_list_certificates_filter_status(self, svc, sample_cert, expired_cert):
        certs = svc.list_certificates(status="expired")
        assert all(c.status == CertStatus.EXPIRED for c in certs)

    def test_list_certificates_filter_type(self, svc, sample_cert):
        certs = svc.list_certificates(cert_type="dv")
        assert all(c.cert_type == CertType.DV for c in certs)

    def test_list_certificates_pagination(self, svc):
        for i in range(5):
            svc.add_certificate(common_name=f"host{i}.example.com")
        page = svc.list_certificates(limit=2, offset=0)
        assert len(page) == 2
        page2 = svc.list_certificates(limit=2, offset=2)
        assert len(page2) == 2

    def test_update_certificate(self, svc, sample_cert):
        updated = svc.update_certificate(sample_cert.cert_id, {"issuer": "DigiCert"})
        assert updated is not None
        assert updated.issuer == "DigiCert"

    def test_update_certificate_recalculates_status(self, svc, sample_cert):
        # Move expiry to 3 days from now
        new_expiry = datetime.now(timezone.utc) + timedelta(days=3)
        updated = svc.update_certificate(sample_cert.cert_id, {"valid_to": new_expiry})
        assert updated.status == CertStatus.EXPIRING_SOON
        assert updated.days_until_expiry <= 3

    def test_update_certificate_not_found(self, svc):
        assert svc.update_certificate("CERT-NOPE", {"issuer": "X"}) is None

    def test_delete_certificate(self, svc, sample_cert):
        assert svc.delete_certificate(sample_cert.cert_id) is True
        assert svc.get_certificate(sample_cert.cert_id) is None

    def test_delete_certificate_not_found(self, svc):
        assert svc.delete_certificate("CERT-NOPE") is False

    def test_add_certificate_default_serial(self, svc):
        cert = svc.add_certificate(common_name="auto-serial.test")
        assert cert.serial_number != ""

    def test_add_certificate_various_types(self, svc):
        for ct in ["dv", "ov", "ev", "self_signed", "wildcard"]:
            cert = svc.add_certificate(common_name=f"{ct}.test", cert_type=ct)
            assert cert.cert_type == CertType(ct)


# ============================================================
# Scanning
# ============================================================

class TestScanning:
    def test_scan_host(self, svc):
        scan = svc.scan_host("example.com", 443)
        assert scan.scan_id.startswith("SCAN-")
        assert scan.target_host == "example.com"
        assert scan.port == 443
        assert scan.cert_found is True
        assert scan.cert_id is not None
        assert scan.grade in ["A+", "A", "B", "C", "D", "F"]
        assert scan.protocol_version != ""
        assert scan.cipher_suite != ""

    def test_scan_host_creates_certificate(self, svc):
        scan = svc.scan_host("scan-test.com")
        cert = svc.get_certificate(scan.cert_id)
        assert cert is not None
        assert cert.common_name == "scan-test.com"

    def test_scan_network(self, svc):
        hosts = ["host1.example.com", "host2.example.com", "host3.example.com"]
        scans = svc.scan_network("CLIENT-SCAN", hosts)
        assert len(scans) == 3
        for s in scans:
            cert = svc.get_certificate(s.cert_id)
            assert cert.client_id == "CLIENT-SCAN"

    def test_scan_stores_in_memory(self, svc):
        scan = svc.scan_host("stored.test")
        assert scan.scan_id in svc._scans

    def test_get_scans(self, svc):
        svc.scan_host("a.test")
        svc.scan_host("b.test")
        scans = svc.get_scans()
        assert len(scans) >= 2

    def test_get_scans_filter_host(self, svc):
        svc.scan_host("target.test")
        svc.scan_host("other.test")
        scans = svc.get_scans(host="target.test")
        assert all(s.target_host == "target.test" for s in scans)


class TestGrading:
    def test_grade_perfect(self, svc):
        grade = svc._grade_ssl_config("TLSv1.3", "TLS_AES_256_GCM_SHA384", 4096, True)
        assert grade in ["A+", "A"]

    def test_grade_good(self, svc):
        grade = svc._grade_ssl_config("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", 2048, True)
        assert grade in ["A+", "A"]

    def test_grade_outdated_protocol(self, svc):
        grade = svc._grade_ssl_config("TLSv1.0", "ECDHE-RSA-AES256-GCM-SHA384", 2048, True)
        assert grade in ["C", "D", "F"]

    def test_grade_weak_cipher(self, svc):
        grade = svc._grade_ssl_config("TLSv1.2", "RC4-SHA", 2048, True)
        assert grade in ["C", "D", "F"]

    def test_grade_broken_chain(self, svc):
        grade = svc._grade_ssl_config("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", 2048, False)
        assert grade in ["B", "C", "D"]

    def test_grade_small_key(self, svc):
        grade = svc._grade_ssl_config("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", 512, True)
        assert grade in ["B", "C", "D", "F"]


# ============================================================
# Expiration Tracking
# ============================================================

class TestExpirationTracking:
    def test_check_expirations_creates_alerts(self, svc, expiring_cert, expired_cert):
        alerts = svc.check_expirations()
        assert len(alerts) >= 2
        types = [a.alert_type for a in alerts]
        assert AlertType.EXPIRED in types

    def test_check_expirations_updates_status(self, svc, expired_cert):
        svc.check_expirations()
        cert = svc.get_certificate(expired_cert.cert_id)
        assert cert.status == CertStatus.EXPIRED

    def test_get_expiring_certificates(self, svc, expiring_cert, sample_cert):
        expiring = svc.get_expiring_certificates(days_ahead=10)
        ids = [c.cert_id for c in expiring]
        assert expiring_cert.cert_id in ids

    def test_get_expiring_certificates_wider_window(self, svc, expiring_cert):
        certs_30 = svc.get_expiring_certificates(days_ahead=30)
        certs_1 = svc.get_expiring_certificates(days_ahead=1)
        assert len(certs_30) >= len(certs_1)


# ============================================================
# Renewal
# ============================================================

class TestRenewal:
    def test_request_renewal(self, svc, sample_cert):
        renewal = svc.request_renewal(sample_cert.cert_id, requested_by="admin")
        assert renewal is not None
        assert renewal.renewal_id.startswith("REN-")
        assert renewal.cert_id == sample_cert.cert_id
        assert renewal.requested_by == "admin"

    def test_request_renewal_sets_pending(self, svc):
        # Use a cert with manual renewal so ACME does not auto-complete
        cert = svc.add_certificate(
            common_name="manual-renew.test",
            auto_renew=False,
            renewal_provider="manual",
            valid_to=datetime.now(timezone.utc) + timedelta(days=100),
        )
        svc.request_renewal(cert.cert_id)
        updated = svc.get_certificate(cert.cert_id)
        assert updated.status == CertStatus.PENDING_RENEWAL

    def test_request_renewal_not_found(self, svc):
        assert svc.request_renewal("CERT-NOPE") is None

    def test_complete_renewal(self, svc, sample_cert):
        renewal = svc.request_renewal(sample_cert.cert_id)
        # Disable auto-renew to test manual completion
        sample_cert.auto_renew = False
        completed = svc.complete_renewal(renewal.renewal_id, {
            "common_name": "example.com",
            "client_id": "CLIENT-001",
            "issuer": "DigiCert",
            "valid_from": datetime.now(timezone.utc),
            "valid_to": datetime.now(timezone.utc) + timedelta(days=365),
            "cert_type": "ov",
        })
        assert completed is not None
        assert completed.status == RenewalStatus.COMPLETED
        assert completed.new_cert_id is not None
        assert completed.completed_at is not None

    def test_complete_renewal_not_found(self, svc):
        assert svc.complete_renewal("REN-NOPE", {"common_name": "x"}) is None

    def test_get_renewals(self, svc, sample_cert, expiring_cert):
        svc.request_renewal(sample_cert.cert_id)
        svc.request_renewal(expiring_cert.cert_id)
        renewals = svc.get_renewals()
        assert len(renewals) >= 2

    def test_get_renewals_filter_cert(self, svc, sample_cert, expiring_cert):
        svc.request_renewal(sample_cert.cert_id)
        svc.request_renewal(expiring_cert.cert_id)
        renewals = svc.get_renewals(cert_id=sample_cert.cert_id)
        assert all(r.cert_id == sample_cert.cert_id for r in renewals)

    def test_acme_renewal_triggered(self, svc):
        """Auto-renew LE cert should trigger ACME simulation."""
        cert = svc.add_certificate(
            common_name="acme.test",
            auto_renew=True,
            renewal_provider="lets_encrypt",
            valid_to=datetime.now(timezone.utc) + timedelta(days=10),
        )
        renewal = svc.request_renewal(cert.cert_id)
        # ACME should have run; status is completed or failed
        assert renewal.status in (RenewalStatus.COMPLETED, RenewalStatus.FAILED)


# ============================================================
# Alerts
# ============================================================

class TestAlerts:
    def test_get_alerts_empty(self, svc):
        alerts = svc.get_alerts()
        assert isinstance(alerts, list)

    def test_alerts_created_by_expiration_check(self, svc, expired_cert):
        svc.check_expirations()
        alerts = svc.get_alerts(cert_id=expired_cert.cert_id)
        assert len(alerts) >= 1

    def test_acknowledge_alert(self, svc, expired_cert):
        svc.check_expirations()
        alerts = svc.get_alerts(cert_id=expired_cert.cert_id)
        assert len(alerts) >= 1
        ack = svc.acknowledge_alert(alerts[0].alert_id)
        assert ack is not None
        assert ack.is_acknowledged is True

    def test_acknowledge_alert_not_found(self, svc):
        assert svc.acknowledge_alert("CALRT-NOPE") is None

    def test_get_alerts_filter_acknowledged(self, svc, expired_cert):
        svc.check_expirations()
        alerts = svc.get_alerts(cert_id=expired_cert.cert_id)
        svc.acknowledge_alert(alerts[0].alert_id)
        unacked = svc.get_alerts(acknowledged=False)
        acked = svc.get_alerts(acknowledged=True)
        for a in unacked:
            assert a.is_acknowledged is False
        for a in acked:
            assert a.is_acknowledged is True

    def test_get_alerts_filter_type(self, svc, expired_cert):
        svc.check_expirations()
        alerts = svc.get_alerts(alert_type="expired")
        assert all(a.alert_type == AlertType.EXPIRED for a in alerts)


# ============================================================
# Analytics
# ============================================================

class TestAnalytics:
    def test_expiration_timeline(self, svc, sample_cert, expiring_cert):
        timeline = svc.get_expiration_timeline(months=6)
        assert isinstance(timeline, dict)
        assert len(timeline) == 6

    def test_cert_inventory(self, svc, sample_cert, expired_cert):
        inv = svc.get_cert_inventory()
        assert inv["total"] >= 2
        assert "by_type" in inv
        assert "by_issuer" in inv
        assert "by_algorithm" in inv
        assert "by_status" in inv

    def test_cert_inventory_filter_client(self, svc, sample_cert, expired_cert):
        inv = svc.get_cert_inventory(client_id="CLIENT-001")
        assert inv["total"] >= 1

    def test_weak_certificates(self, svc):
        svc.add_certificate(
            common_name="weak.test",
            key_algorithm="RSA",
            key_size=1024,
            installed_on=["prod:443"],
        )
        svc.add_certificate(
            common_name="selfsigned.test",
            cert_type="self_signed",
            installed_on=["prod:443"],
        )
        weak = svc.get_weak_certificates()
        assert len(weak) >= 2
        issues_flat = []
        for w in weak:
            issues_flat.extend(w["issues"])
        assert any("Weak RSA" in i for i in issues_flat)
        assert any("Self-signed" in i for i in issues_flat)

    def test_compliance_status(self, svc, sample_cert, expired_cert):
        comp = svc.get_compliance_status()
        assert "pci_dss" in comp
        assert "hipaa" in comp
        assert "overall_compliant" in comp
        assert comp["total_certificates"] >= 2
        # Expired cert causes violations
        assert comp["pci_dss"]["violations"] >= 1
        assert comp["hipaa"]["violations"] >= 1

    def test_compliance_clean(self, svc):
        svc.add_certificate(
            common_name="clean.test",
            key_algorithm="RSA",
            key_size=4096,
            cert_type="ov",
            valid_to=datetime.now(timezone.utc) + timedelta(days=365),
        )
        comp = svc.get_compliance_status()
        assert comp["overall_compliant"] is True

    def test_dashboard(self, svc, sample_cert, expiring_cert, expired_cert):
        dash = svc.get_dashboard()
        assert dash["total_certificates"] >= 3
        assert "active" in dash
        assert "expiring_soon" in dash
        assert "expired" in dash
        assert "pending_renewal" in dash
        assert "unacknowledged_alerts" in dash
        assert "scan_grade_distribution" in dash
        assert "expiring_next_7_days" in dash
        assert "last_check" in dash

    def test_dashboard_expiring_7_days(self, svc, expiring_cert):
        dash = svc.get_dashboard()
        ids = [e["cert_id"] for e in dash["expiring_next_7_days"]]
        assert expiring_cert.cert_id in ids


# ============================================================
# Edge Cases
# ============================================================

class TestEdgeCases:
    def test_add_cert_no_valid_to(self, svc):
        cert = svc.add_certificate(common_name="no-expiry.test")
        assert cert.valid_to is None
        assert cert.status == CertStatus.ACTIVE

    def test_update_immutable_fields(self, svc, sample_cert):
        updated = svc.update_certificate(sample_cert.cert_id, {"cert_id": "HACK"})
        assert updated.cert_id == sample_cert.cert_id  # unchanged

    def test_delete_then_get(self, svc, sample_cert):
        svc.delete_certificate(sample_cert.cert_id)
        assert svc.get_certificate(sample_cert.cert_id) is None

    def test_multiple_scans_same_host(self, svc):
        s1 = svc.scan_host("repeat.test")
        s2 = svc.scan_host("repeat.test")
        assert s1.scan_id != s2.scan_id

    def test_renewal_for_expired_cert(self, svc, expired_cert):
        renewal = svc.request_renewal(expired_cert.cert_id)
        assert renewal is not None

    def test_large_san_list(self, svc):
        sans = [f"sub{i}.example.com" for i in range(50)]
        cert = svc.add_certificate(common_name="many-sans.test", san_names=sans)
        assert len(cert.san_names) == 50

    def test_invalid_cert_type_falls_back(self, svc):
        cert = svc.add_certificate(common_name="bad-type.test", cert_type="invalid")
        assert cert.cert_type == CertType.DV  # fallback
