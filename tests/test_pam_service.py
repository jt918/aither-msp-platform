"""
Tests for PAM (Privileged Access Management) Service
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.pam_service import (
    PAMService,
    CredentialType,
    SessionStatus,
    RequestStatus,
    CredentialVault,
    VaultedCredential,
    AccessSession,
    AccessRequest,
    RotationPolicy,
    _generate_password,
    _encrypt_password,
)


class TestPasswordUtilities:
    """Tests for password generation and encryption utilities"""

    def test_generate_password_default(self):
        password = _generate_password()
        assert len(password) == 24
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)

    def test_generate_password_custom_length(self):
        password = _generate_password(length=32)
        assert len(password) == 32

    def test_generate_password_no_special(self):
        password = _generate_password(length=16, special=False)
        assert len(password) == 16

    def test_generate_password_uniqueness(self):
        passwords = {_generate_password() for _ in range(10)}
        assert len(passwords) == 10  # All unique

    def test_encrypt_password(self):
        encrypted = _encrypt_password("test_password")
        assert encrypted.startswith("enc:v1:")
        parts = encrypted.split(":")
        assert len(parts) == 4


class TestPAMService:
    """Tests for PAMService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = PAMService()

    # ========== Vault Management Tests ==========

    def test_create_vault(self):
        vault = self.service.create_vault(
            client_id="CL-001",
            name="Acme Corp Vault",
            description="Main credential vault",
        )
        assert vault is not None
        assert vault.vault_id.startswith("VLT-")
        assert vault.client_id == "CL-001"
        assert vault.name == "Acme Corp Vault"
        assert vault.credential_count == 0

    def test_create_vault_with_policy(self):
        vault = self.service.create_vault(
            client_id="CL-002",
            name="Secure Vault",
            access_policy={"require_approval": True, "max_checkout_minutes": 30},
        )
        assert vault.access_policy["require_approval"] is True

    def test_list_vaults(self):
        self.service.create_vault(client_id="CL-001", name="Vault A")
        self.service.create_vault(client_id="CL-002", name="Vault B")
        self.service.create_vault(client_id="CL-001", name="Vault C")

        all_vaults = self.service.list_vaults()
        assert len(all_vaults) == 3

        client_vaults = self.service.list_vaults(client_id="CL-001")
        assert len(client_vaults) == 2

    def test_get_vault(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        retrieved = self.service.get_vault(vault.vault_id)
        assert retrieved is not None
        assert retrieved.vault_id == vault.vault_id

    def test_get_vault_not_found(self):
        result = self.service.get_vault("VLT-NONEXISTENT")
        assert result is None

    # ========== Credential Management Tests ==========

    def test_add_credential(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id,
            name="Domain Admin",
            credential_type="admin_account",
            username="admin@acme.com",
            password="SecureP@ss123",
            hostname="dc01.acme.local",
            port=3389,
            notes="Primary domain admin",
        )
        assert cred is not None
        assert cred.cred_id.startswith("CRD-")
        assert cred.name == "Domain Admin"
        assert cred.credential_type == CredentialType.ADMIN_ACCOUNT
        assert cred.username == "admin@acme.com"
        assert cred.hostname == "dc01.acme.local"
        assert cred.port == 3389
        assert cred.encrypted_password.startswith("enc:v1:")
        assert cred.is_checked_out is False

    def test_add_credential_auto_generate_password(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id,
            name="Service Account",
            credential_type="service_account",
            username="svc_backup",
        )
        assert cred is not None
        assert cred.encrypted_password.startswith("enc:v1:")

    def test_add_credential_invalid_vault(self):
        cred = self.service.add_credential(
            vault_id="VLT-NONEXISTENT",
            name="Test",
            credential_type="admin_account",
        )
        assert cred is None

    def test_add_credential_increments_vault_count(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        self.service.add_credential(vault_id=vault.vault_id, name="Cred 1", credential_type="admin_account")
        self.service.add_credential(vault_id=vault.vault_id, name="Cred 2", credential_type="ssh_key")
        updated = self.service.get_vault(vault.vault_id)
        assert updated.credential_count == 2

    def test_get_credential(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Test Cred", credential_type="api_key",
        )
        retrieved = self.service.get_credential(cred.cred_id)
        assert retrieved is not None
        assert retrieved.cred_id == cred.cred_id

    def test_list_credentials(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        self.service.add_credential(vault_id=vault.vault_id, name="Admin", credential_type="admin_account")
        self.service.add_credential(vault_id=vault.vault_id, name="SSH", credential_type="ssh_key")
        self.service.add_credential(vault_id=vault.vault_id, name="API", credential_type="api_key")

        all_creds = self.service.list_credentials(vault_id=vault.vault_id)
        assert len(all_creds) == 3

        ssh_creds = self.service.list_credentials(credential_type="ssh_key")
        assert len(ssh_creds) == 1

    def test_update_credential(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Old Name", credential_type="admin_account",
        )
        updated = self.service.update_credential(
            cred.cred_id, name="New Name", hostname="new-host.local",
        )
        assert updated is not None
        assert updated.name == "New Name"
        assert updated.hostname == "new-host.local"

    def test_update_credential_not_found(self):
        result = self.service.update_credential("CRD-NONEXISTENT", name="Test")
        assert result is None

    def test_all_credential_types(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        for ct in CredentialType:
            cred = self.service.add_credential(
                vault_id=vault.vault_id, name=f"Cred {ct.value}", credential_type=ct.value,
            )
            assert cred.credential_type == ct

    # ========== Checkout / Checkin Tests ==========

    def test_checkout_credential(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            username="admin", password="P@ssw0rd!",
        )
        result = self.service.checkout_credential(
            cred_id=cred.cred_id, user_id="tech-001", purpose="Server maintenance",
        )
        assert result is not None
        assert "error" not in result
        assert result["username"] == "admin"
        assert result["password"] == "P@ssw0rd!"
        assert result["session_id"] is not None

        # Verify credential is now checked out
        updated = self.service.get_credential(cred.cred_id)
        assert updated.is_checked_out is True
        assert updated.checked_out_by == "tech-001"

    def test_checkout_already_checked_out(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            password="P@ssw0rd!",
        )
        self.service.checkout_credential(cred_id=cred.cred_id, user_id="tech-001")
        result = self.service.checkout_credential(cred_id=cred.cred_id, user_id="tech-002")
        assert result is not None
        assert "error" in result

    def test_checkout_nonexistent(self):
        result = self.service.checkout_credential(
            cred_id="CRD-NONEXISTENT", user_id="tech-001",
        )
        assert result is None

    def test_checkin_credential(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            password="P@ssw0rd!",
        )
        self.service.checkout_credential(cred_id=cred.cred_id, user_id="tech-001")
        success = self.service.checkin_credential(cred.cred_id)
        assert success is True

        updated = self.service.get_credential(cred.cred_id)
        assert updated.is_checked_out is False

    def test_force_checkin(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            password="P@ssw0rd!",
        )
        self.service.checkout_credential(cred_id=cred.cred_id, user_id="tech-001")
        success = self.service.force_checkin(cred.cred_id, reason="Emergency")
        assert success is True

    def test_checkout_with_duration(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            password="P@ssw0rd!",
        )
        result = self.service.checkout_credential(
            cred_id=cred.cred_id, user_id="tech-001", duration_minutes=30,
        )
        assert result is not None
        assert result["expires_at"] is not None

    def test_checkout_increments_access_count(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            password="P@ssw0rd!",
        )
        self.service.checkout_credential(cred_id=cred.cred_id, user_id="tech-001")
        self.service.checkin_credential(cred.cred_id)
        self.service.checkout_credential(cred_id=cred.cred_id, user_id="tech-001")

        updated = self.service.get_credential(cred.cred_id)
        assert updated.access_count == 2

    # ========== Access Request Tests ==========

    def test_request_access(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Root", credential_type="root_account",
        )
        request = self.service.request_access(
            user_id="tech-001",
            cred_id=cred.cred_id,
            purpose="Emergency fix",
            urgency="critical",
            max_duration_minutes=30,
        )
        assert request is not None
        assert request.request_id.startswith("REQ-")
        assert request.status == RequestStatus.PENDING
        assert request.urgency == "critical"

    def test_request_access_invalid_cred(self):
        result = self.service.request_access(
            user_id="tech-001", cred_id="CRD-NONEXISTENT",
        )
        assert result is None

    def test_approve_request(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Root", credential_type="root_account",
        )
        request = self.service.request_access(user_id="tech-001", cred_id=cred.cred_id)
        approved = self.service.approve_request(request.request_id, approved_by="admin-001")
        assert approved is not None
        assert approved.status == RequestStatus.APPROVED
        assert approved.approved_by == "admin-001"
        assert approved.expires_at is not None

    def test_deny_request(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Root", credential_type="root_account",
        )
        request = self.service.request_access(user_id="tech-001", cred_id=cred.cred_id)
        denied = self.service.deny_request(request.request_id, denied_by="admin-001", reason="Not needed")
        assert denied is not None
        assert denied.status == RequestStatus.DENIED

    def test_approve_already_approved(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Root", credential_type="root_account",
        )
        request = self.service.request_access(user_id="tech-001", cred_id=cred.cred_id)
        self.service.approve_request(request.request_id, approved_by="admin-001")
        result = self.service.approve_request(request.request_id, approved_by="admin-002")
        assert result is None

    def test_get_pending_requests(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred1 = self.service.add_credential(
            vault_id=vault.vault_id, name="Cred 1", credential_type="admin_account",
        )
        cred2 = self.service.add_credential(
            vault_id=vault.vault_id, name="Cred 2", credential_type="ssh_key",
        )
        self.service.request_access(user_id="tech-001", cred_id=cred1.cred_id)
        req2 = self.service.request_access(user_id="tech-002", cred_id=cred2.cred_id)
        self.service.approve_request(req2.request_id, approved_by="admin-001")

        pending = self.service.get_pending_requests()
        assert len(pending) == 1

        pending_for_cred1 = self.service.get_pending_requests(cred_id=cred1.cred_id)
        assert len(pending_for_cred1) == 1

    # ========== Session Management Tests ==========

    def test_start_session(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )
        session = self.service.start_session(
            cred_id=cred.cred_id,
            user_id="tech-001",
            purpose="Maintenance",
            ip_address="10.0.0.50",
        )
        assert session is not None
        assert session.session_id.startswith("SES-")
        assert session.status == SessionStatus.ACTIVE
        assert session.ip_address == "10.0.0.50"

    def test_end_session(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )
        session = self.service.start_session(cred_id=cred.cred_id, user_id="tech-001")
        ended = self.service.end_session(session.session_id)
        assert ended is not None
        assert ended.status == SessionStatus.COMPLETED
        assert ended.ended_at is not None

    def test_terminate_session(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )
        session = self.service.start_session(cred_id=cred.cred_id, user_id="tech-001")
        terminated = self.service.terminate_session(session.session_id, reason="Suspicious")
        assert terminated is not None
        assert terminated.status == SessionStatus.TERMINATED

    def test_end_session_not_found(self):
        result = self.service.end_session("SES-NONEXISTENT")
        assert result is None

    def test_log_command(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )
        session = self.service.start_session(cred_id=cred.cred_id, user_id="tech-001")

        success = self.service.log_command(
            session_id=session.session_id,
            command="whoami",
            output="admin",
            exit_code=0,
        )
        assert success is True

        success2 = self.service.log_command(
            session_id=session.session_id,
            command="ipconfig /all",
            output="Windows IP Configuration...",
            exit_code=0,
        )
        assert success2 is True

    def test_log_command_inactive_session(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )
        session = self.service.start_session(cred_id=cred.cred_id, user_id="tech-001")
        self.service.end_session(session.session_id)
        result = self.service.log_command(session.session_id, "whoami")
        assert result is False

    def test_get_session_recording(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )
        session = self.service.start_session(cred_id=cred.cred_id, user_id="tech-001")
        self.service.log_command(session.session_id, "whoami", "admin", 0)
        self.service.log_command(session.session_id, "hostname", "SRV-01", 0)

        recording = self.service.get_session_recording(session.session_id)
        assert recording is not None
        assert recording["command_count"] == 2
        assert len(recording["commands"]) == 2
        assert recording["commands"][0]["command"] == "whoami"

    def test_get_session_recording_not_found(self):
        result = self.service.get_session_recording("SES-NONEXISTENT")
        assert result is None

    # ========== Credential Rotation Tests ==========

    def test_rotate_credential(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            password="OldPassword",
        )
        result = self.service.rotate_credential(cred.cred_id)
        assert result is not None
        assert "error" not in result
        assert result["cred_id"] == cred.cred_id
        assert "rotated_at" in result
        assert "next_rotation" in result

    def test_rotate_credential_with_password(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )
        result = self.service.rotate_credential(cred.cred_id, new_password="NewP@ss123!")
        assert result is not None
        assert "error" not in result

    def test_rotate_checked_out_credential(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            password="P@ss",
        )
        self.service.checkout_credential(cred.cred_id, user_id="tech-001")
        result = self.service.rotate_credential(cred.cred_id)
        assert result is not None
        assert "error" in result

    def test_rotate_nonexistent(self):
        result = self.service.rotate_credential("CRD-NONEXISTENT")
        assert result is None

    def test_rotate_all_expired(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Old Cred", credential_type="admin_account",
            rotation_interval_days=1,
        )
        # Backdate the last_rotated
        cred_obj = self.service._credentials[cred.cred_id]
        cred_obj.last_rotated = datetime.now(timezone.utc) - timedelta(days=5)

        results = self.service.rotate_all_expired()
        assert len(results) >= 1

    # ========== Rotation Policy Tests ==========

    def test_create_rotation_policy(self):
        policy = self.service.create_rotation_policy(
            name="Admin Rotation",
            credential_types=["admin_account", "root_account"],
            rotation_interval_days=30,
            complexity_requirements={"length": 32, "special": True},
            notify_on_rotation=True,
        )
        assert policy is not None
        assert policy.policy_id.startswith("POL-")
        assert policy.rotation_interval_days == 30
        assert len(policy.credential_types) == 2

    def test_get_policies(self):
        self.service.create_rotation_policy(name="Policy A", rotation_interval_days=30)
        self.service.create_rotation_policy(name="Policy B", rotation_interval_days=90)
        policies = self.service.get_policies()
        assert len(policies) == 2

    def test_check_rotation_compliance(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        self.service.add_credential(
            vault_id=vault.vault_id, name="Compliant", credential_type="admin_account",
            rotation_interval_days=90,
        )
        cred2 = self.service.add_credential(
            vault_id=vault.vault_id, name="Overdue", credential_type="ssh_key",
            rotation_interval_days=1,
        )
        # Backdate
        cred2_obj = self.service._credentials[cred2.cred_id]
        cred2_obj.last_rotated = datetime.now(timezone.utc) - timedelta(days=10)

        compliance = self.service.check_rotation_compliance()
        assert compliance["total_credentials"] == 2
        assert compliance["non_compliant"] >= 1
        assert compliance["compliance_rate"] < 100.0

    def test_compliance_empty(self):
        compliance = self.service.check_rotation_compliance()
        assert compliance["total_credentials"] == 0
        assert compliance["compliance_rate"] == 100.0

    # ========== Audit Trail Tests ==========

    def test_get_access_audit_trail(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )
        self.service.start_session(cred_id=cred.cred_id, user_id="tech-001", purpose="Task 1")
        self.service.start_session(cred_id=cred.cred_id, user_id="tech-002", purpose="Task 2")

        trail = self.service.get_access_audit_trail()
        assert len(trail) == 2

        user_trail = self.service.get_access_audit_trail(user_id="tech-001")
        assert len(user_trail) == 1

    def test_get_high_risk_sessions(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
        )

        # Create a terminated session (high risk)
        session = self.service.start_session(cred_id=cred.cred_id, user_id="tech-001")
        self.service.terminate_session(session.session_id, reason="Suspicious")

        high_risk = self.service.get_high_risk_sessions()
        assert len(high_risk) >= 1
        assert high_risk[0]["risk_score"] >= 25

    # ========== Dashboard Tests ==========

    def test_get_dashboard(self):
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            password="P@ss",
        )
        self.service.add_credential(
            vault_id=vault.vault_id, name="SSH", credential_type="ssh_key",
        )

        dashboard = self.service.get_dashboard()
        assert dashboard["total_vaults"] == 1
        assert dashboard["total_credentials"] == 2
        assert "credential_types" in dashboard
        assert "compliance_rate" in dashboard
        assert "active_sessions" in dashboard

    def test_dashboard_empty(self):
        dashboard = self.service.get_dashboard()
        assert dashboard["total_vaults"] == 0
        assert dashboard["total_credentials"] == 0
        assert dashboard["active_sessions"] == 0

    # ========== Integration / Workflow Tests ==========

    def test_full_checkout_workflow(self):
        """Test complete checkout -> use -> checkin workflow"""
        # Setup
        vault = self.service.create_vault(client_id="CL-001", name="Production Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id,
            name="Prod DB Admin",
            credential_type="database",
            username="dbadmin",
            password="DbP@ss!2024",
            hostname="db-prod-01.local",
            port=5432,
        )

        # Request access
        request = self.service.request_access(
            user_id="tech-001", cred_id=cred.cred_id,
            purpose="Database maintenance", urgency="normal",
        )
        assert request.status == RequestStatus.PENDING

        # Approve
        approved = self.service.approve_request(request.request_id, approved_by="admin-001")
        assert approved.status == RequestStatus.APPROVED

        # Checkout
        checkout = self.service.checkout_credential(
            cred_id=cred.cred_id, user_id="tech-001",
            purpose="Database maintenance", ip_address="10.0.0.50",
        )
        assert checkout["password"] == "DbP@ss!2024"
        session_id = checkout["session_id"]

        # Log commands
        self.service.log_command(session_id, "SELECT version();", "PostgreSQL 15.2", 0)
        self.service.log_command(session_id, "VACUUM ANALYZE;", "VACUUM", 0)

        # Get recording
        recording = self.service.get_session_recording(session_id)
        assert recording["command_count"] == 2

        # Checkin
        self.service.checkin_credential(cred.cred_id)

        # Verify audit trail
        trail = self.service.get_access_audit_trail(cred_id=cred.cred_id)
        assert len(trail) >= 1

    def test_full_rotation_workflow(self):
        """Test complete rotation policy workflow"""
        # Create policy
        policy = self.service.create_rotation_policy(
            name="Monthly Admin Rotation",
            credential_types=["admin_account"],
            rotation_interval_days=30,
            complexity_requirements={"length": 32, "special": True},
        )
        assert policy is not None

        # Create vault and credential
        vault = self.service.create_vault(client_id="CL-001", name="Test Vault")
        cred = self.service.add_credential(
            vault_id=vault.vault_id, name="Admin", credential_type="admin_account",
            rotation_interval_days=1,
        )

        # Backdate rotation
        cred_obj = self.service._credentials[cred.cred_id]
        cred_obj.last_rotated = datetime.now(timezone.utc) - timedelta(days=5)

        # Check compliance
        compliance = self.service.check_rotation_compliance()
        assert compliance["non_compliant"] >= 1

        # Rotate expired
        rotated = self.service.rotate_all_expired()
        assert len(rotated) >= 1

        # Verify compliance improved
        compliance2 = self.service.check_rotation_compliance()
        assert compliance2["non_compliant"] < compliance["non_compliant"]


class TestEnums:
    """Tests for PAM enums"""

    def test_credential_type_values(self):
        assert CredentialType.ADMIN_ACCOUNT.value == "admin_account"
        assert CredentialType.SERVICE_ACCOUNT.value == "service_account"
        assert CredentialType.API_KEY.value == "api_key"
        assert CredentialType.SSH_KEY.value == "ssh_key"
        assert CredentialType.DATABASE.value == "database"
        assert CredentialType.NETWORK_DEVICE.value == "network_device"
        assert CredentialType.CLOUD_IAM.value == "cloud_iam"
        assert CredentialType.ROOT_ACCOUNT.value == "root_account"

    def test_session_status_values(self):
        assert SessionStatus.ACTIVE.value == "active"
        assert SessionStatus.COMPLETED.value == "completed"
        assert SessionStatus.TERMINATED.value == "terminated"
        assert SessionStatus.EXPIRED.value == "expired"

    def test_request_status_values(self):
        assert RequestStatus.PENDING.value == "pending"
        assert RequestStatus.APPROVED.value == "approved"
        assert RequestStatus.DENIED.value == "denied"
        assert RequestStatus.EXPIRED.value == "expired"


class TestDataclasses:
    """Tests for PAM dataclasses"""

    def test_credential_vault_defaults(self):
        vault = CredentialVault(vault_id="VLT-TEST", client_id="CL-001", name="Test")
        assert vault.credentials == []
        assert vault.access_policy == {}
        assert vault.credential_count == 0

    def test_vaulted_credential_defaults(self):
        cred = VaultedCredential(cred_id="CRD-TEST", vault_id="VLT-TEST", name="Test")
        assert cred.credential_type == CredentialType.ADMIN_ACCOUNT
        assert cred.is_checked_out is False
        assert cred.access_count == 0
        assert cred.rotation_interval_days == 90

    def test_access_session_defaults(self):
        session = AccessSession(session_id="SES-TEST", cred_id="CRD-TEST", user_id="user-001")
        assert session.status == SessionStatus.ACTIVE
        assert session.commands_logged == []
        assert session.duration_seconds == 0

    def test_access_request_defaults(self):
        req = AccessRequest(request_id="REQ-TEST", user_id="user-001", cred_id="CRD-TEST")
        assert req.status == RequestStatus.PENDING
        assert req.urgency == "normal"
        assert req.max_duration_minutes == 60

    def test_rotation_policy_defaults(self):
        policy = RotationPolicy(policy_id="POL-TEST", name="Test")
        assert policy.rotation_interval_days == 90
        assert policy.notify_on_rotation is True
        assert policy.enabled is True
