"""
Tests for White-Label Branding Service
"""

import pytest
from datetime import datetime, timezone

from services.msp.white_label import (
    WhiteLabelService,
    BrandConfig,
    EmailTemplate,
    BrandAsset,
)


class TestWhiteLabelService:
    """Tests for WhiteLabelService class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = WhiteLabelService()

    # ========== Brand CRUD Tests ==========

    def test_create_brand_basic(self):
        """Test basic brand creation."""
        brand = self.service.create_brand(
            tenant_id="TEN-001",
            company_name="Acme IT Solutions",
        )
        assert brand is not None
        assert brand.brand_id.startswith("WL-")
        assert brand.tenant_id == "TEN-001"
        assert brand.company_name == "Acme IT Solutions"
        assert brand.is_active is True
        assert brand.primary_color == "#1a73e8"

    def test_create_brand_full(self):
        """Test brand creation with all options."""
        brand = self.service.create_brand(
            tenant_id="TEN-002",
            company_name="CloudOps Pro",
            logo_url="https://cdn.cloudops.pro/logo.png",
            favicon_url="https://cdn.cloudops.pro/favicon.ico",
            primary_color="#0066cc",
            secondary_color="#f8f9fa",
            accent_color="#28a745",
            font_family="Roboto, sans-serif",
            custom_css=".header { border-bottom: 2px solid #0066cc; }",
            login_background_url="https://cdn.cloudops.pro/bg.jpg",
            email_header_url="https://cdn.cloudops.pro/email-header.png",
            email_footer_html="<p>CloudOps Pro Inc. | 123 Tech St</p>",
            support_email="help@cloudops.pro",
            support_phone="1-800-CLOUD",
            support_url="https://support.cloudops.pro",
            terms_url="https://cloudops.pro/terms",
            privacy_url="https://cloudops.pro/privacy",
            custom_domain="app.cloudops.pro",
        )
        assert brand.primary_color == "#0066cc"
        assert brand.font_family == "Roboto, sans-serif"
        assert brand.support_email == "help@cloudops.pro"
        assert brand.custom_domain == "app.cloudops.pro"
        assert brand.domain_verified is False

    def test_get_brand(self):
        """Test getting a brand by ID."""
        brand = self.service.create_brand(tenant_id="TEN-003", company_name="GetTest Inc")
        fetched = self.service.get_brand(brand.brand_id)
        assert fetched is not None
        assert fetched.brand_id == brand.brand_id
        assert fetched.company_name == "GetTest Inc"

    def test_get_brand_not_found(self):
        """Test getting a non-existent brand."""
        result = self.service.get_brand("WL-NONEXIST")
        assert result is None

    def test_get_brand_by_tenant(self):
        """Test getting a brand by tenant ID."""
        self.service.create_brand(tenant_id="TEN-004", company_name="TenantLookup LLC")
        fetched = self.service.get_brand_by_tenant("TEN-004")
        assert fetched is not None
        assert fetched.company_name == "TenantLookup LLC"

    def test_get_brand_by_tenant_not_found(self):
        """Test getting brand for non-existent tenant."""
        result = self.service.get_brand_by_tenant("TEN-FAKE")
        assert result is None

    def test_get_brand_by_domain(self):
        """Test getting a brand by custom domain."""
        brand = self.service.create_brand(
            tenant_id="TEN-005",
            company_name="Domain Corp",
            custom_domain="portal.domaincorp.com",
        )
        # Not verified yet, should not find
        result = self.service.get_brand_by_domain("portal.domaincorp.com")
        assert result is None

        # Manually verify
        brand.domain_verified = True
        result = self.service.get_brand_by_domain("portal.domaincorp.com")
        assert result is not None
        assert result.company_name == "Domain Corp"

    def test_update_brand(self):
        """Test updating brand fields."""
        brand = self.service.create_brand(tenant_id="TEN-006", company_name="Old Name")
        updated = self.service.update_brand(brand.brand_id, company_name="New Name", primary_color="#ff0000")
        assert updated is not None
        assert updated.company_name == "New Name"
        assert updated.primary_color == "#ff0000"

    def test_update_brand_resets_domain_verified(self):
        """Test that changing custom_domain resets domain_verified."""
        brand = self.service.create_brand(
            tenant_id="TEN-007",
            company_name="DomainReset",
            custom_domain="old.domain.com",
        )
        brand.domain_verified = True
        updated = self.service.update_brand(brand.brand_id, custom_domain="new.domain.com")
        assert updated.domain_verified is False

    def test_update_brand_not_found(self):
        """Test updating a non-existent brand."""
        result = self.service.update_brand("WL-NONEXIST", company_name="Nope")
        assert result is None

    def test_delete_brand(self):
        """Test deleting a brand."""
        brand = self.service.create_brand(tenant_id="TEN-008", company_name="DeleteMe")
        result = self.service.delete_brand(brand.brand_id)
        assert result is True
        assert self.service.get_brand(brand.brand_id) is None

    def test_delete_brand_cascades(self):
        """Test that deleting a brand also removes templates and assets."""
        brand = self.service.create_brand(tenant_id="TEN-009", company_name="CascadeDel")
        self.service.create_email_template(brand.brand_id, "welcome", "Hello $name")
        self.service.upload_asset(brand.brand_id, "logo", "/tmp/logo.png", "image/png")

        assert len(self.service.get_email_templates(brand.brand_id)) == 1
        assert len(self.service.get_assets(brand.brand_id)) == 1

        self.service.delete_brand(brand.brand_id)
        assert len(self.service.get_email_templates(brand.brand_id)) == 0
        assert len(self.service.get_assets(brand.brand_id)) == 0

    def test_delete_brand_not_found(self):
        """Test deleting a non-existent brand."""
        result = self.service.delete_brand("WL-NONEXIST")
        assert result is False

    def test_list_brands(self):
        """Test listing all brands."""
        self.service.create_brand(tenant_id="TEN-010", company_name="ListA")
        self.service.create_brand(tenant_id="TEN-011", company_name="ListB")
        brands = self.service.list_brands()
        assert len(brands) == 2

    def test_list_brands_active_only(self):
        """Test listing only active brands."""
        b1 = self.service.create_brand(tenant_id="TEN-012", company_name="Active")
        b2 = self.service.create_brand(tenant_id="TEN-013", company_name="Inactive")
        b2.is_active = False

        active = self.service.list_brands(active_only=True)
        assert len(active) == 1
        assert active[0].company_name == "Active"

    # ========== Asset Tests ==========

    def test_upload_asset(self):
        """Test uploading a brand asset."""
        brand = self.service.create_brand(tenant_id="TEN-020", company_name="AssetTest")
        asset = self.service.upload_asset(
            brand_id=brand.brand_id,
            asset_type="logo",
            file_path="/uploads/logo.png",
            mime_type="image/png",
        )
        assert asset is not None
        assert asset.asset_id.startswith("WLA-")
        assert asset.asset_type == "logo"
        assert asset.file_path == "/uploads/logo.png"
        assert asset.mime_type == "image/png"

    def test_upload_asset_brand_not_found(self):
        """Test uploading asset for non-existent brand."""
        result = self.service.upload_asset("WL-FAKE", "logo", "/tmp/x.png")
        assert result is None

    def test_get_assets(self):
        """Test listing assets for a brand."""
        brand = self.service.create_brand(tenant_id="TEN-021", company_name="MultiAsset")
        self.service.upload_asset(brand.brand_id, "logo", "/uploads/logo.png")
        self.service.upload_asset(brand.brand_id, "favicon", "/uploads/fav.ico")
        assets = self.service.get_assets(brand.brand_id)
        assert len(assets) == 2

    def test_delete_asset(self):
        """Test deleting an asset."""
        brand = self.service.create_brand(tenant_id="TEN-022", company_name="DelAsset")
        asset = self.service.upload_asset(brand.brand_id, "logo", "/uploads/logo.png")
        result = self.service.delete_asset(asset.asset_id)
        assert result is True
        assert len(self.service.get_assets(brand.brand_id)) == 0

    def test_delete_asset_not_found(self):
        """Test deleting a non-existent asset."""
        result = self.service.delete_asset("WLA-FAKE")
        assert result is False

    # ========== Email Template Tests ==========

    def test_create_email_template(self):
        """Test creating an email template."""
        brand = self.service.create_brand(tenant_id="TEN-030", company_name="EmailTest")
        tmpl = self.service.create_email_template(
            brand_id=brand.brand_id,
            template_name="welcome",
            subject_template="Welcome to $company_name!",
            body_html_template="<h1>Welcome, $name!</h1><p>Your account is ready.</p>",
            body_text_template="Welcome, $name! Your account is ready.",
        )
        assert tmpl is not None
        assert tmpl.template_id.startswith("WLT-")
        assert tmpl.template_name == "welcome"

    def test_create_email_template_brand_not_found(self):
        """Test creating template for non-existent brand."""
        result = self.service.create_email_template("WL-FAKE", "welcome")
        assert result is None

    def test_update_email_template(self):
        """Test updating an email template."""
        brand = self.service.create_brand(tenant_id="TEN-031", company_name="UpdateTmpl")
        tmpl = self.service.create_email_template(brand.brand_id, "alert", "Alert: $title")
        updated = self.service.update_email_template(
            tmpl.template_id,
            subject_template="URGENT: $title",
        )
        assert updated is not None
        assert updated.subject_template == "URGENT: $title"

    def test_update_email_template_not_found(self):
        """Test updating a non-existent template."""
        result = self.service.update_email_template("WLT-FAKE", subject_template="nope")
        assert result is None

    def test_get_email_template(self):
        """Test getting a single email template."""
        brand = self.service.create_brand(tenant_id="TEN-032", company_name="GetTmpl")
        tmpl = self.service.create_email_template(brand.brand_id, "report", "Monthly Report")
        fetched = self.service.get_email_template(tmpl.template_id)
        assert fetched is not None
        assert fetched.template_name == "report"

    def test_get_email_template_not_found(self):
        """Test getting a non-existent template."""
        result = self.service.get_email_template("WLT-FAKE")
        assert result is None

    def test_delete_email_template(self):
        """Test deleting an email template."""
        brand = self.service.create_brand(tenant_id="TEN-033", company_name="DelTmpl")
        tmpl = self.service.create_email_template(brand.brand_id, "ticket_update", "Ticket #$id")
        result = self.service.delete_email_template(tmpl.template_id)
        assert result is True
        assert self.service.get_email_template(tmpl.template_id) is None

    def test_delete_email_template_not_found(self):
        """Test deleting a non-existent template."""
        result = self.service.delete_email_template("WLT-FAKE")
        assert result is False

    def test_get_email_templates(self):
        """Test listing templates for a brand."""
        brand = self.service.create_brand(tenant_id="TEN-034", company_name="ListTmpl")
        self.service.create_email_template(brand.brand_id, "welcome", "Welcome!")
        self.service.create_email_template(brand.brand_id, "alert", "Alert!")
        self.service.create_email_template(brand.brand_id, "report", "Report")
        templates = self.service.get_email_templates(brand.brand_id)
        assert len(templates) == 3

    def test_render_email(self):
        """Test rendering an email template with variables."""
        brand = self.service.create_brand(
            tenant_id="TEN-035",
            company_name="RenderCo",
            support_email="help@renderco.com",
        )
        self.service.create_email_template(
            brand_id=brand.brand_id,
            template_name="welcome",
            subject_template="Welcome to $company_name, $name!",
            body_html_template="<h1>Hi $name</h1><p>Contact $support_email for help.</p>",
            body_text_template="Hi $name. Contact $support_email for help.",
        )

        result = self.service.render_email(
            template_name="welcome",
            brand_id=brand.brand_id,
            variables={"name": "Alice"},
        )
        assert result is not None
        assert "RenderCo" in result["subject"]
        assert "Alice" in result["subject"]
        assert "help@renderco.com" in result["body_html"]
        assert "Alice" in result["body_text"]

    def test_render_email_not_found(self):
        """Test rendering a non-existent template."""
        result = self.service.render_email("nonexistent", "WL-FAKE", {})
        assert result is None

    # ========== CSS Generation Tests ==========

    def test_generate_css(self):
        """Test CSS generation from brand config."""
        brand = self.service.create_brand(
            tenant_id="TEN-040",
            company_name="CSSTest",
            primary_color="#003366",
            secondary_color="#f0f0f0",
            accent_color="#ff9900",
            font_family="Montserrat, sans-serif",
        )
        css = self.service.generate_css(brand.brand_id)
        assert css is not None
        assert "--wl-primary-color: #003366" in css
        assert "--wl-secondary-color: #f0f0f0" in css
        assert "--wl-accent-color: #ff9900" in css
        assert "Montserrat" in css

    def test_generate_css_with_custom_css(self):
        """Test CSS generation includes custom CSS."""
        brand = self.service.create_brand(
            tenant_id="TEN-041",
            company_name="CustomCSS",
            custom_css=".sidebar { background: navy; }",
        )
        css = self.service.generate_css(brand.brand_id)
        assert ".sidebar { background: navy; }" in css

    def test_generate_css_not_found(self):
        """Test CSS generation for non-existent brand."""
        result = self.service.generate_css("WL-NONEXIST")
        assert result is None

    # ========== Domain Verification Tests ==========

    def test_validate_custom_domain_dns_failure(self):
        """Test domain verification with an invalid domain."""
        result = self.service.validate_custom_domain("this-domain-does-not-exist-12345.invalid")
        assert result["verified"] is False
        assert result["error"] is not None

    def test_validate_custom_domain_structure(self):
        """Test domain verification returns expected structure."""
        result = self.service.validate_custom_domain("example.com")
        assert "domain" in result
        assert "verified" in result
        assert "expected_cname" in result
        assert result["domain"] == "example.com"
        assert result["expected_cname"] == "platform.aitherdominion.com"

    # ========== Dashboard Tests ==========

    def test_get_dashboard_empty(self):
        """Test dashboard with no brands."""
        dashboard = self.service.get_dashboard()
        assert dashboard["total_brands"] == 0
        assert dashboard["active_brands"] == 0
        assert dashboard["inactive_brands"] == 0
        assert dashboard["verified_domains"] == 0
        assert dashboard["total_email_templates"] == 0
        assert dashboard["total_assets"] == 0

    def test_get_dashboard_with_data(self):
        """Test dashboard with brands, templates, and assets."""
        b1 = self.service.create_brand(tenant_id="TEN-050", company_name="Dashboard1")
        b2 = self.service.create_brand(tenant_id="TEN-051", company_name="Dashboard2")
        b2.is_active = False

        self.service.create_email_template(b1.brand_id, "welcome", "Hello")
        self.service.create_email_template(b1.brand_id, "alert", "Alert")
        self.service.upload_asset(b1.brand_id, "logo", "/tmp/logo.png")

        dashboard = self.service.get_dashboard()
        assert dashboard["total_brands"] == 2
        assert dashboard["active_brands"] == 1
        assert dashboard["inactive_brands"] == 1
        assert dashboard["total_email_templates"] == 2
        assert dashboard["total_assets"] == 1
        assert len(dashboard["brands"]) == 2

    # ========== Dataclass Tests ==========

    def test_brand_config_defaults(self):
        """Test BrandConfig dataclass defaults."""
        brand = BrandConfig(brand_id="WL-TEST", tenant_id="T1", company_name="Test")
        assert brand.primary_color == "#1a73e8"
        assert brand.secondary_color == "#ffffff"
        assert brand.accent_color == "#ff6d00"
        assert brand.font_family == "Inter, sans-serif"
        assert brand.is_active is True
        assert brand.domain_verified is False
        assert brand.created_at is not None

    def test_email_template_defaults(self):
        """Test EmailTemplate dataclass defaults."""
        tmpl = EmailTemplate(template_id="WLT-TEST", brand_id="WL-1", template_name="welcome")
        assert tmpl.subject_template == ""
        assert tmpl.body_html_template == ""
        assert tmpl.body_text_template == ""
        assert tmpl.created_at is not None

    def test_brand_asset_defaults(self):
        """Test BrandAsset dataclass defaults."""
        asset = BrandAsset(asset_id="WLA-TEST", brand_id="WL-1", asset_type="logo", file_path="/tmp/x.png")
        assert asset.mime_type == ""
        assert asset.uploaded_at is not None

    # ========== Integration / Edge Cases ==========

    def test_multiple_brands_isolation(self):
        """Test that multiple brands are isolated from each other."""
        b1 = self.service.create_brand(tenant_id="TEN-060", company_name="IsoA")
        b2 = self.service.create_brand(tenant_id="TEN-061", company_name="IsoB")

        self.service.create_email_template(b1.brand_id, "welcome", "Hi A")
        self.service.create_email_template(b2.brand_id, "welcome", "Hi B")
        self.service.upload_asset(b1.brand_id, "logo", "/a/logo.png")

        assert len(self.service.get_email_templates(b1.brand_id)) == 1
        assert len(self.service.get_email_templates(b2.brand_id)) == 1
        assert len(self.service.get_assets(b1.brand_id)) == 1
        assert len(self.service.get_assets(b2.brand_id)) == 0

    def test_update_brand_ignores_unknown_fields(self):
        """Test that update_brand ignores fields not in the allowed set."""
        brand = self.service.create_brand(tenant_id="TEN-062", company_name="FilterTest")
        # Pass disallowed fields via kwargs dict to avoid Python arg conflict
        updates = {"tenant_id": "HACKED", "company_name": "Safe", "domain_verified": True}
        updated = self.service.update_brand(brand.brand_id, **updates)
        assert updated.tenant_id == "TEN-062"       # Not changed (not in allowed set)
        assert updated.domain_verified is False      # Not changed (not in allowed set)
        assert updated.company_name == "Safe"        # Changed (in allowed set)

    def test_render_email_safe_substitute(self):
        """Test that missing variables in templates are left as-is (safe_substitute)."""
        brand = self.service.create_brand(tenant_id="TEN-063", company_name="SafeSub")
        self.service.create_email_template(
            brand.brand_id, "test",
            subject_template="Hello $name, your $thing is ready",
        )
        result = self.service.render_email("test", brand.brand_id, {"name": "Bob"})
        assert result is not None
        assert "Bob" in result["subject"]
        assert "$thing" in result["subject"]  # safe_substitute leaves it
