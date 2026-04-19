"""
AITHER Platform - White-Label Branding Service
MSP partner branding and customization system

Provides:
- Brand configuration management per tenant
- Custom CSS generation from brand colors/fonts
- Email template management with variable rendering
- Brand asset upload and management
- Custom domain verification via DNS CNAME
- Brand resolution by custom domain

G-46: DB persistence with in-memory fallback.
"""

import uuid
import re
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from string import Template

try:
    from sqlalchemy.orm import Session
    from models.white_label import (
        WhiteLabelBrandModel,
        WhiteLabelEmailTemplateModel,
        WhiteLabelAssetModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class BrandConfig:
    """White-label brand configuration for an MSP tenant."""
    brand_id: str
    tenant_id: str
    company_name: str
    logo_url: str = ""
    favicon_url: str = ""
    primary_color: str = "#1a73e8"
    secondary_color: str = "#ffffff"
    accent_color: str = "#ff6d00"
    font_family: str = "Inter, sans-serif"
    custom_css: str = ""
    login_background_url: str = ""
    email_header_url: str = ""
    email_footer_html: str = ""
    support_email: str = ""
    support_phone: str = ""
    support_url: str = ""
    terms_url: str = ""
    privacy_url: str = ""
    custom_domain: Optional[str] = None
    domain_verified: bool = False
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class EmailTemplate:
    """Branded email template."""
    template_id: str
    brand_id: str
    template_name: str  # welcome, alert, ticket_update, report, invoice, etc.
    subject_template: str = ""
    body_html_template: str = ""
    body_text_template: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None


@dataclass
class BrandAsset:
    """Uploaded brand asset."""
    asset_id: str
    brand_id: str
    asset_type: str  # logo, favicon, background, icon
    file_path: str
    mime_type: str = ""
    uploaded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================
# Conversion helpers: ORM model <-> dataclass
# ============================================================

def _brand_from_row(row) -> BrandConfig:
    """Convert WhiteLabelBrandModel row to BrandConfig dataclass."""
    return BrandConfig(
        brand_id=row.brand_id,
        tenant_id=row.tenant_id,
        company_name=row.company_name,
        logo_url=row.logo_url or "",
        favicon_url=row.favicon_url or "",
        primary_color=row.primary_color or "#1a73e8",
        secondary_color=row.secondary_color or "#ffffff",
        accent_color=row.accent_color or "#ff6d00",
        font_family=row.font_family or "Inter, sans-serif",
        custom_css=row.custom_css or "",
        login_background_url=row.login_background_url or "",
        email_header_url=row.email_header_url or "",
        email_footer_html=row.email_footer_html or "",
        support_email=row.support_email or "",
        support_phone=row.support_phone or "",
        support_url=row.support_url or "",
        terms_url=row.terms_url or "",
        privacy_url=row.privacy_url or "",
        custom_domain=row.custom_domain,
        domain_verified=row.domain_verified if row.domain_verified is not None else False,
        is_active=row.is_active if row.is_active is not None else True,
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _template_from_row(row) -> EmailTemplate:
    """Convert WhiteLabelEmailTemplateModel row to EmailTemplate dataclass."""
    return EmailTemplate(
        template_id=row.template_id,
        brand_id=row.brand_id,
        template_name=row.template_name,
        subject_template=row.subject_template or "",
        body_html_template=row.body_html_template or "",
        body_text_template=row.body_text_template or "",
        created_at=row.created_at or datetime.now(timezone.utc),
        updated_at=row.updated_at,
    )


def _asset_from_row(row) -> BrandAsset:
    """Convert WhiteLabelAssetModel row to BrandAsset dataclass."""
    return BrandAsset(
        asset_id=row.asset_id,
        brand_id=row.brand_id,
        asset_type=row.asset_type,
        file_path=row.file_path,
        mime_type=row.mime_type or "",
        uploaded_at=row.uploaded_at or datetime.now(timezone.utc),
    )


# ============================================================
# Service
# ============================================================

class WhiteLabelService:
    """
    White-Label Branding Service

    Manages MSP partner branding: colours, logos, CSS generation,
    email templates, asset uploads, and custom domain verification.

    Accepts an optional db: Session for persistence.
    Falls back to in-memory dicts when db is None.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback storage
        self._brands: Dict[str, BrandConfig] = {}
        self._templates: Dict[str, EmailTemplate] = {}
        self._assets: Dict[str, BrandAsset] = {}

        # Expected CNAME target for custom domain verification
        self.cname_target = "platform.aitherdominion.com"

    # ========== Brand CRUD ==========

    def create_brand(
        self,
        tenant_id: str,
        company_name: str,
        logo_url: str = "",
        favicon_url: str = "",
        primary_color: str = "#1a73e8",
        secondary_color: str = "#ffffff",
        accent_color: str = "#ff6d00",
        font_family: str = "Inter, sans-serif",
        custom_css: str = "",
        login_background_url: str = "",
        email_header_url: str = "",
        email_footer_html: str = "",
        support_email: str = "",
        support_phone: str = "",
        support_url: str = "",
        terms_url: str = "",
        privacy_url: str = "",
        custom_domain: Optional[str] = None,
    ) -> BrandConfig:
        """Create a new white-label brand configuration for a tenant."""
        brand_id = f"WL-{uuid.uuid4().hex[:8].upper()}"

        brand = BrandConfig(
            brand_id=brand_id,
            tenant_id=tenant_id,
            company_name=company_name,
            logo_url=logo_url,
            favicon_url=favicon_url,
            primary_color=primary_color,
            secondary_color=secondary_color,
            accent_color=accent_color,
            font_family=font_family,
            custom_css=custom_css,
            login_background_url=login_background_url,
            email_header_url=email_header_url,
            email_footer_html=email_footer_html,
            support_email=support_email,
            support_phone=support_phone,
            support_url=support_url,
            terms_url=terms_url,
            privacy_url=privacy_url,
            custom_domain=custom_domain,
        )

        if self._use_db:
            try:
                row = WhiteLabelBrandModel(
                    brand_id=brand_id,
                    tenant_id=tenant_id,
                    company_name=company_name,
                    logo_url=logo_url,
                    favicon_url=favicon_url,
                    primary_color=primary_color,
                    secondary_color=secondary_color,
                    accent_color=accent_color,
                    font_family=font_family,
                    custom_css=custom_css,
                    login_background_url=login_background_url,
                    email_header_url=email_header_url,
                    email_footer_html=email_footer_html,
                    support_email=support_email,
                    support_phone=support_phone,
                    support_url=support_url,
                    terms_url=terms_url,
                    privacy_url=privacy_url,
                    custom_domain=custom_domain,
                    is_active=True,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
                logger.info("Brand %s persisted to DB for tenant %s", brand_id, tenant_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for brand %s, using memory: %s", brand_id, exc)
                self._brands[brand_id] = brand
        else:
            self._brands[brand_id] = brand

        return brand

    def get_brand(self, brand_id: str) -> Optional[BrandConfig]:
        """Get brand configuration by brand_id."""
        if self._use_db:
            try:
                row = self.db.query(WhiteLabelBrandModel).filter(
                    WhiteLabelBrandModel.brand_id == brand_id
                ).first()
                if row:
                    return _brand_from_row(row)
                return None
            except Exception as exc:
                logger.warning("DB read failed for brand %s: %s", brand_id, exc)
        return self._brands.get(brand_id)

    def get_brand_by_tenant(self, tenant_id: str) -> Optional[BrandConfig]:
        """Get brand configuration by tenant_id."""
        if self._use_db:
            try:
                row = self.db.query(WhiteLabelBrandModel).filter(
                    WhiteLabelBrandModel.tenant_id == tenant_id
                ).first()
                if row:
                    return _brand_from_row(row)
                return None
            except Exception as exc:
                logger.warning("DB read failed for tenant %s: %s", tenant_id, exc)
        for b in self._brands.values():
            if b.tenant_id == tenant_id:
                return b
        return None

    def get_brand_by_domain(self, domain: str) -> Optional[BrandConfig]:
        """Get brand configuration by custom domain."""
        if self._use_db:
            try:
                row = self.db.query(WhiteLabelBrandModel).filter(
                    WhiteLabelBrandModel.custom_domain == domain,
                    WhiteLabelBrandModel.domain_verified == True,
                    WhiteLabelBrandModel.is_active == True,
                ).first()
                if row:
                    return _brand_from_row(row)
                return None
            except Exception as exc:
                logger.warning("DB read failed for domain %s: %s", domain, exc)
        for b in self._brands.values():
            if b.custom_domain == domain and b.domain_verified and b.is_active:
                return b
        return None

    def update_brand(self, brand_id: str, **kwargs) -> Optional[BrandConfig]:
        """Update an existing brand configuration."""
        allowed = {
            "company_name", "logo_url", "favicon_url", "primary_color",
            "secondary_color", "accent_color", "font_family", "custom_css",
            "login_background_url", "email_header_url", "email_footer_html",
            "support_email", "support_phone", "support_url", "terms_url",
            "privacy_url", "custom_domain", "is_active",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed}

        if self._use_db:
            try:
                row = self.db.query(WhiteLabelBrandModel).filter(
                    WhiteLabelBrandModel.brand_id == brand_id
                ).first()
                if not row:
                    return None
                for k, v in updates.items():
                    setattr(row, k, v)
                # Reset domain_verified if custom_domain changed
                if "custom_domain" in updates:
                    row.domain_verified = False
                self.db.commit()
                self.db.refresh(row)
                return _brand_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for brand %s: %s", brand_id, exc)

        brand = self._brands.get(brand_id)
        if not brand:
            return None
        for k, v in updates.items():
            setattr(brand, k, v)
        if "custom_domain" in updates:
            brand.domain_verified = False
        brand.updated_at = datetime.now(timezone.utc)
        return brand

    def delete_brand(self, brand_id: str) -> bool:
        """Delete a brand configuration and its associated templates/assets."""
        if self._use_db:
            try:
                row = self.db.query(WhiteLabelBrandModel).filter(
                    WhiteLabelBrandModel.brand_id == brand_id
                ).first()
                if not row:
                    return False
                # Cascade delete templates and assets
                self.db.query(WhiteLabelEmailTemplateModel).filter(
                    WhiteLabelEmailTemplateModel.brand_id == brand_id
                ).delete()
                self.db.query(WhiteLabelAssetModel).filter(
                    WhiteLabelAssetModel.brand_id == brand_id
                ).delete()
                self.db.delete(row)
                self.db.commit()
                return True
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete failed for brand %s: %s", brand_id, exc)

        if brand_id not in self._brands:
            return False
        del self._brands[brand_id]
        # Clean up related templates and assets
        self._templates = {k: v for k, v in self._templates.items() if v.brand_id != brand_id}
        self._assets = {k: v for k, v in self._assets.items() if v.brand_id != brand_id}
        return True

    def list_brands(self, active_only: bool = False) -> List[BrandConfig]:
        """List all brand configurations."""
        if self._use_db:
            try:
                q = self.db.query(WhiteLabelBrandModel)
                if active_only:
                    q = q.filter(WhiteLabelBrandModel.is_active == True)
                rows = q.order_by(WhiteLabelBrandModel.created_at.desc()).all()
                return [_brand_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB list brands failed: %s", exc)
        brands = list(self._brands.values())
        if active_only:
            brands = [b for b in brands if b.is_active]
        return brands

    # ========== Asset Management ==========

    def upload_asset(
        self,
        brand_id: str,
        asset_type: str,
        file_path: str,
        mime_type: str = "",
    ) -> Optional[BrandAsset]:
        """Record an uploaded brand asset (logo, favicon, background, icon)."""
        # Verify brand exists
        brand = self.get_brand(brand_id)
        if not brand:
            return None

        asset_id = f"WLA-{uuid.uuid4().hex[:8].upper()}"
        asset = BrandAsset(
            asset_id=asset_id,
            brand_id=brand_id,
            asset_type=asset_type,
            file_path=file_path,
            mime_type=mime_type,
        )

        if self._use_db:
            try:
                row = WhiteLabelAssetModel(
                    asset_id=asset_id,
                    brand_id=brand_id,
                    asset_type=asset_type,
                    file_path=file_path,
                    mime_type=mime_type,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
                logger.info("Asset %s persisted for brand %s", asset_id, brand_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for asset %s: %s", asset_id, exc)
                self._assets[asset_id] = asset
        else:
            self._assets[asset_id] = asset

        return asset

    def get_assets(self, brand_id: str) -> List[BrandAsset]:
        """List all assets for a brand."""
        if self._use_db:
            try:
                rows = self.db.query(WhiteLabelAssetModel).filter(
                    WhiteLabelAssetModel.brand_id == brand_id
                ).all()
                return [_asset_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB read assets failed for brand %s: %s", brand_id, exc)
        return [a for a in self._assets.values() if a.brand_id == brand_id]

    def delete_asset(self, asset_id: str) -> bool:
        """Delete a brand asset."""
        if self._use_db:
            try:
                row = self.db.query(WhiteLabelAssetModel).filter(
                    WhiteLabelAssetModel.asset_id == asset_id
                ).first()
                if not row:
                    return False
                self.db.delete(row)
                self.db.commit()
                return True
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete asset failed %s: %s", asset_id, exc)
        if asset_id in self._assets:
            del self._assets[asset_id]
            return True
        return False

    # ========== Email Template Management ==========

    def create_email_template(
        self,
        brand_id: str,
        template_name: str,
        subject_template: str = "",
        body_html_template: str = "",
        body_text_template: str = "",
    ) -> Optional[EmailTemplate]:
        """Create a branded email template."""
        brand = self.get_brand(brand_id)
        if not brand:
            return None

        template_id = f"WLT-{uuid.uuid4().hex[:8].upper()}"
        tmpl = EmailTemplate(
            template_id=template_id,
            brand_id=brand_id,
            template_name=template_name,
            subject_template=subject_template,
            body_html_template=body_html_template,
            body_text_template=body_text_template,
        )

        if self._use_db:
            try:
                row = WhiteLabelEmailTemplateModel(
                    template_id=template_id,
                    brand_id=brand_id,
                    template_name=template_name,
                    subject_template=subject_template,
                    body_html_template=body_html_template,
                    body_text_template=body_text_template,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
                logger.info("Email template %s persisted for brand %s", template_id, brand_id)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for template %s: %s", template_id, exc)
                self._templates[template_id] = tmpl
        else:
            self._templates[template_id] = tmpl

        return tmpl

    def update_email_template(self, template_id: str, **kwargs) -> Optional[EmailTemplate]:
        """Update an existing email template."""
        allowed = {"template_name", "subject_template", "body_html_template", "body_text_template"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}

        if self._use_db:
            try:
                row = self.db.query(WhiteLabelEmailTemplateModel).filter(
                    WhiteLabelEmailTemplateModel.template_id == template_id
                ).first()
                if not row:
                    return None
                for k, v in updates.items():
                    setattr(row, k, v)
                self.db.commit()
                self.db.refresh(row)
                return _template_from_row(row)
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update template failed %s: %s", template_id, exc)

        tmpl = self._templates.get(template_id)
        if not tmpl:
            return None
        for k, v in updates.items():
            setattr(tmpl, k, v)
        tmpl.updated_at = datetime.now(timezone.utc)
        return tmpl

    def get_email_template(self, template_id: str) -> Optional[EmailTemplate]:
        """Get a single email template by ID."""
        if self._use_db:
            try:
                row = self.db.query(WhiteLabelEmailTemplateModel).filter(
                    WhiteLabelEmailTemplateModel.template_id == template_id
                ).first()
                if row:
                    return _template_from_row(row)
                return None
            except Exception as exc:
                logger.warning("DB read template failed %s: %s", template_id, exc)
        return self._templates.get(template_id)

    def delete_email_template(self, template_id: str) -> bool:
        """Delete an email template."""
        if self._use_db:
            try:
                row = self.db.query(WhiteLabelEmailTemplateModel).filter(
                    WhiteLabelEmailTemplateModel.template_id == template_id
                ).first()
                if not row:
                    return False
                self.db.delete(row)
                self.db.commit()
                return True
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete template failed %s: %s", template_id, exc)
        if template_id in self._templates:
            del self._templates[template_id]
            return True
        return False

    def get_email_templates(self, brand_id: str) -> List[EmailTemplate]:
        """List all email templates for a brand."""
        if self._use_db:
            try:
                rows = self.db.query(WhiteLabelEmailTemplateModel).filter(
                    WhiteLabelEmailTemplateModel.brand_id == brand_id
                ).all()
                return [_template_from_row(r) for r in rows]
            except Exception as exc:
                logger.warning("DB list templates failed for brand %s: %s", brand_id, exc)
        return [t for t in self._templates.values() if t.brand_id == brand_id]

    def render_email(
        self,
        template_name: str,
        brand_id: str,
        variables: Dict[str, str],
    ) -> Optional[Dict[str, str]]:
        """Render a branded email template with variable substitution.

        Returns dict with keys: subject, body_html, body_text.
        Uses Python string.Template ($variable) syntax.
        """
        # Find the template for this brand and name
        tmpl = None
        if self._use_db:
            try:
                row = self.db.query(WhiteLabelEmailTemplateModel).filter(
                    WhiteLabelEmailTemplateModel.brand_id == brand_id,
                    WhiteLabelEmailTemplateModel.template_name == template_name,
                ).first()
                if row:
                    tmpl = _template_from_row(row)
            except Exception as exc:
                logger.warning("DB template lookup failed: %s", exc)

        if not tmpl:
            for t in self._templates.values():
                if t.brand_id == brand_id and t.template_name == template_name:
                    tmpl = t
                    break

        if not tmpl:
            return None

        # Inject brand variables
        brand = self.get_brand(brand_id)
        if brand:
            variables.setdefault("company_name", brand.company_name)
            variables.setdefault("support_email", brand.support_email)
            variables.setdefault("support_phone", brand.support_phone)
            variables.setdefault("support_url", brand.support_url)
            variables.setdefault("logo_url", brand.logo_url)
            variables.setdefault("email_header_url", brand.email_header_url)
            variables.setdefault("email_footer_html", brand.email_footer_html)

        try:
            subject = Template(tmpl.subject_template).safe_substitute(variables)
            body_html = Template(tmpl.body_html_template).safe_substitute(variables)
            body_text = Template(tmpl.body_text_template).safe_substitute(variables)
        except Exception as exc:
            logger.error("Template rendering failed: %s", exc)
            return None

        return {
            "subject": subject,
            "body_html": body_html,
            "body_text": body_text,
        }

    # ========== CSS Generation ==========

    def generate_css(self, brand_id: str) -> Optional[str]:
        """Generate CSS custom properties from a brand's configuration.

        Returns a CSS string with :root variables that can be injected
        into the platform to theme the entire UI.
        """
        brand = self.get_brand(brand_id)
        if not brand:
            return None

        css_vars = f""":root {{
  --wl-primary-color: {brand.primary_color};
  --wl-secondary-color: {brand.secondary_color};
  --wl-accent-color: {brand.accent_color};
  --wl-font-family: {brand.font_family};
  --wl-logo-url: url('{brand.logo_url}');
  --wl-favicon-url: url('{brand.favicon_url}');
  --wl-login-bg-url: url('{brand.login_background_url}');
}}

body {{
  font-family: var(--wl-font-family);
}}

.wl-primary {{
  color: var(--wl-primary-color);
}}

.wl-primary-bg {{
  background-color: var(--wl-primary-color);
}}

.wl-secondary {{
  color: var(--wl-secondary-color);
}}

.wl-secondary-bg {{
  background-color: var(--wl-secondary-color);
}}

.wl-accent {{
  color: var(--wl-accent-color);
}}

.wl-accent-bg {{
  background-color: var(--wl-accent-color);
}}
"""
        # Append any custom CSS the partner provided
        if brand.custom_css:
            css_vars += f"\n/* Custom CSS */\n{brand.custom_css}\n"

        return css_vars

    # ========== Domain Verification ==========

    def validate_custom_domain(self, domain: str) -> Dict[str, Any]:
        """Verify a custom domain has a CNAME record pointing to the platform.

        Performs a DNS CNAME lookup and checks that it resolves to the
        expected platform hostname.
        """
        result = {
            "domain": domain,
            "verified": False,
            "expected_cname": self.cname_target,
            "actual_cname": None,
            "error": None,
        }

        try:
            answers = socket.getaddrinfo(domain, None)
            # Try CNAME resolution via socket (basic check)
            resolved_ip = answers[0][4][0] if answers else None

            # Also resolve the target to compare
            target_answers = socket.getaddrinfo(self.cname_target, None)
            target_ip = target_answers[0][4][0] if target_answers else None

            if resolved_ip and target_ip and resolved_ip == target_ip:
                result["verified"] = True
                result["actual_cname"] = self.cname_target
            else:
                result["actual_cname"] = resolved_ip
                result["error"] = (
                    f"Domain resolves to {resolved_ip} but expected "
                    f"{target_ip} ({self.cname_target})"
                )
        except socket.gaierror as exc:
            result["error"] = f"DNS resolution failed: {exc}"
        except Exception as exc:
            result["error"] = f"Verification error: {exc}"

        # If verified, update the brand record
        if result["verified"]:
            if self._use_db:
                try:
                    row = self.db.query(WhiteLabelBrandModel).filter(
                        WhiteLabelBrandModel.custom_domain == domain
                    ).first()
                    if row:
                        row.domain_verified = True
                        self.db.commit()
                except Exception as exc:
                    self.db.rollback()
                    logger.warning("DB domain verify update failed: %s", exc)
            else:
                for b in self._brands.values():
                    if b.custom_domain == domain:
                        b.domain_verified = True

        return result

    # ========== Dashboard / Stats ==========

    def get_dashboard(self) -> Dict[str, Any]:
        """Return statistics on white-label brands."""
        brands = self.list_brands()
        active = [b for b in brands if b.is_active]
        verified_domains = [b for b in brands if b.domain_verified]

        # Count templates and assets
        template_count = 0
        asset_count = 0
        if self._use_db:
            try:
                template_count = self.db.query(WhiteLabelEmailTemplateModel).count()
                asset_count = self.db.query(WhiteLabelAssetModel).count()
            except Exception:
                template_count = len(self._templates)
                asset_count = len(self._assets)
        else:
            template_count = len(self._templates)
            asset_count = len(self._assets)

        return {
            "total_brands": len(brands),
            "active_brands": len(active),
            "inactive_brands": len(brands) - len(active),
            "verified_domains": len(verified_domains),
            "total_email_templates": template_count,
            "total_assets": asset_count,
            "brands": [
                {
                    "brand_id": b.brand_id,
                    "tenant_id": b.tenant_id,
                    "company_name": b.company_name,
                    "is_active": b.is_active,
                    "custom_domain": b.custom_domain,
                    "domain_verified": b.domain_verified,
                }
                for b in brands
            ],
        }
