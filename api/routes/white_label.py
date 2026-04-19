"""
API Routes for White-Label Branding Service
Uses WhiteLabelService for all operations
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.white_label import WhiteLabelService

router = APIRouter(prefix="/white-label", tags=["White-Label Branding"])


def _init_wl_service() -> WhiteLabelService:
    """Initialize WhiteLabelService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return WhiteLabelService(db=db)
    except Exception:
        return WhiteLabelService()


# Initialize service with DB persistence
wl_service = _init_wl_service()


# ========== Request/Response Models ==========

class BrandCreate(BaseModel):
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


class BrandUpdate(BaseModel):
    company_name: Optional[str] = None
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    accent_color: Optional[str] = None
    font_family: Optional[str] = None
    custom_css: Optional[str] = None
    login_background_url: Optional[str] = None
    email_header_url: Optional[str] = None
    email_footer_html: Optional[str] = None
    support_email: Optional[str] = None
    support_phone: Optional[str] = None
    support_url: Optional[str] = None
    terms_url: Optional[str] = None
    privacy_url: Optional[str] = None
    custom_domain: Optional[str] = None
    is_active: Optional[bool] = None


class AssetUpload(BaseModel):
    asset_type: str  # logo, favicon, background, icon
    file_path: str
    mime_type: str = ""


class EmailTemplateCreate(BaseModel):
    template_name: str
    subject_template: str = ""
    body_html_template: str = ""
    body_text_template: str = ""


class EmailTemplateUpdate(BaseModel):
    template_name: Optional[str] = None
    subject_template: Optional[str] = None
    body_html_template: Optional[str] = None
    body_text_template: Optional[str] = None


class EmailRender(BaseModel):
    template_name: str
    variables: Dict[str, str] = {}


class PreviewRequest(BaseModel):
    page: str = "login"  # login, dashboard, email


# ========== Helper Functions ==========

def brand_to_dict(brand) -> dict:
    """Convert BrandConfig dataclass to dict."""
    return {
        "brand_id": brand.brand_id,
        "tenant_id": brand.tenant_id,
        "company_name": brand.company_name,
        "logo_url": brand.logo_url,
        "favicon_url": brand.favicon_url,
        "primary_color": brand.primary_color,
        "secondary_color": brand.secondary_color,
        "accent_color": brand.accent_color,
        "font_family": brand.font_family,
        "custom_css": brand.custom_css,
        "login_background_url": brand.login_background_url,
        "email_header_url": brand.email_header_url,
        "email_footer_html": brand.email_footer_html,
        "support_email": brand.support_email,
        "support_phone": brand.support_phone,
        "support_url": brand.support_url,
        "terms_url": brand.terms_url,
        "privacy_url": brand.privacy_url,
        "custom_domain": brand.custom_domain,
        "domain_verified": brand.domain_verified,
        "is_active": brand.is_active,
        "created_at": brand.created_at.isoformat() if brand.created_at else None,
        "updated_at": brand.updated_at.isoformat() if brand.updated_at else None,
    }


def template_to_dict(tmpl) -> dict:
    """Convert EmailTemplate dataclass to dict."""
    return {
        "template_id": tmpl.template_id,
        "brand_id": tmpl.brand_id,
        "template_name": tmpl.template_name,
        "subject_template": tmpl.subject_template,
        "body_html_template": tmpl.body_html_template,
        "body_text_template": tmpl.body_text_template,
        "created_at": tmpl.created_at.isoformat() if tmpl.created_at else None,
        "updated_at": tmpl.updated_at.isoformat() if tmpl.updated_at else None,
    }


def asset_to_dict(asset) -> dict:
    """Convert BrandAsset dataclass to dict."""
    return {
        "asset_id": asset.asset_id,
        "brand_id": asset.brand_id,
        "asset_type": asset.asset_type,
        "file_path": asset.file_path,
        "mime_type": asset.mime_type,
        "uploaded_at": asset.uploaded_at.isoformat() if asset.uploaded_at else None,
    }


# ========== Brand Routes ==========

@router.post("/brands")
async def create_brand(data: BrandCreate, current_user: dict = Depends(require_admin)):
    """Create a new white-label brand configuration."""
    brand = wl_service.create_brand(**data.model_dump())
    return brand_to_dict(brand)


@router.get("/brands")
async def list_brands(
    active_only: bool = Query(False, description="Only return active brands"),
    current_user: dict = Depends(get_current_user),
):
    """List all white-label brand configurations."""
    brands = wl_service.list_brands(active_only=active_only)
    return [brand_to_dict(b) for b in brands]


@router.get("/brands/{brand_id}")
async def get_brand(brand_id: str, current_user: dict = Depends(get_current_user)):
    """Get a brand configuration by ID."""
    brand = wl_service.get_brand(brand_id)
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")
    return brand_to_dict(brand)


@router.put("/brands/{brand_id}")
async def update_brand(brand_id: str, data: BrandUpdate, current_user: dict = Depends(require_admin)):
    """Update an existing brand configuration."""
    updates = data.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    brand = wl_service.update_brand(brand_id, **updates)
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")
    return brand_to_dict(brand)


@router.delete("/brands/{brand_id}")
async def delete_brand(brand_id: str, current_user: dict = Depends(require_admin)):
    """Delete a brand configuration and all associated templates/assets."""
    result = wl_service.delete_brand(brand_id)
    if not result:
        raise HTTPException(status_code=404, detail="Brand not found")
    return {"status": "deleted", "brand_id": brand_id}


# ========== Asset Routes ==========

@router.post("/brands/{brand_id}/assets")
async def upload_asset(brand_id: str, data: AssetUpload, current_user: dict = Depends(require_admin)):
    """Upload a brand asset (logo, favicon, background, icon)."""
    asset = wl_service.upload_asset(
        brand_id=brand_id,
        asset_type=data.asset_type,
        file_path=data.file_path,
        mime_type=data.mime_type,
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Brand not found")
    return asset_to_dict(asset)


@router.get("/brands/{brand_id}/assets")
async def list_assets(brand_id: str, current_user: dict = Depends(get_current_user)):
    """List all assets for a brand."""
    brand = wl_service.get_brand(brand_id)
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")
    assets = wl_service.get_assets(brand_id)
    return [asset_to_dict(a) for a in assets]


@router.delete("/brands/{brand_id}/assets/{asset_id}")
async def delete_asset(brand_id: str, asset_id: str, current_user: dict = Depends(require_admin)):
    """Delete a brand asset."""
    result = wl_service.delete_asset(asset_id)
    if not result:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"status": "deleted", "asset_id": asset_id}


# ========== CSS Route ==========

@router.get("/brands/{brand_id}/css")
async def get_brand_css(brand_id: str):
    """Generate and return CSS custom properties for a brand.

    This endpoint is intentionally public so iframes and custom
    domain pages can load the stylesheet without authentication.
    """
    css = wl_service.generate_css(brand_id)
    if css is None:
        raise HTTPException(status_code=404, detail="Brand not found")
    return {"brand_id": brand_id, "css": css}


# ========== Domain Verification ==========

@router.post("/brands/{brand_id}/verify-domain")
async def verify_domain(brand_id: str, current_user: dict = Depends(require_admin)):
    """Verify a brand's custom domain CNAME record."""
    brand = wl_service.get_brand(brand_id)
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")
    if not brand.custom_domain:
        raise HTTPException(status_code=400, detail="No custom domain configured for this brand")
    result = wl_service.validate_custom_domain(brand.custom_domain)
    return result


# ========== Email Template Routes ==========

@router.post("/brands/{brand_id}/email-templates")
async def create_email_template(
    brand_id: str, data: EmailTemplateCreate, current_user: dict = Depends(require_admin)
):
    """Create a branded email template."""
    tmpl = wl_service.create_email_template(
        brand_id=brand_id,
        template_name=data.template_name,
        subject_template=data.subject_template,
        body_html_template=data.body_html_template,
        body_text_template=data.body_text_template,
    )
    if not tmpl:
        raise HTTPException(status_code=404, detail="Brand not found")
    return template_to_dict(tmpl)


@router.get("/brands/{brand_id}/email-templates")
async def list_email_templates(brand_id: str, current_user: dict = Depends(get_current_user)):
    """List all email templates for a brand."""
    brand = wl_service.get_brand(brand_id)
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")
    templates = wl_service.get_email_templates(brand_id)
    return [template_to_dict(t) for t in templates]


@router.get("/email-templates/{template_id}")
async def get_email_template(template_id: str, current_user: dict = Depends(get_current_user)):
    """Get a single email template by ID."""
    tmpl = wl_service.get_email_template(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Email template not found")
    return template_to_dict(tmpl)


@router.put("/email-templates/{template_id}")
async def update_email_template(
    template_id: str, data: EmailTemplateUpdate, current_user: dict = Depends(require_admin)
):
    """Update an email template."""
    updates = data.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    tmpl = wl_service.update_email_template(template_id, **updates)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Email template not found")
    return template_to_dict(tmpl)


@router.delete("/email-templates/{template_id}")
async def delete_email_template(template_id: str, current_user: dict = Depends(require_admin)):
    """Delete an email template."""
    result = wl_service.delete_email_template(template_id)
    if not result:
        raise HTTPException(status_code=404, detail="Email template not found")
    return {"status": "deleted", "template_id": template_id}


# ========== Email Rendering ==========

@router.post("/brands/{brand_id}/render-email")
async def render_email(brand_id: str, data: EmailRender, current_user: dict = Depends(get_current_user)):
    """Render a branded email template with variable substitution."""
    result = wl_service.render_email(
        template_name=data.template_name,
        brand_id=brand_id,
        variables=data.variables,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Template not found for this brand")
    return result


# ========== Preview ==========

@router.post("/brands/{brand_id}/preview")
async def preview_branded_page(brand_id: str, data: PreviewRequest, current_user: dict = Depends(get_current_user)):
    """Generate an HTML preview of a branded page (login, dashboard, email)."""
    brand = wl_service.get_brand(brand_id)
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    css = wl_service.generate_css(brand_id) or ""

    if data.page == "login":
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{brand.company_name} - Login</title>
    <style>{css}</style>
</head>
<body style="background: var(--wl-primary-color); display: flex; justify-content: center; align-items: center; min-height: 100vh;">
    <div style="background: var(--wl-secondary-color); padding: 2rem; border-radius: 8px; width: 400px; text-align: center;">
        <img src="{brand.logo_url}" alt="{brand.company_name}" style="max-width: 200px; margin-bottom: 1rem;" />
        <h2>{brand.company_name}</h2>
        <input type="email" placeholder="Email" style="width: 100%; padding: 0.5rem; margin: 0.5rem 0; box-sizing: border-box;" />
        <input type="password" placeholder="Password" style="width: 100%; padding: 0.5rem; margin: 0.5rem 0; box-sizing: border-box;" />
        <button style="width: 100%; padding: 0.75rem; background: var(--wl-accent-color); color: white; border: none; border-radius: 4px; cursor: pointer; margin-top: 0.5rem;">Sign In</button>
        <p style="margin-top: 1rem; font-size: 0.8rem;">
            <a href="{brand.terms_url}">Terms</a> | <a href="{brand.privacy_url}">Privacy</a>
        </p>
        <p style="font-size: 0.8rem;">Support: {brand.support_email}</p>
    </div>
</body>
</html>"""
    elif data.page == "dashboard":
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{brand.company_name} - Dashboard</title>
    <style>{css}</style>
</head>
<body>
    <nav style="background: var(--wl-primary-color); color: var(--wl-secondary-color); padding: 1rem; display: flex; align-items: center;">
        <img src="{brand.logo_url}" alt="{brand.company_name}" style="height: 32px; margin-right: 1rem;" />
        <span style="font-size: 1.2rem; font-weight: bold;">{brand.company_name}</span>
    </nav>
    <main style="padding: 2rem;">
        <h1>Dashboard Preview</h1>
        <p>This is a preview of the branded dashboard for <strong>{brand.company_name}</strong>.</p>
    </main>
</body>
</html>"""
    elif data.page == "email":
        html = f"""<!DOCTYPE html>
<html>
<head><title>{brand.company_name} - Email Preview</title></head>
<body style="font-family: {brand.font_family}; max-width: 600px; margin: 0 auto;">
    <div style="background: var(--wl-primary-color); padding: 1rem; text-align: center;">
        <img src="{brand.email_header_url or brand.logo_url}" alt="{brand.company_name}" style="max-height: 48px;" />
    </div>
    <div style="padding: 1.5rem;">
        <h2>Email Preview</h2>
        <p>Hello, this is a sample branded email from <strong>{brand.company_name}</strong>.</p>
        <p>Contact support at <a href="mailto:{brand.support_email}">{brand.support_email}</a> or call {brand.support_phone}.</p>
    </div>
    <div style="background: #f5f5f5; padding: 1rem; text-align: center; font-size: 0.8rem;">
        {brand.email_footer_html or f'&copy; {brand.company_name}'}
    </div>
</body>
</html>"""
    else:
        raise HTTPException(status_code=400, detail=f"Unknown preview page: {data.page}. Use login, dashboard, or email.")

    return {"brand_id": brand_id, "page": data.page, "html": html}


# ========== Domain Resolution (Public) ==========

@router.get("/resolve/{domain}")
async def resolve_domain(domain: str):
    """Resolve a custom domain to a brand configuration.

    This endpoint is public - used by the reverse proxy / front-end
    to determine which brand to render for a custom domain request.
    """
    brand = wl_service.get_brand_by_domain(domain)
    if not brand:
        raise HTTPException(status_code=404, detail="No brand found for this domain")
    return brand_to_dict(brand)


# ========== Dashboard ==========

@router.get("/dashboard")
async def get_dashboard(current_user: dict = Depends(require_admin)):
    """Get white-label branding statistics and summary."""
    return wl_service.get_dashboard()
