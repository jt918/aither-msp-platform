"""
AITHER Platform - White-Label Branding Persistence Models

Tables for MSP white-label brand configurations, email templates,
and brand assets.
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON,
    Index,
)
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


# ============================================================
# White-Label Brand Configuration
# ============================================================

class WhiteLabelBrandModel(Base):
    """White-label brand configuration for an MSP tenant."""
    __tablename__ = "wl_brands"

    id = Column(String(36), primary_key=True, default=_uuid)
    brand_id = Column(String(30), unique=True, nullable=False, index=True)
    tenant_id = Column(String(100), unique=True, nullable=False, index=True)
    company_name = Column(String(300), nullable=False)
    logo_url = Column(String(500), default="")
    favicon_url = Column(String(500), default="")
    primary_color = Column(String(20), default="#1a73e8")
    secondary_color = Column(String(20), default="#ffffff")
    accent_color = Column(String(20), default="#ff6d00")
    font_family = Column(String(200), default="Inter, sans-serif")
    custom_css = Column(Text, default="")
    login_background_url = Column(String(500), default="")
    email_header_url = Column(String(500), default="")
    email_footer_html = Column(Text, default="")
    support_email = Column(String(200), default="")
    support_phone = Column(String(50), default="")
    support_url = Column(String(500), default="")
    terms_url = Column(String(500), default="")
    privacy_url = Column(String(500), default="")
    custom_domain = Column(String(300), nullable=True, index=True)
    domain_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True, index=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# White-Label Email Templates
# ============================================================

class WhiteLabelEmailTemplateModel(Base):
    """Branded email template for an MSP tenant."""
    __tablename__ = "wl_email_templates"

    id = Column(String(36), primary_key=True, default=_uuid)
    template_id = Column(String(30), unique=True, nullable=False, index=True)
    brand_id = Column(String(30), nullable=False, index=True)
    template_name = Column(String(100), nullable=False)
    subject_template = Column(String(500), default="")
    body_html_template = Column(Text, default="")
    body_text_template = Column(Text, default="")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    __table_args__ = (
        Index("ix_wl_et_brand_name", "brand_id", "template_name"),
    )


# ============================================================
# White-Label Brand Assets
# ============================================================

class WhiteLabelAssetModel(Base):
    """Uploaded asset (logo, favicon, background) for a brand."""
    __tablename__ = "wl_assets"

    id = Column(String(36), primary_key=True, default=_uuid)
    asset_id = Column(String(30), unique=True, nullable=False, index=True)
    brand_id = Column(String(30), nullable=False, index=True)
    asset_type = Column(String(50), nullable=False)
    file_path = Column(String(500), nullable=False)
    mime_type = Column(String(100), default="")
    uploaded_at = Column(DateTime, default=func.now())
