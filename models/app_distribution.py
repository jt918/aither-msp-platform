"""
AITHER Platform — App Distribution Models
Tracks releases, downloads, and update channels for all Aither product apps.
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, Numeric, JSON
from sqlalchemy.sql import func
from core.database import Base


class AppRelease(Base):
    __tablename__ = "app_releases"

    id = Column(String(36), primary_key=True)
    app_id = Column(String(50), nullable=False, index=True)        # shield, synapse, gigos, ace
    platform = Column(String(20), nullable=False)                   # android, windows, macos, ios
    version = Column(String(20), nullable=False)
    version_code = Column(Integer, nullable=False)
    channel = Column(String(20), default="stable")                  # stable, beta, canary
    release_notes = Column(Text)
    file_name = Column(String(255))
    file_size_bytes = Column(Integer)
    file_hash_sha256 = Column(String(64))
    download_url = Column(Text)                                     # relative path under /releases/
    min_os_version = Column(String(20))
    is_current = Column(Boolean, default=True)
    is_mandatory = Column(Boolean, default=False)
    download_count = Column(Integer, default=0)
    release_metadata = Column("metadata", JSON, default={})
    published_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AppDownloadLog(Base):
    __tablename__ = "app_download_logs"

    id = Column(String(36), primary_key=True)
    release_id = Column(String(36), index=True)
    app_id = Column(String(50), index=True)
    platform = Column(String(20))
    version = Column(String(20))
    user_id = Column(String(36), nullable=True)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    downloaded_at = Column(DateTime(timezone=True), server_default=func.now())


class AppRegistration(Base):
    __tablename__ = "app_registrations"

    id = Column(String(36), primary_key=True)
    app_id = Column(String(50), unique=True, nullable=False)
    display_name = Column(String(100), nullable=False)
    description = Column(Text)
    icon_url = Column(Text)
    category = Column(String(50))                                   # security, ai, commerce, workforce
    platforms = Column(JSON, default=[])                             # ["android", "windows", "macos"]
    bundle_ids = Column(JSON, default={})                            # {"android": "com.aither.shield", ...}
    api_base_path = Column(String(100))                             # /api/shield, /api/synapse, etc.
    requires_subscription = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
