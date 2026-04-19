"""
AITHER Platform - Knowledge Base Persistence Models

Tables for KB articles, categories, documentation entries, and article votes.
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


class KBArticleModel(Base):
    """Knowledge base article."""
    __tablename__ = "kb_articles"

    id = Column(String(36), primary_key=True, default=_uuid)
    article_id = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    content_markdown = Column(Text, default="")
    category = Column(String(100), nullable=False, index=True)
    subcategory = Column(String(100), default="")
    tags = Column(JSON, default=list)
    client_id = Column(String(100), nullable=True, index=True)
    visibility = Column(String(20), default="internal", index=True)
    status = Column(String(20), default="draft", index=True)
    author = Column(String(200), default="")
    views = Column(Integer, default=0)
    helpful_votes = Column(Integer, default=0)
    not_helpful_votes = Column(Integer, default=0)
    related_articles = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_kb_art_cat_status", "category", "status"),
        Index("ix_kb_art_vis_status", "visibility", "status"),
    )


class KBCategoryModel(Base):
    """Knowledge base category."""
    __tablename__ = "kb_categories"

    id = Column(String(36), primary_key=True, default=_uuid)
    category_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    parent_id = Column(String(50), nullable=True, index=True)
    article_count = Column(Integer, default=0)
    icon = Column(String(50), default="folder")

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class DocumentationEntryModel(Base):
    """Client documentation entry (runbooks, SOPs, configs, etc.)."""
    __tablename__ = "kb_documentation"

    id = Column(String(36), primary_key=True, default=_uuid)
    doc_id = Column(String(50), unique=True, nullable=False, index=True)
    client_id = Column(String(100), nullable=False, index=True)
    doc_type = Column(String(30), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    content = Column(Text, default="")
    is_encrypted = Column(Boolean, default=False)
    last_verified = Column(DateTime, nullable=True)
    verified_by = Column(String(200), nullable=True)
    expiry_date = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_kb_doc_client_type", "client_id", "doc_type"),
    )


class ArticleVoteModel(Base):
    """Article feedback vote record."""
    __tablename__ = "kb_article_votes"

    id = Column(String(36), primary_key=True, default=_uuid)
    article_id = Column(String(50), nullable=False, index=True)
    user_id = Column(String(100), default="anonymous")
    is_helpful = Column(Boolean, nullable=False)
    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_kb_vote_article", "article_id"),
    )
