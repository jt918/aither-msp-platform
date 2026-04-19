"""
API Routes for Knowledge Base & IT Documentation
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.knowledge_base import (
    KnowledgeBaseService,
    ArticleVisibility,
    ArticleStatus,
    DocType,
)

router = APIRouter(prefix="/kb", tags=["Knowledge Base"])


def _init_kb_service() -> KnowledgeBaseService:
    """Initialize KnowledgeBaseService with DB if available."""
    try:
        db_gen = get_sync_db()
        db = next(db_gen)
        return KnowledgeBaseService(db=db)
    except Exception:
        return KnowledgeBaseService()


kb_service = _init_kb_service()


# ========== Request/Response Models ==========

class ArticleCreate(BaseModel):
    title: str
    content_markdown: str
    category: str
    subcategory: str = ""
    tags: List[str] = []
    client_id: Optional[str] = None
    visibility: str = "internal"
    author: str = ""
    related_articles: List[str] = []


class ArticleUpdate(BaseModel):
    title: Optional[str] = None
    content_markdown: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    tags: Optional[List[str]] = None
    client_id: Optional[str] = None
    visibility: Optional[str] = None
    author: Optional[str] = None
    related_articles: Optional[List[str]] = None


class VoteRequest(BaseModel):
    is_helpful: bool


class CategoryCreate(BaseModel):
    name: str
    description: str = ""
    parent_id: Optional[str] = None
    icon: str = "folder"


class CategoryUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    parent_id: Optional[str] = None
    icon: Optional[str] = None


class DocumentationCreate(BaseModel):
    client_id: str
    doc_type: str
    title: str
    content: str = ""
    is_encrypted: bool = False
    expiry_date: Optional[str] = None


class DocumentationUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    is_encrypted: Optional[bool] = None
    last_verified: Optional[str] = None
    verified_by: Optional[str] = None
    expiry_date: Optional[str] = None


class TicketSuggestRequest(BaseModel):
    title: str = ""
    description: str = ""
    category: str = ""


class GenerateFromTicketRequest(BaseModel):
    ticket_id: str
    resolution: str
    title: Optional[str] = None
    category: str = "Troubleshooting"
    author: str = "Auto-Generated"


# ========== Helper Functions ==========

def article_to_dict(article) -> dict:
    vis = article.visibility
    st = article.status
    return {
        "article_id": article.article_id,
        "title": article.title,
        "content_markdown": article.content_markdown,
        "category": article.category,
        "subcategory": article.subcategory,
        "tags": article.tags,
        "client_id": article.client_id,
        "visibility": vis.value if hasattr(vis, "value") else str(vis),
        "status": st.value if hasattr(st, "value") else str(st),
        "author": article.author,
        "views": article.views,
        "helpful_votes": article.helpful_votes,
        "not_helpful_votes": article.not_helpful_votes,
        "related_articles": article.related_articles,
        "created_at": article.created_at.isoformat() if article.created_at else None,
        "updated_at": article.updated_at.isoformat() if article.updated_at else None,
    }


def category_to_dict(cat) -> dict:
    return {
        "category_id": cat.category_id,
        "name": cat.name,
        "description": cat.description,
        "parent_id": cat.parent_id,
        "article_count": cat.article_count,
        "icon": cat.icon,
    }


def search_result_to_dict(sr) -> dict:
    return {
        "article_id": sr.article_id,
        "title": sr.title,
        "snippet": sr.snippet,
        "relevance_score": sr.relevance_score,
        "category": sr.category,
        "tags": sr.tags,
    }


def doc_to_dict(doc) -> dict:
    dt = doc.doc_type
    return {
        "doc_id": doc.doc_id,
        "client_id": doc.client_id,
        "doc_type": dt.value if hasattr(dt, "value") else str(dt),
        "title": doc.title,
        "content": doc.content,
        "is_encrypted": doc.is_encrypted,
        "last_verified": doc.last_verified.isoformat() if doc.last_verified else None,
        "verified_by": doc.verified_by,
        "expiry_date": doc.expiry_date.isoformat() if doc.expiry_date else None,
        "created_at": doc.created_at.isoformat() if doc.created_at else None,
        "updated_at": doc.updated_at.isoformat() if doc.updated_at else None,
    }


# ========== Article CRUD ==========

@router.post("/articles")
async def create_article(request: ArticleCreate, current_user: dict = Depends(get_current_user)):
    """Create a new KB article."""
    try:
        visibility = ArticleVisibility(request.visibility)
    except ValueError:
        visibility = ArticleVisibility.INTERNAL

    article = kb_service.create_article(
        title=request.title,
        content_markdown=request.content_markdown,
        category=request.category,
        subcategory=request.subcategory,
        tags=request.tags,
        client_id=request.client_id,
        visibility=visibility,
        author=request.author or current_user.get("username", ""),
        related_articles=request.related_articles,
    )
    return {"status": "created", "article": article_to_dict(article)}


@router.get("/articles")
async def list_articles(
    category: Optional[str] = None,
    status: Optional[str] = None,
    visibility: Optional[str] = None,
    client_id: Optional[str] = None,
    tag: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """List articles with optional filters."""
    status_enum = ArticleStatus(status) if status else None
    vis_enum = ArticleVisibility(visibility) if visibility else None
    articles = kb_service.list_articles(
        category=category, status=status_enum, visibility=vis_enum,
        client_id=client_id, tag=tag,
    )
    return {"articles": [article_to_dict(a) for a in articles], "count": len(articles)}


@router.get("/articles/{article_id}")
async def get_article(article_id: str, current_user: dict = Depends(get_current_user)):
    """Get a single article by ID."""
    article = kb_service.get_article(article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return {"article": article_to_dict(article)}


@router.put("/articles/{article_id}")
async def update_article(article_id: str, request: ArticleUpdate, current_user: dict = Depends(get_current_user)):
    """Update an existing article."""
    updates = {k: v for k, v in request.dict().items() if v is not None}
    if "visibility" in updates:
        try:
            updates["visibility"] = ArticleVisibility(updates["visibility"])
        except ValueError:
            pass
    article = kb_service.update_article(article_id, **updates)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return {"status": "updated", "article": article_to_dict(article)}


@router.delete("/articles/{article_id}")
async def delete_article(article_id: str, current_user: dict = Depends(require_admin)):
    """Delete an article (admin only)."""
    deleted = kb_service.delete_article(article_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Article not found")
    return {"status": "deleted", "article_id": article_id}


# ========== Publishing Workflow ==========

@router.post("/articles/{article_id}/publish")
async def publish_article(article_id: str, current_user: dict = Depends(get_current_user)):
    """Publish a draft article."""
    article = kb_service.publish_article(article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return {"status": "published", "article": article_to_dict(article)}


@router.post("/articles/{article_id}/archive")
async def archive_article(article_id: str, current_user: dict = Depends(get_current_user)):
    """Archive an article."""
    article = kb_service.archive_article(article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return {"status": "archived", "article": article_to_dict(article)}


@router.post("/articles/{article_id}/review")
async def mark_review(article_id: str, current_user: dict = Depends(get_current_user)):
    """Flag article for review."""
    article = kb_service.mark_review_needed(article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return {"status": "review_needed", "article": article_to_dict(article)}


# ========== Search ==========

@router.get("/search")
async def search_articles(
    q: str = Query(..., min_length=1),
    category: Optional[str] = None,
    visibility: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Search KB articles by keyword."""
    vis_enum = ArticleVisibility(visibility) if visibility else None
    results = kb_service.search_articles(query=q, category=category, visibility=vis_enum)
    return {"results": [search_result_to_dict(r) for r in results], "count": len(results)}


# ========== Feedback ==========

@router.post("/articles/{article_id}/vote")
async def vote_article(article_id: str, request: VoteRequest, current_user: dict = Depends(get_current_user)):
    """Vote on whether an article was helpful."""
    if request.is_helpful:
        article = kb_service.vote_helpful(article_id)
    else:
        article = kb_service.vote_not_helpful(article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return {
        "status": "voted",
        "article_id": article_id,
        "helpful_votes": article.helpful_votes,
        "not_helpful_votes": article.not_helpful_votes,
    }


# ========== Categories ==========

@router.post("/categories")
async def create_category(request: CategoryCreate, current_user: dict = Depends(require_admin)):
    """Create a new category (admin only)."""
    cat = kb_service.create_category(
        name=request.name, description=request.description,
        parent_id=request.parent_id, icon=request.icon,
    )
    return {"status": "created", "category": category_to_dict(cat)}


@router.get("/categories")
async def list_categories(current_user: dict = Depends(get_current_user)):
    """List all categories."""
    cats = kb_service.list_categories()
    return {"categories": [category_to_dict(c) for c in cats], "count": len(cats)}


@router.get("/categories/{category_id}")
async def get_category(category_id: str, current_user: dict = Depends(get_current_user)):
    """Get a category by ID."""
    cat = kb_service.get_category(category_id)
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"category": category_to_dict(cat)}


@router.put("/categories/{category_id}")
async def update_category(category_id: str, request: CategoryUpdate, current_user: dict = Depends(require_admin)):
    """Update a category (admin only)."""
    updates = {k: v for k, v in request.dict().items() if v is not None}
    cat = kb_service.update_category(category_id, **updates)
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"status": "updated", "category": category_to_dict(cat)}


# ========== Documentation ==========

@router.post("/docs")
async def create_documentation(request: DocumentationCreate, current_user: dict = Depends(get_current_user)):
    """Create a client documentation entry."""
    try:
        doc_type = DocType(request.doc_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid doc_type: {request.doc_type}")
    expiry = None
    if request.expiry_date:
        try:
            expiry = datetime.fromisoformat(request.expiry_date)
        except ValueError:
            pass
    doc = kb_service.create_documentation(
        client_id=request.client_id, doc_type=doc_type,
        title=request.title, content=request.content,
        is_encrypted=request.is_encrypted, expiry_date=expiry,
    )
    return {"status": "created", "documentation": doc_to_dict(doc)}


@router.get("/docs")
async def list_documentation(
    client_id: Optional[str] = None,
    doc_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """List documentation entries."""
    dt = DocType(doc_type) if doc_type else None
    docs = kb_service.list_documentation(client_id=client_id, doc_type=dt)
    return {"documentation": [doc_to_dict(d) for d in docs], "count": len(docs)}


@router.get("/docs/{doc_id}")
async def get_documentation(doc_id: str, current_user: dict = Depends(get_current_user)):
    """Get a documentation entry by ID."""
    doc = kb_service.get_documentation(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Documentation not found")
    return {"documentation": doc_to_dict(doc)}


@router.put("/docs/{doc_id}")
async def update_documentation(doc_id: str, request: DocumentationUpdate, current_user: dict = Depends(get_current_user)):
    """Update a documentation entry."""
    updates = {}
    for k, v in request.dict().items():
        if v is not None:
            if k in ("last_verified", "expiry_date"):
                try:
                    updates[k] = datetime.fromisoformat(v)
                except ValueError:
                    pass
            else:
                updates[k] = v
    doc = kb_service.update_documentation(doc_id, **updates)
    if not doc:
        raise HTTPException(status_code=404, detail="Documentation not found")
    return {"status": "updated", "documentation": doc_to_dict(doc)}


@router.delete("/docs/{doc_id}")
async def delete_documentation(doc_id: str, current_user: dict = Depends(require_admin)):
    """Delete a documentation entry (admin only)."""
    deleted = kb_service.delete_documentation(doc_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Documentation not found")
    return {"status": "deleted", "doc_id": doc_id}


# ========== Auto-suggest & Auto-generate ==========

@router.post("/suggest-for-ticket")
async def suggest_for_ticket(request: TicketSuggestRequest, current_user: dict = Depends(get_current_user)):
    """Suggest KB articles relevant to a ticket."""
    results = kb_service.suggest_articles_for_ticket(request.dict())
    return {"suggestions": [search_result_to_dict(r) for r in results], "count": len(results)}


@router.post("/generate-from-ticket")
async def generate_from_ticket(request: GenerateFromTicketRequest, current_user: dict = Depends(get_current_user)):
    """Generate a KB article from a ticket resolution."""
    article = kb_service.generate_article_from_resolution(
        ticket_id=request.ticket_id, resolution=request.resolution,
        title=request.title, category=request.category, author=request.author,
    )
    return {"status": "created", "article": article_to_dict(article)}


# ========== Analytics ==========

@router.get("/analytics/top-viewed")
async def top_viewed(limit: int = Query(10, ge=1, le=50), current_user: dict = Depends(get_current_user)):
    """Get most viewed articles."""
    articles = kb_service.get_most_viewed(limit=limit)
    return {"articles": [article_to_dict(a) for a in articles], "count": len(articles)}


@router.get("/analytics/most-helpful")
async def most_helpful(limit: int = Query(10, ge=1, le=50), current_user: dict = Depends(get_current_user)):
    """Get articles with the most helpful votes."""
    articles = kb_service.get_most_helpful(limit=limit)
    return {"articles": [article_to_dict(a) for a in articles], "count": len(articles)}


@router.get("/analytics/search-gaps")
async def search_gaps(current_user: dict = Depends(get_current_user)):
    """Get searches that returned no results."""
    gaps = kb_service.get_search_gaps()
    return {"gaps": gaps, "count": len(gaps)}


@router.get("/analytics/stale")
async def stale_articles(days: int = Query(90, ge=1), current_user: dict = Depends(get_current_user)):
    """Get articles not updated in N days."""
    articles = kb_service.get_stale_articles(days=days)
    return {"articles": [article_to_dict(a) for a in articles], "count": len(articles)}


# ========== Dashboard ==========

@router.get("/dashboard")
async def dashboard(current_user: dict = Depends(get_current_user)):
    """Get KB dashboard metrics."""
    return kb_service.get_dashboard()
