"""
AITHER Platform - Knowledge Base & IT Documentation Service
Searchable knowledge base for MSP technicians and client portal users.

Provides:
- Article CRUD with publishing workflow
- Full-text keyword search with relevance scoring
- Category management with nesting
- Client documentation (runbooks, SOPs, configs, passwords, diagrams)
- Auto-suggest articles for tickets
- Auto-generate articles from ticket resolutions
- Analytics: top viewed, most helpful, search gaps, stale articles
- Dashboard metrics

G-46: DB persistence with in-memory fallback.
"""

import uuid
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.knowledge_base import (
        KBArticleModel,
        KBCategoryModel,
        DocumentationEntryModel,
        ArticleVoteModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class ArticleVisibility(str, Enum):
    INTERNAL = "internal"
    CLIENT = "client"
    PUBLIC = "public"


class ArticleStatus(str, Enum):
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"
    REVIEW_NEEDED = "review_needed"


class DocType(str, Enum):
    NETWORK_DIAGRAM = "network_diagram"
    PASSWORD_VAULT = "password_vault"
    RUNBOOK = "runbook"
    SOP = "sop"
    CONFIG_BACKUP = "config_backup"
    CONTACT_LIST = "contact_list"
    VENDOR_INFO = "vendor_info"
    ARCHITECTURE = "architecture"
    DISASTER_RECOVERY = "disaster_recovery"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class KBArticle:
    article_id: str
    title: str
    content_markdown: str
    category: str
    subcategory: str = ""
    tags: List[str] = field(default_factory=list)
    client_id: Optional[str] = None
    visibility: ArticleVisibility = ArticleVisibility.INTERNAL
    status: ArticleStatus = ArticleStatus.DRAFT
    author: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    views: int = 0
    helpful_votes: int = 0
    not_helpful_votes: int = 0
    related_articles: List[str] = field(default_factory=list)


@dataclass
class KBCategory:
    category_id: str
    name: str
    description: str = ""
    parent_id: Optional[str] = None
    article_count: int = 0
    icon: str = "folder"


@dataclass
class KBSearchResult:
    article_id: str
    title: str
    snippet: str
    relevance_score: float
    category: str
    tags: List[str] = field(default_factory=list)


@dataclass
class DocumentationEntry:
    doc_id: str
    client_id: str
    doc_type: DocType
    title: str
    content: str = ""
    is_encrypted: bool = False
    last_verified: Optional[datetime] = None
    verified_by: Optional[str] = None
    expiry_date: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RunbookStep:
    step_number: int
    title: str
    instructions: str
    expected_outcome: str = ""
    rollback_instructions: str = ""
    estimated_time_minutes: int = 5


# ============================================================
# Helper converters
# ============================================================

def _article_from_row(row) -> KBArticle:
    return KBArticle(
        article_id=row.article_id,
        title=row.title,
        content_markdown=row.content_markdown or "",
        category=row.category,
        subcategory=row.subcategory or "",
        tags=row.tags or [],
        client_id=row.client_id,
        visibility=ArticleVisibility(row.visibility) if row.visibility else ArticleVisibility.INTERNAL,
        status=ArticleStatus(row.status) if row.status else ArticleStatus.DRAFT,
        author=row.author or "",
        created_at=row.created_at or datetime.utcnow(),
        updated_at=row.updated_at or datetime.utcnow(),
        views=row.views or 0,
        helpful_votes=row.helpful_votes or 0,
        not_helpful_votes=row.not_helpful_votes or 0,
        related_articles=row.related_articles or [],
    )


def _category_from_row(row) -> KBCategory:
    return KBCategory(
        category_id=row.category_id,
        name=row.name,
        description=row.description or "",
        parent_id=row.parent_id,
        article_count=row.article_count or 0,
        icon=row.icon or "folder",
    )


def _doc_from_row(row) -> DocumentationEntry:
    return DocumentationEntry(
        doc_id=row.doc_id,
        client_id=row.client_id,
        doc_type=DocType(row.doc_type) if row.doc_type else DocType.SOP,
        title=row.title,
        content=row.content or "",
        is_encrypted=row.is_encrypted or False,
        last_verified=row.last_verified,
        verified_by=row.verified_by,
        expiry_date=row.expiry_date,
        created_at=row.created_at or datetime.utcnow(),
        updated_at=row.updated_at or datetime.utcnow(),
    )


# ============================================================
# Pre-seeded data
# ============================================================

_SEED_CATEGORIES = [
    ("CAT-001", "Getting Started", "Onboarding and initial setup guides", "book-open"),
    ("CAT-002", "Troubleshooting", "Common issue resolution guides", "wrench"),
    ("CAT-003", "How-To Guides", "Step-by-step instructions", "list-check"),
    ("CAT-004", "Security", "Security best practices and policies", "shield"),
    ("CAT-005", "Email", "Email setup and troubleshooting", "mail"),
    ("CAT-006", "Network", "Network connectivity and configuration", "wifi"),
    ("CAT-007", "Hardware", "Hardware setup and troubleshooting", "cpu"),
    ("CAT-008", "Software", "Software installation and configuration", "package"),
    ("CAT-009", "Policies", "Company IT policies and procedures", "file-text"),
    ("CAT-010", "Client-Specific", "Documentation specific to individual clients", "users"),
]

_SEED_ARTICLES = [
    {
        "article_id": "KB-001",
        "title": "How to Reset a User's Password in Active Directory",
        "category": "How-To Guides",
        "subcategory": "Active Directory",
        "tags": ["active-directory", "password", "reset", "user-management"],
        "visibility": ArticleVisibility.INTERNAL,
        "content_markdown": (
            "# How to Reset a User's Password in Active Directory\n\n"
            "## Prerequisites\n- Active Directory Users and Computers (ADUC) access\n"
            "- Domain Admin or delegated password reset permissions\n\n"
            "## Steps\n1. Open **Active Directory Users and Computers**\n"
            "2. Navigate to the user's OU\n3. Right-click the user account\n"
            "4. Select **Reset Password**\n5. Enter the new temporary password\n"
            "6. Check **User must change password at next logon**\n7. Click OK\n\n"
            "## Notes\n- Ensure the password meets complexity requirements\n"
            "- Inform the user of the temporary password via a secure channel"
        ),
        "author": "System",
    },
    {
        "article_id": "KB-002",
        "title": "Troubleshooting VPN Connection Issues",
        "category": "Troubleshooting",
        "subcategory": "VPN",
        "tags": ["vpn", "connectivity", "remote-access", "network"],
        "visibility": ArticleVisibility.CLIENT,
        "content_markdown": (
            "# Troubleshooting VPN Connection Issues\n\n"
            "## Common Causes\n- Incorrect credentials\n- Internet connectivity issues\n"
            "- VPN client outdated\n- Firewall blocking VPN traffic\n\n"
            "## Steps\n1. Verify your internet connection is working\n"
            "2. Check your VPN credentials are correct\n"
            "3. Restart the VPN client application\n"
            "4. Try connecting to a different VPN server\n"
            "5. Temporarily disable local firewall and retry\n"
            "6. Reinstall the VPN client if issues persist\n\n"
            "## Escalation\nIf none of the above resolves the issue, submit a ticket."
        ),
        "author": "System",
    },
    {
        "article_id": "KB-003",
        "title": "Setting Up Email on Mobile Devices (iOS/Android)",
        "category": "How-To Guides",
        "subcategory": "Email",
        "tags": ["email", "mobile", "ios", "android", "setup"],
        "visibility": ArticleVisibility.CLIENT,
        "content_markdown": (
            "# Setting Up Email on Mobile Devices\n\n"
            "## iOS (iPhone/iPad)\n1. Go to **Settings > Mail > Accounts > Add Account**\n"
            "2. Select **Microsoft Exchange** or **Other**\n"
            "3. Enter your email address and password\n"
            "4. Verify server settings if prompted\n\n"
            "## Android\n1. Open the **Gmail** app\n"
            "2. Tap your profile icon > **Add another account**\n"
            "3. Select **Exchange and Office 365**\n"
            "4. Enter your email and password\n"
            "5. Accept any security permissions\n\n"
            "## Server Settings\n- Server: mail.company.com\n- Port: 443\n- Security: SSL/TLS"
        ),
        "author": "System",
    },
    {
        "article_id": "KB-004",
        "title": "Printer Not Printing - Troubleshooting Guide",
        "category": "Troubleshooting",
        "subcategory": "Printers",
        "tags": ["printer", "troubleshooting", "hardware", "print-spooler"],
        "visibility": ArticleVisibility.CLIENT,
        "content_markdown": (
            "# Printer Not Printing - Troubleshooting Guide\n\n"
            "## Quick Fixes\n1. Check the printer is powered on and connected\n"
            "2. Verify paper tray is loaded and no paper jams\n"
            "3. Check ink/toner levels\n\n"
            "## Software Steps\n1. Open **Settings > Printers & Scanners**\n"
            "2. Verify the correct printer is set as default\n"
            "3. Clear the print queue\n4. Restart the Print Spooler service:\n"
            "   - Open Services (services.msc)\n   - Find Print Spooler\n"
            "   - Right-click > Restart\n\n"
            "## Network Printers\n- Verify the printer IP is reachable (ping test)\n"
            "- Reinstall the printer driver if needed"
        ),
        "author": "System",
    },
    {
        "article_id": "KB-005",
        "title": "How to Request New Software Installation",
        "category": "How-To Guides",
        "subcategory": "Software",
        "tags": ["software", "installation", "request", "policy"],
        "visibility": ArticleVisibility.CLIENT,
        "content_markdown": (
            "# How to Request New Software Installation\n\n"
            "## Process\n1. Submit a ticket through the client portal\n"
            "2. Include the software name and version needed\n"
            "3. Provide business justification\n"
            "4. Your manager will receive an approval request\n\n"
            "## Approved Software List\nSee the approved software catalog in the portal.\n\n"
            "## Timeline\n- Pre-approved software: 1 business day\n"
            "- New software requiring approval: 3-5 business days\n"
            "- Enterprise software: may require additional licensing review"
        ),
        "author": "System",
    },
    {
        "article_id": "KB-006",
        "title": "WiFi Connectivity Troubleshooting",
        "category": "Troubleshooting",
        "subcategory": "Network",
        "tags": ["wifi", "wireless", "connectivity", "network"],
        "visibility": ArticleVisibility.CLIENT,
        "content_markdown": (
            "# WiFi Connectivity Troubleshooting\n\n"
            "## Steps\n1. Toggle WiFi off and on\n"
            "2. Forget the network and reconnect\n"
            "3. Restart your device\n"
            "4. Move closer to the access point\n"
            "5. Check if other devices can connect\n"
            "6. Run network diagnostics (Windows: right-click WiFi icon > Troubleshoot)\n\n"
            "## Advanced\n- Flush DNS: `ipconfig /flushdns`\n"
            "- Reset network stack: `netsh winsock reset`\n"
            "- Update WiFi driver from Device Manager"
        ),
        "author": "System",
    },
    {
        "article_id": "KB-007",
        "title": "Outlook Not Syncing - Common Fixes",
        "category": "Troubleshooting",
        "subcategory": "Email",
        "tags": ["outlook", "email", "sync", "office365"],
        "visibility": ArticleVisibility.CLIENT,
        "content_markdown": (
            "# Outlook Not Syncing - Common Fixes\n\n"
            "## Steps\n1. Check your internet connection\n"
            "2. Look for **Disconnected** or **Need Password** in the status bar\n"
            "3. Toggle Work Offline: **Send/Receive > Work Offline**\n"
            "4. Repair the Outlook profile:\n"
            "   - Control Panel > Mail > Show Profiles > Repair\n"
            "5. Clear the Outlook cache:\n"
            "   - Close Outlook\n   - Delete files in `%localappdata%\\Microsoft\\Outlook\\RoamCache`\n"
            "6. Create a new Outlook profile if repair fails\n\n"
            "## Office 365 Specific\n- Sign out and back into your Microsoft account\n"
            "- Run the Microsoft Support and Recovery Assistant (SaRA)"
        ),
        "author": "System",
    },
    {
        "article_id": "KB-008",
        "title": "How to Connect to Remote Desktop",
        "category": "How-To Guides",
        "subcategory": "Remote Access",
        "tags": ["rdp", "remote-desktop", "remote-access", "connection"],
        "visibility": ArticleVisibility.CLIENT,
        "content_markdown": (
            "# How to Connect to Remote Desktop\n\n"
            "## Windows\n1. Press **Win + R**, type `mstsc`, press Enter\n"
            "2. Enter the computer name or IP address\n"
            "3. Click **Connect**\n4. Enter your domain credentials\n\n"
            "## macOS\n1. Download **Microsoft Remote Desktop** from the App Store\n"
            "2. Click **Add PC**\n3. Enter the PC name or IP\n"
            "4. Add your user account credentials\n\n"
            "## Troubleshooting\n- Ensure Remote Desktop is enabled on the target PC\n"
            "- Check that port 3389 is not blocked by firewall\n"
            "- Verify you are on the VPN if connecting remotely"
        ),
        "author": "System",
    },
    {
        "article_id": "KB-009",
        "title": "Security Best Practices for End Users",
        "category": "Security",
        "subcategory": "Awareness",
        "tags": ["security", "best-practices", "awareness", "training"],
        "visibility": ArticleVisibility.PUBLIC,
        "content_markdown": (
            "# Security Best Practices for End Users\n\n"
            "## Password Security\n- Use unique passwords for each account\n"
            "- Enable multi-factor authentication (MFA)\n"
            "- Never share passwords via email or chat\n\n"
            "## Email Safety\n- Do not click links from unknown senders\n"
            "- Verify unexpected attachments before opening\n"
            "- Report suspicious emails to IT\n\n"
            "## Device Security\n- Lock your computer when stepping away (Win+L)\n"
            "- Keep your OS and software updated\n"
            "- Do not install unapproved software\n\n"
            "## Data Protection\n- Save files to approved cloud storage\n"
            "- Do not copy sensitive data to USB drives without approval"
        ),
        "author": "System",
    },
    {
        "article_id": "KB-010",
        "title": "What to Do If You Suspect a Phishing Email",
        "category": "Security",
        "subcategory": "Phishing",
        "tags": ["phishing", "security", "email", "incident-response"],
        "visibility": ArticleVisibility.PUBLIC,
        "content_markdown": (
            "# What to Do If You Suspect a Phishing Email\n\n"
            "## Do NOT\n- Click any links in the email\n"
            "- Download or open attachments\n- Reply to the sender\n"
            "- Forward it to colleagues\n\n"
            "## Do\n1. **Report it**: Use the **Report Phishing** button in Outlook\n"
            "2. If no button: forward the email as an attachment to security@company.com\n"
            "3. Delete the email from your inbox\n"
            "4. If you clicked a link or entered credentials:\n"
            "   - Change your password immediately\n"
            "   - Contact IT support right away\n"
            "   - Note the time and what you clicked\n\n"
            "## How to Identify Phishing\n- Sender address doesn't match the organization\n"
            "- Urgent language: 'Act now' or 'Account suspended'\n"
            "- Generic greeting: 'Dear Customer'\n"
            "- Suspicious links (hover to check URL)"
        ),
        "author": "System",
    },
]


# ============================================================
# Service
# ============================================================

class KnowledgeBaseService:
    """
    Knowledge Base & IT Documentation service.

    Manages KB articles, categories, client documentation,
    search, auto-suggest, and analytics.
    Accepts optional db: Session for persistence.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE
        self.articles: Dict[str, KBArticle] = {}
        self.categories: Dict[str, KBCategory] = {}
        self.documentation: Dict[str, DocumentationEntry] = {}
        self._search_log: List[Dict[str, Any]] = []

        # Hydrate from DB or seed defaults
        if self._use_db:
            self._hydrate_from_db()
        else:
            self._seed_defaults()

    # ------ DB hydration ------

    def _hydrate_from_db(self) -> None:
        try:
            for row in self.db.query(KBArticleModel).all():
                a = _article_from_row(row)
                self.articles[a.article_id] = a
            for row in self.db.query(KBCategoryModel).all():
                c = _category_from_row(row)
                self.categories[c.category_id] = c
            for row in self.db.query(DocumentationEntryModel).all():
                d = _doc_from_row(row)
                self.documentation[d.doc_id] = d
        except Exception as e:
            logger.error(f"DB hydration error: {e}")

        # Seed if empty
        if not self.categories:
            self._seed_categories()
        if not self.articles:
            self._seed_articles()

    def _seed_defaults(self) -> None:
        self._seed_categories()
        self._seed_articles()

    def _seed_categories(self) -> None:
        for cid, name, desc, icon in _SEED_CATEGORIES:
            cat = KBCategory(category_id=cid, name=name, description=desc, icon=icon)
            self.categories[cid] = cat
            self._persist_category(cat)

    def _seed_articles(self) -> None:
        for data in _SEED_ARTICLES:
            art = KBArticle(
                article_id=data["article_id"],
                title=data["title"],
                content_markdown=data.get("content_markdown", ""),
                category=data["category"],
                subcategory=data.get("subcategory", ""),
                tags=data.get("tags", []),
                visibility=data.get("visibility", ArticleVisibility.INTERNAL),
                status=ArticleStatus.PUBLISHED,
                author=data.get("author", "System"),
            )
            self.articles[art.article_id] = art
            self._persist_article(art)

    # ------ Persistence helpers ------

    def _persist_article(self, article: KBArticle) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(KBArticleModel).filter(
                KBArticleModel.article_id == article.article_id
            ).first()
            vals = dict(
                title=article.title,
                content_markdown=article.content_markdown,
                category=article.category,
                subcategory=article.subcategory,
                tags=article.tags,
                client_id=article.client_id,
                visibility=article.visibility.value if isinstance(article.visibility, ArticleVisibility) else article.visibility,
                status=article.status.value if isinstance(article.status, ArticleStatus) else article.status,
                author=article.author,
                views=article.views,
                helpful_votes=article.helpful_votes,
                not_helpful_votes=article.not_helpful_votes,
                related_articles=article.related_articles,
            )
            if existing:
                for k, v in vals.items():
                    setattr(existing, k, v)
            else:
                row = KBArticleModel(article_id=article.article_id, **vals)
                self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist article error: {e}")

    def _persist_category(self, cat: KBCategory) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(KBCategoryModel).filter(
                KBCategoryModel.category_id == cat.category_id
            ).first()
            vals = dict(
                name=cat.name,
                description=cat.description,
                parent_id=cat.parent_id,
                article_count=cat.article_count,
                icon=cat.icon,
            )
            if existing:
                for k, v in vals.items():
                    setattr(existing, k, v)
            else:
                row = KBCategoryModel(category_id=cat.category_id, **vals)
                self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist category error: {e}")

    def _persist_doc(self, doc: DocumentationEntry) -> None:
        if not self._use_db:
            return
        try:
            existing = self.db.query(DocumentationEntryModel).filter(
                DocumentationEntryModel.doc_id == doc.doc_id
            ).first()
            vals = dict(
                client_id=doc.client_id,
                doc_type=doc.doc_type.value if isinstance(doc.doc_type, DocType) else doc.doc_type,
                title=doc.title,
                content=doc.content,
                is_encrypted=doc.is_encrypted,
                last_verified=doc.last_verified,
                verified_by=doc.verified_by,
                expiry_date=doc.expiry_date,
            )
            if existing:
                for k, v in vals.items():
                    setattr(existing, k, v)
            else:
                row = DocumentationEntryModel(doc_id=doc.doc_id, **vals)
                self.db.add(row)
            self.db.commit()
        except Exception as e:
            logger.error(f"DB persist doc error: {e}")

    def _delete_article_db(self, article_id: str) -> None:
        if not self._use_db:
            return
        try:
            self.db.query(KBArticleModel).filter(
                KBArticleModel.article_id == article_id
            ).delete()
            self.db.commit()
        except Exception as e:
            logger.error(f"DB delete article error: {e}")

    def _delete_doc_db(self, doc_id: str) -> None:
        if not self._use_db:
            return
        try:
            self.db.query(DocumentationEntryModel).filter(
                DocumentationEntryModel.doc_id == doc_id
            ).delete()
            self.db.commit()
        except Exception as e:
            logger.error(f"DB delete doc error: {e}")

    # ============================================================
    # Article CRUD
    # ============================================================

    def create_article(
        self,
        title: str,
        content_markdown: str,
        category: str,
        subcategory: str = "",
        tags: List[str] = None,
        client_id: Optional[str] = None,
        visibility: ArticleVisibility = ArticleVisibility.INTERNAL,
        author: str = "",
        related_articles: List[str] = None,
    ) -> KBArticle:
        """Create a new KB article in draft status."""
        article_id = f"KB-{uuid.uuid4().hex[:8].upper()}"
        article = KBArticle(
            article_id=article_id,
            title=title,
            content_markdown=content_markdown,
            category=category,
            subcategory=subcategory,
            tags=tags or [],
            client_id=client_id,
            visibility=visibility,
            status=ArticleStatus.DRAFT,
            author=author,
            related_articles=related_articles or [],
        )
        self.articles[article_id] = article
        self._persist_article(article)
        self._update_category_counts()
        logger.info(f"Created KB article {article_id}: {title}")
        return article

    def get_article(self, article_id: str) -> Optional[KBArticle]:
        """Get an article by ID, incrementing view count."""
        article = self.articles.get(article_id)
        if article:
            article.views += 1
            article.updated_at = datetime.utcnow()
            self._persist_article(article)
        return article

    def update_article(self, article_id: str, **kwargs) -> Optional[KBArticle]:
        """Update article fields."""
        article = self.articles.get(article_id)
        if not article:
            return None
        for key, val in kwargs.items():
            if hasattr(article, key) and key not in ("article_id", "created_at"):
                setattr(article, key, val)
        article.updated_at = datetime.utcnow()
        self._persist_article(article)
        self._update_category_counts()
        return article

    def delete_article(self, article_id: str) -> bool:
        """Delete an article."""
        if article_id not in self.articles:
            return False
        del self.articles[article_id]
        self._delete_article_db(article_id)
        self._update_category_counts()
        return True

    def list_articles(
        self,
        category: Optional[str] = None,
        status: Optional[ArticleStatus] = None,
        visibility: Optional[ArticleVisibility] = None,
        client_id: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[KBArticle]:
        """List articles with optional filters."""
        results = list(self.articles.values())
        if category:
            results = [a for a in results if a.category == category]
        if status:
            results = [a for a in results if a.status == status]
        if visibility:
            results = [a for a in results if a.visibility == visibility]
        if client_id:
            results = [a for a in results if a.client_id == client_id or a.client_id is None]
        if tag:
            results = [a for a in results if tag in a.tags]
        return sorted(results, key=lambda a: a.updated_at, reverse=True)

    # ============================================================
    # Publishing workflow
    # ============================================================

    def publish_article(self, article_id: str) -> Optional[KBArticle]:
        """Publish a draft article."""
        return self.update_article(article_id, status=ArticleStatus.PUBLISHED)

    def archive_article(self, article_id: str) -> Optional[KBArticle]:
        """Archive an article."""
        return self.update_article(article_id, status=ArticleStatus.ARCHIVED)

    def mark_review_needed(self, article_id: str) -> Optional[KBArticle]:
        """Flag an article for review."""
        return self.update_article(article_id, status=ArticleStatus.REVIEW_NEEDED)

    # ============================================================
    # Search
    # ============================================================

    def search_articles(
        self,
        query: str,
        category: Optional[str] = None,
        visibility: Optional[ArticleVisibility] = None,
        status: Optional[ArticleStatus] = None,
    ) -> List[KBSearchResult]:
        """
        Keyword search across articles with relevance scoring.

        Scoring:
        - Title exact match: +10
        - Title word match: +3 per word
        - Tag match: +5 per tag
        - Content word match: +1 per word
        - Category match: +2
        """
        if not query or not query.strip():
            return []

        query_lower = query.lower().strip()
        words = re.split(r'\s+', query_lower)
        results: List[KBSearchResult] = []

        candidates = list(self.articles.values())
        if category:
            candidates = [a for a in candidates if a.category == category]
        if visibility:
            candidates = [a for a in candidates if a.visibility == visibility]
        if status:
            candidates = [a for a in candidates if a.status == status]
        else:
            # Default to published articles for search
            candidates = [a for a in candidates if a.status == ArticleStatus.PUBLISHED]

        for article in candidates:
            score = 0.0
            title_lower = article.title.lower()
            content_lower = article.content_markdown.lower()
            tags_lower = [t.lower() for t in article.tags]

            # Title exact match
            if query_lower in title_lower:
                score += 10.0

            # Title word matches
            for w in words:
                if w in title_lower:
                    score += 3.0

            # Tag matches
            for w in words:
                for tag in tags_lower:
                    if w in tag:
                        score += 5.0

            # Content word matches
            for w in words:
                count = content_lower.count(w)
                score += min(count, 5) * 1.0  # cap at 5 per word

            # Category match
            if query_lower in article.category.lower():
                score += 2.0

            if score > 0:
                # Build snippet
                snippet = self._extract_snippet(article.content_markdown, words)
                results.append(KBSearchResult(
                    article_id=article.article_id,
                    title=article.title,
                    snippet=snippet,
                    relevance_score=round(score, 2),
                    category=article.category,
                    tags=article.tags,
                ))

        # Log the search
        self._search_log.append({
            "query": query,
            "results_count": len(results),
            "timestamp": datetime.utcnow().isoformat(),
        })

        results.sort(key=lambda r: r.relevance_score, reverse=True)
        return results

    def _extract_snippet(self, content: str, words: List[str], max_len: int = 200) -> str:
        """Extract a snippet around the first matching word."""
        content_clean = re.sub(r'[#*_\[\]()]', '', content)
        lower = content_clean.lower()
        best_pos = len(lower)
        for w in words:
            pos = lower.find(w)
            if 0 <= pos < best_pos:
                best_pos = pos
        start = max(0, best_pos - 40)
        end = min(len(content_clean), start + max_len)
        snippet = content_clean[start:end].strip()
        if start > 0:
            snippet = "..." + snippet
        if end < len(content_clean):
            snippet = snippet + "..."
        return snippet

    # ============================================================
    # Feedback
    # ============================================================

    def vote_helpful(self, article_id: str) -> Optional[KBArticle]:
        """Record a helpful vote."""
        article = self.articles.get(article_id)
        if not article:
            return None
        article.helpful_votes += 1
        self._persist_article(article)
        if self._use_db:
            try:
                vote = ArticleVoteModel(article_id=article_id, is_helpful=True)
                self.db.add(vote)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB vote error: {e}")
        return article

    def vote_not_helpful(self, article_id: str) -> Optional[KBArticle]:
        """Record a not-helpful vote."""
        article = self.articles.get(article_id)
        if not article:
            return None
        article.not_helpful_votes += 1
        self._persist_article(article)
        if self._use_db:
            try:
                vote = ArticleVoteModel(article_id=article_id, is_helpful=False)
                self.db.add(vote)
                self.db.commit()
            except Exception as e:
                logger.error(f"DB vote error: {e}")
        return article

    # ============================================================
    # Categories
    # ============================================================

    def create_category(
        self,
        name: str,
        description: str = "",
        parent_id: Optional[str] = None,
        icon: str = "folder",
    ) -> KBCategory:
        """Create a new category."""
        category_id = f"CAT-{uuid.uuid4().hex[:6].upper()}"
        cat = KBCategory(
            category_id=category_id,
            name=name,
            description=description,
            parent_id=parent_id,
            icon=icon,
        )
        self.categories[category_id] = cat
        self._persist_category(cat)
        return cat

    def get_category(self, category_id: str) -> Optional[KBCategory]:
        """Get a category by ID."""
        return self.categories.get(category_id)

    def list_categories(self) -> List[KBCategory]:
        """List all categories."""
        return sorted(self.categories.values(), key=lambda c: c.name)

    def update_category(self, category_id: str, **kwargs) -> Optional[KBCategory]:
        """Update category fields."""
        cat = self.categories.get(category_id)
        if not cat:
            return None
        for key, val in kwargs.items():
            if hasattr(cat, key) and key != "category_id":
                setattr(cat, key, val)
        self._persist_category(cat)
        return cat

    def _update_category_counts(self) -> None:
        """Recount articles per category."""
        counts: Dict[str, int] = {}
        for a in self.articles.values():
            counts[a.category] = counts.get(a.category, 0) + 1
        for cat in self.categories.values():
            cat.article_count = counts.get(cat.name, 0)

    # ============================================================
    # Documentation
    # ============================================================

    def create_documentation(
        self,
        client_id: str,
        doc_type: DocType,
        title: str,
        content: str = "",
        is_encrypted: bool = False,
        expiry_date: Optional[datetime] = None,
    ) -> DocumentationEntry:
        """Create a client documentation entry."""
        doc_id = f"DOC-{uuid.uuid4().hex[:8].upper()}"
        doc = DocumentationEntry(
            doc_id=doc_id,
            client_id=client_id,
            doc_type=doc_type,
            title=title,
            content=content,
            is_encrypted=is_encrypted,
            expiry_date=expiry_date,
        )
        self.documentation[doc_id] = doc
        self._persist_doc(doc)
        logger.info(f"Created documentation {doc_id}: {title}")
        return doc

    def get_documentation(self, doc_id: str) -> Optional[DocumentationEntry]:
        """Get a documentation entry by ID."""
        return self.documentation.get(doc_id)

    def list_documentation(
        self,
        client_id: Optional[str] = None,
        doc_type: Optional[DocType] = None,
    ) -> List[DocumentationEntry]:
        """List documentation entries with optional filters."""
        results = list(self.documentation.values())
        if client_id:
            results = [d for d in results if d.client_id == client_id]
        if doc_type:
            results = [d for d in results if d.doc_type == doc_type]
        return sorted(results, key=lambda d: d.updated_at, reverse=True)

    def update_documentation(self, doc_id: str, **kwargs) -> Optional[DocumentationEntry]:
        """Update documentation fields."""
        doc = self.documentation.get(doc_id)
        if not doc:
            return None
        for key, val in kwargs.items():
            if hasattr(doc, key) and key not in ("doc_id", "created_at"):
                setattr(doc, key, val)
        doc.updated_at = datetime.utcnow()
        self._persist_doc(doc)
        return doc

    def delete_documentation(self, doc_id: str) -> bool:
        """Delete a documentation entry."""
        if doc_id not in self.documentation:
            return False
        del self.documentation[doc_id]
        self._delete_doc_db(doc_id)
        return True

    # ============================================================
    # Auto-suggest & Auto-generate
    # ============================================================

    def suggest_articles_for_ticket(self, ticket_data: Dict[str, Any]) -> List[KBSearchResult]:
        """
        Suggest relevant KB articles based on ticket title/description/category.
        Combines keywords from ticket fields for a relevance search.
        """
        parts = []
        if ticket_data.get("title"):
            parts.append(ticket_data["title"])
        if ticket_data.get("description"):
            parts.append(ticket_data["description"])
        if ticket_data.get("category"):
            parts.append(ticket_data["category"])
        query = " ".join(parts)
        if not query.strip():
            return []
        return self.search_articles(query)[:5]

    def generate_article_from_resolution(
        self,
        ticket_id: str,
        resolution: str,
        title: Optional[str] = None,
        category: str = "Troubleshooting",
        author: str = "Auto-Generated",
    ) -> KBArticle:
        """
        Generate a KB article from a resolved ticket's resolution notes.
        """
        if not title:
            title = f"Resolution: Ticket {ticket_id}"

        content = (
            f"# {title}\n\n"
            f"*Auto-generated from ticket {ticket_id}*\n\n"
            f"## Resolution\n{resolution}\n\n"
            f"## Related Ticket\n- Ticket ID: {ticket_id}\n"
        )

        return self.create_article(
            title=title,
            content_markdown=content,
            category=category,
            tags=["auto-generated", f"ticket-{ticket_id}"],
            author=author,
        )

    # ============================================================
    # Analytics
    # ============================================================

    def get_most_viewed(self, limit: int = 10) -> List[KBArticle]:
        """Get the most viewed articles."""
        articles = sorted(self.articles.values(), key=lambda a: a.views, reverse=True)
        return articles[:limit]

    def get_most_helpful(self, limit: int = 10) -> List[KBArticle]:
        """Get articles with the highest helpful votes."""
        articles = sorted(self.articles.values(), key=lambda a: a.helpful_votes, reverse=True)
        return articles[:limit]

    def get_search_gaps(self) -> List[Dict[str, Any]]:
        """Get search queries that returned zero results."""
        return [
            entry for entry in self._search_log
            if entry["results_count"] == 0
        ]

    def get_stale_articles(self, days: int = 90) -> List[KBArticle]:
        """Get articles not updated in the specified number of days."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        return [
            a for a in self.articles.values()
            if a.updated_at < cutoff and a.status == ArticleStatus.PUBLISHED
        ]

    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard summary metrics."""
        now = datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        total_articles = len(self.articles)
        published = sum(1 for a in self.articles.values() if a.status == ArticleStatus.PUBLISHED)
        drafts = sum(1 for a in self.articles.values() if a.status == ArticleStatus.DRAFT)
        archived = sum(1 for a in self.articles.values() if a.status == ArticleStatus.ARCHIVED)
        review_needed = sum(1 for a in self.articles.values() if a.status == ArticleStatus.REVIEW_NEEDED)

        total_views = sum(a.views for a in self.articles.values())
        total_docs = len(self.documentation)
        total_categories = len(self.categories)

        # Search volume this month
        search_volume = sum(
            1 for s in self._search_log
            if s.get("timestamp", "") >= month_start.isoformat()
        )

        gaps = self.get_search_gaps()
        stale = self.get_stale_articles()

        return {
            "total_articles": total_articles,
            "published": published,
            "drafts": drafts,
            "archived": archived,
            "review_needed": review_needed,
            "total_views": total_views,
            "total_documentation": total_docs,
            "total_categories": total_categories,
            "search_volume_this_month": search_volume,
            "search_gaps_count": len(gaps),
            "stale_articles_count": len(stale),
        }
