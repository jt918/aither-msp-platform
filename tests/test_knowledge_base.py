"""
Tests for Knowledge Base & IT Documentation Service
"""

import pytest
from datetime import datetime, timedelta

from services.msp.knowledge_base import (
    KnowledgeBaseService,
    ArticleVisibility,
    ArticleStatus,
    DocType,
    KBArticle,
    KBCategory,
    KBSearchResult,
    DocumentationEntry,
    RunbookStep,
)


class TestKnowledgeBaseService:
    """Tests for KnowledgeBaseService"""

    def setup_method(self):
        """Set up test fixtures"""
        self.service = KnowledgeBaseService()

    # ========== Seed Data Tests ==========

    def test_seed_categories(self):
        """Test that default categories are seeded"""
        cats = self.service.list_categories()
        assert len(cats) == 10
        names = [c.name for c in cats]
        assert "Troubleshooting" in names
        assert "Security" in names
        assert "How-To Guides" in names
        assert "Getting Started" in names

    def test_seed_articles(self):
        """Test that 10 default articles are seeded"""
        articles = self.service.list_articles(status=ArticleStatus.PUBLISHED)
        assert len(articles) == 10

    def test_seed_article_content(self):
        """Test seeded article has correct content"""
        article = self.service.get_article("KB-001")
        assert article is not None
        assert article.title == "How to Reset a User's Password in Active Directory"
        assert "Active Directory" in article.content_markdown
        assert article.status == ArticleStatus.PUBLISHED

    # ========== Article CRUD Tests ==========

    def test_create_article(self):
        """Test creating a new article"""
        article = self.service.create_article(
            title="Test Article",
            content_markdown="# Test\nSome content here",
            category="Troubleshooting",
            subcategory="Testing",
            tags=["test", "demo"],
            author="Tester",
        )
        assert article is not None
        assert article.article_id.startswith("KB-")
        assert article.title == "Test Article"
        assert article.status == ArticleStatus.DRAFT
        assert "test" in article.tags

    def test_create_article_unique_id(self):
        """Test articles get unique IDs"""
        a1 = self.service.create_article(
            title="A1", content_markdown="c1", category="Test"
        )
        a2 = self.service.create_article(
            title="A2", content_markdown="c2", category="Test"
        )
        assert a1.article_id != a2.article_id

    def test_get_article(self):
        """Test getting an article by ID"""
        article = self.service.create_article(
            title="Get Test", content_markdown="body", category="Test"
        )
        fetched = self.service.get_article(article.article_id)
        assert fetched is not None
        assert fetched.title == "Get Test"

    def test_get_article_increments_views(self):
        """Test that getting an article increments view count"""
        article = self.service.create_article(
            title="Views Test", content_markdown="body", category="Test"
        )
        initial_views = article.views
        self.service.get_article(article.article_id)
        assert article.views == initial_views + 1

    def test_get_article_not_found(self):
        """Test getting nonexistent article returns None"""
        assert self.service.get_article("KB-NONEXISTENT") is None

    def test_update_article(self):
        """Test updating article fields"""
        article = self.service.create_article(
            title="Original", content_markdown="body", category="Test"
        )
        updated = self.service.update_article(
            article.article_id, title="Updated Title", tags=["new-tag"]
        )
        assert updated is not None
        assert updated.title == "Updated Title"
        assert "new-tag" in updated.tags

    def test_update_article_not_found(self):
        """Test updating nonexistent article returns None"""
        assert self.service.update_article("KB-NOPE", title="X") is None

    def test_delete_article(self):
        """Test deleting an article"""
        article = self.service.create_article(
            title="Delete Me", content_markdown="x", category="Test"
        )
        assert self.service.delete_article(article.article_id) is True
        assert self.service.get_article(article.article_id) is None

    def test_delete_article_not_found(self):
        """Test deleting nonexistent article returns False"""
        assert self.service.delete_article("KB-NOPE") is False

    def test_list_articles_no_filter(self):
        """Test listing all articles"""
        articles = self.service.list_articles()
        assert len(articles) >= 10  # seeded articles

    def test_list_articles_by_category(self):
        """Test listing articles filtered by category"""
        articles = self.service.list_articles(category="Security")
        assert len(articles) >= 2
        for a in articles:
            assert a.category == "Security"

    def test_list_articles_by_status(self):
        """Test listing articles filtered by status"""
        self.service.create_article(
            title="Draft Article", content_markdown="x", category="Test"
        )
        drafts = self.service.list_articles(status=ArticleStatus.DRAFT)
        assert len(drafts) >= 1
        for a in drafts:
            assert a.status == ArticleStatus.DRAFT

    def test_list_articles_by_visibility(self):
        """Test listing articles filtered by visibility"""
        public = self.service.list_articles(visibility=ArticleVisibility.PUBLIC)
        assert len(public) >= 2  # KB-009, KB-010
        for a in public:
            assert a.visibility == ArticleVisibility.PUBLIC

    def test_list_articles_by_tag(self):
        """Test listing articles by tag"""
        articles = self.service.list_articles(tag="security")
        assert len(articles) >= 2

    # ========== Publishing Workflow Tests ==========

    def test_publish_article(self):
        """Test publishing a draft article"""
        article = self.service.create_article(
            title="Publish Me", content_markdown="x", category="Test"
        )
        assert article.status == ArticleStatus.DRAFT
        published = self.service.publish_article(article.article_id)
        assert published is not None
        assert published.status == ArticleStatus.PUBLISHED

    def test_archive_article(self):
        """Test archiving an article"""
        article = self.service.create_article(
            title="Archive Me", content_markdown="x", category="Test"
        )
        archived = self.service.archive_article(article.article_id)
        assert archived.status == ArticleStatus.ARCHIVED

    def test_mark_review_needed(self):
        """Test flagging article for review"""
        article = self.service.create_article(
            title="Review Me", content_markdown="x", category="Test"
        )
        reviewed = self.service.mark_review_needed(article.article_id)
        assert reviewed.status == ArticleStatus.REVIEW_NEEDED

    def test_publish_not_found(self):
        """Test publishing nonexistent article"""
        assert self.service.publish_article("KB-NOPE") is None

    # ========== Search Tests ==========

    def test_search_by_title(self):
        """Test searching by title keyword"""
        results = self.service.search_articles("password")
        assert len(results) >= 1
        assert any("Password" in r.title for r in results)

    def test_search_by_tag(self):
        """Test searching matches tags"""
        results = self.service.search_articles("phishing")
        assert len(results) >= 1
        assert any("phishing" in r.tags for r in results)

    def test_search_relevance_ordering(self):
        """Test that results are ordered by relevance score"""
        results = self.service.search_articles("email")
        if len(results) > 1:
            for i in range(len(results) - 1):
                assert results[i].relevance_score >= results[i + 1].relevance_score

    def test_search_empty_query(self):
        """Test empty query returns no results"""
        assert self.service.search_articles("") == []
        assert self.service.search_articles("   ") == []

    def test_search_no_results(self):
        """Test search with no matches"""
        results = self.service.search_articles("xyzzynonexistent123")
        assert len(results) == 0

    def test_search_logs_gap(self):
        """Test that searches with no results are logged as gaps"""
        self.service.search_articles("totallyuniquenonsense999")
        gaps = self.service.get_search_gaps()
        assert len(gaps) >= 1
        assert any("totallyuniquenonsense999" in g["query"] for g in gaps)

    def test_search_with_category_filter(self):
        """Test search with category filter"""
        results = self.service.search_articles("email", category="Troubleshooting")
        for r in results:
            assert r.category == "Troubleshooting"

    def test_search_result_has_snippet(self):
        """Test search results include snippets"""
        results = self.service.search_articles("VPN")
        assert len(results) >= 1
        assert results[0].snippet != ""

    # ========== Feedback Tests ==========

    def test_vote_helpful(self):
        """Test voting an article as helpful"""
        article = self.service.create_article(
            title="Vote Test", content_markdown="x", category="Test"
        )
        self.service.publish_article(article.article_id)
        result = self.service.vote_helpful(article.article_id)
        assert result.helpful_votes == 1

    def test_vote_not_helpful(self):
        """Test voting an article as not helpful"""
        article = self.service.create_article(
            title="Vote Test 2", content_markdown="x", category="Test"
        )
        result = self.service.vote_not_helpful(article.article_id)
        assert result.not_helpful_votes == 1

    def test_vote_multiple(self):
        """Test multiple votes accumulate"""
        article = self.service.create_article(
            title="Multi Vote", content_markdown="x", category="Test"
        )
        self.service.vote_helpful(article.article_id)
        self.service.vote_helpful(article.article_id)
        self.service.vote_not_helpful(article.article_id)
        assert article.helpful_votes == 2
        assert article.not_helpful_votes == 1

    def test_vote_not_found(self):
        """Test voting on nonexistent article"""
        assert self.service.vote_helpful("KB-NOPE") is None
        assert self.service.vote_not_helpful("KB-NOPE") is None

    # ========== Category Tests ==========

    def test_create_category(self):
        """Test creating a new category"""
        cat = self.service.create_category(
            name="Custom Category", description="A custom cat", icon="star"
        )
        assert cat.category_id.startswith("CAT-")
        assert cat.name == "Custom Category"
        assert cat.icon == "star"

    def test_get_category(self):
        """Test getting a category by ID"""
        cat = self.service.get_category("CAT-001")
        assert cat is not None
        assert cat.name == "Getting Started"

    def test_get_category_not_found(self):
        """Test getting nonexistent category"""
        assert self.service.get_category("CAT-NOPE") is None

    def test_list_categories(self):
        """Test listing categories returns sorted list"""
        cats = self.service.list_categories()
        assert len(cats) >= 10
        # Check sorted by name
        names = [c.name for c in cats]
        assert names == sorted(names)

    def test_update_category(self):
        """Test updating a category"""
        cat = self.service.create_category(name="Old Name")
        updated = self.service.update_category(cat.category_id, name="New Name")
        assert updated is not None
        assert updated.name == "New Name"

    def test_update_category_not_found(self):
        """Test updating nonexistent category"""
        assert self.service.update_category("CAT-NOPE", name="X") is None

    def test_category_with_parent(self):
        """Test creating a nested category"""
        parent = self.service.create_category(name="Parent")
        child = self.service.create_category(
            name="Child", parent_id=parent.category_id
        )
        assert child.parent_id == parent.category_id

    # ========== Documentation Tests ==========

    def test_create_documentation(self):
        """Test creating a documentation entry"""
        doc = self.service.create_documentation(
            client_id="CLIENT-001",
            doc_type=DocType.RUNBOOK,
            title="Server Restart Runbook",
            content="Step 1: ...",
        )
        assert doc.doc_id.startswith("DOC-")
        assert doc.client_id == "CLIENT-001"
        assert doc.doc_type == DocType.RUNBOOK
        assert doc.title == "Server Restart Runbook"

    def test_get_documentation(self):
        """Test getting documentation by ID"""
        doc = self.service.create_documentation(
            client_id="C1", doc_type=DocType.SOP, title="Test SOP"
        )
        fetched = self.service.get_documentation(doc.doc_id)
        assert fetched is not None
        assert fetched.title == "Test SOP"

    def test_get_documentation_not_found(self):
        """Test getting nonexistent documentation"""
        assert self.service.get_documentation("DOC-NOPE") is None

    def test_list_documentation(self):
        """Test listing documentation"""
        self.service.create_documentation(
            client_id="C1", doc_type=DocType.SOP, title="SOP 1"
        )
        self.service.create_documentation(
            client_id="C1", doc_type=DocType.RUNBOOK, title="Runbook 1"
        )
        self.service.create_documentation(
            client_id="C2", doc_type=DocType.SOP, title="SOP 2"
        )
        # Filter by client
        c1_docs = self.service.list_documentation(client_id="C1")
        assert len(c1_docs) == 2
        # Filter by type
        sops = self.service.list_documentation(doc_type=DocType.SOP)
        assert len(sops) >= 2

    def test_update_documentation(self):
        """Test updating documentation"""
        doc = self.service.create_documentation(
            client_id="C1", doc_type=DocType.CONFIG_BACKUP, title="Old Config"
        )
        updated = self.service.update_documentation(
            doc.doc_id, title="New Config", verified_by="Admin"
        )
        assert updated is not None
        assert updated.title == "New Config"
        assert updated.verified_by == "Admin"

    def test_update_documentation_not_found(self):
        """Test updating nonexistent documentation"""
        assert self.service.update_documentation("DOC-NOPE", title="X") is None

    def test_delete_documentation(self):
        """Test deleting documentation"""
        doc = self.service.create_documentation(
            client_id="C1", doc_type=DocType.VENDOR_INFO, title="Delete Me"
        )
        assert self.service.delete_documentation(doc.doc_id) is True
        assert self.service.get_documentation(doc.doc_id) is None

    def test_delete_documentation_not_found(self):
        """Test deleting nonexistent documentation"""
        assert self.service.delete_documentation("DOC-NOPE") is False

    def test_encrypted_documentation(self):
        """Test creating encrypted documentation"""
        doc = self.service.create_documentation(
            client_id="C1",
            doc_type=DocType.PASSWORD_VAULT,
            title="Client Passwords",
            content="encrypted_blob_here",
            is_encrypted=True,
        )
        assert doc.is_encrypted is True

    def test_documentation_with_expiry(self):
        """Test documentation with expiry date"""
        expiry = datetime.utcnow() + timedelta(days=365)
        doc = self.service.create_documentation(
            client_id="C1",
            doc_type=DocType.CONTACT_LIST,
            title="Vendor Contacts",
            expiry_date=expiry,
        )
        assert doc.expiry_date is not None

    # ========== All DocType values ==========

    def test_all_doc_types(self):
        """Test that all DocType enum values are valid"""
        expected = [
            "network_diagram", "password_vault", "runbook", "sop",
            "config_backup", "contact_list", "vendor_info",
            "architecture", "disaster_recovery",
        ]
        for val in expected:
            assert DocType(val) is not None

    # ========== Auto-suggest Tests ==========

    def test_suggest_articles_for_ticket(self):
        """Test suggesting articles for a ticket"""
        suggestions = self.service.suggest_articles_for_ticket({
            "title": "User cannot connect to VPN",
            "description": "VPN client shows error",
            "category": "network",
        })
        assert len(suggestions) >= 1
        # Should find VPN troubleshooting article
        assert any("VPN" in s.title for s in suggestions)

    def test_suggest_empty_ticket(self):
        """Test suggesting for empty ticket data"""
        suggestions = self.service.suggest_articles_for_ticket({})
        assert suggestions == []

    def test_suggest_limits_to_5(self):
        """Test suggestions are limited to 5"""
        suggestions = self.service.suggest_articles_for_ticket({
            "title": "email network printer password VPN outlook security",
        })
        assert len(suggestions) <= 5

    # ========== Auto-generate Tests ==========

    def test_generate_article_from_resolution(self):
        """Test generating article from ticket resolution"""
        article = self.service.generate_article_from_resolution(
            ticket_id="TKT-001",
            resolution="Restarted the print spooler service and cleared the queue.",
            title="Fix: Print Spooler Restart",
        )
        assert article is not None
        assert article.title == "Fix: Print Spooler Restart"
        assert "TKT-001" in article.content_markdown
        assert article.status == ArticleStatus.DRAFT
        assert "auto-generated" in article.tags

    def test_generate_article_default_title(self):
        """Test auto-generated article gets default title"""
        article = self.service.generate_article_from_resolution(
            ticket_id="TKT-999",
            resolution="Fixed the issue.",
        )
        assert "TKT-999" in article.title

    # ========== Analytics Tests ==========

    def test_get_most_viewed(self):
        """Test getting most viewed articles"""
        # Access an article a few times to bump views
        for _ in range(5):
            self.service.get_article("KB-001")
        top = self.service.get_most_viewed(limit=3)
        assert len(top) == 3
        assert top[0].views >= top[1].views

    def test_get_most_helpful(self):
        """Test getting most helpful articles"""
        self.service.vote_helpful("KB-001")
        self.service.vote_helpful("KB-001")
        self.service.vote_helpful("KB-002")
        top = self.service.get_most_helpful(limit=3)
        assert len(top) == 3
        assert top[0].helpful_votes >= top[1].helpful_votes

    def test_get_search_gaps(self):
        """Test getting search gap queries"""
        self.service.search_articles("zzz_no_match_ever")
        gaps = self.service.get_search_gaps()
        assert len(gaps) >= 1

    def test_get_stale_articles(self):
        """Test getting stale articles"""
        # Create an article with old updated_at
        article = self.service.create_article(
            title="Old Article", content_markdown="old", category="Test"
        )
        article.status = ArticleStatus.PUBLISHED
        article.updated_at = datetime.utcnow() - timedelta(days=120)
        stale = self.service.get_stale_articles(days=90)
        assert any(a.article_id == article.article_id for a in stale)

    def test_stale_excludes_non_published(self):
        """Test that stale check only returns published articles"""
        article = self.service.create_article(
            title="Draft Old", content_markdown="x", category="Test"
        )
        article.updated_at = datetime.utcnow() - timedelta(days=200)
        # Article is DRAFT, not PUBLISHED, so should not appear
        stale = self.service.get_stale_articles(days=90)
        assert not any(a.article_id == article.article_id for a in stale)

    # ========== Dashboard Tests ==========

    def test_get_dashboard(self):
        """Test dashboard returns all expected metrics"""
        dashboard = self.service.get_dashboard()
        assert "total_articles" in dashboard
        assert "published" in dashboard
        assert "drafts" in dashboard
        assert "archived" in dashboard
        assert "review_needed" in dashboard
        assert "total_views" in dashboard
        assert "total_documentation" in dashboard
        assert "total_categories" in dashboard
        assert "search_volume_this_month" in dashboard
        assert "search_gaps_count" in dashboard
        assert "stale_articles_count" in dashboard
        assert dashboard["total_articles"] >= 10
        assert dashboard["published"] >= 10
        assert dashboard["total_categories"] >= 10

    # ========== Enum Tests ==========

    def test_article_visibility_enum(self):
        """Test ArticleVisibility enum values"""
        assert ArticleVisibility.INTERNAL.value == "internal"
        assert ArticleVisibility.CLIENT.value == "client"
        assert ArticleVisibility.PUBLIC.value == "public"

    def test_article_status_enum(self):
        """Test ArticleStatus enum values"""
        assert ArticleStatus.DRAFT.value == "draft"
        assert ArticleStatus.PUBLISHED.value == "published"
        assert ArticleStatus.ARCHIVED.value == "archived"
        assert ArticleStatus.REVIEW_NEEDED.value == "review_needed"

    def test_doc_type_enum(self):
        """Test DocType enum values"""
        assert DocType.NETWORK_DIAGRAM.value == "network_diagram"
        assert DocType.PASSWORD_VAULT.value == "password_vault"
        assert DocType.RUNBOOK.value == "runbook"
        assert DocType.SOP.value == "sop"
        assert DocType.CONFIG_BACKUP.value == "config_backup"
        assert DocType.CONTACT_LIST.value == "contact_list"
        assert DocType.VENDOR_INFO.value == "vendor_info"
        assert DocType.ARCHITECTURE.value == "architecture"
        assert DocType.DISASTER_RECOVERY.value == "disaster_recovery"

    # ========== Dataclass Tests ==========

    def test_runbook_step_dataclass(self):
        """Test RunbookStep dataclass"""
        step = RunbookStep(
            step_number=1,
            title="Power cycle the server",
            instructions="Press the power button to shut down, wait 30 seconds, press again.",
            expected_outcome="Server boots normally",
            rollback_instructions="Contact data center support",
            estimated_time_minutes=10,
        )
        assert step.step_number == 1
        assert step.title == "Power cycle the server"
        assert step.estimated_time_minutes == 10

    def test_kb_article_defaults(self):
        """Test KBArticle default values"""
        article = KBArticle(
            article_id="KB-TEST",
            title="Test",
            content_markdown="body",
            category="Test",
        )
        assert article.subcategory == ""
        assert article.tags == []
        assert article.client_id is None
        assert article.visibility == ArticleVisibility.INTERNAL
        assert article.status == ArticleStatus.DRAFT
        assert article.views == 0
        assert article.helpful_votes == 0
        assert article.not_helpful_votes == 0
        assert article.related_articles == []

    def test_kb_search_result_dataclass(self):
        """Test KBSearchResult dataclass"""
        sr = KBSearchResult(
            article_id="KB-001",
            title="Test",
            snippet="...some snippet...",
            relevance_score=8.5,
            category="Troubleshooting",
            tags=["test"],
        )
        assert sr.relevance_score == 8.5
        assert sr.category == "Troubleshooting"

    # ========== Category Count Tests ==========

    def test_category_count_updates(self):
        """Test that category article counts update correctly"""
        self.service.create_article(
            title="Security Article",
            content_markdown="x",
            category="Security",
        )
        cats = self.service.list_categories()
        security_cat = next((c for c in cats if c.name == "Security"), None)
        assert security_cat is not None
        # Should count seeded security articles + our new one
        assert security_cat.article_count >= 3

    # ========== Client-scoped Article Tests ==========

    def test_client_specific_article(self):
        """Test creating a client-specific article"""
        article = self.service.create_article(
            title="Acme VPN Config",
            content_markdown="Custom Acme VPN setup",
            category="Client-Specific",
            client_id="CLIENT-ACME",
            visibility=ArticleVisibility.CLIENT,
        )
        assert article.client_id == "CLIENT-ACME"
        assert article.visibility == ArticleVisibility.CLIENT

    def test_list_articles_by_client(self):
        """Test listing articles for a specific client includes global"""
        self.service.create_article(
            title="Client Doc",
            content_markdown="x",
            category="Test",
            client_id="CLIENT-XYZ",
        )
        articles = self.service.list_articles(client_id="CLIENT-XYZ")
        # Should include client-specific + global (client_id=None) articles
        has_client = any(a.client_id == "CLIENT-XYZ" for a in articles)
        has_global = any(a.client_id is None for a in articles)
        assert has_client
        assert has_global
