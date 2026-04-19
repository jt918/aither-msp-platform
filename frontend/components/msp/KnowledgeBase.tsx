/**
 * Knowledge Base - MSP Documentation and Solutions
 * Searchable knowledge base for technicians and clients
 */

import { useState } from 'react'
import {
  Book,
  Search,
  Plus,
  Folder,
  FileText,
  Tag,
  Clock,
  User,
  ThumbsUp,
  Eye,
  Edit,
  Trash2,
  ChevronRight,
  Star,
  Bookmark,
  ExternalLink,
  Filter,
  SortAsc
} from 'lucide-react'

interface Article {
  id: string
  title: string
  excerpt: string
  content: string
  category: string
  tags: string[]
  author: string
  created_at: string
  updated_at: string
  views: number
  helpful: number
  is_featured: boolean
  access_level: 'public' | 'internal' | 'admin'
}

interface Category {
  id: string
  name: string
  icon: string
  article_count: number
  description: string
}

// Mock data
const mockCategories: Category[] = [
  { id: 'CAT-001', name: 'Getting Started', icon: '🚀', article_count: 12, description: 'Onboarding and setup guides' },
  { id: 'CAT-002', name: 'Troubleshooting', icon: '🔧', article_count: 45, description: 'Common issues and solutions' },
  { id: 'CAT-003', name: 'Network & Security', icon: '🔒', article_count: 28, description: 'Network configuration and security best practices' },
  { id: 'CAT-004', name: 'Software', icon: '💻', article_count: 34, description: 'Application installation and configuration' },
  { id: 'CAT-005', name: 'Hardware', icon: '🖥️', article_count: 22, description: 'Hardware setup and maintenance' },
  { id: 'CAT-006', name: 'Best Practices', icon: '📋', article_count: 18, description: 'Recommended procedures and standards' }
]

const mockArticles: Article[] = [
  {
    id: 'ART-001',
    title: 'How to Reset a Windows Password Without Losing Data',
    excerpt: 'Step-by-step guide to safely reset Windows passwords using multiple methods including Safe Mode, Command Prompt, and third-party tools.',
    content: 'Full article content...',
    category: 'Troubleshooting',
    tags: ['Windows', 'Password', 'Security', 'Reset'],
    author: 'John Tech',
    created_at: '2024-01-10T10:00:00',
    updated_at: '2024-01-15T09:00:00',
    views: 1245,
    helpful: 89,
    is_featured: true,
    access_level: 'public'
  },
  {
    id: 'ART-002',
    title: 'Configuring VPN Client for Remote Access',
    excerpt: 'Complete guide to setting up and troubleshooting VPN connections for secure remote work.',
    content: 'Full article content...',
    category: 'Network & Security',
    tags: ['VPN', 'Remote Access', 'Security', 'Network'],
    author: 'Sarah Admin',
    created_at: '2024-01-08T14:00:00',
    updated_at: '2024-01-12T16:00:00',
    views: 856,
    helpful: 67,
    is_featured: true,
    access_level: 'public'
  },
  {
    id: 'ART-003',
    title: 'Microsoft 365 Email Migration Checklist',
    excerpt: 'Pre-migration checklist and step-by-step process for migrating to Microsoft 365.',
    content: 'Full article content...',
    category: 'Software',
    tags: ['Microsoft 365', 'Email', 'Migration', 'Office'],
    author: 'Mike Cloud',
    created_at: '2024-01-05T11:00:00',
    updated_at: '2024-01-14T10:00:00',
    views: 678,
    helpful: 52,
    is_featured: false,
    access_level: 'internal'
  },
  {
    id: 'ART-004',
    title: 'New Employee IT Onboarding Process',
    excerpt: 'Standard operating procedure for setting up new employee accounts, equipment, and access.',
    content: 'Full article content...',
    category: 'Getting Started',
    tags: ['Onboarding', 'New Hire', 'Setup', 'SOP'],
    author: 'HR Team',
    created_at: '2024-01-03T09:00:00',
    updated_at: '2024-01-10T14:00:00',
    views: 423,
    helpful: 38,
    is_featured: false,
    access_level: 'internal'
  },
  {
    id: 'ART-005',
    title: 'Backup and Recovery Procedures',
    excerpt: 'Enterprise backup strategy, recovery procedures, and disaster recovery planning.',
    content: 'Full article content...',
    category: 'Best Practices',
    tags: ['Backup', 'Recovery', 'Disaster Recovery', 'DR'],
    author: 'John Tech',
    created_at: '2024-01-01T08:00:00',
    updated_at: '2024-01-08T12:00:00',
    views: 567,
    helpful: 45,
    is_featured: false,
    access_level: 'admin'
  },
  {
    id: 'ART-006',
    title: 'Printer Installation and Troubleshooting',
    excerpt: 'Guide to installing network printers and resolving common print issues.',
    content: 'Full article content...',
    category: 'Hardware',
    tags: ['Printer', 'Hardware', 'Network', 'Troubleshooting'],
    author: 'Sarah Admin',
    created_at: '2023-12-28T10:00:00',
    updated_at: '2024-01-05T11:00:00',
    views: 892,
    helpful: 71,
    is_featured: false,
    access_level: 'public'
  }
]

export default function KnowledgeBase() {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const [selectedArticle, setSelectedArticle] = useState<Article | null>(null)
  const [showNewArticle, setShowNewArticle] = useState(false)
  const [sortBy, setSortBy] = useState<'recent' | 'popular' | 'helpful'>('recent')

  const filteredArticles = mockArticles.filter(article => {
    const matchesSearch = searchQuery === '' ||
      article.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      article.excerpt.toLowerCase().includes(searchQuery.toLowerCase()) ||
      article.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))
    const matchesCategory = !selectedCategory || article.category === selectedCategory
    return matchesSearch && matchesCategory
  }).sort((a, b) => {
    switch (sortBy) {
      case 'popular': return b.views - a.views
      case 'helpful': return b.helpful - a.helpful
      default: return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
    }
  })

  const featuredArticles = mockArticles.filter(a => a.is_featured)

  const getAccessBadge = (level: string) => {
    switch (level) {
      case 'public': return 'bg-green-100 text-green-800'
      case 'internal': return 'bg-blue-100 text-blue-800'
      case 'admin': return 'bg-purple-100 text-purple-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Knowledge Base</h1>
          <p className="text-gray-500">Documentation, guides, and solutions</p>
        </div>
        <button
          onClick={() => setShowNewArticle(true)}
          className="flex items-center gap-2 px-4 py-2 text-white bg-aether-600 rounded-lg hover:bg-aether-700"
        >
          <Plus className="w-4 h-4" />
          New Article
        </button>
      </div>

      {/* Search Bar */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="max-w-2xl mx-auto">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search articles, guides, and solutions..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-12 pr-4 py-3 text-lg border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
            />
          </div>
          <div className="flex items-center gap-2 mt-3">
            <span className="text-sm text-gray-500">Popular:</span>
            {['VPN', 'Password Reset', 'Email', 'Backup'].map(tag => (
              <button
                key={tag}
                onClick={() => setSearchQuery(tag)}
                className="px-3 py-1 text-sm text-aether-600 bg-aether-50 rounded-full hover:bg-aether-100"
              >
                {tag}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Featured Articles */}
      {searchQuery === '' && !selectedCategory && featuredArticles.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Star className="w-5 h-5 text-yellow-500" />
            Featured Articles
          </h2>
          <div className="grid grid-cols-2 gap-4">
            {featuredArticles.map(article => (
              <div
                key={article.id}
                onClick={() => setSelectedArticle(article)}
                className="bg-white rounded-lg shadow p-4 border-l-4 border-yellow-400 cursor-pointer hover:shadow-md transition-shadow"
              >
                <h3 className="font-semibold text-gray-900">{article.title}</h3>
                <p className="text-sm text-gray-500 mt-1 line-clamp-2">{article.excerpt}</p>
                <div className="flex items-center gap-3 mt-3 text-sm text-gray-400">
                  <span className="flex items-center gap-1">
                    <Eye className="w-3 h-3" />
                    {article.views}
                  </span>
                  <span className="flex items-center gap-1">
                    <ThumbsUp className="w-3 h-3" />
                    {article.helpful}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Categories */}
      {searchQuery === '' && !selectedCategory && (
        <div className="space-y-3">
          <h2 className="text-lg font-semibold">Browse by Category</h2>
          <div className="grid grid-cols-3 gap-4">
            {mockCategories.map(category => (
              <div
                key={category.id}
                onClick={() => setSelectedCategory(category.name)}
                className="bg-white rounded-lg shadow p-4 cursor-pointer hover:shadow-md transition-shadow"
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{category.icon}</span>
                  <div>
                    <h3 className="font-semibold">{category.name}</h3>
                    <p className="text-sm text-gray-500">{category.article_count} articles</p>
                  </div>
                </div>
                <p className="text-sm text-gray-500 mt-2">{category.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Articles List */}
      {(searchQuery !== '' || selectedCategory) && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {selectedCategory && (
                <>
                  <button
                    onClick={() => setSelectedCategory(null)}
                    className="text-sm text-aether-600 hover:text-aether-700"
                  >
                    All Categories
                  </button>
                  <ChevronRight className="w-4 h-4 text-gray-400" />
                  <span className="text-sm font-medium">{selectedCategory}</span>
                </>
              )}
              <span className="text-sm text-gray-500">
                {filteredArticles.length} article{filteredArticles.length !== 1 ? 's' : ''} found
              </span>
            </div>
            <div className="flex items-center gap-2">
              <SortAsc className="w-4 h-4 text-gray-400" />
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="text-sm border border-gray-300 rounded-lg px-3 py-1.5"
              >
                <option value="recent">Most Recent</option>
                <option value="popular">Most Viewed</option>
                <option value="helpful">Most Helpful</option>
              </select>
            </div>
          </div>

          {/* Articles */}
          <div className="bg-white rounded-lg shadow divide-y">
            {filteredArticles.map(article => (
              <div
                key={article.id}
                onClick={() => setSelectedArticle(article)}
                className="p-4 cursor-pointer hover:bg-gray-50"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-gray-900">{article.title}</h3>
                      <span className={`px-2 py-0.5 text-xs rounded-full capitalize ${getAccessBadge(article.access_level)}`}>
                        {article.access_level}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 mt-1">{article.excerpt}</p>
                    <div className="flex items-center gap-4 mt-2">
                      <div className="flex flex-wrap gap-1">
                        {article.tags.slice(0, 3).map(tag => (
                          <span key={tag} className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded-full">
                            {tag}
                          </span>
                        ))}
                      </div>
                      <span className="text-xs text-gray-400">•</span>
                      <span className="text-xs text-gray-400">
                        Updated {new Date(article.updated_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm text-gray-400 ml-4">
                    <span className="flex items-center gap-1">
                      <Eye className="w-4 h-4" />
                      {article.views}
                    </span>
                    <span className="flex items-center gap-1">
                      <ThumbsUp className="w-4 h-4" />
                      {article.helpful}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Article Detail Modal */}
      {selectedArticle && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setSelectedArticle(null)} />
          <div className="relative bg-white rounded-lg shadow-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto m-4">
            {/* Header */}
            <div className="sticky top-0 bg-white border-b p-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setSelectedArticle(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ← Back
                </button>
                <span className="text-gray-300">|</span>
                <span className="text-sm text-gray-500">{selectedArticle.category}</span>
              </div>
              <div className="flex items-center gap-2">
                <button className="p-2 text-gray-400 hover:text-aether-600 rounded-lg" title="Bookmark">
                  <Bookmark className="w-4 h-4" />
                </button>
                <button className="p-2 text-gray-400 hover:text-aether-600 rounded-lg" title="Share">
                  <ExternalLink className="w-4 h-4" />
                </button>
                <button className="p-2 text-gray-400 hover:text-aether-600 rounded-lg" title="Edit">
                  <Edit className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Content */}
            <div className="p-6">
              <h1 className="text-2xl font-bold text-gray-900">{selectedArticle.title}</h1>

              <div className="flex items-center gap-4 mt-3 text-sm text-gray-500">
                <span className="flex items-center gap-1">
                  <User className="w-4 h-4" />
                  {selectedArticle.author}
                </span>
                <span className="flex items-center gap-1">
                  <Clock className="w-4 h-4" />
                  Updated {new Date(selectedArticle.updated_at).toLocaleDateString()}
                </span>
                <span className="flex items-center gap-1">
                  <Eye className="w-4 h-4" />
                  {selectedArticle.views} views
                </span>
              </div>

              <div className="flex flex-wrap gap-1 mt-4">
                {selectedArticle.tags.map(tag => (
                  <span key={tag} className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded-full">
                    <Tag className="w-3 h-3 inline mr-1" />
                    {tag}
                  </span>
                ))}
              </div>

              {/* Article Body */}
              <div className="mt-6 prose max-w-none">
                <p className="text-gray-600">{selectedArticle.excerpt}</p>
                <hr className="my-4" />
                <p className="text-gray-600">
                  This is where the full article content would be displayed. In a real implementation,
                  this would be rich text content with headings, code blocks, images, and other
                  formatting.
                </p>
                <h2 className="text-lg font-semibold mt-6">Prerequisites</h2>
                <ul className="list-disc pl-5 space-y-1 text-gray-600">
                  <li>Administrator access to the system</li>
                  <li>Network connectivity</li>
                  <li>Required software installed</li>
                </ul>
                <h2 className="text-lg font-semibold mt-6">Step-by-Step Instructions</h2>
                <ol className="list-decimal pl-5 space-y-2 text-gray-600">
                  <li>First, log in to the system with your administrator credentials</li>
                  <li>Navigate to the settings panel</li>
                  <li>Follow the configuration wizard</li>
                  <li>Verify the changes were applied correctly</li>
                </ol>
              </div>

              {/* Feedback */}
              <div className="mt-8 p-4 bg-gray-50 rounded-lg">
                <p className="text-center text-sm text-gray-600 mb-3">Was this article helpful?</p>
                <div className="flex items-center justify-center gap-4">
                  <button className="flex items-center gap-2 px-4 py-2 text-green-600 border border-green-200 rounded-lg hover:bg-green-50">
                    <ThumbsUp className="w-4 h-4" />
                    Yes ({selectedArticle.helpful})
                  </button>
                  <button className="flex items-center gap-2 px-4 py-2 text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-100">
                    <ThumbsUp className="w-4 h-4 transform rotate-180" />
                    No
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
