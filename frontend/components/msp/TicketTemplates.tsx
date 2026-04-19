import { useState } from 'react'
import {
  FileText,
  Plus,
  Search,
  Filter,
  Edit,
  Trash2,
  Copy,
  Eye,
  CheckCircle,
  Clock,
  Tag,
  Star,
  X,
  AlertTriangle,
  Server,
  Shield,
  Users,
  Mail
} from 'lucide-react'

type TemplateCategory = 'incident' | 'service_request' | 'change' | 'problem' | 'access'
type TemplatePriority = 'low' | 'medium' | 'high' | 'critical'

interface TicketTemplate {
  id: string
  name: string
  category: TemplateCategory
  priority: TemplatePriority
  subject: string
  description: string
  assignee?: string
  tags: string[]
  fields: { name: string; value: string; required: boolean }[]
  usageCount: number
  isActive: boolean
  isFavorite: boolean
  createdBy: string
  createdAt: string
  updatedAt: string
}

const mockTemplates: TicketTemplate[] = [
  {
    id: 'TPL-001',
    name: 'Password Reset Request',
    category: 'service_request',
    priority: 'medium',
    subject: 'Password Reset - [User Name]',
    description: 'User requires password reset for their account. Please verify identity using security questions before proceeding.',
    assignee: 'Help Desk',
    tags: ['password', 'identity', 'access'],
    fields: [
      { name: 'User Email', value: '', required: true },
      { name: 'Account Type', value: 'AD/Office365', required: true },
      { name: 'Verification Method', value: 'Security Questions', required: true }
    ],
    usageCount: 245,
    isActive: true,
    isFavorite: true,
    createdBy: 'Sarah Mitchell',
    createdAt: '2024-06-15',
    updatedAt: '2025-01-10'
  },
  {
    id: 'TPL-002',
    name: 'Server Down - Critical',
    category: 'incident',
    priority: 'critical',
    subject: 'CRITICAL: [Server Name] - Unresponsive',
    description: 'Production server is not responding to ping or connections. Immediate investigation required. Follow escalation procedures.',
    assignee: 'Infrastructure Team',
    tags: ['server', 'outage', 'critical'],
    fields: [
      { name: 'Server Name', value: '', required: true },
      { name: 'IP Address', value: '', required: true },
      { name: 'Last Known Status', value: '', required: true },
      { name: 'Affected Services', value: '', required: true }
    ],
    usageCount: 32,
    isActive: true,
    isFavorite: true,
    createdBy: 'David Johnson',
    createdAt: '2024-08-20',
    updatedAt: '2025-01-15'
  },
  {
    id: 'TPL-003',
    name: 'New Employee Onboarding',
    category: 'service_request',
    priority: 'medium',
    subject: 'New Employee Setup - [Employee Name]',
    description: 'Complete IT setup for new employee including: AD account, email, VPN access, workstation setup, and required software installation.',
    assignee: 'Onboarding Team',
    tags: ['onboarding', 'new hire', 'setup'],
    fields: [
      { name: 'Employee Name', value: '', required: true },
      { name: 'Start Date', value: '', required: true },
      { name: 'Department', value: '', required: true },
      { name: 'Manager', value: '', required: true },
      { name: 'Required Software', value: 'Office 365, Slack', required: false }
    ],
    usageCount: 89,
    isActive: true,
    isFavorite: false,
    createdBy: 'Emily Davis',
    createdAt: '2024-07-01',
    updatedAt: '2025-01-08'
  },
  {
    id: 'TPL-004',
    name: 'Security Incident Report',
    category: 'incident',
    priority: 'high',
    subject: 'Security Alert: [Incident Type]',
    description: 'Security incident detected. Document all findings and preserve evidence. Do not modify affected systems until investigation is complete.',
    assignee: 'Security Team',
    tags: ['security', 'incident', 'investigation'],
    fields: [
      { name: 'Incident Type', value: '', required: true },
      { name: 'Affected Systems', value: '', required: true },
      { name: 'Discovery Method', value: '', required: true },
      { name: 'Initial Assessment', value: '', required: true },
      { name: 'Containment Actions', value: '', required: false }
    ],
    usageCount: 18,
    isActive: true,
    isFavorite: true,
    createdBy: 'David Johnson',
    createdAt: '2024-09-15',
    updatedAt: '2025-01-12'
  },
  {
    id: 'TPL-005',
    name: 'Software Installation Request',
    category: 'service_request',
    priority: 'low',
    subject: 'Software Request: [Software Name]',
    description: 'Request to install approved software on user workstation. Verify software is on approved list before proceeding.',
    assignee: 'Help Desk',
    tags: ['software', 'installation', 'request'],
    fields: [
      { name: 'Software Name', value: '', required: true },
      { name: 'Version', value: '', required: false },
      { name: 'Business Justification', value: '', required: true },
      { name: 'Workstation ID', value: '', required: true }
    ],
    usageCount: 156,
    isActive: true,
    isFavorite: false,
    createdBy: 'Michael Brown',
    createdAt: '2024-05-20',
    updatedAt: '2024-12-15'
  },
  {
    id: 'TPL-006',
    name: 'Network Connectivity Issue',
    category: 'incident',
    priority: 'medium',
    subject: 'Network Issue: [Location/User]',
    description: 'User experiencing network connectivity problems. Troubleshoot local connection first, then escalate if issue is infrastructure-related.',
    assignee: 'Network Team',
    tags: ['network', 'connectivity', 'troubleshoot'],
    fields: [
      { name: 'Location', value: '', required: true },
      { name: 'Connection Type', value: 'Wired/Wireless', required: true },
      { name: 'Error Messages', value: '', required: false },
      { name: 'Affected Users', value: '', required: true }
    ],
    usageCount: 198,
    isActive: true,
    isFavorite: false,
    createdBy: 'Sarah Mitchell',
    createdAt: '2024-04-10',
    updatedAt: '2025-01-05'
  }
]

export default function TicketTemplates() {
  const [templates] = useState<TicketTemplate[]>(mockTemplates)
  const [selectedTemplate, setSelectedTemplate] = useState<TicketTemplate | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterCategory, setFilterCategory] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)

  const filteredTemplates = templates.filter(template => {
    const matchesSearch = template.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      template.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
      template.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()))
    const matchesCategory = filterCategory === 'all' || template.category === filterCategory
    return matchesSearch && matchesCategory
  })

  const getCategoryIcon = (category: TemplateCategory) => {
    switch (category) {
      case 'incident': return <AlertTriangle className="w-4 h-4 text-red-500" />
      case 'service_request': return <FileText className="w-4 h-4 text-blue-500" />
      case 'change': return <Server className="w-4 h-4 text-purple-500" />
      case 'problem': return <Shield className="w-4 h-4 text-orange-500" />
      case 'access': return <Users className="w-4 h-4 text-green-500" />
      default: return <FileText className="w-4 h-4 text-gray-500" />
    }
  }

  const getCategoryColor = (category: TemplateCategory) => {
    switch (category) {
      case 'incident': return 'bg-red-100 text-red-700'
      case 'service_request': return 'bg-blue-100 text-blue-700'
      case 'change': return 'bg-purple-100 text-purple-700'
      case 'problem': return 'bg-orange-100 text-orange-700'
      case 'access': return 'bg-green-100 text-green-700'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  const getPriorityColor = (priority: TemplatePriority) => {
    switch (priority) {
      case 'critical': return 'bg-red-100 text-red-700'
      case 'high': return 'bg-orange-100 text-orange-700'
      case 'medium': return 'bg-yellow-100 text-yellow-700'
      case 'low': return 'bg-gray-100 text-gray-700'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  const totalTemplates = templates.length
  const activeTemplates = templates.filter(t => t.isActive).length
  const totalUsage = templates.reduce((sum, t) => sum + t.usageCount, 0)
  const favorites = templates.filter(t => t.isFavorite).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Ticket Templates</h1>
          <p className="text-gray-600 mt-1">Manage reusable ticket templates for common requests</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700"
        >
          <Plus className="w-4 h-4" />
          New Template
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Templates</p>
              <p className="text-3xl font-bold text-gray-900">{totalTemplates}</p>
            </div>
            <div className="p-3 bg-gray-100 rounded-lg">
              <FileText className="w-6 h-6 text-gray-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Active</p>
              <p className="text-3xl font-bold text-green-600">{activeTemplates}</p>
            </div>
            <div className="p-3 bg-green-100 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Usage</p>
              <p className="text-3xl font-bold text-aether-600">{totalUsage}</p>
            </div>
            <div className="p-3 bg-aether-100 rounded-lg">
              <Copy className="w-6 h-6 text-aether-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Favorites</p>
              <p className="text-3xl font-bold text-yellow-600">{favorites}</p>
            </div>
            <div className="p-3 bg-yellow-100 rounded-lg">
              <Star className="w-6 h-6 text-yellow-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search templates..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-5 h-5 text-gray-400" />
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
          >
            <option value="all">All Categories</option>
            <option value="incident">Incident</option>
            <option value="service_request">Service Request</option>
            <option value="change">Change</option>
            <option value="problem">Problem</option>
            <option value="access">Access</option>
          </select>
        </div>
      </div>

      {/* Templates Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredTemplates.map((template) => (
          <div
            key={template.id}
            className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 hover:shadow-md transition-shadow cursor-pointer"
            onClick={() => setSelectedTemplate(template)}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${getCategoryColor(template.category)}`}>
                  {getCategoryIcon(template.category)}
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900">{template.name}</h3>
                  <p className="text-sm text-gray-500 capitalize">{template.category.replace('_', ' ')}</p>
                </div>
              </div>
              {template.isFavorite && (
                <Star className="w-5 h-5 text-yellow-500 fill-yellow-500" />
              )}
            </div>

            <p className="text-sm text-gray-600 mb-4 line-clamp-2">{template.description}</p>

            <div className="flex flex-wrap gap-2 mb-4">
              {template.tags.slice(0, 3).map((tag, index) => (
                <span key={index} className="px-2 py-1 bg-gray-100 text-gray-600 rounded text-xs">
                  {tag}
                </span>
              ))}
              {template.tags.length > 3 && (
                <span className="px-2 py-1 bg-gray-100 text-gray-600 rounded text-xs">
                  +{template.tags.length - 3}
                </span>
              )}
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-gray-100">
              <div className="flex items-center gap-2 text-sm text-gray-500">
                <Copy className="w-4 h-4" />
                <span>{template.usageCount} uses</span>
              </div>
              <span className={`px-2 py-1 rounded text-xs font-medium capitalize ${getPriorityColor(template.priority)}`}>
                {template.priority}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Template Detail Modal */}
      {selectedTemplate && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setSelectedTemplate(null)} />
            <div className="relative bg-white rounded-xl shadow-xl w-full max-w-2xl p-6">
              <button
                onClick={() => setSelectedTemplate(null)}
                className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
              >
                <X className="w-6 h-6" />
              </button>

              {/* Header */}
              <div className="flex items-start gap-4 mb-6">
                <div className={`p-3 rounded-lg ${getCategoryColor(selectedTemplate.category)}`}>
                  {getCategoryIcon(selectedTemplate.category)}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h2 className="text-xl font-bold text-gray-900">{selectedTemplate.name}</h2>
                    {selectedTemplate.isFavorite && (
                      <Star className="w-5 h-5 text-yellow-500 fill-yellow-500" />
                    )}
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${getCategoryColor(selectedTemplate.category)}`}>
                      {selectedTemplate.category.replace('_', ' ')}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${getPriorityColor(selectedTemplate.priority)}`}>
                      {selectedTemplate.priority}
                    </span>
                    <span className="text-sm text-gray-500">{selectedTemplate.id}</span>
                  </div>
                </div>
              </div>

              {/* Subject */}
              <div className="mb-4">
                <p className="text-sm font-medium text-gray-700 mb-1">Subject Template</p>
                <p className="px-3 py-2 bg-gray-50 rounded-lg text-gray-900">{selectedTemplate.subject}</p>
              </div>

              {/* Description */}
              <div className="mb-4">
                <p className="text-sm font-medium text-gray-700 mb-1">Description</p>
                <p className="px-3 py-2 bg-gray-50 rounded-lg text-gray-600">{selectedTemplate.description}</p>
              </div>

              {/* Fields */}
              <div className="mb-4">
                <p className="text-sm font-medium text-gray-700 mb-2">Template Fields</p>
                <div className="space-y-2">
                  {selectedTemplate.fields.map((field, index) => (
                    <div key={index} className="flex items-center gap-3 px-3 py-2 bg-gray-50 rounded-lg">
                      <span className="font-medium text-gray-700">{field.name}</span>
                      {field.required && (
                        <span className="px-2 py-0.5 bg-red-100 text-red-600 rounded text-xs">Required</span>
                      )}
                      {field.value && (
                        <span className="text-gray-500 text-sm">Default: {field.value}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Tags */}
              <div className="mb-4">
                <p className="text-sm font-medium text-gray-700 mb-2">Tags</p>
                <div className="flex flex-wrap gap-2">
                  {selectedTemplate.tags.map((tag, index) => (
                    <span key={index} className="px-3 py-1 bg-aether-50 text-aether-700 rounded-full text-sm">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>

              {/* Info */}
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-sm text-gray-500">Assignee</p>
                  <p className="font-medium text-gray-900">{selectedTemplate.assignee || 'Auto-assign'}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <p className="text-sm text-gray-500">Usage Count</p>
                  <p className="font-medium text-gray-900">{selectedTemplate.usageCount} tickets</p>
                </div>
              </div>

              {/* Meta */}
              <div className="flex items-center justify-between text-sm text-gray-500 mb-6">
                <span>Created by {selectedTemplate.createdBy} on {new Date(selectedTemplate.createdAt).toLocaleDateString()}</span>
                <span>Updated: {new Date(selectedTemplate.updatedAt).toLocaleDateString()}</span>
              </div>

              {/* Actions */}
              <div className="flex justify-between items-center pt-6 border-t border-gray-200">
                <div className="flex gap-2">
                  <button className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded">
                    <Edit className="w-5 h-5" />
                  </button>
                  <button className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded">
                    <Copy className="w-5 h-5" />
                  </button>
                  <button className="p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded">
                    <Trash2 className="w-5 h-5" />
                  </button>
                </div>
                <button className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700 flex items-center gap-2">
                  <FileText className="w-4 h-4" />
                  Use Template
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setShowCreateModal(false)} />
            <div className="relative bg-white rounded-xl shadow-xl w-full max-w-lg p-6">
              <button
                onClick={() => setShowCreateModal(false)}
                className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
              >
                <X className="w-6 h-6" />
              </button>

              <h2 className="text-xl font-bold text-gray-900 mb-6">Create New Template</h2>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Template Name</label>
                  <input
                    type="text"
                    placeholder="Enter template name"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Category</label>
                    <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500">
                      <option value="incident">Incident</option>
                      <option value="service_request">Service Request</option>
                      <option value="change">Change</option>
                      <option value="problem">Problem</option>
                      <option value="access">Access</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
                    <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500">
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Subject Template</label>
                  <input
                    type="text"
                    placeholder="e.g., [Category]: [Issue]"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                  <textarea
                    rows={3}
                    placeholder="Enter template description"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Tags</label>
                  <input
                    type="text"
                    placeholder="Enter tags separated by commas"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
                  Create Template
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
