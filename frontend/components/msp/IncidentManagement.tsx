import { useState } from 'react'
import {
  AlertTriangle,
  AlertCircle,
  CheckCircle,
  Clock,
  Search,
  Filter,
  Plus,
  ChevronRight,
  User,
  Calendar,
  Tag,
  MessageSquare,
  Paperclip,
  ArrowUp,
  ArrowDown,
  MoreVertical,
  Bell,
  RefreshCw,
  TrendingUp,
  Users,
  Zap,
  X
} from 'lucide-react'

// Types
interface Incident {
  id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'investigating' | 'identified' | 'monitoring' | 'resolved'
  category: string
  affectedSystems: string[]
  assignee: string
  reporter: string
  createdAt: string
  updatedAt: string
  resolvedAt?: string
  impactedUsers: number
  updates: { timestamp: string; message: string; author: string }[]
}

// Mock data
const incidents: Incident[] = [
  {
    id: 'INC-001',
    title: 'Database Connection Pool Exhaustion',
    description: 'Primary database experiencing connection pool exhaustion leading to slow response times across multiple services.',
    severity: 'critical',
    status: 'investigating',
    category: 'Database',
    affectedSystems: ['API Gateway', 'User Service', 'Order Service'],
    assignee: 'David Johnson',
    reporter: 'Monitoring System',
    createdAt: '2025-01-15T14:30:00Z',
    updatedAt: '2025-01-15T15:45:00Z',
    impactedUsers: 2500,
    updates: [
      { timestamp: '2025-01-15T15:45:00Z', message: 'Increased connection pool size, monitoring for improvement', author: 'David Johnson' },
      { timestamp: '2025-01-15T15:00:00Z', message: 'Identified as connection pool exhaustion, investigating root cause', author: 'David Johnson' },
      { timestamp: '2025-01-15T14:35:00Z', message: 'Incident created automatically by monitoring alert', author: 'System' }
    ]
  },
  {
    id: 'INC-002',
    title: 'CDN Certificate Expiration Warning',
    description: 'SSL certificate for CDN will expire in 7 days, requiring renewal to prevent service disruption.',
    severity: 'high',
    status: 'identified',
    category: 'Security',
    affectedSystems: ['CDN', 'Static Assets'],
    assignee: 'Michael Brown',
    reporter: 'Sarah Mitchell',
    createdAt: '2025-01-14T10:00:00Z',
    updatedAt: '2025-01-15T09:30:00Z',
    impactedUsers: 0,
    updates: [
      { timestamp: '2025-01-15T09:30:00Z', message: 'Certificate renewal in progress, ETA 2 hours', author: 'Michael Brown' },
      { timestamp: '2025-01-14T10:00:00Z', message: 'Certificate expiration detected, assigned for renewal', author: 'Sarah Mitchell' }
    ]
  },
  {
    id: 'INC-003',
    title: 'Email Delivery Delays',
    description: 'Transactional emails experiencing 15-30 minute delays due to mail queue backlog.',
    severity: 'medium',
    status: 'monitoring',
    category: 'Email',
    affectedSystems: ['Email Service', 'Notification Service'],
    assignee: 'Emily Chen',
    reporter: 'Support Team',
    createdAt: '2025-01-15T11:00:00Z',
    updatedAt: '2025-01-15T14:00:00Z',
    impactedUsers: 450,
    updates: [
      { timestamp: '2025-01-15T14:00:00Z', message: 'Queue size returning to normal, continuing to monitor', author: 'Emily Chen' },
      { timestamp: '2025-01-15T12:30:00Z', message: 'Scaled up email workers to process backlog', author: 'Emily Chen' },
      { timestamp: '2025-01-15T11:00:00Z', message: 'Multiple user reports of delayed password reset emails', author: 'Support Team' }
    ]
  },
  {
    id: 'INC-004',
    title: 'Minor UI Rendering Issue',
    description: 'Dashboard charts not rendering correctly in Safari browser version 16.x.',
    severity: 'low',
    status: 'open',
    category: 'Frontend',
    affectedSystems: ['Web Dashboard'],
    assignee: '',
    reporter: 'QA Team',
    createdAt: '2025-01-15T16:00:00Z',
    updatedAt: '2025-01-15T16:00:00Z',
    impactedUsers: 50,
    updates: [
      { timestamp: '2025-01-15T16:00:00Z', message: 'Issue reported by QA during testing', author: 'QA Team' }
    ]
  },
  {
    id: 'INC-005',
    title: 'Payment Gateway Timeout',
    description: 'Intermittent timeouts when processing payments through Stripe gateway.',
    severity: 'critical',
    status: 'resolved',
    category: 'Payments',
    affectedSystems: ['Payment Service', 'Checkout'],
    assignee: 'David Johnson',
    reporter: 'Monitoring System',
    createdAt: '2025-01-14T08:00:00Z',
    updatedAt: '2025-01-14T10:30:00Z',
    resolvedAt: '2025-01-14T10:30:00Z',
    impactedUsers: 180,
    updates: [
      { timestamp: '2025-01-14T10:30:00Z', message: 'Issue resolved, Stripe confirmed network issue on their end', author: 'David Johnson' },
      { timestamp: '2025-01-14T09:00:00Z', message: 'Confirmed as Stripe-side issue, opened ticket with their support', author: 'David Johnson' },
      { timestamp: '2025-01-14T08:00:00Z', message: 'Multiple payment timeout alerts triggered', author: 'System' }
    ]
  }
]

const getSeverityColor = (severity: Incident['severity']) => {
  switch (severity) {
    case 'critical': return 'bg-red-100 text-red-700 border-red-200'
    case 'high': return 'bg-orange-100 text-orange-700 border-orange-200'
    case 'medium': return 'bg-yellow-100 text-yellow-700 border-yellow-200'
    case 'low': return 'bg-gray-100 text-gray-700 border-gray-200'
  }
}

const getStatusColor = (status: Incident['status']) => {
  switch (status) {
    case 'open': return 'bg-red-500'
    case 'investigating': return 'bg-orange-500'
    case 'identified': return 'bg-yellow-500'
    case 'monitoring': return 'bg-blue-500'
    case 'resolved': return 'bg-green-500'
  }
}

const getStatusIcon = (status: Incident['status']) => {
  switch (status) {
    case 'open': return <AlertCircle className="w-4 h-4" />
    case 'investigating': return <Search className="w-4 h-4" />
    case 'identified': return <AlertTriangle className="w-4 h-4" />
    case 'monitoring': return <Clock className="w-4 h-4" />
    case 'resolved': return <CheckCircle className="w-4 h-4" />
  }
}

export default function IncidentManagement() {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)

  const activeIncidents = incidents.filter(i => i.status !== 'resolved')
  const filteredIncidents = incidents.filter(incident => {
    const matchesSearch = incident.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          incident.id.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === 'all' || incident.status === statusFilter
    const matchesSeverity = severityFilter === 'all' || incident.severity === severityFilter
    return matchesSearch && matchesStatus && matchesSeverity
  })

  const stats = {
    total: incidents.length,
    critical: activeIncidents.filter(i => i.severity === 'critical').length,
    open: incidents.filter(i => i.status === 'open').length,
    resolved24h: incidents.filter(i => i.status === 'resolved').length,
    mttr: '2.5h' // Mean time to resolve
  }

  const formatTime = (dateStr: string) => {
    const date = new Date(dateStr)
    return date.toLocaleString()
  }

  const getTimeAgo = (dateStr: string) => {
    const date = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMins / 60)
    const diffDays = Math.floor(diffHours / 24)

    if (diffDays > 0) return `${diffDays}d ago`
    if (diffHours > 0) return `${diffHours}h ago`
    return `${diffMins}m ago`
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Incident Management</h1>
          <p className="text-gray-600 mt-1">Track and resolve system incidents</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
            <Bell className="w-4 h-4" />
            Alerts
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
            <Plus className="w-4 h-4" />
            Report Incident
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
              <p className="text-sm text-gray-500">Total Incidents</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 rounded-lg">
              <Zap className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-red-600">{stats.critical}</p>
              <p className="text-sm text-gray-500">Critical Active</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-100 rounded-lg">
              <AlertCircle className="w-5 h-5 text-orange-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.open}</p>
              <p className="text-sm text-gray-500">Open</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.resolved24h}</p>
              <p className="text-sm text-gray-500">Resolved (24h)</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Clock className="w-5 h-5 text-purple-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.mttr}</p>
              <p className="text-sm text-gray-500">Avg MTTR</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm p-4">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search incidents..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-aether-500"
            />
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg"
          >
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="identified">Identified</option>
            <option value="monitoring">Monitoring</option>
            <option value="resolved">Resolved</option>
          </select>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg"
          >
            <option value="all">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Incidents List */}
      <div className="space-y-4">
        {filteredIncidents.map((incident) => (
          <div
            key={incident.id}
            className="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow cursor-pointer"
            onClick={() => setSelectedIncident(incident)}
          >
            <div className="p-6">
              <div className="flex items-start gap-4">
                {/* Status Indicator */}
                <div className={`w-3 h-3 rounded-full mt-1.5 ${getStatusColor(incident.status)}`} />

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-mono text-gray-500">{incident.id}</span>
                        <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${getSeverityColor(incident.severity)}`}>
                          {incident.severity}
                        </span>
                        <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 text-gray-600">
                          {incident.category}
                        </span>
                      </div>
                      <h3 className="text-lg font-semibold text-gray-900 mt-1">{incident.title}</h3>
                      <p className="text-sm text-gray-600 mt-1 line-clamp-2">{incident.description}</p>
                    </div>
                    <div className="flex items-center gap-1 text-sm text-gray-500">
                      {getStatusIcon(incident.status)}
                      <span className="capitalize">{incident.status.replace('_', ' ')}</span>
                    </div>
                  </div>

                  {/* Meta Info */}
                  <div className="flex items-center gap-4 mt-4 text-sm text-gray-500">
                    <div className="flex items-center gap-1">
                      <User className="w-4 h-4" />
                      <span>{incident.assignee || 'Unassigned'}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Users className="w-4 h-4" />
                      <span>{incident.impactedUsers} impacted</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Clock className="w-4 h-4" />
                      <span>{getTimeAgo(incident.createdAt)}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <MessageSquare className="w-4 h-4" />
                      <span>{incident.updates.length} updates</span>
                    </div>
                  </div>

                  {/* Affected Systems */}
                  <div className="flex items-center gap-2 mt-3">
                    <span className="text-xs text-gray-500">Affected:</span>
                    <div className="flex flex-wrap gap-1">
                      {incident.affectedSystems.map((system, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-gray-100 text-gray-600 text-xs rounded">
                          {system}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <ChevronRight className="w-5 h-5 text-gray-400" />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-white rounded-2xl shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="sticky top-0 bg-white border-b px-6 py-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-mono text-gray-500">{selectedIncident.id}</span>
                    <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${getSeverityColor(selectedIncident.severity)}`}>
                      {selectedIncident.severity}
                    </span>
                    <span className={`flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full text-white ${getStatusColor(selectedIncident.status)}`}>
                      {getStatusIcon(selectedIncident.status)}
                      {selectedIncident.status}
                    </span>
                  </div>
                  <h2 className="text-xl font-bold text-gray-900 mt-2">{selectedIncident.title}</h2>
                </div>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="p-2 hover:bg-gray-100 rounded-lg"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              {/* Description */}
              <div>
                <h3 className="font-medium text-gray-900 mb-2">Description</h3>
                <p className="text-gray-600">{selectedIncident.description}</p>
              </div>

              {/* Details Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-500">Category</p>
                  <p className="font-medium">{selectedIncident.category}</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-500">Assignee</p>
                  <p className="font-medium">{selectedIncident.assignee || 'Unassigned'}</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-500">Reporter</p>
                  <p className="font-medium">{selectedIncident.reporter}</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-500">Impacted Users</p>
                  <p className="font-medium">{selectedIncident.impactedUsers}</p>
                </div>
              </div>

              {/* Affected Systems */}
              <div>
                <h3 className="font-medium text-gray-900 mb-2">Affected Systems</h3>
                <div className="flex flex-wrap gap-2">
                  {selectedIncident.affectedSystems.map((system, idx) => (
                    <span key={idx} className="px-3 py-1 bg-red-50 text-red-700 rounded-lg text-sm">
                      {system}
                    </span>
                  ))}
                </div>
              </div>

              {/* Timeline */}
              <div>
                <h3 className="font-medium text-gray-900 mb-3">Updates Timeline</h3>
                <div className="space-y-4">
                  {selectedIncident.updates.map((update, idx) => (
                    <div key={idx} className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <div className="w-3 h-3 rounded-full bg-aether-500" />
                        {idx < selectedIncident.updates.length - 1 && (
                          <div className="w-0.5 flex-1 bg-gray-200" />
                        )}
                      </div>
                      <div className="pb-4">
                        <p className="text-sm text-gray-500">{formatTime(update.timestamp)}</p>
                        <p className="text-gray-900 mt-1">{update.message}</p>
                        <p className="text-sm text-gray-500 mt-1">— {update.author}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Actions */}
              <div className="flex justify-end gap-3 pt-4 border-t">
                {selectedIncident.status !== 'resolved' && (
                  <>
                    <button className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                      Add Update
                    </button>
                    <button className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700">
                      Mark Resolved
                    </button>
                  </>
                )}
                {selectedIncident.status === 'resolved' && (
                  <button className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                    Reopen Incident
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
