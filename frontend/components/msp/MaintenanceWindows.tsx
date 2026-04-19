import { useState } from 'react'
import {
  Wrench,
  Search,
  Filter,
  Plus,
  Calendar,
  Clock,
  Server,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Play,
  Pause,
  MoreVertical,
  X,
  Users,
  Bell,
  FileText,
  RefreshCw
} from 'lucide-react'

interface MaintenanceWindow {
  id: string
  title: string
  description: string
  type: 'scheduled' | 'emergency' | 'recurring'
  priority: 'critical' | 'high' | 'normal' | 'low'
  status: 'planned' | 'approved' | 'in_progress' | 'completed' | 'cancelled' | 'failed'
  scheduledStart: string
  scheduledEnd: string
  actualStart?: string
  actualEnd?: string
  affectedSystems: string[]
  owner: string
  approver?: string
  notificationsSent: boolean
  changeTicket?: string
  rollbackPlan: string
  impactLevel: 'none' | 'minor' | 'moderate' | 'major' | 'critical'
  notes: string[]
}

const mockWindows: MaintenanceWindow[] = [
  {
    id: 'MW-001',
    title: 'Database Server Upgrade',
    description: 'Upgrading PostgreSQL from 14.x to 16.x for improved performance and security patches.',
    type: 'scheduled',
    priority: 'high',
    status: 'approved',
    scheduledStart: '2025-01-25T02:00:00Z',
    scheduledEnd: '2025-01-25T06:00:00Z',
    affectedSystems: ['db-primary', 'db-replica-01', 'db-replica-02'],
    owner: 'Emily Chen',
    approver: 'Sarah Mitchell',
    notificationsSent: true,
    changeTicket: 'CHG-2025-0042',
    rollbackPlan: 'Restore from pre-upgrade snapshot if upgrade fails',
    impactLevel: 'major',
    notes: ['Backup verified', 'Staging test successful']
  },
  {
    id: 'MW-002',
    title: 'Network Switch Firmware Update',
    description: 'Applying critical security patches to core network switches.',
    type: 'scheduled',
    priority: 'critical',
    status: 'planned',
    scheduledStart: '2025-01-26T03:00:00Z',
    scheduledEnd: '2025-01-26T05:00:00Z',
    affectedSystems: ['core-sw-01', 'core-sw-02', 'access-sw-*'],
    owner: 'David Johnson',
    notificationsSent: false,
    changeTicket: 'CHG-2025-0045',
    rollbackPlan: 'Firmware downgrade procedure documented',
    impactLevel: 'critical',
    notes: []
  },
  {
    id: 'MW-003',
    title: 'SSL Certificate Renewal',
    description: 'Renewing SSL certificates for api.aither.io and app.aither.io domains.',
    type: 'scheduled',
    priority: 'normal',
    status: 'completed',
    scheduledStart: '2025-01-18T10:00:00Z',
    scheduledEnd: '2025-01-18T11:00:00Z',
    actualStart: '2025-01-18T10:05:00Z',
    actualEnd: '2025-01-18T10:45:00Z',
    affectedSystems: ['api-gateway', 'web-frontend'],
    owner: 'Emily Chen',
    approver: 'David Johnson',
    notificationsSent: true,
    rollbackPlan: 'Previous certificates backed up',
    impactLevel: 'minor',
    notes: ['Completed ahead of schedule', 'No issues reported']
  },
  {
    id: 'MW-004',
    title: 'Emergency Security Patch',
    description: 'Critical vulnerability patch for OpenSSL on all production servers.',
    type: 'emergency',
    priority: 'critical',
    status: 'completed',
    scheduledStart: '2025-01-17T14:00:00Z',
    scheduledEnd: '2025-01-17T16:00:00Z',
    actualStart: '2025-01-17T14:15:00Z',
    actualEnd: '2025-01-17T15:30:00Z',
    affectedSystems: ['All production servers'],
    owner: 'Christopher Martinez',
    approver: 'Sarah Mitchell',
    notificationsSent: true,
    changeTicket: 'CHG-2025-0040',
    rollbackPlan: 'N/A - Security critical',
    impactLevel: 'moderate',
    notes: ['CVE-2025-XXXX patched', 'All systems verified']
  },
  {
    id: 'MW-005',
    title: 'Weekly Backup Verification',
    description: 'Routine backup integrity verification and restoration test.',
    type: 'recurring',
    priority: 'low',
    status: 'in_progress',
    scheduledStart: '2025-01-19T01:00:00Z',
    scheduledEnd: '2025-01-19T04:00:00Z',
    actualStart: '2025-01-19T01:00:00Z',
    affectedSystems: ['backup-server', 'test-restore-env'],
    owner: 'Emily Chen',
    notificationsSent: true,
    rollbackPlan: 'N/A',
    impactLevel: 'none',
    notes: ['Running weekly']
  },
  {
    id: 'MW-006',
    title: 'Load Balancer Configuration Update',
    description: 'Updating load balancer rules for new microservices deployment.',
    type: 'scheduled',
    priority: 'normal',
    status: 'cancelled',
    scheduledStart: '2025-01-20T02:00:00Z',
    scheduledEnd: '2025-01-20T03:00:00Z',
    affectedSystems: ['lb-primary', 'lb-secondary'],
    owner: 'David Johnson',
    notificationsSent: false,
    rollbackPlan: 'Revert to previous config',
    impactLevel: 'minor',
    notes: ['Postponed due to dependency on MW-001']
  }
]

const types = ['All', 'Scheduled', 'Emergency', 'Recurring']
const statuses = ['All', 'Planned', 'Approved', 'In Progress', 'Completed', 'Cancelled', 'Failed']

export default function MaintenanceWindows() {
  const [windows] = useState<MaintenanceWindow[]>(mockWindows)
  const [searchTerm, setSearchTerm] = useState('')
  const [typeFilter, setTypeFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All')
  const [selectedWindow, setSelectedWindow] = useState<MaintenanceWindow | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)

  const filteredWindows = windows.filter(w => {
    const matchesSearch = w.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      w.description.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesType = typeFilter === 'All' || w.type.toLowerCase() === typeFilter.toLowerCase()
    const matchesStatus = statusFilter === 'All' || w.status.replace('_', ' ').toLowerCase() === statusFilter.toLowerCase()
    return matchesSearch && matchesType && matchesStatus
  })

  const getStatusColor = (status: MaintenanceWindow['status']) => {
    switch (status) {
      case 'planned': return 'bg-gray-100 text-gray-700'
      case 'approved': return 'bg-blue-100 text-blue-700'
      case 'in_progress': return 'bg-yellow-100 text-yellow-700'
      case 'completed': return 'bg-green-100 text-green-700'
      case 'cancelled': return 'bg-gray-100 text-gray-500'
      case 'failed': return 'bg-red-100 text-red-700'
    }
  }

  const getTypeColor = (type: MaintenanceWindow['type']) => {
    switch (type) {
      case 'scheduled': return 'bg-blue-100 text-blue-700'
      case 'emergency': return 'bg-red-100 text-red-700'
      case 'recurring': return 'bg-purple-100 text-purple-700'
    }
  }

  const getImpactColor = (impact: MaintenanceWindow['impactLevel']) => {
    switch (impact) {
      case 'none': return 'text-gray-500'
      case 'minor': return 'text-green-600'
      case 'moderate': return 'text-yellow-600'
      case 'major': return 'text-orange-600'
      case 'critical': return 'text-red-600'
    }
  }

  const formatDateTime = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  // Stats
  const plannedWindows = windows.filter(w => ['planned', 'approved'].includes(w.status)).length
  const inProgress = windows.filter(w => w.status === 'in_progress').length
  const completedThisWeek = windows.filter(w => w.status === 'completed').length
  const upcomingCritical = windows.filter(w => w.priority === 'critical' && ['planned', 'approved'].includes(w.status)).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Maintenance Windows</h1>
          <p className="text-gray-600">Schedule and track system maintenance</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700"
        >
          <Plus className="w-5 h-5" />
          Schedule Maintenance
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Calendar className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{plannedWindows}</p>
              <p className="text-sm text-gray-500">Upcoming</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Play className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{inProgress}</p>
              <p className="text-sm text-gray-500">In Progress</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle2 className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{completedThisWeek}</p>
              <p className="text-sm text-gray-500">Completed</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{upcomingCritical}</p>
              <p className="text-sm text-gray-500">Critical Pending</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search maintenance windows..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
            >
              {types.map(type => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
            >
              {statuses.map(status => (
                <option key={status} value={status}>{status}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Windows List */}
      <div className="space-y-4">
        {filteredWindows.map(window => (
          <div
            key={window.id}
            onClick={() => setSelectedWindow(window)}
            className={`bg-white rounded-lg shadow p-6 cursor-pointer hover:shadow-md transition-shadow ${
              window.status === 'in_progress' ? 'border-l-4 border-yellow-500' :
              window.type === 'emergency' ? 'border-l-4 border-red-500' : ''
            }`}
          >
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-lg ${
                  window.status === 'in_progress' ? 'bg-yellow-100' :
                  window.type === 'emergency' ? 'bg-red-100' :
                  'bg-aether-100'
                }`}>
                  <Wrench className={`w-5 h-5 ${
                    window.status === 'in_progress' ? 'text-yellow-600' :
                    window.type === 'emergency' ? 'text-red-600' :
                    'text-aether-600'
                  }`} />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900">{window.title}</h3>
                  <p className="text-sm text-gray-500">{window.id} • {window.owner}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-1 text-xs font-medium rounded ${getTypeColor(window.type)}`}>
                  {window.type}
                </span>
                <span className={`px-2 py-1 text-xs font-medium rounded ${getStatusColor(window.status)}`}>
                  {window.status.replace('_', ' ')}
                </span>
              </div>
            </div>

            <p className="text-gray-600 line-clamp-2 mb-3">{window.description}</p>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4 text-sm text-gray-500">
                <span className="flex items-center gap-1">
                  <Clock className="w-4 h-4" />
                  {formatDateTime(window.scheduledStart)} - {formatDateTime(window.scheduledEnd)}
                </span>
                <span className="flex items-center gap-1">
                  <Server className="w-4 h-4" />
                  {window.affectedSystems.length} systems
                </span>
                <span className={`flex items-center gap-1 font-medium ${getImpactColor(window.impactLevel)}`}>
                  <AlertTriangle className="w-4 h-4" />
                  {window.impactLevel} impact
                </span>
              </div>
              {window.notificationsSent && (
                <span className="flex items-center gap-1 text-sm text-green-600">
                  <Bell className="w-4 h-4" />
                  Notified
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {filteredWindows.length === 0 && (
        <div className="bg-white rounded-lg shadow p-12 text-center">
          <Wrench className="w-12 h-12 text-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No maintenance windows found</h3>
          <p className="text-gray-500">Try adjusting your search or filter criteria</p>
        </div>
      )}

      {/* Window Detail Modal */}
      {selectedWindow && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setSelectedWindow(null)} />
            <div className="relative bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-500">{selectedWindow.id}</span>
                  <span className={`px-2 py-1 text-xs font-medium rounded ${getTypeColor(selectedWindow.type)}`}>
                    {selectedWindow.type}
                  </span>
                  <span className={`px-2 py-1 text-xs font-medium rounded ${getStatusColor(selectedWindow.status)}`}>
                    {selectedWindow.status.replace('_', ' ')}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedWindow(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6">
                <h2 className="text-xl font-bold text-gray-900 mb-2">{selectedWindow.title}</h2>
                <p className="text-gray-600 mb-6">{selectedWindow.description}</p>

                {/* Schedule */}
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Scheduled Start</p>
                    <p className="font-medium text-gray-900">{formatDateTime(selectedWindow.scheduledStart)}</p>
                    {selectedWindow.actualStart && (
                      <p className="text-sm text-green-600">Actual: {formatDateTime(selectedWindow.actualStart)}</p>
                    )}
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Scheduled End</p>
                    <p className="font-medium text-gray-900">{formatDateTime(selectedWindow.scheduledEnd)}</p>
                    {selectedWindow.actualEnd && (
                      <p className="text-sm text-green-600">Actual: {formatDateTime(selectedWindow.actualEnd)}</p>
                    )}
                  </div>
                </div>

                {/* Details */}
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Owner</p>
                    <p className="font-medium text-gray-900">{selectedWindow.owner}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Approver</p>
                    <p className="font-medium text-gray-900">{selectedWindow.approver || 'Pending'}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Impact Level</p>
                    <p className={`font-medium capitalize ${getImpactColor(selectedWindow.impactLevel)}`}>
                      {selectedWindow.impactLevel}
                    </p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Change Ticket</p>
                    <p className="font-medium text-aether-600">{selectedWindow.changeTicket || 'N/A'}</p>
                  </div>
                </div>

                {/* Affected Systems */}
                <div className="mb-6">
                  <p className="text-sm font-medium text-gray-500 mb-2">Affected Systems</p>
                  <div className="flex flex-wrap gap-2">
                    {selectedWindow.affectedSystems.map(system => (
                      <span key={system} className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm flex items-center gap-1">
                        <Server className="w-3 h-3" />
                        {system}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Rollback Plan */}
                <div className="mb-6 p-4 bg-orange-50 border border-orange-200 rounded-lg">
                  <p className="text-sm font-medium text-orange-700 mb-1 flex items-center gap-1">
                    <RefreshCw className="w-4 h-4" />
                    Rollback Plan
                  </p>
                  <p className="text-orange-800">{selectedWindow.rollbackPlan}</p>
                </div>

                {/* Notes */}
                {selectedWindow.notes.length > 0 && (
                  <div className="mb-6">
                    <p className="text-sm font-medium text-gray-500 mb-2">Notes</p>
                    <div className="space-y-2">
                      {selectedWindow.notes.map((note, i) => (
                        <p key={i} className="text-sm text-gray-700 bg-gray-50 p-3 rounded-lg flex items-start gap-2">
                          <CheckCircle2 className="w-4 h-4 text-green-500 mt-0.5" />
                          {note}
                        </p>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                {selectedWindow.status === 'planned' && (
                  <div className="flex gap-3 pt-4 border-t border-gray-200">
                    <button className="flex-1 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
                      Approve
                    </button>
                    <button className="flex-1 px-4 py-2 border border-gray-200 text-gray-700 rounded-lg hover:bg-gray-50">
                      Request Changes
                    </button>
                  </div>
                )}
                {selectedWindow.status === 'approved' && (
                  <div className="flex gap-3 pt-4 border-t border-gray-200">
                    <button className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center justify-center gap-2">
                      <Play className="w-4 h-4" />
                      Start Maintenance
                    </button>
                    <button className="flex-1 px-4 py-2 border border-gray-200 text-gray-700 rounded-lg hover:bg-gray-50 flex items-center justify-center gap-2">
                      <Bell className="w-4 h-4" />
                      Send Notifications
                    </button>
                  </div>
                )}
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
            <div className="relative bg-white rounded-xl shadow-xl max-w-xl w-full">
              <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
                <h2 className="text-lg font-semibold">Schedule Maintenance</h2>
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Title</label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                    placeholder="Maintenance window title..."
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                  <textarea
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                    placeholder="Describe the maintenance work..."
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                    <select className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent">
                      <option value="scheduled">Scheduled</option>
                      <option value="emergency">Emergency</option>
                      <option value="recurring">Recurring</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Impact Level</label>
                    <select className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent">
                      <option value="none">None</option>
                      <option value="minor">Minor</option>
                      <option value="moderate">Moderate</option>
                      <option value="major">Major</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Start Time</label>
                    <input
                      type="datetime-local"
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">End Time</label>
                    <input
                      type="datetime-local"
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Affected Systems</label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                    placeholder="Comma-separated list of systems..."
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Rollback Plan</label>
                  <textarea
                    rows={2}
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                    placeholder="How to rollback if maintenance fails..."
                  />
                </div>
              </div>
              <div className="px-6 py-4 border-t border-gray-200 flex justify-end gap-3">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
                  Schedule
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
