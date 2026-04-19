import { useState } from 'react'
import {
  Bell,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  XCircle,
  Clock,
  Server,
  Shield,
  Cpu,
  HardDrive,
  Wifi,
  Filter,
  Search,
  Settings,
  Volume2,
  VolumeX,
  Eye,
  EyeOff,
  Trash2,
  ChevronRight,
  RefreshCw,
  MoreVertical
} from 'lucide-react'

interface Alert {
  id: string
  title: string
  message: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: 'security' | 'performance' | 'availability' | 'capacity' | 'compliance'
  source: string
  sourceType: 'server' | 'network' | 'application' | 'database' | 'security'
  status: 'active' | 'acknowledged' | 'resolved' | 'suppressed'
  triggeredAt: string
  acknowledgedAt?: string
  resolvedAt?: string
  acknowledgedBy?: string
  count: number
  relatedAlerts: number
}

interface AlertRule {
  id: string
  name: string
  condition: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  enabled: boolean
  notifyChannels: string[]
  triggerCount: number
}

const alerts: Alert[] = [
  {
    id: 'ALT-001',
    title: 'CPU Usage Critical',
    message: 'Server prod-web-01 CPU usage exceeded 95% for more than 5 minutes',
    severity: 'critical',
    category: 'performance',
    source: 'prod-web-01',
    sourceType: 'server',
    status: 'active',
    triggeredAt: '2025-01-18T14:32:00Z',
    count: 3,
    relatedAlerts: 2
  },
  {
    id: 'ALT-002',
    title: 'Disk Space Low',
    message: 'Database server db-primary disk usage at 92%',
    severity: 'high',
    category: 'capacity',
    source: 'db-primary',
    sourceType: 'database',
    status: 'acknowledged',
    triggeredAt: '2025-01-18T12:15:00Z',
    acknowledgedAt: '2025-01-18T12:20:00Z',
    acknowledgedBy: 'David Johnson',
    count: 1,
    relatedAlerts: 0
  },
  {
    id: 'ALT-003',
    title: 'Failed Login Attempts',
    message: 'Multiple failed login attempts detected from IP 192.168.1.105',
    severity: 'high',
    category: 'security',
    source: 'auth-service',
    sourceType: 'security',
    status: 'active',
    triggeredAt: '2025-01-18T14:45:00Z',
    count: 15,
    relatedAlerts: 5
  },
  {
    id: 'ALT-004',
    title: 'API Response Time Degraded',
    message: 'API gateway response time exceeded 2000ms threshold',
    severity: 'medium',
    category: 'performance',
    source: 'api-gateway',
    sourceType: 'application',
    status: 'resolved',
    triggeredAt: '2025-01-18T10:30:00Z',
    resolvedAt: '2025-01-18T11:15:00Z',
    count: 1,
    relatedAlerts: 0
  },
  {
    id: 'ALT-005',
    title: 'SSL Certificate Expiring',
    message: 'SSL certificate for api.aither.io expires in 14 days',
    severity: 'medium',
    category: 'compliance',
    source: 'api.aither.io',
    sourceType: 'application',
    status: 'active',
    triggeredAt: '2025-01-18T00:00:00Z',
    count: 1,
    relatedAlerts: 0
  },
  {
    id: 'ALT-006',
    title: 'Network Latency Spike',
    message: 'Network latency to AWS us-east-1 exceeded 100ms',
    severity: 'low',
    category: 'performance',
    source: 'network-monitor',
    sourceType: 'network',
    status: 'suppressed',
    triggeredAt: '2025-01-18T13:00:00Z',
    count: 8,
    relatedAlerts: 3
  },
  {
    id: 'ALT-007',
    title: 'Backup Job Failed',
    message: 'Scheduled backup for db-replica failed with timeout error',
    severity: 'high',
    category: 'availability',
    source: 'backup-service',
    sourceType: 'application',
    status: 'active',
    triggeredAt: '2025-01-18T02:00:00Z',
    count: 2,
    relatedAlerts: 1
  },
  {
    id: 'ALT-008',
    title: 'Memory Usage Warning',
    message: 'Application server app-02 memory usage at 85%',
    severity: 'medium',
    category: 'capacity',
    source: 'app-02',
    sourceType: 'server',
    status: 'acknowledged',
    triggeredAt: '2025-01-18T11:45:00Z',
    acknowledgedAt: '2025-01-18T12:00:00Z',
    acknowledgedBy: 'Sarah Mitchell',
    count: 1,
    relatedAlerts: 0
  }
]

const alertRules: AlertRule[] = [
  { id: 'RULE-001', name: 'CPU High Usage', condition: 'CPU > 90% for 5 min', severity: 'critical', enabled: true, notifyChannels: ['slack', 'pagerduty'], triggerCount: 45 },
  { id: 'RULE-002', name: 'Disk Space Critical', condition: 'Disk > 90%', severity: 'high', enabled: true, notifyChannels: ['slack', 'email'], triggerCount: 12 },
  { id: 'RULE-003', name: 'Failed Logins', condition: '> 10 failed logins in 5 min', severity: 'high', enabled: true, notifyChannels: ['slack', 'pagerduty', 'email'], triggerCount: 8 },
  { id: 'RULE-004', name: 'API Latency', condition: 'Response time > 2000ms', severity: 'medium', enabled: true, notifyChannels: ['slack'], triggerCount: 156 },
  { id: 'RULE-005', name: 'SSL Expiry Warning', condition: 'Certificate expires < 30 days', severity: 'medium', enabled: true, notifyChannels: ['email'], triggerCount: 3 },
  { id: 'RULE-006', name: 'Memory Warning', condition: 'Memory > 80%', severity: 'low', enabled: false, notifyChannels: ['slack'], triggerCount: 234 }
]

export default function AlertsManagement() {
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [activeTab, setActiveTab] = useState<'alerts' | 'rules' | 'history'>('alerts')
  const [localAlerts, setLocalAlerts] = useState(alerts)

  const filteredAlerts = localAlerts.filter(alert => {
    const matchesSearch = alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         alert.source.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter
    const matchesStatus = statusFilter === 'all' || alert.status === statusFilter
    const matchesCategory = categoryFilter === 'all' || alert.category === categoryFilter
    return matchesSearch && matchesSeverity && matchesStatus && matchesCategory
  })

  const stats = {
    critical: localAlerts.filter(a => a.severity === 'critical' && a.status === 'active').length,
    high: localAlerts.filter(a => a.severity === 'high' && a.status === 'active').length,
    medium: localAlerts.filter(a => a.severity === 'medium' && a.status === 'active').length,
    low: localAlerts.filter(a => a.severity === 'low' && a.status === 'active').length,
    total: localAlerts.filter(a => a.status === 'active').length,
    acknowledged: localAlerts.filter(a => a.status === 'acknowledged').length
  }

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-blue-100 text-blue-800 border-blue-200',
      info: 'bg-gray-100 text-gray-800 border-gray-200'
    }
    return colors[severity] || 'bg-gray-100 text-gray-800'
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <AlertCircle className="w-5 h-5 text-red-500" />
      case 'high': return <AlertTriangle className="w-5 h-5 text-orange-500" />
      case 'medium': return <AlertTriangle className="w-5 h-5 text-yellow-500" />
      case 'low': return <Info className="w-5 h-5 text-blue-500" />
      default: return <Info className="w-5 h-5 text-gray-500" />
    }
  }

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      active: 'bg-red-100 text-red-800',
      acknowledged: 'bg-yellow-100 text-yellow-800',
      resolved: 'bg-green-100 text-green-800',
      suppressed: 'bg-gray-100 text-gray-800'
    }
    return styles[status] || 'bg-gray-100 text-gray-800'
  }

  const getSourceIcon = (sourceType: string) => {
    switch (sourceType) {
      case 'server': return <Server className="w-4 h-4" />
      case 'network': return <Wifi className="w-4 h-4" />
      case 'application': return <Cpu className="w-4 h-4" />
      case 'database': return <HardDrive className="w-4 h-4" />
      case 'security': return <Shield className="w-4 h-4" />
      default: return <Server className="w-4 h-4" />
    }
  }

  const formatTime = (dateStr: string) => {
    const date = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMs / 3600000)

    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    return date.toLocaleDateString()
  }

  const acknowledgeAlert = (alertId: string) => {
    setLocalAlerts(prev => prev.map(a =>
      a.id === alertId ? {
        ...a,
        status: 'acknowledged',
        acknowledgedAt: new Date().toISOString(),
        acknowledgedBy: 'Current User'
      } : a
    ))
  }

  const resolveAlert = (alertId: string) => {
    setLocalAlerts(prev => prev.map(a =>
      a.id === alertId ? {
        ...a,
        status: 'resolved',
        resolvedAt: new Date().toISOString()
      } : a
    ))
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Alerts Management</h1>
          <p className="text-gray-500">Monitor and manage system alerts and notifications</p>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 flex items-center gap-2">
            <Settings className="w-4 h-4" />
            Alert Rules
          </button>
          <button className="px-4 py-2 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 flex items-center gap-2">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Severity Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <div className="bg-red-50 border border-red-200 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <AlertCircle className="w-6 h-6 text-red-500" />
            <span className="text-2xl font-bold text-red-700">{stats.critical}</span>
          </div>
          <p className="text-sm text-red-600 mt-1">Critical</p>
        </div>
        <div className="bg-orange-50 border border-orange-200 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <AlertTriangle className="w-6 h-6 text-orange-500" />
            <span className="text-2xl font-bold text-orange-700">{stats.high}</span>
          </div>
          <p className="text-sm text-orange-600 mt-1">High</p>
        </div>
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <AlertTriangle className="w-6 h-6 text-yellow-500" />
            <span className="text-2xl font-bold text-yellow-700">{stats.medium}</span>
          </div>
          <p className="text-sm text-yellow-600 mt-1">Medium</p>
        </div>
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <Info className="w-6 h-6 text-blue-500" />
            <span className="text-2xl font-bold text-blue-700">{stats.low}</span>
          </div>
          <p className="text-sm text-blue-600 mt-1">Low</p>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <Bell className="w-6 h-6 text-gray-500" />
            <span className="text-2xl font-bold text-gray-700">{stats.total}</span>
          </div>
          <p className="text-sm text-gray-600 mt-1">Total Active</p>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <Eye className="w-6 h-6 text-gray-500" />
            <span className="text-2xl font-bold text-gray-700">{stats.acknowledged}</span>
          </div>
          <p className="text-sm text-gray-600 mt-1">Acknowledged</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-4">
          {[
            { id: 'alerts', label: 'Active Alerts', icon: Bell },
            { id: 'rules', label: 'Alert Rules', icon: Settings },
            { id: 'history', label: 'History', icon: Clock }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as 'alerts' | 'rules' | 'history')}
              className={`flex items-center gap-2 px-4 py-3 border-b-2 font-medium transition-colors ${
                activeTab === tab.id
                  ? 'border-aether-600 text-aether-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Alerts Tab */}
      {activeTab === 'alerts' && (
        <>
          {/* Filters */}
          <div className="flex flex-wrap gap-4 items-center">
            <div className="relative flex-1 min-w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search alerts..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
              >
                <option value="all">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
              >
                <option value="all">All Status</option>
                <option value="active">Active</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
                <option value="suppressed">Suppressed</option>
              </select>
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
              >
                <option value="all">All Categories</option>
                <option value="security">Security</option>
                <option value="performance">Performance</option>
                <option value="availability">Availability</option>
                <option value="capacity">Capacity</option>
                <option value="compliance">Compliance</option>
              </select>
            </div>
          </div>

          {/* Alerts List */}
          <div className="space-y-3">
            {filteredAlerts.map(alert => (
              <div
                key={alert.id}
                className={`bg-white rounded-xl border p-4 hover:shadow-md transition-shadow cursor-pointer ${
                  alert.severity === 'critical' ? 'border-red-200' :
                  alert.severity === 'high' ? 'border-orange-200' : 'border-gray-200'
                }`}
                onClick={() => setSelectedAlert(alert)}
              >
                <div className="flex items-start gap-4">
                  {getSeverityIcon(alert.severity)}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="font-semibold text-gray-900">{alert.title}</h3>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getStatusBadge(alert.status)}`}>
                        {alert.status}
                      </span>
                      {alert.count > 1 && (
                        <span className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full text-xs">
                          ×{alert.count}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{alert.message}</p>
                    <div className="flex items-center gap-4 text-xs text-gray-500">
                      <span className="flex items-center gap-1">
                        {getSourceIcon(alert.sourceType)}
                        {alert.source}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatTime(alert.triggeredAt)}
                      </span>
                      {alert.relatedAlerts > 0 && (
                        <span className="text-aether-600">{alert.relatedAlerts} related</span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {alert.status === 'active' && (
                      <button
                        onClick={(e) => { e.stopPropagation(); acknowledgeAlert(alert.id) }}
                        className="px-3 py-1.5 text-sm bg-yellow-100 text-yellow-700 rounded-lg hover:bg-yellow-200"
                      >
                        Acknowledge
                      </button>
                    )}
                    {(alert.status === 'active' || alert.status === 'acknowledged') && (
                      <button
                        onClick={(e) => { e.stopPropagation(); resolveAlert(alert.id) }}
                        className="px-3 py-1.5 text-sm bg-green-100 text-green-700 rounded-lg hover:bg-green-200"
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Rules Tab */}
      {activeTab === 'rules' && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Rule</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Condition</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Severity</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Channels</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Triggers</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {alertRules.map(rule => (
                <tr key={rule.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <span className="font-medium text-gray-900">{rule.name}</span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">
                    {rule.condition}
                  </td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(rule.severity)}`}>
                      {rule.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex gap-1">
                      {rule.notifyChannels.map(channel => (
                        <span key={channel} className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded text-xs">
                          {channel}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">
                    {rule.triggerCount}
                  </td>
                  <td className="px-6 py-4">
                    <button className={`relative w-12 h-6 rounded-full transition-colors ${
                      rule.enabled ? 'bg-green-500' : 'bg-gray-300'
                    }`}>
                      <span className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                        rule.enabled ? 'left-7' : 'left-1'
                      }`} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="text-center py-12">
            <Clock className="w-12 h-12 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">Alert History</h3>
            <p className="text-gray-500 max-w-md mx-auto">
              View historical alerts, resolution times, and trend analysis.
            </p>
          </div>
        </div>
      )}

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className={`p-6 border-b ${
              selectedAlert.severity === 'critical' ? 'bg-red-50 border-red-200' :
              selectedAlert.severity === 'high' ? 'bg-orange-50 border-orange-200' :
              'bg-gray-50 border-gray-200'
            }`}>
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3">
                  {getSeverityIcon(selectedAlert.severity)}
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <h2 className="text-xl font-bold text-gray-900">{selectedAlert.title}</h2>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadge(selectedAlert.status)}`}>
                        {selectedAlert.status}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600">{selectedAlert.id}</p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="p-2 text-gray-400 hover:text-gray-600 rounded-lg"
                >
                  <XCircle className="w-5 h-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-6">
              <div className="bg-gray-50 rounded-lg p-4">
                <p className="text-gray-700">{selectedAlert.message}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Source</p>
                  <div className="flex items-center gap-2">
                    {getSourceIcon(selectedAlert.sourceType)}
                    <span className="font-medium text-gray-900">{selectedAlert.source}</span>
                  </div>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Category</p>
                  <p className="font-medium text-gray-900 capitalize">{selectedAlert.category}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Triggered</p>
                  <p className="font-medium text-gray-900">{new Date(selectedAlert.triggeredAt).toLocaleString()}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Occurrences</p>
                  <p className="font-medium text-gray-900">{selectedAlert.count} times</p>
                </div>
              </div>

              {selectedAlert.acknowledgedBy && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                  <p className="text-sm text-yellow-700">
                    Acknowledged by <span className="font-medium">{selectedAlert.acknowledgedBy}</span> at {new Date(selectedAlert.acknowledgedAt!).toLocaleString()}
                  </p>
                </div>
              )}

              {selectedAlert.resolvedAt && (
                <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                  <p className="text-sm text-green-700">
                    Resolved at {new Date(selectedAlert.resolvedAt).toLocaleString()}
                  </p>
                </div>
              )}

              <div className="flex gap-3 pt-4 border-t border-gray-200">
                {selectedAlert.status === 'active' && (
                  <button
                    onClick={() => { acknowledgeAlert(selectedAlert.id); setSelectedAlert(null) }}
                    className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600"
                  >
                    <Eye className="w-4 h-4" />
                    Acknowledge
                  </button>
                )}
                {selectedAlert.status !== 'resolved' && (
                  <button
                    onClick={() => { resolveAlert(selectedAlert.id); setSelectedAlert(null) }}
                    className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-green-600 text-white rounded-lg hover:bg-green-700"
                  >
                    <CheckCircle className="w-4 h-4" />
                    Resolve
                  </button>
                )}
                <button className="px-4 py-2.5 border border-gray-200 rounded-lg hover:bg-gray-50">
                  <VolumeX className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
