/**
 * RMM Dashboard - Remote Monitoring and Management
 * Real-time endpoint monitoring, alerts, and automation
 */

import { useState } from 'react'
import {
  Monitor,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Cpu,
  HardDrive,
  Wifi,
  RefreshCw,
  Play,
  Settings,
  Eye,
  Terminal,
  Power,
  Activity,
  Shield,
  ChevronRight,
  Search,
  Filter
} from 'lucide-react'

interface Endpoint {
  id: string
  hostname: string
  ip_address: string
  os: string
  status: 'online' | 'offline' | 'warning' | 'maintenance'
  last_seen: string
  agent_version: string
  client: string
  metrics: {
    cpu: number
    memory: number
    disk: number
    network: number
  }
  alerts: number
  patches_pending: number
}

interface Alert {
  id: string
  endpoint_id: string
  hostname: string
  type: 'critical' | 'warning' | 'info'
  category: string
  message: string
  timestamp: string
  acknowledged: boolean
}

interface AutomationPolicy {
  id: string
  name: string
  trigger: string
  action: string
  enabled: boolean
  last_run: string
  executions: number
}

// Mock data
const mockEndpoints: Endpoint[] = [
  {
    id: 'EP-001',
    hostname: 'WKS-ACME-001',
    ip_address: '192.168.1.101',
    os: 'Windows 11 Pro',
    status: 'online',
    last_seen: '2024-01-15T10:30:00',
    agent_version: '3.2.1',
    client: 'Acme Corp',
    metrics: { cpu: 45, memory: 62, disk: 78, network: 12 },
    alerts: 0,
    patches_pending: 2
  },
  {
    id: 'EP-002',
    hostname: 'SRV-ACME-DC01',
    ip_address: '192.168.1.10',
    os: 'Windows Server 2022',
    status: 'warning',
    last_seen: '2024-01-15T10:29:00',
    agent_version: '3.2.1',
    client: 'Acme Corp',
    metrics: { cpu: 85, memory: 91, disk: 45, network: 34 },
    alerts: 2,
    patches_pending: 5
  },
  {
    id: 'EP-003',
    hostname: 'WKS-GLOBEX-012',
    ip_address: '10.0.0.112',
    os: 'Windows 10 Enterprise',
    status: 'online',
    last_seen: '2024-01-15T10:30:00',
    agent_version: '3.2.0',
    client: 'Globex Industries',
    metrics: { cpu: 23, memory: 45, disk: 56, network: 8 },
    alerts: 0,
    patches_pending: 0
  },
  {
    id: 'EP-004',
    hostname: 'SRV-GLOBEX-APP01',
    ip_address: '10.0.0.20',
    os: 'Ubuntu 22.04 LTS',
    status: 'online',
    last_seen: '2024-01-15T10:30:00',
    agent_version: '3.2.1',
    client: 'Globex Industries',
    metrics: { cpu: 67, memory: 58, disk: 34, network: 45 },
    alerts: 1,
    patches_pending: 3
  },
  {
    id: 'EP-005',
    hostname: 'WKS-INITECH-007',
    ip_address: '172.16.0.107',
    os: 'macOS Sonoma',
    status: 'offline',
    last_seen: '2024-01-15T08:15:00',
    agent_version: '3.1.9',
    client: 'Initech',
    metrics: { cpu: 0, memory: 0, disk: 0, network: 0 },
    alerts: 1,
    patches_pending: 4
  },
  {
    id: 'EP-006',
    hostname: 'SRV-INITECH-SQL01',
    ip_address: '172.16.0.50',
    os: 'Windows Server 2019',
    status: 'maintenance',
    last_seen: '2024-01-15T10:00:00',
    agent_version: '3.2.1',
    client: 'Initech',
    metrics: { cpu: 12, memory: 34, disk: 89, network: 5 },
    alerts: 0,
    patches_pending: 8
  }
]

const mockAlerts: Alert[] = [
  {
    id: 'ALR-001',
    endpoint_id: 'EP-002',
    hostname: 'SRV-ACME-DC01',
    type: 'critical',
    category: 'Performance',
    message: 'Memory usage exceeded 90% threshold',
    timestamp: '2024-01-15T10:25:00',
    acknowledged: false
  },
  {
    id: 'ALR-002',
    endpoint_id: 'EP-002',
    hostname: 'SRV-ACME-DC01',
    type: 'warning',
    category: 'Performance',
    message: 'CPU usage sustained above 80% for 15 minutes',
    timestamp: '2024-01-15T10:20:00',
    acknowledged: false
  },
  {
    id: 'ALR-003',
    endpoint_id: 'EP-005',
    hostname: 'WKS-INITECH-007',
    type: 'critical',
    category: 'Connectivity',
    message: 'Endpoint offline for more than 2 hours',
    timestamp: '2024-01-15T10:15:00',
    acknowledged: false
  },
  {
    id: 'ALR-004',
    endpoint_id: 'EP-004',
    hostname: 'SRV-GLOBEX-APP01',
    type: 'warning',
    category: 'Security',
    message: 'Failed login attempts detected (5 in last hour)',
    timestamp: '2024-01-15T10:10:00',
    acknowledged: true
  }
]

const mockPolicies: AutomationPolicy[] = [
  {
    id: 'POL-001',
    name: 'Auto-Restart Hung Services',
    trigger: 'Service not responding > 5 min',
    action: 'Restart service and notify',
    enabled: true,
    last_run: '2024-01-15T09:45:00',
    executions: 23
  },
  {
    id: 'POL-002',
    name: 'Disk Cleanup on Low Space',
    trigger: 'Disk usage > 85%',
    action: 'Run cleanup script',
    enabled: true,
    last_run: '2024-01-15T08:00:00',
    executions: 156
  },
  {
    id: 'POL-003',
    name: 'Reboot After Updates',
    trigger: 'Pending reboot > 24 hours',
    action: 'Schedule reboot off-hours',
    enabled: true,
    last_run: '2024-01-14T23:00:00',
    executions: 45
  },
  {
    id: 'POL-004',
    name: 'Agent Version Check',
    trigger: 'Agent version outdated',
    action: 'Auto-update agent',
    enabled: false,
    last_run: '2024-01-10T12:00:00',
    executions: 89
  }
]

export default function RMMDashboard() {
  const [activeTab, setActiveTab] = useState<'endpoints' | 'alerts' | 'automation'>('endpoints')
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null)

  const filteredEndpoints = mockEndpoints.filter(ep => {
    const matchesSearch = ep.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ep.ip_address.includes(searchQuery) ||
      ep.client.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesStatus = statusFilter === 'all' || ep.status === statusFilter
    return matchesSearch && matchesStatus
  })

  const stats = {
    total: mockEndpoints.length,
    online: mockEndpoints.filter(e => e.status === 'online').length,
    offline: mockEndpoints.filter(e => e.status === 'offline').length,
    warning: mockEndpoints.filter(e => e.status === 'warning').length,
    alerts: mockAlerts.filter(a => !a.acknowledged).length
  }

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      online: 'bg-green-100 text-green-800',
      offline: 'bg-red-100 text-red-800',
      warning: 'bg-yellow-100 text-yellow-800',
      maintenance: 'bg-blue-100 text-blue-800'
    }
    return styles[status] || 'bg-gray-100 text-gray-800'
  }

  const getMetricColor = (value: number) => {
    if (value >= 90) return 'text-red-600'
    if (value >= 75) return 'text-yellow-600'
    return 'text-green-600'
  }

  const getMetricBarColor = (value: number) => {
    if (value >= 90) return 'bg-red-500'
    if (value >= 75) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">RMM Dashboard</h1>
          <p className="text-gray-500">Remote Monitoring and Management</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-4 py-2 text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button className="flex items-center gap-2 px-4 py-2 text-white bg-aether-600 rounded-lg hover:bg-aether-700">
            <Play className="w-4 h-4" />
            Run Discovery
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-5 gap-4">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Monitor className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold">{stats.total}</p>
              <p className="text-sm text-gray-500">Total Endpoints</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-green-600">{stats.online}</p>
              <p className="text-sm text-gray-500">Online</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 rounded-lg">
              <XCircle className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-red-600">{stats.offline}</p>
              <p className="text-sm text-gray-500">Offline</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-yellow-600">{stats.warning}</p>
              <p className="text-sm text-gray-500">Warning</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Activity className="w-5 h-5 text-purple-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-purple-600">{stats.alerts}</p>
              <p className="text-sm text-gray-500">Active Alerts</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-lg shadow">
        <div className="border-b border-gray-200">
          <nav className="flex -mb-px">
            {[
              { id: 'endpoints', label: 'Endpoints', icon: Monitor },
              { id: 'alerts', label: 'Alerts', icon: AlertTriangle, badge: stats.alerts },
              { id: 'automation', label: 'Automation', icon: Settings }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-6 py-4 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-aether-600 text-aether-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
                {tab.badge && tab.badge > 0 && (
                  <span className="px-2 py-0.5 text-xs bg-red-100 text-red-800 rounded-full">
                    {tab.badge}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'endpoints' && (
            <div className="space-y-4">
              {/* Filters */}
              <div className="flex items-center gap-4">
                <div className="relative flex-1 max-w-md">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search by hostname, IP, or client..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <Filter className="w-4 h-4 text-gray-400" />
                  <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
                  >
                    <option value="all">All Status</option>
                    <option value="online">Online</option>
                    <option value="offline">Offline</option>
                    <option value="warning">Warning</option>
                    <option value="maintenance">Maintenance</option>
                  </select>
                </div>
              </div>

              {/* Endpoints Table */}
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-200">
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Endpoint</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Status</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Client</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">CPU</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Memory</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Disk</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Alerts</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEndpoints.map(endpoint => (
                      <tr key={endpoint.id} className="border-b border-gray-100 hover:bg-gray-50">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-3">
                            <div className="p-2 bg-gray-100 rounded-lg">
                              {endpoint.os.includes('Server') ? (
                                <Server className="w-4 h-4 text-gray-600" />
                              ) : (
                                <Monitor className="w-4 h-4 text-gray-600" />
                              )}
                            </div>
                            <div>
                              <p className="font-medium">{endpoint.hostname}</p>
                              <p className="text-sm text-gray-500">{endpoint.ip_address} • {endpoint.os}</p>
                            </div>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 text-xs rounded-full capitalize ${getStatusBadge(endpoint.status)}`}>
                            {endpoint.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-sm">{endpoint.client}</td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${getMetricBarColor(endpoint.metrics.cpu)}`}
                                style={{ width: `${endpoint.metrics.cpu}%` }}
                              />
                            </div>
                            <span className={`text-sm font-medium ${getMetricColor(endpoint.metrics.cpu)}`}>
                              {endpoint.metrics.cpu}%
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${getMetricBarColor(endpoint.metrics.memory)}`}
                                style={{ width: `${endpoint.metrics.memory}%` }}
                              />
                            </div>
                            <span className={`text-sm font-medium ${getMetricColor(endpoint.metrics.memory)}`}>
                              {endpoint.metrics.memory}%
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${getMetricBarColor(endpoint.metrics.disk)}`}
                                style={{ width: `${endpoint.metrics.disk}%` }}
                              />
                            </div>
                            <span className={`text-sm font-medium ${getMetricColor(endpoint.metrics.disk)}`}>
                              {endpoint.metrics.disk}%
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          {endpoint.alerts > 0 ? (
                            <span className="px-2 py-1 text-xs bg-red-100 text-red-800 rounded-full">
                              {endpoint.alerts} alerts
                            </span>
                          ) : (
                            <span className="text-sm text-gray-400">None</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => setSelectedEndpoint(endpoint)}
                              className="p-1.5 text-gray-400 hover:text-aether-600 hover:bg-aether-50 rounded"
                              title="View Details"
                            >
                              <Eye className="w-4 h-4" />
                            </button>
                            <button className="p-1.5 text-gray-400 hover:text-aether-600 hover:bg-aether-50 rounded" title="Remote Terminal">
                              <Terminal className="w-4 h-4" />
                            </button>
                            <button className="p-1.5 text-gray-400 hover:text-aether-600 hover:bg-aether-50 rounded" title="Power Options">
                              <Power className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-4">
              {mockAlerts.map(alert => (
                <div
                  key={alert.id}
                  className={`p-4 rounded-lg border-l-4 ${
                    alert.type === 'critical'
                      ? 'bg-red-50 border-red-500'
                      : alert.type === 'warning'
                      ? 'bg-yellow-50 border-yellow-500'
                      : 'bg-blue-50 border-blue-500'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className={`w-5 h-5 mt-0.5 ${
                        alert.type === 'critical' ? 'text-red-600' :
                        alert.type === 'warning' ? 'text-yellow-600' : 'text-blue-600'
                      }`} />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 text-xs rounded-full capitalize ${
                            alert.type === 'critical' ? 'bg-red-100 text-red-800' :
                            alert.type === 'warning' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-blue-100 text-blue-800'
                          }`}>
                            {alert.type}
                          </span>
                          <span className="text-sm font-medium text-gray-700">{alert.category}</span>
                          {alert.acknowledged && (
                            <span className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded-full">
                              Acknowledged
                            </span>
                          )}
                        </div>
                        <p className="mt-1 font-medium text-gray-900">{alert.message}</p>
                        <p className="text-sm text-gray-500 mt-1">
                          {alert.hostname} • {new Date(alert.timestamp).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {!alert.acknowledged && (
                        <button className="px-3 py-1.5 text-sm text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
                          Acknowledge
                        </button>
                      )}
                      <button className="px-3 py-1.5 text-sm text-white bg-aether-600 rounded-lg hover:bg-aether-700">
                        View Details
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'automation' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Automation Policies</h3>
                <button className="flex items-center gap-2 px-4 py-2 text-white bg-aether-600 rounded-lg hover:bg-aether-700">
                  <Settings className="w-4 h-4" />
                  Create Policy
                </button>
              </div>

              <div className="space-y-3">
                {mockPolicies.map(policy => (
                  <div
                    key={policy.id}
                    className={`p-4 bg-white border rounded-lg ${policy.enabled ? 'border-green-200' : 'border-gray-200'}`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <div className={`w-3 h-3 rounded-full ${policy.enabled ? 'bg-green-500' : 'bg-gray-300'}`} />
                        <div>
                          <p className="font-medium">{policy.name}</p>
                          <div className="flex items-center gap-4 mt-1 text-sm text-gray-500">
                            <span><strong>Trigger:</strong> {policy.trigger}</span>
                            <span><strong>Action:</strong> {policy.action}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right text-sm">
                          <p className="text-gray-500">Last run: {new Date(policy.last_run).toLocaleString()}</p>
                          <p className="text-gray-500">{policy.executions} total executions</p>
                        </div>
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input type="checkbox" checked={policy.enabled} className="sr-only peer" readOnly />
                          <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-aether-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-aether-600"></div>
                        </label>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Endpoint Detail Drawer */}
      {selectedEndpoint && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-black/50" onClick={() => setSelectedEndpoint(null)} />
          <div className="relative w-full max-w-lg bg-white shadow-xl">
            <div className="flex items-center justify-between p-4 border-b">
              <h3 className="text-lg font-semibold">{selectedEndpoint.hostname}</h3>
              <button onClick={() => setSelectedEndpoint(null)} className="text-gray-400 hover:text-gray-600">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-6 overflow-y-auto" style={{ maxHeight: 'calc(100vh - 80px)' }}>
              {/* Status */}
              <div className="flex items-center gap-4">
                <span className={`px-3 py-1 text-sm rounded-full capitalize ${getStatusBadge(selectedEndpoint.status)}`}>
                  {selectedEndpoint.status}
                </span>
                <span className="text-sm text-gray-500">Last seen: {new Date(selectedEndpoint.last_seen).toLocaleString()}</span>
              </div>

              {/* Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-500">IP Address</p>
                  <p className="font-medium">{selectedEndpoint.ip_address}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-500">Operating System</p>
                  <p className="font-medium">{selectedEndpoint.os}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-500">Client</p>
                  <p className="font-medium">{selectedEndpoint.client}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-500">Agent Version</p>
                  <p className="font-medium">{selectedEndpoint.agent_version}</p>
                </div>
              </div>

              {/* Metrics */}
              <div>
                <h4 className="font-semibold mb-3">System Metrics</h4>
                <div className="space-y-3">
                  {[
                    { label: 'CPU', value: selectedEndpoint.metrics.cpu, icon: Cpu },
                    { label: 'Memory', value: selectedEndpoint.metrics.memory, icon: Activity },
                    { label: 'Disk', value: selectedEndpoint.metrics.disk, icon: HardDrive },
                    { label: 'Network', value: selectedEndpoint.metrics.network, icon: Wifi }
                  ].map(metric => (
                    <div key={metric.label} className="flex items-center gap-3">
                      <metric.icon className="w-4 h-4 text-gray-400" />
                      <span className="w-16 text-sm">{metric.label}</span>
                      <div className="flex-1 h-2 bg-gray-200 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${getMetricBarColor(metric.value)}`}
                          style={{ width: `${metric.value}%` }}
                        />
                      </div>
                      <span className={`w-12 text-sm font-medium text-right ${getMetricColor(metric.value)}`}>
                        {metric.value}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Quick Actions */}
              <div>
                <h4 className="font-semibold mb-3">Quick Actions</h4>
                <div className="grid grid-cols-2 gap-2">
                  <button className="flex items-center justify-center gap-2 p-3 bg-gray-100 rounded-lg hover:bg-gray-200">
                    <Terminal className="w-4 h-4" />
                    Remote Shell
                  </button>
                  <button className="flex items-center justify-center gap-2 p-3 bg-gray-100 rounded-lg hover:bg-gray-200">
                    <Monitor className="w-4 h-4" />
                    Remote Desktop
                  </button>
                  <button className="flex items-center justify-center gap-2 p-3 bg-gray-100 rounded-lg hover:bg-gray-200">
                    <RefreshCw className="w-4 h-4" />
                    Restart Agent
                  </button>
                  <button className="flex items-center justify-center gap-2 p-3 bg-gray-100 rounded-lg hover:bg-gray-200">
                    <Power className="w-4 h-4" />
                    Reboot System
                  </button>
                </div>
              </div>

              {/* Patches */}
              <div>
                <h4 className="font-semibold mb-3">Pending Patches</h4>
                {selectedEndpoint.patches_pending > 0 ? (
                  <div className="flex items-center justify-between p-3 bg-yellow-50 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4 text-yellow-600" />
                      <span>{selectedEndpoint.patches_pending} patches pending</span>
                    </div>
                    <button className="text-sm text-aether-600 hover:text-aether-700 font-medium">
                      Install Now
                    </button>
                  </div>
                ) : (
                  <p className="text-sm text-gray-500">All patches installed</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
