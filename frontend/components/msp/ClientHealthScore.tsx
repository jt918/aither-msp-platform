import { useState } from 'react'
import {
  Activity,
  Building2,
  Shield,
  Server,
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  TrendingDown,
  ChevronRight,
  Clock,
  Cpu,
  HardDrive,
  Wifi,
  RefreshCw,
  Filter,
  Search,
  X
} from 'lucide-react'

interface HealthMetric {
  name: string
  score: number
  weight: number
  status: 'healthy' | 'warning' | 'critical'
  trend: 'up' | 'down' | 'stable'
  details: string
}

interface ClientHealth {
  id: string
  name: string
  industry: string
  overallScore: number
  previousScore: number
  status: 'healthy' | 'warning' | 'critical'
  metrics: HealthMetric[]
  deviceCount: number
  openTickets: number
  criticalAlerts: number
  lastAssessment: string
  contractType: string
}

const mockClients: ClientHealth[] = [
  {
    id: 'CLT-001',
    name: 'Acme Corporation',
    industry: 'Manufacturing',
    overallScore: 92,
    previousScore: 89,
    status: 'healthy',
    metrics: [
      { name: 'Security Posture', score: 95, weight: 25, status: 'healthy', trend: 'up', details: 'All endpoints protected, no vulnerabilities' },
      { name: 'Patch Compliance', score: 88, weight: 20, status: 'healthy', trend: 'stable', details: '88% devices fully patched' },
      { name: 'Backup Health', score: 100, weight: 20, status: 'healthy', trend: 'stable', details: 'All backups successful' },
      { name: 'System Performance', score: 85, weight: 15, status: 'healthy', trend: 'down', details: 'Minor performance degradation on 2 servers' },
      { name: 'Network Health', score: 94, weight: 20, status: 'healthy', trend: 'up', details: '99.9% uptime this month' }
    ],
    deviceCount: 156,
    openTickets: 3,
    criticalAlerts: 0,
    lastAssessment: '2025-01-20T10:30:00',
    contractType: 'Premium'
  },
  {
    id: 'CLT-002',
    name: 'TechStart Inc',
    industry: 'Technology',
    overallScore: 78,
    previousScore: 82,
    status: 'warning',
    metrics: [
      { name: 'Security Posture', score: 72, weight: 25, status: 'warning', trend: 'down', details: '5 endpoints missing antivirus' },
      { name: 'Patch Compliance', score: 65, weight: 20, status: 'warning', trend: 'down', details: '35% devices need updates' },
      { name: 'Backup Health', score: 90, weight: 20, status: 'healthy', trend: 'stable', details: '1 backup job failed yesterday' },
      { name: 'System Performance', score: 82, weight: 15, status: 'healthy', trend: 'stable', details: 'Normal performance levels' },
      { name: 'Network Health', score: 80, weight: 20, status: 'warning', trend: 'down', details: 'Intermittent connectivity issues' }
    ],
    deviceCount: 89,
    openTickets: 12,
    criticalAlerts: 2,
    lastAssessment: '2025-01-20T09:15:00',
    contractType: 'Standard'
  },
  {
    id: 'CLT-003',
    name: 'HealthFirst Medical',
    industry: 'Healthcare',
    overallScore: 45,
    previousScore: 52,
    status: 'critical',
    metrics: [
      { name: 'Security Posture', score: 40, weight: 25, status: 'critical', trend: 'down', details: 'HIPAA compliance issues detected' },
      { name: 'Patch Compliance', score: 35, weight: 20, status: 'critical', trend: 'down', details: 'Critical patches missing on 65% devices' },
      { name: 'Backup Health', score: 60, weight: 20, status: 'warning', trend: 'down', details: '3 backup jobs failing consistently' },
      { name: 'System Performance', score: 50, weight: 15, status: 'warning', trend: 'stable', details: 'Database server overloaded' },
      { name: 'Network Health', score: 45, weight: 20, status: 'critical', trend: 'down', details: 'Firewall rules misconfigured' }
    ],
    deviceCount: 234,
    openTickets: 28,
    criticalAlerts: 8,
    lastAssessment: '2025-01-20T11:00:00',
    contractType: 'Enterprise'
  },
  {
    id: 'CLT-004',
    name: 'Global Finance LLC',
    industry: 'Finance',
    overallScore: 96,
    previousScore: 95,
    status: 'healthy',
    metrics: [
      { name: 'Security Posture', score: 98, weight: 25, status: 'healthy', trend: 'up', details: 'Full compliance, zero vulnerabilities' },
      { name: 'Patch Compliance', score: 95, weight: 20, status: 'healthy', trend: 'stable', details: '95% devices fully patched' },
      { name: 'Backup Health', score: 100, weight: 20, status: 'healthy', trend: 'stable', details: 'All backups verified' },
      { name: 'System Performance', score: 92, weight: 15, status: 'healthy', trend: 'up', details: 'Optimized performance' },
      { name: 'Network Health', score: 96, weight: 20, status: 'healthy', trend: 'stable', details: '100% uptime this month' }
    ],
    deviceCount: 312,
    openTickets: 2,
    criticalAlerts: 0,
    lastAssessment: '2025-01-20T08:45:00',
    contractType: 'Enterprise'
  },
  {
    id: 'CLT-005',
    name: 'RetailMax Stores',
    industry: 'Retail',
    overallScore: 71,
    previousScore: 68,
    status: 'warning',
    metrics: [
      { name: 'Security Posture', score: 75, weight: 25, status: 'warning', trend: 'up', details: 'POS systems need security update' },
      { name: 'Patch Compliance', score: 70, weight: 20, status: 'warning', trend: 'up', details: '30% devices need updates' },
      { name: 'Backup Health', score: 80, weight: 20, status: 'healthy', trend: 'stable', details: 'Backups running normally' },
      { name: 'System Performance', score: 65, weight: 15, status: 'warning', trend: 'stable', details: 'Some POS terminals slow' },
      { name: 'Network Health', score: 68, weight: 20, status: 'warning', trend: 'up', details: 'Store connectivity issues at 3 locations' }
    ],
    deviceCount: 445,
    openTickets: 15,
    criticalAlerts: 1,
    lastAssessment: '2025-01-20T07:30:00',
    contractType: 'Standard'
  }
]

export default function ClientHealthScore() {
  const [clients] = useState<ClientHealth[]>(mockClients)
  const [selectedClient, setSelectedClient] = useState<ClientHealth | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterStatus, setFilterStatus] = useState<string>('all')

  const filteredClients = clients.filter(client => {
    const matchesSearch = client.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      client.industry.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesStatus = filterStatus === 'all' || client.status === filterStatus
    return matchesSearch && matchesStatus
  })

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-600 bg-green-100'
      case 'warning': return 'text-yellow-600 bg-yellow-100'
      case 'critical': return 'text-red-600 bg-red-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600'
    if (score >= 60) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getScoreBgColor = (score: number) => {
    if (score >= 80) return 'bg-green-500'
    if (score >= 60) return 'bg-yellow-500'
    return 'bg-red-500'
  }

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <TrendingUp className="w-4 h-4 text-green-500" />
      case 'down': return <TrendingDown className="w-4 h-4 text-red-500" />
      default: return <Activity className="w-4 h-4 text-gray-400" />
    }
  }

  const averageScore = Math.round(clients.reduce((sum, c) => sum + c.overallScore, 0) / clients.length)
  const healthyCount = clients.filter(c => c.status === 'healthy').length
  const warningCount = clients.filter(c => c.status === 'warning').length
  const criticalCount = clients.filter(c => c.status === 'critical').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Client Health Scores</h1>
          <p className="text-gray-600 mt-1">Monitor and assess client infrastructure health</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
          <RefreshCw className="w-4 h-4" />
          Refresh All
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Average Health Score</p>
              <p className={`text-3xl font-bold ${getScoreColor(averageScore)}`}>{averageScore}%</p>
            </div>
            <div className={`p-3 rounded-lg ${averageScore >= 80 ? 'bg-green-100' : averageScore >= 60 ? 'bg-yellow-100' : 'bg-red-100'}`}>
              <Activity className={`w-6 h-6 ${getScoreColor(averageScore)}`} />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Healthy Clients</p>
              <p className="text-3xl font-bold text-green-600">{healthyCount}</p>
            </div>
            <div className="p-3 bg-green-100 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Needs Attention</p>
              <p className="text-3xl font-bold text-yellow-600">{warningCount}</p>
            </div>
            <div className="p-3 bg-yellow-100 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-yellow-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Critical</p>
              <p className="text-3xl font-bold text-red-600">{criticalCount}</p>
            </div>
            <div className="p-3 bg-red-100 rounded-lg">
              <XCircle className="w-6 h-6 text-red-600" />
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
            placeholder="Search clients..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-5 h-5 text-gray-400" />
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
          >
            <option value="all">All Status</option>
            <option value="healthy">Healthy</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      {/* Client List */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left px-6 py-4 text-sm font-semibold text-gray-600">Client</th>
                <th className="text-center px-6 py-4 text-sm font-semibold text-gray-600">Health Score</th>
                <th className="text-center px-6 py-4 text-sm font-semibold text-gray-600">Status</th>
                <th className="text-center px-6 py-4 text-sm font-semibold text-gray-600">Devices</th>
                <th className="text-center px-6 py-4 text-sm font-semibold text-gray-600">Open Tickets</th>
                <th className="text-center px-6 py-4 text-sm font-semibold text-gray-600">Alerts</th>
                <th className="text-center px-6 py-4 text-sm font-semibold text-gray-600">Contract</th>
                <th className="text-right px-6 py-4 text-sm font-semibold text-gray-600">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredClients.map((client) => {
                const scoreDiff = client.overallScore - client.previousScore
                return (
                  <tr
                    key={client.id}
                    className="border-b border-gray-100 hover:bg-gray-50 cursor-pointer"
                    onClick={() => setSelectedClient(client)}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-aether-100 flex items-center justify-center">
                          <Building2 className="w-5 h-5 text-aether-600" />
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">{client.name}</p>
                          <p className="text-sm text-gray-500">{client.industry}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col items-center">
                        <div className="flex items-center gap-2">
                          <span className={`text-2xl font-bold ${getScoreColor(client.overallScore)}`}>
                            {client.overallScore}
                          </span>
                          {scoreDiff !== 0 && (
                            <span className={`text-sm ${scoreDiff > 0 ? 'text-green-500' : 'text-red-500'}`}>
                              {scoreDiff > 0 ? '+' : ''}{scoreDiff}
                            </span>
                          )}
                        </div>
                        <div className="w-24 h-2 bg-gray-200 rounded-full mt-1">
                          <div
                            className={`h-full rounded-full ${getScoreBgColor(client.overallScore)}`}
                            style={{ width: `${client.overallScore}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium capitalize ${getStatusColor(client.status)}`}>
                        {client.status === 'healthy' && <CheckCircle className="w-3 h-3" />}
                        {client.status === 'warning' && <AlertTriangle className="w-3 h-3" />}
                        {client.status === 'critical' && <XCircle className="w-3 h-3" />}
                        {client.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <div className="flex items-center justify-center gap-1">
                        <Server className="w-4 h-4 text-gray-400" />
                        <span className="text-gray-700">{client.deviceCount}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={client.openTickets > 10 ? 'text-yellow-600 font-medium' : 'text-gray-700'}>
                        {client.openTickets}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-center">
                      {client.criticalAlerts > 0 ? (
                        <span className="inline-flex items-center gap-1 px-2 py-1 bg-red-100 text-red-700 rounded-full text-sm font-medium">
                          <AlertTriangle className="w-3 h-3" />
                          {client.criticalAlerts}
                        </span>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className={`px-2 py-1 rounded text-sm ${
                        client.contractType === 'Enterprise' ? 'bg-purple-100 text-purple-700' :
                        client.contractType === 'Premium' ? 'bg-blue-100 text-blue-700' :
                        'bg-gray-100 text-gray-700'
                      }`}>
                        {client.contractType}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button className="text-aether-600 hover:text-aether-700">
                        <ChevronRight className="w-5 h-5" />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Client Detail Modal */}
      {selectedClient && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setSelectedClient(null)} />
            <div className="relative bg-white rounded-xl shadow-xl w-full max-w-4xl p-6">
              <button
                onClick={() => setSelectedClient(null)}
                className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
              >
                <X className="w-6 h-6" />
              </button>

              {/* Header */}
              <div className="flex items-start gap-4 mb-6">
                <div className="w-16 h-16 rounded-xl bg-aether-100 flex items-center justify-center">
                  <Building2 className="w-8 h-8 text-aether-600" />
                </div>
                <div className="flex-1">
                  <h2 className="text-2xl font-bold text-gray-900">{selectedClient.name}</h2>
                  <p className="text-gray-500">{selectedClient.industry} | {selectedClient.contractType} Contract</p>
                </div>
                <div className="text-right">
                  <div className={`text-4xl font-bold ${getScoreColor(selectedClient.overallScore)}`}>
                    {selectedClient.overallScore}%
                  </div>
                  <p className="text-sm text-gray-500">Health Score</p>
                </div>
              </div>

              {/* Quick Stats */}
              <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="bg-gray-50 rounded-lg p-4 text-center">
                  <Server className="w-6 h-6 text-gray-400 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-gray-900">{selectedClient.deviceCount}</p>
                  <p className="text-sm text-gray-500">Devices</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4 text-center">
                  <Cpu className="w-6 h-6 text-gray-400 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-gray-900">{selectedClient.openTickets}</p>
                  <p className="text-sm text-gray-500">Open Tickets</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4 text-center">
                  <AlertTriangle className="w-6 h-6 text-gray-400 mx-auto mb-2" />
                  <p className="text-2xl font-bold text-gray-900">{selectedClient.criticalAlerts}</p>
                  <p className="text-sm text-gray-500">Critical Alerts</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4 text-center">
                  <Clock className="w-6 h-6 text-gray-400 mx-auto mb-2" />
                  <p className="text-sm font-medium text-gray-900">
                    {new Date(selectedClient.lastAssessment).toLocaleDateString()}
                  </p>
                  <p className="text-sm text-gray-500">Last Assessment</p>
                </div>
              </div>

              {/* Health Metrics */}
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Health Metrics</h3>
              <div className="space-y-4">
                {selectedClient.metrics.map((metric, index) => (
                  <div key={index} className="bg-gray-50 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        {metric.name === 'Security Posture' && <Shield className="w-5 h-5 text-aether-600" />}
                        {metric.name === 'Patch Compliance' && <HardDrive className="w-5 h-5 text-aether-600" />}
                        {metric.name === 'Backup Health' && <Server className="w-5 h-5 text-aether-600" />}
                        {metric.name === 'System Performance' && <Cpu className="w-5 h-5 text-aether-600" />}
                        {metric.name === 'Network Health' && <Wifi className="w-5 h-5 text-aether-600" />}
                        <div>
                          <p className="font-medium text-gray-900">{metric.name}</p>
                          <p className="text-sm text-gray-500">Weight: {metric.weight}%</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {getTrendIcon(metric.trend)}
                        <span className={`text-2xl font-bold ${getScoreColor(metric.score)}`}>
                          {metric.score}%
                        </span>
                      </div>
                    </div>
                    <div className="w-full h-2 bg-gray-200 rounded-full mb-2">
                      <div
                        className={`h-full rounded-full ${getScoreBgColor(metric.score)}`}
                        style={{ width: `${metric.score}%` }}
                      />
                    </div>
                    <p className="text-sm text-gray-600">{metric.details}</p>
                  </div>
                ))}
              </div>

              {/* Actions */}
              <div className="flex justify-end gap-3 mt-6 pt-6 border-t border-gray-200">
                <button className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
                  View Full Report
                </button>
                <button className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
                  Schedule Review
                </button>
                <button className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
                  Run Assessment
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
