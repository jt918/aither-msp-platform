import { useState } from 'react'
import {
  Clock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  TrendingUp,
  TrendingDown,
  Calendar,
  Building2,
  Filter,
  Download,
  Target,
  Timer,
  Zap,
  AlertCircle,
  BarChart3,
  ChevronRight
} from 'lucide-react'

interface SLAMetric {
  id: string
  name: string
  target: number
  current: number
  trend: 'up' | 'down' | 'stable'
  unit: string
  status: 'met' | 'at_risk' | 'breached'
}

interface ClientSLA {
  id: string
  client: string
  tier: 'gold' | 'silver' | 'bronze'
  responseTime: { target: number; actual: number; unit: string }
  resolutionTime: { target: number; actual: number; unit: string }
  uptime: { target: number; actual: number }
  ticketsMet: number
  ticketsTotal: number
  compliance: number
  status: 'compliant' | 'at_risk' | 'breaching'
  lastIncident: string | null
}

interface SLABreach {
  id: string
  ticketId: string
  client: string
  type: 'response' | 'resolution' | 'uptime'
  metric: string
  breachTime: string
  impact: string
  rootCause: string
  status: 'open' | 'resolved' | 'credited'
}

const mockMetrics: SLAMetric[] = [
  { id: '1', name: 'Average Response Time', target: 15, current: 12, trend: 'down', unit: 'min', status: 'met' },
  { id: '2', name: 'Average Resolution Time', target: 4, current: 3.8, trend: 'down', unit: 'hrs', status: 'met' },
  { id: '3', name: 'First Call Resolution', target: 70, current: 74, trend: 'up', unit: '%', status: 'met' },
  { id: '4', name: 'System Uptime', target: 99.9, current: 99.95, trend: 'stable', unit: '%', status: 'met' },
  { id: '5', name: 'Customer Satisfaction', target: 90, current: 88, trend: 'down', unit: '%', status: 'at_risk' },
  { id: '6', name: 'SLA Compliance Rate', target: 95, current: 96.5, trend: 'up', unit: '%', status: 'met' },
]

const mockClientSLAs: ClientSLA[] = [
  {
    id: 'CL-001',
    client: 'Acme Corporation',
    tier: 'gold',
    responseTime: { target: 15, actual: 10, unit: 'min' },
    resolutionTime: { target: 4, actual: 3.2, unit: 'hrs' },
    uptime: { target: 99.99, actual: 99.99 },
    ticketsMet: 145,
    ticketsTotal: 148,
    compliance: 98.0,
    status: 'compliant',
    lastIncident: null
  },
  {
    id: 'CL-002',
    client: 'TechStart Inc',
    tier: 'silver',
    responseTime: { target: 30, actual: 25, unit: 'min' },
    resolutionTime: { target: 8, actual: 7.5, unit: 'hrs' },
    uptime: { target: 99.9, actual: 99.92 },
    ticketsMet: 89,
    ticketsTotal: 92,
    compliance: 96.7,
    status: 'compliant',
    lastIncident: '2024-01-10'
  },
  {
    id: 'CL-003',
    client: 'Global Finance Ltd',
    tier: 'gold',
    responseTime: { target: 15, actual: 18, unit: 'min' },
    resolutionTime: { target: 4, actual: 4.8, unit: 'hrs' },
    uptime: { target: 99.99, actual: 99.95 },
    ticketsMet: 52,
    ticketsTotal: 58,
    compliance: 89.7,
    status: 'at_risk',
    lastIncident: '2024-01-14'
  },
  {
    id: 'CL-004',
    client: 'HealthCare Plus',
    tier: 'gold',
    responseTime: { target: 15, actual: 22, unit: 'min' },
    resolutionTime: { target: 4, actual: 5.5, unit: 'hrs' },
    uptime: { target: 99.99, actual: 99.85 },
    ticketsMet: 38,
    ticketsTotal: 45,
    compliance: 84.4,
    status: 'breaching',
    lastIncident: '2024-01-15'
  },
  {
    id: 'CL-005',
    client: 'Retail Giant Co',
    tier: 'bronze',
    responseTime: { target: 60, actual: 45, unit: 'min' },
    resolutionTime: { target: 24, actual: 18, unit: 'hrs' },
    uptime: { target: 99.5, actual: 99.8 },
    ticketsMet: 124,
    ticketsTotal: 126,
    compliance: 98.4,
    status: 'compliant',
    lastIncident: null
  },
]

const mockBreaches: SLABreach[] = [
  {
    id: 'BR-001',
    ticketId: 'TKT-4521',
    client: 'HealthCare Plus',
    type: 'response',
    metric: 'Response time exceeded by 7 min',
    breachTime: '2024-01-15 14:32',
    impact: 'High',
    rootCause: 'Staffing shortage during peak hours',
    status: 'open'
  },
  {
    id: 'BR-002',
    ticketId: 'TKT-4518',
    client: 'Global Finance Ltd',
    type: 'resolution',
    metric: 'Resolution time exceeded by 1.5 hrs',
    breachTime: '2024-01-14 18:45',
    impact: 'Medium',
    rootCause: 'Complex infrastructure issue',
    status: 'resolved'
  },
  {
    id: 'BR-003',
    ticketId: 'TKT-4510',
    client: 'HealthCare Plus',
    type: 'uptime',
    metric: 'Downtime of 45 min',
    breachTime: '2024-01-13 03:15',
    impact: 'Critical',
    rootCause: 'Network switch failure',
    status: 'credited'
  },
]

export default function SLADashboard() {
  const [selectedTier, setSelectedTier] = useState<string | null>(null)
  const [timeRange, setTimeRange] = useState('30d')

  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'gold': return 'bg-yellow-100 text-yellow-800 border-yellow-300'
      case 'silver': return 'bg-gray-100 text-gray-700 border-gray-300'
      case 'bronze': return 'bg-orange-100 text-orange-800 border-orange-300'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
      case 'met':
        return 'text-green-600 bg-green-50'
      case 'at_risk':
        return 'text-yellow-600 bg-yellow-50'
      case 'breaching':
      case 'breached':
        return 'text-red-600 bg-red-50'
      default:
        return 'text-gray-600 bg-gray-50'
    }
  }

  const filteredClients = selectedTier
    ? mockClientSLAs.filter(c => c.tier === selectedTier)
    : mockClientSLAs

  const complianceRate = mockClientSLAs.reduce((sum, c) => sum + c.compliance, 0) / mockClientSLAs.length
  const atRiskCount = mockClientSLAs.filter(c => c.status === 'at_risk' || c.status === 'breaching').length
  const activeBreaches = mockBreaches.filter(b => b.status === 'open').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SLA Dashboard</h1>
          <p className="text-gray-500">Service Level Agreement monitoring and compliance</p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
          >
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
            <option value="12m">Last 12 months</option>
          </select>
          <button className="btn-secondary flex items-center gap-2">
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      {/* Overall Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Overall Compliance</p>
              <p className="text-2xl font-bold text-gray-900">{complianceRate.toFixed(1)}%</p>
            </div>
            <div className="w-12 h-12 rounded-lg bg-green-100 flex items-center justify-center">
              <Target className="w-6 h-6 text-green-600" />
            </div>
          </div>
          <div className="mt-2 flex items-center gap-1 text-sm text-green-600">
            <TrendingUp className="w-4 h-4" />
            <span>+2.3% vs last period</span>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Tickets Met SLA</p>
              <p className="text-2xl font-bold text-gray-900">
                {mockClientSLAs.reduce((sum, c) => sum + c.ticketsMet, 0)}/
                {mockClientSLAs.reduce((sum, c) => sum + c.ticketsTotal, 0)}
              </p>
            </div>
            <div className="w-12 h-12 rounded-lg bg-blue-100 flex items-center justify-center">
              <CheckCircle2 className="w-6 h-6 text-blue-600" />
            </div>
          </div>
          <div className="mt-2 flex items-center gap-1 text-sm text-green-600">
            <TrendingUp className="w-4 h-4" />
            <span>96.5% success rate</span>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Clients At Risk</p>
              <p className="text-2xl font-bold text-gray-900">{atRiskCount}</p>
            </div>
            <div className="w-12 h-12 rounded-lg bg-yellow-100 flex items-center justify-center">
              <AlertTriangle className="w-6 h-6 text-yellow-600" />
            </div>
          </div>
          <div className="mt-2 text-sm text-gray-500">
            {mockClientSLAs.filter(c => c.status === 'breaching').length} actively breaching
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Active Breaches</p>
              <p className="text-2xl font-bold text-gray-900">{activeBreaches}</p>
            </div>
            <div className="w-12 h-12 rounded-lg bg-red-100 flex items-center justify-center">
              <AlertCircle className="w-6 h-6 text-red-600" />
            </div>
          </div>
          <div className="mt-2 text-sm text-red-600">
            Requires immediate attention
          </div>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <BarChart3 className="w-5 h-5 text-aether-600" />
          Key SLA Metrics
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {mockMetrics.map(metric => (
            <div
              key={metric.id}
              className={`p-4 rounded-lg border ${
                metric.status === 'met' ? 'border-green-200 bg-green-50/50' :
                metric.status === 'at_risk' ? 'border-yellow-200 bg-yellow-50/50' :
                'border-red-200 bg-red-50/50'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-700">{metric.name}</span>
                {metric.trend === 'up' && <TrendingUp className="w-4 h-4 text-green-500" />}
                {metric.trend === 'down' && <TrendingDown className="w-4 h-4 text-green-500" />}
                {metric.trend === 'stable' && <span className="text-xs text-gray-400">-</span>}
              </div>
              <div className="flex items-end justify-between">
                <div>
                  <span className="text-2xl font-bold text-gray-900">{metric.current}</span>
                  <span className="text-sm text-gray-500 ml-1">{metric.unit}</span>
                </div>
                <div className="text-right">
                  <span className="text-xs text-gray-500">Target: {metric.target}{metric.unit}</span>
                  <div className={`text-xs font-medium ${
                    metric.status === 'met' ? 'text-green-600' :
                    metric.status === 'at_risk' ? 'text-yellow-600' :
                    'text-red-600'
                  }`}>
                    {metric.status === 'met' ? 'Meeting SLA' :
                     metric.status === 'at_risk' ? 'At Risk' :
                     'Breached'}
                  </div>
                </div>
              </div>
              <div className="mt-2 w-full h-2 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${
                    metric.status === 'met' ? 'bg-green-500' :
                    metric.status === 'at_risk' ? 'bg-yellow-500' :
                    'bg-red-500'
                  }`}
                  style={{ width: `${Math.min((metric.current / metric.target) * 100, 100)}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Client SLA Performance */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <Building2 className="w-5 h-5 text-aether-600" />
              Client SLA Performance
            </h2>
            <div className="flex items-center gap-2">
              {['gold', 'silver', 'bronze'].map(tier => (
                <button
                  key={tier}
                  onClick={() => setSelectedTier(selectedTier === tier ? null : tier)}
                  className={`px-3 py-1 rounded-full text-xs font-medium capitalize border ${
                    selectedTier === tier ? getTierColor(tier) : 'bg-white text-gray-500 border-gray-200'
                  }`}
                >
                  {tier}
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-gray-50">
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Client</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Tier</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Response Time</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Resolution Time</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Uptime</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Compliance</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Status</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredClients.map(client => (
                <tr key={client.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="font-medium text-gray-900">{client.client}</div>
                    <div className="text-xs text-gray-500">
                      {client.ticketsMet}/{client.ticketsTotal} tickets met
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2.5 py-1 rounded-full text-xs font-medium capitalize border ${getTierColor(client.tier)}`}>
                      {client.tier}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <Timer className={`w-4 h-4 ${
                        client.responseTime.actual <= client.responseTime.target ? 'text-green-500' : 'text-red-500'
                      }`} />
                      <span className={
                        client.responseTime.actual <= client.responseTime.target ? 'text-green-600' : 'text-red-600'
                      }>
                        {client.responseTime.actual} {client.responseTime.unit}
                      </span>
                      <span className="text-xs text-gray-400">
                        / {client.responseTime.target} {client.responseTime.unit}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <Clock className={`w-4 h-4 ${
                        client.resolutionTime.actual <= client.resolutionTime.target ? 'text-green-500' : 'text-red-500'
                      }`} />
                      <span className={
                        client.resolutionTime.actual <= client.resolutionTime.target ? 'text-green-600' : 'text-red-600'
                      }>
                        {client.resolutionTime.actual} {client.resolutionTime.unit}
                      </span>
                      <span className="text-xs text-gray-400">
                        / {client.resolutionTime.target} {client.resolutionTime.unit}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <Zap className={`w-4 h-4 ${
                        client.uptime.actual >= client.uptime.target ? 'text-green-500' : 'text-red-500'
                      }`} />
                      <span className={
                        client.uptime.actual >= client.uptime.target ? 'text-green-600' : 'text-red-600'
                      }>
                        {client.uptime.actual}%
                      </span>
                      <span className="text-xs text-gray-400">
                        / {client.uptime.target}%
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            client.compliance >= 95 ? 'bg-green-500' :
                            client.compliance >= 90 ? 'bg-yellow-500' :
                            'bg-red-500'
                          }`}
                          style={{ width: `${client.compliance}%` }}
                        />
                      </div>
                      <span className="text-sm font-medium text-gray-900">
                        {client.compliance.toFixed(1)}%
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${getStatusColor(client.status)}`}>
                      {client.status === 'compliant' && <CheckCircle2 className="w-3.5 h-3.5" />}
                      {client.status === 'at_risk' && <AlertTriangle className="w-3.5 h-3.5" />}
                      {client.status === 'breaching' && <XCircle className="w-3.5 h-3.5" />}
                      {client.status === 'compliant' ? 'Compliant' :
                       client.status === 'at_risk' ? 'At Risk' : 'Breaching'}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <button className="text-aether-600 hover:text-aether-700">
                      <ChevronRight className="w-5 h-5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent Breaches */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
          <AlertCircle className="w-5 h-5 text-red-500" />
          Recent SLA Breaches
        </h2>
        <div className="space-y-3">
          {mockBreaches.map(breach => (
            <div
              key={breach.id}
              className={`p-4 rounded-lg border ${
                breach.status === 'open' ? 'border-red-200 bg-red-50' :
                breach.status === 'resolved' ? 'border-gray-200 bg-gray-50' :
                'border-blue-200 bg-blue-50'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-lg ${
                    breach.type === 'response' ? 'bg-yellow-100' :
                    breach.type === 'resolution' ? 'bg-orange-100' :
                    'bg-red-100'
                  }`}>
                    {breach.type === 'response' && <Timer className="w-4 h-4 text-yellow-600" />}
                    {breach.type === 'resolution' && <Clock className="w-4 h-4 text-orange-600" />}
                    {breach.type === 'uptime' && <Zap className="w-4 h-4 text-red-600" />}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-gray-900">{breach.client}</span>
                      <span className="text-xs text-gray-500">#{breach.ticketId}</span>
                    </div>
                    <p className="text-sm text-gray-700 mt-1">{breach.metric}</p>
                    <p className="text-xs text-gray-500 mt-1">
                      Root cause: {breach.rootCause}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    breach.status === 'open' ? 'bg-red-100 text-red-700' :
                    breach.status === 'resolved' ? 'bg-gray-100 text-gray-700' :
                    'bg-blue-100 text-blue-700'
                  }`}>
                    {breach.status === 'open' ? 'Open' :
                     breach.status === 'resolved' ? 'Resolved' : 'Credited'}
                  </span>
                  <p className="text-xs text-gray-500 mt-1">{breach.breachTime}</p>
                  <p className="text-xs font-medium mt-1" style={{
                    color: breach.impact === 'Critical' ? '#dc2626' :
                           breach.impact === 'High' ? '#ea580c' :
                           breach.impact === 'Medium' ? '#ca8a04' : '#65a30d'
                  }}>
                    {breach.impact} Impact
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
