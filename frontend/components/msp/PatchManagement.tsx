import { useState, useEffect } from 'react'
import {
  Shield,
  Download,
  AlertTriangle,
  CheckCircle,
  Clock,
  Server,
  Monitor,
  RefreshCw,
  Calendar,
  Filter,
  Play,
  Pause,
  Settings,
  ChevronRight
} from 'lucide-react'

interface Patch {
  id: string
  name: string
  vendor: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string
  releaseDate: string
  affectedSystems: number
  installedSystems: number
  status: 'pending' | 'approved' | 'deployed' | 'failed'
  description: string
}

interface PatchGroup {
  id: string
  name: string
  systems: number
  schedule: string
  lastRun: string
  nextRun: string
  status: 'active' | 'paused'
}

export default function PatchManagement() {
  const [activeTab, setActiveTab] = useState<'patches' | 'groups' | 'compliance' | 'schedule'>('patches')
  const [patches, setPatches] = useState<Patch[]>([])
  const [groups, setGroups] = useState<PatchGroup[]>([])
  const [filter, setFilter] = useState({ severity: '', status: '' })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = () => {
    setPatches([
      {
        id: 'PATCH-001',
        name: 'KB5034441 - Security Update',
        vendor: 'Microsoft',
        severity: 'critical',
        category: 'Security',
        releaseDate: '2026-02-01',
        affectedSystems: 45,
        installedSystems: 38,
        status: 'deployed',
        description: 'Critical security vulnerability fix for Windows Server 2022'
      },
      {
        id: 'PATCH-002',
        name: 'KB5034442 - Cumulative Update',
        vendor: 'Microsoft',
        severity: 'high',
        category: 'Feature',
        releaseDate: '2026-02-03',
        affectedSystems: 120,
        installedSystems: 0,
        status: 'approved',
        description: 'February 2026 cumulative update for Windows 11'
      },
      {
        id: 'PATCH-003',
        name: 'FortiOS 7.4.3',
        vendor: 'Fortinet',
        severity: 'critical',
        category: 'Security',
        releaseDate: '2026-01-28',
        affectedSystems: 8,
        installedSystems: 8,
        status: 'deployed',
        description: 'Critical vulnerability patch for FortiGate firewalls'
      },
      {
        id: 'PATCH-004',
        name: 'Chrome 122.0.6261',
        vendor: 'Google',
        severity: 'medium',
        category: 'Browser',
        releaseDate: '2026-02-02',
        affectedSystems: 200,
        installedSystems: 145,
        status: 'deployed',
        description: 'Chrome browser security and stability update'
      },
      {
        id: 'PATCH-005',
        name: 'Adobe Reader 24.001',
        vendor: 'Adobe',
        severity: 'high',
        category: 'Application',
        releaseDate: '2026-01-30',
        affectedSystems: 85,
        installedSystems: 20,
        status: 'pending',
        description: 'Security patches for Adobe Reader vulnerabilities'
      },
      {
        id: 'PATCH-006',
        name: 'VMware ESXi 8.0U2c',
        vendor: 'VMware',
        severity: 'critical',
        category: 'Hypervisor',
        releaseDate: '2026-01-25',
        affectedSystems: 12,
        installedSystems: 10,
        status: 'deployed',
        description: 'Critical security update for ESXi hypervisor'
      }
    ])

    setGroups([
      { id: 'GRP-001', name: 'Production Servers', systems: 45, schedule: 'Weekly - Sunday 2AM', lastRun: '2026-02-02', nextRun: '2026-02-09', status: 'active' },
      { id: 'GRP-002', name: 'Development Workstations', systems: 78, schedule: 'Daily - 6PM', lastRun: '2026-02-04', nextRun: '2026-02-05', status: 'active' },
      { id: 'GRP-003', name: 'Network Devices', systems: 24, schedule: 'Monthly - 1st Sunday', lastRun: '2026-02-02', nextRun: '2026-03-02', status: 'active' },
      { id: 'GRP-004', name: 'Test Environment', systems: 15, schedule: 'On-demand', lastRun: '2026-02-01', nextRun: 'Manual', status: 'paused' },
    ])

    setLoading(false)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'low': return 'bg-green-100 text-green-800 border-green-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'deployed': return 'bg-green-100 text-green-800'
      case 'approved': return 'bg-blue-100 text-blue-800'
      case 'pending': return 'bg-yellow-100 text-yellow-800'
      case 'failed': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getCompliancePercentage = (installed: number, affected: number) => {
    return affected > 0 ? Math.round((installed / affected) * 100) : 0
  }

  const filteredPatches = patches.filter(p => {
    if (filter.severity && p.severity !== filter.severity) return false
    if (filter.status && p.status !== filter.status) return false
    return true
  })

  const criticalPending = patches.filter(p => p.severity === 'critical' && p.status !== 'deployed').length
  const totalCompliance = patches.reduce((acc, p) => acc + getCompliancePercentage(p.installedSystems, p.affectedSystems), 0) / patches.length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Patch Management</h1>
          <p className="text-gray-500">Automated Patch Deployment & Compliance</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            className="flex items-center gap-2 px-4 py-2 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50"
          >
            <RefreshCw className="w-4 h-4" />
            Sync
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
            <Download className="w-4 h-4" />
            Deploy All Approved
          </button>
        </div>
      </div>

      {/* Alert Banner */}
      {criticalPending > 0 && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex items-center gap-4">
          <AlertTriangle className="w-6 h-6 text-red-600" />
          <div className="flex-1">
            <p className="font-medium text-red-800">Critical Patches Pending</p>
            <p className="text-sm text-red-600">{criticalPending} critical patches require immediate deployment</p>
          </div>
          <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 text-sm">
            Review Now
          </button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Download className="w-6 h-6 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{patches.length}</p>
              <p className="text-sm text-gray-500">Available Patches</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-red-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{patches.filter(p => p.severity === 'critical').length}</p>
              <p className="text-sm text-gray-500">Critical</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{patches.filter(p => p.status === 'deployed').length}</p>
              <p className="text-sm text-gray-500">Deployed</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Shield className="w-6 h-6 text-purple-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{Math.round(totalCompliance)}%</p>
              <p className="text-sm text-gray-500">Compliance</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-8">
          {[
            { id: 'patches', label: 'Patches', icon: Download },
            { id: 'groups', label: 'Patch Groups', icon: Server },
            { id: 'compliance', label: 'Compliance', icon: Shield },
            { id: 'schedule', label: 'Schedule', icon: Calendar },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 pb-4 border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-aether-600 text-aether-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              <tab.icon className="w-5 h-5" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Patches Tab */}
      {activeTab === 'patches' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-4">
            <select
              value={filter.severity}
              onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
            >
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select
              value={filter.status}
              onChange={(e) => setFilter({ ...filter, status: e.target.value })}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
            >
              <option value="">All Status</option>
              <option value="pending">Pending</option>
              <option value="approved">Approved</option>
              <option value="deployed">Deployed</option>
              <option value="failed">Failed</option>
            </select>
          </div>

          {/* Patches List */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Patch</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Vendor</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Severity</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Status</th>
                  <th className="text-center px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Progress</th>
                  <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {filteredPatches.map((patch) => (
                  <tr key={patch.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div>
                        <p className="font-medium text-gray-900">{patch.name}</p>
                        <p className="text-sm text-gray-500">{patch.description}</p>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-700">{patch.vendor}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${getSeverityColor(patch.severity)}`}>
                        {patch.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${getStatusColor(patch.status)}`}>
                        {patch.status}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="w-full max-w-[120px] mx-auto">
                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                          <span>{patch.installedSystems}/{patch.affectedSystems}</span>
                          <span>{getCompliancePercentage(patch.installedSystems, patch.affectedSystems)}%</span>
                        </div>
                        <div className="w-full h-2 bg-gray-100 rounded-full">
                          <div
                            className="h-full bg-green-500 rounded-full"
                            style={{ width: `${getCompliancePercentage(patch.installedSystems, patch.affectedSystems)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {patch.status === 'pending' && (
                        <button className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700">
                          Approve
                        </button>
                      )}
                      {patch.status === 'approved' && (
                        <button className="px-3 py-1 bg-green-600 text-white rounded text-sm hover:bg-green-700">
                          Deploy
                        </button>
                      )}
                      {patch.status === 'deployed' && (
                        <span className="text-sm text-gray-500">Complete</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Groups Tab */}
      {activeTab === 'groups' && (
        <div className="space-y-4">
          {groups.map((group) => (
            <div key={group.id} className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-xl ${group.status === 'active' ? 'bg-green-100' : 'bg-gray-100'}`}>
                    <Server className={`w-6 h-6 ${group.status === 'active' ? 'text-green-600' : 'text-gray-600'}`} />
                  </div>
                  <div>
                    <h3 className="font-semibold text-gray-900">{group.name}</h3>
                    <p className="text-sm text-gray-500">{group.systems} systems | {group.schedule}</p>
                  </div>
                </div>
                <div className="flex items-center gap-6">
                  <div className="text-right">
                    <p className="text-sm text-gray-500">Last Run</p>
                    <p className="font-medium text-gray-900">{group.lastRun}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-gray-500">Next Run</p>
                    <p className="font-medium text-gray-900">{group.nextRun}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button className={`p-2 rounded-lg ${
                      group.status === 'active' ? 'bg-yellow-100 text-yellow-600' : 'bg-green-100 text-green-600'
                    }`}>
                      {group.status === 'active' ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5" />}
                    </button>
                    <button className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg">
                      <Settings className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Compliance Tab */}
      {activeTab === 'compliance' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance by Category</h3>
            <div className="space-y-4">
              {[
                { category: 'Security Patches', compliance: 94, systems: 156 },
                { category: 'Feature Updates', compliance: 78, systems: 120 },
                { category: 'Browser Updates', compliance: 89, systems: 200 },
                { category: 'Application Updates', compliance: 65, systems: 85 },
              ].map((item, i) => (
                <div key={i}>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-700">{item.category}</span>
                    <span className="font-medium text-gray-900">{item.compliance}%</span>
                  </div>
                  <div className="w-full h-3 bg-gray-100 rounded-full">
                    <div
                      className={`h-full rounded-full ${
                        item.compliance >= 90 ? 'bg-green-500' :
                        item.compliance >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${item.compliance}%` }}
                    />
                  </div>
                  <p className="text-xs text-gray-500 mt-1">{item.systems} systems</p>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Non-Compliant Systems</h3>
            <div className="space-y-3">
              {[
                { name: 'WS-SALES-042', patches: 8, critical: 2 },
                { name: 'DEV-LAPTOP-015', patches: 5, critical: 1 },
                { name: 'LEGACY-SERVER-01', patches: 12, critical: 3 },
                { name: 'PRINTER-FLOOR3', patches: 3, critical: 0 },
              ].map((system, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <Monitor className="w-5 h-5 text-gray-400" />
                    <span className="font-medium text-gray-900">{system.name}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-sm text-gray-500">{system.patches} patches</span>
                    {system.critical > 0 && (
                      <span className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs font-medium">
                        {system.critical} critical
                      </span>
                    )}
                    <ChevronRight className="w-4 h-4 text-gray-400" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Schedule Tab */}
      {activeTab === 'schedule' && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Upcoming Patch Deployments</h3>
          <div className="space-y-4">
            {[
              { time: '2026-02-05 06:00', group: 'Development Workstations', patches: 5, systems: 78 },
              { time: '2026-02-09 02:00', group: 'Production Servers', patches: 3, systems: 45 },
              { time: '2026-02-15 04:00', group: 'Network Devices', patches: 2, systems: 24 },
              { time: '2026-03-02 02:00', group: 'Network Devices', patches: 4, systems: 24 },
            ].map((schedule, i) => (
              <div key={i} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-4">
                  <div className="p-2 bg-blue-100 rounded-lg">
                    <Calendar className="w-5 h-5 text-blue-600" />
                  </div>
                  <div>
                    <p className="font-medium text-gray-900">{schedule.group}</p>
                    <p className="text-sm text-gray-500">{schedule.time}</p>
                  </div>
                </div>
                <div className="flex items-center gap-6">
                  <div className="text-right">
                    <p className="font-medium text-gray-900">{schedule.patches} patches</p>
                    <p className="text-sm text-gray-500">{schedule.systems} systems</p>
                  </div>
                  <button className="px-3 py-1.5 text-sm text-gray-600 border border-gray-300 rounded hover:bg-gray-100">
                    Reschedule
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
