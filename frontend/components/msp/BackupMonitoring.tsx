import { useState } from 'react'
import {
  HardDrive,
  Cloud,
  Server,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Database,
  Calendar,
  TrendingUp,
  Download,
  Play,
  Pause,
  Settings,
  ChevronRight,
  Filter,
  Search
} from 'lucide-react'

interface BackupJob {
  id: string
  name: string
  type: 'full' | 'incremental' | 'differential'
  source: string
  destination: string
  schedule: string
  status: 'success' | 'failed' | 'running' | 'warning' | 'scheduled'
  lastRun: string | null
  nextRun: string
  duration: number | null
  size: number | null
  retention: number
  enabled: boolean
  errorMessage?: string
}

interface BackupTarget {
  id: string
  name: string
  type: 'local' | 'cloud' | 'offsite'
  provider?: string
  capacity: number
  used: number
  status: 'online' | 'offline' | 'degraded'
  lastSync: string
}

const backupJobs: BackupJob[] = [
  {
    id: 'BKP-001',
    name: 'Production Database Full',
    type: 'full',
    source: 'db-prod-primary',
    destination: 'AWS S3 - Prod Backups',
    schedule: 'Daily at 2:00 AM',
    status: 'success',
    lastRun: '2025-01-18T02:00:00Z',
    nextRun: '2025-01-19T02:00:00Z',
    duration: 45,
    size: 128.5,
    retention: 30,
    enabled: true
  },
  {
    id: 'BKP-002',
    name: 'File Server Incremental',
    type: 'incremental',
    source: 'fs-corp-01',
    destination: 'Azure Blob - Corp Files',
    schedule: 'Every 4 hours',
    status: 'running',
    lastRun: '2025-01-18T12:00:00Z',
    nextRun: '2025-01-18T16:00:00Z',
    duration: null,
    size: null,
    retention: 14,
    enabled: true
  },
  {
    id: 'BKP-003',
    name: 'Exchange Mailbox Backup',
    type: 'differential',
    source: 'exchange-prod',
    destination: 'Local NAS - Exchange',
    schedule: 'Daily at 11:00 PM',
    status: 'failed',
    lastRun: '2025-01-17T23:00:00Z',
    nextRun: '2025-01-18T23:00:00Z',
    duration: 12,
    size: null,
    retention: 60,
    enabled: true,
    errorMessage: 'Connection timeout to Exchange server'
  },
  {
    id: 'BKP-004',
    name: 'VM Snapshots - Dev',
    type: 'full',
    source: 'vmware-dev-cluster',
    destination: 'Veeam Repository',
    schedule: 'Weekly - Sunday 3:00 AM',
    status: 'success',
    lastRun: '2025-01-14T03:00:00Z',
    nextRun: '2025-01-21T03:00:00Z',
    duration: 180,
    size: 512.3,
    retention: 90,
    enabled: true
  },
  {
    id: 'BKP-005',
    name: 'CRM Database',
    type: 'incremental',
    source: 'crm-mysql-prod',
    destination: 'AWS S3 - CRM Backups',
    schedule: 'Every 6 hours',
    status: 'warning',
    lastRun: '2025-01-18T06:00:00Z',
    nextRun: '2025-01-18T12:00:00Z',
    duration: 28,
    size: 45.2,
    retention: 14,
    enabled: true,
    errorMessage: 'Backup completed with warnings - 3 tables skipped'
  },
  {
    id: 'BKP-006',
    name: 'Legacy System Archive',
    type: 'full',
    source: 'legacy-server-01',
    destination: 'Tape Library',
    schedule: 'Monthly - 1st at 1:00 AM',
    status: 'scheduled',
    lastRun: '2025-01-01T01:00:00Z',
    nextRun: '2025-02-01T01:00:00Z',
    duration: 360,
    size: 1024,
    retention: 365,
    enabled: false
  }
]

const backupTargets: BackupTarget[] = [
  {
    id: 'TGT-001',
    name: 'AWS S3 - Prod Backups',
    type: 'cloud',
    provider: 'AWS',
    capacity: 5000,
    used: 2847,
    status: 'online',
    lastSync: '2025-01-18T14:30:00Z'
  },
  {
    id: 'TGT-002',
    name: 'Azure Blob - Corp Files',
    type: 'cloud',
    provider: 'Azure',
    capacity: 10000,
    used: 6234,
    status: 'online',
    lastSync: '2025-01-18T14:25:00Z'
  },
  {
    id: 'TGT-003',
    name: 'Local NAS - Exchange',
    type: 'local',
    capacity: 2000,
    used: 1850,
    status: 'degraded',
    lastSync: '2025-01-18T14:00:00Z'
  },
  {
    id: 'TGT-004',
    name: 'Veeam Repository',
    type: 'local',
    capacity: 8000,
    used: 4521,
    status: 'online',
    lastSync: '2025-01-18T14:28:00Z'
  },
  {
    id: 'TGT-005',
    name: 'Tape Library',
    type: 'offsite',
    capacity: 50000,
    used: 28500,
    status: 'offline',
    lastSync: '2025-01-15T00:00:00Z'
  }
]

export default function BackupMonitoring() {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [selectedJob, setSelectedJob] = useState<BackupJob | null>(null)
  const [activeTab, setActiveTab] = useState<'jobs' | 'targets' | 'history'>('jobs')

  const filteredJobs = backupJobs.filter(job => {
    const matchesSearch = job.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         job.source.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === 'all' || job.status === statusFilter
    const matchesType = typeFilter === 'all' || job.type === typeFilter
    return matchesSearch && matchesStatus && matchesType
  })

  const stats = {
    totalJobs: backupJobs.length,
    successful: backupJobs.filter(j => j.status === 'success').length,
    failed: backupJobs.filter(j => j.status === 'failed').length,
    running: backupJobs.filter(j => j.status === 'running').length,
    totalStorage: backupTargets.reduce((sum, t) => sum + t.capacity, 0),
    usedStorage: backupTargets.reduce((sum, t) => sum + t.used, 0),
    successRate: Math.round((backupJobs.filter(j => j.status === 'success').length /
                            backupJobs.filter(j => j.lastRun).length) * 100)
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success': return <CheckCircle className="w-5 h-5 text-green-500" />
      case 'failed': return <XCircle className="w-5 h-5 text-red-500" />
      case 'running': return <RefreshCw className="w-5 h-5 text-blue-500 animate-spin" />
      case 'warning': return <AlertTriangle className="w-5 h-5 text-yellow-500" />
      case 'scheduled': return <Clock className="w-5 h-5 text-gray-400" />
      default: return <Clock className="w-5 h-5 text-gray-400" />
    }
  }

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      success: 'bg-green-100 text-green-800',
      failed: 'bg-red-100 text-red-800',
      running: 'bg-blue-100 text-blue-800',
      warning: 'bg-yellow-100 text-yellow-800',
      scheduled: 'bg-gray-100 text-gray-800',
      online: 'bg-green-100 text-green-800',
      offline: 'bg-red-100 text-red-800',
      degraded: 'bg-yellow-100 text-yellow-800'
    }
    return styles[status] || 'bg-gray-100 text-gray-800'
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'cloud': return <Cloud className="w-5 h-5 text-blue-500" />
      case 'local': return <HardDrive className="w-5 h-5 text-gray-500" />
      case 'offsite': return <Server className="w-5 h-5 text-purple-500" />
      default: return <Database className="w-5 h-5 text-gray-500" />
    }
  }

  const formatDuration = (minutes: number | null) => {
    if (minutes === null) return '-'
    if (minutes < 60) return `${minutes}m`
    const hours = Math.floor(minutes / 60)
    const mins = minutes % 60
    return `${hours}h ${mins}m`
  }

  const formatSize = (gb: number | null) => {
    if (gb === null) return '-'
    if (gb >= 1000) return `${(gb / 1000).toFixed(1)} TB`
    return `${gb.toFixed(1)} GB`
  }

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'Never'
    const date = new Date(dateStr)
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Backup Monitoring</h1>
          <p className="text-gray-500">Track backup jobs, storage targets, and data protection status</p>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 flex items-center gap-2">
            <Download className="w-4 h-4" />
            Export Report
          </button>
          <button className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700 flex items-center gap-2">
            <Play className="w-4 h-4" />
            Run Backup
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Jobs</p>
              <p className="text-3xl font-bold text-gray-900">{stats.totalJobs}</p>
            </div>
            <div className="w-12 h-12 bg-aether-100 rounded-lg flex items-center justify-center">
              <Database className="w-6 h-6 text-aether-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center gap-4 text-sm">
            <span className="text-green-600">{stats.successful} successful</span>
            <span className="text-red-600">{stats.failed} failed</span>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Success Rate</p>
              <p className="text-3xl font-bold text-gray-900">{stats.successRate}%</p>
            </div>
            <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
              <TrendingUp className="w-6 h-6 text-green-600" />
            </div>
          </div>
          <div className="mt-4">
            <div className="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
              <div
                className="h-full bg-green-500 rounded-full"
                style={{ width: `${stats.successRate}%` }}
              />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Storage Used</p>
              <p className="text-3xl font-bold text-gray-900">{formatSize(stats.usedStorage)}</p>
            </div>
            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
              <HardDrive className="w-6 h-6 text-blue-600" />
            </div>
          </div>
          <div className="mt-4 text-sm text-gray-500">
            of {formatSize(stats.totalStorage)} total capacity
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Running Now</p>
              <p className="text-3xl font-bold text-gray-900">{stats.running}</p>
            </div>
            <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
              <RefreshCw className="w-6 h-6 text-purple-600" />
            </div>
          </div>
          <div className="mt-4 text-sm text-gray-500">
            Active backup operations
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-4">
          {[
            { id: 'jobs', label: 'Backup Jobs', icon: Database },
            { id: 'targets', label: 'Storage Targets', icon: HardDrive },
            { id: 'history', label: 'History', icon: Clock }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as 'jobs' | 'targets' | 'history')}
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

      {/* Jobs Tab */}
      {activeTab === 'jobs' && (
        <>
          {/* Filters */}
          <div className="flex flex-wrap gap-4 items-center">
            <div className="relative flex-1 min-w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search backup jobs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
              >
                <option value="all">All Status</option>
                <option value="success">Success</option>
                <option value="failed">Failed</option>
                <option value="running">Running</option>
                <option value="warning">Warning</option>
                <option value="scheduled">Scheduled</option>
              </select>
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
              >
                <option value="all">All Types</option>
                <option value="full">Full</option>
                <option value="incremental">Incremental</option>
                <option value="differential">Differential</option>
              </select>
            </div>
          </div>

          {/* Jobs Table */}
          <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Job</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Type</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Last Run</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Next Run</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Size</th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {filteredJobs.map(job => (
                  <tr
                    key={job.id}
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => setSelectedJob(job)}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(job.status)}
                        <div>
                          <p className="font-medium text-gray-900">{job.name}</p>
                          <p className="text-sm text-gray-500">{job.source}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="capitalize text-sm text-gray-600">{job.type}</span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadge(job.status)}`}>
                        {job.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {formatDate(job.lastRun)}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {formatDate(job.nextRun)}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {formatSize(job.size)}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <button
                          className="p-1.5 text-gray-400 hover:text-aether-600 hover:bg-aether-50 rounded"
                          onClick={(e) => { e.stopPropagation() }}
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button
                          className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded"
                          onClick={(e) => { e.stopPropagation() }}
                        >
                          <Settings className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Targets Tab */}
      {activeTab === 'targets' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {backupTargets.map(target => (
            <div key={target.id} className="bg-white rounded-xl border border-gray-200 p-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  {getTypeIcon(target.type)}
                  <div>
                    <h3 className="font-medium text-gray-900">{target.name}</h3>
                    <p className="text-sm text-gray-500 capitalize">{target.type} Storage</p>
                  </div>
                </div>
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadge(target.status)}`}>
                  {target.status}
                </span>
              </div>

              <div className="space-y-3">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span className="text-gray-500">Storage Used</span>
                    <span className="font-medium">{formatSize(target.used)} / {formatSize(target.capacity)}</span>
                  </div>
                  <div className="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        (target.used / target.capacity) > 0.9
                          ? 'bg-red-500'
                          : (target.used / target.capacity) > 0.75
                            ? 'bg-yellow-500'
                            : 'bg-green-500'
                      }`}
                      style={{ width: `${(target.used / target.capacity) * 100}%` }}
                    />
                  </div>
                </div>

                {target.provider && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">Provider</span>
                    <span className="font-medium">{target.provider}</span>
                  </div>
                )}

                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Last Sync</span>
                  <span className="text-gray-600">{formatDate(target.lastSync)}</span>
                </div>

                <div className="pt-3 border-t border-gray-100">
                  <button className="w-full flex items-center justify-center gap-2 py-2 text-sm text-aether-600 hover:bg-aether-50 rounded-lg transition-colors">
                    <Settings className="w-4 h-4" />
                    Configure Target
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="text-center py-12">
            <Calendar className="w-12 h-12 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">Backup History</h3>
            <p className="text-gray-500 max-w-md mx-auto">
              View detailed backup execution history, including success/failure logs,
              duration trends, and data transfer metrics.
            </p>
            <button className="mt-4 px-4 py-2 text-aether-600 hover:bg-aether-50 rounded-lg transition-colors">
              Load History
            </button>
          </div>
        </div>
      )}

      {/* Job Detail Modal */}
      {selectedJob && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {getStatusIcon(selectedJob.status)}
                  <div>
                    <h2 className="text-xl font-bold text-gray-900">{selectedJob.name}</h2>
                    <p className="text-sm text-gray-500">{selectedJob.id}</p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedJob(null)}
                  className="p-2 text-gray-400 hover:text-gray-600 rounded-lg"
                >
                  <XCircle className="w-5 h-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-6">
              {selectedJob.errorMessage && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-red-500 mt-0.5" />
                    <div>
                      <p className="font-medium text-red-800">Error Message</p>
                      <p className="text-sm text-red-600 mt-1">{selectedJob.errorMessage}</p>
                    </div>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Source</p>
                  <p className="font-medium text-gray-900">{selectedJob.source}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Destination</p>
                  <p className="font-medium text-gray-900">{selectedJob.destination}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Backup Type</p>
                  <p className="font-medium text-gray-900 capitalize">{selectedJob.type}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Schedule</p>
                  <p className="font-medium text-gray-900">{selectedJob.schedule}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Last Run</p>
                  <p className="font-medium text-gray-900">{formatDate(selectedJob.lastRun)}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Next Run</p>
                  <p className="font-medium text-gray-900">{formatDate(selectedJob.nextRun)}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Duration</p>
                  <p className="font-medium text-gray-900">{formatDuration(selectedJob.duration)}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Backup Size</p>
                  <p className="font-medium text-gray-900">{formatSize(selectedJob.size)}</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Retention</p>
                  <p className="font-medium text-gray-900">{selectedJob.retention} days</p>
                </div>
                <div className="bg-gray-50 rounded-lg p-4">
                  <p className="text-sm text-gray-500 mb-1">Enabled</p>
                  <p className="font-medium text-gray-900">{selectedJob.enabled ? 'Yes' : 'No'}</p>
                </div>
              </div>

              <div className="flex gap-3 pt-4 border-t border-gray-200">
                <button className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
                  <Play className="w-4 h-4" />
                  Run Now
                </button>
                <button className="flex-1 flex items-center justify-center gap-2 py-2.5 border border-gray-200 rounded-lg hover:bg-gray-50">
                  <Settings className="w-4 h-4" />
                  Edit Job
                </button>
                <button className="flex items-center justify-center gap-2 px-4 py-2.5 border border-gray-200 rounded-lg hover:bg-gray-50">
                  {selectedJob.enabled ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
