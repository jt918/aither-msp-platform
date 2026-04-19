import { useState } from 'react'
import {
  FileText,
  Search,
  Filter,
  Download,
  RefreshCw,
  AlertTriangle,
  AlertCircle,
  Info,
  Bug,
  CheckCircle,
  Clock,
  Server,
  Database,
  Shield,
  Network,
  ChevronDown,
  Copy,
  X,
  Calendar
} from 'lucide-react'

type LogLevel = 'info' | 'warning' | 'error' | 'debug' | 'critical'
type LogSource = 'system' | 'application' | 'security' | 'network' | 'database'

interface LogEntry {
  id: string
  timestamp: string
  level: LogLevel
  source: LogSource
  service: string
  message: string
  details?: string
  host: string
  userId?: string
}

const mockLogs: LogEntry[] = [
  {
    id: 'LOG-001',
    timestamp: '2025-01-20T11:45:32.123Z',
    level: 'error',
    source: 'application',
    service: 'api-gateway',
    message: 'Connection timeout to database server',
    details: 'java.sql.SQLException: Connection timed out after 30000ms. Server: db-primary-01. Retry attempt: 3/5',
    host: 'app-server-01',
    userId: 'system'
  },
  {
    id: 'LOG-002',
    timestamp: '2025-01-20T11:45:30.456Z',
    level: 'warning',
    source: 'security',
    service: 'auth-service',
    message: 'Multiple failed login attempts detected',
    details: 'User: admin@acme.com, IP: 192.168.1.105, Attempts: 5, Account locked for 15 minutes',
    host: 'auth-server-01',
    userId: 'admin@acme.com'
  },
  {
    id: 'LOG-003',
    timestamp: '2025-01-20T11:45:28.789Z',
    level: 'info',
    source: 'system',
    service: 'scheduler',
    message: 'Scheduled backup job completed successfully',
    details: 'Job: daily-backup, Duration: 45m 23s, Files: 12,456, Size: 2.3GB',
    host: 'backup-server-01'
  },
  {
    id: 'LOG-004',
    timestamp: '2025-01-20T11:45:25.012Z',
    level: 'critical',
    source: 'network',
    service: 'firewall',
    message: 'Potential DDoS attack detected',
    details: 'Source IPs: Multiple, Requests/sec: 15,000+, Action: Rate limiting enabled, Geo-blocking activated',
    host: 'fw-edge-01'
  },
  {
    id: 'LOG-005',
    timestamp: '2025-01-20T11:45:20.345Z',
    level: 'debug',
    source: 'application',
    service: 'payment-service',
    message: 'Transaction processing initiated',
    details: 'TransactionID: TXN-98765, Amount: $1,234.56, Gateway: Stripe, Status: Processing',
    host: 'payment-server-01',
    userId: 'user@example.com'
  },
  {
    id: 'LOG-006',
    timestamp: '2025-01-20T11:45:15.678Z',
    level: 'info',
    source: 'database',
    service: 'postgresql',
    message: 'Query optimization suggestion',
    details: 'Slow query detected: SELECT * FROM orders WHERE..., Duration: 3.2s, Suggestion: Add index on created_at column',
    host: 'db-primary-01'
  },
  {
    id: 'LOG-007',
    timestamp: '2025-01-20T11:45:10.901Z',
    level: 'warning',
    source: 'system',
    service: 'disk-monitor',
    message: 'Disk space warning threshold reached',
    details: 'Volume: /dev/sda1, Usage: 85%, Available: 45GB, Threshold: 80%',
    host: 'app-server-02'
  },
  {
    id: 'LOG-008',
    timestamp: '2025-01-20T11:45:05.234Z',
    level: 'error',
    source: 'application',
    service: 'email-service',
    message: 'Failed to send notification email',
    details: 'Recipient: user@domain.com, Error: SMTP connection refused, Retry scheduled',
    host: 'mail-server-01'
  },
  {
    id: 'LOG-009',
    timestamp: '2025-01-20T11:45:00.567Z',
    level: 'info',
    source: 'security',
    service: 'audit-log',
    message: 'User permission changed',
    details: 'User: john.doe, Role changed: viewer -> editor, Changed by: admin, Module: Documents',
    host: 'auth-server-01',
    userId: 'admin'
  },
  {
    id: 'LOG-010',
    timestamp: '2025-01-20T11:44:55.890Z',
    level: 'info',
    source: 'network',
    service: 'load-balancer',
    message: 'Server added to pool',
    details: 'Server: app-server-03, Pool: web-frontend, Health: OK, Weight: 1',
    host: 'lb-primary-01'
  }
]

export default function SystemLogs() {
  const [logs] = useState<LogEntry[]>(mockLogs)
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterLevel, setFilterLevel] = useState<string>('all')
  const [filterSource, setFilterSource] = useState<string>('all')
  const [isLive, setIsLive] = useState(true)
  const [showFilters, setShowFilters] = useState(false)

  const filteredLogs = logs.filter(log => {
    const matchesSearch = log.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.service.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (log.details?.toLowerCase().includes(searchQuery.toLowerCase()))
    const matchesLevel = filterLevel === 'all' || log.level === filterLevel
    const matchesSource = filterSource === 'all' || log.source === filterSource
    return matchesSearch && matchesLevel && matchesSource
  })

  const getLevelIcon = (level: LogLevel) => {
    switch (level) {
      case 'info': return <Info className="w-4 h-4 text-blue-500" />
      case 'warning': return <AlertTriangle className="w-4 h-4 text-yellow-500" />
      case 'error': return <AlertCircle className="w-4 h-4 text-red-500" />
      case 'critical': return <AlertCircle className="w-4 h-4 text-red-600" />
      case 'debug': return <Bug className="w-4 h-4 text-gray-500" />
      default: return <Info className="w-4 h-4 text-gray-500" />
    }
  }

  const getLevelColor = (level: LogLevel) => {
    switch (level) {
      case 'info': return 'bg-blue-100 text-blue-700'
      case 'warning': return 'bg-yellow-100 text-yellow-700'
      case 'error': return 'bg-red-100 text-red-700'
      case 'critical': return 'bg-red-200 text-red-800'
      case 'debug': return 'bg-gray-100 text-gray-700'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  const getSourceIcon = (source: LogSource) => {
    switch (source) {
      case 'system': return <Server className="w-4 h-4" />
      case 'application': return <FileText className="w-4 h-4" />
      case 'security': return <Shield className="w-4 h-4" />
      case 'network': return <Network className="w-4 h-4" />
      case 'database': return <Database className="w-4 h-4" />
      default: return <FileText className="w-4 h-4" />
    }
  }

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const errorCount = logs.filter(l => l.level === 'error' || l.level === 'critical').length
  const warningCount = logs.filter(l => l.level === 'warning').length
  const infoCount = logs.filter(l => l.level === 'info').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">System Logs</h1>
          <p className="text-gray-600 mt-1">Real-time log monitoring and analysis</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsLive(!isLive)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg border ${
              isLive ? 'bg-green-100 border-green-300 text-green-700' : 'bg-gray-100 border-gray-300 text-gray-700'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
            {isLive ? 'Live' : 'Paused'}
          </button>
          <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
            <Download className="w-4 h-4" />
            Export
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Logs</p>
              <p className="text-3xl font-bold text-gray-900">{logs.length}</p>
            </div>
            <div className="p-3 bg-gray-100 rounded-lg">
              <FileText className="w-6 h-6 text-gray-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Errors</p>
              <p className="text-3xl font-bold text-red-600">{errorCount}</p>
            </div>
            <div className="p-3 bg-red-100 rounded-lg">
              <AlertCircle className="w-6 h-6 text-red-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Warnings</p>
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
              <p className="text-sm text-gray-500">Info</p>
              <p className="text-3xl font-bold text-blue-600">{infoCount}</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-lg">
              <Info className="w-6 h-6 text-blue-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search logs by message, service, or host..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
          >
            <Filter className="w-4 h-4" />
            Filters
            <ChevronDown className={`w-4 h-4 transition-transform ${showFilters ? 'rotate-180' : ''}`} />
          </button>
        </div>

        {showFilters && (
          <div className="flex flex-wrap gap-4 mt-4 pt-4 border-t border-gray-200">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Level</label>
              <select
                value={filterLevel}
                onChange={(e) => setFilterLevel(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
              >
                <option value="all">All Levels</option>
                <option value="critical">Critical</option>
                <option value="error">Error</option>
                <option value="warning">Warning</option>
                <option value="info">Info</option>
                <option value="debug">Debug</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Source</label>
              <select
                value={filterSource}
                onChange={(e) => setFilterSource(e.target.value)}
                className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
              >
                <option value="all">All Sources</option>
                <option value="system">System</option>
                <option value="application">Application</option>
                <option value="security">Security</option>
                <option value="network">Network</option>
                <option value="database">Database</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Time Range</label>
              <select className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500">
                <option value="1h">Last Hour</option>
                <option value="6h">Last 6 Hours</option>
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="custom">Custom Range</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Log Stream */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        <div className="p-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-gray-900">Log Stream</h2>
            <span className="text-sm text-gray-500">{filteredLogs.length} entries</span>
          </div>
        </div>

        <div className="divide-y divide-gray-100 max-h-[600px] overflow-y-auto font-mono text-sm">
          {filteredLogs.map((log) => (
            <div
              key={log.id}
              className="p-4 hover:bg-gray-50 cursor-pointer"
              onClick={() => setSelectedLog(log)}
            >
              <div className="flex items-start gap-4">
                <div className="flex items-center gap-2 text-gray-400 w-28 shrink-0">
                  <Clock className="w-3 h-3" />
                  <span className="text-xs">{formatTimestamp(log.timestamp)}</span>
                </div>
                <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${getLevelColor(log.level)} w-16 text-center shrink-0`}>
                  {log.level}
                </span>
                <div className="flex items-center gap-2 text-gray-500 w-24 shrink-0">
                  {getSourceIcon(log.source)}
                  <span className="text-xs capitalize">{log.source}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-aether-600 font-medium">[{log.service}]</span>
                    <span className="text-gray-500">@{log.host}</span>
                  </div>
                  <p className="text-gray-900 break-words">{log.message}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Log Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setSelectedLog(null)} />
            <div className="relative bg-white rounded-xl shadow-xl w-full max-w-3xl p-6">
              <button
                onClick={() => setSelectedLog(null)}
                className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
              >
                <X className="w-6 h-6" />
              </button>

              {/* Header */}
              <div className="flex items-start gap-4 mb-6">
                <div className={`p-3 rounded-lg ${getLevelColor(selectedLog.level)}`}>
                  {getLevelIcon(selectedLog.level)}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${getLevelColor(selectedLog.level)}`}>
                      {selectedLog.level}
                    </span>
                    <span className="text-sm text-gray-500">{selectedLog.id}</span>
                  </div>
                  <h2 className="text-xl font-semibold text-gray-900 mt-2">{selectedLog.message}</h2>
                </div>
              </div>

              {/* Details */}
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-sm text-gray-500 mb-1">Timestamp</p>
                    <p className="font-medium text-gray-900">{new Date(selectedLog.timestamp).toLocaleString()}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-sm text-gray-500 mb-1">Source</p>
                    <div className="flex items-center gap-2">
                      {getSourceIcon(selectedLog.source)}
                      <span className="font-medium text-gray-900 capitalize">{selectedLog.source}</span>
                    </div>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-sm text-gray-500 mb-1">Service</p>
                    <p className="font-medium text-gray-900">{selectedLog.service}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-sm text-gray-500 mb-1">Host</p>
                    <p className="font-medium text-gray-900">{selectedLog.host}</p>
                  </div>
                </div>

                {selectedLog.userId && (
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-sm text-gray-500 mb-1">User ID</p>
                    <p className="font-medium text-gray-900">{selectedLog.userId}</p>
                  </div>
                )}

                {selectedLog.details && (
                  <div className="bg-gray-50 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-sm text-gray-500">Details</p>
                      <button
                        onClick={() => copyToClipboard(selectedLog.details || '')}
                        className="flex items-center gap-1 text-sm text-aether-600 hover:text-aether-700"
                      >
                        <Copy className="w-4 h-4" />
                        Copy
                      </button>
                    </div>
                    <pre className="font-mono text-sm text-gray-900 whitespace-pre-wrap break-words">
                      {selectedLog.details}
                    </pre>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex justify-end gap-3 mt-6 pt-6 border-t border-gray-200">
                <button className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
                  View Related Logs
                </button>
                <button className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
                  Create Ticket
                </button>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(selectedLog, null, 2))}
                  className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700"
                >
                  Copy JSON
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
