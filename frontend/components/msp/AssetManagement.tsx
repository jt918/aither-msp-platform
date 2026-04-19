import { useState, useEffect } from 'react'
import {
  Monitor,
  Server,
  Laptop,
  Smartphone,
  Printer,
  Wifi,
  HardDrive,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Search,
  Filter,
  Plus,
  Download,
  RefreshCw,
  Settings,
  Trash2,
  Eye
} from 'lucide-react'

interface Asset {
  id: string
  name: string
  type: 'server' | 'workstation' | 'laptop' | 'mobile' | 'printer' | 'network' | 'storage'
  status: 'online' | 'offline' | 'warning' | 'maintenance'
  os: string
  ip: string
  lastSeen: string
  assignedTo: string | null
  location: string
  health: number
  warranties: {
    expiry: string
    status: 'active' | 'expiring' | 'expired'
  }
  patches: {
    pending: number
    critical: number
  }
}

interface AssetStats {
  total: number
  online: number
  offline: number
  warning: number
  patchesPending: number
  warrantiesExpiring: number
}

export default function AssetManagement() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [stats, setStats] = useState<AssetStats | null>(null)
  const [filter, setFilter] = useState({ type: '', status: '', search: '' })
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = () => {
    setAssets([
      {
        id: 'AST-001',
        name: 'PROD-WEB-01',
        type: 'server',
        status: 'online',
        os: 'Ubuntu 22.04 LTS',
        ip: '10.0.1.10',
        lastSeen: '2026-02-04T10:30:00',
        assignedTo: null,
        location: 'Data Center A',
        health: 98,
        warranties: { expiry: '2027-06-15', status: 'active' },
        patches: { pending: 2, critical: 0 }
      },
      {
        id: 'AST-002',
        name: 'PROD-DB-01',
        type: 'server',
        status: 'online',
        os: 'Ubuntu 22.04 LTS',
        ip: '10.0.1.11',
        lastSeen: '2026-02-04T10:30:00',
        assignedTo: null,
        location: 'Data Center A',
        health: 95,
        warranties: { expiry: '2027-06-15', status: 'active' },
        patches: { pending: 1, critical: 0 }
      },
      {
        id: 'AST-003',
        name: 'WS-SALES-001',
        type: 'workstation',
        status: 'online',
        os: 'Windows 11 Pro',
        ip: '10.0.2.50',
        lastSeen: '2026-02-04T10:25:00',
        assignedTo: 'Sarah Chen',
        location: 'Office - Floor 2',
        health: 92,
        warranties: { expiry: '2026-03-20', status: 'expiring' },
        patches: { pending: 5, critical: 1 }
      },
      {
        id: 'AST-004',
        name: 'LAPTOP-DEV-015',
        type: 'laptop',
        status: 'online',
        os: 'macOS Sonoma 14.3',
        ip: '10.0.3.102',
        lastSeen: '2026-02-04T09:45:00',
        assignedTo: 'Michael Torres',
        location: 'Remote',
        health: 100,
        warranties: { expiry: '2028-01-10', status: 'active' },
        patches: { pending: 0, critical: 0 }
      },
      {
        id: 'AST-005',
        name: 'FIREWALL-EDGE-01',
        type: 'network',
        status: 'online',
        os: 'FortiOS 7.4',
        ip: '10.0.0.1',
        lastSeen: '2026-02-04T10:30:00',
        assignedTo: null,
        location: 'Data Center A',
        health: 100,
        warranties: { expiry: '2027-12-31', status: 'active' },
        patches: { pending: 0, critical: 0 }
      },
      {
        id: 'AST-006',
        name: 'NAS-BACKUP-01',
        type: 'storage',
        status: 'warning',
        os: 'Synology DSM 7.2',
        ip: '10.0.1.50',
        lastSeen: '2026-02-04T10:28:00',
        assignedTo: null,
        location: 'Data Center B',
        health: 78,
        warranties: { expiry: '2025-08-15', status: 'expired' },
        patches: { pending: 3, critical: 2 }
      },
      {
        id: 'AST-007',
        name: 'PRINTER-FLOOR2-01',
        type: 'printer',
        status: 'offline',
        os: 'HP JetDirect',
        ip: '10.0.2.200',
        lastSeen: '2026-02-03T16:45:00',
        assignedTo: null,
        location: 'Office - Floor 2',
        health: 0,
        warranties: { expiry: '2026-06-30', status: 'active' },
        patches: { pending: 0, critical: 0 }
      },
      {
        id: 'AST-008',
        name: 'MOBILE-EXEC-001',
        type: 'mobile',
        status: 'online',
        os: 'iOS 17.3',
        ip: 'DHCP',
        lastSeen: '2026-02-04T10:15:00',
        assignedTo: 'David Kim',
        location: 'Remote',
        health: 100,
        warranties: { expiry: '2027-09-01', status: 'active' },
        patches: { pending: 1, critical: 0 }
      }
    ])

    setStats({
      total: 156,
      online: 142,
      offline: 8,
      warning: 6,
      patchesPending: 47,
      warrantiesExpiring: 12
    })

    setLoading(false)
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'server': return Server
      case 'workstation': return Monitor
      case 'laptop': return Laptop
      case 'mobile': return Smartphone
      case 'printer': return Printer
      case 'network': return Wifi
      case 'storage': return HardDrive
      default: return Monitor
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'bg-green-100 text-green-800'
      case 'offline': return 'bg-red-100 text-red-800'
      case 'warning': return 'bg-yellow-100 text-yellow-800'
      case 'maintenance': return 'bg-blue-100 text-blue-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getStatusDot = (status: string) => {
    switch (status) {
      case 'online': return 'bg-green-500'
      case 'offline': return 'bg-red-500'
      case 'warning': return 'bg-yellow-500'
      case 'maintenance': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  const getHealthColor = (health: number) => {
    if (health >= 90) return 'text-green-600'
    if (health >= 70) return 'text-yellow-600'
    if (health >= 50) return 'text-orange-600'
    return 'text-red-600'
  }

  const filteredAssets = assets.filter(asset => {
    if (filter.type && asset.type !== filter.type) return false
    if (filter.status && asset.status !== filter.status) return false
    if (filter.search) {
      const search = filter.search.toLowerCase()
      return asset.name.toLowerCase().includes(search) ||
             asset.ip.toLowerCase().includes(search) ||
             (asset.assignedTo?.toLowerCase().includes(search) ?? false)
    }
    return true
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Asset Management</h1>
          <p className="text-gray-500">IT Asset Inventory & Monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-4 py-2 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50">
            <Download className="w-4 h-4" />
            Export
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
            <Plus className="w-4 h-4" />
            Add Asset
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Monitor className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
                <p className="text-sm text-gray-500">Total Assets</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.online}</p>
                <p className="text-sm text-gray-500">Online</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-100 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-red-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.offline}</p>
                <p className="text-sm text-gray-500">Offline</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-yellow-100 rounded-lg">
                <Clock className="w-6 h-6 text-yellow-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.warning}</p>
                <p className="text-sm text-gray-500">Warnings</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-100 rounded-lg">
                <Shield className="w-6 h-6 text-purple-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.patchesPending}</p>
                <p className="text-sm text-gray-500">Patches Due</p>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-100 rounded-lg">
                <Clock className="w-6 h-6 text-orange-600" />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.warrantiesExpiring}</p>
                <p className="text-sm text-gray-500">Warranties</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search assets..."
            value={filter.search}
            onChange={(e) => setFilter({ ...filter, search: e.target.value })}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
          />
        </div>
        <select
          value={filter.type}
          onChange={(e) => setFilter({ ...filter, type: e.target.value })}
          className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
        >
          <option value="">All Types</option>
          <option value="server">Servers</option>
          <option value="workstation">Workstations</option>
          <option value="laptop">Laptops</option>
          <option value="mobile">Mobile</option>
          <option value="printer">Printers</option>
          <option value="network">Network</option>
          <option value="storage">Storage</option>
        </select>
        <select
          value={filter.status}
          onChange={(e) => setFilter({ ...filter, status: e.target.value })}
          className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-aether-500"
        >
          <option value="">All Status</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="warning">Warning</option>
          <option value="maintenance">Maintenance</option>
        </select>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-4 py-2 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Asset Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Asset</th>
              <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Type</th>
              <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Status</th>
              <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">IP Address</th>
              <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Assigned To</th>
              <th className="text-center px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Health</th>
              <th className="text-center px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Patches</th>
              <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {filteredAssets.map((asset) => {
              const TypeIcon = getTypeIcon(asset.type)
              return (
                <tr key={asset.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-gray-100 rounded-lg">
                        <TypeIcon className="w-5 h-5 text-gray-600" />
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">{asset.name}</p>
                        <p className="text-sm text-gray-500">{asset.os}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="capitalize text-gray-700">{asset.type}</span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${getStatusDot(asset.status)}`} />
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(asset.status)}`}>
                        {asset.status}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 font-mono text-sm text-gray-700">{asset.ip}</td>
                  <td className="px-6 py-4 text-gray-700">
                    {asset.assignedTo || <span className="text-gray-400">Unassigned</span>}
                  </td>
                  <td className="px-6 py-4 text-center">
                    <span className={`font-bold ${getHealthColor(asset.health)}`}>
                      {asset.health}%
                    </span>
                  </td>
                  <td className="px-6 py-4 text-center">
                    {asset.patches.critical > 0 ? (
                      <span className="px-2 py-1 bg-red-100 text-red-800 rounded text-xs font-medium">
                        {asset.patches.critical} critical
                      </span>
                    ) : asset.patches.pending > 0 ? (
                      <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded text-xs font-medium">
                        {asset.patches.pending} pending
                      </span>
                    ) : (
                      <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-medium">
                        Up to date
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <button className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded">
                        <Eye className="w-4 h-4" />
                      </button>
                      <button className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded">
                        <Settings className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
