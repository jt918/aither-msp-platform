import { useState } from 'react'
import {
  Box,
  Calendar,
  AlertTriangle,
  CheckCircle,
  Clock,
  DollarSign,
  TrendingUp,
  RefreshCw,
  Trash2,
  Search,
  Filter,
  Plus,
  ChevronRight,
  BarChart3,
  Package,
  Laptop,
  Server,
  Smartphone,
  Monitor,
  Printer,
  HardDrive,
  X,
  ArrowRight,
  FileText
} from 'lucide-react'

// Types
interface Asset {
  id: string
  name: string
  type: 'laptop' | 'desktop' | 'server' | 'mobile' | 'printer' | 'network' | 'storage'
  manufacturer: string
  model: string
  serialNumber: string
  purchaseDate: string
  warrantyExpiry: string
  expectedLifespan: number // years
  currentAge: number // months
  lifecycleStage: 'new' | 'active' | 'aging' | 'end_of_life' | 'retired'
  status: 'in_use' | 'in_stock' | 'maintenance' | 'disposed'
  assignedTo: string | null
  department: string
  purchaseCost: number
  currentValue: number
  maintenanceCost: number
  nextMaintenanceDate: string
  location: string
}

// Mock data
const assets: Asset[] = [
  {
    id: 'AST-001',
    name: 'MacBook Pro 16"',
    type: 'laptop',
    manufacturer: 'Apple',
    model: 'MacBook Pro 16" M3 Max',
    serialNumber: 'C02X12345ABC',
    purchaseDate: '2024-01-15',
    warrantyExpiry: '2027-01-15',
    expectedLifespan: 4,
    currentAge: 12,
    lifecycleStage: 'active',
    status: 'in_use',
    assignedTo: 'Sarah Mitchell',
    department: 'Engineering',
    purchaseCost: 3499,
    currentValue: 2800,
    maintenanceCost: 0,
    nextMaintenanceDate: '2025-01-15',
    location: 'HQ - Floor 3'
  },
  {
    id: 'AST-002',
    name: 'Dell PowerEdge R750',
    type: 'server',
    manufacturer: 'Dell',
    model: 'PowerEdge R750xs',
    serialNumber: 'DELL789456123',
    purchaseDate: '2022-06-01',
    warrantyExpiry: '2025-06-01',
    expectedLifespan: 5,
    currentAge: 31,
    lifecycleStage: 'aging',
    status: 'in_use',
    assignedTo: null,
    department: 'IT Infrastructure',
    purchaseCost: 12500,
    currentValue: 6250,
    maintenanceCost: 1500,
    nextMaintenanceDate: '2025-02-01',
    location: 'Data Center A'
  },
  {
    id: 'AST-003',
    name: 'ThinkPad X1 Carbon',
    type: 'laptop',
    manufacturer: 'Lenovo',
    model: 'ThinkPad X1 Carbon Gen 11',
    serialNumber: 'LNV456789012',
    purchaseDate: '2023-03-10',
    warrantyExpiry: '2026-03-10',
    expectedLifespan: 4,
    currentAge: 22,
    lifecycleStage: 'active',
    status: 'in_use',
    assignedTo: 'David Johnson',
    department: 'Engineering',
    purchaseCost: 2199,
    currentValue: 1540,
    maintenanceCost: 0,
    nextMaintenanceDate: '2025-03-10',
    location: 'HQ - Floor 3'
  },
  {
    id: 'AST-004',
    name: 'HP LaserJet Enterprise',
    type: 'printer',
    manufacturer: 'HP',
    model: 'LaserJet Enterprise M507dn',
    serialNumber: 'HP123456789',
    purchaseDate: '2020-11-15',
    warrantyExpiry: '2023-11-15',
    expectedLifespan: 5,
    currentAge: 50,
    lifecycleStage: 'end_of_life',
    status: 'maintenance',
    assignedTo: null,
    department: 'Operations',
    purchaseCost: 899,
    currentValue: 150,
    maintenanceCost: 450,
    nextMaintenanceDate: '2025-01-20',
    location: 'HQ - Floor 1'
  },
  {
    id: 'AST-005',
    name: 'iPhone 15 Pro',
    type: 'mobile',
    manufacturer: 'Apple',
    model: 'iPhone 15 Pro 256GB',
    serialNumber: 'APPL987654321',
    purchaseDate: '2024-10-01',
    warrantyExpiry: '2025-10-01',
    expectedLifespan: 3,
    currentAge: 3,
    lifecycleStage: 'new',
    status: 'in_use',
    assignedTo: 'Emily Chen',
    department: 'Product',
    purchaseCost: 1199,
    currentValue: 1100,
    maintenanceCost: 0,
    nextMaintenanceDate: '2025-10-01',
    location: 'HQ - Floor 2'
  },
  {
    id: 'AST-006',
    name: 'NetApp Storage Array',
    type: 'storage',
    manufacturer: 'NetApp',
    model: 'AFF A250',
    serialNumber: 'NA789123456',
    purchaseDate: '2021-08-20',
    warrantyExpiry: '2024-08-20',
    expectedLifespan: 5,
    currentAge: 41,
    lifecycleStage: 'aging',
    status: 'in_use',
    assignedTo: null,
    department: 'IT Infrastructure',
    purchaseCost: 45000,
    currentValue: 18000,
    maintenanceCost: 5000,
    nextMaintenanceDate: '2025-02-20',
    location: 'Data Center A'
  },
  {
    id: 'AST-007',
    name: 'Dell OptiPlex 7090',
    type: 'desktop',
    manufacturer: 'Dell',
    model: 'OptiPlex 7090 Tower',
    serialNumber: 'DELL321654987',
    purchaseDate: '2019-05-10',
    warrantyExpiry: '2022-05-10',
    expectedLifespan: 5,
    currentAge: 68,
    lifecycleStage: 'retired',
    status: 'disposed',
    assignedTo: null,
    department: 'Finance',
    purchaseCost: 1299,
    currentValue: 0,
    maintenanceCost: 200,
    nextMaintenanceDate: '',
    location: 'Disposed'
  }
]

const getTypeIcon = (type: Asset['type']) => {
  switch (type) {
    case 'laptop': return <Laptop className="w-5 h-5" />
    case 'desktop': return <Monitor className="w-5 h-5" />
    case 'server': return <Server className="w-5 h-5" />
    case 'mobile': return <Smartphone className="w-5 h-5" />
    case 'printer': return <Printer className="w-5 h-5" />
    case 'storage': return <HardDrive className="w-5 h-5" />
    default: return <Box className="w-5 h-5" />
  }
}

const getStageColor = (stage: Asset['lifecycleStage']) => {
  switch (stage) {
    case 'new': return 'bg-green-100 text-green-700'
    case 'active': return 'bg-blue-100 text-blue-700'
    case 'aging': return 'bg-yellow-100 text-yellow-700'
    case 'end_of_life': return 'bg-orange-100 text-orange-700'
    case 'retired': return 'bg-gray-100 text-gray-700'
  }
}

const getStatusColor = (status: Asset['status']) => {
  switch (status) {
    case 'in_use': return 'bg-green-500'
    case 'in_stock': return 'bg-blue-500'
    case 'maintenance': return 'bg-yellow-500'
    case 'disposed': return 'bg-gray-500'
  }
}

export default function AssetLifecycle() {
  const [searchTerm, setSearchTerm] = useState('')
  const [stageFilter, setStageFilter] = useState<string>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)
  const [viewMode, setViewMode] = useState<'list' | 'lifecycle'>('list')

  const activeAssets = assets.filter(a => a.status !== 'disposed')

  const filteredAssets = assets.filter(asset => {
    const matchesSearch = asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          asset.serialNumber.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStage = stageFilter === 'all' || asset.lifecycleStage === stageFilter
    const matchesType = typeFilter === 'all' || asset.type === typeFilter
    return matchesSearch && matchesStage && matchesType
  })

  const stats = {
    totalAssets: activeAssets.length,
    totalValue: activeAssets.reduce((sum, a) => sum + a.currentValue, 0),
    endOfLife: activeAssets.filter(a => a.lifecycleStage === 'end_of_life').length,
    warrantyExpiring: activeAssets.filter(a => {
      const expiry = new Date(a.warrantyExpiry)
      const now = new Date()
      const thirtyDays = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)
      return expiry <= thirtyDays && expiry > now
    }).length
  }

  const lifecycleBreakdown = {
    new: activeAssets.filter(a => a.lifecycleStage === 'new').length,
    active: activeAssets.filter(a => a.lifecycleStage === 'active').length,
    aging: activeAssets.filter(a => a.lifecycleStage === 'aging').length,
    end_of_life: activeAssets.filter(a => a.lifecycleStage === 'end_of_life').length
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Asset Lifecycle</h1>
          <p className="text-gray-600 mt-1">Track asset health, depreciation, and replacement planning</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
            <BarChart3 className="w-4 h-4" />
            Reports
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
            <Plus className="w-4 h-4" />
            Add Asset
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Package className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.totalAssets}</p>
              <p className="text-sm text-gray-500">Active Assets</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <DollarSign className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">${(stats.totalValue / 1000).toFixed(0)}k</p>
              <p className="text-sm text-gray-500">Total Value</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-100 rounded-lg">
              <AlertTriangle className="w-5 h-5 text-orange-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.endOfLife}</p>
              <p className="text-sm text-gray-500">End of Life</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Clock className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.warrantyExpiring}</p>
              <p className="text-sm text-gray-500">Warranty Expiring</p>
            </div>
          </div>
        </div>
      </div>

      {/* Lifecycle Overview */}
      <div className="bg-white rounded-xl shadow-sm p-6">
        <h3 className="font-semibold text-gray-900 mb-4">Lifecycle Distribution</h3>
        <div className="flex items-center gap-2">
          {Object.entries(lifecycleBreakdown).map(([stage, count]) => {
            const percentage = (count / activeAssets.length) * 100
            const colors: Record<string, string> = {
              new: 'bg-green-500',
              active: 'bg-blue-500',
              aging: 'bg-yellow-500',
              end_of_life: 'bg-orange-500'
            }
            return (
              <div
                key={stage}
                className={`h-8 ${colors[stage]} rounded transition-all relative group`}
                style={{ width: `${percentage}%`, minWidth: count > 0 ? '40px' : '0' }}
              >
                <div className="absolute inset-0 flex items-center justify-center text-white text-xs font-medium">
                  {count > 0 && count}
                </div>
                <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 bg-gray-900 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                  {stage.replace('_', ' ')}: {count}
                </div>
              </div>
            )
          })}
        </div>
        <div className="flex items-center justify-center gap-6 mt-6">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded bg-green-500" />
            <span className="text-sm text-gray-600">New</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded bg-blue-500" />
            <span className="text-sm text-gray-600">Active</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded bg-yellow-500" />
            <span className="text-sm text-gray-600">Aging</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded bg-orange-500" />
            <span className="text-sm text-gray-600">End of Life</span>
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
              placeholder="Search assets..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg"
            />
          </div>
          <select
            value={stageFilter}
            onChange={(e) => setStageFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg"
          >
            <option value="all">All Stages</option>
            <option value="new">New</option>
            <option value="active">Active</option>
            <option value="aging">Aging</option>
            <option value="end_of_life">End of Life</option>
            <option value="retired">Retired</option>
          </select>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg"
          >
            <option value="all">All Types</option>
            <option value="laptop">Laptops</option>
            <option value="desktop">Desktops</option>
            <option value="server">Servers</option>
            <option value="mobile">Mobile</option>
            <option value="printer">Printers</option>
            <option value="storage">Storage</option>
          </select>
        </div>
      </div>

      {/* Assets List */}
      <div className="bg-white rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Asset</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Stage</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Age</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Value</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Warranty</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Assigned To</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredAssets.map((asset) => {
                const warrantyExpired = new Date(asset.warrantyExpiry) < new Date()
                const warrantyExpiringSoon = !warrantyExpired && new Date(asset.warrantyExpiry) < new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)

                return (
                  <tr
                    key={asset.id}
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() => setSelectedAsset(asset)}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${
                          asset.type === 'server' ? 'bg-purple-100 text-purple-600' :
                          asset.type === 'laptop' ? 'bg-blue-100 text-blue-600' :
                          asset.type === 'mobile' ? 'bg-green-100 text-green-600' :
                          'bg-gray-100 text-gray-600'
                        }`}>
                          {getTypeIcon(asset.type)}
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">{asset.name}</p>
                          <p className="text-sm text-gray-500">{asset.serialNumber}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full capitalize ${getStageColor(asset.lifecycleStage)}`}>
                        {asset.lifecycleStage.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div>
                        <p className="font-medium">{Math.floor(asset.currentAge / 12)}y {asset.currentAge % 12}m</p>
                        <div className="w-20 h-1.5 bg-gray-200 rounded-full mt-1">
                          <div
                            className={`h-1.5 rounded-full ${
                              asset.currentAge / (asset.expectedLifespan * 12) > 0.8 ? 'bg-red-500' :
                              asset.currentAge / (asset.expectedLifespan * 12) > 0.6 ? 'bg-yellow-500' : 'bg-green-500'
                            }`}
                            style={{ width: `${Math.min(100, (asset.currentAge / (asset.expectedLifespan * 12)) * 100)}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div>
                        <p className="font-medium">${asset.currentValue.toLocaleString()}</p>
                        <p className="text-xs text-gray-500">
                          {Math.round((1 - asset.currentValue / asset.purchaseCost) * 100)}% depreciated
                        </p>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className={`flex items-center gap-1 ${
                        warrantyExpired ? 'text-red-600' : warrantyExpiringSoon ? 'text-yellow-600' : 'text-green-600'
                      }`}>
                        {warrantyExpired ? <AlertTriangle className="w-4 h-4" /> : <CheckCircle className="w-4 h-4" />}
                        <span className="text-sm">{new Date(asset.warrantyExpiry).toLocaleDateString()}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600">
                      {asset.assignedTo || '-'}
                    </td>
                    <td className="px-6 py-4">
                      <ChevronRight className="w-5 h-5 text-gray-400" />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Asset Detail Modal */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-white rounded-2xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`p-3 rounded-xl ${
                  selectedAsset.type === 'server' ? 'bg-purple-100 text-purple-600' :
                  selectedAsset.type === 'laptop' ? 'bg-blue-100 text-blue-600' :
                  'bg-gray-100 text-gray-600'
                }`}>
                  {getTypeIcon(selectedAsset.type)}
                </div>
                <div>
                  <h2 className="text-xl font-bold text-gray-900">{selectedAsset.name}</h2>
                  <p className="text-gray-500">{selectedAsset.manufacturer} {selectedAsset.model}</p>
                </div>
              </div>
              <button onClick={() => setSelectedAsset(null)} className="p-2 hover:bg-gray-100 rounded-lg">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-500">Serial Number</p>
                  <p className="font-mono text-sm">{selectedAsset.serialNumber}</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-500">Status</p>
                  <span className={`inline-flex items-center gap-1 text-sm capitalize`}>
                    <div className={`w-2 h-2 rounded-full ${getStatusColor(selectedAsset.status)}`} />
                    {selectedAsset.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-500">Department</p>
                  <p className="font-medium">{selectedAsset.department}</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-xs text-gray-500">Location</p>
                  <p className="font-medium">{selectedAsset.location}</p>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="p-4 bg-blue-50 rounded-lg text-center">
                  <p className="text-2xl font-bold text-blue-700">${selectedAsset.purchaseCost.toLocaleString()}</p>
                  <p className="text-sm text-blue-600">Purchase Cost</p>
                </div>
                <div className="p-4 bg-green-50 rounded-lg text-center">
                  <p className="text-2xl font-bold text-green-700">${selectedAsset.currentValue.toLocaleString()}</p>
                  <p className="text-sm text-green-600">Current Value</p>
                </div>
                <div className="p-4 bg-yellow-50 rounded-lg text-center">
                  <p className="text-2xl font-bold text-yellow-700">${selectedAsset.maintenanceCost.toLocaleString()}</p>
                  <p className="text-sm text-yellow-600">Maintenance Cost</p>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t">
                <button className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                  <FileText className="w-4 h-4 inline mr-2" />
                  View History
                </button>
                <button className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
                  <RefreshCw className="w-4 h-4 inline mr-2" />
                  Schedule Maintenance
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
