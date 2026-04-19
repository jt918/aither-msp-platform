import { useState } from 'react'
import {
  Package,
  Search,
  Filter,
  Plus,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  BarChart3,
  Box,
  Truck,
  MapPin,
  Tag,
  Edit,
  Trash2,
  ChevronRight,
  Download,
  RefreshCw,
  QrCode,
  History,
  ArrowUpRight,
  ArrowDownRight
} from 'lucide-react'

interface InventoryItem {
  id: string
  name: string
  sku: string
  category: string
  quantity: number
  minStock: number
  maxStock: number
  unitPrice: number
  location: string
  supplier: string
  lastRestocked: string
  status: 'in_stock' | 'low_stock' | 'out_of_stock' | 'on_order'
  serialTracking: boolean
}

interface StockMovement {
  id: string
  itemId: string
  itemName: string
  type: 'in' | 'out' | 'transfer' | 'adjustment'
  quantity: number
  from?: string
  to?: string
  date: string
  user: string
  notes: string
}

const mockInventory: InventoryItem[] = [
  {
    id: 'INV-001',
    name: 'Dell OptiPlex 7090',
    sku: 'DELL-7090-I7',
    category: 'Workstations',
    quantity: 25,
    minStock: 10,
    maxStock: 50,
    unitPrice: 1299,
    location: 'Warehouse A',
    supplier: 'Dell Technologies',
    lastRestocked: '2024-01-10',
    status: 'in_stock',
    serialTracking: true
  },
  {
    id: 'INV-002',
    name: 'Cisco Meraki MR46',
    sku: 'CISCO-MR46',
    category: 'Networking',
    quantity: 8,
    minStock: 10,
    maxStock: 30,
    unitPrice: 895,
    location: 'Warehouse B',
    supplier: 'Cisco Systems',
    lastRestocked: '2024-01-05',
    status: 'low_stock',
    serialTracking: true
  },
  {
    id: 'INV-003',
    name: 'Microsoft Surface Pro 9',
    sku: 'MS-SP9-256',
    category: 'Tablets',
    quantity: 0,
    minStock: 5,
    maxStock: 20,
    unitPrice: 1599,
    location: 'Warehouse A',
    supplier: 'Microsoft',
    lastRestocked: '2023-12-15',
    status: 'out_of_stock',
    serialTracking: true
  },
  {
    id: 'INV-004',
    name: 'CAT6 Ethernet Cable 100ft',
    sku: 'CAT6-100FT-BLUE',
    category: 'Cables',
    quantity: 150,
    minStock: 50,
    maxStock: 200,
    unitPrice: 25,
    location: 'Warehouse B',
    supplier: 'Cable Matters',
    lastRestocked: '2024-01-12',
    status: 'in_stock',
    serialTracking: false
  },
  {
    id: 'INV-005',
    name: 'Logitech MX Master 3',
    sku: 'LOG-MXM3-BLK',
    category: 'Peripherals',
    quantity: 42,
    minStock: 20,
    maxStock: 100,
    unitPrice: 99,
    location: 'Warehouse A',
    supplier: 'Logitech',
    lastRestocked: '2024-01-08',
    status: 'in_stock',
    serialTracking: false
  },
  {
    id: 'INV-006',
    name: 'APC Smart-UPS 1500VA',
    sku: 'APC-SMT1500',
    category: 'Power',
    quantity: 12,
    minStock: 15,
    maxStock: 40,
    unitPrice: 599,
    location: 'Warehouse C',
    supplier: 'APC',
    lastRestocked: '2024-01-03',
    status: 'low_stock',
    serialTracking: true
  },
]

const mockMovements: StockMovement[] = [
  {
    id: 'MOV-001',
    itemId: 'INV-001',
    itemName: 'Dell OptiPlex 7090',
    type: 'out',
    quantity: 5,
    to: 'Client: Acme Corp',
    date: '2024-01-15T10:30:00',
    user: 'John Smith',
    notes: 'Deployment for new office'
  },
  {
    id: 'MOV-002',
    itemId: 'INV-002',
    itemName: 'Cisco Meraki MR46',
    type: 'in',
    quantity: 10,
    from: 'Supplier',
    date: '2024-01-14T14:00:00',
    user: 'Sarah Johnson',
    notes: 'Restock order #PO-4521'
  },
  {
    id: 'MOV-003',
    itemId: 'INV-004',
    itemName: 'CAT6 Ethernet Cable 100ft',
    type: 'transfer',
    quantity: 25,
    from: 'Warehouse A',
    to: 'Warehouse B',
    date: '2024-01-13T09:15:00',
    user: 'Mike Chen',
    notes: 'Balance inventory across locations'
  },
  {
    id: 'MOV-004',
    itemId: 'INV-005',
    itemName: 'Logitech MX Master 3',
    type: 'adjustment',
    quantity: -2,
    date: '2024-01-12T16:45:00',
    user: 'Emily Davis',
    notes: 'Inventory count correction'
  },
]

const categories = ['All', 'Workstations', 'Networking', 'Tablets', 'Cables', 'Peripherals', 'Power']
const locations = ['All Locations', 'Warehouse A', 'Warehouse B', 'Warehouse C']

export default function InventoryManagement() {
  const [view, setView] = useState<'inventory' | 'movements'>('inventory')
  const [searchTerm, setSearchTerm] = useState('')
  const [filterCategory, setFilterCategory] = useState('All')
  const [filterLocation, setFilterLocation] = useState('All Locations')
  const [filterStatus, setFilterStatus] = useState<string | null>(null)
  const [selectedItem, setSelectedItem] = useState<InventoryItem | null>(null)

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'in_stock': return 'bg-green-100 text-green-700'
      case 'low_stock': return 'bg-yellow-100 text-yellow-700'
      case 'out_of_stock': return 'bg-red-100 text-red-700'
      case 'on_order': return 'bg-blue-100 text-blue-700'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  const getMovementIcon = (type: string) => {
    switch (type) {
      case 'in': return <ArrowDownRight className="w-4 h-4 text-green-500" />
      case 'out': return <ArrowUpRight className="w-4 h-4 text-red-500" />
      case 'transfer': return <RefreshCw className="w-4 h-4 text-blue-500" />
      case 'adjustment': return <Edit className="w-4 h-4 text-yellow-500" />
      default: return null
    }
  }

  const filteredInventory = mockInventory.filter(item => {
    const matchesSearch = item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.sku.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCategory = filterCategory === 'All' || item.category === filterCategory
    const matchesLocation = filterLocation === 'All Locations' || item.location === filterLocation
    const matchesStatus = !filterStatus || item.status === filterStatus
    return matchesSearch && matchesCategory && matchesLocation && matchesStatus
  })

  const stats = {
    totalItems: mockInventory.length,
    totalValue: mockInventory.reduce((sum, item) => sum + (item.quantity * item.unitPrice), 0),
    lowStock: mockInventory.filter(i => i.status === 'low_stock').length,
    outOfStock: mockInventory.filter(i => i.status === 'out_of_stock').length
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Inventory Management</h1>
          <p className="text-gray-500">Track and manage IT assets and supplies</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-secondary flex items-center gap-2">
            <Download className="w-4 h-4" />
            Export
          </button>
          <button className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Add Item
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Items</p>
              <p className="text-2xl font-bold text-gray-900">{stats.totalItems}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center">
              <Package className="w-5 h-5 text-blue-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Total Value</p>
              <p className="text-2xl font-bold text-gray-900">
                ${(stats.totalValue / 1000).toFixed(0)}K
              </p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-green-100 flex items-center justify-center">
              <BarChart3 className="w-5 h-5 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Low Stock</p>
              <p className="text-2xl font-bold text-yellow-600">{stats.lowStock}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-yellow-100 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-yellow-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Out of Stock</p>
              <p className="text-2xl font-bold text-red-600">{stats.outOfStock}</p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-red-100 flex items-center justify-center">
              <Box className="w-5 h-5 text-red-600" />
            </div>
          </div>
        </div>
      </div>

      {/* View Toggle & Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setView('inventory')}
              className={`px-4 py-2 rounded-lg text-sm font-medium ${
                view === 'inventory' ? 'bg-aether-100 text-aether-700' : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              Inventory
            </button>
            <button
              onClick={() => setView('movements')}
              className={`px-4 py-2 rounded-lg text-sm font-medium ${
                view === 'movements' ? 'bg-aether-100 text-aether-700' : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              Stock Movements
            </button>
          </div>

          {view === 'inventory' && (
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search items..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm w-64"
                />
              </div>
              <select
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
              >
                {categories.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
              <select
                value={filterLocation}
                onChange={(e) => setFilterLocation(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
              >
                {locations.map(loc => (
                  <option key={loc} value={loc}>{loc}</option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>

      {/* Inventory List */}
      {view === 'inventory' && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Item</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Category</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Quantity</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Location</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Status</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase">Value</th>
                <th className="text-left px-6 py-3 text-xs font-semibold text-gray-500 uppercase"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {filteredInventory.map(item => (
                <tr key={item.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-gray-100 flex items-center justify-center">
                        <Package className="w-5 h-5 text-gray-500" />
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">{item.name}</p>
                        <p className="text-xs text-gray-500">{item.sku}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="px-2.5 py-1 bg-gray-100 text-gray-700 text-xs font-medium rounded">
                      {item.category}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div>
                      <p className="font-medium text-gray-900">{item.quantity}</p>
                      <p className="text-xs text-gray-500">Min: {item.minStock} / Max: {item.maxStock}</p>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-1.5">
                      <MapPin className="w-4 h-4 text-gray-400" />
                      <span className="text-sm text-gray-700">{item.location}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium ${getStatusColor(item.status)}`}>
                      {item.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="font-semibold text-gray-900">
                      ${(item.quantity * item.unitPrice).toLocaleString()}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => setSelectedItem(item)}
                      className="text-aether-600 hover:text-aether-700"
                    >
                      <ChevronRight className="w-5 h-5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Stock Movements */}
      {view === 'movements' && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <History className="w-5 h-5 text-aether-600" />
              Recent Stock Movements
            </h2>
          </div>
          <div className="space-y-3">
            {mockMovements.map(movement => (
              <div
                key={movement.id}
                className="flex items-center justify-between p-4 bg-gray-50 rounded-lg"
              >
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-full bg-white flex items-center justify-center shadow-sm">
                    {getMovementIcon(movement.type)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-gray-900">{movement.itemName}</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        movement.type === 'in' ? 'bg-green-100 text-green-700' :
                        movement.type === 'out' ? 'bg-red-100 text-red-700' :
                        movement.type === 'transfer' ? 'bg-blue-100 text-blue-700' :
                        'bg-yellow-100 text-yellow-700'
                      }`}>
                        {movement.type}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500">
                      {movement.type === 'in' && `From: ${movement.from}`}
                      {movement.type === 'out' && `To: ${movement.to}`}
                      {movement.type === 'transfer' && `${movement.from} → ${movement.to}`}
                      {movement.type === 'adjustment' && 'Stock adjustment'}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">{movement.notes}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className={`font-semibold ${
                    movement.quantity > 0 && movement.type !== 'out' ? 'text-green-600' : 'text-red-600'
                  }`}>
                    {movement.quantity > 0 && movement.type !== 'out' ? '+' : ''}{movement.quantity}
                  </p>
                  <p className="text-xs text-gray-500">{new Date(movement.date).toLocaleString()}</p>
                  <p className="text-xs text-gray-400">{movement.user}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Low Stock Alert */}
      {stats.lowStock > 0 && view === 'inventory' && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-yellow-500 mt-0.5" />
            <div>
              <h3 className="font-semibold text-yellow-800">Low Stock Alert</h3>
              <p className="text-sm text-yellow-700 mt-1">
                {stats.lowStock} item(s) are running low on stock. Consider reordering soon.
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {mockInventory
                  .filter(i => i.status === 'low_stock')
                  .map(item => (
                    <span key={item.id} className="px-2 py-1 bg-white rounded-lg text-sm text-gray-700">
                      {item.name} ({item.quantity}/{item.minStock})
                    </span>
                  ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Item Detail Modal */}
      {selectedItem && (
        <>
          <div className="fixed inset-0 bg-black/50 z-40" onClick={() => setSelectedItem(null)} />
          <div className="fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-full max-w-lg bg-white rounded-xl shadow-xl z-50 p-6">
            <div className="flex items-start gap-4 mb-6">
              <div className="w-14 h-14 rounded-lg bg-gray-100 flex items-center justify-center">
                <Package className="w-7 h-7 text-gray-500" />
              </div>
              <div className="flex-1">
                <h2 className="text-xl font-semibold text-gray-900">{selectedItem.name}</h2>
                <p className="text-gray-500">{selectedItem.sku}</p>
              </div>
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(selectedItem.status)}`}>
                {selectedItem.status.replace('_', ' ')}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-6">
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs text-gray-500">Current Stock</p>
                <p className="text-xl font-bold text-gray-900">{selectedItem.quantity}</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs text-gray-500">Unit Price</p>
                <p className="text-xl font-bold text-gray-900">${selectedItem.unitPrice}</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs text-gray-500">Location</p>
                <p className="font-medium text-gray-900">{selectedItem.location}</p>
              </div>
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-xs text-gray-500">Supplier</p>
                <p className="font-medium text-gray-900">{selectedItem.supplier}</p>
              </div>
            </div>

            <div className="flex items-center justify-between p-3 bg-blue-50 rounded-lg mb-6">
              <span className="text-sm text-blue-700">Total Value</span>
              <span className="text-lg font-bold text-blue-700">
                ${(selectedItem.quantity * selectedItem.unitPrice).toLocaleString()}
              </span>
            </div>

            <div className="flex gap-2">
              <button className="flex-1 btn-primary flex items-center justify-center gap-2">
                <Plus className="w-4 h-4" />
                Add Stock
              </button>
              <button className="flex-1 btn-secondary flex items-center justify-center gap-2">
                <Truck className="w-4 h-4" />
                Ship Out
              </button>
              <button
                onClick={() => setSelectedItem(null)}
                className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
              >
                Close
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
