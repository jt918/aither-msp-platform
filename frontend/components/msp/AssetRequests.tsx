import { useState } from 'react'
import {
  Package,
  Search,
  Filter,
  Plus,
  Laptop,
  Monitor,
  Headphones,
  Server,
  Smartphone,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  User,
  DollarSign,
  Calendar,
  MessageSquare,
  MoreVertical,
  X,
  Send,
  ThumbsUp,
  ThumbsDown
} from 'lucide-react'

interface AssetRequest {
  id: string
  title: string
  description: string
  type: 'hardware' | 'software' | 'peripheral' | 'subscription'
  category: string
  priority: 'urgent' | 'high' | 'normal' | 'low'
  status: 'pending' | 'approved' | 'denied' | 'ordered' | 'delivered' | 'cancelled'
  requester: {
    name: string
    department: string
    email: string
  }
  estimatedCost: number
  actualCost?: number
  justification: string
  approver?: string
  approvedAt?: string
  createdAt: string
  neededBy?: string
  notes: string[]
  quantity: number
}

const mockRequests: AssetRequest[] = [
  {
    id: 'AR-001',
    title: 'MacBook Pro 16" M3 Max',
    description: 'New laptop for development work - current machine is 5 years old and cannot run latest dev tools efficiently.',
    type: 'hardware',
    category: 'Laptop',
    priority: 'high',
    status: 'approved',
    requester: { name: 'David Johnson', department: 'Engineering', email: 'david@aither.io' },
    estimatedCost: 3499,
    justification: 'Required for running containerized development environments and iOS builds. Current machine fails to compile large projects.',
    approver: 'Sarah Mitchell',
    approvedAt: '2025-01-16T14:00:00Z',
    createdAt: '2025-01-14T09:00:00Z',
    neededBy: '2025-02-01',
    notes: ['Approved for next budget cycle'],
    quantity: 1
  },
  {
    id: 'AR-002',
    title: 'JetBrains All Products Pack - 5 Licenses',
    description: 'Annual subscription for IDE tools including IntelliJ, WebStorm, and DataGrip.',
    type: 'subscription',
    category: 'Software',
    priority: 'normal',
    status: 'pending',
    requester: { name: 'Emily Chen', department: 'Engineering', email: 'emily@aither.io' },
    estimatedCost: 2995,
    justification: 'Team currently using free alternatives but productivity would increase significantly with professional tools.',
    createdAt: '2025-01-17T10:30:00Z',
    notes: [],
    quantity: 5
  },
  {
    id: 'AR-003',
    title: 'Dual Monitor Setup - 27" 4K',
    description: 'Two LG 27" 4K monitors for new hire workstation.',
    type: 'peripheral',
    category: 'Monitor',
    priority: 'normal',
    status: 'ordered',
    requester: { name: 'Jennifer Lee', department: 'Human Resources', email: 'jennifer@aither.io' },
    estimatedCost: 900,
    actualCost: 850,
    justification: 'Standard equipment for new engineering hire starting February 1st.',
    approver: 'Sarah Mitchell',
    approvedAt: '2025-01-15T11:00:00Z',
    createdAt: '2025-01-13T16:00:00Z',
    neededBy: '2025-01-30',
    notes: ['Ordered from Dell - ETA Jan 28'],
    quantity: 2
  },
  {
    id: 'AR-004',
    title: 'Zoom Enterprise License',
    description: 'Upgrade from Pro to Enterprise for additional webinar capacity and features.',
    type: 'subscription',
    category: 'Software',
    priority: 'urgent',
    status: 'pending',
    requester: { name: 'Michael Brown', department: 'Sales', email: 'michael@aither.io' },
    estimatedCost: 1800,
    justification: 'Customer webinars exceeding Pro plan limits. Need enterprise features for upcoming product launch.',
    createdAt: '2025-01-18T08:00:00Z',
    neededBy: '2025-01-25',
    notes: [],
    quantity: 1
  },
  {
    id: 'AR-005',
    title: 'Sony WH-1000XM5 Headphones',
    description: 'Noise-cancelling headphones for remote workers.',
    type: 'peripheral',
    category: 'Audio',
    priority: 'low',
    status: 'denied',
    requester: { name: 'Alex Rodriguez', department: 'Customer Success', email: 'alex@aither.io' },
    estimatedCost: 1400,
    justification: 'Request for 4 sets of headphones for remote team members for better call quality.',
    approver: 'Sarah Mitchell',
    createdAt: '2025-01-10T13:00:00Z',
    notes: ['Denied - Please use existing budget for WFH equipment'],
    quantity: 4
  },
  {
    id: 'AR-006',
    title: 'Dell PowerEdge R750 Server',
    description: 'Production server for new microservices cluster.',
    type: 'hardware',
    category: 'Server',
    priority: 'high',
    status: 'delivered',
    requester: { name: 'Emily Chen', department: 'Engineering', email: 'emily@aither.io' },
    estimatedCost: 12500,
    actualCost: 11800,
    justification: 'Required for production deployment of new customer-facing services. Current capacity at 85%.',
    approver: 'Sarah Mitchell',
    approvedAt: '2025-01-05T10:00:00Z',
    createdAt: '2025-01-02T09:00:00Z',
    neededBy: '2025-01-15',
    notes: ['Delivered and installed in rack 3', 'Configured by DevOps team'],
    quantity: 1
  }
]

const types = ['All', 'Hardware', 'Software', 'Peripheral', 'Subscription']
const statuses = ['All', 'Pending', 'Approved', 'Denied', 'Ordered', 'Delivered', 'Cancelled']

export default function AssetRequests() {
  const [requests] = useState<AssetRequest[]>(mockRequests)
  const [searchTerm, setSearchTerm] = useState('')
  const [typeFilter, setTypeFilter] = useState('All')
  const [statusFilter, setStatusFilter] = useState('All')
  const [selectedRequest, setSelectedRequest] = useState<AssetRequest | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)

  const filteredRequests = requests.filter(req => {
    const matchesSearch = req.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      req.description.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesType = typeFilter === 'All' || req.type.toLowerCase() === typeFilter.toLowerCase()
    const matchesStatus = statusFilter === 'All' || req.status.toLowerCase() === statusFilter.toLowerCase()
    return matchesSearch && matchesType && matchesStatus
  })

  const getTypeIcon = (type: AssetRequest['type']) => {
    switch (type) {
      case 'hardware': return <Laptop className="w-5 h-5" />
      case 'software': return <Monitor className="w-5 h-5" />
      case 'peripheral': return <Headphones className="w-5 h-5" />
      case 'subscription': return <Server className="w-5 h-5" />
    }
  }

  const getStatusColor = (status: AssetRequest['status']) => {
    switch (status) {
      case 'pending': return 'bg-yellow-100 text-yellow-700'
      case 'approved': return 'bg-green-100 text-green-700'
      case 'denied': return 'bg-red-100 text-red-700'
      case 'ordered': return 'bg-blue-100 text-blue-700'
      case 'delivered': return 'bg-purple-100 text-purple-700'
      case 'cancelled': return 'bg-gray-100 text-gray-700'
    }
  }

  const getPriorityColor = (priority: AssetRequest['priority']) => {
    switch (priority) {
      case 'urgent': return 'bg-red-100 text-red-700 border-red-200'
      case 'high': return 'bg-orange-100 text-orange-700 border-orange-200'
      case 'normal': return 'bg-gray-100 text-gray-700 border-gray-200'
      case 'low': return 'bg-blue-100 text-blue-700 border-blue-200'
    }
  }

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount)
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    })
  }

  // Stats
  const pendingRequests = requests.filter(r => r.status === 'pending').length
  const totalPendingValue = requests.filter(r => r.status === 'pending').reduce((sum, r) => sum + r.estimatedCost, 0)
  const approvedThisMonth = requests.filter(r => r.status === 'approved').length
  const deliveredThisMonth = requests.filter(r => r.status === 'delivered').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Asset Requests</h1>
          <p className="text-gray-600">Request and track hardware, software, and equipment</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700"
        >
          <Plus className="w-5 h-5" />
          New Request
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Clock className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{pendingRequests}</p>
              <p className="text-sm text-gray-500">Pending Approval</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-aether-100 rounded-lg">
              <DollarSign className="w-5 h-5 text-aether-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{formatCurrency(totalPendingValue)}</p>
              <p className="text-sm text-gray-500">Pending Value</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle2 className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{approvedThisMonth}</p>
              <p className="text-sm text-gray-500">Approved</p>
            </div>
          </div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Package className="w-5 h-5 text-purple-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{deliveredThisMonth}</p>
              <p className="text-sm text-gray-500">Delivered</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search requests..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
            >
              {types.map(type => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
            >
              {statuses.map(status => (
                <option key={status} value={status}>{status}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Request List */}
      <div className="space-y-4">
        {filteredRequests.map(request => (
          <div
            key={request.id}
            onClick={() => setSelectedRequest(request)}
            className="bg-white rounded-lg shadow p-6 cursor-pointer hover:shadow-md transition-shadow"
          >
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-lg ${
                  request.type === 'hardware' ? 'bg-blue-100 text-blue-600' :
                  request.type === 'software' ? 'bg-purple-100 text-purple-600' :
                  request.type === 'peripheral' ? 'bg-green-100 text-green-600' :
                  'bg-orange-100 text-orange-600'
                }`}>
                  {getTypeIcon(request.type)}
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900">{request.title}</h3>
                  <p className="text-sm text-gray-500">{request.category} • Qty: {request.quantity}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2 py-1 text-xs font-medium rounded border ${getPriorityColor(request.priority)}`}>
                  {request.priority}
                </span>
                <span className={`px-2 py-1 text-xs font-medium rounded ${getStatusColor(request.status)}`}>
                  {request.status}
                </span>
              </div>
            </div>

            <p className="text-gray-600 line-clamp-2 mb-3">{request.description}</p>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4 text-sm text-gray-500">
                <span className="flex items-center gap-1">
                  <User className="w-4 h-4" />
                  {request.requester.name}
                </span>
                <span className="flex items-center gap-1">
                  <Calendar className="w-4 h-4" />
                  {formatDate(request.createdAt)}
                </span>
                <span className="flex items-center gap-1 font-medium text-gray-900">
                  <DollarSign className="w-4 h-4" />
                  {formatCurrency(request.estimatedCost)}
                </span>
              </div>
              {request.neededBy && (
                <span className="text-sm text-orange-600">
                  Needed by: {formatDate(request.neededBy)}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {filteredRequests.length === 0 && (
        <div className="bg-white rounded-lg shadow p-12 text-center">
          <Package className="w-12 h-12 text-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No requests found</h3>
          <p className="text-gray-500">Try adjusting your search or filter criteria</p>
        </div>
      )}

      {/* Request Detail Modal */}
      {selectedRequest && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setSelectedRequest(null)} />
            <div className="relative bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-500">{selectedRequest.id}</span>
                  <span className={`px-2 py-1 text-xs font-medium rounded ${getStatusColor(selectedRequest.status)}`}>
                    {selectedRequest.status}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedRequest(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6">
                {/* Header */}
                <div className="flex items-start gap-4 mb-6">
                  <div className={`p-3 rounded-lg ${
                    selectedRequest.type === 'hardware' ? 'bg-blue-100 text-blue-600' :
                    selectedRequest.type === 'software' ? 'bg-purple-100 text-purple-600' :
                    selectedRequest.type === 'peripheral' ? 'bg-green-100 text-green-600' :
                    'bg-orange-100 text-orange-600'
                  }`}>
                    {getTypeIcon(selectedRequest.type)}
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-gray-900">{selectedRequest.title}</h2>
                    <p className="text-gray-500">{selectedRequest.category} • Quantity: {selectedRequest.quantity}</p>
                  </div>
                </div>

                {/* Description */}
                <div className="mb-6">
                  <h3 className="text-sm font-medium text-gray-500 mb-2">Description</h3>
                  <p className="text-gray-700">{selectedRequest.description}</p>
                </div>

                {/* Justification */}
                <div className="mb-6">
                  <h3 className="text-sm font-medium text-gray-500 mb-2">Business Justification</h3>
                  <p className="text-gray-700">{selectedRequest.justification}</p>
                </div>

                {/* Details Grid */}
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Requester</p>
                    <p className="font-medium text-gray-900">{selectedRequest.requester.name}</p>
                    <p className="text-sm text-gray-500">{selectedRequest.requester.department}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Estimated Cost</p>
                    <p className="font-medium text-gray-900 text-lg">{formatCurrency(selectedRequest.estimatedCost)}</p>
                    {selectedRequest.actualCost && (
                      <p className="text-sm text-green-600">Actual: {formatCurrency(selectedRequest.actualCost)}</p>
                    )}
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Requested</p>
                    <p className="font-medium text-gray-900">{formatDate(selectedRequest.createdAt)}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-xs text-gray-500">Needed By</p>
                    <p className="font-medium text-gray-900">
                      {selectedRequest.neededBy ? formatDate(selectedRequest.neededBy) : 'Not specified'}
                    </p>
                  </div>
                </div>

                {/* Approver Info */}
                {selectedRequest.approver && (
                  <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
                    <div className="flex items-center gap-2 text-green-700">
                      <CheckCircle2 className="w-5 h-5" />
                      <span className="font-medium">Approved by {selectedRequest.approver}</span>
                    </div>
                    {selectedRequest.approvedAt && (
                      <p className="text-sm text-green-600 mt-1">
                        on {formatDate(selectedRequest.approvedAt)}
                      </p>
                    )}
                  </div>
                )}

                {/* Notes */}
                {selectedRequest.notes.length > 0 && (
                  <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-500 mb-2">Notes</h3>
                    <div className="space-y-2">
                      {selectedRequest.notes.map((note, i) => (
                        <p key={i} className="text-gray-700 text-sm bg-gray-50 p-3 rounded-lg">
                          {note}
                        </p>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions for pending requests */}
                {selectedRequest.status === 'pending' && (
                  <div className="border-t border-gray-200 pt-4 flex gap-3">
                    <button className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center justify-center gap-2">
                      <ThumbsUp className="w-4 h-4" />
                      Approve
                    </button>
                    <button className="flex-1 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 flex items-center justify-center gap-2">
                      <ThumbsDown className="w-4 h-4" />
                      Deny
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setShowCreateModal(false)} />
            <div className="relative bg-white rounded-xl shadow-xl max-w-xl w-full">
              <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
                <h2 className="text-lg font-semibold">New Asset Request</h2>
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Asset Name</label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                    placeholder="e.g., MacBook Pro 16 M3"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                    <select className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent">
                      <option value="hardware">Hardware</option>
                      <option value="software">Software</option>
                      <option value="peripheral">Peripheral</option>
                      <option value="subscription">Subscription</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
                    <select className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent">
                      <option value="normal">Normal</option>
                      <option value="low">Low</option>
                      <option value="high">High</option>
                      <option value="urgent">Urgent</option>
                    </select>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Estimated Cost</label>
                    <input
                      type="number"
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                      placeholder="0.00"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Quantity</label>
                    <input
                      type="number"
                      className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                      defaultValue={1}
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Business Justification</label>
                  <textarea
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                    placeholder="Why is this asset needed?"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Needed By (Optional)</label>
                  <input
                    type="date"
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-transparent"
                  />
                </div>
              </div>
              <div className="px-6 py-4 border-t border-gray-200 flex justify-end gap-3">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 text-gray-700 border border-gray-200 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700 flex items-center gap-2">
                  <Send className="w-4 h-4" />
                  Submit Request
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
