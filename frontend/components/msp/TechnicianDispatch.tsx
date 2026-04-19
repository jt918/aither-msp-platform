import { useState } from 'react'
import {
  MapPin,
  User,
  Clock,
  Phone,
  CheckCircle,
  AlertTriangle,
  Navigation,
  Calendar,
  Wrench,
  ChevronRight,
  X,
  Search,
  Filter,
  Plus,
  RefreshCw,
  Car,
  Home,
  Building2
} from 'lucide-react'

type TechnicianStatus = 'available' | 'on_job' | 'en_route' | 'on_break' | 'offline'
type JobPriority = 'low' | 'medium' | 'high' | 'emergency'
type JobStatus = 'pending' | 'assigned' | 'en_route' | 'in_progress' | 'completed' | 'cancelled'

interface Technician {
  id: string
  name: string
  avatar?: string
  status: TechnicianStatus
  phone: string
  skills: string[]
  currentLocation?: string
  currentJobId?: string
  jobsToday: number
  rating: number
}

interface DispatchJob {
  id: string
  title: string
  client: string
  address: string
  priority: JobPriority
  status: JobStatus
  scheduledTime: string
  estimatedDuration: number
  technicianId?: string
  technicianName?: string
  description: string
  equipment: string[]
  contactName: string
  contactPhone: string
  notes?: string
}

const mockTechnicians: Technician[] = [
  {
    id: 'TECH-001',
    name: 'Mike Thompson',
    status: 'on_job',
    phone: '(555) 123-4567',
    skills: ['Network', 'Server', 'Desktop'],
    currentLocation: 'Acme Corp - Downtown',
    currentJobId: 'JOB-002',
    jobsToday: 3,
    rating: 4.8
  },
  {
    id: 'TECH-002',
    name: 'Sarah Chen',
    status: 'available',
    phone: '(555) 234-5678',
    skills: ['Security', 'Network', 'Cloud'],
    currentLocation: 'Office',
    jobsToday: 2,
    rating: 4.9
  },
  {
    id: 'TECH-003',
    name: 'James Rodriguez',
    status: 'en_route',
    phone: '(555) 345-6789',
    skills: ['Desktop', 'Printer', 'Phone'],
    currentLocation: 'En route to TechStart Inc',
    currentJobId: 'JOB-003',
    jobsToday: 4,
    rating: 4.7
  },
  {
    id: 'TECH-004',
    name: 'Emily Watson',
    status: 'on_break',
    phone: '(555) 456-7890',
    skills: ['Server', 'Backup', 'Cloud'],
    currentLocation: 'Lunch break',
    jobsToday: 2,
    rating: 4.6
  },
  {
    id: 'TECH-005',
    name: 'David Kim',
    status: 'offline',
    phone: '(555) 567-8901',
    skills: ['Network', 'Security', 'Server'],
    jobsToday: 0,
    rating: 4.9
  }
]

const mockJobs: DispatchJob[] = [
  {
    id: 'JOB-001',
    title: 'Server Maintenance',
    client: 'Acme Corporation',
    address: '123 Business Ave, Suite 400',
    priority: 'high',
    status: 'pending',
    scheduledTime: '2025-01-20T14:00:00',
    estimatedDuration: 120,
    description: 'Quarterly server maintenance and updates',
    equipment: ['Laptop', 'USB Drive', 'Tools'],
    contactName: 'John Smith',
    contactPhone: '(555) 111-2222',
    notes: 'Building requires badge access'
  },
  {
    id: 'JOB-002',
    title: 'Network Troubleshooting',
    client: 'Acme Corporation',
    address: '456 Downtown Plaza',
    priority: 'high',
    status: 'in_progress',
    scheduledTime: '2025-01-20T10:00:00',
    estimatedDuration: 90,
    technicianId: 'TECH-001',
    technicianName: 'Mike Thompson',
    description: 'Users reporting intermittent connectivity issues',
    equipment: ['Network Tester', 'Laptop', 'Cables'],
    contactName: 'Jane Doe',
    contactPhone: '(555) 222-3333'
  },
  {
    id: 'JOB-003',
    title: 'Workstation Setup',
    client: 'TechStart Inc',
    address: '789 Innovation Blvd',
    priority: 'medium',
    status: 'en_route',
    scheduledTime: '2025-01-20T13:00:00',
    estimatedDuration: 60,
    technicianId: 'TECH-003',
    technicianName: 'James Rodriguez',
    description: 'New employee workstation setup',
    equipment: ['Laptop', 'Monitor', 'Peripherals'],
    contactName: 'Bob Wilson',
    contactPhone: '(555) 333-4444'
  },
  {
    id: 'JOB-004',
    title: 'Emergency - Server Down',
    client: 'HealthFirst Medical',
    address: '321 Medical Center Dr',
    priority: 'emergency',
    status: 'pending',
    scheduledTime: '2025-01-20T09:00:00',
    estimatedDuration: 180,
    description: 'Primary database server unresponsive - critical',
    equipment: ['Laptop', 'Server Tools', 'Replacement Parts'],
    contactName: 'Dr. Sarah Miller',
    contactPhone: '(555) 444-5555',
    notes: 'URGENT - affects patient systems'
  },
  {
    id: 'JOB-005',
    title: 'Printer Installation',
    client: 'Global Finance LLC',
    address: '555 Financial District',
    priority: 'low',
    status: 'assigned',
    scheduledTime: '2025-01-20T15:30:00',
    estimatedDuration: 45,
    technicianId: 'TECH-002',
    technicianName: 'Sarah Chen',
    description: 'Install and configure new network printer',
    equipment: ['Printer', 'Network Cable', 'Driver USB'],
    contactName: 'Mike Brown',
    contactPhone: '(555) 555-6666'
  }
]

export default function TechnicianDispatch() {
  const [technicians] = useState<Technician[]>(mockTechnicians)
  const [jobs] = useState<DispatchJob[]>(mockJobs)
  const [selectedJob, setSelectedJob] = useState<DispatchJob | null>(null)
  const [selectedTech, setSelectedTech] = useState<Technician | null>(null)
  const [activeTab, setActiveTab] = useState<'jobs' | 'technicians'>('jobs')
  const [filterStatus, setFilterStatus] = useState<string>('all')

  const getStatusColor = (status: TechnicianStatus) => {
    switch (status) {
      case 'available': return 'bg-green-100 text-green-700'
      case 'on_job': return 'bg-blue-100 text-blue-700'
      case 'en_route': return 'bg-yellow-100 text-yellow-700'
      case 'on_break': return 'bg-orange-100 text-orange-700'
      case 'offline': return 'bg-gray-100 text-gray-500'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  const getJobStatusColor = (status: JobStatus) => {
    switch (status) {
      case 'pending': return 'bg-gray-100 text-gray-700'
      case 'assigned': return 'bg-blue-100 text-blue-700'
      case 'en_route': return 'bg-yellow-100 text-yellow-700'
      case 'in_progress': return 'bg-purple-100 text-purple-700'
      case 'completed': return 'bg-green-100 text-green-700'
      case 'cancelled': return 'bg-red-100 text-red-700'
      default: return 'bg-gray-100 text-gray-700'
    }
  }

  const getPriorityColor = (priority: JobPriority) => {
    switch (priority) {
      case 'emergency': return 'bg-red-100 text-red-700 border-red-300'
      case 'high': return 'bg-orange-100 text-orange-700 border-orange-300'
      case 'medium': return 'bg-yellow-100 text-yellow-700 border-yellow-300'
      case 'low': return 'bg-gray-100 text-gray-700 border-gray-300'
      default: return 'bg-gray-100 text-gray-700 border-gray-300'
    }
  }

  const availableTechs = technicians.filter(t => t.status === 'available').length
  const onJobTechs = technicians.filter(t => t.status === 'on_job' || t.status === 'en_route').length
  const pendingJobs = jobs.filter(j => j.status === 'pending').length
  const emergencyJobs = jobs.filter(j => j.priority === 'emergency' && j.status !== 'completed').length

  const filteredJobs = jobs.filter(job => {
    if (filterStatus === 'all') return true
    return job.status === filterStatus
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Technician Dispatch</h1>
          <p className="text-gray-600 mt-1">Manage field technicians and dispatch jobs</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
            <Plus className="w-4 h-4" />
            New Job
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Available Techs</p>
              <p className="text-3xl font-bold text-green-600">{availableTechs}</p>
            </div>
            <div className="p-3 bg-green-100 rounded-lg">
              <User className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Techs on Jobs</p>
              <p className="text-3xl font-bold text-blue-600">{onJobTechs}</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-lg">
              <Wrench className="w-6 h-6 text-blue-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Pending Jobs</p>
              <p className="text-3xl font-bold text-yellow-600">{pendingJobs}</p>
            </div>
            <div className="p-3 bg-yellow-100 rounded-lg">
              <Clock className="w-6 h-6 text-yellow-600" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Emergency Jobs</p>
              <p className="text-3xl font-bold text-red-600">{emergencyJobs}</p>
            </div>
            <div className="p-3 bg-red-100 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-red-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-4 border-b border-gray-200">
        <button
          onClick={() => setActiveTab('jobs')}
          className={`px-4 py-2 font-medium ${activeTab === 'jobs' ? 'text-aether-600 border-b-2 border-aether-600' : 'text-gray-500'}`}
        >
          Jobs ({jobs.length})
        </button>
        <button
          onClick={() => setActiveTab('technicians')}
          className={`px-4 py-2 font-medium ${activeTab === 'technicians' ? 'text-aether-600 border-b-2 border-aether-600' : 'text-gray-500'}`}
        >
          Technicians ({technicians.length})
        </button>
      </div>

      {/* Jobs Tab */}
      {activeTab === 'jobs' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search jobs..."
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
              />
            </div>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500"
            >
              <option value="all">All Status</option>
              <option value="pending">Pending</option>
              <option value="assigned">Assigned</option>
              <option value="en_route">En Route</option>
              <option value="in_progress">In Progress</option>
              <option value="completed">Completed</option>
            </select>
          </div>

          {/* Jobs List */}
          <div className="space-y-3">
            {filteredJobs.map((job) => (
              <div
                key={job.id}
                className={`bg-white rounded-xl shadow-sm border p-4 cursor-pointer hover:shadow-md transition-shadow ${
                  job.priority === 'emergency' ? 'border-red-200 bg-red-50' : 'border-gray-100'
                }`}
                onClick={() => setSelectedJob(job)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-4">
                    <div className={`p-2 rounded-lg ${getPriorityColor(job.priority)}`}>
                      <Wrench className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold text-gray-900">{job.title}</h3>
                        {job.priority === 'emergency' && (
                          <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded text-xs font-medium">
                            EMERGENCY
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-500">{job.client}</p>
                      <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
                        <span className="flex items-center gap-1">
                          <MapPin className="w-4 h-4" />
                          {job.address}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-4 h-4" />
                          {new Date(job.scheduledTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium capitalize ${getJobStatusColor(job.status)}`}>
                      {job.status.replace('_', ' ')}
                    </span>
                    {job.technicianName ? (
                      <span className="text-sm text-gray-600">
                        <User className="w-4 h-4 inline mr-1" />
                        {job.technicianName}
                      </span>
                    ) : (
                      <span className="text-sm text-gray-400">Unassigned</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Technicians Tab */}
      {activeTab === 'technicians' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {technicians.map((tech) => (
            <div
              key={tech.id}
              className="bg-white rounded-xl shadow-sm border border-gray-100 p-4 cursor-pointer hover:shadow-md transition-shadow"
              onClick={() => setSelectedTech(tech)}
            >
              <div className="flex items-start gap-3">
                <div className="w-12 h-12 rounded-full bg-aether-100 flex items-center justify-center text-aether-600 font-semibold">
                  {tech.name.split(' ').map(n => n[0]).join('')}
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold text-gray-900">{tech.name}</h3>
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium capitalize mt-1 ${getStatusColor(tech.status)}`}>
                    {tech.status.replace('_', ' ')}
                  </span>
                </div>
              </div>
              <div className="mt-4 space-y-2 text-sm">
                <div className="flex items-center gap-2 text-gray-500">
                  <Phone className="w-4 h-4" />
                  {tech.phone}
                </div>
                {tech.currentLocation && (
                  <div className="flex items-center gap-2 text-gray-500">
                    <MapPin className="w-4 h-4" />
                    {tech.currentLocation}
                  </div>
                )}
                <div className="flex items-center gap-2 text-gray-500">
                  <Wrench className="w-4 h-4" />
                  {tech.jobsToday} jobs today
                </div>
              </div>
              <div className="mt-3 flex flex-wrap gap-1">
                {tech.skills.map((skill, index) => (
                  <span key={index} className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded text-xs">
                    {skill}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Job Detail Modal */}
      {selectedJob && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen px-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setSelectedJob(null)} />
            <div className="relative bg-white rounded-xl shadow-xl w-full max-w-2xl p-6">
              <button
                onClick={() => setSelectedJob(null)}
                className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
              >
                <X className="w-6 h-6" />
              </button>

              {/* Header */}
              <div className="flex items-start gap-4 mb-6">
                <div className={`p-3 rounded-lg ${getPriorityColor(selectedJob.priority)}`}>
                  <Wrench className="w-6 h-6" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h2 className="text-xl font-bold text-gray-900">{selectedJob.title}</h2>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${getJobStatusColor(selectedJob.status)}`}>
                      {selectedJob.status.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="text-gray-500">{selectedJob.id}</p>
                </div>
              </div>

              {/* Details */}
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-50 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
                      <Building2 className="w-4 h-4" />
                      Client
                    </div>
                    <p className="font-medium text-gray-900">{selectedJob.client}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
                      <Clock className="w-4 h-4" />
                      Scheduled
                    </div>
                    <p className="font-medium text-gray-900">
                      {new Date(selectedJob.scheduledTime).toLocaleString()}
                    </p>
                  </div>
                </div>

                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
                    <MapPin className="w-4 h-4" />
                    Address
                  </div>
                  <p className="font-medium text-gray-900">{selectedJob.address}</p>
                </div>

                <div className="bg-gray-50 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
                    <Phone className="w-4 h-4" />
                    Contact
                  </div>
                  <p className="font-medium text-gray-900">{selectedJob.contactName} - {selectedJob.contactPhone}</p>
                </div>

                <div>
                  <p className="text-sm font-medium text-gray-700 mb-2">Description</p>
                  <p className="text-gray-600">{selectedJob.description}</p>
                </div>

                <div>
                  <p className="text-sm font-medium text-gray-700 mb-2">Required Equipment</p>
                  <div className="flex flex-wrap gap-2">
                    {selectedJob.equipment.map((item, index) => (
                      <span key={index} className="px-3 py-1 bg-aether-50 text-aether-700 rounded-full text-sm">
                        {item}
                      </span>
                    ))}
                  </div>
                </div>

                {selectedJob.notes && (
                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                    <p className="text-sm font-medium text-yellow-800 mb-1">Notes</p>
                    <p className="text-yellow-700">{selectedJob.notes}</p>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex justify-between items-center pt-6 mt-6 border-t border-gray-200">
                <div>
                  {selectedJob.technicianName ? (
                    <span className="flex items-center gap-2 text-gray-600">
                      <User className="w-4 h-4" />
                      Assigned to: {selectedJob.technicianName}
                    </span>
                  ) : (
                    <span className="text-gray-400">Unassigned</span>
                  )}
                </div>
                <div className="flex gap-3">
                  <button className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 flex items-center gap-2">
                    <Navigation className="w-4 h-4" />
                    Get Directions
                  </button>
                  {!selectedJob.technicianId && (
                    <button className="px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700 flex items-center gap-2">
                      <User className="w-4 h-4" />
                      Assign Tech
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
