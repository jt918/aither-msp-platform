import { useState, useEffect } from 'react'
import {
  Shield,
  AlertTriangle,
  AlertOctagon,
  Activity,
  Lock,
  Unlock,
  Eye,
  Server,
  Globe,
  CheckCircle,
  XCircle,
  Clock
} from 'lucide-react'
import api from '../../services/api'

interface Incident {
  incident_id: string
  title: string
  severity: string
  status: string
  affected_systems: string[]
  created_at: string
}

export default function Cyber911() {
  const [defconLevel, setDefconLevel] = useState(5)
  const [activeIncidents, setActiveIncidents] = useState(0)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchDashboard()
  }, [])

  const fetchDashboard = async () => {
    try {
      const response = await api.get('/api/msp/cyber-911/dashboard')
      const data = response.data
      setDefconLevel(data.defcon_level || 5)
      setActiveIncidents(data.active_incidents || 0)
      setIncidents(data.recent_incidents || [])
    } catch (error) {
      console.error('Error fetching cyber dashboard:', error)
    } finally {
      setLoading(false)
    }
  }

  const getDefconColor = (level: number) => {
    switch (level) {
      case 1: return 'from-red-600 to-red-800'
      case 2: return 'from-red-500 to-red-700'
      case 3: return 'from-orange-500 to-orange-700'
      case 4: return 'from-yellow-500 to-yellow-700'
      case 5: return 'from-green-500 to-green-700'
      default: return 'from-gray-500 to-gray-700'
    }
  }

  const getDefconText = (level: number) => {
    switch (level) {
      case 1: return 'Maximum Alert - Critical Breach'
      case 2: return 'High Alert - Active Threat'
      case 3: return 'Increased Readiness'
      case 4: return 'Elevated Awareness'
      case 5: return 'Normal Operations'
      default: return 'Unknown Status'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-300'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-300'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-300'
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-300'
      default: return 'bg-gray-100 text-gray-800 border-gray-300'
    }
  }

  // Demo data for display
  const demoIncidents: Incident[] = [
    {
      incident_id: 'INC-001',
      title: 'Brute Force Attack Detected',
      severity: 'high',
      status: 'investigating',
      affected_systems: ['auth-server-01', 'vpn-gateway'],
      created_at: new Date(Date.now() - 30 * 60000).toISOString()
    },
    {
      incident_id: 'INC-002',
      title: 'Suspicious Outbound Traffic',
      severity: 'medium',
      status: 'contained',
      affected_systems: ['workstation-42'],
      created_at: new Date(Date.now() - 2 * 3600000).toISOString()
    },
    {
      incident_id: 'INC-003',
      title: 'Malware Detection - Ransomware Variant',
      severity: 'critical',
      status: 'resolved',
      affected_systems: ['file-server-02'],
      created_at: new Date(Date.now() - 24 * 3600000).toISOString()
    }
  ]

  const displayIncidents = incidents.length > 0 ? incidents : demoIncidents

  return (
    <div className="space-y-6">
      {/* DEFCON Banner */}
      <div className={`bg-gradient-to-r ${getDefconColor(defconLevel)} rounded-xl p-6 text-white`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="p-4 bg-white/20 rounded-xl">
              <Shield className="w-10 h-10" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">DEFCON {defconLevel}</h1>
              <p className="text-white/80 text-lg">{getDefconText(defconLevel)}</p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-4xl font-bold">{activeIncidents}</p>
            <p className="text-white/80">Active Incidents</p>
          </div>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 rounded-lg">
              <AlertOctagon className="w-6 h-6 text-red-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Critical Incidents</p>
              <p className="text-2xl font-bold text-gray-900">0</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Lock className="w-6 h-6 text-blue-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Blocked IPs (24h)</p>
              <p className="text-2xl font-bold text-gray-900">47</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-100 rounded-lg">
              <Server className="w-6 h-6 text-orange-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Isolated Hosts</p>
              <p className="text-2xl font-bold text-gray-900">2</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <p className="text-sm text-gray-500">Resolved (24h)</p>
              <p className="text-2xl font-bold text-gray-900">12</p>
            </div>
          </div>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        <div className="p-5 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Security Incidents</h2>
            <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 text-sm flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Report Incident
            </button>
          </div>
        </div>

        <div className="divide-y divide-gray-100">
          {displayIncidents.map((incident) => (
            <div key={incident.incident_id} className="p-5 hover:bg-gray-50">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="font-medium text-gray-900">{incident.title}</h3>
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(incident.severity)}`}>
                      {incident.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-sm text-gray-500">
                    <span className="flex items-center gap-1">
                      <Clock className="w-4 h-4" />
                      {new Date(incident.created_at).toLocaleString()}
                    </span>
                    <span className="flex items-center gap-1">
                      <Server className="w-4 h-4" />
                      {incident.affected_systems.length} affected
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {incident.affected_systems.map((system, i) => (
                      <span key={i} className="px-2 py-1 bg-gray-100 text-gray-600 rounded text-xs">
                        {system}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                    incident.status === 'investigating' ? 'bg-blue-100 text-blue-700' :
                    incident.status === 'contained' ? 'bg-orange-100 text-orange-700' :
                    incident.status === 'resolved' ? 'bg-green-100 text-green-700' :
                    'bg-gray-100 text-gray-700'
                  }`}>
                    {incident.status}
                  </span>
                </div>
              </div>
            </div>
          ))}

          {displayIncidents.length === 0 && (
            <div className="p-12 text-center">
              <Shield className="w-12 h-12 text-green-500 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900">All Clear</h3>
              <p className="text-gray-500">No active security incidents</p>
            </div>
          )}
        </div>
      </div>

      {/* Threat Intelligence */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Intelligence Feed</h3>
          <div className="space-y-3">
            {[
              { type: 'IOC', title: 'New Ransomware C2 Servers', severity: 'high', time: '2h ago' },
              { type: 'Advisory', title: 'Critical VMware Vulnerability', severity: 'critical', time: '5h ago' },
              { type: 'IOC', title: 'Phishing Campaign Indicators', severity: 'medium', time: '12h ago' },
            ].map((item, i) => (
              <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <Globe className={`w-5 h-5 ${
                    item.severity === 'critical' ? 'text-red-500' :
                    item.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'
                  }`} />
                  <div>
                    <p className="font-medium text-gray-900">{item.title}</p>
                    <p className="text-xs text-gray-500">{item.type}</p>
                  </div>
                </div>
                <span className="text-sm text-gray-500">{item.time}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Response Playbooks</h3>
          <div className="space-y-3">
            {[
              { name: 'Ransomware Response', status: 'ready', lastUsed: '3 days ago' },
              { name: 'Data Breach Protocol', status: 'ready', lastUsed: '2 weeks ago' },
              { name: 'DDoS Mitigation', status: 'ready', lastUsed: '1 month ago' },
              { name: 'Insider Threat', status: 'ready', lastUsed: 'Never' },
            ].map((playbook, i) => (
              <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <Activity className="w-5 h-5 text-aether-600" />
                  <span className="font-medium text-gray-900">{playbook.name}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-sm text-gray-500">{playbook.lastUsed}</span>
                  <span className="px-2 py-1 bg-green-100 text-green-700 rounded text-xs">
                    {playbook.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
