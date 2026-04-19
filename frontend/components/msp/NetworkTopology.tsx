/**
 * Network Topology - MSP Solutions
 *
 * Visualizes network infrastructure, devices, connections, and health status.
 * Features interactive node display, traffic flow, and alert management.
 */

import React, { useState } from 'react';
import {
  Network,
  Server,
  Monitor,
  Wifi,
  Router,
  Shield,
  Cloud,
  Database,
  HardDrive,
  Cpu,
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Search,
  Filter,
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Settings,
  Eye,
  X,
  Signal,
  Globe,
  Lock,
  Layers
} from 'lucide-react';

// Types
interface NetworkNode {
  id: string;
  name: string;
  type: 'server' | 'switch' | 'router' | 'firewall' | 'endpoint' | 'cloud' | 'storage' | 'wireless';
  ip: string;
  mac?: string;
  status: 'online' | 'offline' | 'warning' | 'critical';
  location: string;
  zone: string;
  os?: string;
  uptime?: string;
  cpu?: number;
  memory?: number;
  bandwidth?: { in: number; out: number };
  connections: string[];
  alerts: number;
  lastSeen: string;
}

interface NetworkZone {
  id: string;
  name: string;
  color: string;
  nodeCount: number;
  healthScore: number;
}

// Mock Data
const nodes: NetworkNode[] = [
  {
    id: 'node-001',
    name: 'Core-Router-01',
    type: 'router',
    ip: '10.0.0.1',
    mac: '00:1A:2B:3C:4D:5E',
    status: 'online',
    location: 'Data Center 1',
    zone: 'core',
    uptime: '45d 12h',
    cpu: 35,
    memory: 42,
    bandwidth: { in: 850, out: 720 },
    connections: ['node-002', 'node-003', 'node-004'],
    alerts: 0,
    lastSeen: '2024-12-30T12:00:00Z'
  },
  {
    id: 'node-002',
    name: 'FW-External-01',
    type: 'firewall',
    ip: '10.0.0.2',
    status: 'online',
    location: 'Data Center 1',
    zone: 'dmz',
    uptime: '90d 8h',
    cpu: 28,
    memory: 55,
    bandwidth: { in: 1200, out: 980 },
    connections: ['node-001', 'node-005'],
    alerts: 0,
    lastSeen: '2024-12-30T12:00:00Z'
  },
  {
    id: 'node-003',
    name: 'SW-Access-01',
    type: 'switch',
    ip: '10.0.1.1',
    status: 'online',
    location: 'Floor 1',
    zone: 'access',
    uptime: '120d 4h',
    cpu: 15,
    memory: 38,
    connections: ['node-001', 'node-006', 'node-007', 'node-008'],
    alerts: 0,
    lastSeen: '2024-12-30T12:00:00Z'
  },
  {
    id: 'node-004',
    name: 'SRV-App-01',
    type: 'server',
    ip: '10.0.10.10',
    status: 'online',
    location: 'Data Center 1',
    zone: 'server',
    os: 'Ubuntu 22.04',
    uptime: '30d 16h',
    cpu: 72,
    memory: 68,
    connections: ['node-001', 'node-009'],
    alerts: 1,
    lastSeen: '2024-12-30T12:00:00Z'
  },
  {
    id: 'node-005',
    name: 'Cloud-AWS-Gateway',
    type: 'cloud',
    ip: '52.123.45.67',
    status: 'online',
    location: 'AWS us-east-1',
    zone: 'cloud',
    bandwidth: { in: 2500, out: 1800 },
    connections: ['node-002'],
    alerts: 0,
    lastSeen: '2024-12-30T12:00:00Z'
  },
  {
    id: 'node-006',
    name: 'WS-Eng-042',
    type: 'endpoint',
    ip: '10.0.1.42',
    status: 'online',
    location: 'Floor 1',
    zone: 'access',
    os: 'Windows 11',
    connections: ['node-003'],
    alerts: 0,
    lastSeen: '2024-12-30T11:58:00Z'
  },
  {
    id: 'node-007',
    name: 'WS-Sales-015',
    type: 'endpoint',
    ip: '10.0.1.15',
    status: 'warning',
    location: 'Floor 1',
    zone: 'access',
    os: 'Windows 10',
    connections: ['node-003'],
    alerts: 2,
    lastSeen: '2024-12-30T11:45:00Z'
  },
  {
    id: 'node-008',
    name: 'AP-Floor1-01',
    type: 'wireless',
    ip: '10.0.1.250',
    status: 'online',
    location: 'Floor 1',
    zone: 'access',
    bandwidth: { in: 450, out: 320 },
    connections: ['node-003'],
    alerts: 0,
    lastSeen: '2024-12-30T12:00:00Z'
  },
  {
    id: 'node-009',
    name: 'SAN-Primary',
    type: 'storage',
    ip: '10.0.10.100',
    status: 'critical',
    location: 'Data Center 1',
    zone: 'server',
    cpu: 45,
    memory: 92,
    connections: ['node-004'],
    alerts: 3,
    lastSeen: '2024-12-30T12:00:00Z'
  },
  {
    id: 'node-010',
    name: 'SRV-DB-01',
    type: 'server',
    ip: '10.0.10.20',
    status: 'offline',
    location: 'Data Center 1',
    zone: 'server',
    os: 'RHEL 8',
    connections: ['node-001'],
    alerts: 5,
    lastSeen: '2024-12-30T08:30:00Z'
  }
];

const zones: NetworkZone[] = [
  { id: 'core', name: 'Core Network', color: 'purple', nodeCount: 1, healthScore: 100 },
  { id: 'dmz', name: 'DMZ', color: 'orange', nodeCount: 1, healthScore: 100 },
  { id: 'server', name: 'Server Zone', color: 'blue', nodeCount: 3, healthScore: 45 },
  { id: 'access', name: 'Access Layer', color: 'green', nodeCount: 4, healthScore: 85 },
  { id: 'cloud', name: 'Cloud', color: 'cyan', nodeCount: 1, healthScore: 100 }
];

const NetworkTopology: React.FC = () => {
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [zoneFilter, setZoneFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState<'topology' | 'list'>('topology');

  // Stats
  const totalNodes = nodes.length;
  const onlineNodes = nodes.filter(n => n.status === 'online').length;
  const alertNodes = nodes.filter(n => n.alerts > 0).length;
  const totalAlerts = nodes.reduce((sum, n) => sum + n.alerts, 0);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'text-green-400 bg-green-500/20 border-green-500/50';
      case 'warning': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/50';
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/50';
      case 'offline': return 'text-gray-400 bg-gray-500/20 border-gray-500/50';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/50';
    }
  };

  const getStatusBgColor = (status: string) => {
    switch (status) {
      case 'online': return 'bg-green-500';
      case 'warning': return 'bg-yellow-500';
      case 'critical': return 'bg-red-500';
      case 'offline': return 'bg-gray-500';
      default: return 'bg-gray-500';
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'server': return <Server className="w-6 h-6" />;
      case 'switch': return <Network className="w-6 h-6" />;
      case 'router': return <Router className="w-6 h-6" />;
      case 'firewall': return <Shield className="w-6 h-6" />;
      case 'endpoint': return <Monitor className="w-6 h-6" />;
      case 'cloud': return <Cloud className="w-6 h-6" />;
      case 'storage': return <HardDrive className="w-6 h-6" />;
      case 'wireless': return <Wifi className="w-6 h-6" />;
      default: return <Cpu className="w-6 h-6" />;
    }
  };

  const getZoneColor = (zone: string) => {
    const z = zones.find(zn => zn.id === zone);
    if (!z) return 'gray';
    return z.color;
  };

  const filteredNodes = nodes.filter(node => {
    if (searchTerm && !node.name.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !node.ip.includes(searchTerm)) return false;
    if (zoneFilter !== 'all' && node.zone !== zoneFilter) return false;
    if (statusFilter !== 'all' && node.status !== statusFilter) return false;
    return true;
  });

  // Group nodes by zone for topology view
  const nodesByZone = filteredNodes.reduce((acc, node) => {
    if (!acc[node.zone]) acc[node.zone] = [];
    acc[node.zone].push(node);
    return acc;
  }, {} as Record<string, NetworkNode[]>);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Network Topology</h1>
          <p className="text-sm text-gray-400 mt-1">Visualize and monitor network infrastructure</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 bg-aether-dark border border-gray-700 rounded-lg p-1">
            <button
              onClick={() => setViewMode('topology')}
              className={`p-2 rounded ${viewMode === 'topology' ? 'bg-aether-accent text-white' : 'text-gray-400 hover:text-white'}`}
            >
              <Layers className="w-4 h-4" />
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`p-2 rounded ${viewMode === 'list' ? 'bg-aether-accent text-white' : 'text-gray-400 hover:text-white'}`}
            >
              <Activity className="w-4 h-4" />
            </button>
          </div>
          <button className="flex items-center gap-2 px-4 py-2 bg-aether-dark border border-gray-700 rounded-lg text-gray-300 hover:bg-gray-700">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Total Devices</p>
              <p className="text-2xl font-bold text-white">{totalNodes}</p>
              <p className="text-xs text-green-400 mt-1">{onlineNodes} online</p>
            </div>
            <div className="p-3 bg-blue-500/20 rounded-lg">
              <Network className="w-6 h-6 text-blue-400" />
            </div>
          </div>
        </div>

        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Network Health</p>
              <p className="text-2xl font-bold text-green-400">{Math.round((onlineNodes / totalNodes) * 100)}%</p>
              <p className="text-xs text-gray-500 mt-1">{totalNodes - onlineNodes} issues</p>
            </div>
            <div className="p-3 bg-green-500/20 rounded-lg">
              <Activity className="w-6 h-6 text-green-400" />
            </div>
          </div>
        </div>

        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Active Alerts</p>
              <p className="text-2xl font-bold text-red-400">{totalAlerts}</p>
              <p className="text-xs text-gray-500 mt-1">{alertNodes} devices affected</p>
            </div>
            <div className="p-3 bg-red-500/20 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-red-400" />
            </div>
          </div>
        </div>

        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Network Zones</p>
              <p className="text-2xl font-bold text-white">{zones.length}</p>
              <p className="text-xs text-gray-500 mt-1">Segmented</p>
            </div>
            <div className="p-3 bg-purple-500/20 rounded-lg">
              <Lock className="w-6 h-6 text-purple-400" />
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by name or IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-aether-dark border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-aether-accent"
          />
        </div>

        <select
          value={zoneFilter}
          onChange={(e) => setZoneFilter(e.target.value)}
          className="bg-aether-dark border border-gray-700 rounded-lg px-3 py-2 text-white"
        >
          <option value="all">All Zones</option>
          {zones.map(zone => (
            <option key={zone.id} value={zone.id}>{zone.name}</option>
          ))}
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-aether-dark border border-gray-700 rounded-lg px-3 py-2 text-white"
        >
          <option value="all">All Status</option>
          <option value="online">Online</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
          <option value="offline">Offline</option>
        </select>
      </div>

      {/* Topology View */}
      {viewMode === 'topology' && (
        <div className="space-y-4">
          {zones.filter(zone => !zoneFilter || zoneFilter === 'all' || zone.id === zoneFilter).map(zone => {
            const zoneNodes = nodesByZone[zone.id] || [];
            if (zoneNodes.length === 0) return null;

            return (
              <div key={zone.id} className="bg-aether-dark-blue rounded-lg border border-gray-700 p-4">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full bg-${zone.color}-500`} />
                    <h3 className="text-white font-semibold">{zone.name}</h3>
                    <span className="text-sm text-gray-400">({zoneNodes.length} devices)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-sm ${zone.healthScore >= 90 ? 'text-green-400' : zone.healthScore >= 70 ? 'text-yellow-400' : 'text-red-400'}`}>
                      {zone.healthScore}% health
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4">
                  {zoneNodes.map(node => (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      className={`p-4 rounded-lg border cursor-pointer transition-all hover:scale-105 ${getStatusColor(node.status)}`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className={`p-2 rounded-lg ${node.status === 'online' ? 'bg-green-500/20' : node.status === 'warning' ? 'bg-yellow-500/20' : node.status === 'critical' ? 'bg-red-500/20' : 'bg-gray-500/20'}`}>
                          {getNodeIcon(node.type)}
                        </div>
                        {node.alerts > 0 && (
                          <span className="px-2 py-0.5 bg-red-500 text-white text-xs rounded-full">
                            {node.alerts}
                          </span>
                        )}
                      </div>
                      <p className="text-white font-medium text-sm truncate">{node.name}</p>
                      <p className="text-gray-400 text-xs font-mono">{node.ip}</p>
                      <div className="flex items-center gap-1 mt-2">
                        <div className={`w-2 h-2 rounded-full ${getStatusBgColor(node.status)}`} />
                        <span className="text-xs text-gray-400 capitalize">{node.status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* List View */}
      {viewMode === 'list' && (
        <div className="bg-aether-dark-blue rounded-lg border border-gray-700 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="text-left text-xs text-gray-400 border-b border-gray-700 bg-gray-800/50">
                <th className="px-4 py-3">Device</th>
                <th className="px-4 py-3">IP Address</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Zone</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">CPU</th>
                <th className="px-4 py-3">Memory</th>
                <th className="px-4 py-3">Alerts</th>
                <th className="px-4 py-3">Last Seen</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredNodes.map(node => (
                <tr
                  key={node.id}
                  className="border-b border-gray-700/50 hover:bg-gray-800/30 cursor-pointer"
                  onClick={() => setSelectedNode(node)}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {getNodeIcon(node.type)}
                      <div>
                        <p className="text-white font-medium">{node.name}</p>
                        <p className="text-xs text-gray-500">{node.location}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-sm text-gray-300">{node.ip}</td>
                  <td className="px-4 py-3 text-gray-300 capitalize">{node.type}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs bg-${getZoneColor(node.zone)}-500/20 text-${getZoneColor(node.zone)}-400`}>
                      {node.zone}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${getStatusColor(node.status)}`}>
                      <div className={`w-2 h-2 rounded-full ${getStatusBgColor(node.status)}`} />
                      {node.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {node.cpu !== undefined ? (
                      <div className="w-16">
                        <div className="flex justify-between text-xs mb-1">
                          <span className={node.cpu > 80 ? 'text-red-400' : 'text-gray-400'}>{node.cpu}%</span>
                        </div>
                        <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${node.cpu > 80 ? 'bg-red-500' : node.cpu > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                            style={{ width: `${node.cpu}%` }}
                          />
                        </div>
                      </div>
                    ) : (
                      <span className="text-gray-500">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {node.memory !== undefined ? (
                      <div className="w-16">
                        <div className="flex justify-between text-xs mb-1">
                          <span className={node.memory > 80 ? 'text-red-400' : 'text-gray-400'}>{node.memory}%</span>
                        </div>
                        <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${node.memory > 80 ? 'bg-red-500' : node.memory > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                            style={{ width: `${node.memory}%` }}
                          />
                        </div>
                      </div>
                    ) : (
                      <span className="text-gray-500">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {node.alerts > 0 ? (
                      <span className="px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded">
                        {node.alerts}
                      </span>
                    ) : (
                      <span className="text-gray-500">0</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">
                    {new Date(node.lastSeen).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-3">
                    <button className="p-1.5 hover:bg-gray-700 rounded">
                      <Eye className="w-4 h-4 text-gray-400" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Node Detail Modal */}
      {selectedNode && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-aether-dark-blue rounded-xl border border-gray-700 w-full max-w-2xl">
            <div className="p-6 border-b border-gray-700 flex items-start justify-between">
              <div className="flex items-center gap-4">
                <div className={`p-3 rounded-lg ${getStatusColor(selectedNode.status)}`}>
                  {getNodeIcon(selectedNode.type)}
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">{selectedNode.name}</h2>
                  <p className="text-gray-400 font-mono">{selectedNode.ip}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-2 hover:bg-gray-700 rounded-lg"
              >
                <X className="w-5 h-5 text-gray-400" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <p className="text-sm text-gray-400 mb-1">Status</p>
                  <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full ${getStatusColor(selectedNode.status)}`}>
                    <div className={`w-2 h-2 rounded-full ${getStatusBgColor(selectedNode.status)}`} />
                    {selectedNode.status}
                  </span>
                </div>
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <p className="text-sm text-gray-400 mb-1">Type</p>
                  <p className="text-white capitalize">{selectedNode.type}</p>
                </div>
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <p className="text-sm text-gray-400 mb-1">Location</p>
                  <p className="text-white">{selectedNode.location}</p>
                </div>
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <p className="text-sm text-gray-400 mb-1">Zone</p>
                  <p className="text-white capitalize">{selectedNode.zone}</p>
                </div>
              </div>

              {(selectedNode.cpu !== undefined || selectedNode.memory !== undefined) && (
                <div className="grid grid-cols-2 gap-4">
                  {selectedNode.cpu !== undefined && (
                    <div className="p-4 bg-gray-800/50 rounded-lg">
                      <div className="flex justify-between items-center mb-2">
                        <p className="text-sm text-gray-400">CPU Usage</p>
                        <p className={`font-bold ${selectedNode.cpu > 80 ? 'text-red-400' : 'text-white'}`}>{selectedNode.cpu}%</p>
                      </div>
                      <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${selectedNode.cpu > 80 ? 'bg-red-500' : selectedNode.cpu > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                          style={{ width: `${selectedNode.cpu}%` }}
                        />
                      </div>
                    </div>
                  )}
                  {selectedNode.memory !== undefined && (
                    <div className="p-4 bg-gray-800/50 rounded-lg">
                      <div className="flex justify-between items-center mb-2">
                        <p className="text-sm text-gray-400">Memory Usage</p>
                        <p className={`font-bold ${selectedNode.memory > 80 ? 'text-red-400' : 'text-white'}`}>{selectedNode.memory}%</p>
                      </div>
                      <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${selectedNode.memory > 80 ? 'bg-red-500' : selectedNode.memory > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                          style={{ width: `${selectedNode.memory}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}

              {selectedNode.bandwidth && (
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <p className="text-sm text-gray-400 mb-3">Bandwidth</p>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="flex items-center gap-2">
                      <Signal className="w-4 h-4 text-green-400" />
                      <span className="text-white">{selectedNode.bandwidth.in} Mbps In</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Signal className="w-4 h-4 text-blue-400" />
                      <span className="text-white">{selectedNode.bandwidth.out} Mbps Out</span>
                    </div>
                  </div>
                </div>
              )}

              <div className="p-4 bg-gray-800/50 rounded-lg">
                <p className="text-sm text-gray-400 mb-2">Connected To ({selectedNode.connections.length})</p>
                <div className="flex flex-wrap gap-2">
                  {selectedNode.connections.map(connId => {
                    const connNode = nodes.find(n => n.id === connId);
                    if (!connNode) return null;
                    return (
                      <span
                        key={connId}
                        className="px-2 py-1 bg-aether-dark border border-gray-700 rounded text-sm text-gray-300"
                      >
                        {connNode.name}
                      </span>
                    );
                  })}
                </div>
              </div>

              {selectedNode.alerts > 0 && (
                <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <div className="flex items-center gap-2 text-red-400 mb-2">
                    <AlertTriangle className="w-5 h-5" />
                    <span className="font-medium">{selectedNode.alerts} Active Alert(s)</span>
                  </div>
                  <p className="text-sm text-gray-400">This device requires immediate attention.</p>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-gray-700 flex justify-end gap-3">
              <button className="px-4 py-2 bg-aether-dark border border-gray-700 text-gray-300 rounded-lg hover:bg-gray-700">
                View Logs
              </button>
              <button className="px-4 py-2 bg-aether-accent text-white rounded-lg hover:bg-aether-accent/80">
                Manage Device
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default NetworkTopology;
