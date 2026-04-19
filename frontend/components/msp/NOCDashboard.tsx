import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Monitor, AlertTriangle, Shield, Activity, Clock, Wifi, WifiOff,
  ChevronLeft, ChevronRight, Pause, Play, Maximize, Minimize,
  RefreshCw, Server, HardDrive, AlertCircle, CheckCircle, XCircle,
  Wrench, Cpu, MemoryStick, Network, Zap, TrendingUp, Bell
} from 'lucide-react';
import api from '../../services/api';

// ── Interfaces ─────────────────────────────────────────────────────────

interface EndpointsSummary {
  total: number;
  online: number;
  offline: number;
  warning: number;
  maintenance: number;
}

interface AlertItem {
  id: string;
  severity: string;
  title: string;
  endpoint: string;
  created_at: string;
  acknowledged: boolean;
}

interface AlertsSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  recent_alerts: AlertItem[];
}

interface IncidentsSummary {
  active: number;
  contained: number;
  resolved_today: number;
  defcon_level: number;
}

interface TicketsSummary {
  open: number;
  sla_compliant: number;
  sla_breached: number;
  avg_resolution: number;
}

interface SelfHealingSummary {
  total_today: number;
  auto_resolved: number;
  escalated: number;
  success_rate: number;
}

interface PatchesSummary {
  pending: number;
  installed_today: number;
  failed: number;
}

interface NetworkSummary {
  total_devices: number;
  devices_by_type: Record<string, number>;
  devices_by_status: Record<string, number>;
}

interface SystemHealth {
  api_latency_ms: number;
  uptime_seconds: number;
  last_backup: string;
}

interface NOCData {
  timestamp: string;
  endpoints_summary: EndpointsSummary;
  alerts_summary: AlertsSummary;
  incidents_summary: IncidentsSummary;
  tickets_summary: TicketsSummary;
  self_healing_summary: SelfHealingSummary;
  patches_summary: PatchesSummary;
  network_summary: NetworkSummary;
  system_health: SystemHealth;
}

interface NOCDashboardProps {
  refreshInterval?: number;
  rotationInterval?: number;
  panels?: string[];
}

// ── Panel Definitions ──────────────────────────────────────────────────

const ALL_PANELS = [
  'overview',
  'endpoint_health',
  'active_alerts',
  'incident_timeline',
  'sla_status',
  'network_map',
  'patch_status',
  'self_healing_activity',
] as const;

const PANEL_LABELS: Record<string, string> = {
  overview: 'System Overview',
  endpoint_health: 'Endpoint Health',
  active_alerts: 'Active Alerts',
  incident_timeline: 'Incident Timeline',
  sla_status: 'SLA Status',
  network_map: 'Network Map',
  patch_status: 'Patch Status',
  self_healing_activity: 'Self-Healing Activity',
};

// ── Helper Components ──────────────────────────────────────────────────

const StatusDot: React.FC<{ color: string }> = ({ color }) => (
  <span className={`inline-block w-3 h-3 rounded-full ${color} shadow-lg`} />
);

const MetricCard: React.FC<{
  label: string;
  value: number | string;
  icon: React.ReactNode;
  color?: string;
}> = ({ label, value, icon, color = 'text-cyan-400' }) => (
  <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 flex flex-col items-center justify-center">
    <div className={`${color} mb-2`}>{icon}</div>
    <div className={`text-4xl font-bold ${color}`}>{value}</div>
    <div className="text-gray-400 text-sm mt-1 uppercase tracking-wider">{label}</div>
  </div>
);

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const colors: Record<string, string> = {
    critical: 'bg-red-600 text-white animate-pulse',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-blue-500 text-white',
    info: 'bg-gray-500 text-white',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${colors[severity] || colors.info}`}>
      {severity}
    </span>
  );
};

const ProgressBar: React.FC<{ value: number; max: number; color: string }> = ({ value, max, color }) => {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div className="w-full bg-gray-700 rounded-full h-3">
      <div className={`${color} h-3 rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
    </div>
  );
};

const DefconIndicator: React.FC<{ level: number }> = ({ level }) => {
  const colors: Record<number, string> = {
    1: 'bg-red-600 text-white animate-pulse',
    2: 'bg-orange-500 text-white',
    3: 'bg-yellow-500 text-black',
    4: 'bg-blue-500 text-white',
    5: 'bg-green-500 text-white',
  };
  return (
    <div className={`${colors[level] || colors[5]} rounded-lg px-6 py-4 text-center`}>
      <div className="text-lg font-bold uppercase tracking-widest">DEFCON {level}</div>
    </div>
  );
};

// ── Main Component ─────────────────────────────────────────────────────

const NOCDashboard: React.FC<NOCDashboardProps> = ({
  refreshInterval = 30,
  rotationInterval = 15,
  panels: enabledPanels,
}) => {
  const [data, setData] = useState<NOCData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPanel, setCurrentPanel] = useState(0);
  const [paused, setPaused] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [connected, setConnected] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());

  const containerRef = useRef<HTMLDivElement>(null);
  const panels = enabledPanels || [...ALL_PANELS];

  // ── Data Fetching ────────────────────────────────────────────────

  const fetchData = useCallback(async () => {
    try {
      const res = await api.get('/api/noc/dashboard');
      setData(res.data);
      setLastRefresh(new Date());
      setConnected(true);
      setError(null);
    } catch (err: any) {
      setConnected(false);
      setError(err?.message || 'Connection lost');
    } finally {
      setLoading(false);
    }
  }, []);

  // ── Effects ──────────────────────────────────────────────────────

  // Initial fetch + refresh interval
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, refreshInterval * 1000);
    return () => clearInterval(interval);
  }, [fetchData, refreshInterval]);

  // Panel rotation
  useEffect(() => {
    if (paused) return;
    const interval = setInterval(() => {
      setCurrentPanel((prev) => (prev + 1) % panels.length);
    }, rotationInterval * 1000);
    return () => clearInterval(interval);
  }, [paused, rotationInterval, panels.length]);

  // Clock
  useEffect(() => {
    const interval = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  // Keyboard controls
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      switch (e.key) {
        case ' ':
          e.preventDefault();
          setPaused((p) => !p);
          break;
        case 'ArrowLeft':
          setCurrentPanel((p) => (p - 1 + panels.length) % panels.length);
          break;
        case 'ArrowRight':
          setCurrentPanel((p) => (p + 1) % panels.length);
          break;
        case 'f':
        case 'F':
          toggleFullscreen();
          break;
        case 'r':
        case 'R':
          fetchData();
          break;
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [panels.length, fetchData]);

  // Fullscreen change listener
  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  // ── Fullscreen Toggle ────────────────────────────────────────────

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      containerRef.current?.requestFullscreen?.();
    } else {
      document.exitFullscreen?.();
    }
  };

  // ── Panel Renderers ──────────────────────────────────────────────

  const renderOverview = () => {
    if (!data) return null;
    const { endpoints_summary: ep, alerts_summary: al, incidents_summary: inc, tickets_summary: tk } = data;
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 p-6">
        <MetricCard label="Total Endpoints" value={ep.total} icon={<Server size={32} />} color="text-cyan-400" />
        <MetricCard label="Online" value={ep.online} icon={<Wifi size={32} />} color="text-green-400" />
        <MetricCard label="Offline" value={ep.offline} icon={<WifiOff size={32} />} color="text-red-400" />
        <MetricCard label="Warning" value={ep.warning} icon={<AlertTriangle size={32} />} color="text-yellow-400" />
        <MetricCard label="Active Incidents" value={inc.active} icon={<Shield size={32} />} color="text-red-400" />
        <MetricCard label="Open Tickets" value={tk.open} icon={<Activity size={32} />} color="text-blue-400" />
        <MetricCard label="Critical Alerts" value={al.critical} icon={<AlertCircle size={32} />} color="text-red-500" />
        <div className="flex items-center justify-center">
          <DefconIndicator level={inc.defcon_level} />
        </div>
      </div>
    );
  };

  const renderEndpointHealth = () => {
    if (!data) return null;
    const { endpoints_summary: ep } = data;
    const statuses = [
      { label: 'Online', count: ep.online, color: 'bg-green-500', total: ep.total },
      { label: 'Offline', count: ep.offline, color: 'bg-red-500', total: ep.total },
      { label: 'Warning', count: ep.warning, color: 'bg-yellow-500', total: ep.total },
      { label: 'Maintenance', count: ep.maintenance, color: 'bg-blue-500', total: ep.total },
    ];
    return (
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-4 gap-4">
          {statuses.map((s) => (
            <div key={s.label} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <StatusDot color={s.color} />
                <span className="text-gray-300 uppercase text-sm tracking-wider">{s.label}</span>
              </div>
              <div className="text-3xl font-bold text-white mb-2">{s.count}</div>
              <ProgressBar value={s.count} max={s.total || 1} color={s.color} />
              <div className="text-gray-500 text-xs mt-1">
                {s.total > 0 ? ((s.count / s.total) * 100).toFixed(1) : 0}% of fleet
              </div>
            </div>
          ))}
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-gray-300 text-sm uppercase tracking-wider mb-3">Fleet Health Score</h3>
          <div className="flex items-center gap-4">
            <div className="text-5xl font-bold text-green-400">
              {ep.total > 0 ? ((ep.online / ep.total) * 100).toFixed(0) : 100}%
            </div>
            <ProgressBar value={ep.online} max={ep.total || 1} color="bg-green-500" />
          </div>
        </div>
      </div>
    );
  };

  const renderActiveAlerts = () => {
    if (!data) return null;
    const { alerts_summary: al } = data;
    return (
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-4 gap-4 mb-6">
          <MetricCard label="Critical" value={al.critical} icon={<AlertCircle size={24} />} color="text-red-500" />
          <MetricCard label="High" value={al.high} icon={<AlertTriangle size={24} />} color="text-orange-400" />
          <MetricCard label="Medium" value={al.medium} icon={<Bell size={24} />} color="text-yellow-400" />
          <MetricCard label="Low" value={al.low} icon={<Activity size={24} />} color="text-blue-400" />
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="max-h-[50vh] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-900 sticky top-0">
                <tr>
                  <th className="text-left p-3 text-gray-400">Severity</th>
                  <th className="text-left p-3 text-gray-400">Alert</th>
                  <th className="text-left p-3 text-gray-400">Endpoint</th>
                  <th className="text-left p-3 text-gray-400">Time</th>
                  <th className="text-left p-3 text-gray-400">Status</th>
                </tr>
              </thead>
              <tbody>
                {al.recent_alerts.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="p-6 text-center text-gray-500">No active alerts</td>
                  </tr>
                ) : (
                  al.recent_alerts.map((alert) => (
                    <tr key={alert.id} className="border-t border-gray-700 hover:bg-gray-750">
                      <td className="p-3"><SeverityBadge severity={alert.severity} /></td>
                      <td className="p-3 text-white">{alert.title}</td>
                      <td className="p-3 text-gray-300 font-mono text-xs">{alert.endpoint}</td>
                      <td className="p-3 text-gray-400 text-xs">{new Date(alert.created_at).toLocaleTimeString()}</td>
                      <td className="p-3">
                        {alert.acknowledged ? (
                          <span className="text-green-400 text-xs">ACK</span>
                        ) : (
                          <span className="text-red-400 text-xs animate-pulse">NEW</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  const renderIncidentTimeline = () => {
    if (!data) return null;
    const { incidents_summary: inc } = data;
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <DefconIndicator level={inc.defcon_level} />
          <div className="grid grid-cols-3 gap-4 flex-1 ml-6">
            <MetricCard label="Active" value={inc.active} icon={<Shield size={24} />} color="text-red-400" />
            <MetricCard label="Contained" value={inc.contained} icon={<CheckCircle size={24} />} color="text-yellow-400" />
            <MetricCard label="Resolved Today" value={inc.resolved_today} icon={<CheckCircle size={24} />} color="text-green-400" />
          </div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h3 className="text-gray-300 text-sm uppercase tracking-wider mb-4">Cyber-911 Status</h3>
          <div className="flex items-center gap-4">
            <div className={`text-2xl font-bold ${inc.active > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {inc.active > 0 ? 'INCIDENTS ACTIVE' : 'ALL CLEAR'}
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderSLAStatus = () => {
    if (!data) return null;
    const { tickets_summary: tk } = data;
    const total = tk.sla_compliant + tk.sla_breached;
    const compliancePct = total > 0 ? ((tk.sla_compliant / total) * 100).toFixed(1) : '100.0';
    return (
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard label="Open Tickets" value={tk.open} icon={<Activity size={24} />} color="text-blue-400" />
          <MetricCard label="SLA Compliant" value={tk.sla_compliant} icon={<CheckCircle size={24} />} color="text-green-400" />
          <MetricCard label="SLA Breached" value={tk.sla_breached} icon={<XCircle size={24} />} color="text-red-400" />
          <MetricCard label="Avg Resolution" value={`${tk.avg_resolution}m`} icon={<Clock size={24} />} color="text-cyan-400" />
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h3 className="text-gray-300 text-sm uppercase tracking-wider mb-4">SLA Compliance Rate</h3>
          <div className="flex items-center gap-6">
            <div className={`text-6xl font-bold ${Number(compliancePct) >= 95 ? 'text-green-400' : Number(compliancePct) >= 80 ? 'text-yellow-400' : 'text-red-400'}`}>
              {compliancePct}%
            </div>
            <div className="flex-1">
              <ProgressBar value={tk.sla_compliant} max={total || 1} color={Number(compliancePct) >= 95 ? 'bg-green-500' : Number(compliancePct) >= 80 ? 'bg-yellow-500' : 'bg-red-500'} />
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderNetworkMap = () => {
    if (!data) return null;
    const { network_summary: net } = data;
    return (
      <div className="p-6 space-y-6">
        <MetricCard label="Total Devices" value={net.total_devices} icon={<Network size={32} />} color="text-cyan-400" />
        <div className="grid grid-cols-2 gap-6">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <h3 className="text-gray-300 text-sm uppercase tracking-wider mb-4">Devices by Type</h3>
            {Object.keys(net.devices_by_type).length === 0 ? (
              <div className="text-gray-500 text-center py-4">No devices discovered</div>
            ) : (
              <div className="space-y-3">
                {Object.entries(net.devices_by_type).map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between">
                    <span className="text-gray-300 capitalize">{type}</span>
                    <span className="text-cyan-400 font-bold text-lg">{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <h3 className="text-gray-300 text-sm uppercase tracking-wider mb-4">Devices by Status</h3>
            {Object.keys(net.devices_by_status).length === 0 ? (
              <div className="text-gray-500 text-center py-4">No status data</div>
            ) : (
              <div className="space-y-3">
                {Object.entries(net.devices_by_status).map(([status, count]) => (
                  <div key={status} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <StatusDot color={status === 'online' ? 'bg-green-500' : status === 'offline' ? 'bg-red-500' : 'bg-yellow-500'} />
                      <span className="text-gray-300 capitalize">{status}</span>
                    </div>
                    <span className="text-white font-bold text-lg">{count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderPatchStatus = () => {
    if (!data) return null;
    const { patches_summary: p } = data;
    const total = p.pending + p.installed_today + p.failed;
    return (
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-3 gap-6">
          <MetricCard label="Pending" value={p.pending} icon={<Clock size={28} />} color="text-yellow-400" />
          <MetricCard label="Installed Today" value={p.installed_today} icon={<CheckCircle size={28} />} color="text-green-400" />
          <MetricCard label="Failed" value={p.failed} icon={<XCircle size={28} />} color="text-red-400" />
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h3 className="text-gray-300 text-sm uppercase tracking-wider mb-4">Patch Compliance</h3>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <div className="text-gray-500 text-xs mb-1">Pending</div>
              <ProgressBar value={p.pending} max={total || 1} color="bg-yellow-500" />
            </div>
            <div>
              <div className="text-gray-500 text-xs mb-1">Installed</div>
              <ProgressBar value={p.installed_today} max={total || 1} color="bg-green-500" />
            </div>
            <div>
              <div className="text-gray-500 text-xs mb-1">Failed</div>
              <ProgressBar value={p.failed} max={total || 1} color="bg-red-500" />
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderSelfHealing = () => {
    if (!data) return null;
    const { self_healing_summary: sh } = data;
    return (
      <div className="p-6 space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard label="Total Today" value={sh.total_today} icon={<Zap size={24} />} color="text-cyan-400" />
          <MetricCard label="Auto-Resolved" value={sh.auto_resolved} icon={<CheckCircle size={24} />} color="text-green-400" />
          <MetricCard label="Escalated" value={sh.escalated} icon={<TrendingUp size={24} />} color="text-orange-400" />
          <MetricCard label="Success Rate" value={`${sh.success_rate.toFixed(1)}%`} icon={<Activity size={24} />}
            color={sh.success_rate >= 90 ? 'text-green-400' : sh.success_rate >= 70 ? 'text-yellow-400' : 'text-red-400'} />
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h3 className="text-gray-300 text-sm uppercase tracking-wider mb-4">Auto-Remediation Effectiveness</h3>
          <div className="flex items-center gap-6">
            <div className={`text-6xl font-bold ${sh.success_rate >= 90 ? 'text-green-400' : sh.success_rate >= 70 ? 'text-yellow-400' : 'text-red-400'}`}>
              {sh.success_rate.toFixed(0)}%
            </div>
            <div className="flex-1">
              <ProgressBar value={sh.success_rate} max={100} color={sh.success_rate >= 90 ? 'bg-green-500' : sh.success_rate >= 70 ? 'bg-yellow-500' : 'bg-red-500'} />
            </div>
          </div>
        </div>
      </div>
    );
  };

  // ── Panel Router ─────────────────────────────────────────────────

  const renderPanel = (panelName: string) => {
    switch (panelName) {
      case 'overview': return renderOverview();
      case 'endpoint_health': return renderEndpointHealth();
      case 'active_alerts': return renderActiveAlerts();
      case 'incident_timeline': return renderIncidentTimeline();
      case 'sla_status': return renderSLAStatus();
      case 'network_map': return renderNetworkMap();
      case 'patch_status': return renderPatchStatus();
      case 'self_healing_activity': return renderSelfHealing();
      default: return <div className="p-6 text-gray-500">Unknown panel: {panelName}</div>;
    }
  };

  // ── Main Render ──────────────────────────────────────────────────

  if (loading && !data) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <Monitor className="w-16 h-16 text-cyan-400 mx-auto mb-4 animate-pulse" />
          <div className="text-gray-400 text-lg">Initializing NOC Dashboard...</div>
        </div>
      </div>
    );
  }

  const activePanelName = panels[currentPanel] || 'overview';

  return (
    <div ref={containerRef} className="min-h-screen bg-gray-900 text-white flex flex-col">
      {/* ── Header ────────────────────────────────────────────────── */}
      <header className="bg-gray-950 border-b border-gray-800 px-6 py-3 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-4">
          <Monitor className="w-6 h-6 text-cyan-400" />
          <h1 className="text-lg font-bold tracking-wider uppercase text-cyan-400">
            Aither NOC
          </h1>
          <span className="text-gray-600 text-sm">|</span>
          <span className="text-gray-400 text-sm font-medium">
            {PANEL_LABELS[activePanelName] || activePanelName}
          </span>
        </div>

        <div className="flex items-center gap-6">
          {/* Panel indicator dots */}
          <div className="flex items-center gap-1">
            {panels.map((_, idx) => (
              <button
                key={idx}
                onClick={() => setCurrentPanel(idx)}
                className={`w-2 h-2 rounded-full transition-all ${
                  idx === currentPanel ? 'bg-cyan-400 w-4' : 'bg-gray-600 hover:bg-gray-500'
                }`}
              />
            ))}
          </div>

          {/* Controls */}
          <div className="flex items-center gap-2">
            <button onClick={() => setCurrentPanel((p) => (p - 1 + panels.length) % panels.length)}
              className="p-1 text-gray-500 hover:text-gray-300" title="Previous (Left Arrow)">
              <ChevronLeft size={18} />
            </button>
            <button onClick={() => setPaused((p) => !p)}
              className={`p-1 ${paused ? 'text-yellow-400' : 'text-gray-500 hover:text-gray-300'}`} title="Pause/Resume (Space)">
              {paused ? <Play size={18} /> : <Pause size={18} />}
            </button>
            <button onClick={() => setCurrentPanel((p) => (p + 1) % panels.length)}
              className="p-1 text-gray-500 hover:text-gray-300" title="Next (Right Arrow)">
              <ChevronRight size={18} />
            </button>
            <button onClick={fetchData}
              className="p-1 text-gray-500 hover:text-gray-300" title="Refresh (R)">
              <RefreshCw size={18} />
            </button>
            <button onClick={toggleFullscreen}
              className="p-1 text-gray-500 hover:text-gray-300" title="Fullscreen (F)">
              {isFullscreen ? <Minimize size={18} /> : <Maximize size={18} />}
            </button>
          </div>

          {/* Clock */}
          <div className="flex items-center gap-2 text-gray-400 font-mono text-sm">
            <Clock size={14} />
            {currentTime.toLocaleTimeString()}
          </div>
        </div>
      </header>

      {/* ── Panel Content ─────────────────────────────────────────── */}
      <main className="flex-1 overflow-auto">
        {error && (
          <div className="bg-red-900/50 border border-red-700 text-red-300 px-4 py-2 text-sm flex items-center gap-2">
            <AlertTriangle size={16} />
            {error}
          </div>
        )}
        {renderPanel(activePanelName)}
      </main>

      {/* ── Status Bar ────────────────────────────────────────────── */}
      <footer className="bg-gray-950 border-t border-gray-800 px-6 py-2 flex items-center justify-between text-xs text-gray-500 shrink-0">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1">
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500 animate-pulse'}`} />
            {connected ? 'Connected' : 'Disconnected'}
          </div>
          <span>Refresh: {refreshInterval}s</span>
          <span>Rotation: {rotationInterval}s{paused ? ' (PAUSED)' : ''}</span>
        </div>
        <div className="flex items-center gap-4">
          <span>Panel {currentPanel + 1}/{panels.length}</span>
          {lastRefresh && <span>Last refresh: {lastRefresh.toLocaleTimeString()}</span>}
          <span className="text-gray-600">Space:Pause | Arrows:Navigate | F:Fullscreen | R:Refresh</span>
        </div>
      </footer>
    </div>
  );
};

export default NOCDashboard;
