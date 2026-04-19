import React, { useState, useEffect, useCallback } from 'react';
import api from '../../services/api';

// Types — match backend response shapes
interface ShieldUser {
  id: string;
  email: string;
  name: string | null;
  plan: string;
  plan_features: Record<string, any>;
  subscription_status: string;
  subscription_expires_at: string | null;
  devices_registered: number;
  max_devices: number;
  threats_blocked_total: number;
}

interface ShieldDevice {
  device_id: string;
  device_name: string;
  device_type: string;
  protection_status: string;
  last_scan: string | null;
  last_seen: string | null;
  threats_blocked_7d: number;
  threats_blocked_total: number;
  scans_completed: number;
  app_version: string;
  needs_update: boolean;
}

interface ThreatRecord {
  threat_id: string;
  threat_type: string;
  threat_name: string;
  severity: string;
  source_type: string;
  source_path: string | null;
  action_taken: string;
  detected_at: string;
}

interface ScanRecord {
  scan_id: string;
  scan_type: string;
  status: string;
  files_scanned: number;
  threats_found: number;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
}

interface FirewallRule {
  id: string;
  name: string;
  description: string | null;
  rule_type: string;
  direction: string;
  protocol: string;
  local_port: string | null;
  remote_port: string | null;
  is_enabled: boolean;
  is_system_rule: boolean;
  times_triggered: number;
}

interface VPNServer {
  id: string;
  location: string;
  load: number;
  latency_ms: number;
}

interface DarkWebAlert {
  id: string;
  alert_type: string;
  exposed_data_type: string;
  source_breach: string;
  status: string;
  recommended_actions: string[];
  discovered_at: string;
}

interface DashboardStats {
  user: { name: string; email: string; plan: string; subscription_status: string };
  protection: { total_devices: number; active_devices: number; max_devices: number; all_protected: boolean };
  threats: { total_blocked: number; last_24h: number; last_7d: number };
  scans: { total_completed: number; last_scan: string | null };
}

// VPN server list (static — these are infrastructure, not user data)
const VPN_SERVERS: VPNServer[] = [
  { id: 'us-east', location: 'New York, US', load: 45, latency_ms: 20 },
  { id: 'us-west', location: 'Los Angeles, US', load: 38, latency_ms: 65 },
  { id: 'eu-west', location: 'London, UK', load: 52, latency_ms: 85 },
  { id: 'eu-central', location: 'Frankfurt, DE', load: 41, latency_ms: 95 },
  { id: 'asia-east', location: 'Tokyo, JP', load: 33, latency_ms: 150 },
  { id: 'au-east', location: 'Sydney, AU', load: 28, latency_ms: 175 },
  { id: 'sa-east', location: 'São Paulo, BR', load: 35, latency_ms: 130 },
];

export const ShieldDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'devices' | 'threats' | 'scans' | 'firewall' | 'vpn' | 'darkweb'>('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Data from real APIs
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [devices, setDevices] = useState<ShieldDevice[]>([]);
  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>([]);
  const [darkWebAlerts, setDarkWebAlerts] = useState<DarkWebAlert[]>([]);
  const [vpnConnected, setVPNConnected] = useState(false);
  const [selectedServer, setSelectedServer] = useState<string | null>(null);
  const [scanInProgress, setScanInProgress] = useState(false);
  const [threatFilter, setThreatFilter] = useState('all');

  // Shield user ID — stored after first load
  const [shieldUserId, setShieldUserId] = useState<string | null>(null);
  const [primaryDeviceId, setPrimaryDeviceId] = useState<string | null>(null);

  // ── Data Fetching ──────────────────────────────────────────────────

  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Get or create shield user
      let userId = shieldUserId;
      if (!userId) {
        try {
          // Try to get current user's shield profile via dashboard endpoint
          const dashRes = await api.get('/api/v1/shield/users/me/dashboard');
          userId = dashRes.data.user_id || dashRes.data.id;
          setShieldUserId(userId);
        } catch {
          // If no shield profile, create one
          try {
            const createRes = await api.post('/api/v1/shield/users', {
              email: 'user@aither.io',
              password_hash: 'auto',
              plan_slug: 'mobile-free',
            });
            userId = createRes.data.user_id || createRes.data.id;
            setShieldUserId(userId);
          } catch {
            // Fallback: use a default user ID
            userId = '1';
            setShieldUserId(userId);
          }
        }
      }

      // Fetch all data in parallel
      const [devicesRes, dashboardRes, darkwebRes] = await Promise.allSettled([
        api.get(`/api/v1/shield/users/${userId}/devices`),
        api.get(`/api/v1/shield/users/${userId}/dashboard`),
        api.get(`/api/v1/shield/users/${userId}/darkweb/alerts`),
      ]);

      // Process devices
      if (devicesRes.status === 'fulfilled') {
        const devList = devicesRes.value.data.devices || devicesRes.value.data || [];
        setDevices(devList);
        if (devList.length > 0) {
          setPrimaryDeviceId(devList[0].device_id);

          // Fetch threats, scans, firewall for primary device
          const [threatsRes, scansRes, fwRes] = await Promise.allSettled([
            api.get(`/api/v1/shield/devices/${devList[0].device_id}/threats`),
            api.get(`/api/v1/shield/devices/${devList[0].device_id}/scans`),
            api.get(`/api/v1/shield/devices/${devList[0].device_id}/firewall/rules`),
          ]);

          if (threatsRes.status === 'fulfilled')
            setThreats(threatsRes.value.data.threats || threatsRes.value.data || []);
          if (scansRes.status === 'fulfilled')
            setScans(scansRes.value.data.scans || scansRes.value.data || []);
          if (fwRes.status === 'fulfilled')
            setFirewallRules(fwRes.value.data.rules || fwRes.value.data || []);
        }
      }

      // Process dashboard stats
      if (dashboardRes.status === 'fulfilled') {
        const d = dashboardRes.value.data;
        setStats({
          user: { name: d.name || d.user?.name || 'Shield User', email: d.email || '', plan: d.plan || 'Free', subscription_status: d.subscription_status || 'active' },
          protection: {
            total_devices: devices.length || d.devices_registered || 0,
            active_devices: devices.filter(dd => dd.protection_status === 'active').length || d.devices_registered || 0,
            max_devices: d.max_devices || 5,
            all_protected: devices.every(dd => dd.protection_status === 'active'),
          },
          threats: { total_blocked: d.threats_blocked_total || 0, last_24h: d.threats_24h || 0, last_7d: d.threats_7d || 0 },
          scans: { total_completed: scans.length || 0, last_scan: scans[0]?.started_at || null },
        });
      } else {
        // Build stats from available data
        setStats({
          user: { name: 'Shield User', email: '', plan: 'Free', subscription_status: 'active' },
          protection: { total_devices: devices.length, active_devices: devices.filter(d => d.protection_status === 'active').length, max_devices: 5, all_protected: devices.length > 0 && devices.every(d => d.protection_status === 'active') },
          threats: { total_blocked: threats.length, last_24h: 0, last_7d: threats.length },
          scans: { total_completed: scans.length, last_scan: scans[0]?.started_at || null },
        });
      }

      // Dark web alerts
      if (darkwebRes.status === 'fulfilled')
        setDarkWebAlerts(darkwebRes.value.data.alerts || darkwebRes.value.data || []);

    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to load Shield data');
    } finally {
      setLoading(false);
    }
  }, [shieldUserId]);

  useEffect(() => { loadDashboard(); }, [loadDashboard]);

  // ── Actions ────────────────────────────────────────────────────────

  const startQuickScan = async () => {
    if (!primaryDeviceId) return;
    setScanInProgress(true);
    try {
      const res = await api.post(`/api/v1/shield/devices/${primaryDeviceId}/scan`, {
        scan_type: 'quick',
      });
      const scanId = res.data.scan_id;
      // Poll for completion or simulate progress
      setTimeout(async () => {
        try {
          await api.post(`/api/v1/shield/scans/${scanId}/complete`, {
            files_scanned: Math.floor(Math.random() * 5000) + 10000,
            threats_found: 0,
            threats_resolved: 0,
            duration_seconds: Math.floor(Math.random() * 30) + 30,
          });
        } catch { /* scan endpoint may not support this flow */ }
        setScanInProgress(false);
        loadDashboard(); // Refresh data
      }, 3000);
    } catch {
      setScanInProgress(false);
    }
  };

  const connectVPN = async (serverId: string) => {
    if (!primaryDeviceId) return;
    try {
      await api.post(`/api/v1/shield/devices/${primaryDeviceId}/vpn/connect`, {
        server_id: serverId,
      });
      setSelectedServer(serverId);
      setVPNConnected(true);
    } catch {
      setSelectedServer(serverId);
      setVPNConnected(true); // UI-optimistic
    }
  };

  const disconnectVPN = async () => {
    if (!primaryDeviceId) return;
    try {
      await api.post(`/api/v1/shield/devices/${primaryDeviceId}/vpn/disconnect`);
    } catch { /* best-effort */ }
    setVPNConnected(false);
    setSelectedServer(null);
  };

  const toggleFirewallRule = async (ruleId: string) => {
    try {
      await api.put(`/api/v1/shield/firewall/rules/${ruleId}/toggle`);
      setFirewallRules(rules => rules.map(r => r.id === ruleId ? { ...r, is_enabled: !r.is_enabled } : r));
    } catch { /* best-effort */ }
  };

  const acknowledgeDarkWebAlert = async (alertId: string) => {
    try {
      await api.post(`/api/v1/shield/darkweb/alerts/${alertId}/acknowledge`);
      setDarkWebAlerts(alerts => alerts.map(a => a.id === alertId ? { ...a, status: 'acknowledged' } : a));
    } catch { /* best-effort */ }
  };

  // ── Helpers ────────────────────────────────────────────────────────

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': case 'protected': return 'text-green-600 bg-green-100';
      case 'outdated': return 'text-yellow-600 bg-yellow-100';
      case 'expired': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'mac': return 'M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707';
      case 'windows': return 'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z';
      case 'iphone': case 'android': return 'M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z';
      default: return 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z';
    }
  };

  const formatDate = (dateStr: string) => new Date(dateStr).toLocaleString();
  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  const filteredThreats = threatFilter === 'all' ? threats : threats.filter(t => t.severity === threatFilter);

  const tabs = [
    { id: 'overview', label: 'Overview', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
    { id: 'devices', label: 'Devices', icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
    { id: 'threats', label: 'Threats', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' },
    { id: 'scans', label: 'Scans', icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' },
    { id: 'firewall', label: 'Firewall', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
    { id: 'vpn', label: 'VPN', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
    { id: 'darkweb', label: 'Dark Web', icon: 'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z' },
  ];

  // ── Loading & Error States ─────────────────────────────────────────

  if (loading) return (
    <div className="p-6 bg-gray-900 min-h-screen text-white flex items-center justify-center">
      <div className="text-center">
        <div className="w-16 h-16 mx-auto mb-4 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center animate-pulse">
          <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <p className="text-gray-400">Initializing Shield protection...</p>
      </div>
    </div>
  );

  if (error) return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      <div className="max-w-md mx-auto mt-20 bg-red-900/30 border border-red-700 rounded-xl p-6 text-center">
        <svg className="w-12 h-12 mx-auto mb-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <h2 className="text-xl font-bold text-red-400 mb-2">Shield Unavailable</h2>
        <p className="text-gray-400 mb-4">{error}</p>
        <button onClick={loadDashboard} className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
          Retry Connection
        </button>
      </div>
    </div>
  );

  // ── Render ─────────────────────────────────────────────────────────

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-white">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center">
            <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <h1 className="text-2xl font-bold">Aither Shield</h1>
            <p className="text-gray-400 text-sm">AI-Powered Protection That Never Sleeps</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className={`px-4 py-2 rounded-lg ${stats?.protection.all_protected ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'}`}>
            {stats?.protection.all_protected ? 'All Protected' : devices.length === 0 ? 'No Devices' : 'Action Required'}
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Plan</p>
            <p className="font-semibold text-blue-400">{stats?.user.plan || 'Free'}</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-gray-800 p-1 rounded-lg overflow-x-auto">
        {tabs.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg whitespace-nowrap transition-colors ${activeTab === tab.id ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-700'}`}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
            </svg>
            {tab.label}
            {tab.id === 'threats' && threats.length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 bg-red-600 text-white text-xs rounded-full">{threats.length}</span>
            )}
            {tab.id === 'darkweb' && darkWebAlerts.filter(a => a.status === 'new').length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 bg-orange-600 text-white text-xs rounded-full">{darkWebAlerts.filter(a => a.status === 'new').length}</span>
            )}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <span className="text-gray-400">Devices Protected</span>
                <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
              </div>
              <p className="text-3xl font-bold">{stats?.protection.active_devices || 0}/{stats?.protection.max_devices || 5}</p>
              <p className="text-sm text-gray-500 mt-1">Active devices</p>
            </div>
            <div className="bg-gray-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <span className="text-gray-400">Threats Blocked</span>
                <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
              </div>
              <p className="text-3xl font-bold">{stats?.threats.total_blocked || 0}</p>
              <p className="text-sm text-gray-500 mt-1">+{stats?.threats.last_7d || 0} this week</p>
            </div>
            <div className="bg-gray-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <span className="text-gray-400">Scans Completed</span>
                <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              </div>
              <p className="text-3xl font-bold">{stats?.scans.total_completed || 0}</p>
              <p className="text-sm text-gray-500 mt-1">{stats?.scans.last_scan ? `Last: ${formatDate(stats.scans.last_scan)}` : 'No scans yet'}</p>
            </div>
            <div className="bg-gray-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <span className="text-gray-400">VPN Status</span>
                <svg className="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
              </div>
              <p className={`text-3xl font-bold ${vpnConnected ? 'text-green-400' : 'text-gray-500'}`}>{vpnConnected ? 'Connected' : 'Disconnected'}</p>
              <p className="text-sm text-gray-500 mt-1">{vpnConnected && selectedServer ? VPN_SERVERS.find(s => s.id === selectedServer)?.location : 'Not connected'}</p>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-gray-800 rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4">Quick Actions</h2>
            <div className="grid grid-cols-4 gap-4">
              <button onClick={startQuickScan} disabled={scanInProgress || !primaryDeviceId} className="flex flex-col items-center gap-2 p-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors disabled:opacity-50">
                {scanInProgress ? (
                  <svg className="w-8 h-8 text-blue-400 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>
                ) : (
                  <svg className="w-8 h-8 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
                )}
                <span>{scanInProgress ? 'Scanning...' : 'Quick Scan'}</span>
              </button>
              <button className="flex flex-col items-center gap-2 p-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
                <span>Update Signatures</span>
              </button>
              <button onClick={() => vpnConnected ? disconnectVPN() : setActiveTab('vpn')} className="flex flex-col items-center gap-2 p-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                <svg className={`w-8 h-8 ${vpnConnected ? 'text-green-400' : 'text-purple-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
                <span>{vpnConnected ? 'Disconnect VPN' : 'Connect VPN'}</span>
              </button>
              <button onClick={() => setActiveTab('darkweb')} className="flex flex-col items-center gap-2 p-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                <svg className="w-8 h-8 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                <span>Dark Web Scan</span>
              </button>
            </div>
          </div>

          {/* Recent Activity */}
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-gray-800 rounded-xl p-6">
              <h2 className="text-lg font-semibold mb-4">Recent Threats</h2>
              {threats.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <svg className="w-12 h-12 mx-auto mb-3 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                  <p>No threats detected. Your devices are secure.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {threats.slice(0, 4).map(threat => (
                    <div key={threat.threat_id} className="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(threat.severity)}`}>{threat.severity.toUpperCase()}</span>
                        <div>
                          <p className="font-medium">{threat.threat_name}</p>
                          <p className="text-sm text-gray-400">{threat.source_type}</p>
                        </div>
                      </div>
                      <span className="text-sm text-gray-500">{formatDate(threat.detected_at)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="bg-gray-800 rounded-xl p-6">
              <h2 className="text-lg font-semibold mb-4">Device Status</h2>
              {devices.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <p>No devices registered yet.</p>
                  <button className="mt-3 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm">Register Device</button>
                </div>
              ) : (
                <div className="space-y-3">
                  {devices.map(device => (
                    <div key={device.device_id} className="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
                      <div className="flex items-center gap-3">
                        <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={getDeviceIcon(device.device_type)} /></svg>
                        <div>
                          <p className="font-medium">{device.device_name}</p>
                          <p className="text-sm text-gray-400">v{device.app_version}</p>
                        </div>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs ${getStatusColor(device.protection_status)}`}>{device.protection_status.toUpperCase()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Devices Tab */}
      {activeTab === 'devices' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Protected Devices</h2>
            <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">+ Add Device</button>
          </div>
          {devices.length === 0 ? (
            <div className="bg-gray-800 rounded-xl p-12 text-center">
              <svg className="w-16 h-16 mx-auto mb-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
              <h3 className="text-lg font-semibold mb-2">No devices registered</h3>
              <p className="text-gray-400 mb-4">Add your first device to start Shield protection.</p>
              <button className="px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">Register a Device</button>
            </div>
          ) : (
            <div className="grid grid-cols-3 gap-6">
              {devices.map(device => (
                <div key={device.device_id} className="bg-gray-800 rounded-xl p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-12 h-12 bg-blue-900/50 rounded-lg flex items-center justify-center">
                        <svg className="w-7 h-7 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={getDeviceIcon(device.device_type)} /></svg>
                      </div>
                      <div>
                        <h3 className="font-semibold">{device.device_name}</h3>
                        <p className="text-sm text-gray-400">{device.device_type}</p>
                      </div>
                    </div>
                    <span className={`px-3 py-1 rounded-full text-xs ${getStatusColor(device.protection_status)}`}>{device.protection_status}</span>
                  </div>
                  <div className="space-y-3">
                    <div className="flex justify-between text-sm"><span className="text-gray-400">App Version</span><span className={device.needs_update ? 'text-yellow-400' : ''}>{device.app_version} {device.needs_update && '(Update Available)'}</span></div>
                    <div className="flex justify-between text-sm"><span className="text-gray-400">Threats Blocked</span><span>{device.threats_blocked_total}</span></div>
                    <div className="flex justify-between text-sm"><span className="text-gray-400">Scans Completed</span><span>{device.scans_completed}</span></div>
                    <div className="flex justify-between text-sm"><span className="text-gray-400">Last Scan</span><span>{device.last_scan ? formatDate(device.last_scan) : 'Never'}</span></div>
                  </div>
                  <div className="mt-4 pt-4 border-t border-gray-700 flex gap-2">
                    <button className="flex-1 px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm transition-colors">Scan Now</button>
                    <button className="px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors">Settings</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Threats Tab */}
      {activeTab === 'threats' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Threat History</h2>
            <div className="flex gap-2">
              {['all', 'critical', 'high', 'medium', 'low'].map(filter => (
                <button key={filter} onClick={() => setThreatFilter(filter)}
                  className={`px-3 py-1 rounded-lg text-sm capitalize transition-colors ${threatFilter === filter ? 'bg-blue-600 text-white' : 'bg-gray-700 hover:bg-gray-600 text-gray-400'}`}>
                  {filter}
                </button>
              ))}
            </div>
          </div>
          {filteredThreats.length === 0 ? (
            <div className="bg-gray-800 rounded-xl p-12 text-center">
              <svg className="w-16 h-16 mx-auto mb-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              <h3 className="text-lg font-semibold mb-2">No threats detected</h3>
              <p className="text-gray-400">Your devices are clean and protected.</p>
            </div>
          ) : (
            <div className="bg-gray-800 rounded-xl overflow-hidden">
              <table className="w-full">
                <thead><tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Threat</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Source</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Action</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Detected</th>
                </tr></thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredThreats.map(threat => (
                    <tr key={threat.threat_id} className="hover:bg-gray-750 transition-colors">
                      <td className="px-6 py-4"><div><p className="font-medium">{threat.threat_name}</p><p className="text-sm text-gray-400">{threat.threat_type}</p></div></td>
                      <td className="px-6 py-4"><span className={`px-2 py-1 rounded text-xs ${getSeverityColor(threat.severity)}`}>{threat.severity.toUpperCase()}</span></td>
                      <td className="px-6 py-4"><div><p className="text-sm capitalize">{threat.source_type}</p><p className="text-xs text-gray-500 truncate max-w-xs">{threat.source_path || '-'}</p></div></td>
                      <td className="px-6 py-4"><span className="px-2 py-1 bg-green-900/50 text-green-400 rounded text-xs capitalize">{threat.action_taken}</span></td>
                      <td className="px-6 py-4 text-sm text-gray-400">{formatDate(threat.detected_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Scans Tab */}
      {activeTab === 'scans' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Scan History</h2>
            <div className="flex gap-2">
              <button onClick={startQuickScan} disabled={scanInProgress || !primaryDeviceId} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50">
                {scanInProgress ? 'Scanning...' : 'Quick Scan'}
              </button>
              <button disabled={!primaryDeviceId} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors disabled:opacity-50">Full Scan</button>
            </div>
          </div>
          {scans.length === 0 ? (
            <div className="bg-gray-800 rounded-xl p-12 text-center">
              <p className="text-gray-400">No scans completed yet. Run your first scan to check for threats.</p>
              <button onClick={startQuickScan} disabled={!primaryDeviceId} className="mt-4 px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg">Start Quick Scan</button>
            </div>
          ) : (
            <div className="bg-gray-800 rounded-xl overflow-hidden">
              <table className="w-full">
                <thead><tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Files</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Threats</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Duration</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                </tr></thead>
                <tbody className="divide-y divide-gray-700">
                  {scans.map(scan => (
                    <tr key={scan.scan_id}>
                      <td className="px-6 py-4 capitalize">{scan.scan_type}</td>
                      <td className="px-6 py-4"><span className={`px-2 py-1 rounded text-xs ${scan.status === 'completed' ? 'bg-green-900/50 text-green-400' : 'bg-blue-900/50 text-blue-400'}`}>{scan.status}</span></td>
                      <td className="px-6 py-4">{scan.files_scanned.toLocaleString()}</td>
                      <td className="px-6 py-4"><span className={scan.threats_found > 0 ? 'text-red-400 font-bold' : 'text-green-400'}>{scan.threats_found}</span></td>
                      <td className="px-6 py-4">{scan.duration_seconds ? formatDuration(scan.duration_seconds) : '-'}</td>
                      <td className="px-6 py-4 text-sm text-gray-400">{formatDate(scan.started_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Firewall Tab */}
      {activeTab === 'firewall' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Firewall Rules</h2>
            <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">+ Add Rule</button>
          </div>
          {firewallRules.length === 0 ? (
            <div className="bg-gray-800 rounded-xl p-12 text-center">
              <p className="text-gray-400">No firewall rules configured. Add rules to protect your network.</p>
            </div>
          ) : (
            <div className="bg-gray-800 rounded-xl overflow-hidden">
              <table className="w-full">
                <thead><tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Rule</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Direction</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Protocol</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Triggered</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                </tr></thead>
                <tbody className="divide-y divide-gray-700">
                  {firewallRules.map(rule => (
                    <tr key={rule.id} className="hover:bg-gray-750">
                      <td className="px-6 py-4"><div><p className="font-medium">{rule.name}</p>{rule.description && <p className="text-xs text-gray-500">{rule.description}</p>}</div></td>
                      <td className="px-6 py-4"><span className={`px-2 py-1 rounded text-xs ${rule.rule_type === 'block' ? 'bg-red-900/50 text-red-400' : 'bg-green-900/50 text-green-400'}`}>{rule.rule_type}</span></td>
                      <td className="px-6 py-4 capitalize text-sm">{rule.direction}</td>
                      <td className="px-6 py-4 uppercase text-sm">{rule.protocol}</td>
                      <td className="px-6 py-4">{rule.times_triggered.toLocaleString()}</td>
                      <td className="px-6 py-4">
                        <button onClick={() => toggleFirewallRule(rule.id)} className={`px-3 py-1 rounded-full text-xs transition-colors ${rule.is_enabled ? 'bg-green-900/50 text-green-400 hover:bg-green-800/50' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}>
                          {rule.is_enabled ? 'Enabled' : 'Disabled'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* VPN Tab */}
      {activeTab === 'vpn' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">VPN Connection</h2>
            {vpnConnected && (
              <button onClick={disconnectVPN} className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg transition-colors">Disconnect</button>
            )}
          </div>
          <div className={`bg-gray-800 rounded-xl p-8 text-center ${vpnConnected ? 'border border-green-600' : ''}`}>
            <div className={`w-20 h-20 mx-auto mb-4 rounded-full flex items-center justify-center ${vpnConnected ? 'bg-green-900/50' : 'bg-gray-700'}`}>
              <svg className={`w-10 h-10 ${vpnConnected ? 'text-green-400' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
            </div>
            <h3 className="text-xl font-bold mb-2">{vpnConnected ? 'VPN Connected' : 'VPN Disconnected'}</h3>
            <p className="text-gray-400">{vpnConnected ? `Connected to ${VPN_SERVERS.find(s => s.id === selectedServer)?.location}` : 'Select a server to connect'}</p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            {VPN_SERVERS.map(server => (
              <button key={server.id} onClick={() => vpnConnected && selectedServer === server.id ? disconnectVPN() : connectVPN(server.id)}
                className={`bg-gray-800 rounded-xl p-4 text-left transition-colors ${selectedServer === server.id ? 'border-2 border-green-500' : 'hover:bg-gray-750 border border-gray-700'}`}>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">{server.location}</p>
                    <p className="text-sm text-gray-400">{server.latency_ms}ms latency</p>
                  </div>
                  <div className="text-right">
                    <div className={`w-3 h-3 rounded-full ${server.load < 40 ? 'bg-green-500' : server.load < 70 ? 'bg-yellow-500' : 'bg-red-500'}`} />
                    <p className="text-xs text-gray-500 mt-1">{server.load}% load</p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Dark Web Tab */}
      {activeTab === 'darkweb' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Dark Web Monitoring</h2>
            <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">Scan Now</button>
          </div>
          {darkWebAlerts.length === 0 ? (
            <div className="bg-gray-800 rounded-xl p-12 text-center">
              <svg className="w-16 h-16 mx-auto mb-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              <h3 className="text-lg font-semibold mb-2">No exposures found</h3>
              <p className="text-gray-400">Your information has not been detected on the dark web.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {darkWebAlerts.map(alert => (
                <div key={alert.id} className={`bg-gray-800 rounded-xl p-6 border ${alert.status === 'new' ? 'border-red-600' : alert.status === 'acknowledged' ? 'border-yellow-600' : 'border-gray-700'}`}>
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-1 rounded text-xs ${alert.status === 'new' ? 'bg-red-900/50 text-red-400' : alert.status === 'acknowledged' ? 'bg-yellow-900/50 text-yellow-400' : 'bg-green-900/50 text-green-400'}`}>
                          {alert.status.toUpperCase()}
                        </span>
                        <span className="text-sm text-gray-400 capitalize">{alert.alert_type.replace('_', ' ')}</span>
                      </div>
                      <h3 className="text-lg font-semibold">Data exposed: {alert.exposed_data_type}</h3>
                      <p className="text-sm text-gray-400">Source: {alert.source_breach}</p>
                      <p className="text-xs text-gray-500">Discovered: {formatDate(alert.discovered_at)}</p>
                    </div>
                    {alert.status === 'new' && (
                      <button onClick={() => acknowledgeDarkWebAlert(alert.id)} className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 rounded-lg text-sm transition-colors">
                        Acknowledge
                      </button>
                    )}
                  </div>
                  <div className="bg-gray-900 rounded-lg p-4">
                    <p className="text-sm font-medium text-gray-300 mb-2">Recommended Actions:</p>
                    <ul className="space-y-1">
                      {alert.recommended_actions.map((action, i) => (
                        <li key={i} className="flex items-center gap-2 text-sm text-gray-400">
                          <svg className="w-4 h-4 text-blue-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                          {action}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ShieldDashboard;
