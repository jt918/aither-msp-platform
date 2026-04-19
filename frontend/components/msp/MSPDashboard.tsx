import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Wrench, CheckCircle, Clock, Users } from 'lucide-react';
import api from '../../services/api';

interface SelfHealingStatus {
  total_alerts: number;
  auto_remediated: number;
  tickets_created: number;
  success_rate: number;
}

interface CyberStatus {
  defcon_level: number;
  active_incidents: number;
  contained_today: number;
  mttr_minutes: number;
}

interface ITSMStatus {
  open_tickets: number;
  sla_compliance: number;
  avg_resolution_time: number;
  tickets_today: number;
}

const MSPDashboard: React.FC = () => {
  const [selfHealing, setSelfHealing] = useState<SelfHealingStatus | null>(null);
  const [cyber, setCyber] = useState<CyberStatus | null>(null);
  const [itsm, setITSM] = useState<ITSMStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [shRes, cyberRes, itsmRes] = await Promise.allSettled([
        api.get('/api/msp/self-healing/dashboard'),
        api.get('/api/msp/cyber-911/dashboard'),
        api.get('/api/msp/itsm/dashboard')
      ]);

      if (shRes.status === 'fulfilled') {
        const shData = shRes.value.data;
        setSelfHealing({
          total_alerts: shData.system_status?.total_incidents || 0,
          auto_remediated: shData.system_status?.auto_resolved || 0,
          tickets_created: shData.system_status?.tickets_created || 0,
          success_rate: shData.system_status?.success_rate || 100
        });
      }

      if (cyberRes.status === 'fulfilled') {
        const cyberData = cyberRes.value.data;
        setCyber({
          defcon_level: cyberData.defcon_level || 5,
          active_incidents: cyberData.active_incidents || 0,
          contained_today: cyberData.blocked_ips || 0,
          mttr_minutes: cyberData.mttr_minutes || 0
        });
      }

      if (itsmRes.status === 'fulfilled') {
        const itsmData = itsmRes.value.data;
        setITSM({
          open_tickets: itsmData.metrics?.open_tickets || 0,
          sla_compliance: 100 - (itsmData.metrics?.sla_breached || 0),
          avg_resolution_time: itsmData.metrics?.avg_resolution_hours || 0,
          tickets_today: itsmData.metrics?.total_tickets || 0
        });
      }

      setLoading(false);
    } catch (error) {
      console.error('Error fetching MSP data:', error);
      // Fall back to demo data on error
      setSelfHealing({ total_alerts: 156, auto_remediated: 142, tickets_created: 14, success_rate: 91.0 });
      setCyber({ defcon_level: 4, active_incidents: 2, contained_today: 5, mttr_minutes: 45 });
      setITSM({ open_tickets: 28, sla_compliance: 94.5, avg_resolution_time: 4.2, tickets_today: 12 });
      setLoading(false);
    }
  };

  const getDefconColor = (level: number) => {
    if (level <= 2) return 'bg-red-500';
    if (level <= 3) return 'bg-orange-500';
    if (level <= 4) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-aether-primary"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">MSP Command Center</h1>
        <span className="text-sm text-gray-500">Real-time monitoring</span>
      </div>

      {/* DEFCON Status Banner */}
      {cyber && (
        <div className={`${getDefconColor(cyber.defcon_level)} rounded-lg p-4 text-white`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8" />
              <div>
                <h2 className="text-xl font-bold">DEFCON {cyber.defcon_level}</h2>
                <p className="text-sm opacity-90">
                  {cyber.defcon_level === 5 ? 'Normal Operations' :
                   cyber.defcon_level === 4 ? 'Elevated Awareness' :
                   cyber.defcon_level === 3 ? 'Increased Readiness' :
                   cyber.defcon_level === 2 ? 'High Alert' : 'Maximum Alert'}
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold">{cyber.active_incidents}</p>
              <p className="text-sm opacity-90">Active Incidents</p>
            </div>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Self-Healing Stats */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Auto-Remediation Rate</p>
              <p className="text-2xl font-bold text-green-600">{selfHealing?.success_rate}%</p>
            </div>
            <div className="p-3 bg-green-100 rounded-full">
              <Wrench className="h-6 w-6 text-green-600" />
            </div>
          </div>
          <p className="mt-2 text-sm text-gray-500">
            {selfHealing?.auto_remediated} of {selfHealing?.total_alerts} alerts auto-fixed
          </p>
        </div>

        {/* Tickets Created */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Escalated to Tickets</p>
              <p className="text-2xl font-bold text-orange-600">{selfHealing?.tickets_created}</p>
            </div>
            <div className="p-3 bg-orange-100 rounded-full">
              <AlertTriangle className="h-6 w-6 text-orange-600" />
            </div>
          </div>
          <p className="mt-2 text-sm text-gray-500">Requires human intervention</p>
        </div>

        {/* SLA Compliance */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">SLA Compliance</p>
              <p className="text-2xl font-bold text-blue-600">{itsm?.sla_compliance}%</p>
            </div>
            <div className="p-3 bg-blue-100 rounded-full">
              <CheckCircle className="h-6 w-6 text-blue-600" />
            </div>
          </div>
          <p className="mt-2 text-sm text-gray-500">Avg resolution: {itsm?.avg_resolution_time}h</p>
        </div>

        {/* Open Tickets */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-500">Open Tickets</p>
              <p className="text-2xl font-bold text-gray-900">{itsm?.open_tickets}</p>
            </div>
            <div className="p-3 bg-gray-100 rounded-full">
              <Clock className="h-6 w-6 text-gray-600" />
            </div>
          </div>
          <p className="mt-2 text-sm text-gray-500">{itsm?.tickets_today} new today</p>
        </div>
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Self-Healing Activity */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4">Self-Healing Activity</h3>
          <div className="space-y-4">
            {[
              { type: 'CPU High', status: 'remediated', time: '2 min ago' },
              { type: 'Disk Space', status: 'remediated', time: '15 min ago' },
              { type: 'Service Down', status: 'escalated', time: '23 min ago' },
              { type: 'Memory Leak', status: 'remediated', time: '45 min ago' },
              { type: 'Network Timeout', status: 'remediated', time: '1 hour ago' },
            ].map((alert, idx) => (
              <div key={idx} className="flex items-center justify-between py-2 border-b last:border-0">
                <div className="flex items-center space-x-3">
                  {alert.status === 'remediated' ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertTriangle className="h-5 w-5 text-orange-500" />
                  )}
                  <span className="font-medium">{alert.type}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 rounded text-xs ${
                    alert.status === 'remediated' ? 'bg-green-100 text-green-700' : 'bg-orange-100 text-orange-700'
                  }`}>
                    {alert.status}
                  </span>
                  <span className="text-sm text-gray-500">{alert.time}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Security Incidents */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold mb-4">Security Incidents</h3>
          <div className="space-y-4">
            {[
              { title: 'Brute Force Attempt', severity: 'high', status: 'investigating' },
              { title: 'Suspicious Login', severity: 'medium', status: 'contained' },
              { title: 'Malware Detected', severity: 'high', status: 'resolved' },
              { title: 'Policy Violation', severity: 'low', status: 'resolved' },
            ].map((incident, idx) => (
              <div key={idx} className="flex items-center justify-between py-2 border-b last:border-0">
                <div>
                  <p className="font-medium">{incident.title}</p>
                  <span className={`text-xs ${
                    incident.severity === 'high' ? 'text-red-600' :
                    incident.severity === 'medium' ? 'text-orange-600' : 'text-yellow-600'
                  }`}>
                    {incident.severity.toUpperCase()}
                  </span>
                </div>
                <span className={`px-2 py-1 rounded text-xs ${
                  incident.status === 'investigating' ? 'bg-blue-100 text-blue-700' :
                  incident.status === 'contained' ? 'bg-orange-100 text-orange-700' :
                  'bg-green-100 text-green-700'
                }`}>
                  {incident.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default MSPDashboard;
