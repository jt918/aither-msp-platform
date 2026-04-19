/**
 * Compliance Dashboard - MSP Solutions
 *
 * Tracks regulatory compliance status across frameworks (SOC2, HIPAA, PCI-DSS, ISO27001, GDPR).
 * Features compliance scoring, control mapping, evidence collection, and audit readiness.
 */

import React, { useState } from 'react';
import {
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  FileText,
  Calendar,
  ChevronDown,
  ChevronRight,
  Upload,
  Download,
  Eye,
  Filter,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Target,
  Lock,
  Server,
  Users,
  Database,
  Activity
} from 'lucide-react';

// Types
interface ComplianceFramework {
  id: string;
  name: string;
  shortName: string;
  totalControls: number;
  compliantControls: number;
  partialControls: number;
  nonCompliantControls: number;
  score: number;
  lastAudit: string;
  nextAudit: string;
  status: 'compliant' | 'partial' | 'non_compliant' | 'pending';
  trend: 'up' | 'down' | 'stable';
}

interface ComplianceControl {
  id: string;
  frameworkId: string;
  controlId: string;
  title: string;
  description: string;
  category: string;
  status: 'compliant' | 'partial' | 'non_compliant' | 'not_applicable';
  owner: string;
  evidenceCount: number;
  lastReviewed: string;
  dueDate: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
}

interface AuditFinding {
  id: string;
  frameworkId: string;
  controlId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'in_progress' | 'remediated' | 'accepted';
  foundDate: string;
  dueDate: string;
  owner: string;
}

// Mock Data
const frameworks: ComplianceFramework[] = [
  {
    id: 'soc2',
    name: 'SOC 2 Type II',
    shortName: 'SOC2',
    totalControls: 89,
    compliantControls: 82,
    partialControls: 5,
    nonCompliantControls: 2,
    score: 92,
    lastAudit: '2024-06-15',
    nextAudit: '2025-06-15',
    status: 'compliant',
    trend: 'up'
  },
  {
    id: 'hipaa',
    name: 'HIPAA Security Rule',
    shortName: 'HIPAA',
    totalControls: 54,
    compliantControls: 48,
    partialControls: 4,
    nonCompliantControls: 2,
    score: 89,
    lastAudit: '2024-03-20',
    nextAudit: '2025-03-20',
    status: 'partial',
    trend: 'stable'
  },
  {
    id: 'pci',
    name: 'PCI-DSS v4.0',
    shortName: 'PCI',
    totalControls: 78,
    compliantControls: 71,
    partialControls: 5,
    nonCompliantControls: 2,
    score: 91,
    lastAudit: '2024-09-01',
    nextAudit: '2025-03-01',
    status: 'compliant',
    trend: 'up'
  },
  {
    id: 'iso27001',
    name: 'ISO 27001:2022',
    shortName: 'ISO',
    totalControls: 93,
    compliantControls: 78,
    partialControls: 10,
    nonCompliantControls: 5,
    score: 84,
    lastAudit: '2024-01-10',
    nextAudit: '2025-01-10',
    status: 'partial',
    trend: 'up'
  },
  {
    id: 'gdpr',
    name: 'GDPR',
    shortName: 'GDPR',
    totalControls: 42,
    compliantControls: 38,
    partialControls: 3,
    nonCompliantControls: 1,
    score: 90,
    lastAudit: '2024-05-01',
    nextAudit: '2025-05-01',
    status: 'compliant',
    trend: 'stable'
  }
];

const controls: ComplianceControl[] = [
  {
    id: 'ctrl-001',
    frameworkId: 'soc2',
    controlId: 'CC6.1',
    title: 'Logical Access Controls',
    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets.',
    category: 'Access Control',
    status: 'compliant',
    owner: 'IT Security',
    evidenceCount: 12,
    lastReviewed: '2024-12-01',
    dueDate: '2025-03-01',
    priority: 'critical'
  },
  {
    id: 'ctrl-002',
    frameworkId: 'soc2',
    controlId: 'CC7.2',
    title: 'Security Incident Response',
    description: 'The entity monitors system components and the operation of those components for anomalies.',
    category: 'Monitoring',
    status: 'compliant',
    owner: 'SOC Team',
    evidenceCount: 8,
    lastReviewed: '2024-11-15',
    dueDate: '2025-02-15',
    priority: 'high'
  },
  {
    id: 'ctrl-003',
    frameworkId: 'soc2',
    controlId: 'CC8.1',
    title: 'Change Management',
    description: 'The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes.',
    category: 'Change Management',
    status: 'partial',
    owner: 'DevOps',
    evidenceCount: 5,
    lastReviewed: '2024-10-20',
    dueDate: '2025-01-20',
    priority: 'high'
  },
  {
    id: 'ctrl-004',
    frameworkId: 'hipaa',
    controlId: '164.312(a)(1)',
    title: 'Access Control',
    description: 'Implement technical policies and procedures for electronic information systems that maintain ePHI.',
    category: 'Technical Safeguards',
    status: 'compliant',
    owner: 'IT Security',
    evidenceCount: 15,
    lastReviewed: '2024-12-10',
    dueDate: '2025-03-10',
    priority: 'critical'
  },
  {
    id: 'ctrl-005',
    frameworkId: 'hipaa',
    controlId: '164.312(e)(1)',
    title: 'Transmission Security',
    description: 'Implement technical security measures to guard against unauthorized access to ePHI being transmitted.',
    category: 'Technical Safeguards',
    status: 'non_compliant',
    owner: 'Network Team',
    evidenceCount: 2,
    lastReviewed: '2024-11-01',
    dueDate: '2025-01-15',
    priority: 'critical'
  },
  {
    id: 'ctrl-006',
    frameworkId: 'pci',
    controlId: '3.4',
    title: 'Render PAN Unreadable',
    description: 'Render PAN unreadable anywhere it is stored using strong cryptography.',
    category: 'Data Protection',
    status: 'compliant',
    owner: 'Data Security',
    evidenceCount: 10,
    lastReviewed: '2024-12-05',
    dueDate: '2025-03-05',
    priority: 'critical'
  }
];

const findings: AuditFinding[] = [
  {
    id: 'find-001',
    frameworkId: 'soc2',
    controlId: 'CC8.1',
    title: 'Incomplete change management documentation',
    severity: 'high',
    status: 'in_progress',
    foundDate: '2024-06-15',
    dueDate: '2025-01-31',
    owner: 'DevOps'
  },
  {
    id: 'find-002',
    frameworkId: 'hipaa',
    controlId: '164.312(e)(1)',
    title: 'TLS 1.0 still enabled on legacy systems',
    severity: 'critical',
    status: 'open',
    foundDate: '2024-03-20',
    dueDate: '2025-01-15',
    owner: 'Network Team'
  },
  {
    id: 'find-003',
    frameworkId: 'iso27001',
    controlId: 'A.9.2.3',
    title: 'Privileged access rights not reviewed quarterly',
    severity: 'medium',
    status: 'remediated',
    foundDate: '2024-01-10',
    dueDate: '2024-04-10',
    owner: 'IT Security'
  },
  {
    id: 'find-004',
    frameworkId: 'pci',
    controlId: '11.3',
    title: 'Penetration testing scope incomplete',
    severity: 'high',
    status: 'in_progress',
    foundDate: '2024-09-01',
    dueDate: '2025-02-01',
    owner: 'Security Team'
  }
];

const ComplianceDashboard: React.FC = () => {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set(['Access Control']));
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [viewMode, setViewMode] = useState<'frameworks' | 'controls' | 'findings'>('frameworks');

  // Calculate overall compliance score
  const overallScore = Math.round(
    frameworks.reduce((sum, f) => sum + f.score, 0) / frameworks.length
  );

  const totalFindings = findings.length;
  const openFindings = findings.filter(f => f.status === 'open' || f.status === 'in_progress').length;
  const criticalFindings = findings.filter(f => f.severity === 'critical' && f.status !== 'remediated').length;

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
      case 'remediated':
        return 'text-green-400 bg-green-500/20';
      case 'partial':
      case 'in_progress':
        return 'text-yellow-400 bg-yellow-500/20';
      case 'non_compliant':
      case 'open':
        return 'text-red-400 bg-red-500/20';
      case 'accepted':
      case 'not_applicable':
        return 'text-gray-400 bg-gray-500/20';
      default:
        return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20';
      case 'high': return 'text-orange-400 bg-orange-500/20';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20';
      case 'low': return 'text-blue-400 bg-blue-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-400';
    if (score >= 75) return 'text-yellow-400';
    return 'text-red-400';
  };

  const toggleCategory = (category: string) => {
    const newExpanded = new Set(expandedCategories);
    if (newExpanded.has(category)) {
      newExpanded.delete(category);
    } else {
      newExpanded.add(category);
    }
    setExpandedCategories(newExpanded);
  };

  const filteredControls = controls.filter(c => {
    if (selectedFramework && c.frameworkId !== selectedFramework) return false;
    if (statusFilter !== 'all' && c.status !== statusFilter) return false;
    return true;
  });

  const controlsByCategory = filteredControls.reduce((acc, control) => {
    if (!acc[control.category]) {
      acc[control.category] = [];
    }
    acc[control.category].push(control);
    return acc;
  }, {} as Record<string, ComplianceControl[]>);

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'Access Control': return <Lock className="w-4 h-4" />;
      case 'Monitoring': return <Activity className="w-4 h-4" />;
      case 'Change Management': return <RefreshCw className="w-4 h-4" />;
      case 'Technical Safeguards': return <Server className="w-4 h-4" />;
      case 'Data Protection': return <Database className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Compliance Dashboard</h1>
          <p className="text-sm text-gray-400 mt-1">Monitor regulatory compliance across all frameworks</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-4 py-2 bg-aether-dark border border-gray-700 rounded-lg text-gray-300 hover:bg-gray-700">
            <Download className="w-4 h-4" />
            Export Report
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-aether-accent text-white rounded-lg hover:bg-aether-accent/80">
            <RefreshCw className="w-4 h-4" />
            Run Assessment
          </button>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Overall Score</p>
              <p className={`text-3xl font-bold ${getScoreColor(overallScore)}`}>{overallScore}%</p>
            </div>
            <div className="p-3 bg-green-500/20 rounded-lg">
              <Target className="w-6 h-6 text-green-400" />
            </div>
          </div>
        </div>

        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Frameworks</p>
              <p className="text-3xl font-bold text-white">{frameworks.length}</p>
            </div>
            <div className="p-3 bg-blue-500/20 rounded-lg">
              <Shield className="w-6 h-6 text-blue-400" />
            </div>
          </div>
        </div>

        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Open Findings</p>
              <p className="text-3xl font-bold text-yellow-400">{openFindings}</p>
            </div>
            <div className="p-3 bg-yellow-500/20 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-yellow-400" />
            </div>
          </div>
        </div>

        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Critical Issues</p>
              <p className="text-3xl font-bold text-red-400">{criticalFindings}</p>
            </div>
            <div className="p-3 bg-red-500/20 rounded-lg">
              <XCircle className="w-6 h-6 text-red-400" />
            </div>
          </div>
        </div>

        <div className="bg-aether-dark-blue rounded-lg p-4 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Next Audit</p>
              <p className="text-xl font-bold text-white">Jan 10, 2025</p>
              <p className="text-xs text-gray-500">ISO 27001</p>
            </div>
            <div className="p-3 bg-purple-500/20 rounded-lg">
              <Calendar className="w-6 h-6 text-purple-400" />
            </div>
          </div>
        </div>
      </div>

      {/* View Tabs */}
      <div className="flex gap-2 border-b border-gray-700 pb-2">
        <button
          onClick={() => setViewMode('frameworks')}
          className={`px-4 py-2 rounded-t-lg ${viewMode === 'frameworks' ? 'bg-aether-dark-blue text-white' : 'text-gray-400 hover:text-white'}`}
        >
          Frameworks
        </button>
        <button
          onClick={() => setViewMode('controls')}
          className={`px-4 py-2 rounded-t-lg ${viewMode === 'controls' ? 'bg-aether-dark-blue text-white' : 'text-gray-400 hover:text-white'}`}
        >
          Controls
        </button>
        <button
          onClick={() => setViewMode('findings')}
          className={`px-4 py-2 rounded-t-lg ${viewMode === 'findings' ? 'bg-aether-dark-blue text-white' : 'text-gray-400 hover:text-white'}`}
        >
          Audit Findings
        </button>
      </div>

      {/* Frameworks View */}
      {viewMode === 'frameworks' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {frameworks.map(framework => (
            <div
              key={framework.id}
              className="bg-aether-dark-blue rounded-lg border border-gray-700 p-5 hover:border-aether-accent/50 transition-colors cursor-pointer"
              onClick={() => {
                setSelectedFramework(framework.id);
                setViewMode('controls');
              }}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-white">{framework.name}</h3>
                  <span className={`inline-block mt-1 px-2 py-0.5 rounded text-xs ${getStatusColor(framework.status)}`}>
                    {framework.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="text-right">
                  <p className={`text-3xl font-bold ${getScoreColor(framework.score)}`}>{framework.score}%</p>
                  <div className="flex items-center gap-1 text-xs mt-1">
                    {framework.trend === 'up' && <TrendingUp className="w-3 h-3 text-green-400" />}
                    {framework.trend === 'down' && <TrendingDown className="w-3 h-3 text-red-400" />}
                    {framework.trend === 'stable' && <span className="text-gray-400">—</span>}
                    <span className={framework.trend === 'up' ? 'text-green-400' : framework.trend === 'down' ? 'text-red-400' : 'text-gray-400'}>
                      {framework.trend}
                    </span>
                  </div>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="mb-4">
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>Control Status</span>
                  <span>{framework.compliantControls}/{framework.totalControls} compliant</span>
                </div>
                <div className="h-2 bg-gray-700 rounded-full overflow-hidden flex">
                  <div
                    className="bg-green-500"
                    style={{ width: `${(framework.compliantControls / framework.totalControls) * 100}%` }}
                  />
                  <div
                    className="bg-yellow-500"
                    style={{ width: `${(framework.partialControls / framework.totalControls) * 100}%` }}
                  />
                  <div
                    className="bg-red-500"
                    style={{ width: `${(framework.nonCompliantControls / framework.totalControls) * 100}%` }}
                  />
                </div>
              </div>

              {/* Control Breakdown */}
              <div className="grid grid-cols-3 gap-2 mb-4">
                <div className="text-center p-2 bg-green-500/10 rounded">
                  <p className="text-lg font-bold text-green-400">{framework.compliantControls}</p>
                  <p className="text-xs text-gray-400">Compliant</p>
                </div>
                <div className="text-center p-2 bg-yellow-500/10 rounded">
                  <p className="text-lg font-bold text-yellow-400">{framework.partialControls}</p>
                  <p className="text-xs text-gray-400">Partial</p>
                </div>
                <div className="text-center p-2 bg-red-500/10 rounded">
                  <p className="text-lg font-bold text-red-400">{framework.nonCompliantControls}</p>
                  <p className="text-xs text-gray-400">Non-Compliant</p>
                </div>
              </div>

              {/* Audit Info */}
              <div className="flex justify-between text-sm border-t border-gray-700 pt-3">
                <div>
                  <p className="text-gray-400">Last Audit</p>
                  <p className="text-white">{new Date(framework.lastAudit).toLocaleDateString()}</p>
                </div>
                <div className="text-right">
                  <p className="text-gray-400">Next Audit</p>
                  <p className="text-white">{new Date(framework.nextAudit).toLocaleDateString()}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Controls View */}
      {viewMode === 'controls' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-4 flex-wrap">
            <select
              value={selectedFramework || ''}
              onChange={(e) => setSelectedFramework(e.target.value || null)}
              className="bg-aether-dark border border-gray-700 rounded-lg px-3 py-2 text-white"
            >
              <option value="">All Frameworks</option>
              {frameworks.map(f => (
                <option key={f.id} value={f.id}>{f.shortName}</option>
              ))}
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-aether-dark border border-gray-700 rounded-lg px-3 py-2 text-white"
            >
              <option value="all">All Statuses</option>
              <option value="compliant">Compliant</option>
              <option value="partial">Partial</option>
              <option value="non_compliant">Non-Compliant</option>
              <option value="not_applicable">N/A</option>
            </select>

            <span className="text-sm text-gray-400">
              Showing {filteredControls.length} controls
            </span>
          </div>

          {/* Controls by Category */}
          <div className="space-y-2">
            {Object.entries(controlsByCategory).map(([category, categoryControls]) => (
              <div key={category} className="bg-aether-dark-blue rounded-lg border border-gray-700">
                <button
                  onClick={() => toggleCategory(category)}
                  className="w-full flex items-center justify-between p-4 hover:bg-gray-800/50"
                >
                  <div className="flex items-center gap-3">
                    {expandedCategories.has(category) ? (
                      <ChevronDown className="w-4 h-4 text-gray-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    )}
                    {getCategoryIcon(category)}
                    <span className="font-medium text-white">{category}</span>
                    <span className="text-sm text-gray-400">({categoryControls.length})</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded">
                      {categoryControls.filter(c => c.status === 'compliant').length} compliant
                    </span>
                    {categoryControls.some(c => c.status === 'non_compliant') && (
                      <span className="text-xs px-2 py-1 bg-red-500/20 text-red-400 rounded">
                        {categoryControls.filter(c => c.status === 'non_compliant').length} issues
                      </span>
                    )}
                  </div>
                </button>

                {expandedCategories.has(category) && (
                  <div className="border-t border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="text-left text-xs text-gray-400 border-b border-gray-700">
                          <th className="px-4 py-2">Control ID</th>
                          <th className="px-4 py-2">Title</th>
                          <th className="px-4 py-2">Status</th>
                          <th className="px-4 py-2">Priority</th>
                          <th className="px-4 py-2">Owner</th>
                          <th className="px-4 py-2">Evidence</th>
                          <th className="px-4 py-2">Due Date</th>
                          <th className="px-4 py-2">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {categoryControls.map(control => (
                          <tr key={control.id} className="border-b border-gray-700/50 hover:bg-gray-800/30">
                            <td className="px-4 py-3">
                              <span className="font-mono text-sm text-aether-accent">{control.controlId}</span>
                            </td>
                            <td className="px-4 py-3">
                              <p className="text-white text-sm">{control.title}</p>
                              <p className="text-xs text-gray-500 truncate max-w-xs">{control.description}</p>
                            </td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-1 rounded text-xs ${getStatusColor(control.status)}`}>
                                {control.status.replace('_', ' ')}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span className={`text-sm ${getPriorityColor(control.priority)}`}>
                                {control.priority}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-300">{control.owner}</td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-1">
                                <FileText className="w-3 h-3 text-gray-400" />
                                <span className="text-sm text-gray-300">{control.evidenceCount}</span>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-300">
                              {new Date(control.dueDate).toLocaleDateString()}
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <button className="p-1 hover:bg-gray-700 rounded" title="View Details">
                                  <Eye className="w-4 h-4 text-gray-400" />
                                </button>
                                <button className="p-1 hover:bg-gray-700 rounded" title="Upload Evidence">
                                  <Upload className="w-4 h-4 text-gray-400" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings View */}
      {viewMode === 'findings' && (
        <div className="bg-aether-dark-blue rounded-lg border border-gray-700">
          <div className="p-4 border-b border-gray-700 flex items-center justify-between">
            <h3 className="font-semibold text-white">Audit Findings</h3>
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-400">{findings.length} total findings</span>
            </div>
          </div>
          <table className="w-full">
            <thead>
              <tr className="text-left text-xs text-gray-400 border-b border-gray-700">
                <th className="px-4 py-3">Finding</th>
                <th className="px-4 py-3">Framework</th>
                <th className="px-4 py-3">Control</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Owner</th>
                <th className="px-4 py-3">Due Date</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map(finding => (
                <tr key={finding.id} className="border-b border-gray-700/50 hover:bg-gray-800/30">
                  <td className="px-4 py-4">
                    <p className="text-white">{finding.title}</p>
                    <p className="text-xs text-gray-500">Found: {new Date(finding.foundDate).toLocaleDateString()}</p>
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-sm text-gray-300">
                      {frameworks.find(f => f.id === finding.frameworkId)?.shortName}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span className="font-mono text-sm text-aether-accent">{finding.controlId}</span>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(finding.severity)}`}>
                      {finding.severity}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`px-2 py-1 rounded text-xs ${getStatusColor(finding.status)}`}>
                      {finding.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-sm text-gray-300">{finding.owner}</td>
                  <td className="px-4 py-4">
                    <span className={`text-sm ${new Date(finding.dueDate) < new Date() ? 'text-red-400' : 'text-gray-300'}`}>
                      {new Date(finding.dueDate).toLocaleDateString()}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <button className="p-1 hover:bg-gray-700 rounded">
                      <Eye className="w-4 h-4 text-gray-400" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default ComplianceDashboard;
