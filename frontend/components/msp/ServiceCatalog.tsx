import { useState } from 'react'
import {
  Search,
  Filter,
  Plus,
  Server,
  Shield,
  Cloud,
  HelpCircle,
  Clock,
  DollarSign,
  Star,
  Check,
  X,
  ChevronRight,
  Users,
  Settings,
  Zap,
  Database,
  Monitor,
  Lock,
  Globe,
  BarChart3,
  Phone,
  Mail,
  MessageSquare
} from 'lucide-react'

// Types
interface ServiceFeature {
  name: string
  included: boolean
}

interface ServiceTier {
  id: string
  name: string
  price: number
  billingCycle: 'monthly' | 'annually' | 'per-user' | 'per-device'
  features: ServiceFeature[]
  popular?: boolean
}

interface Service {
  id: string
  name: string
  category: string
  description: string
  icon: string
  status: 'active' | 'coming-soon' | 'deprecated'
  slaTarget: string
  responseTime: string
  tiers: ServiceTier[]
  subscribers: number
  rating: number
  reviews: number
}

// Mock data
const services: Service[] = [
  {
    id: 'svc-001',
    name: 'Managed Endpoint Protection',
    category: 'Security',
    description: 'Enterprise-grade endpoint security with AI-powered threat detection, real-time monitoring, and automated remediation.',
    icon: 'shield',
    status: 'active',
    slaTarget: '99.9%',
    responseTime: '15 min',
    subscribers: 245,
    rating: 4.8,
    reviews: 89,
    tiers: [
      {
        id: 'tier-basic',
        name: 'Basic',
        price: 5,
        billingCycle: 'per-device',
        features: [
          { name: 'Antivirus Protection', included: true },
          { name: 'Weekly Scans', included: true },
          { name: 'Email Support', included: true },
          { name: 'Real-time Monitoring', included: false },
          { name: 'Threat Hunting', included: false },
          { name: '24/7 SOC', included: false }
        ]
      },
      {
        id: 'tier-pro',
        name: 'Professional',
        price: 12,
        billingCycle: 'per-device',
        popular: true,
        features: [
          { name: 'Antivirus Protection', included: true },
          { name: 'Daily Scans', included: true },
          { name: 'Priority Support', included: true },
          { name: 'Real-time Monitoring', included: true },
          { name: 'Threat Hunting', included: false },
          { name: '24/7 SOC', included: false }
        ]
      },
      {
        id: 'tier-enterprise',
        name: 'Enterprise',
        price: 25,
        billingCycle: 'per-device',
        features: [
          { name: 'Antivirus Protection', included: true },
          { name: 'Continuous Scans', included: true },
          { name: 'Dedicated Support', included: true },
          { name: 'Real-time Monitoring', included: true },
          { name: 'Threat Hunting', included: true },
          { name: '24/7 SOC', included: true }
        ]
      }
    ]
  },
  {
    id: 'svc-002',
    name: 'Cloud Infrastructure Management',
    category: 'Infrastructure',
    description: 'Complete cloud management including provisioning, monitoring, optimization, and cost control across AWS, Azure, and GCP.',
    icon: 'cloud',
    status: 'active',
    slaTarget: '99.95%',
    responseTime: '30 min',
    subscribers: 178,
    rating: 4.6,
    reviews: 62,
    tiers: [
      {
        id: 'tier-starter',
        name: 'Starter',
        price: 500,
        billingCycle: 'monthly',
        features: [
          { name: 'Single Cloud Platform', included: true },
          { name: 'Basic Monitoring', included: true },
          { name: 'Monthly Reports', included: true },
          { name: 'Cost Optimization', included: false },
          { name: 'Auto-scaling', included: false },
          { name: 'Disaster Recovery', included: false }
        ]
      },
      {
        id: 'tier-business',
        name: 'Business',
        price: 1500,
        billingCycle: 'monthly',
        popular: true,
        features: [
          { name: 'Multi-Cloud Support', included: true },
          { name: 'Advanced Monitoring', included: true },
          { name: 'Weekly Reports', included: true },
          { name: 'Cost Optimization', included: true },
          { name: 'Auto-scaling', included: true },
          { name: 'Disaster Recovery', included: false }
        ]
      },
      {
        id: 'tier-enterprise',
        name: 'Enterprise',
        price: 5000,
        billingCycle: 'monthly',
        features: [
          { name: 'Multi-Cloud Support', included: true },
          { name: 'Full Observability', included: true },
          { name: 'Real-time Reports', included: true },
          { name: 'Cost Optimization', included: true },
          { name: 'Auto-scaling', included: true },
          { name: 'Disaster Recovery', included: true }
        ]
      }
    ]
  },
  {
    id: 'svc-003',
    name: '24/7 Help Desk Support',
    category: 'Support',
    description: 'Round-the-clock IT support with multi-channel access including phone, email, chat, and self-service portal.',
    icon: 'helpdesk',
    status: 'active',
    slaTarget: '99.5%',
    responseTime: '5 min',
    subscribers: 412,
    rating: 4.7,
    reviews: 156,
    tiers: [
      {
        id: 'tier-basic',
        name: 'Basic',
        price: 25,
        billingCycle: 'per-user',
        features: [
          { name: 'Email Support', included: true },
          { name: 'Business Hours', included: true },
          { name: 'Knowledge Base', included: true },
          { name: 'Phone Support', included: false },
          { name: 'Live Chat', included: false },
          { name: 'Dedicated Agent', included: false }
        ]
      },
      {
        id: 'tier-pro',
        name: 'Professional',
        price: 50,
        billingCycle: 'per-user',
        popular: true,
        features: [
          { name: 'Email Support', included: true },
          { name: '24/7 Coverage', included: true },
          { name: 'Knowledge Base', included: true },
          { name: 'Phone Support', included: true },
          { name: 'Live Chat', included: true },
          { name: 'Dedicated Agent', included: false }
        ]
      },
      {
        id: 'tier-premium',
        name: 'Premium',
        price: 100,
        billingCycle: 'per-user',
        features: [
          { name: 'Email Support', included: true },
          { name: '24/7 Coverage', included: true },
          { name: 'Knowledge Base', included: true },
          { name: 'Phone Support', included: true },
          { name: 'Live Chat', included: true },
          { name: 'Dedicated Agent', included: true }
        ]
      }
    ]
  },
  {
    id: 'svc-004',
    name: 'Backup & Disaster Recovery',
    category: 'Infrastructure',
    description: 'Automated backup solutions with rapid recovery, geo-redundant storage, and compliance-ready retention policies.',
    icon: 'database',
    status: 'active',
    slaTarget: '99.99%',
    responseTime: '10 min',
    subscribers: 289,
    rating: 4.9,
    reviews: 94,
    tiers: [
      {
        id: 'tier-basic',
        name: 'Basic',
        price: 100,
        billingCycle: 'monthly',
        features: [
          { name: 'Daily Backups', included: true },
          { name: '30-Day Retention', included: true },
          { name: 'Local Storage', included: true },
          { name: 'Geo-Redundancy', included: false },
          { name: 'Point-in-Time Recovery', included: false },
          { name: 'DR Orchestration', included: false }
        ]
      },
      {
        id: 'tier-pro',
        name: 'Professional',
        price: 300,
        billingCycle: 'monthly',
        popular: true,
        features: [
          { name: 'Hourly Backups', included: true },
          { name: '90-Day Retention', included: true },
          { name: 'Cloud Storage', included: true },
          { name: 'Geo-Redundancy', included: true },
          { name: 'Point-in-Time Recovery', included: true },
          { name: 'DR Orchestration', included: false }
        ]
      },
      {
        id: 'tier-enterprise',
        name: 'Enterprise',
        price: 800,
        billingCycle: 'monthly',
        features: [
          { name: 'Continuous Backups', included: true },
          { name: '7-Year Retention', included: true },
          { name: 'Multi-Cloud Storage', included: true },
          { name: 'Geo-Redundancy', included: true },
          { name: 'Point-in-Time Recovery', included: true },
          { name: 'DR Orchestration', included: true }
        ]
      }
    ]
  },
  {
    id: 'svc-005',
    name: 'Network Monitoring & Management',
    category: 'Infrastructure',
    description: 'Comprehensive network visibility with performance monitoring, traffic analysis, and proactive alerting.',
    icon: 'network',
    status: 'active',
    slaTarget: '99.9%',
    responseTime: '15 min',
    subscribers: 198,
    rating: 4.5,
    reviews: 71,
    tiers: [
      {
        id: 'tier-basic',
        name: 'Basic',
        price: 200,
        billingCycle: 'monthly',
        features: [
          { name: 'Up to 25 Devices', included: true },
          { name: 'Basic Monitoring', included: true },
          { name: 'Email Alerts', included: true },
          { name: 'Traffic Analysis', included: false },
          { name: 'Performance Reports', included: false },
          { name: 'Configuration Backup', included: false }
        ]
      },
      {
        id: 'tier-pro',
        name: 'Professional',
        price: 500,
        billingCycle: 'monthly',
        popular: true,
        features: [
          { name: 'Up to 100 Devices', included: true },
          { name: 'Advanced Monitoring', included: true },
          { name: 'Multi-Channel Alerts', included: true },
          { name: 'Traffic Analysis', included: true },
          { name: 'Performance Reports', included: true },
          { name: 'Configuration Backup', included: false }
        ]
      },
      {
        id: 'tier-enterprise',
        name: 'Enterprise',
        price: 1500,
        billingCycle: 'monthly',
        features: [
          { name: 'Unlimited Devices', included: true },
          { name: 'AI-Powered Monitoring', included: true },
          { name: 'Smart Alerts', included: true },
          { name: 'Traffic Analysis', included: true },
          { name: 'Performance Reports', included: true },
          { name: 'Configuration Backup', included: true }
        ]
      }
    ]
  },
  {
    id: 'svc-006',
    name: 'Identity & Access Management',
    category: 'Security',
    description: 'Centralized identity management with SSO, MFA, and role-based access control across all applications.',
    icon: 'lock',
    status: 'coming-soon',
    slaTarget: '99.99%',
    responseTime: '10 min',
    subscribers: 0,
    rating: 0,
    reviews: 0,
    tiers: [
      {
        id: 'tier-basic',
        name: 'Basic',
        price: 3,
        billingCycle: 'per-user',
        features: [
          { name: 'Single Sign-On', included: true },
          { name: 'MFA', included: true },
          { name: 'User Directory', included: true },
          { name: 'Conditional Access', included: false },
          { name: 'Privileged Access', included: false },
          { name: 'Identity Governance', included: false }
        ]
      },
      {
        id: 'tier-pro',
        name: 'Professional',
        price: 8,
        billingCycle: 'per-user',
        popular: true,
        features: [
          { name: 'Single Sign-On', included: true },
          { name: 'MFA', included: true },
          { name: 'User Directory', included: true },
          { name: 'Conditional Access', included: true },
          { name: 'Privileged Access', included: true },
          { name: 'Identity Governance', included: false }
        ]
      },
      {
        id: 'tier-enterprise',
        name: 'Enterprise',
        price: 15,
        billingCycle: 'per-user',
        features: [
          { name: 'Single Sign-On', included: true },
          { name: 'MFA', included: true },
          { name: 'User Directory', included: true },
          { name: 'Conditional Access', included: true },
          { name: 'Privileged Access', included: true },
          { name: 'Identity Governance', included: true }
        ]
      }
    ]
  }
]

const categories = ['All', 'Security', 'Infrastructure', 'Support', 'Compliance']

const getIcon = (iconName: string) => {
  const icons: Record<string, React.ReactNode> = {
    shield: <Shield className="w-6 h-6" />,
    cloud: <Cloud className="w-6 h-6" />,
    helpdesk: <HelpCircle className="w-6 h-6" />,
    database: <Database className="w-6 h-6" />,
    network: <Globe className="w-6 h-6" />,
    lock: <Lock className="w-6 h-6" />,
    server: <Server className="w-6 h-6" />,
    monitor: <Monitor className="w-6 h-6" />
  }
  return icons[iconName] || <Server className="w-6 h-6" />
}

export default function ServiceCatalog() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('All')
  const [selectedService, setSelectedService] = useState<Service | null>(null)
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')

  const filteredServices = services.filter(service => {
    const matchesSearch = service.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          service.description.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCategory = selectedCategory === 'All' || service.category === selectedCategory
    return matchesSearch && matchesCategory
  })

  const stats = {
    totalServices: services.length,
    activeServices: services.filter(s => s.status === 'active').length,
    totalSubscribers: services.reduce((sum, s) => sum + s.subscribers, 0),
    avgRating: (services.filter(s => s.rating > 0).reduce((sum, s) => sum + s.rating, 0) / services.filter(s => s.rating > 0).length).toFixed(1)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Service Catalog</h1>
          <p className="text-gray-600 mt-1">Browse and subscribe to managed IT services</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-aether-600 text-white rounded-lg hover:bg-aether-700">
          <Plus className="w-4 h-4" />
          Request Service
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Server className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.totalServices}</p>
              <p className="text-sm text-gray-500">Total Services</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <Zap className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.activeServices}</p>
              <p className="text-sm text-gray-500">Active Services</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Users className="w-5 h-5 text-purple-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.totalSubscribers}</p>
              <p className="text-sm text-gray-500">Subscribers</p>
            </div>
          </div>
        </div>
        <div className="bg-white p-4 rounded-xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Star className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{stats.avgRating}</p>
              <p className="text-sm text-gray-500">Avg Rating</p>
            </div>
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
              placeholder="Search services..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-aether-500 focus:border-aether-500"
            />
          </div>
          <div className="flex items-center gap-2 overflow-x-auto pb-2 md:pb-0">
            {categories.map((category) => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-colors ${
                  selectedCategory === category
                    ? 'bg-aether-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                {category}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredServices.map((service) => (
          <div
            key={service.id}
            className="bg-white rounded-xl shadow-sm hover:shadow-md transition-shadow cursor-pointer"
            onClick={() => setSelectedService(service)}
          >
            <div className="p-6">
              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div className={`p-3 rounded-xl ${
                  service.category === 'Security' ? 'bg-red-100 text-red-600' :
                  service.category === 'Infrastructure' ? 'bg-blue-100 text-blue-600' :
                  'bg-green-100 text-green-600'
                }`}>
                  {getIcon(service.icon)}
                </div>
                <span className={`px-2.5 py-1 text-xs font-medium rounded-full ${
                  service.status === 'active' ? 'bg-green-100 text-green-700' :
                  service.status === 'coming-soon' ? 'bg-yellow-100 text-yellow-700' :
                  'bg-gray-100 text-gray-700'
                }`}>
                  {service.status === 'coming-soon' ? 'Coming Soon' : service.status}
                </span>
              </div>

              {/* Content */}
              <h3 className="text-lg font-semibold text-gray-900 mb-2">{service.name}</h3>
              <p className="text-sm text-gray-600 mb-4 line-clamp-2">{service.description}</p>

              {/* SLA Info */}
              <div className="flex items-center gap-4 mb-4 text-sm">
                <div className="flex items-center gap-1.5 text-gray-600">
                  <BarChart3 className="w-4 h-4" />
                  <span>SLA {service.slaTarget}</span>
                </div>
                <div className="flex items-center gap-1.5 text-gray-600">
                  <Clock className="w-4 h-4" />
                  <span>{service.responseTime}</span>
                </div>
              </div>

              {/* Pricing */}
              <div className="border-t pt-4">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-sm text-gray-500">Starting at</span>
                    <div className="flex items-baseline gap-1">
                      <span className="text-2xl font-bold text-gray-900">
                        ${service.tiers[0]?.price}
                      </span>
                      <span className="text-sm text-gray-500">
                        /{service.tiers[0]?.billingCycle.replace('per-', '').replace('ly', '')}
                      </span>
                    </div>
                  </div>
                  {service.rating > 0 && (
                    <div className="flex items-center gap-1.5">
                      <Star className="w-4 h-4 text-yellow-400 fill-yellow-400" />
                      <span className="font-medium">{service.rating}</span>
                      <span className="text-sm text-gray-500">({service.reviews})</span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="px-6 py-3 bg-gray-50 rounded-b-xl flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-sm text-gray-600">
                <Users className="w-4 h-4" />
                <span>{service.subscribers} subscribers</span>
              </div>
              <ChevronRight className="w-5 h-5 text-gray-400" />
            </div>
          </div>
        ))}
      </div>

      {/* Service Detail Modal */}
      {selectedService && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-white rounded-2xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`p-3 rounded-xl ${
                  selectedService.category === 'Security' ? 'bg-red-100 text-red-600' :
                  selectedService.category === 'Infrastructure' ? 'bg-blue-100 text-blue-600' :
                  'bg-green-100 text-green-600'
                }`}>
                  {getIcon(selectedService.icon)}
                </div>
                <div>
                  <h2 className="text-xl font-bold text-gray-900">{selectedService.name}</h2>
                  <p className="text-sm text-gray-500">{selectedService.category}</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedService(null)}
                className="p-2 hover:bg-gray-100 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6">
              {/* Description */}
              <p className="text-gray-600 mb-6">{selectedService.description}</p>

              {/* SLA Details */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">SLA Target</p>
                  <p className="text-xl font-bold text-gray-900">{selectedService.slaTarget}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Response Time</p>
                  <p className="text-xl font-bold text-gray-900">{selectedService.responseTime}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Subscribers</p>
                  <p className="text-xl font-bold text-gray-900">{selectedService.subscribers}</p>
                </div>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <p className="text-sm text-gray-500">Rating</p>
                  <div className="flex items-center gap-1.5">
                    <Star className="w-5 h-5 text-yellow-400 fill-yellow-400" />
                    <span className="text-xl font-bold text-gray-900">{selectedService.rating || 'N/A'}</span>
                  </div>
                </div>
              </div>

              {/* Pricing Tiers */}
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Pricing Plans</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {selectedService.tiers.map((tier) => (
                  <div
                    key={tier.id}
                    className={`rounded-xl border-2 p-6 ${
                      tier.popular ? 'border-aether-500 ring-2 ring-aether-100' : 'border-gray-200'
                    }`}
                  >
                    {tier.popular && (
                      <span className="inline-block px-3 py-1 bg-aether-100 text-aether-700 text-xs font-medium rounded-full mb-3">
                        Most Popular
                      </span>
                    )}
                    <h4 className="text-lg font-semibold text-gray-900">{tier.name}</h4>
                    <div className="flex items-baseline gap-1 mt-2 mb-4">
                      <span className="text-3xl font-bold text-gray-900">${tier.price}</span>
                      <span className="text-gray-500">/{tier.billingCycle.replace('per-', '').replace('ly', '')}</span>
                    </div>
                    <ul className="space-y-3 mb-6">
                      {tier.features.map((feature, idx) => (
                        <li key={idx} className="flex items-center gap-2 text-sm">
                          {feature.included ? (
                            <Check className="w-4 h-4 text-green-500" />
                          ) : (
                            <X className="w-4 h-4 text-gray-300" />
                          )}
                          <span className={feature.included ? 'text-gray-700' : 'text-gray-400'}>
                            {feature.name}
                          </span>
                        </li>
                      ))}
                    </ul>
                    <button
                      className={`w-full py-2.5 rounded-lg font-medium ${
                        tier.popular
                          ? 'bg-aether-600 text-white hover:bg-aether-700'
                          : 'border border-gray-300 text-gray-700 hover:bg-gray-50'
                      }`}
                    >
                      {selectedService.status === 'coming-soon' ? 'Notify Me' : 'Subscribe'}
                    </button>
                  </div>
                ))}
              </div>

              {/* Contact Options */}
              <div className="mt-8 p-4 bg-gray-50 rounded-xl">
                <h4 className="font-medium text-gray-900 mb-3">Need help choosing?</h4>
                <div className="flex flex-wrap gap-3">
                  <button className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
                    <Phone className="w-4 h-4" />
                    Schedule Call
                  </button>
                  <button className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
                    <Mail className="w-4 h-4" />
                    Email Sales
                  </button>
                  <button className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50">
                    <MessageSquare className="w-4 h-4" />
                    Live Chat
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
