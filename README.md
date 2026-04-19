# Aither MSP Platform

**The only platform where your antivirus, firewall, RMM, helpdesk, and incident response share the same brain.**

Aither MSP is a unified Managed Service Provider platform that replaces 6-8 separate tools with one integrated stack. When Shield detects a threat, Cyber-911 auto-classifies it, Self-Healing attempts remediation, and if it fails, ITSM auto-creates a ticket with full context. Zero swivel-chair.

---

## Core Services

| Service | Description | Tests |
|---------|-------------|-------|
| **RMM** | Remote Monitoring & Management -- endpoint registration, heartbeat, commands, patches, policies | 53 |
| **Aither Shield** | Consumer AV/Firewall -- 5 detection engines, 7 subscription tiers, VPN, dark web monitoring | 23+ |
| **Cyber-911** | Incident Response & SOAR -- 10 threat types, 8 automated response actions, DEFCON system | 19 |
| **Self-Healing** | Tier-1 Auto-Remediation -- 8 fault types with real Win/Linux commands via RMM dispatch | built-in |
| **ITSM** | IT Service Management -- SLA-driven ticketing (P1: 15min response / 1hr resolve) | 20 |
| **SOAR Playbooks** | Security Orchestration -- 5 pre-built playbooks, 20 action types, approval gates | 45 |
| **SIEM Ingest** | Security Event Pipeline -- syslog/WinEvent/Elastic parsers, 4 correlation rules | 41 |
| **Network Discovery** | SNMP/Ping sweep -- 11 device types, 30+ OIDs, 50+ vendor OUIs, topology mapping | 53 |
| **BDR** | Backup & Disaster Recovery -- policies, jobs, verification, DR plans, storage analytics | 65 |
| **Compliance** | Framework Templates -- HIPAA (40), SOC2 (31), NIST 800-171 (32), CMMC (21), PCI-DSS (32) | 33 |
| **Billing Engine** | Multi-Tenant Billing -- MRR/ARR/churn analytics, 6 pricing tiers, invoice generation | 66 |
| **White-Label** | MSP Branding -- CSS generation, email templates, custom domain verification | 44 |
| **Dark Web Monitor** | Breach Monitoring -- HIBP/SpyCloud integration, risk scoring, exposure alerts | 59 |
| **Signature Pipeline** | Threat Signatures -- versioned DB, delta updates, 3 feed sources, 25 seed signatures | 83 |
| **Agent Protocol** | RMM Agent Comms -- registration, auth, heartbeat, command queue, auto-update | 39 |
| **MDM** | Mobile Device Management -- BYOD, geofencing, compliance rules, 11 remote actions | 72 |
| **App Distribution** | Release Management -- 5 apps, channels (stable/beta/canary), auto-update API | 44 |
| **NOC Dashboard** | TV-Mode Display -- 8 auto-rotating panels, SSE alerts, keyboard controls | 18 |
| **Notification Connector** | Alert Routing -- Email/Slack/PagerDuty/Teams/Webhook/SMS with throttling | 59 |
| **PSA Connector** | ConnectWise Integration -- company/ticket/config sync, conflict resolution | 33 |
| **Sentinel MSP** | Vendor Oversight -- SLA tracking, performance scoring, escalation ladder | 19 |

**Total: 724+ tests passing**

---

## Tech Stack

- **Backend:** Python 3.10+, FastAPI, SQLAlchemy, PostgreSQL
- **Frontend:** React, TypeScript, TailwindCSS, Lucide Icons
- **Database:** PostgreSQL (D: drive) with SQLAlchemy ORM
- **Background Jobs:** Celery + Redis
- **Real-Time:** WebSocket + Server-Sent Events
- **Monitoring:** Prometheus integration, native dashboard

---

## Architecture

```
aither-msp-platform/
├── services_msp/           # Core MSP service layer
│   ├── rmm.py              # Remote Monitoring & Management
│   ├── cyber_911.py         # Incident Response
│   ├── self_healing.py      # Auto-Remediation
│   ├── itsm.py              # Ticketing / Help Desk
│   ├── soar_playbook.py     # SOAR Playbook Engine
│   ├── siem_ingest.py       # SIEM Event Pipeline
│   ├── network_discovery.py # SNMP/Network Discovery
│   ├── bdr_service.py       # Backup & Disaster Recovery
│   ├── compliance_frameworks.py  # HIPAA/SOC2/NIST/CMMC/PCI
│   ├── billing_engine.py    # Multi-Tenant Billing
│   ├── white_label.py       # MSP Branding
│   ├── agent_protocol.py    # RMM Agent Communication
│   ├── mdm_service.py       # Mobile Device Management
│   ├── app_distribution.py  # App Release Management
│   └── noc_aggregator.py    # NOC Dashboard Aggregation
├── services_shield/         # Consumer Security
│   ├── shield_service.py    # AV/Firewall/VPN/Dark Web
│   ├── dark_web_monitor.py  # Breach Monitoring
│   └── signature_pipeline.py # Signature Updates
├── api/routes/              # FastAPI route handlers
├── models/                  # SQLAlchemy ORM models
├── tests/                   # pytest test suite
├── frontend/components/msp/ # React dashboard components
└── docs/                    # Sales playbook + infra requirements
```

---

## Integration with Aither OS

This repo is a **standalone extraction** of the MSP components from the full [Aither Dominion](https://github.com/jt918/aither-dominion) platform. The services are designed to run independently or as part of the full Aither OS ecosystem.

**Integration points with Aither OS:**
- Shield ↔ Cyber-911: Threat intelligence sharing via Cyber-Shield Bridge
- RMM ↔ Self-Healing: Command dispatch for auto-remediation
- ITSM ↔ Self-Healing: Ticket auto-creation on escalation
- SIEM ↔ Cyber-911: Correlated events auto-create incidents
- SOAR ↔ Cyber-911: Playbooks auto-trigger on new incidents
- Billing ↔ RMM: Endpoint count drives per-seat billing
- Compliance ↔ Shield: Scan events map to compliance controls

---

## Pricing Tiers

### Shield Consumer (B2C)
| Tier | Price | Devices |
|------|-------|---------|
| Free | $0 | 1 |
| Personal | $4.99/mo | 3 |
| Family | $9.99/mo | 10 |
| Pro | $14.99/mo | 15 |

### MSP Platform (B2B)
| Tier | Per Endpoint/Mo | Includes |
|------|----------------|----------|
| Starter | $2.50 | RMM + ITSM + Shield Basic |
| Professional | $4.00 | + Cyber-911 + Self-Healing + Patches |
| Enterprise | $6.00 | + SOAR + Compliance + White-Label |

---

## Quick Start

```bash
# Backend
cd backend && pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm run dev

# Tests
pytest tests/ -v
```

---

## External Infrastructure Required

See [docs/EXTERNAL_INFRASTRUCTURE_REQUIREMENTS.md](docs/EXTERNAL_INFRASTRUCTURE_REQUIREMENTS.md) for:
- RMM Agent binary compilation (Go recommended)
- ClamAV/YARA scanning engine integration
- WireGuard VPN server deployment (7 locations)
- Dark web API keys (HIBP / SpyCloud)
- Code signing certificates
- Cloud hosting & deployment

---

## License

Proprietary - Aither Technology
