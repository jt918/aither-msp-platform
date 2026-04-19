# EXTERNAL INFRASTRUCTURE REQUIREMENTS

**Date:** 2026-04-19
**Author:** Aither Engineering
**Purpose:** Everything the Aither MSP platform needs that lives outside the codebase -- cloud services, signing certificates, API keys, hardware, and third-party subscriptions required to go from "demo-ready" to "ship-ready."

---

## TABLE OF CONTENTS

1. [RMM Agent Binary Compilation](#1-rmm-agent-binary-compilation)
2. [Antivirus / Scanning Engine](#2-antivirus--scanning-engine)
3. [VPN Server Infrastructure](#3-vpn-server-infrastructure)
4. [Dark Web Monitoring API](#4-dark-web-monitoring-api)
5. [SIEM / Log Collection Infrastructure](#5-siem--log-collection-infrastructure)
6. [Threat Intelligence Feeds](#6-threat-intelligence-feeds)
7. [Code Signing Certificates](#7-code-signing-certificates)
8. [APK / Mobile App Build Pipeline](#8-apk--mobile-app-build-pipeline)
9. [App Store Accounts](#9-app-store-accounts)
10. [Cloud Hosting & Deployment](#10-cloud-hosting--deployment)
11. [Email / Notification Infrastructure](#11-email--notification-infrastructure)
12. [DNS & Custom Domain Infrastructure](#12-dns--custom-domain-infrastructure)
13. [Backup Storage Targets](#13-backup-storage-targets)
14. [PSA / Third-Party Integration Credentials](#14-psa--third-party-integration-credentials)
15. [SSL / TLS Certificates](#15-ssl--tls-certificates)
16. [Monitoring & Observability](#16-monitoring--observability)
17. [Budget Summary](#17-budget-summary)
18. [Priority Sequencing](#18-priority-sequencing)

---

## 1. RMM AGENT BINARY COMPILATION

### What We Need
A lightweight daemon that runs on client endpoints to collect system metrics, execute commands from the Aither RMM queue, and send heartbeats.

### Platform Targets
| Platform | Format | Compiler | Notes |
|----------|--------|----------|-------|
| Windows x64 | .msi installer | Go cross-compile or MSVC | Must run as Windows Service |
| Windows x86 | .msi installer | Go cross-compile | Legacy support |
| Linux x64 | .deb + .rpm | Go native or cross | systemd unit file |
| Linux ARM64 | .deb + .rpm | Go cross-compile | Raspberry Pi / ARM servers |
| macOS x64 | .pkg installer | Go cross-compile | LaunchDaemon plist |
| macOS ARM64 | .pkg installer | Go cross-compile | Apple Silicon |

### Technology Recommendation
**Go** is the recommended language:
- Single static binary, no runtime dependencies
- Cross-compilation built-in (`GOOS=windows GOARCH=amd64 go build`)
- Low memory footprint (~10-15MB RSS)
- Native Windows Service support via `golang.org/x/sys/windows/svc`
- Native systemd support via `coreos/go-systemd`

### Infrastructure Required
| Item | Provider Options | Est. Cost | Notes |
|------|-----------------|-----------|-------|
| Build server (CI/CD) | GitHub Actions / GitLab CI | Free-$44/mo | Cross-compilation pipeline |
| Windows code-signing cert | DigiCert / Sectigo / GlobalSign | $200-500/yr | EV cert recommended for SmartScreen bypass |
| macOS Developer ID cert | Apple Developer Program | $99/yr | Required for notarization |
| macOS Notarization | Apple Notary Service | Free (with dev account) | Required since macOS Catalina |
| Artifact storage | S3 / Azure Blob / GCS | ~$5/mo | Store compiled binaries |

### Server-Side Status
**DONE** -- The agent communication protocol is built:
- `backend/services/msp/agent_protocol.py` -- Registration, authentication, heartbeat, command queue
- `backend/api/routes/agent_protocol.py` -- All agent-facing API endpoints
- `backend/models/agent_protocol.py` -- DB persistence for registered agents

### Agent Binary Spec (for the developer who builds this)
```
Agent Behavior:
1. On install: POST /agent/register with hostname, OS, arch, version
   - Receives: agent_id, api_key, config (intervals, features)
2. Every 60s (configurable): POST /agent/checkin
   - Sends: CPU%, RAM%, disk%, running services, uptime
   - Receives: list of pending commands
3. For each command: execute, POST /agent/commands/{id}/result
   - Sends: exit_code, stdout, stderr, execution_time_ms
4. Every 3600s: GET /agent/update/check
   - If new version: download, verify SHA-256, self-update

Auth: X-Agent-ID + X-Agent-Key headers on every request
Retry: exponential backoff on network failure (5s, 10s, 30s, 60s, 300s)
Logging: local log file, configurable level, max 50MB rotation
```

---

## 2. ANTIVIRUS / SCANNING ENGINE

### What We Need
A real file-scanning engine that detects malware via signature matching, heuristic analysis, and behavioral monitoring.

### Option A: ClamAV Integration (Recommended for MVP)
| Item | Details | Cost |
|------|---------|------|
| ClamAV daemon (clamd) | Open-source AV engine | Free |
| freshclam | Signature update daemon | Free |
| Signature database | ClamAV official + community | Free |
| Custom YARA rules | Aither-specific detections | Free (we write them) |

**Integration approach:**
- Install clamd on each endpoint alongside RMM agent
- Agent calls `clamdscan` for on-demand scans
- Configure clamd for on-access scanning (Linux: fanotify, Windows: via ClamAV's OnAccessScanning)
- freshclam pulls updates every 4 hours
- Our signature pipeline pushes custom YARA rules to endpoints

### Option B: Windows Minifilter Driver (Advanced)
| Item | Details | Cost |
|------|---------|------|
| Windows Driver Kit (WDK) | Microsoft developer tool | Free |
| EV code-signing cert | Required for kernel drivers | $200-500/yr (same as RMM) |
| WHQL certification | Microsoft driver signing | $0-250 per submission |
| Test lab | Physical machines for driver testing | Variable |

**Not recommended for MVP** -- kernel driver development is high-risk, requires WHQL certification, and takes 3-6 months.

### Option C: Third-Party EDR OEM (Fastest to Market)
| Vendor | Model | Cost |
|--------|-------|------|
| Bitdefender GravityZone OEM | White-label EDR | ~$1-2/endpoint/mo |
| ESET Protect OEM | White-label AV+EDR | ~$1.50/endpoint/mo |
| Webroot OEM | White-label AV | ~$0.50-1/endpoint/mo |

**Fastest path to market** but reduces margins and adds vendor dependency.

### Server-Side Status
**DONE** -- The signature pipeline is built:
- `backend/services/shield/signature_pipeline.py` -- Signature DB, versioning, delta updates, feed management
- `backend/api/routes/signature_pipeline.py` -- All distribution endpoints
- 20+ sample signatures pre-seeded

---

## 3. VPN SERVER INFRASTRUCTURE

### What We Need
WireGuard VPN servers in the 7 locations already defined in Shield.

### Deployment Plan
| Location | Provider | Server Spec | Est. Cost/Mo |
|----------|----------|-------------|--------------|
| New York (US-East) | DigitalOcean / Vultr | 2 vCPU, 4GB RAM, 1Gbps | $24 |
| Los Angeles (US-West) | DigitalOcean / Vultr | 2 vCPU, 4GB RAM, 1Gbps | $24 |
| London (EU-West) | DigitalOcean / Vultr | 2 vCPU, 4GB RAM, 1Gbps | $24 |
| Frankfurt (EU-Central) | Hetzner / Vultr | 2 vCPU, 4GB RAM, 1Gbps | $15-24 |
| Tokyo (Asia-Pacific) | Vultr / Linode | 2 vCPU, 4GB RAM, 1Gbps | $24 |
| Singapore (SE-Asia) | DigitalOcean / Vultr | 2 vCPU, 4GB RAM, 1Gbps | $24 |
| Sydney (Oceania) | Vultr / AWS Lightsail | 2 vCPU, 4GB RAM, 1Gbps | $24 |
| **Total** | | | **~$159-168/mo** |

### Setup Per Server
```bash
# 1. Install WireGuard
apt install wireguard

# 2. Generate server keys
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key

# 3. Configure interface (wg0.conf)
[Interface]
Address = 10.{location_id}.0.1/16
ListenPort = 51820
PrivateKey = {server_private_key}
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# 4. Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# 5. Start
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
```

### Key Management
- Each Shield user gets a unique WireGuard peer key pair
- Keys generated server-side via Aither API, distributed to Shield app
- Peer configs pushed to VPN servers via API or SSH automation
- IP assignment: 10.{location_id}.{user_block}.{device}/32

### Bandwidth Considerations
- Budget 100GB/user/month average
- 1,000 users = ~100TB/month
- At $0.01/GB (DigitalOcean transfer pricing) = ~$1,000/month bandwidth
- Consider providers with unmetered bandwidth (Hetzner, some Vultr plans)

### Server-Side Status
**DONE** -- VPN session management is built in Shield service. Needs key generation and server push automation.

---

## 4. DARK WEB MONITORING API

### What We Need
An API feed that checks if user credentials/PII have been exposed in data breaches.

### Provider Options
| Provider | API | Cost | Coverage |
|----------|-----|------|----------|
| Have I Been Pwned (HIBP) | hibp-api-key via API | $3.50/mo (individual) or enterprise pricing | 14B+ breached records |
| SpyCloud | Enterprise API | Custom pricing (~$5K-20K/yr) | Dark web + paste sites |
| Identity Guard | Enterprise API | Custom pricing | Consumer-focused |
| DarkOwl | Vision API | Custom pricing (~$10K+/yr) | Deep/dark web crawling |

### Recommended: HIBP API (MVP) + SpyCloud (Growth)

**HIBP Integration (ready to wire):**
```
API Key: Purchase at https://haveibeenpwned.com/API/Key
Endpoint: https://haveibeenpwned.com/api/v3/breachedaccount/{email}
Headers: hibp-api-key: {key}, user-agent: Aither-Shield
Rate Limit: 10 requests/minute (free), higher with enterprise
```

### Server-Side Status
**DONE** -- Dark web monitoring service is built:
- `backend/services/shield/dark_web_monitor.py` -- Full monitoring service with HIBP/SpyCloud stubs ready for API keys
- `backend/api/routes/dark_web_monitor.py` -- All endpoints
- Identity management, breach DB, exposure alerts, risk scoring all implemented

---

## 5. SIEM / LOG COLLECTION INFRASTRUCTURE

### What We Need
Log collection infrastructure to feed the SIEM ingest pipeline.

### Log Sources to Collect
| Source | Protocol | Port | Notes |
|--------|----------|------|-------|
| Windows Event Logs | WEF (Windows Event Forwarding) | 5985/5986 | Via WinRM |
| Linux syslog | Syslog (RFC 5424) | 514 (UDP/TCP) | rsyslog/syslog-ng |
| Firewall logs | Syslog | 514 | Fortinet, pfSense, etc. |
| Network devices | SNMP Traps | 162 | Switches, routers |
| Cloud services | Webhook/API | 443 | AWS CloudTrail, Azure Activity |
| Endpoint EDR | Agent push | 443 | Via RMM agent |

### Infrastructure Required
| Item | Details | Cost |
|------|---------|------|
| Syslog collector server | 4 vCPU, 8GB RAM, 500GB SSD | $48-80/mo |
| Elasticsearch cluster (optional) | 3-node cluster for log storage | $150-300/mo (or use managed) |
| Log retention storage | S3/Glacier for compliance retention | ~$23/TB/mo (S3) |

### Alternative: Wazuh (Open-Source SIEM)
- Free, open-source SIEM + XDR
- Includes agent for Windows/Linux/macOS
- Feeds directly into our SIEM ingest pipeline
- Recommended for MSPs who don't have existing SIEM

### Server-Side Status
**DONE** -- SIEM ingest pipeline is built:
- `backend/services/msp/siem_ingest.py` -- Syslog, Windows Event, Elastic/Wazuh parsers
- 4 pre-built correlation rules (brute force, privilege escalation, audit tampering, suspicious process)
- Auto-creates Cyber-911 incidents from correlated events

---

## 6. THREAT INTELLIGENCE FEEDS

### What We Need
External threat data to enrich our signature database and Cyber-911 incident context.

### Feed Options
| Feed | Type | Cost | Data |
|------|------|------|------|
| AlienVault OTX | Open-source | Free | IPs, domains, file hashes, URLs |
| Abuse.ch | Open-source | Free | Malware, botnet, SSL abuse |
| VirusTotal | API | Free (500 req/day) / $800+/mo | File/URL reputation |
| Shodan | API | Free (limited) / $59/mo | Internet scanning, exposed services |
| GreyNoise | API | Free (50 req/day) / $300/mo | Internet noise vs. targeted attacks |
| MISP | Open-source platform | Free (self-hosted) | Threat sharing platform |

### Recommended Stack
1. **AlienVault OTX** (free) -- immediate integration, IOC enrichment
2. **Abuse.ch feeds** (free) -- malware hash lists, botnet C2 lists
3. **VirusTotal** (free tier) -- file reputation checks
4. **MISP** (self-hosted) -- threat intel sharing with MSP clients

### Server-Side Status
**DONE** -- Signature pipeline supports multiple feed sources with pull scheduling.

---

## 7. CODE SIGNING CERTIFICATES

### What We Need
Digital signatures for all distributed binaries so OS security features (SmartScreen, Gatekeeper) don't block installation.

| Certificate | Platform | Provider | Cost | Duration |
|------------|----------|----------|------|----------|
| EV Code Signing | Windows | DigiCert | $410/yr | Immediate SmartScreen trust |
| Standard Code Signing | Windows (fallback) | Sectigo | $200/yr | Builds SmartScreen reputation over time |
| Apple Developer ID | macOS + iOS | Apple | $99/yr | Required for notarization |
| Google Play Signing | Android | Google | $25 one-time | Play Store upload signing |

### What Gets Signed
- RMM Agent installer (.msi, .pkg)
- Shield desktop app (.exe, .dmg)
- Shield mobile app (.apk, .ipa)
- Any PowerShell scripts distributed to endpoints
- WireGuard config packages

---

## 8. APK / MOBILE APP BUILD PIPELINE

### What We Need
CI/CD pipeline to compile Shield and other apps for Android and iOS.

### Android (APK)
| Item | Details | Cost |
|------|---------|------|
| Android SDK | Build tools, platform tools | Free |
| Gradle build system | Android build | Free |
| Android Keystore | APK signing key | Generated locally, stored securely |
| CI/CD runner | GitHub Actions / GitLab CI | Free-$44/mo |

```bash
# Build signed APK
./gradlew assembleRelease \
  -Pandroid.injected.signing.store.file=keystore.jks \
  -Pandroid.injected.signing.key.alias=shield \
  -Pandroid.injected.signing.store.password=$STORE_PASS \
  -Pandroid.injected.signing.key.password=$KEY_PASS
```

### iOS (IPA)
| Item | Details | Cost |
|------|---------|------|
| Apple Developer Account | Required for App Store | $99/yr |
| Xcode (macOS only) | iOS build tool | Free (requires Mac) |
| macOS build machine | CI/CD for iOS builds | $50-100/mo (Mac cloud) |
| Provisioning profiles | Distribution certificates | Via Apple Developer portal |

### Recommended: React Native or Flutter
If building mobile apps from scratch, use a cross-platform framework:
- **React Native** -- aligns with existing React frontend
- **Flutter** -- better performance, single codebase for Android + iOS

### Server-Side Status
**DONE** -- App distribution service is built:
- `backend/services/msp/app_distribution.py` -- Release management, update checks, download tracking
- `backend/api/routes/app_distribution.py` -- All endpoints including auto-update API
- 5 apps pre-registered (Shield, Synapse, ACE, GigOS, RMM Agent)

---

## 9. APP STORE ACCOUNTS

| Store | Account | Cost | Review Time |
|-------|---------|------|-------------|
| Google Play Store | Google Developer Account | $25 one-time | 1-7 days |
| Apple App Store | Apple Developer Program | $99/yr | 1-7 days |
| Microsoft Store | Microsoft Partner Center | Free | 1-5 days |
| Aither Direct (own CDN) | Self-hosted downloads | CDN cost only | Instant |

### Recommended Launch Strategy
1. **Phase 1:** Aither Direct (own download page) -- immediate, no review
2. **Phase 2:** Google Play Store -- Android distribution
3. **Phase 3:** Apple App Store -- iOS distribution
4. **Phase 4:** Microsoft Store -- Windows distribution

---

## 10. CLOUD HOSTING & DEPLOYMENT

### Production Environment
| Component | Spec | Provider Options | Est. Cost/Mo |
|-----------|------|-----------------|--------------|
| API Server (primary) | 8 vCPU, 32GB RAM, 500GB SSD | DigitalOcean / AWS / Azure | $160-320 |
| API Server (standby) | 8 vCPU, 32GB RAM, 500GB SSD | Same, different region | $160-320 |
| PostgreSQL Database | 4 vCPU, 16GB RAM, 500GB SSD | Managed DB (DO/AWS RDS) | $100-200 |
| PostgreSQL Replica | Read replica | Managed DB | $100-200 |
| Redis (cache + Celery) | 2GB RAM | Managed Redis | $15-30 |
| Load Balancer | L7 with SSL termination | Cloud LB | $18-25 |
| Object Storage | S3-compatible | S3 / Spaces / R2 | $5-50 |
| CDN | Static assets + downloads | Cloudflare / CloudFront | Free-$20 |
| **Total** | | | **$558-1,165/mo** |

### Kubernetes (Growth Phase)
When managing 50+ MSP clients:
| Component | Spec | Cost |
|-----------|------|------|
| K8s cluster (3 nodes) | 4 vCPU, 16GB each | $150-300/mo |
| Ingress controller | nginx / Traefik | Free |
| Cert-manager | Let's Encrypt automation | Free |
| Helm charts | Deployment management | Free |

---

## 11. EMAIL / NOTIFICATION INFRASTRUCTURE

### What We Need
Email sending for alerts, reports, ticket notifications, and marketing.

| Service | Use Case | Provider Options | Cost |
|---------|----------|-----------------|------|
| Transactional email | Alerts, tickets, reports | SendGrid / Postmark / SES | Free-$20/mo (up to 40K emails) |
| Marketing email | Newsletters, onboarding | Mailchimp / Brevo | Free-$20/mo |
| SMS alerts | Critical security alerts | Twilio / Vonage | $0.0075/msg |
| Slack integration | Webhook notifications | Slack API | Free |
| PagerDuty | On-call escalation | PagerDuty | $21/user/mo |
| Microsoft Teams | Webhook notifications | Teams Connectors | Free |

### Server-Side Status
**DONE** -- Notification connector is built with all 6 dispatch methods implemented (Email/Slack/PagerDuty/Teams/Webhook/SMS). Just needs API keys/credentials.

---

## 12. DNS & CUSTOM DOMAIN INFRASTRUCTURE

### What We Need
DNS management for white-label custom domains.

| Item | Details | Cost |
|------|---------|------|
| Primary domain | aither.io or aitheros.com | $10-50/yr |
| Wildcard SSL | *.aither.io via Let's Encrypt | Free |
| DNS hosting | Cloudflare / Route53 | Free-$5/mo |
| Custom domain SSL | Per-tenant via Let's Encrypt + cert-manager | Free |
| DNS verification | CNAME validation for white-label domains | Built into white-label service |

### White-Label Domain Flow
1. MSP partner registers custom domain (e.g., `security.mspname.com`)
2. Partner creates CNAME: `security.mspname.com -> custom.aither.io`
3. Aither verifies CNAME via DNS lookup
4. cert-manager issues Let's Encrypt cert for custom domain
5. Ingress routes traffic to partner's branded instance

### Server-Side Status
**DONE** -- White-label service includes domain verification and CSS generation.

---

## 13. BACKUP STORAGE TARGETS

### What We Need
Storage destinations for the BDR (Backup & Disaster Recovery) service.

| Destination | Provider | Cost | Use Case |
|-------------|----------|------|----------|
| Local NAS | Customer-owned | $0 (customer hardware) | Fast local recovery |
| S3 Standard | AWS S3 | $0.023/GB/mo | Active backups, 30-day retention |
| S3 Glacier | AWS Glacier | $0.004/GB/mo | Long-term compliance retention |
| Azure Blob Cool | Microsoft Azure | $0.01/GB/mo | Alternative cloud target |
| Backblaze B2 | Backblaze | $0.005/GB/mo | Budget cloud storage |
| Wasabi | Wasabi | $0.0069/GB/mo | No egress fees |

### Recommended: Wasabi or Backblaze B2
- No egress fees (critical for restores)
- S3-compatible API (works with existing tools)
- Compliance certifications (SOC2, HIPAA)

### Storage Math
| Scenario | Endpoints | Avg Backup Size | Monthly Storage | Cost (Wasabi) |
|----------|-----------|----------------|-----------------|---------------|
| Small MSP | 50 | 50GB each | 2.5TB | $17/mo |
| Medium MSP | 250 | 50GB each | 12.5TB | $86/mo |
| Large MSP | 1,000 | 50GB each | 50TB | $345/mo |

### Server-Side Status
**DONE** -- BDR service supports all destination types (local/NAS/S3/Azure/GCS/offsite).

---

## 14. PSA / THIRD-PARTY INTEGRATION CREDENTIALS

### ConnectWise Manage (Primary PSA)
| Item | How to Get | Cost |
|------|-----------|------|
| API Client ID | ConnectWise Developer Portal | Free with ConnectWise subscription |
| Public/Private Key Pair | Generated in ConnectWise Manage | Free |
| Sandbox environment | ConnectWise Developer Portal | Free (for testing) |

### Other PSA Integrations (Future)
| PSA | API Access | Notes |
|-----|-----------|-------|
| Autotask / Datto PSA | API credentials via Datto Partner Portal | Requires partner agreement |
| HaloPSA | API key via Halo admin panel | REST API |
| Syncro | API token via Syncro settings | REST API |

### Server-Side Status
**DONE** -- PSA connector is built with ConnectWise Manage API patterns, ready for credentials.

---

## 15. SSL / TLS CERTIFICATES

| Certificate | Purpose | Provider | Cost |
|------------|---------|----------|------|
| Platform SSL | aither.io HTTPS | Let's Encrypt | Free |
| Wildcard SSL | *.aither.io subdomains | Let's Encrypt | Free |
| VPN Server SSL | WireGuard (uses own crypto) | N/A | N/A |
| Agent-to-Server mTLS | Optional mutual TLS for agents | Self-signed CA | Free |

### Recommendation
Use Let's Encrypt for everything web-facing. Use self-signed CA for agent mTLS (internal trust only).

---

## 16. MONITORING & OBSERVABILITY

### What We Need
Monitoring for the Aither platform itself (not customer endpoints -- that's RMM).

| Component | Provider Options | Cost |
|-----------|-----------------|------|
| Uptime monitoring | UptimeRobot / Better Stack | Free-$20/mo |
| APM (Application Performance) | Datadog / New Relic / Grafana Cloud | Free tier-$50/mo |
| Log aggregation | Grafana Loki / ELK / Datadog | Free (self-hosted)-$50/mo |
| Error tracking | Sentry | Free-$26/mo |
| Status page | Instatus / Betteruptime | Free-$20/mo |

### Server-Side Status
**PARTIALLY DONE** -- Native monitoring dashboard exists with Prometheus integration. Need external uptime monitoring and status page.

---

## 17. BUDGET SUMMARY

### MVP Launch (Minimum Viable)

| Category | Monthly | Annual | Notes |
|----------|---------|--------|-------|
| Cloud hosting (API + DB) | $300 | $3,600 | Single-region, no HA |
| VPN servers (7 locations) | $165 | $1,980 | |
| Code signing (Windows EV) | $34 | $410 | |
| Apple Developer | $8 | $99 | |
| Google Play | $2 | $25 (one-time) | |
| HIBP API | $4 | $42 | |
| Email (SendGrid free) | $0 | $0 | Up to 100/day |
| DNS (Cloudflare free) | $0 | $0 | |
| SSL (Let's Encrypt) | $0 | $0 | |
| Monitoring (free tiers) | $0 | $0 | |
| **MVP Total** | **~$513** | **~$6,156** | |

### Growth Phase (50+ MSP clients)

| Category | Monthly | Annual | Notes |
|----------|---------|--------|-------|
| Cloud hosting (HA) | $800 | $9,600 | Multi-region, replicas |
| VPN servers (scaled) | $330 | $3,960 | Doubled capacity |
| Backup storage (Wasabi) | $200 | $2,400 | ~30TB |
| SIEM infrastructure | $150 | $1,800 | Syslog collector + storage |
| Email (SendGrid paid) | $20 | $240 | 40K emails/mo |
| Monitoring (paid) | $50 | $600 | Sentry + uptime |
| Threat intel feeds | $60 | $720 | Shodan + VirusTotal |
| SMS (Twilio) | $50 | $600 | Critical alerts |
| **Growth Total** | **~$1,660** | **~$19,920** | |

### Enterprise Phase (500+ MSP clients)

| Category | Monthly | Annual | Notes |
|----------|---------|--------|-------|
| Kubernetes cluster | $500 | $6,000 | Auto-scaling |
| Cloud hosting (full HA) | $2,000 | $24,000 | Multi-region, hot standby |
| VPN servers (scaled) | $660 | $7,920 | 14 servers |
| Backup storage | $1,000 | $12,000 | ~150TB |
| SpyCloud enterprise | $1,500 | $18,000 | Deep dark web monitoring |
| CDN (Cloudflare Pro) | $20 | $240 | |
| PagerDuty | $63 | $756 | 3 users |
| **Enterprise Total** | **~$5,743** | **~$68,916** | |

---

## 18. PRIORITY SEQUENCING

### Phase 1: MVP Launch (Weeks 1-4)
1. Provision cloud hosting (API server + PostgreSQL + Redis)
2. Purchase Windows EV code-signing certificate
3. Purchase Apple Developer account
4. Sign up for HIBP API
5. Set up SendGrid (free tier)
6. Set up Cloudflare (free tier)
7. Build RMM agent binary (Go)
8. Deploy to 1 VPN server location (US-East) for testing

### Phase 2: Beta Launch (Weeks 5-8)
9. Deploy remaining 6 VPN server locations
10. Build and publish Shield Android APK
11. Set up CI/CD pipeline for agent + app builds
12. Purchase Google Play Store account
13. Integrate ClamAV into Shield agent
14. Set up Sentry for error tracking
15. Launch status page

### Phase 3: GA Launch (Weeks 9-12)
16. Set up database replication (read replica)
17. Set up automated backups for platform DB
18. Integrate AlienVault OTX + Abuse.ch threat feeds
19. Set up Wazuh for customer SIEM option
20. Build Shield iOS app, submit to App Store
21. Stand up backup storage (Wasabi)

### Phase 4: Scale (Months 4-6)
22. Migrate to Kubernetes
23. Set up multi-region failover
24. Integrate SpyCloud enterprise
25. Set up PagerDuty for on-call
26. Obtain ConnectWise sandbox credentials
27. Launch white-label program with first MSP partner

---

## DECISION LOG

| Decision | Options Considered | Chosen | Rationale |
|----------|-------------------|--------|-----------|
| Agent language | Go, Rust, C++, Python | **Go** | Cross-compile, single binary, low memory, Windows Service support |
| AV engine (MVP) | ClamAV, YARA-only, OEM | **ClamAV + YARA** | Free, proven, extensible with custom rules |
| VPN protocol | WireGuard, OpenVPN, IPSec | **WireGuard** | Modern, fast, low overhead, small codebase |
| Dark web API | HIBP, SpyCloud, DarkOwl | **HIBP (MVP)** | Cheapest, largest dataset, easy API |
| Cloud provider | AWS, Azure, DigitalOcean | **DigitalOcean (MVP)** | Simplest, predictable pricing, sufficient for launch |
| Backup storage | S3, Glacier, Wasabi, B2 | **Wasabi** | No egress fees, S3-compatible, compliance certs |
| Mobile framework | React Native, Flutter, Native | **React Native** | Matches existing React frontend skill set |
| SIEM option | Splunk, Elastic, Wazuh | **Wazuh** | Free, open-source, includes agent, feeds our pipeline |
