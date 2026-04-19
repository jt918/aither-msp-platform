"""
AITHER Platform - Network Traffic Analyzer Service
Monitors LAN/WAN/web traffic patterns, detects suspicious flows,
and feeds into the threat scoring system.

Provides:
- Traffic flow recording and analysis
- Network segment management
- Traffic baseline computation
- Anomaly detection (port scan, DNS tunneling, beaconing, exfiltration,
  lateral movement, C2 communication, protocol violation, ARP spoofing,
  DGA domain detection, slow DoS, encrypted tunnel abuse)
- DNS query logging and suspicious-DNS detection
- Connection profiling per IP
- Bandwidth / top-talker / protocol analytics
- Network health dashboard

G-46: DB persistence with in-memory fallback.
"""

import math
import uuid
import logging
import hashlib
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set, Tuple
from enum import Enum

try:
    from sqlalchemy.orm import Session
    from models.network_traffic import (
        TrafficFlowModel,
        TrafficBaselineModel,
        TrafficAnomalyModel,
        NetworkSegmentModel,
        DNSQueryModel,
        ConnectionProfileModel,
    )
    ORM_AVAILABLE = True
except Exception:
    ORM_AVAILABLE = False
    Session = None

logger = logging.getLogger(__name__)


# ============================================================
# Enums
# ============================================================

class TrafficAnomalyType(str, Enum):
    """Types of traffic anomalies the analyzer can detect."""
    BANDWIDTH_SPIKE = "bandwidth_spike"
    PORT_SCAN = "port_scan"
    DNS_TUNNELING = "dns_tunneling"
    BEACONING = "beaconing"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    PROTOCOL_VIOLATION = "protocol_violation"
    UNUSUAL_PORT = "unusual_port"
    UNUSUAL_DESTINATION = "unusual_destination"
    ENCRYPTED_TUNNEL_ABUSE = "encrypted_tunnel_abuse"
    ARP_SPOOFING = "arp_spoofing"
    DHCP_STARVATION = "dhcp_starvation"
    BROADCAST_STORM = "broadcast_storm"
    SLOW_DOS = "slow_dos"


class SegmentType(str, Enum):
    """Network segment types."""
    LAN = "lan"
    WAN = "wan"
    DMZ = "dmz"
    GUEST = "guest"
    IOT = "iot"
    SERVER = "server"
    MANAGEMENT = "management"
    VPN = "vpn"


class TrustLevel(str, Enum):
    """Segment trust levels."""
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"
    ISOLATED = "isolated"


class FlowState(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    RESET = "reset"
    TIMEOUT = "timeout"


class AppProtocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    RDP = "rdp"
    SMB = "smb"
    DNS = "dns"
    FTP = "ftp"
    SMTP = "smtp"
    UNKNOWN = "unknown"


# ============================================================
# Dataclasses
# ============================================================

@dataclass
class TrafficFlow:
    """Single recorded traffic flow."""
    flow_id: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration_seconds: float = 0.0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    flow_state: str = "active"
    application_protocol: str = "unknown"
    is_encrypted: bool = False
    is_internal: bool = False
    threat_tags: List[str] = field(default_factory=list)


@dataclass
class TrafficBaseline:
    """Baseline metric for a network segment."""
    baseline_id: str
    network_segment: str
    metric_name: str
    expected_value: float = 0.0
    std_deviation: float = 0.0
    peak_value: float = 0.0
    off_peak_value: float = 0.0
    sample_period: str = "1h"
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TrafficAnomaly:
    """Detected traffic anomaly."""
    anomaly_id: str
    anomaly_type: str
    severity: str = "medium"
    source_ip: str = ""
    dest_ip: str = ""
    description: str = ""
    flow_ids: List[str] = field(default_factory=list)
    deviation_from_baseline: float = 0.0
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_confirmed: bool = False
    auto_action_taken: str = ""


@dataclass
class NetworkSegment:
    """Managed network segment."""
    segment_id: str
    name: str
    cidr: str
    segment_type: str = "lan"
    trust_level: str = "trusted"
    allowed_protocols: List[str] = field(default_factory=list)
    bandwidth_limit_mbps: float = 0.0
    devices_count: int = 0


@dataclass
class DNSQuery:
    """Logged DNS query."""
    query_id: str
    source_ip: str
    query_name: str
    query_type: str = "A"
    response_ip: str = ""
    response_code: str = "NOERROR"
    is_suspicious: bool = False
    suspicion_reason: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ConnectionProfile:
    """Aggregated connection profile for an IP address."""
    profile_id: str
    ip_address: str
    unique_destinations: int = 0
    unique_ports: int = 0
    protocols_used: List[str] = field(default_factory=list)
    total_bytes: int = 0
    total_flows: int = 0
    avg_flow_duration: float = 0.0
    peak_bandwidth_mbps: float = 0.0
    countries_connected: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_server: bool = False
    is_scanner: bool = False


# ============================================================
# Well-known port → expected protocol mapping
# ============================================================

STANDARD_PORT_PROTOCOL = {
    80: "http", 443: "https", 22: "ssh", 3389: "rdp",
    445: "smb", 53: "dns", 21: "ftp", 25: "smtp",
    110: "pop3", 143: "imap", 993: "imaps", 995: "pop3s",
    8080: "http", 8443: "https",
}

ADMIN_PORTS = {22, 445, 3389, 5985, 5986}

# Known-bad IPs (stub - in production, load from threat intel feed)
KNOWN_BAD_IPS: Set[str] = set()


# ============================================================
# Service
# ============================================================

class NetworkTrafficAnalyzerService:
    """
    Network traffic analysis, anomaly detection, and profiling.

    Detects: port scans, DNS tunneling, beaconing (C2 callback),
    data exfiltration, lateral movement, C2 communication,
    protocol violations, ARP spoofing, slow DoS, DGA domains,
    encrypted tunnel abuse, and bandwidth spikes.
    """

    def __init__(self, db: "Session" = None):
        self.db = db
        self._use_db = db is not None and ORM_AVAILABLE

        # In-memory fallback
        self._flows: Dict[str, TrafficFlow] = {}
        self._baselines: Dict[str, TrafficBaseline] = {}
        self._anomalies: Dict[str, TrafficAnomaly] = {}
        self._segments: Dict[str, NetworkSegment] = {}
        self._dns_queries: Dict[str, DNSQuery] = {}
        self._profiles: Dict[str, ConnectionProfile] = {}

        # Detection indices (in-memory)
        self._src_flow_index: Dict[str, List[str]] = defaultdict(list)  # src_ip -> flow_ids
        self._dst_flow_index: Dict[str, List[str]] = defaultdict(list)  # dst_ip -> flow_ids
        self._dns_by_src: Dict[str, List[str]] = defaultdict(list)

        # Detection thresholds
        self._port_scan_threshold = 20       # unique ports in 60s
        self._port_scan_window = 60          # seconds
        self._exfil_bytes_threshold = 100 * 1024 * 1024  # 100 MB
        self._exfil_window = 3600            # 1 hour
        self._lateral_hosts_threshold = 5    # hosts on admin ports
        self._lateral_window = 600           # 10 minutes
        self._dns_subdomain_len = 50         # chars for tunneling flag
        self._beacon_tolerance = 0.15        # 15 % jitter tolerance
        self._dga_entropy_threshold = 3.5
        self._dga_consonant_ratio = 0.7
        self._slow_dos_half_open = 100       # half-open conns

    # ================================================================
    # Flow Management
    # ================================================================

    def record_flow(self, flow_data: Dict[str, Any]) -> TrafficFlow:
        """Record a single traffic flow and run detection."""
        fid = flow_data.get("flow_id", f"FLOW-{uuid.uuid4().hex[:12]}")
        now = datetime.now(timezone.utc)
        fl = TrafficFlow(
            flow_id=fid,
            source_ip=flow_data.get("source_ip", "0.0.0.0"),
            source_port=int(flow_data.get("source_port", 0)),
            dest_ip=flow_data.get("dest_ip", "0.0.0.0"),
            dest_port=int(flow_data.get("dest_port", 0)),
            protocol=flow_data.get("protocol", "tcp"),
            bytes_sent=int(flow_data.get("bytes_sent", 0)),
            bytes_received=int(flow_data.get("bytes_received", 0)),
            packets_sent=int(flow_data.get("packets_sent", 0)),
            packets_received=int(flow_data.get("packets_received", 0)),
            duration_seconds=float(flow_data.get("duration_seconds", 0.0)),
            start_time=flow_data.get("start_time", now),
            end_time=flow_data.get("end_time"),
            flow_state=flow_data.get("flow_state", "active"),
            application_protocol=flow_data.get("application_protocol", "unknown"),
            is_encrypted=bool(flow_data.get("is_encrypted", False)),
            is_internal=bool(flow_data.get("is_internal", False)),
            threat_tags=flow_data.get("threat_tags", []),
        )

        # Persist
        if self._use_db:
            try:
                m = TrafficFlowModel(
                    flow_id=fl.flow_id, source_ip=fl.source_ip,
                    source_port=fl.source_port, dest_ip=fl.dest_ip,
                    dest_port=fl.dest_port, protocol=fl.protocol,
                    bytes_sent=fl.bytes_sent, bytes_received=fl.bytes_received,
                    packets_sent=fl.packets_sent, packets_received=fl.packets_received,
                    duration_seconds=fl.duration_seconds, start_time=fl.start_time,
                    end_time=fl.end_time, flow_state=fl.flow_state,
                    application_protocol=fl.application_protocol,
                    is_encrypted=fl.is_encrypted, is_internal=fl.is_internal,
                    threat_tags=fl.threat_tags,
                )
                self.db.add(m)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for flow %s: %s", fid, exc)

        self._flows[fid] = fl
        self._src_flow_index[fl.source_ip].append(fid)
        self._dst_flow_index[fl.dest_ip].append(fid)

        # Run detections
        self._run_detections(fl)
        return fl

    def record_flows_batch(self, flows: List[Dict[str, Any]]) -> List[TrafficFlow]:
        """Record multiple flows."""
        return [self.record_flow(f) for f in flows]

    def get_flows(self, filters: Dict[str, Any] = None) -> List[TrafficFlow]:
        """Retrieve flows with optional filters."""
        filters = filters or {}
        result = list(self._flows.values())
        if "source_ip" in filters:
            result = [f for f in result if f.source_ip == filters["source_ip"]]
        if "dest_ip" in filters:
            result = [f for f in result if f.dest_ip == filters["dest_ip"]]
        if "protocol" in filters:
            result = [f for f in result if f.protocol == filters["protocol"]]
        if "flow_state" in filters:
            result = [f for f in result if f.flow_state == filters["flow_state"]]
        if "application_protocol" in filters:
            result = [f for f in result if f.application_protocol == filters["application_protocol"]]
        if "is_internal" in filters:
            result = [f for f in result if f.is_internal == filters["is_internal"]]
        if "since" in filters:
            result = [f for f in result if f.start_time >= filters["since"]]
        if "limit" in filters:
            result = result[: int(filters["limit"])]
        return result

    def get_flow(self, flow_id: str) -> Optional[TrafficFlow]:
        """Get a single flow by ID."""
        return self._flows.get(flow_id)

    # ================================================================
    # Segment Management
    # ================================================================

    def create_segment(self, name: str, cidr: str, segment_type: str = "lan",
                       trust_level: str = "trusted", allowed_protocols: List[str] = None,
                       bandwidth_limit_mbps: float = 0.0,
                       devices_count: int = 0) -> NetworkSegment:
        sid = f"SEG-{uuid.uuid4().hex[:8]}"
        seg = NetworkSegment(
            segment_id=sid, name=name, cidr=cidr,
            segment_type=segment_type, trust_level=trust_level,
            allowed_protocols=allowed_protocols or [],
            bandwidth_limit_mbps=bandwidth_limit_mbps,
            devices_count=devices_count,
        )
        if self._use_db:
            try:
                m = NetworkSegmentModel(
                    segment_id=seg.segment_id, name=seg.name, cidr=seg.cidr,
                    segment_type=seg.segment_type, trust_level=seg.trust_level,
                    allowed_protocols=seg.allowed_protocols,
                    bandwidth_limit_mbps=seg.bandwidth_limit_mbps,
                    devices_count=seg.devices_count,
                )
                self.db.add(m)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for segment %s: %s", sid, exc)
        self._segments[sid] = seg
        return seg

    def get_segments(self) -> List[NetworkSegment]:
        return list(self._segments.values())

    def get_segment(self, segment_id: str) -> Optional[NetworkSegment]:
        return self._segments.get(segment_id)

    def update_segment(self, segment_id: str, **kwargs) -> Optional[NetworkSegment]:
        seg = self._segments.get(segment_id)
        if not seg:
            return None
        for k, v in kwargs.items():
            if hasattr(seg, k):
                setattr(seg, k, v)
        if self._use_db:
            try:
                m = self.db.query(NetworkSegmentModel).filter_by(segment_id=segment_id).first()
                if m:
                    for k, v in kwargs.items():
                        if hasattr(m, k):
                            setattr(m, k, v)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB update failed for segment %s: %s", segment_id, exc)
        return seg

    def delete_segment(self, segment_id: str) -> bool:
        if segment_id not in self._segments:
            return False
        del self._segments[segment_id]
        if self._use_db:
            try:
                self.db.query(NetworkSegmentModel).filter_by(segment_id=segment_id).delete()
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB delete failed for segment %s: %s", segment_id, exc)
        return True

    # ================================================================
    # Baselines
    # ================================================================

    def build_traffic_baseline(self, segment_id: str) -> List[TrafficBaseline]:
        """Compute traffic baselines for a segment from recorded flows."""
        seg = self._segments.get(segment_id)
        if not seg:
            return []

        # Collect flows that belong to this segment (simplified: match CIDR prefix)
        cidr_prefix = seg.cidr.rsplit(".", 1)[0] if "." in seg.cidr else seg.cidr
        segment_flows = [
            f for f in self._flows.values()
            if f.source_ip.startswith(cidr_prefix) or f.dest_ip.startswith(cidr_prefix)
        ]
        if not segment_flows:
            return []

        baselines = []
        now = datetime.now(timezone.utc)

        # Bytes-per-flow baseline
        bytes_vals = [f.bytes_sent + f.bytes_received for f in segment_flows]
        bl_bytes = TrafficBaseline(
            baseline_id=f"BL-{uuid.uuid4().hex[:8]}",
            network_segment=segment_id,
            metric_name="bytes_per_flow",
            expected_value=statistics.mean(bytes_vals),
            std_deviation=statistics.stdev(bytes_vals) if len(bytes_vals) > 1 else 0.0,
            peak_value=max(bytes_vals),
            off_peak_value=min(bytes_vals),
            last_updated=now,
        )
        baselines.append(bl_bytes)

        # Duration baseline
        dur_vals = [f.duration_seconds for f in segment_flows]
        bl_dur = TrafficBaseline(
            baseline_id=f"BL-{uuid.uuid4().hex[:8]}",
            network_segment=segment_id,
            metric_name="duration_seconds",
            expected_value=statistics.mean(dur_vals),
            std_deviation=statistics.stdev(dur_vals) if len(dur_vals) > 1 else 0.0,
            peak_value=max(dur_vals),
            off_peak_value=min(dur_vals),
            last_updated=now,
        )
        baselines.append(bl_dur)

        # Flows-per-minute baseline
        if segment_flows:
            time_span = max(1.0, (now - min(f.start_time for f in segment_flows)).total_seconds())
            fpm = len(segment_flows) / (time_span / 60)
            bl_fpm = TrafficBaseline(
                baseline_id=f"BL-{uuid.uuid4().hex[:8]}",
                network_segment=segment_id,
                metric_name="flows_per_minute",
                expected_value=fpm,
                std_deviation=0.0,
                peak_value=fpm,
                off_peak_value=fpm,
                last_updated=now,
            )
            baselines.append(bl_fpm)

        # Persist
        for bl in baselines:
            self._baselines[bl.baseline_id] = bl
            if self._use_db:
                try:
                    m = TrafficBaselineModel(
                        baseline_id=bl.baseline_id, network_segment=bl.network_segment,
                        metric_name=bl.metric_name, expected_value=bl.expected_value,
                        std_deviation=bl.std_deviation, peak_value=bl.peak_value,
                        off_peak_value=bl.off_peak_value, sample_period=bl.sample_period,
                        last_updated=bl.last_updated,
                    )
                    self.db.add(m)
                except Exception:
                    pass
            if self._use_db:
                try:
                    self.db.commit()
                except Exception:
                    self.db.rollback()

        return baselines

    def get_baselines(self, segment_id: str) -> List[TrafficBaseline]:
        return [b for b in self._baselines.values() if b.network_segment == segment_id]

    # ================================================================
    # Anomaly Management
    # ================================================================

    def _create_anomaly(self, anomaly_type: str, severity: str,
                        source_ip: str = "", dest_ip: str = "",
                        description: str = "", flow_ids: List[str] = None,
                        deviation: float = 0.0,
                        auto_action: str = "") -> TrafficAnomaly:
        aid = f"ANOM-{uuid.uuid4().hex[:8]}"
        anom = TrafficAnomaly(
            anomaly_id=aid, anomaly_type=anomaly_type, severity=severity,
            source_ip=source_ip, dest_ip=dest_ip, description=description,
            flow_ids=flow_ids or [], deviation_from_baseline=deviation,
            auto_action_taken=auto_action,
        )
        self._anomalies[aid] = anom
        if self._use_db:
            try:
                m = TrafficAnomalyModel(
                    anomaly_id=anom.anomaly_id, anomaly_type=anom.anomaly_type,
                    severity=anom.severity, source_ip=anom.source_ip,
                    dest_ip=anom.dest_ip, description=anom.description,
                    flow_ids=anom.flow_ids, deviation_from_baseline=anom.deviation_from_baseline,
                    detected_at=anom.detected_at, is_confirmed=anom.is_confirmed,
                    auto_action_taken=anom.auto_action_taken,
                )
                self.db.add(m)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for anomaly %s: %s", aid, exc)
        logger.warning("ANOMALY DETECTED [%s] %s — %s", severity.upper(), anomaly_type, description)
        return anom

    def get_anomalies(self, filters: Dict[str, Any] = None) -> List[TrafficAnomaly]:
        filters = filters or {}
        result = list(self._anomalies.values())
        if "anomaly_type" in filters:
            result = [a for a in result if a.anomaly_type == filters["anomaly_type"]]
        if "severity" in filters:
            result = [a for a in result if a.severity == filters["severity"]]
        if "source_ip" in filters:
            result = [a for a in result if a.source_ip == filters["source_ip"]]
        if "is_confirmed" in filters:
            result = [a for a in result if a.is_confirmed == filters["is_confirmed"]]
        return result

    def confirm_anomaly(self, anomaly_id: str) -> Optional[TrafficAnomaly]:
        anom = self._anomalies.get(anomaly_id)
        if not anom:
            return None
        anom.is_confirmed = True
        if self._use_db:
            try:
                m = self.db.query(TrafficAnomalyModel).filter_by(anomaly_id=anomaly_id).first()
                if m:
                    m.is_confirmed = True
                    self.db.commit()
            except Exception:
                self.db.rollback()
        return anom

    def dismiss_anomaly(self, anomaly_id: str) -> bool:
        if anomaly_id not in self._anomalies:
            return False
        del self._anomalies[anomaly_id]
        if self._use_db:
            try:
                self.db.query(TrafficAnomalyModel).filter_by(anomaly_id=anomaly_id).delete()
                self.db.commit()
            except Exception:
                self.db.rollback()
        return True

    # ================================================================
    # Detection Engine
    # ================================================================

    def _run_detections(self, flow: TrafficFlow) -> None:
        """Run all applicable detections against a new flow."""
        src = flow.source_ip
        recent_src = self._get_recent_flows_by_src(src, self._port_scan_window)
        self._detect_port_scan(src, recent_src)
        self._detect_data_exfiltration(src, self._get_recent_flows_by_src(src, self._exfil_window))
        self._detect_lateral_movement(src, self._get_recent_flows_by_src(src, self._lateral_window))
        self._detect_c2_communication(flow)
        self._detect_protocol_violation(flow)
        self._detect_encrypted_tunnel_abuse(flow)
        self._detect_slow_dos(flow)

        # Beaconing is checked per destination
        dst_flows = self._get_flows_to_dest(flow.dest_ip)
        if len(dst_flows) >= 5:
            self._detect_beaconing(flow.dest_ip, dst_flows)

    def _get_recent_flows_by_src(self, src_ip: str, window_sec: int) -> List[TrafficFlow]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_sec)
        fids = self._src_flow_index.get(src_ip, [])
        return [self._flows[fid] for fid in fids
                if fid in self._flows and self._flows[fid].start_time >= cutoff]

    def _get_flows_to_dest(self, dest_ip: str) -> List[TrafficFlow]:
        fids = self._dst_flow_index.get(dest_ip, [])
        return [self._flows[fid] for fid in fids if fid in self._flows]

    # ---------- Port Scan ----------
    def _detect_port_scan(self, source_ip: str, recent_flows: List[TrafficFlow]) -> Optional[TrafficAnomaly]:
        """Port scan: >20 unique dest ports from same source in 60s."""
        unique_ports = {f.dest_port for f in recent_flows}
        if len(unique_ports) > self._port_scan_threshold:
            fids = [f.flow_id for f in recent_flows]
            return self._create_anomaly(
                TrafficAnomalyType.PORT_SCAN.value, "high",
                source_ip=source_ip,
                description=f"Port scan detected: {len(unique_ports)} unique ports probed in {self._port_scan_window}s",
                flow_ids=fids,
                deviation=float(len(unique_ports)),
            )
        return None

    # ---------- DNS Tunneling ----------
    def _detect_dns_tunneling(self, dns_query: DNSQuery) -> Optional[TrafficAnomaly]:
        """DNS tunneling: long subdomains, high query rate, TXT abuse."""
        reasons = []
        parts = dns_query.query_name.split(".")
        if parts and len(parts[0]) > self._dns_subdomain_len:
            reasons.append(f"subdomain length {len(parts[0])} chars")
        if dns_query.query_type == "TXT":
            # TXT record abuse — check rate
            recent = [qid for qid in self._dns_by_src.get(dns_query.source_ip, [])
                       if qid in self._dns_queries and self._dns_queries[qid].query_type == "TXT"]
            if len(recent) > 10:
                reasons.append(f"high TXT query rate ({len(recent)} queries)")
        if self._is_dga_domain(dns_query.query_name):
            reasons.append("DGA-like domain detected")

        if reasons:
            dns_query.is_suspicious = True
            dns_query.suspicion_reason = "; ".join(reasons)
            return self._create_anomaly(
                TrafficAnomalyType.DNS_TUNNELING.value, "high",
                source_ip=dns_query.source_ip,
                description=f"DNS tunneling indicators: {'; '.join(reasons)} — query={dns_query.query_name}",
            )
        return None

    # ---------- Beaconing ----------
    def _detect_beaconing(self, dest_ip: str, flow_history: List[TrafficFlow]) -> Optional[TrafficAnomaly]:
        """Beaconing: regular-interval connections to same dest (C2 callback).
        Uses simplified FFT-based periodicity detection."""
        if len(flow_history) < 5:
            return None

        # Sort by start_time
        sorted_flows = sorted(flow_history, key=lambda f: f.start_time)
        intervals = []
        for i in range(1, len(sorted_flows)):
            dt = (sorted_flows[i].start_time - sorted_flows[i - 1].start_time).total_seconds()
            if dt > 0:
                intervals.append(dt)

        if len(intervals) < 4:
            return None

        mean_interval = statistics.mean(intervals)
        if mean_interval <= 0:
            return None

        # Check coefficient of variation — low CV = periodic
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev / mean_interval if mean_interval > 0 else 999.0

        if cv < self._beacon_tolerance:
            fids = [f.flow_id for f in sorted_flows]
            return self._create_anomaly(
                TrafficAnomalyType.BEACONING.value, "critical",
                dest_ip=dest_ip,
                source_ip=sorted_flows[0].source_ip,
                description=(
                    f"Beaconing detected to {dest_ip}: interval ~{mean_interval:.1f}s "
                    f"(CV={cv:.3f}), {len(sorted_flows)} connections"
                ),
                flow_ids=fids,
                deviation=cv,
            )
        return None

    # ---------- Data Exfiltration ----------
    def _detect_data_exfiltration(self, source_ip: str, recent_flows: List[TrafficFlow]) -> Optional[TrafficAnomaly]:
        """Data exfiltration: >100 MB outbound to single external IP in 1 hour."""
        dest_bytes: Dict[str, int] = defaultdict(int)
        dest_fids: Dict[str, List[str]] = defaultdict(list)
        for f in recent_flows:
            if not f.is_internal:
                dest_bytes[f.dest_ip] += f.bytes_sent
                dest_fids[f.dest_ip].append(f.flow_id)

        for dip, total in dest_bytes.items():
            if total > self._exfil_bytes_threshold:
                mb = total / (1024 * 1024)
                return self._create_anomaly(
                    TrafficAnomalyType.DATA_EXFILTRATION.value, "critical",
                    source_ip=source_ip, dest_ip=dip,
                    description=f"Potential data exfiltration: {mb:.1f} MB sent to {dip} in {self._exfil_window}s",
                    flow_ids=dest_fids[dip],
                    deviation=total / self._exfil_bytes_threshold,
                )
        return None

    # ---------- Lateral Movement ----------
    def _detect_lateral_movement(self, source_ip: str, recent_flows: List[TrafficFlow]) -> Optional[TrafficAnomaly]:
        """Lateral movement: internal IP accessing >5 internal hosts on admin ports in 10 min."""
        admin_hosts: Set[str] = set()
        fids = []
        for f in recent_flows:
            if f.is_internal and f.dest_port in ADMIN_PORTS:
                admin_hosts.add(f.dest_ip)
                fids.append(f.flow_id)

        if len(admin_hosts) > self._lateral_hosts_threshold:
            return self._create_anomaly(
                TrafficAnomalyType.LATERAL_MOVEMENT.value, "critical",
                source_ip=source_ip,
                description=(
                    f"Lateral movement: {source_ip} accessed {len(admin_hosts)} internal hosts "
                    f"on admin ports in {self._lateral_window}s"
                ),
                flow_ids=fids,
                deviation=float(len(admin_hosts)),
            )
        return None

    # ---------- C2 Communication ----------
    def _detect_c2_communication(self, flow: TrafficFlow) -> Optional[TrafficAnomaly]:
        """C2 comms: known-bad IPs or DGA-looking domain inferred from flow."""
        if flow.dest_ip in KNOWN_BAD_IPS:
            return self._create_anomaly(
                TrafficAnomalyType.C2_COMMUNICATION.value, "critical",
                source_ip=flow.source_ip, dest_ip=flow.dest_ip,
                description=f"Connection to known-bad IP: {flow.dest_ip}",
                flow_ids=[flow.flow_id],
            )
        return None

    # ---------- Protocol Violation ----------
    def _detect_protocol_violation(self, flow: TrafficFlow) -> Optional[TrafficAnomaly]:
        """Non-standard protocol on standard port."""
        expected = STANDARD_PORT_PROTOCOL.get(flow.dest_port)
        if expected and flow.application_protocol != "unknown" and flow.application_protocol != expected:
            return self._create_anomaly(
                TrafficAnomalyType.PROTOCOL_VIOLATION.value, "medium",
                source_ip=flow.source_ip, dest_ip=flow.dest_ip,
                description=(
                    f"Protocol violation: {flow.application_protocol} on port {flow.dest_port} "
                    f"(expected {expected})"
                ),
                flow_ids=[flow.flow_id],
            )
        return None

    # ---------- Encrypted Tunnel Abuse ----------
    def _detect_encrypted_tunnel_abuse(self, flow: TrafficFlow) -> Optional[TrafficAnomaly]:
        """SSH/VPN tunnels carrying unusual traffic volumes."""
        if flow.application_protocol in ("ssh", "vpn") and flow.bytes_sent > 50 * 1024 * 1024:
            mb = flow.bytes_sent / (1024 * 1024)
            return self._create_anomaly(
                TrafficAnomalyType.ENCRYPTED_TUNNEL_ABUSE.value, "high",
                source_ip=flow.source_ip, dest_ip=flow.dest_ip,
                description=f"Encrypted tunnel abuse: {mb:.1f} MB through {flow.application_protocol} tunnel",
                flow_ids=[flow.flow_id],
                deviation=flow.bytes_sent / (50 * 1024 * 1024),
            )
        return None

    # ---------- Slow DoS ----------
    def _detect_slow_dos(self, flow: TrafficFlow) -> Optional[TrafficAnomaly]:
        """Many half-open connections from distributed sources."""
        # Count active/reset flows to same dest
        dst_flows = self._get_flows_to_dest(flow.dest_ip)
        half_open = [f for f in dst_flows if f.flow_state in ("active", "reset") and f.packets_received == 0]
        if len(half_open) > self._slow_dos_half_open:
            sources = {f.source_ip for f in half_open}
            return self._create_anomaly(
                TrafficAnomalyType.SLOW_DOS.value, "high",
                dest_ip=flow.dest_ip,
                description=(
                    f"Slow DoS: {len(half_open)} half-open connections to {flow.dest_ip} "
                    f"from {len(sources)} sources"
                ),
                flow_ids=[f.flow_id for f in half_open[:20]],
                deviation=float(len(half_open)),
            )
        return None

    # ---------- DGA Domain Detection ----------
    def _is_dga_domain(self, domain: str) -> bool:
        """Entropy + consonant ratio check for algorithmically generated domains."""
        # Extract second-level domain
        parts = domain.rstrip(".").split(".")
        if len(parts) < 2:
            return False
        sld = parts[-2] if len(parts) >= 2 else parts[0]

        if len(sld) < 6:
            return False

        # Shannon entropy
        entropy = self._shannon_entropy(sld)
        if entropy < self._dga_entropy_threshold:
            return False

        # Consonant ratio
        vowels = set("aeiou")
        consonants = sum(1 for c in sld.lower() if c.isalpha() and c not in vowels)
        alpha = sum(1 for c in sld.lower() if c.isalpha())
        if alpha == 0:
            return False
        ratio = consonants / alpha
        return ratio >= self._dga_consonant_ratio

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = Counter(text.lower())
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    # ================================================================
    # DNS Management
    # ================================================================

    def record_dns_query(self, query_data: Dict[str, Any]) -> DNSQuery:
        qid = query_data.get("query_id", f"DNS-{uuid.uuid4().hex[:10]}")
        now = datetime.now(timezone.utc)
        q = DNSQuery(
            query_id=qid,
            source_ip=query_data.get("source_ip", "0.0.0.0"),
            query_name=query_data.get("query_name", ""),
            query_type=query_data.get("query_type", "A"),
            response_ip=query_data.get("response_ip", ""),
            response_code=query_data.get("response_code", "NOERROR"),
            timestamp=query_data.get("timestamp", now),
        )

        # Run DNS tunneling detection
        self._detect_dns_tunneling(q)

        # Persist
        if self._use_db:
            try:
                m = DNSQueryModel(
                    query_id=q.query_id, source_ip=q.source_ip,
                    query_name=q.query_name, query_type=q.query_type,
                    response_ip=q.response_ip, response_code=q.response_code,
                    is_suspicious=q.is_suspicious, suspicion_reason=q.suspicion_reason,
                    timestamp=q.timestamp,
                )
                self.db.add(m)
                self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for DNS query %s: %s", qid, exc)

        self._dns_queries[qid] = q
        self._dns_by_src[q.source_ip].append(qid)
        return q

    def get_dns_queries(self, filters: Dict[str, Any] = None) -> List[DNSQuery]:
        filters = filters or {}
        result = list(self._dns_queries.values())
        if "source_ip" in filters:
            result = [q for q in result if q.source_ip == filters["source_ip"]]
        if "query_type" in filters:
            result = [q for q in result if q.query_type == filters["query_type"]]
        if "is_suspicious" in filters:
            result = [q for q in result if q.is_suspicious == filters["is_suspicious"]]
        return result

    def get_top_queried_domains(self, limit: int = 10) -> List[Dict[str, Any]]:
        counter = Counter(q.query_name for q in self._dns_queries.values())
        return [{"domain": d, "count": c} for d, c in counter.most_common(limit)]

    def get_suspicious_dns(self) -> List[DNSQuery]:
        return [q for q in self._dns_queries.values() if q.is_suspicious]

    # ================================================================
    # Connection Profiles
    # ================================================================

    def build_connection_profile(self, ip_address: str) -> ConnectionProfile:
        """Build/refresh a connection profile for an IP."""
        pid = f"PROF-{hashlib.md5(ip_address.encode()).hexdigest()[:10]}"

        src_flows = [self._flows[fid] for fid in self._src_flow_index.get(ip_address, []) if fid in self._flows]
        dst_flows = [self._flows[fid] for fid in self._dst_flow_index.get(ip_address, []) if fid in self._flows]
        all_flows = src_flows + dst_flows

        unique_dests = {f.dest_ip for f in src_flows}
        unique_ports = {f.dest_port for f in src_flows} | {f.source_port for f in dst_flows}
        protocols = list({f.protocol for f in all_flows})
        total_bytes = sum(f.bytes_sent + f.bytes_received for f in all_flows)
        durations = [f.duration_seconds for f in all_flows if f.duration_seconds > 0]

        first_seen = min((f.start_time for f in all_flows), default=None)
        last_seen = max((f.start_time for f in all_flows), default=None)

        # Heuristic: is_server if more inbound than outbound
        is_server = len(dst_flows) > len(src_flows) * 2
        # is_scanner if many unique destinations + ports
        is_scanner = len(unique_dests) > 50 and len(unique_ports) > 30

        profile = ConnectionProfile(
            profile_id=pid,
            ip_address=ip_address,
            unique_destinations=len(unique_dests),
            unique_ports=len(unique_ports),
            protocols_used=protocols,
            total_bytes=total_bytes,
            total_flows=len(all_flows),
            avg_flow_duration=statistics.mean(durations) if durations else 0.0,
            peak_bandwidth_mbps=0.0,  # would need time-series for real calc
            countries_connected=[],    # would need GeoIP
            first_seen=first_seen,
            last_seen=last_seen,
            is_server=is_server,
            is_scanner=is_scanner,
        )

        self._profiles[ip_address] = profile
        if self._use_db:
            try:
                existing = self.db.query(ConnectionProfileModel).filter_by(ip_address=ip_address).first()
                if existing:
                    for attr in ("unique_destinations", "unique_ports", "protocols_used",
                                 "total_bytes", "total_flows", "avg_flow_duration",
                                 "is_server", "is_scanner", "first_seen", "last_seen"):
                        setattr(existing, attr, getattr(profile, attr))
                    self.db.commit()
                else:
                    m = ConnectionProfileModel(
                        profile_id=profile.profile_id, ip_address=ip_address,
                        unique_destinations=profile.unique_destinations,
                        unique_ports=profile.unique_ports,
                        protocols_used=profile.protocols_used,
                        total_bytes=profile.total_bytes,
                        total_flows=profile.total_flows,
                        avg_flow_duration=profile.avg_flow_duration,
                        is_server=profile.is_server,
                        is_scanner=profile.is_scanner,
                        first_seen=profile.first_seen,
                        last_seen=profile.last_seen,
                    )
                    self.db.add(m)
                    self.db.commit()
            except Exception as exc:
                self.db.rollback()
                logger.warning("DB write failed for profile %s: %s", ip_address, exc)

        return profile

    def get_connection_profile(self, ip_address: str) -> Optional[ConnectionProfile]:
        return self._profiles.get(ip_address)

    def list_profiles(self) -> List[ConnectionProfile]:
        return list(self._profiles.values())

    # ================================================================
    # Analytics
    # ================================================================

    def get_bandwidth_usage(self, segment_id: str = None, period: str = "1h") -> Dict[str, Any]:
        """Bandwidth usage stats, optionally by segment."""
        flows = list(self._flows.values())
        if segment_id:
            seg = self._segments.get(segment_id)
            if seg:
                prefix = seg.cidr.rsplit(".", 1)[0] if "." in seg.cidr else seg.cidr
                flows = [f for f in flows if f.source_ip.startswith(prefix) or f.dest_ip.startswith(prefix)]

        total_bytes = sum(f.bytes_sent + f.bytes_received for f in flows)
        inbound = sum(f.bytes_received for f in flows)
        outbound = sum(f.bytes_sent for f in flows)
        return {
            "segment_id": segment_id,
            "period": period,
            "total_bytes": total_bytes,
            "inbound_bytes": inbound,
            "outbound_bytes": outbound,
            "total_mb": round(total_bytes / (1024 * 1024), 2) if total_bytes else 0,
            "flow_count": len(flows),
        }

    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Top talkers by total bytes."""
        ip_bytes: Dict[str, int] = defaultdict(int)
        for f in self._flows.values():
            ip_bytes[f.source_ip] += f.bytes_sent
            ip_bytes[f.dest_ip] += f.bytes_received
        sorted_ips = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"ip": ip, "total_bytes": b, "total_mb": round(b / (1024 * 1024), 2)} for ip, b in sorted_ips]

    def get_protocol_distribution(self) -> Dict[str, int]:
        """Count of flows per protocol."""
        counter = Counter(f.protocol for f in self._flows.values())
        return dict(counter)

    def get_geographic_destinations(self) -> List[Dict[str, Any]]:
        """External destination IPs (GeoIP would enrich in production)."""
        ext_ips = Counter(
            f.dest_ip for f in self._flows.values() if not f.is_internal
        )
        return [{"ip": ip, "flow_count": c} for ip, c in ext_ips.most_common(20)]

    def get_internal_vs_external_ratio(self) -> Dict[str, Any]:
        internal = sum(1 for f in self._flows.values() if f.is_internal)
        external = sum(1 for f in self._flows.values() if not f.is_internal)
        total = internal + external
        return {
            "internal": internal,
            "external": external,
            "total": total,
            "internal_pct": round(internal / total * 100, 1) if total else 0,
            "external_pct": round(external / total * 100, 1) if total else 0,
        }

    # ================================================================
    # Network Health & Dashboard
    # ================================================================

    def get_network_health(self) -> Dict[str, Any]:
        """Overall network health from traffic perspective."""
        total_flows = len(self._flows)
        active_flows = sum(1 for f in self._flows.values() if f.flow_state == "active")
        total_anomalies = len(self._anomalies)
        critical_anomalies = sum(1 for a in self._anomalies.values() if a.severity == "critical")
        suspicious_dns = sum(1 for q in self._dns_queries.values() if q.is_suspicious)

        # Health score: 100 base, deduct for anomalies
        score = 100
        score -= critical_anomalies * 15
        score -= (total_anomalies - critical_anomalies) * 5
        score -= min(suspicious_dns * 2, 20)
        score = max(0, score)

        if score >= 80:
            status = "healthy"
        elif score >= 50:
            status = "degraded"
        else:
            status = "critical"

        return {
            "score": score,
            "status": status,
            "total_flows": total_flows,
            "active_flows": active_flows,
            "total_anomalies": total_anomalies,
            "critical_anomalies": critical_anomalies,
            "suspicious_dns_queries": suspicious_dns,
            "segments_monitored": len(self._segments),
            "profiles_tracked": len(self._profiles),
        }

    def get_dashboard(self) -> Dict[str, Any]:
        """Aggregated dashboard for network traffic."""
        total_flows = len(self._flows)
        now = datetime.now(timezone.utc)

        # Flows/sec approximation
        recent_cutoff = now - timedelta(minutes=5)
        recent_flows = [f for f in self._flows.values() if f.start_time >= recent_cutoff]
        flows_per_sec = len(recent_flows) / 300 if recent_flows else 0

        # Bandwidth (last hour)
        bw = self.get_bandwidth_usage(period="1h")

        return {
            "total_flows": total_flows,
            "flows_per_second": round(flows_per_sec, 2),
            "bandwidth": bw,
            "anomalies": {
                "total": len(self._anomalies),
                "critical": sum(1 for a in self._anomalies.values() if a.severity == "critical"),
                "high": sum(1 for a in self._anomalies.values() if a.severity == "high"),
                "medium": sum(1 for a in self._anomalies.values() if a.severity == "medium"),
                "recent": [
                    {
                        "anomaly_id": a.anomaly_id,
                        "type": a.anomaly_type,
                        "severity": a.severity,
                        "description": a.description,
                        "detected_at": a.detected_at.isoformat() if a.detected_at else None,
                    }
                    for a in sorted(self._anomalies.values(), key=lambda x: x.detected_at, reverse=True)[:5]
                ],
            },
            "top_talkers": self.get_top_talkers(5),
            "suspicious_dns": len(self.get_suspicious_dns()),
            "protocol_distribution": self.get_protocol_distribution(),
            "internal_external": self.get_internal_vs_external_ratio(),
            "segments": [
                {"segment_id": s.segment_id, "name": s.name, "type": s.segment_type,
                 "devices": s.devices_count}
                for s in self._segments.values()
            ],
            "network_health": self.get_network_health(),
        }
