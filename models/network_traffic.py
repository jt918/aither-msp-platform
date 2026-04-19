"""
AITHER Platform - Network Traffic Analyzer Persistence Models

Tables for traffic flows, baselines, anomalies, network segments,
DNS queries, and connection profiles.
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON,
    Index,
)
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from core.database import Base


def _uuid():
    return str(uuid.uuid4())


# ============================================================
# Traffic Flow
# ============================================================

class TrafficFlowModel(Base):
    """Recorded network traffic flow."""
    __tablename__ = "traffic_flows"

    id = Column(String(36), primary_key=True, default=_uuid)
    flow_id = Column(String(40), unique=True, nullable=False, index=True)
    source_ip = Column(String(50), nullable=False, index=True)
    source_port = Column(Integer, nullable=False)
    dest_ip = Column(String(50), nullable=False, index=True)
    dest_port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False, index=True)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    packets_sent = Column(Integer, default=0)
    packets_received = Column(Integer, default=0)
    duration_seconds = Column(Float, default=0.0)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    flow_state = Column(String(20), default="active", index=True)
    application_protocol = Column(String(20), default="unknown")
    is_encrypted = Column(Boolean, default=False)
    is_internal = Column(Boolean, default=False)
    threat_tags = Column(JSON, default=list)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_tflow_src_dst", "source_ip", "dest_ip"),
        Index("ix_tflow_start", "start_time"),
    )


# ============================================================
# Traffic Baseline
# ============================================================

class TrafficBaselineModel(Base):
    """Traffic baseline metrics for anomaly detection."""
    __tablename__ = "traffic_baselines"

    id = Column(String(36), primary_key=True, default=_uuid)
    baseline_id = Column(String(40), unique=True, nullable=False, index=True)
    network_segment = Column(String(100), nullable=False, index=True)
    metric_name = Column(String(100), nullable=False)
    expected_value = Column(Float, default=0.0)
    std_deviation = Column(Float, default=0.0)
    peak_value = Column(Float, default=0.0)
    off_peak_value = Column(Float, default=0.0)
    sample_period = Column(String(50), default="24h")
    last_updated = Column(DateTime, default=func.now())

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_tbaseline_seg_metric", "network_segment", "metric_name"),
    )


# ============================================================
# Traffic Anomaly
# ============================================================

class TrafficAnomalyModel(Base):
    """Detected traffic anomaly."""
    __tablename__ = "traffic_anomalies"

    id = Column(String(36), primary_key=True, default=_uuid)
    anomaly_id = Column(String(40), unique=True, nullable=False, index=True)
    anomaly_type = Column(String(40), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    source_ip = Column(String(50), default="", index=True)
    dest_ip = Column(String(50), default="")
    description = Column(Text, default="")
    flow_ids = Column(JSON, default=list)
    deviation_from_baseline = Column(Float, default=0.0)
    detected_at = Column(DateTime, default=func.now())
    is_confirmed = Column(Boolean, default=False)
    auto_action_taken = Column(String(200), default="")

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_tanomaly_type_sev", "anomaly_type", "severity"),
    )


# ============================================================
# Network Segment
# ============================================================

class NetworkSegmentModel(Base):
    """Defined network segment / zone."""
    __tablename__ = "network_segments"

    id = Column(String(36), primary_key=True, default=_uuid)
    segment_id = Column(String(40), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    cidr = Column(String(50), nullable=False)
    segment_type = Column(String(20), default="lan", index=True)
    trust_level = Column(String(20), default="trusted")
    allowed_protocols = Column(JSON, default=list)
    bandwidth_limit_mbps = Column(Float, default=0.0)
    devices_count = Column(Integer, default=0)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


# ============================================================
# DNS Query
# ============================================================

class DNSQueryModel(Base):
    """Captured DNS query for analysis."""
    __tablename__ = "dns_queries"

    id = Column(String(36), primary_key=True, default=_uuid)
    query_id = Column(String(40), unique=True, nullable=False, index=True)
    source_ip = Column(String(50), nullable=False, index=True)
    query_name = Column(String(500), nullable=False, index=True)
    query_type = Column(String(10), default="A")
    response_ip = Column(String(50), default="")
    response_code = Column(String(20), default="NOERROR")
    is_suspicious = Column(Boolean, default=False, index=True)
    suspicion_reason = Column(Text, default="")
    timestamp = Column(DateTime, default=func.now(), index=True)

    created_at = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_dns_src_ts", "source_ip", "timestamp"),
    )


# ============================================================
# Connection Profile
# ============================================================

class ConnectionProfileModel(Base):
    """Aggregated connection profile for an IP address."""
    __tablename__ = "connection_profiles"

    id = Column(String(36), primary_key=True, default=_uuid)
    profile_id = Column(String(40), unique=True, nullable=False, index=True)
    ip_address = Column(String(50), nullable=False, unique=True, index=True)
    unique_destinations = Column(Integer, default=0)
    unique_ports = Column(Integer, default=0)
    protocols_used = Column(JSON, default=list)
    total_bytes = Column(Integer, default=0)
    total_flows = Column(Integer, default=0)
    avg_flow_duration = Column(Float, default=0.0)
    peak_bandwidth_mbps = Column(Float, default=0.0)
    countries_connected = Column(JSON, default=list)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    is_server = Column(Boolean, default=False)
    is_scanner = Column(Boolean, default=False)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
