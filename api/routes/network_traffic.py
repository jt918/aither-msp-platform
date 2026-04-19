"""
API Routes for Network Traffic Analyzer Service
Monitors LAN/WAN/web traffic, detects suspicious flows, feeds threat scoring.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

try:
    from sqlalchemy.orm import Session
    from core.database import get_sync_db
    DB_AVAILABLE = True
except Exception:
    DB_AVAILABLE = False

from middleware.auth import get_current_user, require_admin

from services.msp.network_traffic_analyzer import (
    NetworkTrafficAnalyzerService,
    TrafficAnomalyType,
    SegmentType,
    TrustLevel,
)

router = APIRouter(prefix="/traffic", tags=["Network Traffic Analyzer"])


def _init_service() -> NetworkTrafficAnalyzerService:
    """Initialize service with DB if available."""
    if DB_AVAILABLE:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            return NetworkTrafficAnalyzerService(db=db)
        except Exception:
            pass
    return NetworkTrafficAnalyzerService()


service = _init_service()


# ========== Request/Response Models ==========

class FlowRequest(BaseModel):
    source_ip: str
    source_port: int = 0
    dest_ip: str
    dest_port: int = 0
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration_seconds: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    flow_state: str = "active"
    application_protocol: str = "unknown"
    is_encrypted: bool = False
    is_internal: bool = False
    threat_tags: List[str] = Field(default_factory=list)


class FlowBatchRequest(BaseModel):
    flows: List[FlowRequest]


class SegmentRequest(BaseModel):
    name: str
    cidr: str
    segment_type: str = "lan"
    trust_level: str = "trusted"
    allowed_protocols: List[str] = Field(default_factory=list)
    bandwidth_limit_mbps: float = 0.0
    devices_count: int = 0


class SegmentUpdate(BaseModel):
    name: Optional[str] = None
    cidr: Optional[str] = None
    segment_type: Optional[str] = None
    trust_level: Optional[str] = None
    allowed_protocols: Optional[List[str]] = None
    bandwidth_limit_mbps: Optional[float] = None
    devices_count: Optional[int] = None


class DNSQueryRequest(BaseModel):
    source_ip: str
    query_name: str
    query_type: str = "A"
    response_ip: str = ""
    response_code: str = "NOERROR"
    timestamp: Optional[datetime] = None


# ========== Flow Routes ==========

@router.post("/flows")
async def record_flow(req: FlowRequest, _user=Depends(get_current_user)):
    """Record a single traffic flow."""
    data = req.dict()
    flow = service.record_flow(data)
    return {"status": "recorded", "flow_id": flow.flow_id}


@router.post("/flows/batch")
async def record_flows_batch(req: FlowBatchRequest, _user=Depends(get_current_user)):
    """Record multiple traffic flows."""
    flows = service.record_flows_batch([f.dict() for f in req.flows])
    return {"status": "recorded", "count": len(flows), "flow_ids": [f.flow_id for f in flows]}


@router.get("/flows")
async def get_flows(
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    flow_state: Optional[str] = None,
    application_protocol: Optional[str] = None,
    limit: int = Query(100, le=1000),
    _user=Depends(get_current_user),
):
    """List traffic flows with filters."""
    filters: Dict[str, Any] = {"limit": limit}
    if source_ip:
        filters["source_ip"] = source_ip
    if dest_ip:
        filters["dest_ip"] = dest_ip
    if protocol:
        filters["protocol"] = protocol
    if flow_state:
        filters["flow_state"] = flow_state
    if application_protocol:
        filters["application_protocol"] = application_protocol
    flows = service.get_flows(filters)
    return {"flows": [_flow_dict(f) for f in flows], "count": len(flows)}


def _flow_dict(f) -> dict:
    return {
        "flow_id": f.flow_id, "source_ip": f.source_ip, "source_port": f.source_port,
        "dest_ip": f.dest_ip, "dest_port": f.dest_port, "protocol": f.protocol,
        "bytes_sent": f.bytes_sent, "bytes_received": f.bytes_received,
        "packets_sent": f.packets_sent, "packets_received": f.packets_received,
        "duration_seconds": f.duration_seconds,
        "start_time": f.start_time.isoformat() if f.start_time else None,
        "end_time": f.end_time.isoformat() if f.end_time else None,
        "flow_state": f.flow_state, "application_protocol": f.application_protocol,
        "is_encrypted": f.is_encrypted, "is_internal": f.is_internal,
        "threat_tags": f.threat_tags,
    }


# ========== Segment Routes ==========

@router.post("/segments")
async def create_segment(req: SegmentRequest, _user=Depends(get_current_user)):
    seg = service.create_segment(
        name=req.name, cidr=req.cidr, segment_type=req.segment_type,
        trust_level=req.trust_level, allowed_protocols=req.allowed_protocols,
        bandwidth_limit_mbps=req.bandwidth_limit_mbps, devices_count=req.devices_count,
    )
    return {"status": "created", "segment_id": seg.segment_id}


@router.get("/segments")
async def get_segments(_user=Depends(get_current_user)):
    segs = service.get_segments()
    return {"segments": [_seg_dict(s) for s in segs], "count": len(segs)}


@router.put("/segments/{segment_id}")
async def update_segment(segment_id: str, req: SegmentUpdate, _user=Depends(get_current_user)):
    updates = {k: v for k, v in req.dict().items() if v is not None}
    seg = service.update_segment(segment_id, **updates)
    if not seg:
        raise HTTPException(status_code=404, detail="Segment not found")
    return {"status": "updated", "segment": _seg_dict(seg)}


@router.delete("/segments/{segment_id}")
async def delete_segment(segment_id: str, _user=Depends(get_current_user)):
    if not service.delete_segment(segment_id):
        raise HTTPException(status_code=404, detail="Segment not found")
    return {"status": "deleted"}


def _seg_dict(s) -> dict:
    return {
        "segment_id": s.segment_id, "name": s.name, "cidr": s.cidr,
        "segment_type": s.segment_type, "trust_level": s.trust_level,
        "allowed_protocols": s.allowed_protocols,
        "bandwidth_limit_mbps": s.bandwidth_limit_mbps,
        "devices_count": s.devices_count,
    }


# ========== Baseline Routes ==========

@router.post("/segments/{segment_id}/build-baseline")
async def build_baseline(segment_id: str, _user=Depends(get_current_user)):
    baselines = service.build_traffic_baseline(segment_id)
    if not baselines:
        raise HTTPException(status_code=404, detail="Segment not found or no flows for baseline")
    return {"status": "built", "count": len(baselines),
            "baselines": [_bl_dict(b) for b in baselines]}


@router.get("/segments/{segment_id}/baselines")
async def get_baselines(segment_id: str, _user=Depends(get_current_user)):
    baselines = service.get_baselines(segment_id)
    return {"baselines": [_bl_dict(b) for b in baselines], "count": len(baselines)}


def _bl_dict(b) -> dict:
    return {
        "baseline_id": b.baseline_id, "network_segment": b.network_segment,
        "metric_name": b.metric_name, "expected_value": b.expected_value,
        "std_deviation": b.std_deviation, "peak_value": b.peak_value,
        "off_peak_value": b.off_peak_value, "sample_period": b.sample_period,
        "last_updated": b.last_updated.isoformat() if b.last_updated else None,
    }


# ========== Anomaly Routes ==========

@router.get("/anomalies")
async def get_anomalies(
    anomaly_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    _user=Depends(get_current_user),
):
    filters: Dict[str, Any] = {}
    if anomaly_type:
        filters["anomaly_type"] = anomaly_type
    if severity:
        filters["severity"] = severity
    if source_ip:
        filters["source_ip"] = source_ip
    anomalies = service.get_anomalies(filters)
    return {"anomalies": [_anom_dict(a) for a in anomalies], "count": len(anomalies)}


@router.post("/anomalies/{anomaly_id}/confirm")
async def confirm_anomaly(anomaly_id: str, _user=Depends(get_current_user)):
    anom = service.confirm_anomaly(anomaly_id)
    if not anom:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return {"status": "confirmed", "anomaly": _anom_dict(anom)}


@router.post("/anomalies/{anomaly_id}/dismiss")
async def dismiss_anomaly(anomaly_id: str, _user=Depends(get_current_user)):
    if not service.dismiss_anomaly(anomaly_id):
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return {"status": "dismissed"}


def _anom_dict(a) -> dict:
    return {
        "anomaly_id": a.anomaly_id, "anomaly_type": a.anomaly_type,
        "severity": a.severity, "source_ip": a.source_ip, "dest_ip": a.dest_ip,
        "description": a.description, "flow_ids": a.flow_ids,
        "deviation_from_baseline": a.deviation_from_baseline,
        "detected_at": a.detected_at.isoformat() if a.detected_at else None,
        "is_confirmed": a.is_confirmed, "auto_action_taken": a.auto_action_taken,
    }


# ========== DNS Routes ==========

@router.post("/dns")
async def record_dns_query(req: DNSQueryRequest, _user=Depends(get_current_user)):
    data = req.dict()
    q = service.record_dns_query(data)
    return {"status": "recorded", "query_id": q.query_id, "is_suspicious": q.is_suspicious}


@router.get("/dns")
async def get_dns_queries(
    source_ip: Optional[str] = None,
    query_type: Optional[str] = None,
    is_suspicious: Optional[bool] = None,
    _user=Depends(get_current_user),
):
    filters: Dict[str, Any] = {}
    if source_ip:
        filters["source_ip"] = source_ip
    if query_type:
        filters["query_type"] = query_type
    if is_suspicious is not None:
        filters["is_suspicious"] = is_suspicious
    queries = service.get_dns_queries(filters)
    return {"dns_queries": [_dns_dict(q) for q in queries], "count": len(queries)}


@router.get("/dns/top-domains")
async def get_top_domains(limit: int = Query(10, le=100), _user=Depends(get_current_user)):
    return {"top_domains": service.get_top_queried_domains(limit)}


@router.get("/dns/suspicious")
async def get_suspicious_dns(_user=Depends(get_current_user)):
    queries = service.get_suspicious_dns()
    return {"suspicious_queries": [_dns_dict(q) for q in queries], "count": len(queries)}


def _dns_dict(q) -> dict:
    return {
        "query_id": q.query_id, "source_ip": q.source_ip,
        "query_name": q.query_name, "query_type": q.query_type,
        "response_ip": q.response_ip, "response_code": q.response_code,
        "is_suspicious": q.is_suspicious, "suspicion_reason": q.suspicion_reason,
        "timestamp": q.timestamp.isoformat() if q.timestamp else None,
    }


# ========== Profile Routes ==========

@router.get("/profiles")
async def list_profiles(_user=Depends(get_current_user)):
    profiles = service.list_profiles()
    return {"profiles": [_prof_dict(p) for p in profiles], "count": len(profiles)}


@router.get("/profiles/{ip}")
async def get_profile(ip: str, _user=Depends(get_current_user)):
    # Build on-demand if not cached
    profile = service.get_connection_profile(ip)
    if not profile:
        profile = service.build_connection_profile(ip)
    return {"profile": _prof_dict(profile)}


def _prof_dict(p) -> dict:
    return {
        "profile_id": p.profile_id, "ip_address": p.ip_address,
        "unique_destinations": p.unique_destinations, "unique_ports": p.unique_ports,
        "protocols_used": p.protocols_used, "total_bytes": p.total_bytes,
        "total_flows": p.total_flows, "avg_flow_duration": p.avg_flow_duration,
        "peak_bandwidth_mbps": p.peak_bandwidth_mbps,
        "countries_connected": p.countries_connected,
        "first_seen": p.first_seen.isoformat() if p.first_seen else None,
        "last_seen": p.last_seen.isoformat() if p.last_seen else None,
        "is_server": p.is_server, "is_scanner": p.is_scanner,
    }


# ========== Analytics Routes ==========

@router.get("/bandwidth")
async def get_bandwidth(
    segment_id: Optional[str] = None,
    period: str = Query("1h"),
    _user=Depends(get_current_user),
):
    return service.get_bandwidth_usage(segment_id, period)


@router.get("/top-talkers")
async def get_top_talkers(limit: int = Query(10, le=100), _user=Depends(get_current_user)):
    return {"top_talkers": service.get_top_talkers(limit)}


@router.get("/protocols")
async def get_protocol_distribution(_user=Depends(get_current_user)):
    return {"protocols": service.get_protocol_distribution()}


@router.get("/geo-destinations")
async def get_geo_destinations(_user=Depends(get_current_user)):
    return {"destinations": service.get_geographic_destinations()}


# ========== Health & Dashboard ==========

@router.get("/network-health")
async def get_network_health(_user=Depends(get_current_user)):
    return service.get_network_health()


@router.get("/dashboard")
async def get_dashboard(_user=Depends(get_current_user)):
    return service.get_dashboard()
