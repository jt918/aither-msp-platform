"""
API Routes for SIEM Ingest Pipeline
Feeds external security events into the Cyber-911 incident response system.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from middleware.auth import get_current_user, require_admin
from core.database import get_sync_db

from services.msp.siem_ingest import SIEMIngestService

router = APIRouter(prefix="/siem", tags=["SIEM - Ingest Pipeline"])

# Singleton instance
_siem_instance: Optional[SIEMIngestService] = None


def get_siem() -> SIEMIngestService:
    """Get or create SIEMIngestService instance with DB persistence."""
    global _siem_instance
    if _siem_instance is None:
        try:
            db_gen = get_sync_db()
            db = next(db_gen)
            _siem_instance = SIEMIngestService(db=db)
        except Exception:
            _siem_instance = SIEMIngestService()
    return _siem_instance


# ========== Pydantic Models ==========

class SourceCreate(BaseModel):
    name: str
    source_type: str
    config: Optional[Dict[str, Any]] = None


class SourceUpdate(BaseModel):
    name: Optional[str] = None
    source_type: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None


class ParseRuleCreate(BaseModel):
    source_type: str
    field_mappings: Optional[Dict[str, str]] = None
    severity_mapping: Optional[Dict[str, str]] = None
    event_type_mapping: Optional[Dict[str, str]] = None
    is_default: bool = False


class ParseRuleUpdate(BaseModel):
    source_type: Optional[str] = None
    field_mappings: Optional[Dict[str, str]] = None
    severity_mapping: Optional[Dict[str, str]] = None
    event_type_mapping: Optional[Dict[str, str]] = None
    is_default: Optional[bool] = None


class CorrelationRuleCreate(BaseModel):
    name: str
    description: str = ""
    conditions: List[Dict[str, Any]]
    time_window_seconds: int = 300
    min_events: int = 1
    action: str = "create_incident"
    severity: str = "HIGH"
    threat_type: str = ""


class CorrelationRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    conditions: Optional[List[Dict[str, Any]]] = None
    time_window_seconds: Optional[int] = None
    min_events: Optional[int] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    threat_type: Optional[str] = None
    is_enabled: Optional[bool] = None


class SyslogIngest(BaseModel):
    raw_message: str
    source_ip: str = ""


class WindowsEventIngest(BaseModel):
    event_xml: str


class GenericEventIngest(BaseModel):
    event_type: str = ""
    severity: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    hostname: str = ""
    user: str = ""
    message: str = ""
    timestamp: Optional[str] = None
    source_id: str = "generic"
    extra: Optional[Dict[str, Any]] = None


class EventFilter(BaseModel):
    source_id: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    since: Optional[str] = None
    limit: int = 100


# ========== Helper ==========

def _source_to_dict(src) -> Dict[str, Any]:
    return {
        "source_id": src.source_id,
        "name": src.name,
        "source_type": src.source_type,
        "config": src.config,
        "is_enabled": src.is_enabled,
        "events_received": src.events_received,
        "events_processed": src.events_processed,
        "last_event_at": src.last_event_at.isoformat() if src.last_event_at else None,
        "created_at": src.created_at.isoformat() if src.created_at else None,
    }


def _event_to_dict(evt) -> Dict[str, Any]:
    return {
        "event_id": evt.event_id,
        "source_id": evt.source_id,
        "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
        "event_type": evt.event_type,
        "severity_raw": evt.severity_raw,
        "source_ip": evt.source_ip,
        "dest_ip": evt.dest_ip,
        "hostname": evt.hostname,
        "user": evt.user,
        "message": evt.message[:500] if evt.message else "",
        "parsed": evt.parsed,
    }


def _parse_rule_to_dict(rule) -> Dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "source_type": rule.source_type,
        "field_mappings": rule.field_mappings,
        "severity_mapping": rule.severity_mapping,
        "event_type_mapping": rule.event_type_mapping,
        "is_default": rule.is_default,
    }


def _correlation_rule_to_dict(rule) -> Dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "conditions": rule.conditions,
        "time_window_seconds": rule.time_window_seconds,
        "min_events": rule.min_events,
        "action": rule.action,
        "severity": rule.severity,
        "threat_type": rule.threat_type,
        "is_enabled": rule.is_enabled,
    }


# ========== Source CRUD ==========

@router.post("/sources")
async def create_source(data: SourceCreate, current_user: dict = Depends(require_admin)):
    """Register a new SIEM event source."""
    service = get_siem()
    src = service.register_source(
        name=data.name,
        source_type=data.source_type,
        config=data.config,
    )
    return _source_to_dict(src)


@router.get("/sources")
async def list_sources():
    """List all registered SIEM sources."""
    service = get_siem()
    return {
        "sources": [_source_to_dict(s) for s in service.list_sources()],
        "total": len(service.sources),
    }


@router.get("/sources/{source_id}")
async def get_source(source_id: str):
    """Get a specific SIEM source."""
    service = get_siem()
    src = service.get_source(source_id)
    if not src:
        raise HTTPException(status_code=404, detail="Source not found")
    return _source_to_dict(src)


@router.patch("/sources/{source_id}")
async def update_source(source_id: str, data: SourceUpdate, current_user: dict = Depends(require_admin)):
    """Update a SIEM source."""
    service = get_siem()
    updates = {k: v for k, v in data.dict().items() if v is not None}
    src = service.update_source(source_id, **updates)
    if not src:
        raise HTTPException(status_code=404, detail="Source not found")
    return _source_to_dict(src)


@router.delete("/sources/{source_id}")
async def delete_source(source_id: str, current_user: dict = Depends(require_admin)):
    """Delete a SIEM source."""
    service = get_siem()
    if not service.delete_source(source_id):
        raise HTTPException(status_code=404, detail="Source not found")
    return {"success": True, "deleted": source_id}


# ========== Ingest Endpoints ==========

@router.post("/ingest/syslog")
async def ingest_syslog(data: SyslogIngest, current_user: dict = Depends(require_admin)):
    """Ingest a syslog message (RFC 5424 / RFC 3164)."""
    service = get_siem()
    evt = service.ingest_syslog(data.raw_message, data.source_ip)
    return _event_to_dict(evt)


@router.post("/ingest/windows-event")
async def ingest_windows_event(data: WindowsEventIngest, current_user: dict = Depends(require_admin)):
    """Ingest a Windows Event Log XML record."""
    service = get_siem()
    evt = service.ingest_windows_event(data.event_xml)
    return _event_to_dict(evt)


@router.post("/ingest/elastic")
async def ingest_elastic(alert_json: Dict[str, Any], current_user: dict = Depends(require_admin)):
    """Ingest an Elasticsearch / Wazuh alert JSON."""
    service = get_siem()
    evt = service.ingest_elastic_alert(alert_json)
    return _event_to_dict(evt)


@router.post("/ingest/generic")
async def ingest_generic(data: GenericEventIngest, current_user: dict = Depends(require_admin)):
    """Ingest a generic JSON security event."""
    service = get_siem()
    event_dict = data.dict()
    if data.extra:
        event_dict.update(data.extra)
    evt = service.ingest_generic(event_dict)
    return _event_to_dict(evt)


@router.post("/ingest/batch")
async def ingest_batch(events: List[Dict[str, Any]], current_user: dict = Depends(require_admin)):
    """Bulk ingest multiple events."""
    service = get_siem()
    result = service.ingest_batch(events)
    return result


# ========== Correlation ==========

@router.post("/correlate")
async def run_correlation(current_user: dict = Depends(require_admin)):
    """Trigger correlation check against recent events."""
    service = get_siem()
    results = service.correlate_events()
    return {
        "correlations": results,
        "rules_checked": len(service.correlation_rules),
        "triggered": len(results),
    }


# ========== Event Log ==========

@router.get("/events")
async def get_events(
    source_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    """Query ingested events with optional filters."""
    service = get_siem()
    filters = {
        "source_id": source_id,
        "event_type": event_type,
        "severity": severity,
        "hostname": hostname,
        "source_ip": source_ip,
        "since": since,
        "limit": limit,
    }
    events = service.get_event_log(filters)
    return {"events": events, "total": len(events)}


# ========== Parse Rules ==========

@router.post("/parse-rules")
async def create_parse_rule(data: ParseRuleCreate, current_user: dict = Depends(require_admin)):
    """Create a new parse/normalization rule."""
    service = get_siem()
    rule = service.create_parse_rule(
        source_type=data.source_type,
        field_mappings=data.field_mappings,
        severity_mapping=data.severity_mapping,
        event_type_mapping=data.event_type_mapping,
        is_default=data.is_default,
    )
    return _parse_rule_to_dict(rule)


@router.get("/parse-rules")
async def list_parse_rules(source_type: Optional[str] = Query(None)):
    """List parse rules, optionally filtered by source type."""
    service = get_siem()
    rules = service.list_parse_rules(source_type)
    return {"rules": [_parse_rule_to_dict(r) for r in rules], "total": len(rules)}


@router.patch("/parse-rules/{rule_id}")
async def update_parse_rule(rule_id: str, data: ParseRuleUpdate, current_user: dict = Depends(require_admin)):
    """Update a parse rule."""
    service = get_siem()
    updates = {k: v for k, v in data.dict().items() if v is not None}
    rule = service.update_parse_rule(rule_id, **updates)
    if not rule:
        raise HTTPException(status_code=404, detail="Parse rule not found")
    return _parse_rule_to_dict(rule)


# ========== Correlation Rules ==========

@router.post("/correlation-rules")
async def create_correlation_rule(data: CorrelationRuleCreate, current_user: dict = Depends(require_admin)):
    """Create a new correlation rule."""
    service = get_siem()
    rule = service.create_correlation_rule(
        name=data.name,
        description=data.description,
        conditions=data.conditions,
        time_window_seconds=data.time_window_seconds,
        min_events=data.min_events,
        action=data.action,
        severity=data.severity,
        threat_type=data.threat_type,
    )
    return _correlation_rule_to_dict(rule)


@router.get("/correlation-rules")
async def list_correlation_rules():
    """List all correlation rules."""
    service = get_siem()
    rules = service.list_correlation_rules()
    return {"rules": [_correlation_rule_to_dict(r) for r in rules], "total": len(rules)}


@router.patch("/correlation-rules/{rule_id}")
async def update_correlation_rule(rule_id: str, data: CorrelationRuleUpdate, current_user: dict = Depends(require_admin)):
    """Update a correlation rule."""
    service = get_siem()
    updates = {k: v for k, v in data.dict().items() if v is not None}
    rule = service.update_correlation_rule(rule_id, **updates)
    if not rule:
        raise HTTPException(status_code=404, detail="Correlation rule not found")
    return _correlation_rule_to_dict(rule)


# ========== Dashboard ==========

@router.get("/dashboard")
async def get_dashboard():
    """Get SIEM ingest dashboard: stats, events/sec, top sources."""
    service = get_siem()
    return service.get_dashboard()
