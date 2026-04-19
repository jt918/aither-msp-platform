"""
AITHER Platform - Router Registry
Central registry of all API route modules.
"""

from api.routes.msp import router as msp_router
from api.routes.rmm import router as rmm_router
from api.routes.shield import router as shield_router
from api.routes.siem_ingest import router as siem_router
from api.routes.soar_playbook import router as soar_router
from api.routes.compliance_frameworks import router as compliance_router
from api.routes.bdr import router as bdr_router
from api.routes.billing_engine import router as billing_router
from api.routes.network_discovery import router as network_discovery_router
from api.routes.noc_dashboard import router as noc_router
from api.routes.cyber_911 import router as cyber_911_router
from api.routes.dark_web_monitor import router as dark_web_router
from api.routes.endpoint_sniffer import router as endpoint_sniffer_router
from api.routes.agent_protocol import router as agent_protocol_router
from api.routes.app_distribution import router as app_distribution_router
from api.routes.mdm_enhanced import router as mdm_router
from api.routes.notification_connector import router as notification_router
from api.routes.psa_connector import router as psa_router
from api.routes.signature_pipeline import router as signature_router
from api.routes.white_label import router as white_label_router
from api.routes.knowledge_base import router as knowledge_base_router

all_routers = [
    msp_router,
    rmm_router,
    shield_router,
    siem_router,
    soar_router,
    compliance_router,
    bdr_router,
    billing_router,
    network_discovery_router,
    noc_router,
    cyber_911_router,
    dark_web_router,
    endpoint_sniffer_router,
    agent_protocol_router,
    app_distribution_router,
    mdm_router,
    notification_router,
    psa_router,
    signature_router,
    white_label_router,
    knowledge_base_router,
]
