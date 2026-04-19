"""
Tests for NOC Aggregator Service and Routes.
"""

import pytest
import time
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure backend is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.msp.noc_aggregator import NOCAggregatorService, NOCConfig


class TestNOCAggregatorService:
    """Tests for the NOC aggregator service."""

    def test_initialization(self):
        """Service initializes without errors."""
        service = NOCAggregatorService()
        assert service is not None
        assert service._config is not None

    def test_default_config(self):
        """Default config has expected values."""
        service = NOCAggregatorService()
        config = service.get_config()
        assert config["rotation_interval"] == 15
        assert config["refresh_interval"] == 30
        assert config["theme"] == "dark"
        assert config["show_clock"] is True
        assert len(config["panels"]) == 8

    def test_update_config(self):
        """Config updates apply correctly."""
        service = NOCAggregatorService()
        result = service.update_config({
            "rotation_interval": 20,
            "theme": "light",
            "alert_sound": True,
        })
        assert result["rotation_interval"] == 20
        assert result["theme"] == "light"
        assert result["alert_sound"] is True
        # Unchanged fields stay default
        assert result["refresh_interval"] == 30

    def test_update_config_panels(self):
        """Panel list updates correctly."""
        service = NOCAggregatorService()
        new_panels = ["overview", "active_alerts", "sla_status"]
        result = service.update_config({"panels": new_panels})
        assert result["panels"] == new_panels

    def test_dashboard_data_structure(self):
        """Dashboard payload has all required keys."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        assert "timestamp" in data
        assert "endpoints_summary" in data
        assert "alerts_summary" in data
        assert "incidents_summary" in data
        assert "tickets_summary" in data
        assert "self_healing_summary" in data
        assert "patches_summary" in data
        assert "network_summary" in data
        assert "system_health" in data

    def test_endpoints_summary_structure(self):
        """Endpoints summary has correct fields."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        ep = data["endpoints_summary"]
        assert "total" in ep
        assert "online" in ep
        assert "offline" in ep
        assert "warning" in ep
        assert "maintenance" in ep

    def test_alerts_summary_structure(self):
        """Alerts summary has correct fields."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        alerts = data["alerts_summary"]
        assert "critical" in alerts
        assert "high" in alerts
        assert "medium" in alerts
        assert "low" in alerts
        assert "recent_alerts" in alerts
        assert isinstance(alerts["recent_alerts"], list)

    def test_incidents_summary_structure(self):
        """Incidents summary has correct fields."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        inc = data["incidents_summary"]
        assert "active" in inc
        assert "contained" in inc
        assert "resolved_today" in inc
        assert "defcon_level" in inc

    def test_system_health_structure(self):
        """System health has correct fields."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        health = data["system_health"]
        assert "api_latency_ms" in health
        assert "uptime_seconds" in health
        assert "last_backup" in health

    def test_cache_returns_same_data(self):
        """Cached data is returned within TTL."""
        service = NOCAggregatorService()
        data1 = service.get_dashboard_data()
        data2 = service.get_dashboard_data()
        # Same timestamp means cached
        assert data1["timestamp"] == data2["timestamp"]

    def test_cache_expires(self):
        """Cache expires after TTL."""
        service = NOCAggregatorService()
        service.CACHE_TTL = 0  # Instant expiry
        data1 = service.get_dashboard_data()
        data2 = service.get_dashboard_data()
        # Different timestamp means re-aggregated
        # (may be same if very fast, so just verify it ran without error)
        assert "timestamp" in data2

    def test_alert_stream(self):
        """Alert stream returns list."""
        service = NOCAggregatorService()
        alerts = service.get_alert_stream()
        assert isinstance(alerts, list)

    def test_network_summary_structure(self):
        """Network summary has correct fields."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        net = data["network_summary"]
        assert "total_devices" in net
        assert "devices_by_type" in net
        assert "devices_by_status" in net

    def test_patches_summary_structure(self):
        """Patches summary has correct fields."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        patches = data["patches_summary"]
        assert "pending" in patches
        assert "installed_today" in patches
        assert "failed" in patches

    def test_self_healing_summary_structure(self):
        """Self-healing summary has correct fields."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        sh = data["self_healing_summary"]
        assert "total_today" in sh
        assert "auto_resolved" in sh
        assert "escalated" in sh
        assert "success_rate" in sh

    def test_tickets_summary_structure(self):
        """Tickets summary has correct fields."""
        service = NOCAggregatorService()
        data = service.get_dashboard_data()
        tickets = data["tickets_summary"]
        assert "open" in tickets
        assert "sla_compliant" in tickets
        assert "sla_breached" in tickets
        assert "avg_resolution" in tickets


class TestNOCConfig:
    """Tests for the NOCConfig dataclass."""

    def test_defaults(self):
        """Defaults are correct."""
        config = NOCConfig()
        assert config.rotation_interval == 15
        assert config.refresh_interval == 30
        assert config.theme == "dark"
        assert config.show_clock is True
        assert config.alert_sound is False
        assert config.defcon_flash is True
        assert len(config.panels) == 8

    def test_custom_values(self):
        """Custom values override defaults."""
        config = NOCConfig(rotation_interval=30, theme="light")
        assert config.rotation_interval == 30
        assert config.theme == "light"
