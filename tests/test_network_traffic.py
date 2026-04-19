"""
Tests for Network Traffic Analyzer Service
Full coverage: flow recording, all detection patterns, segment management,
DNS analysis, connection profiles, analytics, dashboard.
"""

import pytest
from datetime import datetime, timezone, timedelta

from services.msp.network_traffic_analyzer import (
    NetworkTrafficAnalyzerService,
    TrafficFlow,
    TrafficBaseline,
    TrafficAnomaly,
    NetworkSegment,
    DNSQuery,
    ConnectionProfile,
    TrafficAnomalyType,
    SegmentType,
    TrustLevel,
)


class TestNetworkTrafficAnalyzer:
    """Tests for NetworkTrafficAnalyzerService"""

    def setup_method(self):
        self.service = NetworkTrafficAnalyzerService()

    # ========== Flow Management ==========

    def test_record_flow(self):
        flow = self.service.record_flow({
            "source_ip": "192.168.1.10",
            "source_port": 54321,
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "protocol": "tcp",
            "bytes_sent": 1024,
            "bytes_received": 2048,
        })
        assert flow.flow_id.startswith("FLOW-")
        assert flow.source_ip == "192.168.1.10"
        assert flow.dest_ip == "8.8.8.8"
        assert flow.bytes_sent == 1024

    def test_record_flows_batch(self):
        flows = self.service.record_flows_batch([
            {"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "dest_port": 80},
            {"source_ip": "10.0.0.3", "dest_ip": "10.0.0.4", "dest_port": 443},
        ])
        assert len(flows) == 2

    def test_get_flows_with_filters(self):
        self.service.record_flow({"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "protocol": "tcp"})
        self.service.record_flow({"source_ip": "10.0.0.1", "dest_ip": "10.0.0.3", "protocol": "udp"})
        self.service.record_flow({"source_ip": "10.0.0.5", "dest_ip": "10.0.0.6", "protocol": "tcp"})

        tcp_flows = self.service.get_flows({"protocol": "tcp"})
        assert len(tcp_flows) == 2

        src_flows = self.service.get_flows({"source_ip": "10.0.0.1"})
        assert len(src_flows) == 2

    def test_get_flow_by_id(self):
        flow = self.service.record_flow({"source_ip": "1.2.3.4", "dest_ip": "5.6.7.8"})
        fetched = self.service.get_flow(flow.flow_id)
        assert fetched is not None
        assert fetched.source_ip == "1.2.3.4"

    def test_get_flow_not_found(self):
        assert self.service.get_flow("FLOW-nonexistent") is None

    # ========== Segment Management ==========

    def test_create_segment(self):
        seg = self.service.create_segment("Office LAN", "192.168.1.0/24", "lan", "trusted")
        assert seg.segment_id.startswith("SEG-")
        assert seg.name == "Office LAN"
        assert seg.cidr == "192.168.1.0/24"

    def test_get_segments(self):
        self.service.create_segment("LAN", "10.0.0.0/24")
        self.service.create_segment("DMZ", "172.16.0.0/24", "dmz", "semi_trusted")
        segs = self.service.get_segments()
        assert len(segs) == 2

    def test_update_segment(self):
        seg = self.service.create_segment("LAN", "10.0.0.0/24")
        updated = self.service.update_segment(seg.segment_id, name="Updated LAN", devices_count=42)
        assert updated.name == "Updated LAN"
        assert updated.devices_count == 42

    def test_update_nonexistent_segment(self):
        assert self.service.update_segment("SEG-nope", name="X") is None

    def test_delete_segment(self):
        seg = self.service.create_segment("Temp", "10.10.0.0/24")
        assert self.service.delete_segment(seg.segment_id) is True
        assert self.service.get_segment(seg.segment_id) is None

    def test_delete_nonexistent_segment(self):
        assert self.service.delete_segment("SEG-nope") is False

    # ========== Detection: Port Scan ==========

    def test_detect_port_scan(self):
        """Scanning >20 unique ports from same source triggers anomaly."""
        src = "10.0.0.99"
        for port in range(1, 25):
            self.service.record_flow({
                "source_ip": src, "dest_ip": "10.0.0.1",
                "dest_port": port, "protocol": "tcp",
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "port_scan"})
        assert len(anomalies) >= 1
        assert anomalies[0].source_ip == src

    def test_no_port_scan_below_threshold(self):
        """Fewer than 20 ports should not trigger."""
        for port in range(1, 10):
            self.service.record_flow({
                "source_ip": "10.0.0.50", "dest_ip": "10.0.0.1",
                "dest_port": port,
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "port_scan"})
        assert len(anomalies) == 0

    # ========== Detection: DNS Tunneling ==========

    def test_detect_dns_tunneling_long_subdomain(self):
        """DNS query with >50 char subdomain triggers tunneling detection."""
        long_sub = "a" * 60 + ".evil.com"
        q = self.service.record_dns_query({
            "source_ip": "10.0.0.5",
            "query_name": long_sub,
            "query_type": "A",
        })
        assert q.is_suspicious is True
        assert "subdomain length" in q.suspicion_reason

    def test_detect_dns_tunneling_txt_abuse(self):
        """High TXT query rate triggers detection."""
        for i in range(15):
            self.service.record_dns_query({
                "source_ip": "10.0.0.6",
                "query_name": f"q{i}.tunnel.com",
                "query_type": "TXT",
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "dns_tunneling"})
        assert len(anomalies) >= 1

    def test_no_dns_tunneling_normal_query(self):
        """Normal DNS queries should not trigger."""
        q = self.service.record_dns_query({
            "source_ip": "10.0.0.7",
            "query_name": "google.com",
            "query_type": "A",
        })
        assert q.is_suspicious is False

    # ========== Detection: Beaconing ==========

    def test_detect_beaconing(self):
        """Regular-interval connections to same dest trigger beaconing."""
        base = datetime.now(timezone.utc) - timedelta(minutes=10)
        dest = "203.0.113.50"
        for i in range(10):
            self.service.record_flow({
                "source_ip": "10.0.0.20",
                "dest_ip": dest,
                "dest_port": 443,
                "start_time": base + timedelta(seconds=i * 60),  # exact 60s interval
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "beaconing"})
        assert len(anomalies) >= 1
        assert "Beaconing" in anomalies[0].description

    def test_no_beaconing_irregular_intervals(self):
        """Irregular intervals should not trigger beaconing."""
        base = datetime.now(timezone.utc) - timedelta(minutes=10)
        intervals = [0, 5, 47, 120, 125, 300]  # very irregular
        for i, offset in enumerate(intervals):
            self.service.record_flow({
                "source_ip": "10.0.0.21",
                "dest_ip": "203.0.113.51",
                "dest_port": 80,
                "start_time": base + timedelta(seconds=offset),
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "beaconing"})
        assert len(anomalies) == 0

    # ========== Detection: Data Exfiltration ==========

    def test_detect_data_exfiltration(self):
        """>100MB to single external IP triggers exfiltration alert."""
        src = "10.0.0.30"
        dest = "198.51.100.10"
        chunk = 20 * 1024 * 1024  # 20 MB each
        for _ in range(6):  # 120 MB total
            self.service.record_flow({
                "source_ip": src, "dest_ip": dest,
                "dest_port": 443, "bytes_sent": chunk,
                "is_internal": False,
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "data_exfiltration"})
        assert len(anomalies) >= 1
        assert anomalies[0].severity == "critical"

    def test_no_exfiltration_below_threshold(self):
        """Small transfers should not trigger."""
        self.service.record_flow({
            "source_ip": "10.0.0.31", "dest_ip": "198.51.100.11",
            "bytes_sent": 1024, "is_internal": False,
        })
        anomalies = self.service.get_anomalies({"anomaly_type": "data_exfiltration"})
        assert len(anomalies) == 0

    # ========== Detection: Lateral Movement ==========

    def test_detect_lateral_movement(self):
        """Internal IP hitting >5 hosts on admin ports triggers alert."""
        src = "10.0.0.40"
        for i in range(7):
            self.service.record_flow({
                "source_ip": src, "dest_ip": f"10.0.0.{100 + i}",
                "dest_port": 445, "is_internal": True,
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "lateral_movement"})
        assert len(anomalies) >= 1
        assert "Lateral movement" in anomalies[0].description

    def test_no_lateral_on_non_admin_ports(self):
        """Connections on non-admin ports should not trigger."""
        for i in range(7):
            self.service.record_flow({
                "source_ip": "10.0.0.41", "dest_ip": f"10.0.0.{110 + i}",
                "dest_port": 80, "is_internal": True,
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "lateral_movement"})
        assert len(anomalies) == 0

    # ========== Detection: C2 Communication ==========

    def test_detect_c2_known_bad_ip(self):
        """Connection to known-bad IP triggers C2 alert."""
        from services.msp.network_traffic_analyzer import KNOWN_BAD_IPS
        KNOWN_BAD_IPS.add("198.51.100.66")
        try:
            self.service.record_flow({
                "source_ip": "10.0.0.50", "dest_ip": "198.51.100.66",
                "dest_port": 443,
            })
            anomalies = self.service.get_anomalies({"anomaly_type": "c2_communication"})
            assert len(anomalies) >= 1
        finally:
            KNOWN_BAD_IPS.discard("198.51.100.66")

    # ========== Detection: Protocol Violation ==========

    def test_detect_protocol_violation(self):
        """Non-HTTP protocol on port 80 triggers violation."""
        self.service.record_flow({
            "source_ip": "10.0.0.60", "dest_ip": "10.0.0.61",
            "dest_port": 80, "application_protocol": "ssh",
        })
        anomalies = self.service.get_anomalies({"anomaly_type": "protocol_violation"})
        assert len(anomalies) >= 1
        assert "port 80" in anomalies[0].description

    def test_no_violation_correct_protocol(self):
        """HTTP on port 80 should not trigger."""
        self.service.record_flow({
            "source_ip": "10.0.0.62", "dest_ip": "10.0.0.63",
            "dest_port": 80, "application_protocol": "http",
        })
        anomalies = self.service.get_anomalies({"anomaly_type": "protocol_violation"})
        assert len(anomalies) == 0

    def test_no_violation_unknown_protocol(self):
        """Unknown protocol on standard port should not trigger (may be unclassified)."""
        self.service.record_flow({
            "source_ip": "10.0.0.64", "dest_ip": "10.0.0.65",
            "dest_port": 80, "application_protocol": "unknown",
        })
        anomalies = self.service.get_anomalies({"anomaly_type": "protocol_violation"})
        assert len(anomalies) == 0

    # ========== Detection: DGA Domain ==========

    def test_dga_detection_positive(self):
        """High-entropy, consonant-heavy domain is flagged as DGA."""
        # Need 12+ chars for sufficient entropy above 3.5 threshold
        assert self.service._is_dga_domain("xkrptqwmzfbvcn.com") is True

    def test_dga_detection_negative(self):
        """Normal domain should not flag."""
        assert self.service._is_dga_domain("google.com") is False

    def test_dga_detection_short_domain(self):
        """Very short domains should not flag."""
        assert self.service._is_dga_domain("abc.com") is False

    # ========== Detection: Encrypted Tunnel Abuse ==========

    def test_detect_encrypted_tunnel_abuse(self):
        """Large SSH transfer triggers tunnel abuse."""
        self.service.record_flow({
            "source_ip": "10.0.0.70", "dest_ip": "10.0.0.71",
            "dest_port": 22, "application_protocol": "ssh",
            "bytes_sent": 60 * 1024 * 1024,  # 60 MB
        })
        anomalies = self.service.get_anomalies({"anomaly_type": "encrypted_tunnel_abuse"})
        assert len(anomalies) >= 1

    # ========== Detection: Slow DoS ==========

    def test_detect_slow_dos(self):
        """Many half-open connections trigger slow DoS."""
        dest = "10.0.0.80"
        for i in range(110):
            self.service.record_flow({
                "source_ip": f"10.1.{i // 256}.{i % 256}",
                "dest_ip": dest, "dest_port": 80,
                "flow_state": "active",
                "packets_received": 0,
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "slow_dos"})
        assert len(anomalies) >= 1

    # ========== DNS Analysis ==========

    def test_record_dns_query(self):
        q = self.service.record_dns_query({
            "source_ip": "10.0.0.5",
            "query_name": "example.com",
            "query_type": "A",
            "response_ip": "93.184.216.34",
        })
        assert q.query_id.startswith("DNS-")
        assert q.query_name == "example.com"

    def test_get_dns_queries_filtered(self):
        self.service.record_dns_query({"source_ip": "10.0.0.1", "query_name": "a.com", "query_type": "A"})
        self.service.record_dns_query({"source_ip": "10.0.0.2", "query_name": "b.com", "query_type": "MX"})
        result = self.service.get_dns_queries({"query_type": "MX"})
        assert len(result) == 1
        assert result[0].query_name == "b.com"

    def test_get_top_queried_domains(self):
        for _ in range(5):
            self.service.record_dns_query({"source_ip": "10.0.0.1", "query_name": "popular.com"})
        for _ in range(2):
            self.service.record_dns_query({"source_ip": "10.0.0.1", "query_name": "rare.com"})
        top = self.service.get_top_queried_domains(2)
        assert top[0]["domain"] == "popular.com"
        assert top[0]["count"] == 5

    def test_get_suspicious_dns(self):
        self.service.record_dns_query({
            "source_ip": "10.0.0.8",
            "query_name": "a" * 60 + ".evil.com",
        })
        self.service.record_dns_query({
            "source_ip": "10.0.0.9",
            "query_name": "safe.com",
        })
        suspicious = self.service.get_suspicious_dns()
        assert len(suspicious) >= 1

    # ========== Connection Profiles ==========

    def test_build_connection_profile(self):
        ip = "10.0.0.100"
        self.service.record_flow({"source_ip": ip, "dest_ip": "10.0.0.1", "dest_port": 80, "bytes_sent": 500})
        self.service.record_flow({"source_ip": ip, "dest_ip": "10.0.0.2", "dest_port": 443, "bytes_sent": 700})
        profile = self.service.build_connection_profile(ip)
        assert profile.ip_address == ip
        assert profile.unique_destinations == 2
        assert profile.total_flows == 2
        assert profile.total_bytes == 1200

    def test_get_connection_profile(self):
        ip = "10.0.0.101"
        self.service.record_flow({"source_ip": ip, "dest_ip": "10.0.0.1"})
        self.service.build_connection_profile(ip)
        p = self.service.get_connection_profile(ip)
        assert p is not None
        assert p.ip_address == ip

    def test_list_profiles(self):
        self.service.record_flow({"source_ip": "10.0.0.200", "dest_ip": "10.0.0.1"})
        self.service.record_flow({"source_ip": "10.0.0.201", "dest_ip": "10.0.0.1"})
        self.service.build_connection_profile("10.0.0.200")
        self.service.build_connection_profile("10.0.0.201")
        profiles = self.service.list_profiles()
        assert len(profiles) == 2

    # ========== Baselines ==========

    def test_build_traffic_baseline(self):
        seg = self.service.create_segment("Test", "192.168.1.0/24")
        for i in range(5):
            self.service.record_flow({
                "source_ip": f"192.168.1.{10 + i}",
                "dest_ip": "8.8.8.8",
                "bytes_sent": 1000 * (i + 1),
                "bytes_received": 2000 * (i + 1),
                "duration_seconds": float(i + 1),
            })
        baselines = self.service.build_traffic_baseline(seg.segment_id)
        assert len(baselines) >= 2  # bytes_per_flow + duration_seconds + flows_per_minute
        metric_names = {b.metric_name for b in baselines}
        assert "bytes_per_flow" in metric_names
        assert "duration_seconds" in metric_names

    def test_get_baselines(self):
        seg = self.service.create_segment("BL Test", "172.16.0.0/24")
        self.service.record_flow({"source_ip": "172.16.0.5", "dest_ip": "8.8.8.8", "bytes_sent": 100})
        self.service.build_traffic_baseline(seg.segment_id)
        bl = self.service.get_baselines(seg.segment_id)
        assert len(bl) >= 1

    def test_baseline_nonexistent_segment(self):
        result = self.service.build_traffic_baseline("SEG-nonexistent")
        assert result == []

    # ========== Anomaly Management ==========

    def test_confirm_anomaly(self):
        # Trigger a port scan anomaly
        for port in range(1, 25):
            self.service.record_flow({
                "source_ip": "10.0.0.99", "dest_ip": "10.0.0.1", "dest_port": port,
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "port_scan"})
        assert len(anomalies) >= 1
        confirmed = self.service.confirm_anomaly(anomalies[0].anomaly_id)
        assert confirmed.is_confirmed is True

    def test_dismiss_anomaly(self):
        for port in range(1, 25):
            self.service.record_flow({
                "source_ip": "10.0.0.98", "dest_ip": "10.0.0.1", "dest_port": port,
            })
        anomalies = self.service.get_anomalies({"anomaly_type": "port_scan"})
        aid = anomalies[0].anomaly_id
        assert self.service.dismiss_anomaly(aid) is True
        assert self.service.dismiss_anomaly(aid) is False  # already dismissed

    def test_confirm_nonexistent_anomaly(self):
        assert self.service.confirm_anomaly("ANOM-nope") is None

    # ========== Analytics ==========

    def test_get_bandwidth_usage(self):
        self.service.record_flow({
            "source_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
            "bytes_sent": 5000, "bytes_received": 3000,
        })
        bw = self.service.get_bandwidth_usage()
        assert bw["total_bytes"] == 8000
        assert bw["flow_count"] == 1

    def test_get_top_talkers(self):
        self.service.record_flow({"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "bytes_sent": 10000})
        self.service.record_flow({"source_ip": "10.0.0.3", "dest_ip": "10.0.0.4", "bytes_sent": 50000})
        top = self.service.get_top_talkers(2)
        assert len(top) >= 2
        # Highest talker first
        assert top[0]["total_bytes"] >= top[1]["total_bytes"]

    def test_get_protocol_distribution(self):
        self.service.record_flow({"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "protocol": "tcp"})
        self.service.record_flow({"source_ip": "10.0.0.3", "dest_ip": "10.0.0.4", "protocol": "udp"})
        self.service.record_flow({"source_ip": "10.0.0.5", "dest_ip": "10.0.0.6", "protocol": "tcp"})
        dist = self.service.get_protocol_distribution()
        assert dist["tcp"] == 2
        assert dist["udp"] == 1

    def test_get_geographic_destinations(self):
        self.service.record_flow({"source_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "is_internal": False})
        self.service.record_flow({"source_ip": "10.0.0.2", "dest_ip": "8.8.8.8", "is_internal": False})
        geo = self.service.get_geographic_destinations()
        assert len(geo) >= 1
        assert geo[0]["ip"] == "8.8.8.8"

    def test_get_internal_vs_external_ratio(self):
        self.service.record_flow({"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "is_internal": True})
        self.service.record_flow({"source_ip": "10.0.0.3", "dest_ip": "8.8.8.8", "is_internal": False})
        ratio = self.service.get_internal_vs_external_ratio()
        assert ratio["internal"] == 1
        assert ratio["external"] == 1
        assert ratio["internal_pct"] == 50.0

    # ========== Network Health ==========

    def test_get_network_health_healthy(self):
        self.service.record_flow({"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2"})
        health = self.service.get_network_health()
        assert health["status"] == "healthy"
        assert health["score"] == 100

    def test_get_network_health_degraded(self):
        # Create several anomalies via port scans
        for scan in range(3):
            svc = self.service  # reuse same service
            for port in range(1, 25):
                svc.record_flow({
                    "source_ip": f"10.0.{scan}.99",
                    "dest_ip": "10.0.0.1",
                    "dest_port": port,
                })
        health = self.service.get_network_health()
        assert health["total_anomalies"] >= 3
        assert health["score"] < 100

    # ========== Dashboard ==========

    def test_get_dashboard(self):
        self.service.record_flow({"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "bytes_sent": 1000})
        self.service.create_segment("LAN", "10.0.0.0/24")
        dash = self.service.get_dashboard()
        assert dash["total_flows"] >= 1
        assert "bandwidth" in dash
        assert "anomalies" in dash
        assert "top_talkers" in dash
        assert "network_health" in dash
        assert "segments" in dash
        assert len(dash["segments"]) == 1

    # ========== Enum Values ==========

    def test_anomaly_type_enum(self):
        assert TrafficAnomalyType.PORT_SCAN.value == "port_scan"
        assert TrafficAnomalyType.DNS_TUNNELING.value == "dns_tunneling"
        assert TrafficAnomalyType.BEACONING.value == "beaconing"
        assert TrafficAnomalyType.DATA_EXFILTRATION.value == "data_exfiltration"
        assert TrafficAnomalyType.LATERAL_MOVEMENT.value == "lateral_movement"
        assert TrafficAnomalyType.C2_COMMUNICATION.value == "c2_communication"
        assert TrafficAnomalyType.SLOW_DOS.value == "slow_dos"

    def test_segment_type_enum(self):
        assert SegmentType.LAN.value == "lan"
        assert SegmentType.DMZ.value == "dmz"
        assert SegmentType.VPN.value == "vpn"

    def test_trust_level_enum(self):
        assert TrustLevel.TRUSTED.value == "trusted"
        assert TrustLevel.ISOLATED.value == "isolated"

    # ========== Shannon Entropy ==========

    def test_shannon_entropy(self):
        # All same characters = 0 entropy
        assert NetworkTrafficAnalyzerService._shannon_entropy("aaaa") == 0.0
        # Mixed characters = higher entropy
        e = NetworkTrafficAnalyzerService._shannon_entropy("abcdefgh")
        assert e > 2.5
        # Empty = 0
        assert NetworkTrafficAnalyzerService._shannon_entropy("") == 0.0
