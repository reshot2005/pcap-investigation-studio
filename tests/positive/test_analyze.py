"""Positive tests."""

from __future__ import annotations

from pathlib import Path

from secintel_core.schema import Classification

from pcap_investigation_studio.core import AnalysisConfig, analyze_pcap
from pcap_investigation_studio.filters import apply_filter, parse_filter_expr


class TestPositive:
    def test_indexes_packets(self, sample_pcap: Path) -> None:
        result = analyze_pcap(sample_pcap)
        assert result.index.packet_count() == 15

    def test_beaconing_detected(self, sample_pcap: Path) -> None:
        result = analyze_pcap(sample_pcap)
        beacons = [f for f in result.report.findings if "beaconing" in f.tags]
        assert len(beacons) >= 1

    def test_html_browser_panel(self, sample_pcap: Path) -> None:
        result = analyze_pcap(sample_pcap)
        assert result.html is not None
        assert "pcap-table" in result.html

    def test_filter_engine(self, sample_pcap: Path) -> None:
        result = analyze_pcap(sample_pcap)
        spec = parse_filter_expr("proto=TCP port=443")
        filtered = apply_filter(result.index.packets, spec)
        assert all(p.protocol == "TCP" for p in filtered)
        assert all(p.dst_port == 443 or p.src_port == 443 for p in filtered)

    def test_filter_cli_config(self, sample_pcap: Path) -> None:
        result = analyze_pcap(
            sample_pcap,
            config=AnalysisConfig(filter_expr="proto=TCP port=80"),
        )
        derived = [f for f in result.report.findings if f.classification == Classification.DERIVED]
        assert any("Filter" in f.title for f in derived)

    def test_dns_tunnel(self, dns_pcap: Path) -> None:
        result = analyze_pcap(dns_pcap)
        dns = [f for f in result.report.findings if "tunneling" in f.tags]
        assert len(dns) >= 1
