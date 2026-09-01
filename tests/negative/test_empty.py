"""Negative tests."""

from __future__ import annotations

from pathlib import Path

from pcap_investigation_studio.core import analyze_pcap
from pcap_investigation_studio.parser import make_tcp_packet, write_sample_pcap


class TestNegative:
    def test_small_capture_no_beacon(self, tmp_path: Path) -> None:
        path = tmp_path / "tiny.pcap"
        write_sample_pcap(path, [(0.0, make_tcp_packet())])
        result = analyze_pcap(path)
        beacons = [f for f in result.report.findings if "beaconing" in f.tags]
        assert len(beacons) == 0
