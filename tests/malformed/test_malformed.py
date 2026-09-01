"""Malformed input tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_investigation_studio.core import AnalysisConfig, analyze_pcap


class TestMalformed:
    def test_missing_pcap_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not found"):
            analyze_pcap("missing.pcap", config=AnalysisConfig(base_dir=tmp_path))

    def test_invalid_pcap_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"not a pcap")
        with pytest.raises(ValueError):
            analyze_pcap(bad)
