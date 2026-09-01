"""Edge case tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_investigation_studio.core import analyze_pcap


class TestEdgeCases:
    def test_sample_flag(self, sample_pcap: Path) -> None:
        result = analyze_pcap(sample_pcap, is_sample=True)
        assert result.report.is_sample_data is True

    def test_reproducible_ids(self, sample_pcap: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECINTEL_SOURCE_DATE_EPOCH", "1704067200")
        r1 = analyze_pcap(sample_pcap)
        r2 = analyze_pcap(sample_pcap)
        assert r1.report.findings[0].id == r2.report.findings[0].id
