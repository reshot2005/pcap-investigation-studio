"""CLI integration tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pcap_investigation_studio.cli import app

runner = CliRunner()


class TestCLI:
    def test_analyze_json(self, sample_pcap: Path) -> None:
        result = runner.invoke(app, ["analyze", str(sample_pcap), "--json"])
        assert result.exit_code == 0
        assert '"OBSERVED"' in result.stdout

    def test_analyze_html(self, sample_pcap: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        result = runner.invoke(app, ["analyze", str(sample_pcap), "--html", str(out)])
        assert result.exit_code == 0
        assert "pcap-table" in out.read_text(encoding="utf-8")
