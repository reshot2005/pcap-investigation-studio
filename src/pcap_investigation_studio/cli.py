"""CLI for pcap-investigation-studio."""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from secintel_core import export_json

from pcap_investigation_studio.core import TOOL_NAME, TOOL_VERSION, AnalysisConfig, analyze_pcap

app = typer.Typer(
    name=TOOL_NAME,
    help="Filterable PCAP packet browser with beaconing and DNS tunnel heuristics.",
    no_args_is_help=True,
)
console = Console()


class ExitCode(IntEnum):
    INPUT_ERROR = 2


@app.command()
def analyze(
    pcap_file: Path = typer.Argument(..., help="PCAP capture file"),
    json_output: bool = typer.Option(False, "--json"),
    html_output: Path | None = typer.Option(None, "--html", help="Interactive investigation report"),
    filter_expr: str | None = typer.Option(None, "--filter", "-f", help="Filter: proto=TCP port=443"),
    max_packets: int = typer.Option(250_000, "--max-packets"),
    sample: bool = typer.Option(False, "--sample"),
    offline: bool = typer.Option(True, "--offline/--allow-network"),
    max_bytes: int = typer.Option(200 * 1024 * 1024, "--max-bytes"),
) -> None:
    """Investigate PCAP with filterable browser and threat heuristics."""
    if not offline:
        console.print("[yellow]HTML reports are self-contained; no network required.[/yellow]")

    try:
        config = AnalysisConfig(
            base_dir=Path.cwd(), max_bytes=max_bytes,
            max_packets=max_packets, filter_expr=filter_expr,
        )
        result = analyze_pcap(pcap_file, config=config, is_sample=sample)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.INPUT_ERROR) from exc

    table = Table(title="Investigation Summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Packets", str(result.index.packet_count()))
    table.add_row("Filtered", str(len(result.filtered)))
    table.add_row("Beacon Candidates", str(len(result.beacons)))
    table.add_row("DNS Indicators", str(len(result.dns_indicators)))
    console.print(table)

    if json_output:
        typer.echo(export_json(result.report))
    if html_output:
        html_output.write_text(result.html or export_json(result.report), encoding="utf-8")
        console.print(f"HTML report: {html_output}")
    if not json_output and not html_output:
        typer.echo(export_json(result.report))
    raise typer.Exit(code=0)


@app.command()
def version() -> None:
    console.print(f"{TOOL_NAME} v{TOOL_VERSION}")


def main() -> None:
    app()
