"""Core PCAP investigation analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secintel_core import (
    Classification,
    Confidence,
    Evidence,
    Finding,
    InputArtifact,
    Provenance,
    Report,
    Severity,
    build_environment_info,
    canonical_config_hash,
    deterministic_finding_id,
    reproducible_now,
    sha256_file,
)
from secintel_core.report import render_report_html
from secintel_core.security import safe_resolve_path

from pcap_investigation_studio.filters import apply_filter
from pcap_investigation_studio.heuristics import (
    BeaconCandidate,
    DnsTunnelIndicator,
    detect_beaconing,
    detect_dns_tunneling,
)
from pcap_investigation_studio.models import CaptureIndex, PacketRecord
from pcap_investigation_studio.parser import parse_pcap
from pcap_investigation_studio.visualization import build_browser_panel

TOOL_NAME = "pcap-investigation-studio"
TOOL_VERSION = "0.1.0"


@dataclass
class AnalysisConfig:
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    max_bytes: int = 200 * 1024 * 1024
    max_packets: int = 250_000
    filter_expr: str | None = None


@dataclass
class AnalysisResult:
    report: Report
    index: CaptureIndex
    filtered: list[PacketRecord]
    beacons: list[BeaconCandidate]
    dns_indicators: list[DnsTunnelIndicator]
    html: str | None = None


def _resolve(base: Path, p: Path | str) -> Path:
    up = Path(p)
    return up.resolve() if up.is_absolute() else safe_resolve_path(base, p)


def analyze_pcap(
    input_path: Path | str,
    *,
    config: AnalysisConfig | None = None,
    is_sample: bool = False,
) -> AnalysisResult:
    cfg = config or AnalysisConfig()
    resolved = _resolve(cfg.base_dir, input_path)
    if not resolved.is_file():
        raise ValueError(f"pcap file not found: {resolved}")

    input_hash = sha256_file(resolved, max_bytes=cfg.max_bytes)
    started = reproducible_now()
    index = parse_pcap(resolved, max_packets=cfg.max_packets, max_bytes=cfg.max_bytes)
    beacons = detect_beaconing(index)
    dns_indicators = detect_dns_tunneling(index)

    filtered = index.packets
    if cfg.filter_expr:
        from pcap_investigation_studio.filters import parse_filter_expr
        filtered = apply_filter(index.packets, parse_filter_expr(cfg.filter_expr))

    highlight: set[int] = set()
    for b in beacons:
        highlight.update(b.packet_indices)
    for d in dns_indicators:
        highlight.update(d.packet_indices)

    findings = _emit_findings(
        index, filtered, beacons, dns_indicators,
        input_hash=input_hash, source=str(resolved), started=started,
        filter_expr=cfg.filter_expr,
    )

    ended = reproducible_now()
    report = Report(
        provenance=Provenance(
            tool_name=TOOL_NAME, tool_version=TOOL_VERSION,
            config_hash=canonical_config_hash({
                "max_packets": cfg.max_packets,
                "filter": cfg.filter_expr,
            }),
            inputs=[InputArtifact(
                path=str(resolved), sha256=input_hash,
                size_bytes=resolved.stat().st_size,
            )],
            analysis_started_at=started, analysis_ended_at=ended,
            environment=build_environment_info(),
        ),
        findings=findings,
        is_sample_data=is_sample,
        metadata={
            "packet_count": index.packet_count(),
            "filtered_count": len(filtered),
            "beacon_candidates": len(beacons),
            "dns_indicators": len(dns_indicators),
        },
    )

    panel = build_browser_panel(index.packets, highlight_indices=highlight)
    html = render_report_html(report, tool_title=TOOL_NAME, panels=[panel])

    return AnalysisResult(
        report=report, index=index, filtered=filtered,
        beacons=beacons, dns_indicators=dns_indicators, html=html,
    )


def _emit_findings(
    index: CaptureIndex,
    filtered: list[PacketRecord],
    beacons: list[BeaconCandidate],
    dns_indicators: list[DnsTunnelIndicator],
    *,
    input_hash: str,
    source: str,
    started: Any,
    filter_expr: str | None,
) -> list[Finding]:
    findings: list[Finding] = []

    findings.append(Finding(
        id=deterministic_finding_id("capture-observed", input_hash, {"n": index.packet_count()}),
        title=f"Capture indexed: {index.packet_count()} packets",
        classification=Classification.OBSERVED,
        evidence=[Evidence(source=source, locator={"packets": index.packet_count()}, retrieved_at=started)],
        method="PCAP packet enumeration",
        why_it_matters="Indexed capture enables interactive investigation.",
        plain_language=f"Loaded {index.packet_count()} packets for browsing.",
        severity=Severity.INFO,
        tags=["capture", "browser"],
        timestamp=started,
    ))

    if filter_expr:
        findings.append(Finding(
            id=deterministic_finding_id("filter-derived", input_hash, {"expr": filter_expr}),
            title=f"Filter applied: {len(filtered)} of {index.packet_count()} packets match",
            classification=Classification.DERIVED,
            evidence=[Evidence(source=source, locator={"filter": filter_expr}, retrieved_at=started)],
            method="Server-side filter expression evaluation",
            why_it_matters="Filtered views focus analyst attention.",
            plain_language=f"Filter '{filter_expr}' matched {len(filtered)} packets.",
            severity=Severity.INFO,
            tags=["filter"],
            timestamp=started,
        ))

    for beacon in beacons[:10]:
        findings.append(Finding(
            id=deterministic_finding_id("beacon-inferred", input_hash, {
                "src": beacon.src_ip, "dst": beacon.dst_ip,
            }),
            title=f"Beaconing: {beacon.src_ip} → {beacon.dst_ip}:{beacon.dst_port}",
            classification=Classification.INFERRED,
            confidence=Confidence(
                score=beacon.confidence_score,
                rationale=beacon.rationale,
                supporting_indicators=[f"packets={beacon.packet_count}"],
            ),
            evidence=[Evidence(
                source=source,
                locator={"indices": list(beacon.packet_indices[:20])},
                retrieved_at=started,
            )],
            method="Inter-arrival interval jitter analysis",
            why_it_matters="Periodic beaconing suggests C2 communication.",
            plain_language=beacon.rationale,
            severity=Severity.HIGH,
            tags=["beaconing", "c2", "investigation"],
            timestamp=started,
        ))

    for dns in dns_indicators:
        findings.append(Finding(
            id=deterministic_finding_id("dns-tunnel", input_hash, {"src": dns.src_ip}),
            title=f"DNS tunnel indicator: {dns.src_ip} → {dns.dst_ip}",
            classification=Classification.INFERRED,
            confidence=Confidence(
                score=dns.confidence_score,
                rationale=dns.rationale,
                supporting_indicators=[f"queries={dns.query_count}"],
            ),
            evidence=[Evidence(source=source, locator={"indices": list(dns.packet_indices[:20])}, retrieved_at=started)],
            method="DNS volume + packet size heuristic",
            why_it_matters="DNS tunneling exfiltrates data through resolvers.",
            plain_language=dns.rationale,
            severity=Severity.HIGH,
            tags=["dns", "tunneling", "investigation"],
            timestamp=started,
        ))

    return findings
