"""Investigation heuristics: beaconing and DNS tunnel detection."""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from pcap_investigation_studio.models import CaptureIndex, PacketRecord

_BEACON_PORTS = {80, 443, 8080, 8443, 53}
_DNS_PORT = 53


@dataclass(frozen=True)
class BeaconCandidate:
    src_ip: str
    dst_ip: str
    dst_port: int | None
    interval_mean: float
    packet_count: int
    confidence_score: float
    rationale: str
    packet_indices: tuple[int, ...]


@dataclass(frozen=True)
class DnsTunnelIndicator:
    src_ip: str
    dst_ip: str
    query_count: int
    avg_query_length: float
    confidence_score: float
    rationale: str
    packet_indices: tuple[int, ...]


def detect_beaconing(index: CaptureIndex, *, min_packets: int = 8) -> list[BeaconCandidate]:
    flows: dict[tuple[str, str, int | None], list[PacketRecord]] = {}
    for pkt in index.packets:
        if pkt.protocol not in {"TCP", "UDP"}:
            continue
        key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
        flows.setdefault(key, []).append(pkt)

    candidates: list[BeaconCandidate] = []
    for (src, dst, dport), pkts in flows.items():
        if len(pkts) < min_packets:
            continue
        timestamps = sorted(p.timestamp for p in pkts)
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if not intervals:
            continue
        mean_iv = statistics.mean(intervals)
        stdev_iv = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        if mean_iv <= 0:
            continue
        jitter = stdev_iv / mean_iv
        if jitter > 0.15:
            continue
        confidence = 0.85 if dport in _BEACON_PORTS else 0.72
        candidates.append(BeaconCandidate(
            src_ip=src, dst_ip=dst, dst_port=dport,
            interval_mean=round(mean_iv, 3),
            packet_count=len(pkts),
            confidence_score=confidence,
            rationale=f"Periodic flow: {mean_iv:.2f}s mean interval, jitter {jitter:.3f}",
            packet_indices=tuple(p.index for p in pkts),
        ))
    return sorted(candidates, key=lambda c: c.confidence_score, reverse=True)


def detect_dns_tunneling(index: CaptureIndex, *, min_queries: int = 10) -> list[DnsTunnelIndicator]:
    flows: dict[tuple[str, str], list[PacketRecord]] = {}
    for pkt in index.packets:
        if pkt.dst_port == _DNS_PORT or pkt.src_port == _DNS_PORT or "dns" in pkt.tags:
            flows.setdefault((pkt.src_ip, pkt.dst_ip), []).append(pkt)

    indicators: list[DnsTunnelIndicator] = []
    for (src, dst), pkts in flows.items():
        if len(pkts) < min_queries:
            continue
        sizes = [p.length for p in pkts]
        avg_len = statistics.mean(sizes)
        if avg_len < 100:
            continue
        confidence = min(0.90, 0.55 + (avg_len - 100) / 500)
        indicators.append(DnsTunnelIndicator(
            src_ip=src, dst_ip=dst,
            query_count=len(pkts),
            avg_query_length=round(avg_len, 1),
            confidence_score=round(confidence, 2),
            rationale=f"{len(pkts)} DNS packets, avg {avg_len:.0f}B — possible tunneling",
            packet_indices=tuple(p.index for p in pkts),
        ))
    return indicators
