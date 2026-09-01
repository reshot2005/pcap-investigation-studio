"""Packet record models for investigation browser."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PacketRecord:
    """Rich header-level packet for browser display."""

    index: int
    timestamp: float
    length: int
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    flags: str = ""
    info: str = ""
    tags: tuple[str, ...] = ()

    def to_row(self) -> dict[str, str | int | float]:
        return {
            "index": self.index,
            "time": round(self.timestamp, 6),
            "src": self.src_ip,
            "dst": self.dst_ip,
            "proto": self.protocol,
            "sport": self.src_port or "",
            "dport": self.dst_port or "",
            "len": self.length,
            "flags": self.flags,
            "info": self.info,
            "tags": ",".join(self.tags),
        }


@dataclass
class CaptureIndex:
    """Indexed capture for filtering and heuristics."""

    packets: list[PacketRecord] = field(default_factory=list)
    duration_seconds: float = 0.0
    protocol_counts: dict[str, int] = field(default_factory=dict)

    def packet_count(self) -> int:
        return len(self.packets)
