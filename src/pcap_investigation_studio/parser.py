"""PCAP parser with rich packet records."""

from __future__ import annotations

import socket
from pathlib import Path

import dpkt  # type: ignore[import-untyped]

from pcap_investigation_studio.models import CaptureIndex, PacketRecord

MAX_PACKETS_DEFAULT = 250_000


def _tcp_flags(tcp: dpkt.tcp.TCP) -> str:
    parts: list[str] = []
    if tcp.flags & dpkt.tcp.TH_SYN:
        parts.append("SYN")
    if tcp.flags & dpkt.tcp.TH_ACK:
        parts.append("ACK")
    if tcp.flags & dpkt.tcp.TH_FIN:
        parts.append("FIN")
    if tcp.flags & dpkt.tcp.TH_RST:
        parts.append("RST")
    if tcp.flags & dpkt.tcp.TH_PUSH:
        parts.append("PSH")
    return ",".join(parts) if parts else ""


def _parse_ip_packet(idx: int, ts: float, length: int, ip: dpkt.ip.IP) -> PacketRecord | None:
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    proto = "IP"
    src_port = dst_port = None
    flags = ""
    info = ""
    tags: list[str] = []

    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        proto = "TCP"
        src_port, dst_port = tcp.sport, tcp.dport
        flags = _tcp_flags(tcp)
        info = f"{src_port} → {dst_port}"
        if tcp.data:
            preview = tcp.data[:40].decode("utf-8", errors="replace")
            info += f" [{preview}]"
        if tcp.flags & dpkt.tcp.TH_RST:
            tags.append("tcp-rst")
    elif isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        proto = "UDP"
        src_port, dst_port = udp.sport, udp.dport
        info = f"{src_port} → {dst_port}"
        if dst_port == 53 or src_port == 53:
            tags.append("dns")
    elif isinstance(ip.data, dpkt.icmp.ICMP):
        proto = "ICMP"
        icmp = ip.data
        info = f"type={icmp.type} code={icmp.code}"
        if icmp.type in {3, 4, 5, 11, 12}:
            tags.append("icmp-error")
    else:
        info = f"proto={ip.p}"

    return PacketRecord(
        index=idx, timestamp=ts, length=length,
        src_ip=src, dst_ip=dst, protocol=proto,
        src_port=src_port, dst_port=dst_port,
        flags=flags, info=info, tags=tuple(tags),
    )


def parse_pcap(
    path: Path | str,
    *,
    max_packets: int = MAX_PACKETS_DEFAULT,
    max_bytes: int = 200 * 1024 * 1024,
) -> CaptureIndex:
    """Parse PCAP into indexed packet records."""
    resolved = Path(path)
    if not resolved.is_file():
        raise ValueError(f"pcap file not found: {resolved}")
    if resolved.stat().st_size > max_bytes:
        raise ValueError(f"pcap exceeds max_bytes limit ({max_bytes})")

    index = CaptureIndex()
    first_ts: float | None = None
    last_ts: float | None = None

    with resolved.open("rb") as fh:
        try:
            pcap = dpkt.pcap.Reader(fh)
        except (dpkt.dpkt.NeedData, ValueError) as exc:
            raise ValueError(f"invalid pcap: {exc}") from exc

        for idx, (ts, buf) in enumerate(pcap):
            if idx >= max_packets:
                break
            ts_f = float(ts)
            first_ts = ts_f if first_ts is None else first_ts
            last_ts = ts_f

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except dpkt.dpkt.UnpackError:
                continue
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            record = _parse_ip_packet(idx, ts_f, len(buf), eth.data)
            if record is None:
                continue
            index.packets.append(record)
            index.protocol_counts[record.protocol] = (
                index.protocol_counts.get(record.protocol, 0) + 1
            )

    if first_ts is not None and last_ts is not None:
        index.duration_seconds = max(0.0, last_ts - first_ts)
    return index


def write_sample_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        for ts, buf in packets:
            writer.writepkt(buf, ts)


def make_tcp_packet(
    *,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    sport: int = 12345,
    dport: int = 80,
    payload: bytes = b"GET / HTTP/1.1",
    flags: int = dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00" * 6, dst=b"\xff" * 6,
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    )
    return bytes(eth)
