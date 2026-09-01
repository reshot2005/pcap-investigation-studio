"""Packet filter engine for investigation browser."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from pcap_investigation_studio.models import PacketRecord


@dataclass(frozen=True)
class FilterSpec:
    """User-supplied filter criteria."""

    protocol: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    port: int | None = None
    tag: str | None = None
    text: str | None = None


def apply_filter(packets: list[PacketRecord], spec: FilterSpec) -> list[PacketRecord]:
    """Filter packets by protocol, endpoints, port, tag, or free text."""
    result = packets
    if spec.protocol:
        proto = spec.protocol.upper()
        result = [p for p in result if p.protocol == proto]
    if spec.src_ip:
        result = [p for p in result if p.src_ip == spec.src_ip]
    if spec.dst_ip:
        result = [p for p in result if p.dst_ip == spec.dst_ip]
    if spec.port is not None:
        result = [
            p for p in result
            if p.src_port == spec.port or p.dst_port == spec.port
        ]
    if spec.tag:
        result = [p for p in result if spec.tag in p.tags]
    if spec.text:
        pattern = re.compile(re.escape(spec.text), re.IGNORECASE)
        result = [
            p for p in result
            if pattern.search(p.info) or pattern.search(p.src_ip) or pattern.search(p.dst_ip)
        ]
    return result


def parse_filter_expr(expr: str) -> FilterSpec:
    """Parse simple filter expressions like proto=TCP port=443 tag=dns."""
    spec = FilterSpec()
    for token in expr.split():
        if "=" not in token:
            spec = replace(spec, text=token)
            continue
        key, _, val = token.partition("=")
        key = key.lower()
        if key in {"proto", "protocol"}:
            spec = replace(spec, protocol=val.upper())
        elif key == "src":
            spec = replace(spec, src_ip=val)
        elif key == "dst":
            spec = replace(spec, dst_ip=val)
        elif key == "port":
            spec = replace(spec, port=int(val))
        elif key == "tag":
            spec = replace(spec, tag=val)
        else:
            spec = replace(spec, text=val)
    return spec
