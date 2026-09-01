"""Shared PCAP fixtures."""

from __future__ import annotations

from pathlib import Path

import dpkt
import pytest
import socket

from pcap_investigation_studio.parser import make_tcp_packet, write_sample_pcap


@pytest.fixture
def sample_pcap(tmp_path: Path) -> Path:
    packets: list[tuple[float, bytes]] = []
    for i in range(5):
        packets.append((float(i), make_tcp_packet(
            src_ip="192.168.1.10", dst_ip="10.0.0.5", sport=40000 + i, dport=80,
        )))
    for i in range(10):
        packets.append((100.0 + i * 60.0, make_tcp_packet(
            src_ip="192.168.1.50", dst_ip="93.184.216.34",
            sport=50000, dport=443, payload=b"\x00" * 20,
        )))
    path = tmp_path / "sample.pcap"
    write_sample_pcap(path, packets)
    return path


@pytest.fixture
def dns_pcap(tmp_path: Path) -> Path:
    packets: list[tuple[float, bytes]] = []
    for i in range(15):
        payload = b"x" * 200
        udp = dpkt.udp.UDP(sport=40000 + i, dport=53, data=payload)
        ip = dpkt.ip.IP(
            src=socket.inet_aton("10.1.1.5"), dst=socket.inet_aton("8.8.8.8"),
            p=dpkt.ip.IP_PROTO_UDP, data=udp,
        )
        ip.len = len(ip)
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00" * 6, dst=b"\xff" * 6,
            type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
        )
        packets.append((float(i), bytes(eth)))
    path = tmp_path / "dns.pcap"
    write_sample_pcap(path, packets)
    return path
