"""Packet ingestion and normalization.

We deliberately normalize every scapy packet down to a small, flat
`PacketRecord` before it touches the rule engine or any detector. This keeps
detection logic testable without scapy in the loop, and means the same
detectors work whether packets came from a .pcap file or a live capture.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

from scapy.all import rdpcap, sniff  # type: ignore
from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
from scapy.layers.l2 import ARP, Ether  # type: ignore
from scapy.layers.dns import DNS, DNSQR  # type: ignore


TCP_FLAG_BITS = {
    "F": 0x01,  # FIN
    "S": 0x02,  # SYN
    "R": 0x04,  # RST
    "P": 0x08,  # PSH
    "A": 0x10,  # ACK
    "U": 0x20,  # URG
    "E": 0x40,  # ECE
    "C": 0x80,  # CWR
}


@dataclass
class PacketRecord:
    """Flat, protocol-agnostic view of one packet."""

    index: int
    timestamp: float
    proto: str  # "tcp" | "udp" | "icmp" | "arp" | "other"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: str = ""  # e.g. "S", "SA", "PA"
    length: int = 0
    payload: bytes = b""
    ttl: Optional[int] = None
    # ARP-specific
    arp_op: Optional[int] = None  # 1=request, 2=reply
    arp_spa: Optional[str] = None  # sender protocol addr (IP)
    arp_sha: Optional[str] = None  # sender hardware addr (MAC)
    # DNS-specific
    dns_qname: Optional[str] = None
    dns_qtype: Optional[int] = None
    dns_is_response: Optional[bool] = None
    dns_rcode: Optional[int] = None

    def flags_include(self, flags: str) -> bool:
        """True if every character in `flags` is set on this packet."""
        return all(f in self.tcp_flags for f in flags)


def _tcp_flags_str(flags_int: int) -> str:
    return "".join(ch for ch, bit in TCP_FLAG_BITS.items() if flags_int & bit)


def normalize(pkt, index: int) -> Optional[PacketRecord]:
    """Convert one scapy packet into a PacketRecord, or None if uninteresting."""
    ts = float(getattr(pkt, "time", 0.0))
    rec = PacketRecord(index=index, timestamp=ts, proto="other")

    if Ether in pkt:
        rec.src_mac = pkt[Ether].src
        rec.dst_mac = pkt[Ether].dst

    if ARP in pkt:
        arp = pkt[ARP]
        rec.proto = "arp"
        rec.arp_op = int(arp.op)
        rec.arp_spa = arp.psrc
        rec.arp_sha = arp.hwsrc
        rec.src_ip = arp.psrc
        rec.dst_ip = arp.pdst
        rec.length = len(pkt)
        return rec

    if IP in pkt:
        ip = pkt[IP]
        rec.src_ip = ip.src
        rec.dst_ip = ip.dst
        rec.ttl = int(ip.ttl)
        rec.length = len(pkt)

        if TCP in pkt:
            tcp = pkt[TCP]
            rec.proto = "tcp"
            rec.src_port = int(tcp.sport)
            rec.dst_port = int(tcp.dport)
            rec.tcp_flags = _tcp_flags_str(int(tcp.flags))
            rec.payload = bytes(tcp.payload)
        elif UDP in pkt:
            udp = pkt[UDP]
            rec.proto = "udp"
            rec.src_port = int(udp.sport)
            rec.dst_port = int(udp.dport)
            rec.payload = bytes(udp.payload)
            if DNS in pkt:
                dns = pkt[DNS]
                rec.dns_is_response = bool(dns.qr)
                rec.dns_rcode = int(dns.rcode) if dns.rcode is not None else None
                if dns.qd:
                    try:
                        qd = dns.qd[0] if hasattr(dns.qd, "__getitem__") else dns.qd
                        name = qd.qname
                        rec.dns_qname = name.decode(errors="replace").rstrip(".") if isinstance(name, bytes) else str(name)
                        rec.dns_qtype = int(qd.qtype)
                    except Exception:
                        pass
        elif ICMP in pkt:
            rec.proto = "icmp"
            rec.payload = bytes(pkt[ICMP].payload)
        else:
            rec.proto = "ip_other"

        return rec

    return None


def from_pcap(path: str) -> Iterator[PacketRecord]:
    packets = rdpcap(path)
    idx = 0
    for pkt in packets:
        rec = normalize(pkt, idx)
        idx += 1
        if rec is not None:
            yield rec


def from_live(interface: str, count: int = 0, timeout: Optional[int] = None) -> Iterator[PacketRecord]:
    """Live capture. Requires raw-socket privileges (root / CAP_NET_RAW)."""
    idx_holder = {"i": 0}

    def _handle(pkt):
        rec = normalize(pkt, idx_holder["i"])
        idx_holder["i"] += 1
        if rec is not None:
            results.append(rec)

    results: list[PacketRecord] = []
    sniff(iface=interface, prn=_handle, count=count or 0, timeout=timeout, store=False)
    yield from results
