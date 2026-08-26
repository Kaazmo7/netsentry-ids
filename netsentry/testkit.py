"""Synthetic traffic generators used by the test suite and by
`samples/make_demo_pcap.py` to build a reproducible, entirely fabricated
capture with known-good ground truth for every detector.

No real hosts, no real malware, no captured traffic -- every packet here is
constructed from scratch with scapy so the repo never ships anyone's actual
network data.
"""
from __future__ import annotations

import random
import string

from scapy.all import wrpcap  # type: ignore
from scapy.layers.dns import DNS, DNSQR  # type: ignore
from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
from scapy.layers.l2 import ARP, Ether  # type: ignore


def _eth_ip_tcp(src, dst, sport, dport, flags, t, payload=b""):
    pkt = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=src, dst=dst, ttl=64)
        / TCP(sport=sport, dport=dport, flags=flags)
    )
    if payload:
        pkt = pkt / payload
    pkt.time = t
    return pkt


def benign_web_and_dns(base_time: float, n_flows: int = 12, rng: random.Random | None = None) -> list:
    """Ordinary browsing: full TCP handshakes to a few hosts + normal DNS lookups.

    This is the negative-control traffic: none of it should trip any detector.
    """
    rng = rng or random.Random(1)
    hosts = ["93.184.216.34", "142.250.72.14", "151.101.1.69"]
    hostnames = ["example.com", "mail.google.com", "cdn.example.net", "api.github.com"]
    pkts = []
    t = base_time
    for i in range(n_flows):
        dst = rng.choice(hosts)
        sport = rng.randint(40000, 60000)
        dport = rng.choice([443, 443, 443, 80])
        # three-way handshake + a small request + FIN, all with irregular timing
        pkts.append(_eth_ip_tcp("10.0.0.5", dst, sport, dport, "S", t))
        t += rng.uniform(0.01, 0.05)
        pkts.append(_eth_ip_tcp(dst, "10.0.0.5", dport, sport, "SA", t))
        t += rng.uniform(0.01, 0.05)
        pkts.append(_eth_ip_tcp("10.0.0.5", dst, sport, dport, "A", t, payload=b"GET / HTTP/1.1\r\n"))
        t += rng.uniform(0.2, 3.0)
        pkts.append(_eth_ip_tcp("10.0.0.5", dst, sport, dport, "FA", t))
        t += rng.uniform(0.5, 4.0)

        # a normal, short DNS lookup
        dns_pkt = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="10.0.0.5", dst="10.0.0.1", ttl=64)
            / UDP(sport=rng.randint(40000, 60000), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=rng.choice(hostnames)))
        )
        dns_pkt.time = t
        pkts.append(dns_pkt)
        t += rng.uniform(0.5, 5.0)
    return pkts


def port_scan(
    base_time: float,
    src_ip: str = "10.0.0.50",
    dst_ip: str = "10.0.0.10",
    n_ports: int = 25,
    spacing: float = 0.04,
) -> list:
    """Bare TCP SYNs to many ports on one host in a short burst -- nmap -sS style."""
    pkts = []
    t = base_time
    common_ports = list(range(20, 26)) + [53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5900, 8080, 8443]
    ports = (common_ports + list(range(9000, 9000 + max(0, n_ports - len(common_ports)))))[:n_ports]
    for port in ports:
        pkts.append(_eth_ip_tcp(src_ip, dst_ip, 51000, port, "S", t))
        t += spacing
    return pkts


def arp_spoof(base_time: float, gateway_ip: str = "10.0.0.1") -> list:
    """A legitimate gateway ARP reply, then an attacker claiming the same IP."""
    pkts = []
    legit = Ether(src="aa:bb:cc:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=gateway_ip, hwsrc="aa:bb:cc:00:00:01", pdst="10.0.0.5", hwdst="02:00:00:00:00:01"
    )
    legit.time = base_time
    pkts.append(legit)

    for i in range(3):
        spoof = Ether(src="de:ad:be:ef:00:66", dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, psrc=gateway_ip, hwsrc="de:ad:be:ef:00:66", pdst="10.0.0.5", hwdst="02:00:00:00:00:01"
        )
        spoof.time = base_time + 2.0 + i * 1.5
        pkts.append(spoof)
    return pkts


def dns_tunnel(base_time: float, src_ip: str = "10.0.0.77", base_domain: str = "evil.example.com", n: int = 20, rng: random.Random | None = None) -> list:
    """High-entropy subdomain labels streamed rapidly -- iodine/dnscat2-style tunnel."""
    rng = rng or random.Random(2)
    alphabet = string.ascii_lowercase + string.digits
    pkts = []
    t = base_time
    for _ in range(n):
        label = "".join(rng.choice(alphabet) for _ in range(48))
        qname = f"{label}.{base_domain}"
        pkt = (
            Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:02")
            / IP(src=src_ip, dst="10.0.0.1", ttl=64)
            / UDP(sport=rng.randint(40000, 60000), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname))
        )
        pkt.time = t
        pkts.append(pkt)
        t += rng.uniform(0.05, 0.3)
    return pkts


def beaconing(
    base_time: float,
    src_ip: str = "10.0.0.99",
    dst_ip: str = "203.0.113.5",
    dst_port: int = 443,
    n: int = 10,
    interval: float = 60.0,
    jitter: float = 0.5,
    rng: random.Random | None = None,
) -> list:
    """Near-fixed-interval outbound connection attempts -- classic C2 check-in."""
    rng = rng or random.Random(3)
    pkts = []
    t = base_time
    for _ in range(n):
        pkts.append(_eth_ip_tcp(src_ip, dst_ip, 52000, dst_port, "S", t))
        t += interval + rng.uniform(-jitter, jitter)
    return pkts


def build_demo_capture() -> list:
    """Everything combined, in a plausible chronological order, for the demo pcap."""
    rng = random.Random(42)
    pkts = []
    pkts += benign_web_and_dns(base_time=0.0, n_flows=10, rng=rng)
    pkts += port_scan(base_time=60.0)
    pkts += arp_spoof(base_time=120.0)
    pkts += dns_tunnel(base_time=180.0, rng=rng)
    pkts += beaconing(base_time=240.0, rng=rng)
    pkts += benign_web_and_dns(base_time=900.0, n_flows=6, rng=rng)
    pkts.sort(key=lambda p: p.time)
    return pkts


def write_demo_capture(path: str) -> None:
    wrpcap(path, build_demo_capture())
