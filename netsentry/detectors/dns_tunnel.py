"""DNS tunneling / exfiltration detector.

DNS tunneling tools (iodine, dnscat2, DNSExfiltrator, ...) encode data into
subdomain labels, which makes those labels statistically dense (high
Shannon entropy, near-random-looking) and unusually long compared to normal
hostnames. A single weird-looking query means little; a *sustained stream*
of high-entropy queries to the same parent domain from one host is the
tell.

MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS) for the tunnel
itself; queries that look like they're carrying stolen data are also tagged
T1048.003 (Exfiltration Over Alternative Protocol: DNS).
"""
from __future__ import annotations

import math
from collections import defaultdict

from ..alerts import Alert, Severity
from ..packets import PacketRecord

LONG_LABEL_LEN = 45          # a single query name longer than this is suspicious on its own
ENTROPY_THRESHOLD = 3.6      # bits/char; random base32/base64 data lands ~4.0-4.5
MIN_QUERIES_FOR_TUNNEL = 12  # sustained volume, not a one-off


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _registrable_suffix(qname: str) -> str:
    """Best-effort 'base domain' -- last two labels (good enough for this heuristic)."""
    parts = qname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname


class DnsTunnelDetector:
    name = "dns_tunnel"

    def __init__(
        self,
        entropy_threshold: float = ENTROPY_THRESHOLD,
        min_queries: int = MIN_QUERIES_FOR_TUNNEL,
        long_label_len: int = LONG_LABEL_LEN,
    ):
        self.entropy_threshold = entropy_threshold
        self.min_queries = min_queries
        self.long_label_len = long_label_len

    def analyze(self, records: list[PacketRecord]) -> list[Alert]:
        alerts: list[Alert] = []
        # (src_ip, base_domain) -> list of (qname, entropy, timestamp, packet_index)
        groups: dict[tuple[str, str], list[tuple]] = defaultdict(list)

        for rec in records:
            if rec.proto != "udp" or rec.dst_port != 53 or not rec.dns_qname:
                continue
            if rec.dns_is_response:
                continue
            qname = rec.dns_qname
            label = qname.split(".")[0]
            entropy = _shannon_entropy(label)
            base = _registrable_suffix(qname)
            groups[(rec.src_ip, base)].append((qname, entropy, rec.timestamp, rec.index, len(qname)))

        for (src_ip, base_domain), queries in groups.items():
            high_entropy = [q for q in queries if q[1] >= self.entropy_threshold or q[4] >= self.long_label_len]
            if len(high_entropy) >= self.min_queries:
                avg_entropy = sum(q[1] for q in high_entropy) / len(high_entropy)
                alerts.append(
                    Alert(
                        source=self.name,
                        signature="Possible DNS tunneling",
                        severity=Severity.HIGH,
                        message=(
                            f"{src_ip} sent {len(high_entropy)} high-entropy/long DNS queries "
                            f"under {base_domain} (avg label entropy {avg_entropy:.2f} bits/char) "
                            "-- consistent with DNS-based C2 or data exfiltration"
                        ),
                        src_ip=src_ip,
                        dst_port=53,
                        proto="udp",
                        mitre=["T1071.004", "T1048.003"],
                        packet_index=high_entropy[0][3],
                        timestamp=high_entropy[0][2],
                        evidence={
                            "base_domain": base_domain,
                            "sample_queries": [q[0] for q in high_entropy[:5]],
                            "query_count": len(high_entropy),
                            "avg_entropy": round(avg_entropy, 3),
                        },
                    )
                )
        return alerts
