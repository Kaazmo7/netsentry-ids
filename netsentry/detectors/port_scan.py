"""Port scan detector.

Flags a source host that sends bare TCP SYNs (no completed handshake, no
payload) to an unusually large number of distinct destination ports within a
short, contiguous burst. This is the classic "nmap -sS" signature.

Hits from one source are clustered into "sessions": consecutive hits stay in
the same session as long as the gap between them is under `window` seconds.
A session that touches at least `threshold` distinct ports raises one alert
covering the whole burst, so a single scan doesn't fragment into several
partial alerts.

MITRE ATT&CK: T1046 (Network Service Discovery) when one host is probed,
T1595.001 (Active Scanning: Scanning IP Blocks) when the burst spans
multiple destination hosts.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ..alerts import Alert, Severity
from ..packets import PacketRecord

DEFAULT_WINDOW_SECONDS = 10.0
DEFAULT_PORT_THRESHOLD = 15


@dataclass
class _Hit:
    ts: float
    dst_ip: str
    dst_port: int


class PortScanDetector:
    name = "port_scan"

    def __init__(self, window: float = DEFAULT_WINDOW_SECONDS, threshold: int = DEFAULT_PORT_THRESHOLD):
        self.window = window
        self.threshold = threshold

    def analyze(self, records: list[PacketRecord]) -> list[Alert]:
        by_src: dict[str, list[_Hit]] = defaultdict(list)
        for rec in records:
            if rec.proto != "tcp" or rec.src_ip is None or rec.dst_ip is None:
                continue
            # bare SYN, no payload -> reconnaissance, not a real connection attempt
            if rec.tcp_flags == "S" and len(rec.payload) == 0:
                by_src[rec.src_ip].append(_Hit(rec.timestamp, rec.dst_ip, rec.dst_port))

        alerts: list[Alert] = []
        for src_ip, hits in by_src.items():
            hits.sort(key=lambda h: h.ts)
            session = [hits[0]]
            for h in hits[1:]:
                if h.ts - session[-1].ts <= self.window:
                    session.append(h)
                else:
                    alerts.extend(self._session_alert(src_ip, session))
                    session = [h]
            alerts.extend(self._session_alert(src_ip, session))
        return alerts

    def _session_alert(self, src_ip: str, session: list["_Hit"]) -> list[Alert]:
        distinct_ports = {h.dst_port for h in session}
        if len(distinct_ports) < self.threshold:
            return []
        distinct_targets = {h.dst_ip for h in session}
        technique = "T1046" if len(distinct_targets) == 1 else "T1595.001"
        return [
            Alert(
                source=self.name,
                signature="TCP SYN port scan",
                severity=Severity.HIGH,
                message=(
                    f"{src_ip} probed {len(distinct_ports)} distinct ports across "
                    f"{len(distinct_targets)} host(s) in {session[-1].ts - session[0].ts:.2f}s "
                    "(bare SYN, no handshake)"
                ),
                src_ip=src_ip,
                dst_ip=next(iter(distinct_targets)) if len(distinct_targets) == 1 else None,
                proto="tcp",
                mitre=[technique],
                timestamp=session[0].ts,
                evidence={
                    "distinct_ports": sorted(distinct_ports),
                    "distinct_targets": sorted(distinct_targets),
                    "hit_count": len(session),
                },
            )
        ]
