"""C2 beaconing detector.

Malware implants typically "call home" on a fixed or jittered interval
(e.g. every 60s +/- a few seconds) rather than communicating with the
burstiness of normal human/application traffic. We group TCP connection
attempts (SYNs) by (src_ip, dst_ip, dst_port), measure the coefficient of
variation (stdev/mean) of the inter-arrival times, and flag low-variance,
sustained periodicity as likely beaconing.

MITRE ATT&CK: T1071 (Application Layer Protocol) -- generic C2 channel;
T1008 is noted as a possibility in evidence when interval drift suggests a
fallback schedule, but we keep the primary tag conservative.
"""
from __future__ import annotations

import statistics
from collections import defaultdict

from ..alerts import Alert, Severity
from ..packets import PacketRecord

MIN_CONNECTIONS = 6
MAX_COEFFICIENT_OF_VARIATION = 0.15  # lower = more suspiciously regular


class BeaconingDetector:
    name = "beaconing"

    def __init__(self, min_connections: int = MIN_CONNECTIONS, max_cv: float = MAX_COEFFICIENT_OF_VARIATION):
        self.min_connections = min_connections
        self.max_cv = max_cv

    def analyze(self, records: list[PacketRecord]) -> list[Alert]:
        by_flow: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        for rec in records:
            if rec.proto != "tcp" or rec.tcp_flags != "S" or len(rec.payload) != 0:
                continue
            by_flow[(rec.src_ip, rec.dst_ip, rec.dst_port)].append(rec.timestamp)

        alerts: list[Alert] = []
        for (src_ip, dst_ip, dst_port), timestamps in by_flow.items():
            if len(timestamps) < self.min_connections:
                continue
            timestamps.sort()
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
            if len(intervals) < 2:
                continue
            mean = statistics.mean(intervals)
            if mean <= 0:
                continue
            stdev = statistics.pstdev(intervals)
            cv = stdev / mean
            if cv <= self.max_cv:
                alerts.append(
                    Alert(
                        source=self.name,
                        signature="Periodic beaconing",
                        severity=Severity.HIGH,
                        message=(
                            f"{src_ip} -> {dst_ip}:{dst_port} shows {len(timestamps)} connections at a "
                            f"near-fixed {mean:.1f}s interval (coefficient of variation {cv:.3f}) "
                            "-- consistent with malware C2 check-in behavior"
                        ),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        proto="tcp",
                        mitre=["T1071"],
                        timestamp=timestamps[0],
                        evidence={
                            "connection_count": len(timestamps),
                            "mean_interval_s": round(mean, 2),
                            "coefficient_of_variation": round(cv, 4),
                        },
                    )
                )
        return alerts
