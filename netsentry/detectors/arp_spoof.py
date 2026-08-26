"""ARP spoofing / cache poisoning detector.

Tracks every (IP -> claimed MAC) binding seen in ARP traffic. A legitimate
host's IP should map to exactly one MAC address for the life of the capture;
a second, different MAC claiming the same IP is the signature of an
ARP-spoofing man-in-the-middle attack (e.g. arpspoof / ettercap).

MITRE ATT&CK: T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning)
"""
from __future__ import annotations

from ..alerts import Alert, Severity
from ..packets import PacketRecord


class ArpSpoofDetector:
    name = "arp_spoof"

    def analyze(self, records: list[PacketRecord]) -> list[Alert]:
        bindings: dict[str, str] = {}
        alerts: list[Alert] = []

        for rec in records:
            if rec.proto != "arp" or rec.arp_op != 2:  # only ARP *replies* assert a binding
                continue
            ip, mac = rec.arp_spa, rec.arp_sha
            if ip is None or mac is None:
                continue

            prior = bindings.get(ip)
            if prior is None:
                bindings[ip] = mac
            elif prior != mac:
                alerts.append(
                    Alert(
                        source=self.name,
                        signature="ARP cache poisoning",
                        severity=Severity.CRITICAL,
                        message=(
                            f"IP {ip} changed owner from MAC {prior} to {mac} mid-capture "
                            "-- classic ARP spoofing / MITM signature"
                        ),
                        src_ip=ip,
                        proto="arp",
                        mitre=["T1557.002"],
                        packet_index=rec.index,
                        timestamp=rec.timestamp,
                        evidence={"previous_mac": prior, "new_mac": mac},
                    )
                )
                bindings[ip] = mac  # track the latest claim to avoid alert storms on flapping

        return alerts
