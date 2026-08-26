"""Orchestrates the signature engine and every anomaly detector over a
stream of normalized packets, and sorts the combined findings for report."""
from __future__ import annotations

from typing import Iterable, Optional

from .alerts import Alert
from .detectors import ALL_DETECTORS
from .packets import PacketRecord
from .rules import RuleEngine


class NetSentryEngine:
    def __init__(self, rule_engine: Optional[RuleEngine] = None, detectors: Optional[list] = None):
        self.rule_engine = rule_engine
        self.detectors = [d() for d in (detectors if detectors is not None else ALL_DETECTORS)]

    def run(self, records: Iterable[PacketRecord]) -> list[Alert]:
        records = list(records)
        alerts: list[Alert] = []

        if self.rule_engine is not None:
            for rec in records:
                alerts.extend(self.rule_engine.scan(rec))

        for detector in self.detectors:
            alerts.extend(detector.analyze(records))

        alerts.sort(key=lambda a: (a.timestamp or 0.0, a.sid or 0))
        return alerts

    @staticmethod
    def summarize(alerts: list[Alert]) -> dict:
        by_severity: dict[str, int] = {}
        by_mitre: dict[str, int] = {}
        for a in alerts:
            by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
            for t in a.mitre:
                by_mitre[t] = by_mitre.get(t, 0) + 1
        return {"total": len(alerts), "by_severity": by_severity, "by_mitre_technique": by_mitre}
