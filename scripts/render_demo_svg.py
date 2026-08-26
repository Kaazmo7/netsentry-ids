#!/usr/bin/env python3
"""Render docs/demo-alerts.svg -- a terminal-style snapshot of NetSentry-IDS
running against samples/demo_attack.pcap, embedded in the README."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console  # noqa: E402

from netsentry.__main__ import _print_table  # noqa: E402
from netsentry.engine import NetSentryEngine  # noqa: E402
from netsentry.packets import from_pcap  # noqa: E402
from netsentry.rules import RuleEngine, load_rules  # noqa: E402

if __name__ == "__main__":
    rules = load_rules(str(ROOT / "rules" / "signatures.rules"))
    records = list(from_pcap(str(ROOT / "samples" / "demo_attack.pcap")))
    engine = NetSentryEngine(rule_engine=RuleEngine(rules))
    alerts = engine.run(records)

    console = Console(record=True, width=150)
    _print_table(alerts, len(records), console=console)

    out = ROOT / "docs" / "demo-alerts.svg"
    console.save_svg(str(out), title="netsentry --pcap samples/demo_attack.pcap")
    print(f"wrote {out}")
