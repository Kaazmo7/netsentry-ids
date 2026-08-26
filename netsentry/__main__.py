"""CLI entrypoint: `python -m netsentry --pcap sample.pcap`"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import NetSentryEngine
from .packets import from_live, from_pcap
from .rules import RuleEngine, load_rules

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "signatures.rules"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netsentry",
        description="NetSentry-IDS -- signature + anomaly network intrusion detection engine.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", metavar="FILE", help="analyze an offline .pcap/.pcapng file")
    src.add_argument("--iface", metavar="IFACE", help="capture live from a network interface (requires root)")

    p.add_argument("--count", type=int, default=0, help="live capture: stop after N packets (0 = unlimited)")
    p.add_argument("--timeout", type=int, default=None, help="live capture: stop after N seconds")
    p.add_argument("--rules", metavar="FILE", default=str(DEFAULT_RULES_PATH), help="signature rules file")
    p.add_argument("--no-rules", action="store_true", help="disable the signature engine, anomaly detectors only")
    p.add_argument("--json", action="store_true", help="emit newline-delimited JSON alerts instead of a table")
    p.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low")
    return p


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    rule_engine = None
    if not args.no_rules:
        rules = load_rules(args.rules)
        rule_engine = RuleEngine(rules)

    if args.pcap:
        records = list(from_pcap(args.pcap))
    else:
        records = list(from_live(args.iface, count=args.count, timeout=args.timeout))

    engine = NetSentryEngine(rule_engine=rule_engine)
    alerts = engine.run(records)

    min_sev = _SEVERITY_ORDER[args.min_severity]
    alerts = [a for a in alerts if _SEVERITY_ORDER[a.severity.value] >= min_sev]

    if args.json:
        for a in alerts:
            print(a.to_json())
    else:
        _print_table(alerts, len(records))

    summary = NetSentryEngine.summarize(alerts)
    if not args.json:
        print(f"\n{summary['total']} alert(s) from {len(records)} packet(s).", file=sys.stderr)
        if summary["by_mitre_technique"]:
            techniques = ", ".join(f"{k}×{v}" for k, v in sorted(summary["by_mitre_technique"].items()))
            print(f"MITRE ATT&CK techniques observed: {techniques}", file=sys.stderr)

    return 1 if alerts else 0


def _print_table(alerts, packet_count: int, console=None) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        for a in alerts:
            print(a.one_line())
        return

    console = console or Console()
    table = Table(title=f"NetSentry-IDS -- {len(alerts)} alert(s) across {packet_count} packet(s)")
    table.add_column("Severity", style="bold")
    table.add_column("Signature")
    table.add_column("Source")
    table.add_column("MITRE")
    table.add_column("Detail", overflow="fold")

    severity_style = {"low": "dim", "medium": "yellow", "high": "red", "critical": "bold red"}
    for a in alerts:
        where = f"{a.src_ip or '?'} -> {a.dst_ip or '?'}" + (f":{a.dst_port}" if a.dst_port else "")
        table.add_row(
            f"[{severity_style.get(a.severity.value, '')}]{a.severity.value.upper()}[/]",
            a.signature,
            where,
            ",".join(a.mitre) or "-",
            a.message,
        )
    console.print(table)


if __name__ == "__main__":
    sys.exit(main())
