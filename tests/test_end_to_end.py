import pathlib
import subprocess
import sys
import tempfile

from netsentry import testkit
from netsentry.engine import NetSentryEngine
from netsentry.packets import from_pcap
from netsentry.rules import RuleEngine, load_rules

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES_PATH = REPO_ROOT / "rules" / "signatures.rules"


def test_shipped_rules_file_parses_cleanly():
    rules = load_rules(str(RULES_PATH))
    assert len(rules) >= 8
    assert len({r.sid for r in rules}) == len(rules)  # sids are unique


def test_pcap_round_trip_preserves_detectability():
    """Write synthetic attack traffic to an actual .pcap file and read it
    back through the real ingestion path (rdpcap), proving the detectors
    work against on-disk captures, not just in-memory packet lists."""
    with tempfile.TemporaryDirectory() as tmp:
        pcap_path = str(pathlib.Path(tmp) / "scan.pcap")
        from scapy.all import wrpcap

        wrpcap(pcap_path, testkit.port_scan(base_time=0.0, n_ports=25))

        records = list(from_pcap(pcap_path))
        engine = NetSentryEngine(rule_engine=None)
        alerts = engine.run(records)

        assert any(a.source == "port_scan" for a in alerts)


def test_full_demo_capture_trips_every_detector_and_no_more():
    rules = load_rules(str(RULES_PATH))
    records = list(from_pcap(str(REPO_ROOT / "samples" / "demo_attack.pcap")))
    engine = NetSentryEngine(rule_engine=RuleEngine(rules))
    alerts = engine.run(records)

    sources = {a.source for a in alerts}
    assert sources == {"signature", "port_scan", "arp_spoof", "dns_tunnel", "beaconing"}

    # every alert must be traceable back to a real packet in the capture
    assert all(a.timestamp is not None for a in alerts)


def test_cli_json_output_on_demo_capture():
    result = subprocess.run(
        [sys.executable, "-m", "netsentry", "--pcap", "samples/demo_attack.pcap", "--json"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 1  # alerts found -> non-zero exit by design
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    assert len(lines) >= 4
    import json

    first = json.loads(lines[0])
    assert "signature" in first and "severity" in first


def test_cli_exits_zero_on_clean_traffic():
    with tempfile.TemporaryDirectory() as tmp:
        pcap_path = str(pathlib.Path(tmp) / "clean.pcap")
        from scapy.all import wrpcap

        wrpcap(pcap_path, testkit.benign_web_and_dns(base_time=0.0, n_flows=10))

        result = subprocess.run(
            [sys.executable, "-m", "netsentry", "--pcap", pcap_path, "--json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""
