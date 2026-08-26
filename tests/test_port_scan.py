from netsentry import testkit
from netsentry.detectors.port_scan import PortScanDetector
from netsentry.packets import normalize


def _records(pkts):
    return [r for i, p in enumerate(pkts) if (r := normalize(p, i)) is not None]


def test_flags_a_real_port_scan():
    pkts = testkit.port_scan(base_time=0.0, n_ports=25)
    records = _records(pkts)

    alerts = PortScanDetector().analyze(records)

    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.50"
    assert alerts[0].evidence["hit_count"] >= 25
    assert "T1046" in alerts[0].mitre


def test_ignores_benign_browsing_traffic():
    pkts = testkit.benign_web_and_dns(base_time=0.0, n_flows=20)
    records = _records(pkts)

    alerts = PortScanDetector().analyze(records)

    assert alerts == []


def test_below_threshold_does_not_alert():
    pkts = testkit.port_scan(base_time=0.0, n_ports=5)  # threshold is 15
    records = _records(pkts)

    alerts = PortScanDetector().analyze(records)

    assert alerts == []


def test_server_side_syn_ack_is_not_a_scan():
    """The detector must key off SYNs *sent by* a host, not SYN-ACKs it receives
    while answering many client connections -- otherwise every busy server
    would look like it's scanning its own clients."""
    pkts = testkit.benign_web_and_dns(base_time=0.0, n_flows=25)
    records = _records(pkts)

    # low threshold to prove this isn't just "not enough volume"
    alerts = PortScanDetector(threshold=3).analyze(records)
    assert alerts == []
