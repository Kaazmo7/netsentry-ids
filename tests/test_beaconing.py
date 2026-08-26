from netsentry import testkit
from netsentry.detectors.beaconing import BeaconingDetector
from netsentry.packets import normalize


def _records(pkts):
    return [r for i, p in enumerate(pkts) if (r := normalize(p, i)) is not None]


def test_flags_regular_interval_connections():
    pkts = testkit.beaconing(base_time=0.0, n=10, interval=60.0, jitter=0.5)
    records = _records(pkts)

    alerts = BeaconingDetector().analyze(records)

    assert len(alerts) == 1
    a = alerts[0]
    assert a.dst_ip == "203.0.113.5"
    assert a.dst_port == 443
    assert 55 < a.evidence["mean_interval_s"] < 65
    assert a.evidence["coefficient_of_variation"] < 0.15
    assert "T1071" in a.mitre


def test_ignores_irregular_human_browsing():
    pkts = testkit.benign_web_and_dns(base_time=0.0, n_flows=15)
    records = _records(pkts)

    alerts = BeaconingDetector().analyze(records)

    assert alerts == []


def test_high_jitter_does_not_alert():
    """Interval variance above the CV threshold should not be flagged, even
    with plenty of connections -- this is what keeps the detector honest
    about *regularity*, not just repeated contact with the same host."""
    pkts = testkit.beaconing(base_time=0.0, n=10, interval=60.0, jitter=40.0)
    records = _records(pkts)

    alerts = BeaconingDetector().analyze(records)

    assert alerts == []
