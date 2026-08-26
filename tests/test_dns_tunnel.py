from netsentry import testkit
from netsentry.detectors.dns_tunnel import DnsTunnelDetector, _shannon_entropy
from netsentry.packets import normalize


def _records(pkts):
    return [r for i, p in enumerate(pkts) if (r := normalize(p, i)) is not None]


def test_entropy_helper_ranks_random_above_english():
    assert _shannon_entropy("aaaaaaaa") == 0.0
    assert _shannon_entropy("k3jf9as8dl2m") > _shannon_entropy("mail")


def test_flags_high_volume_high_entropy_queries():
    pkts = testkit.dns_tunnel(base_time=0.0, n=20)
    records = _records(pkts)

    alerts = DnsTunnelDetector().analyze(records)

    assert len(alerts) == 1
    a = alerts[0]
    assert a.src_ip == "10.0.0.77"
    assert a.evidence["base_domain"] == "example.com"  # last-two-labels heuristic
    assert a.evidence["query_count"] >= 12
    assert "T1071.004" in a.mitre


def test_ignores_normal_dns_lookups():
    pkts = testkit.benign_web_and_dns(base_time=0.0, n_flows=20)
    records = _records(pkts)

    alerts = DnsTunnelDetector().analyze(records)

    assert alerts == []


def test_single_odd_query_is_not_enough_volume():
    pkts = testkit.dns_tunnel(base_time=0.0, n=3)  # below MIN_QUERIES_FOR_TUNNEL
    records = _records(pkts)

    alerts = DnsTunnelDetector().analyze(records)

    assert alerts == []
