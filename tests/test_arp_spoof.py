from netsentry import testkit
from netsentry.detectors.arp_spoof import ArpSpoofDetector
from netsentry.packets import normalize


def _records(pkts):
    return [r for i, p in enumerate(pkts) if (r := normalize(p, i)) is not None]


def test_flags_conflicting_ip_to_mac_binding():
    pkts = testkit.arp_spoof(base_time=0.0, gateway_ip="10.0.0.1")
    records = _records(pkts)

    alerts = ArpSpoofDetector().analyze(records)

    # 1 legit binding + 3 spoofed replies -> first spoof triggers the alert,
    # the following two are the *same* new MAC so they don't re-alert
    assert len(alerts) == 1
    a = alerts[0]
    assert a.src_ip == "10.0.0.1"
    assert a.evidence["previous_mac"] == "aa:bb:cc:00:00:01"
    assert a.evidence["new_mac"] == "de:ad:be:ef:00:66"
    assert "T1557.002" in a.mitre


def test_stable_binding_does_not_alert():
    pkts = testkit.arp_spoof(base_time=0.0)[:1]  # only the legitimate reply
    records = _records(pkts)

    alerts = ArpSpoofDetector().analyze(records)

    assert alerts == []
