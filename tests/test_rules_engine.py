import pytest

from netsentry.packets import PacketRecord
from netsentry.rules import RuleEngine, parse_rule


def test_parses_header_and_options():
    rule = parse_rule(
        'alert tcp any any -> any 4444 (msg:"Reverse shell port"; flags:S; sid:1001; mitre:T1571; severity:high;)'
    )
    assert rule.sid == 1001
    assert rule.proto == "tcp"
    assert rule.dport == (4444, 4444)
    assert rule.flags == "S"
    assert rule.mitre == ["T1571"]
    assert rule.severity.value == "high"


def test_rejects_malformed_rule():
    with pytest.raises(ValueError):
        parse_rule("alert tcp any any any (msg:\"broken\"; sid:1;)")


def test_rejects_rule_missing_sid():
    with pytest.raises(ValueError):
        parse_rule('alert tcp any any -> any 80 (msg:"no sid";)')


def test_matches_destination_port_and_flags():
    """`flags:S` means "the SYN flag must be set", matching both a bare SYN
    and a SYN-ACK -- this is the documented "must ALL be set" (subset)
    semantics, not an exact-combination match."""
    rule = parse_rule('alert tcp any any -> any 4444 (msg:"m"; flags:S; sid:1;)')
    hit = PacketRecord(index=0, timestamp=0.0, proto="tcp", src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=4444, tcp_flags="S")
    miss_port = PacketRecord(index=1, timestamp=0.0, proto="tcp", src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=80, tcp_flags="S")
    syn_ack = PacketRecord(index=2, timestamp=0.0, proto="tcp", src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=4444, tcp_flags="SA")
    no_syn = PacketRecord(index=3, timestamp=0.0, proto="tcp", src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=4444, tcp_flags="A")

    assert rule.matches(hit) is True
    assert rule.matches(miss_port) is False
    assert rule.matches(syn_ack) is True
    assert rule.matches(no_syn) is False


def test_content_match_is_case_sensitive_unless_nocase():
    rule = parse_rule('alert tcp any any -> any any (msg:"m"; content:"cmd.exe"; nocase; sid:2;)')
    rec = PacketRecord(index=0, timestamp=0.0, proto="tcp", payload=b"running CMD.EXE now")
    assert rule.matches(rec) is True


def test_dsize_comparison():
    rule = parse_rule('alert icmp any any -> any any (msg:"big icmp"; dsize:>1000; sid:3;)')
    small = PacketRecord(index=0, timestamp=0.0, proto="icmp", payload=b"x" * 10)
    big = PacketRecord(index=1, timestamp=0.0, proto="icmp", payload=b"x" * 2000)
    assert rule.matches(small) is False
    assert rule.matches(big) is True


def test_cidr_source_match():
    rule = parse_rule('alert tcp 10.0.0.0/24 any -> any any (msg:"internal"; sid:4;)')
    inside = PacketRecord(index=0, timestamp=0.0, proto="tcp", src_ip="10.0.0.42")
    outside = PacketRecord(index=1, timestamp=0.0, proto="tcp", src_ip="192.168.1.1")
    assert rule.matches(inside) is True
    assert rule.matches(outside) is False


def test_rule_engine_scans_multiple_rules():
    rules = [
        parse_rule('alert tcp any any -> any 4444 (msg:"a"; sid:1;)'),
        parse_rule('alert tcp any any -> any 80 (msg:"b"; sid:2;)'),
    ]
    engine = RuleEngine(rules)
    rec = PacketRecord(index=0, timestamp=0.0, proto="tcp", dst_port=4444)
    alerts = engine.scan(rec)
    assert len(alerts) == 1
    assert alerts[0].sid == 1
