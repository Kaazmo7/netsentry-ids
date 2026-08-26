"""A small Snort-inspired signature rule engine.

Rule syntax (one rule per non-comment line):

    alert <proto> <src> <sport> -> <dst> <dport> (opt:val; opt:val; ...)

`proto` is tcp|udp|icmp|any. `src`/`dst` are an IP, a CIDR, or "any".
`sport`/`dport` are a port number, a range "low:high", or "any".

Supported options:
    msg:"text"          human-readable description (required)
    sid:<int>            unique rule id (required)
    rev:<int>            rule revision (default 1)
    mitre:T1046[,T1595]  comma-separated MITRE ATT&CK technique ids
    severity:low|medium|high|critical   (default medium)
    flags:<chars>         TCP flags that must ALL be set, e.g. "S", "SA"
    content:"substring"   payload must contain this substring (byte match)
    nocase                 (place after a content option) case-insensitive
    dsize:<op><int>        payload length compare, e.g. ">100", "<20", "=64"
    ttl:<op><int>           IP TTL compare, e.g. "<10"

Example:
    alert tcp any any -> any 4444 (msg:"Possible reverse shell port"; \
        flags:S; sid:1001; mitre:T1571; severity:high;)
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from .alerts import Alert, Severity
from .packets import PacketRecord

_HEADER_RE = re.compile(
    r"^\s*alert\s+(?P<proto>\w+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s+->\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s+\((?P<opts>.*)\)\s*$"
)

_OP_RE = re.compile(r"^(?P<op>[<>=]?)(?P<val>-?\d+)$")


def _match_op(op: str, val: int, target: int) -> bool:
    if op == ">" or op == "":
        return target > val if op == ">" else target == val
    if op == "<":
        return target < val
    if op == ">=":
        return target >= val
    if op == "<=":
        return target <= val
    if op == "=":
        return target == val
    return False


def _parse_endpoint(tok: str):
    if tok == "any":
        return None
    try:
        return ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return ipaddress.ip_network(tok + "/32", strict=False)


def _parse_port(tok: str):
    if tok == "any":
        return None
    if ":" in tok:
        lo, hi = tok.split(":", 1)
        return (int(lo), int(hi))
    return (int(tok), int(tok))


@dataclass
class Rule:
    sid: int
    proto: str
    src: Optional[object]
    sport: Optional[tuple]
    dst: Optional[object]
    dport: Optional[tuple]
    msg: str
    mitre: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    rev: int = 1
    flags: Optional[str] = None
    content: Optional[bytes] = None
    content_nocase: bool = False
    dsize_op: Optional[str] = None
    dsize_val: Optional[int] = None
    ttl_op: Optional[str] = None
    ttl_val: Optional[int] = None
    raw: str = ""

    def matches(self, rec: PacketRecord) -> bool:
        if self.proto != "any" and rec.proto != self.proto:
            return False
        if self.src is not None:
            if rec.src_ip is None or ipaddress.ip_address(rec.src_ip) not in self.src:
                return False
        if self.dst is not None:
            if rec.dst_ip is None or ipaddress.ip_address(rec.dst_ip) not in self.dst:
                return False
        if self.sport is not None:
            if rec.src_port is None or not (self.sport[0] <= rec.src_port <= self.sport[1]):
                return False
        if self.dport is not None:
            if rec.dst_port is None or not (self.dport[0] <= rec.dst_port <= self.dport[1]):
                return False
        if self.flags is not None:
            if not rec.flags_include(self.flags):
                return False
        if self.content is not None:
            hay = rec.payload.lower() if self.content_nocase else rec.payload
            needle = self.content.lower() if self.content_nocase else self.content
            if needle not in hay:
                return False
        if self.dsize_op is not None:
            if not _match_op(self.dsize_op, self.dsize_val, len(rec.payload)):
                return False
        if self.ttl_op is not None:
            if rec.ttl is None or not _match_op(self.ttl_op, self.ttl_val, rec.ttl):
                return False
        return True

    def to_alert(self, rec: PacketRecord) -> Alert:
        return Alert(
            source="signature",
            signature=self.msg,
            severity=self.severity,
            message=self.msg,
            src_ip=rec.src_ip,
            dst_ip=rec.dst_ip,
            src_port=rec.src_port,
            dst_port=rec.dst_port,
            proto=rec.proto,
            mitre=list(self.mitre),
            sid=self.sid,
            packet_index=rec.index,
            timestamp=rec.timestamp,
        )


def _parse_options(opts_str: str) -> dict:
    """Split a `;`-separated option string, respecting quoted strings."""
    opts = []
    buf = ""
    in_quotes = False
    for ch in opts_str:
        if ch == '"':
            in_quotes = not in_quotes
            buf += ch
        elif ch == ";" and not in_quotes:
            if buf.strip():
                opts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        opts.append(buf.strip())

    parsed: dict = {}
    for opt in opts:
        if ":" in opt:
            key, _, val = opt.partition(":")
            key = key.strip()
            val = val.strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            parsed[key] = val
        else:
            parsed[opt.strip()] = True
    return parsed


def parse_rule(line: str) -> Optional[Rule]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _HEADER_RE.match(line)
    if not m:
        raise ValueError(f"Malformed rule (header): {line!r}")
    opts = _parse_options(m.group("opts"))

    if "sid" not in opts or "msg" not in opts:
        raise ValueError(f"Rule missing required sid/msg: {line!r}")

    dsize_op = dsize_val = None
    if "dsize" in opts:
        dm = re.match(r"^(?P<op>[<>=]?)(?P<val>\d+)$", opts["dsize"])
        if not dm:
            raise ValueError(f"Bad dsize in rule: {line!r}")
        dsize_op = dm.group("op") or "="
        dsize_val = int(dm.group("val"))

    ttl_op = ttl_val = None
    if "ttl" in opts:
        tm = re.match(r"^(?P<op>[<>=]?)(?P<val>\d+)$", opts["ttl"])
        if not tm:
            raise ValueError(f"Bad ttl in rule: {line!r}")
        ttl_op = tm.group("op") or "="
        ttl_val = int(tm.group("val"))

    content = opts.get("content")
    return Rule(
        sid=int(opts["sid"]),
        proto=m.group("proto").lower(),
        src=_parse_endpoint(m.group("src")),
        sport=_parse_port(m.group("sport")),
        dst=_parse_endpoint(m.group("dst")),
        dport=_parse_port(m.group("dport")),
        msg=opts["msg"],
        mitre=[t.strip() for t in opts.get("mitre", "").split(",") if t.strip()],
        severity=Severity(opts.get("severity", "medium")),
        rev=int(opts.get("rev", 1)),
        flags=opts.get("flags"),
        content=content.encode() if content else None,
        content_nocase="nocase" in opts,
        dsize_op=dsize_op,
        dsize_val=dsize_val,
        ttl_op=ttl_op,
        ttl_val=ttl_val,
        raw=line,
    )


def load_rules(path: str) -> list[Rule]:
    rules = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            try:
                rule = parse_rule(line)
            except ValueError as e:
                raise ValueError(f"{path}:{lineno}: {e}") from e
            if rule is not None:
                rules.append(rule)
    return rules


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def scan(self, rec: PacketRecord) -> list[Alert]:
        return [r.to_alert(rec) for r in self.rules if r.matches(rec)]
