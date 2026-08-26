"""Alert model shared by the signature engine and every anomaly detector."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """A single detection finding.

    `source` identifies which subsystem raised it ("signature" or a detector
    name like "port_scan"). `mitre` is a list of MITRE ATT&CK technique IDs
    (e.g. ["T1046"]) so findings can be rolled up into an ATT&CK-style
    coverage view, which is how most SOC tooling reports to stakeholders.
    """

    source: str
    signature: str
    severity: Severity
    message: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    mitre: list[str] = field(default_factory=list)
    sid: Optional[int] = None
    packet_index: Optional[int] = None
    timestamp: Optional[float] = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    def one_line(self) -> str:
        where = f"{self.src_ip or '?'}:{self.src_port or '-'} -> {self.dst_ip or '?'}:{self.dst_port or '-'}"
        mitre = f" [{','.join(self.mitre)}]" if self.mitre else ""
        return f"[{self.severity.value.upper():8}] {self.signature}{mitre}: {self.message} ({where})"
