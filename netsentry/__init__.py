"""NetSentry-IDS: a signature + anomaly based network intrusion detection engine.

Operates against offline packet captures (.pcap/.pcapng) or a live interface,
normalizes packets into a lightweight record format, and runs them through:

  1. A custom Snort-like signature rule engine (netsentry.rules)
  2. A set of stateful anomaly detectors (netsentry.detectors.*)

Every finding is emitted as an Alert (netsentry.alerts.Alert) tagged with a
MITRE ATT&CK technique ID where applicable, and can be rendered as JSON lines
or a Rich terminal table.
"""

__version__ = "1.0.0"
