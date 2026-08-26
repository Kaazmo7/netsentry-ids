#!/usr/bin/env python3
"""Regenerate samples/demo_attack.pcap -- a fully synthetic capture containing
benign traffic plus one instance of every attack pattern NetSentry-IDS knows
how to detect. Deterministic (fixed RNG seed) so the shipped .pcap always
matches what this script produces.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from netsentry.testkit import write_demo_capture  # noqa: E402

if __name__ == "__main__":
    out = pathlib.Path(__file__).resolve().parent / "demo_attack.pcap"
    write_demo_capture(str(out))
    print(f"wrote {out}")
