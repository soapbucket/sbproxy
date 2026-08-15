#!/usr/bin/env python3
"""Merge host metadata and lane findings into one certification record.

WOR-2201: a reader reconstructing a certification should not have to grep
lane log prose. One JSON object carries the seven fields the Apple
Silicon evidence promise lists, plus optional live-memory agreement
fields from WOR-2200.
"""

from __future__ import annotations

import json
import math
import sys
from typing import Any

REQUIRED_FIELDS = (
    "macos_version",
    "chip",
    "memory_bytes",
    "engine_version",
    "artifact_digest",
    "time_to_ready_seconds",
    "first_token_result",
)

LIVE_MEMORY_OVERSHOOT = 0.25


def live_rss_within_planned_envelope(
    planned_bytes: int, observed_rss_bytes: int, overshoot: float = LIVE_MEMORY_OVERSHOOT
) -> bool:
    """Match crates/sbproxy-model-host/src/fit.rs::live_rss_within_planned_envelope."""
    if planned_bytes <= 0 or observed_rss_bytes <= 0:
        return False
    if overshoot != overshoot or overshoot < 0.0:  # NaN or negative
        return False
    cap = math.ceil(planned_bytes * (1.0 + overshoot))
    return observed_rss_bytes <= cap


def merge_record(host: dict[str, Any], findings: dict[str, Any]) -> dict[str, Any]:
    """Host fields first, lane findings overwrite so the live run wins."""
    record = dict(host)
    record.update(findings)
    return record


def missing_required(record: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for key in REQUIRED_FIELDS:
        value = record.get(key)
        if value is None or value == "":
            missing.append(key)
    return missing


def write_record(path: str, host: dict[str, Any], findings: dict[str, Any]) -> dict[str, Any]:
    record = merge_record(host, findings)
    missing = missing_required(record)
    if missing:
        raise SystemExit(f"cert record missing required fields: {', '.join(missing)}")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return record


def _self_test() -> None:
    assert live_rss_within_planned_envelope(1000, 1000)
    assert live_rss_within_planned_envelope(1000, 1250)
    assert not live_rss_within_planned_envelope(1000, 1251)
    assert live_rss_within_planned_envelope(1000, 1)
    assert not live_rss_within_planned_envelope(1000, 0)
    assert not live_rss_within_planned_envelope(0, 1000)
    host = {
        "macos_version": "14.7",
        "chip": "Apple M2",
        "memory_bytes": 17179869184,
    }
    findings = {
        "engine_version": "b9415",
        "artifact_digest": "abc",
        "time_to_ready_seconds": 12,
        "first_token_result": "ready",
    }
    record = merge_record(host, findings)
    assert missing_required(record) == []
    assert missing_required(host) == [
        "engine_version",
        "artifact_digest",
        "time_to_ready_seconds",
        "first_token_result",
    ]
    print("PASS cert_record self-test")


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        _self_test()
        return 0
    if len(argv) >= 2 and argv[1] == "--agree":
        if len(argv) not in (4, 5):
            print(
                "usage: cert_record.py --agree <planned-bytes> <observed-rss-bytes> [probe-budget-bytes]",
                file=sys.stderr,
            )
            return 2
        planned = int(argv[2])
        observed = int(argv[3])
        budget = int(argv[4]) if len(argv) == 5 else 0
        if budget and planned > budget:
            print(
                f"planned {planned} exceeds probe budget {budget}",
                file=sys.stderr,
            )
            return 1
        if not live_rss_within_planned_envelope(planned, observed):
            cap = int((planned * (1.0 + LIVE_MEMORY_OVERSHOOT)).__ceil__())
            print(
                f"observed RSS {observed} exceeds planned {planned} "
                f"plus {LIVE_MEMORY_OVERSHOOT:.0%} overshoot (cap {cap})",
                file=sys.stderr,
            )
            return 1
        return 0
    if len(argv) != 4:
        print(
            "usage: cert_record.py --self-test | --agree <planned> <rss> [budget] | <host.json> <findings.json> <out.json>",
            file=sys.stderr,
        )
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        host = json.load(handle)
    with open(argv[2], encoding="utf-8") as handle:
        findings = json.load(handle)
    write_record(argv[3], host, findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
