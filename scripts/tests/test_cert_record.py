#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/lib/cert_record.py (WOR-2201, WOR-2200)."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODULE_PATH = os.path.join(ROOT, "scripts", "lib", "cert_record.py")


def load_mod():
    spec = importlib.util.spec_from_file_location("cert_record", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class CertRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = load_mod()

    def test_seven_fields_are_named(self) -> None:
        self.assertEqual(
            self.mod.REQUIRED_FIELDS,
            (
                "macos_version",
                "chip",
                "memory_bytes",
                "engine_version",
                "artifact_digest",
                "time_to_ready_seconds",
                "first_token_result",
            ),
        )

    def test_missing_required_reports_empty_and_absent(self) -> None:
        missing = self.mod.missing_required(
            {"macos_version": "26.5.2", "chip": "", "memory_bytes": 1}
        )
        self.assertIn("chip", missing)
        self.assertIn("engine_version", missing)
        self.assertNotIn("macos_version", missing)
        self.assertNotIn("memory_bytes", missing)

    def test_live_rss_agrees_inside_overshoot_and_rejects_zero(self) -> None:
        agree = self.mod.live_rss_within_planned_envelope
        self.assertTrue(agree(1_000, 1_000))
        self.assertTrue(agree(1_000, 1_250))
        self.assertFalse(agree(1_000, 1_251))
        self.assertFalse(agree(0, 100))
        self.assertFalse(agree(100, 0))

    def test_write_round_trips_findings(self) -> None:
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
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "record.json")
            record = self.mod.write_record(path, host, findings)
            with open(path, encoding="utf-8") as handle:
                loaded = json.loads(handle.read())
            self.assertEqual(record["engine_version"], "b9415")
            self.assertEqual(loaded["artifact_digest"], "abc")
            self.assertEqual(loaded["chip"], "Apple M2")

    def test_agree_cli_rejects_overshoot(self) -> None:
        self.assertEqual(self.mod.main(["cert_record.py", "--agree", "1000", "1250"]), 0)
        self.assertEqual(self.mod.main(["cert_record.py", "--agree", "1000", "1251"]), 1)
        self.assertEqual(self.mod.main(["cert_record.py", "--agree", "2000", "100", "1000"]), 1)


if __name__ == "__main__":
    unittest.main()
