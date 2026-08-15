#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/lib/notice_coverage.py (WOR-2449)."""
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODULE_PATH = os.path.join(ROOT, "scripts", "lib", "notice_coverage.py")


def load_mod():
    spec = importlib.util.spec_from_file_location("notice_coverage", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class NoticeCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = load_mod()

    def test_apache_only_accepts_plain_apache(self) -> None:
        self.assertTrue(self.mod.is_apache_only("Apache-2.0"))

    def test_dual_mit_apache_is_not_apache_only(self) -> None:
        self.assertFalse(self.mod.is_apache_only("MIT OR Apache-2.0"))
        self.assertFalse(self.mod.is_apache_only("MIT/Apache-2.0"))

    def test_llvm_exception_is_excluded(self) -> None:
        self.assertFalse(self.mod.is_apache_only("Apache-2.0 WITH LLVM-exception"))

    def test_bsl_and_cc0_are_excluded(self) -> None:
        self.assertFalse(self.mod.is_apache_only("BSL-1.0"))
        self.assertFalse(self.mod.is_apache_only("CC0-1.0"))

    def test_r_efi_disjunction_is_not_apache_only(self) -> None:
        self.assertFalse(
            self.mod.is_apache_only("MIT OR Apache-2.0 OR LGPL-2.1-or-later")
        )

    def test_named_crate_is_not_reported(self) -> None:
        missing = self.mod.missing_from_notice(
            [
                {
                    "id": "swc",
                    "name": "swc_ecma_ast",
                    "version": "27.0.0",
                    "license": "Apache-2.0",
                }
            ],
            set(),
            "swc_ecma_ast, swc_ecma_parser\n",
        )
        self.assertEqual(missing, [])

    def test_unnamed_apache_only_crate_is_reported(self) -> None:
        missing = self.mod.missing_from_notice(
            [
                {
                    "id": "swc",
                    "name": "swc_ecma_parser",
                    "version": "43.0.0",
                    "license": "Apache-2.0",
                }
            ],
            set(),
            "pingora-core\n",
        )
        self.assertEqual(
            missing, [("swc_ecma_parser", "43.0.0", "Apache-2.0")]
        )

    def test_workspace_members_are_skipped(self) -> None:
        missing = self.mod.missing_from_notice(
            [
                {
                    "id": "ws",
                    "name": "sbproxy-extension",
                    "version": "0.1.0",
                    "license": "Apache-2.0",
                }
            ],
            {"ws"},
            "",
        )
        self.assertEqual(missing, [])

    def test_cli_fails_when_notice_omits_a_crate(self) -> None:
        metadata = {
            "workspace_members": [],
            "packages": [
                {
                    "id": "gap",
                    "name": "from_variant",
                    "version": "3.0.0",
                    "license": "Apache-2.0",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            notice = os.path.join(tmp, "NOTICE")
            with open(notice, "w", encoding="utf-8") as handle:
                handle.write("pingora-core\n")
            stdin = io.StringIO(json.dumps(metadata))
            captured = io.StringIO()
            with mock.patch("sys.stdin", stdin), mock.patch(
                "sys.stderr", captured
            ):
                rc = self.mod.main(
                    ["notice_coverage.py", "--notice", notice]
                )
            self.assertEqual(rc, 1)
            diagnostic = captured.getvalue()
            self.assertIn("from_variant", diagnostic)
            self.assertIn("WOR-2449", diagnostic)


if __name__ == "__main__":
    unittest.main()
