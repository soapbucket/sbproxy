#!/usr/bin/env python3
"""Behavior tests for the public-item usage scanner."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scripts" / "scan-pub-item-usage.py"


def _scanner_module():
    """Import the scanner for direct calls, despite the hyphens in its name."""
    spec = importlib.util.spec_from_file_location("scan_pub_item_usage", SCANNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PubItemUsageScannerTest(unittest.TestCase):
    def test_example_only_consumer_stays_in_the_tests_only_bucket(self) -> None:
        """An example binary is a demo, not a shipping library consumer."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            source = repo / "crates" / "fixture" / "src"
            examples = repo / "crates" / "fixture" / "examples"
            source.mkdir(parents=True)
            examples.mkdir(parents=True)
            (source / "lib.rs").write_text("pub fn example_only() {}\n")
            (examples / "demo.rs").write_text(
                "use fixture::example_only;\nfn main() { example_only(); }\n"
            )

            completed = subprocess.run(
                [
                    "python3",
                    str(SCANNER),
                    "--repo",
                    str(repo),
                    "--count",
                    "tests-only",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.stdout.strip(), "1")


class CfgTestLineRangeTest(unittest.TestCase):
    """The brace counting `cfg_test_line_ranges` does, in both directions.

    This function decides which references count as production, so the
    direction it fails in decides whether the ratchet over-counts usage
    or under-counts it. Its docstring used to call any miscount
    conservative. Half of that was wrong, and nothing here caught it: a
    test fixture that matched on the byte string `data: {` extended a
    range in `ai_dispatch.rs` by roughly 5,000 lines, swallowed the only
    production reference to `sbproxy_ai::model_group::routing_name`, and
    reddened the ratchet while pointing at the wrong crate. These pin
    the asymmetry so the docstring is defended by something that runs.

    None of this is the real fix. Counting braces without lexing Rust
    cannot be made correct, and the remedy is to strip string and char
    literals before counting. That changes what the scanner reports
    across the whole tree, so it belongs in its own change with its own
    baseline re-derivation rather than here.
    """

    def test_an_unbalanced_opening_brace_runs_the_range_past_the_block(self) -> None:
        """The unsafe direction: the range swallows production code."""
        module = _scanner_module()
        lines = [
            "#[cfg(test)]\n",
            "mod tests {\n",
            '    const OPENER: &[u8] = b"data: {";\n',
            "}\n",
            "pub fn production_reference_below_the_block() {}\n",
        ]

        ranges = module.cfg_test_line_ranges(lines)

        self.assertEqual(ranges, [(1, 5)])
        covered = [
            line
            for number, line in enumerate(lines, start=1)
            if any(first <= number <= last for first, last in ranges)
        ]
        self.assertIn(
            "pub fn production_reference_below_the_block() {}\n",
            covered,
            "the stray `{` has to pull the production line into the test range, "
            "because that is what files a live reference as a test consumer and "
            "drives the tests-only count up",
        )

    def test_an_unbalanced_closing_brace_ends_the_range_early(self) -> None:
        """The safe direction: the range closes before the block does."""
        module = _scanner_module()
        lines = [
            "#[cfg(test)]\n",
            "mod tests {\n",
            '    const CLOSER: &str = "}";\n',
            "    fn genuinely_inside_the_block() {}\n",
            "}\n",
        ]

        ranges = module.cfg_test_line_ranges(lines)

        self.assertEqual(ranges, [(1, 3)])
        covered = [
            line
            for number, line in enumerate(lines, start=1)
            if any(first <= number <= last for first, last in ranges)
        ]
        self.assertNotIn(
            "    fn genuinely_inside_the_block() {}\n",
            covered,
            "the stray `}` has to close the range early, leaving test code read as "
            "production, which makes an item look more used rather than less",
        )

    def test_a_block_with_no_literal_braces_covers_exactly_itself(self) -> None:
        """The control, so the two above are about the literals."""
        module = _scanner_module()
        lines = [
            "pub fn before() {}\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    fn inside() {}\n",
            "}\n",
            "pub fn after() {}\n",
        ]

        self.assertEqual(module.cfg_test_line_ranges(lines), [(2, 5)])


if __name__ == "__main__":
    unittest.main()
