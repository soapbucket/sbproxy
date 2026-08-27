#!/usr/bin/env python3
"""Behavior tests for the public-item usage scanner."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scripts" / "scan-pub-item-usage.py"


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


if __name__ == "__main__":
    unittest.main()
