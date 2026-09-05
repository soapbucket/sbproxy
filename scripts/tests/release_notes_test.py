#!/usr/bin/env python3
"""Release notes must fit GitHub while preserving the complete tagged section."""

import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "release-notes.py"


class ReleaseNotesTests(unittest.TestCase):
    def render(self, changelog, version="1.14.0"):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "CHANGELOG.md"
            notes = root / "body.md"
            full = root / "release-notes.md"
            source.write_text(changelog, encoding="utf-8")
            result = subprocess.run(
                ["python3", str(SCRIPT), version, "--changelog", str(source),
                 "--notes-file", str(notes), "--full-notes-file", str(full)],
                capture_output=True, text=True,
            )
            return (result, notes.read_text() if notes.exists() else None,
                    full.read_text() if full.exists() else None)

    def test_short_notes_include_only_the_requested_version(self):
        section = "## [1.14.0] - 2026-09-05\n\n### Fixed\n\n- Repair.\n"
        result, notes, full = self.render(
            "# Changelog\n\n## [Unreleased]\n\nPending.\n\n" + section
            + "\n## [1.13.0] - 2026-08-18\n\nOld release.\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(notes, section)
        self.assertEqual(full, section)

    def test_large_notes_preserve_every_change_and_link_the_full_asset(self):
        section = "## [1.14.0] - 2026-09-05\n\n### Breaking\n\n- Upgrade together.\n" + "Details.\n" * 40000
        result, notes, full = self.render(section)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(full, section)
        self.assertLessEqual(len(notes.encode("utf-8")), 120000)
        self.assertIn("breaking changes", notes)
        self.assertIn("/releases/download/v1.14.0/release-notes.md", notes)
        self.assertIn("/blob/v1.14.0/CHANGELOG.md", notes)

    def test_multibyte_notes_use_a_conservative_byte_limit(self):
        section = "## [1.14.0] - 2026-09-05\n\n" + "修復" * 30000 + "\n"
        result, notes, full = self.render(section)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(full, section)
        self.assertLessEqual(len(notes.encode("utf-8")), 120000)

    def test_missing_version_refuses_to_publish_notes(self):
        result, notes, full = self.render("## [1.13.0] - 2026-08-18\n\nOld.\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)
        self.assertIsNone(notes)
        self.assertIsNone(full)

    def test_duplicate_version_refuses_to_choose_one(self):
        result, notes, full = self.render("## [1.14.0] - date\n\nOne.\n\n## [1.14.0] - date\n\nTwo.\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)
        self.assertIsNone(notes)
        self.assertIsNone(full)


if __name__ == "__main__":
    unittest.main()
