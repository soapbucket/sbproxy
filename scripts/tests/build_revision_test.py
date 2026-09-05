#!/usr/bin/env python3
"""Exercise the actual dependency-free build script, including Cargo cache invalidation."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "crates/sbproxy/build.rs"
VERSION_CHECK = ROOT / "scripts/check-release-version.sh"
REVISION = "0123456789abcdef0123456789abcdef01234567"


class BuildRevisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.directory.name)
        cls.executable = cls.root / "build-script"
        subprocess.run(
            ["rustc", "--edition=2021", str(BUILD_SCRIPT), "-o", str(cls.executable)],
            check=True, capture_output=True, text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def environment(self, revision=None):
        env = os.environ.copy()
        for name in ["SBPROXY_BUILD_REVISION", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]:
            env.pop(name, None)
        if revision is not None:
            env["SBPROXY_BUILD_REVISION"] = revision
        return env

    def run_script(self, revision=None):
        return subprocess.run(
            [str(self.executable)], cwd=self.root, env=self.environment(revision),
            capture_output=True, text=True,
        )

    def test_explicit_revision_works_without_git_metadata(self):
        result = self.run_script(REVISION)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"cargo:rustc-env=SBPROXY_GIT_SHA={REVISION}\n", result.stdout)

    def test_source_archive_without_override_keeps_unknown_fallback(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cargo:rustc-env=SBPROXY_GIT_SHA=unknown\n", result.stdout)

    def test_invalid_override_is_refused_instead_of_falling_back(self):
        for revision in ["", "abc1234", "A" * 40, "g" * 40, REVISION + "\n"]:
            with self.subTest(revision=repr(revision)):
                result = self.run_script(revision)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("SBPROXY_BUILD_REVISION", result.stderr)
                self.assertNotIn("cargo:rustc-env=SBPROXY_GIT_SHA=", result.stdout)

    def test_cargo_rebuilds_when_only_the_explicit_revision_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory) / "workspace"
            root = workspace / "crates/sbproxy"
            root.mkdir(parents=True)
            # Keep the build script's existing Git watch paths present and
            # unchanged. Missing watch paths would force Cargo to rebuild
            # every time, concealing a missing rerun-if-env-changed directive.
            (workspace / ".git/refs/heads").mkdir(parents=True)
            (workspace / ".git/refs/tags").mkdir()
            (workspace / ".git/HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname = "build-revision-fixture"\nversion = "0.0.0"\nedition = "2021"\n',
                encoding="utf-8",
            )
            shutil.copyfile(BUILD_SCRIPT, root / "build.rs")
            (root / "src/main.rs").write_text(
                'fn main() { println!("{}", env!("SBPROXY_GIT_SHA")); }\n',
                encoding="utf-8",
            )
            for revision in [REVISION, "f" * 40]:
                env = self.environment(revision)
                env["CARGO_TARGET_DIR"] = str(root / "target")
                result = subprocess.run(
                    ["cargo", "run", "--offline", "--quiet"], cwd=root, env=env,
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), revision)


class ReleaseVersionTests(unittest.TestCase):
    def verify(self, line, expected_revision=REVISION, expected_version="1.14.0", exit_code=0):
        with tempfile.TemporaryDirectory() as directory:
            executable = pathlib.Path(directory) / "sbproxy"
            executable.write_text(
                f"#!/usr/bin/env python3\nimport sys\nprint({line!r})\nsys.exit({exit_code})\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            return subprocess.run(
                ["bash", str(VERSION_CHECK), str(executable), expected_revision, expected_version],
                capture_output=True, text=True,
            )

    def test_matching_full_and_abbreviated_revisions_pass(self):
        for revision in [REVISION, REVISION[:9]]:
            result = self.verify(f"sbproxy 1.14.0 (rev {revision}, built 2026-09-05)")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_stale_and_malformed_metadata_are_refused(self):
        for line in [
            "sbproxy 1.14.0 (rev unknown, built 2026-09-05)",
            f"sbproxy 1.14.0 (rev {'f' * 40}, built 2026-09-05)",
            "sbproxy 1.14.0",
            f"sbproxy 1.14.0 (rev {REVISION}, built 2026-09-05)\nextra output",
        ]:
            with self.subTest(line=line):
                self.assertNotEqual(self.verify(line).returncode, 0)

    def test_wrong_release_version_is_refused(self):
        result = self.verify(f"sbproxy 1.13.0 (rev {REVISION}, built 2026-09-05)")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release tag", result.stderr)

    def test_invalid_expected_revision_is_refused(self):
        result = self.verify(
            f"sbproxy 1.14.0 (rev {REVISION}, built 2026-09-05)", expected_revision="",
        )
        self.assertNotEqual(result.returncode, 0)

    def test_failed_binary_is_refused_even_with_valid_output(self):
        result = self.verify(
            f"sbproxy 1.14.0 (rev {REVISION}, built 2026-09-05)", exit_code=1,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
