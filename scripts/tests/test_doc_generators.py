#!/usr/bin/env python3
"""Behavior tests for documentation recording and generation scripts."""

from __future__ import annotations

import os
import http.server
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
import unittest.mock


REPOSITORY = Path(__file__).resolve().parents[2]


def write_executable(path: Path, contents: str) -> None:
    path.write_text(textwrap.dedent(contents).lstrip())
    path.chmod(0o755)


def reserve_port() -> int:
    """A free loopback TCP port, the way the rest of the suites pick one.

    These tests used to hardcode 18080 and 18091. Two gates could not run
    at once because of it: a second worktree's run bound the same pair and
    failed on "address already in use", so gate runs across worktrees were
    serialized by a constant in this file. The recorder connects to the
    port it is given, so the value only has to be free, not fixed.

    Bind port zero, read what the kernel assigned, and close. There is a
    window between the close and the fixture's own bind, which is the same
    window every port-zero allocator in this repository lives with; the
    kernel does not hand the same ephemeral port to two live listeners, and
    a collision here fails loudly on bind rather than corrupting a result.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class TemporaryRepository(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "scripts").mkdir()
        (self.root / "docs" / "tapes").mkdir(parents=True)
        (self.root / "docs" / "assets").mkdir(parents=True)
        (self.root / "examples").mkdir()
        # Allocated per test, so concurrent gates in separate worktrees do
        # not fight over one pair of constants.
        self.main_port = reserve_port()
        self.aux_port = reserve_port()

    def tearDown(self) -> None:
        # These tests start real listeners, and one of them deliberately
        # spawns a proxy that ignores SIGTERM so the recorder's escalation
        # can be observed. When a run dies before that escalation, the
        # listener outlives it, holds the fixture port, and fails every
        # later run with an assertion about missing STOP events. The
        # failure then perpetuates itself, because each failed run leaks
        # another one. Three gate cycles were lost to that loop before
        # this existed.
        #
        # Every process these tests start carries the temp root in its
        # command line, and the root is unique per test, so matching on it
        # cannot reach anything else on the machine.
        subprocess.run(
            ["pkill", "-9", "-f", str(self.root)],
            capture_output=True,
            check=False,
        )
        self.tempdir.cleanup()

    def copy_script(self, name: str) -> Path:
        target = self.root / "scripts" / name
        shutil.copy2(REPOSITORY / "scripts" / name, target)
        return target

    def run_script(
        self,
        name: str,
        *arguments: str,
        env: dict[str, str] | None = None,
        timeout: int = 20,
    ) -> subprocess.CompletedProcess[str]:
        command_env = os.environ.copy()
        if env:
            command_env.update(env)
        command = [str(self.root / "scripts" / name), *arguments]
        if name.endswith(".py"):
            command.insert(0, sys.executable)
        return subprocess.run(
            command,
            cwd=self.root,
            env=command_env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )


class RecordTapesTests(TemporaryRepository):
    def setUp(self) -> None:
        super().setUp()
        self.copy_script("record-tapes.sh")
        self.bin_dir = self.root / "fake-bin"
        self.bin_dir.mkdir()
        self.events = self.root / "sbproxy-events.log"
        self.vhs_events = self.root / "vhs-events.log"

        write_executable(
            self.bin_dir / "sbproxy",
            r"""
            #!/usr/bin/env python3
            import http.server
            import os
            from pathlib import Path
            import signal

            config = Path(__import__("sys").argv[-1])
            port = next(
                int(line.split(":", 1)[1].strip())
                for line in config.read_text().splitlines()
                if line.strip().startswith("http_bind_port:")
            )
            events = Path(os.environ["FAKE_SBPROXY_EVENTS"])
            with events.open("a") as stream:
                stream.write(
                    f"START {config.name} {os.getpid()} "
                    f"{os.environ.get('SBPROXY_REC_LOG', '')}\n"
                )

            if config.name == os.environ.get("FAKE_FAIL_CONFIG"):
                print(os.environ["FAKE_LOG_SECRET"], flush=True)
                raise SystemExit(42)

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()

                def log_message(self, *_args):
                    pass

            def stop(_signum, _frame):
                with events.open("a") as stream:
                    stream.write(f"STOP {config.name} {os.getpid()}\n")
                os._exit(0)

            if config.name == os.environ.get("FAKE_IGNORE_TERM_CONFIG"):
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            else:
                signal.signal(signal.SIGTERM, stop)
            server = http.server.HTTPServer(("127.0.0.1", port), Handler)
            server.serve_forever()
            """,
        )
        write_executable(
            self.bin_dir / "vhs",
            r"""
            #!/usr/bin/env bash
            printf '%s\n' "$1" >> "$FAKE_VHS_EVENTS"
            """,
        )
        write_executable(
            self.bin_dir / "lsof",
            r"""
            #!/usr/bin/env bash
            case "$*" in
              *"tcp:${FAKE_OCCUPIED_PORT}"*)
                printf '%s\n' "$FAKE_UNRELATED_PID"
                ;;
            esac
            """,
        )

    def recorder_env(
        self, unrelated_pid: int, occupied_port: int
    ) -> dict[str, str]:
        return {
            "PATH": f"{self.bin_dir}:{os.environ['PATH']}",
            "SBPROXY_BIN": str(self.bin_dir / "sbproxy"),
            "SBPROXY_DEMO_ENV": str(self.root / "no-credentials.env"),
            "FAKE_SBPROXY_EVENTS": str(self.events),
            "FAKE_VHS_EVENTS": str(self.vhs_events),
            "FAKE_UNRELATED_PID": str(unrelated_pid),
            "FAKE_OCCUPIED_PORT": str(occupied_port),
        }

    def write_recording(self) -> None:
        (self.root / "main.yml").write_text(
            f"proxy:\n  http_bind_port: {self.main_port}\n"
        )
        (self.root / "aux.yml").write_text(
            f"proxy:\n  http_bind_port: {self.aux_port}\n"
        )
        (self.root / "docs" / "tapes" / "demo.tape").write_text(
            "# CONFIG: main.yml\n"
            "# AUX_CONFIG: aux.yml\n"
            'Output "docs/assets/demo.gif"\n'
        )

    def test_record_tapes_starts_and_stops_aux_without_killing_other_owner(
        self,
    ) -> None:
        self.write_recording()
        unrelated = subprocess.Popen(["sleep", "60"])
        try:
            result = self.run_script(
                "record-tapes.sh",
                "demo",
                env=self.recorder_env(unrelated.pid, 9090),
            )

            self.assertEqual(
                result.returncode, 0, result.stdout + result.stderr
            )
            self.assertIsNone(
                unrelated.poll(), "recorder killed an unrelated port owner"
            )
            events = self.events.read_text().splitlines()
            self.assertEqual(
                sorted(line.split()[1] for line in events if line.startswith("START ")),
                ["aux.yml", "main.yml"],
            )
            self.assertEqual(
                sorted(line.split()[1] for line in events if line.startswith("STOP ")),
                ["aux.yml", "main.yml"],
            )
            log_paths = [
                line.split(maxsplit=3)[3]
                for line in events
                if line.startswith("START ")
            ]
            self.assertEqual(len(set(log_paths)), 2)
            self.assertTrue(all(Path(path).parent != Path("/tmp") for path in log_paths))
        finally:
            if unrelated.poll() is None:
                unrelated.terminate()
            unrelated.wait()

    def test_record_tapes_rejects_an_occupied_required_port(self) -> None:
        self.write_recording()
        unrelated = subprocess.Popen(["sleep", "60"])
        try:
            result = self.run_script(
                "record-tapes.sh",
                "demo",
                env=self.recorder_env(unrelated.pid, self.main_port),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(str(self.main_port), result.stdout + result.stderr)
            self.assertIsNone(
                unrelated.poll(), "recorder killed the occupied port owner"
            )
            self.assertFalse(self.events.exists())
        finally:
            if unrelated.poll() is None:
                unrelated.terminate()
            unrelated.wait()

    def test_record_tapes_bounds_shutdown_of_its_own_processes(self) -> None:
        self.write_recording()
        unrelated = subprocess.Popen(["sleep", "60"])
        env = self.recorder_env(unrelated.pid, 19090)
        env["FAKE_IGNORE_TERM_CONFIG"] = "main.yml"
        command_env = os.environ.copy()
        command_env.update(env)
        process = subprocess.Popen(
            [str(self.root / "scripts" / "record-tapes.sh"), "demo"],
            cwd=self.root,
            env=command_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            try:
                stdout, stderr = process.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                if self.events.exists():
                    for line in self.events.read_text().splitlines():
                        if line.startswith("START "):
                            try:
                                os.kill(int(line.split()[2]), 9)
                            except ProcessLookupError:
                                pass
                self.fail("recorder waited forever for an owned process to exit")
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertIsNone(unrelated.poll())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if unrelated.poll() is None:
                unrelated.terminate()
            unrelated.wait()

    def test_failed_start_hides_logs_and_removes_its_workspace(self) -> None:
        self.write_recording()
        secret = "startup-log-secret-must-not-escape"
        env = self.recorder_env(999_999, 19090)
        env["FAKE_FAIL_CONFIG"] = "main.yml"
        env["FAKE_LOG_SECRET"] = secret

        result = self.run_script("record-tapes.sh", "demo", env=env)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(secret, result.stdout + result.stderr)
        events = self.events.read_text().splitlines()
        main_start = next(
            line for line in events if line.startswith("START main.yml ")
        )
        main_log = Path(main_start.split(maxsplit=3)[3])
        self.assertFalse(
            main_log.parent.exists(),
            "recorder left its failed-start workspace on disk",
        )


class RecordedTapeCompatibilityTests(unittest.TestCase):
    def test_log_reading_tapes_use_the_per_recording_log_path(self) -> None:
        for name in (
            "ai-fallback.tape",
            "use-case-production-ops.tape",
            "use-case-serve-on-l4.tape",
        ):
            with self.subTest(name=name):
                contents = (REPOSITORY / "docs" / "tapes" / name).read_text()
                self.assertNotIn("/tmp/sbproxy-rec.log", contents)
                self.assertIn("$SBPROXY_REC_LOG", contents)


class AdminScreenshotCaptureTests(unittest.TestCase):
    def test_extension_route_can_be_captured_without_rewriting_other_assets(
        self,
    ) -> None:
        script = (REPOSITORY / "scripts" / "capture-admin-screenshots.mjs").read_text()

        self.assertIn(
            '{ path: "/admin/ui/extensions", file: "admin-extensions.png" }',
            script,
        )
        self.assertIn("ADMIN_SCREENSHOTS", script)
        self.assertIn("selectedRoutes", script)


class ConformanceRunnerSafetyTests(unittest.TestCase):
    def test_occupied_callback_port_is_rejected_without_http_probe(self) -> None:
        requests: list[str] = []

        class UnrelatedHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        # Reserved rather than fixed, so two gates in two worktrees can run
        # this at the same time. The runner reads the same port from the
        # environment below, so the test still occupies the port the runner
        # is about to want, which is the whole point of the case.
        callback_port = reserve_port()
        server = http.server.HTTPServer(
            ("127.0.0.1", callback_port), UnrelatedHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = os.environ.copy()
            env["SBPROXY_BIN"] = "/usr/bin/true"
            env["SBPROXY_CONFORMANCE_CALLBACK_PORT"] = str(callback_port)
            result = subprocess.run(
                [
                    "bash",
                    str(REPOSITORY / "e2e" / "conformance" / "run-tests.sh"),
                    "01",
                ],
                cwd=REPOSITORY,
                env=env,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(callback_port), result.stdout + result.stderr)
        self.assertEqual(
            requests,
            [],
            "runner probed or sent test traffic to an unrelated listener",
        )


class GenerateExampleTapesTests(TemporaryRepository):
    def setUp(self) -> None:
        super().setUp()
        self.copy_script("gen-example-tapes.py")

    def write_example(self, name: str, model: str) -> Path:
        directory = self.root / "examples" / name
        directory.mkdir()
        config = directory / "sb.yml"
        config.write_text(
            "# Test:\n"
            "#   curl -s http://127.0.0.1:8080/v1/chat/completions \\\n"
            f"#     -d '{{\"model\":\"{model}\"}}'\n"
            "proxy:\n"
            "  http_bind_port: 8080\n"
            "origins:\n"
            f'  "{name}.local":\n'
            "    action:\n"
            "      type: ai_proxy\n"
            f"      default_model: {model}\n"
        )
        return config

    def test_the_word_do_in_a_request_body_is_not_a_shell_separator(self) -> None:
        """A prompt containing "do" must survive the multi-line join.

        The join inserts `; do` so a `for ... do` loop still runs after its
        newlines are removed. That rewrite used to match the bare word `do`
        anywhere, so the ai-rag-local example's "When do refunds arrive?"
        was recorded as "When; do refunds arrive?" and the cassette showed a
        malformed question. Nothing caught it: the tape was still generated,
        still current, and still passed `make tapes-check`.
        """
        directory = self.root / "examples" / "prose"
        directory.mkdir()
        (directory / "sb.yml").write_text(
            "# Test:\n"
            "#   curl -s http://127.0.0.1:8080/v1/chat/completions \\\n"
            '#     -d \'{"messages":[{"role":"user",'
            '"content":"When do refunds arrive?"}]}\'\n'
            "proxy:\n"
            "  http_bind_port: 8080\n"
            "origins:\n"
            '  "prose.local":\n'
            "    action:\n"
            "      type: ai_proxy\n"
            "      default_model: claude-3-opus-latest\n"
        )

        self.run_script("gen-example-tapes.py", "--only", "prose")

        tape = (self.root / "docs" / "tapes" / "prose.tape").read_text()
        self.assertIn("When do refunds arrive?", tape)
        self.assertNotIn("When; do", tape)

    def test_a_real_shell_loop_still_gets_its_separator(self) -> None:
        """The guard must not break the case the rewrite exists for."""
        directory = self.root / "examples" / "loop"
        directory.mkdir()
        (directory / "sb.yml").write_text(
            "# Test:\n"
            "#   for i in $(seq 1 3); do\n"
            "#     curl -s http://127.0.0.1:8080/health\n"
            "#   done\n"
            "proxy:\n"
            "  http_bind_port: 8080\n"
            "origins:\n"
            '  "loop.local":\n'
            "    action:\n"
            "      type: ai_proxy\n"
            "      default_model: claude-3-opus-latest\n"
        )

        self.run_script("gen-example-tapes.py", "--only", "loop")

        tape = (self.root / "docs" / "tapes" / "loop.tape").read_text()
        self.assertIn("; do", tape)
        self.assertIn("; done", tape)

    def test_check_reports_only_selected_drift_without_writing_files(self) -> None:
        selected = self.write_example("selected", "claude-3-opus-latest")
        other = self.write_example("other", "gemini-1.5-pro")
        before = {
            selected: selected.read_bytes(),
            other: other.read_bytes(),
        }

        result = self.run_script(
            "gen-example-tapes.py", "--check", "--only", "selected"
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("selected", result.stdout)
        self.assertNotIn("other", result.stdout)
        self.assertEqual(
            list((self.root / "docs" / "tapes").iterdir()),
            [],
            "--check wrote a generated tape",
        )
        self.assertEqual(selected.read_bytes(), before[selected])
        self.assertEqual(other.read_bytes(), before[other])

    def test_generation_never_rewrites_source_example_models(self) -> None:
        config = self.write_example("demo", "claude-3-opus-latest")
        before = config.read_bytes()

        result = self.run_script("gen-example-tapes.py", "--only", "demo")

        self.assertEqual(
            result.returncode, 0, result.stdout + result.stderr
        )
        self.assertEqual(config.read_bytes(), before)
        tape = self.root / "docs" / "tapes" / "demo.tape"
        self.assertTrue(tape.is_file())
        self.assertIn("claude-haiku-4-5", tape.read_text())

    def test_generated_tape_check_is_clean_then_reports_outdated_content(
        self,
    ) -> None:
        self.write_example("demo", "claude-3-opus-latest")
        generated = self.run_script(
            "gen-example-tapes.py", "--only", "demo"
        )
        self.assertEqual(
            generated.returncode, 0, generated.stdout + generated.stderr
        )

        clean = self.run_script(
            "gen-example-tapes.py", "--check", "--only", "demo"
        )
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)

        tape = self.root / "docs" / "tapes" / "demo.tape"
        tape.write_text(tape.read_text() + "# drift\n")
        outdated = self.run_script(
            "gen-example-tapes.py", "--check", "--only", "demo"
        )
        self.assertEqual(outdated.returncode, 1)
        self.assertIn("outdated", outdated.stdout)

    def test_check_reports_a_stale_generated_tape(self) -> None:
        config = self.write_example("demo", "claude-3-opus-latest")
        generated = self.run_script(
            "gen-example-tapes.py", "--only", "demo"
        )
        self.assertEqual(
            generated.returncode, 0, generated.stdout + generated.stderr
        )
        config.write_text(config.read_text() + "# redis\n")

        stale = self.run_script(
            "gen-example-tapes.py", "--check", "--only", "demo"
        )

        self.assertEqual(stale.returncode, 1)
        self.assertIn("stale", stale.stdout)

    def test_default_check_and_generation_remove_a_deleted_examples_tape(
        self,
    ) -> None:
        config = self.write_example("removed", "claude-3-opus-latest")
        generated = self.run_script(
            "gen-example-tapes.py", "--only", "removed"
        )
        self.assertEqual(
            generated.returncode, 0, generated.stdout + generated.stderr
        )
        tape = self.root / "docs" / "tapes" / "removed.tape"
        self.assertTrue(tape.is_file())
        config.unlink()

        stale = self.run_script("gen-example-tapes.py", "--check")
        self.assertEqual(stale.returncode, 1)
        self.assertIn("removed.tape (stale)", stale.stdout)
        self.assertTrue(tape.is_file(), "--check removed the stale tape")

        cleaned = self.run_script("gen-example-tapes.py")
        self.assertEqual(
            cleaned.returncode, 0, cleaned.stdout + cleaned.stderr
        )
        self.assertFalse(tape.exists())

    def test_generation_preserves_a_hand_authored_tape(self) -> None:
        self.write_example("demo", "claude-3-opus-latest")
        tape = self.root / "docs" / "tapes" / "demo.tape"
        tape.write_text("# Hand-authored recording\n")
        before = tape.read_bytes()

        result = self.run_script(
            "gen-example-tapes.py", "--only", "demo"
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(tape.read_bytes(), before)
        self.assertIn("hand-authored", result.stdout)


class WireExampleGifsTests(TemporaryRepository):
    def test_check_fails_when_a_gif_is_not_wired(self) -> None:
        self.copy_script("wire-example-gifs.py")
        example = self.root / "examples" / "demo"
        example.mkdir()
        readme = example / "README.md"
        readme.write_text("# Demo\n\n*Last modified: 2026-07-28*\n")
        (self.root / "docs" / "assets" / "demo.gif").write_bytes(b"GIF89a")
        before = readme.read_bytes()

        result = self.run_script("wire-example-gifs.py", "--check")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(readme.read_bytes(), before)


class SyncDocConfigsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "docs").mkdir()
        example = self.root / "examples" / "basic-proxy"
        example.mkdir(parents=True)
        self.canonical_body = (
            "proxy:\n"
            "  http_bind_port: 8080\n"
            "\n"
            "origins:\n"
            '  "myapp.example.com":\n'
            "    action:\n"
            "      type: proxy\n"
            "      url: https://test.sbproxy.dev\n"
        )
        (example / "sb.yml").write_text(
            "# yaml-language-server: $schema=../../schemas/sb-config.schema.json\n"
            "# sbproxy-docs:begin\n"
            f"{self.canonical_body}"
            "# sbproxy-docs:end\n"
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def run_guard(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(REPOSITORY / "scripts" / "sync-doc-configs.py"),
                "--root",
                str(self.root),
                *arguments,
            ],
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_check_rejects_a_broken_strict_config(self) -> None:
        document = self.root / "docs" / "reference.md"
        document.write_text(
            "<!-- sbproxy-config: examples/basic-proxy/sb.yml -->\n"
            "```yaml\n"
            f"{self.canonical_body.replace('test.sbproxy.dev', 'stale.example.com')}"
            "```\n"
        )
        before = document.read_bytes()

        result = self.run_guard("--check")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("drift", result.stderr)
        self.assertEqual(document.read_bytes(), before, "--check rewrote the doc")

    def test_check_accepts_a_strict_config_and_an_explicit_excerpt(self) -> None:
        (self.root / "docs" / "reference.md").write_text(
            "<!-- sbproxy-config: examples/basic-proxy/sb.yml -->\n"
            "```yaml\n"
            f"{self.canonical_body}"
            "```\n"
            "\n"
            "<!-- sbproxy-config-excerpt -->\n"
            "```yaml\n"
            "action:\n"
            "  type: proxy\n"
            "```\n"
        )

        result = self.run_guard("--check")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 strict block", result.stdout)
        self.assertIn("1 excerpt", result.stdout)

    def test_check_rejects_a_source_outside_the_example_compiler_sweep(self) -> None:
        alternate = self.root / "examples" / "basic-proxy" / "alternate.yml"
        alternate.write_text(
            "# sbproxy-docs:begin\n"
            f"{self.canonical_body}"
            "# sbproxy-docs:end\n"
        )
        (self.root / "docs" / "reference.md").write_text(
            "<!-- sbproxy-config: examples/basic-proxy/alternate.yml -->\n"
            "```yaml\n"
            f"{self.canonical_body}"
            "```\n"
        )

        result = self.run_guard("--check")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("compiler sweep", result.stderr)

    def test_check_walks_nested_documentation_directories(self) -> None:
        nested = self.root / "docs" / "guides"
        nested.mkdir()
        (nested / "reference.md").write_text(
            "<!-- sbproxy-config: examples/basic-proxy/sb.yml -->\n"
            "```yaml\n"
            "stale: true\n"
            "```\n"
        )

        result = self.run_guard("--check")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("docs/guides/reference.md", result.stderr)

    def test_sync_refreshes_strict_config_without_rewriting_excerpt(self) -> None:
        document = self.root / "docs" / "reference.md"
        excerpt = "action:\n  type: proxy\n"
        document.write_text(
            "<!-- sbproxy-config: examples/basic-proxy/sb.yml -->\n"
            "```yaml\n"
            "stale: true\n"
            "```\n"
            "\n"
            "<!-- sbproxy-config-excerpt -->\n"
            "```yaml\n"
            f"{excerpt}"
            "```\n"
        )

        result = self.run_guard()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        contents = document.read_text()
        self.assertIn(self.canonical_body, contents)
        self.assertIn(excerpt, contents)
        self.assertNotIn("stale: true", contents)


class DocDriftCatalogTests(unittest.TestCase):
    """`check-doc-drift.sh` against a scratch root and a mutated catalog."""

    def _root(self) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        shutil.copytree(REPOSITORY / "docs", root / "docs")
        for name in ("llms.txt", "README.md", "SECURITY.md", "CLAUDE.md", "MIGRATION.md"):
            shutil.copy(REPOSITORY / name, root / name)
        (root / "crates" / "sbproxy-ai" / "data").mkdir(parents=True)
        for name in ("ai_providers.yml", "ai_providers.yml.gz"):
            shutil.copy(
                REPOSITORY / "crates" / "sbproxy-ai" / "data" / name,
                root / "crates" / "sbproxy-ai" / "data" / name,
            )
        (root / ".github" / "workflows").mkdir(parents=True)
        shutil.copy(
            REPOSITORY / ".github" / "workflows" / "release.yml",
            root / ".github" / "workflows" / "release.yml",
        )
        shutil.copytree(REPOSITORY / "schemas", root / "schemas")
        return root

    def _write_catalog(self, root: Path, text: str) -> None:
        import gzip

        data = root / "crates" / "sbproxy-ai" / "data"
        (data / "ai_providers.yml").write_text(text)
        (data / "ai_providers.yml.gz").write_bytes(
            gzip.compress(text.encode("utf-8"), 9, mtime=0)
        )

    def _run(self, root: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(REPOSITORY / "scripts" / "check-doc-drift.sh"), "--root", str(root)],
            capture_output=True,
            text=True,
        )

    def test_the_catalog_is_counted_the_way_serde_counts_it(self) -> None:
        """Key order is not part of the count, because it is not to serde.

        The count came off `^  - name:`, justified by a Rust test that
        pins the count and the format split but never the key order.
        `YamlProvider` is a plain derive, so `- display_name: NewCo` then
        `name: newco` parses on one side and vanished on the other; the
        two counters then disagreed by one and this script blamed the
        prose, which is how a correct doc gets edited back to a wrong
        number.
        """
        root = self._root()
        self.assertEqual(self._run(root).returncode, 0, "baseline should be clean")

        catalog_before = (
            root / "crates" / "sbproxy-ai" / "data" / "ai_providers.yml"
        ).read_text()
        lines = catalog_before.split("\n")
        for index, line in enumerate(lines):
            if line.startswith("  - name: "):
                name = line[len("  - name: "):]
                self.assertTrue(lines[index + 1].startswith("    display_name:"))
                lines[index] = "  - " + lines[index + 1].strip()
                lines[index + 1] = "    name: " + name
                break
        else:
            self.fail("no provider entry led with `name:`")
        swapped = "\n".join(lines)
        # Derived, not written down: the catalog's size is exactly the thing
        # this suite exists to stop anyone hardcoding, and a literal here goes
        # stale the first time a provider is added or removed.
        entries = len(re.findall(r"^  - name:", catalog_before, re.MULTILINE))
        self.assertEqual(
            len(re.findall(r"^  - name:", swapped, re.MULTILINE)),
            entries - 1,
            "the old regex should miscount this catalog, which is the point",
        )
        self._write_catalog(root, swapped)
        result = self._run(root)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_an_entry_with_no_name_is_reported(self) -> None:
        root = self._root()
        catalog = root / "crates" / "sbproxy-ai" / "data" / "ai_providers.yml"
        self._write_catalog(
            root, catalog.read_text() + "  - display_name: Nameless\n    format: openai\n"
        )
        result = self._run(root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no `name:`", result.stderr)

    def test_the_format_split_is_held_even_when_the_total_is_right(self) -> None:
        """The breakdown drifts on its own, and only the breakdown sees it.

        Retyping one `custom` entry as `openai` leaves the total alone,
        so every total claim in the tree stays green while "3
        custom-format entries" on four pages goes wrong.
        """
        root = self._root()
        catalog = root / "crates" / "sbproxy-ai" / "data" / "ai_providers.yml"
        before = catalog.read_text()
        # One fewer than the catalog ships, because the line below retypes
        # exactly one. Derived for the same reason as the total above.
        remaining = len(re.findall(r"^    format: custom$", before, re.MULTILINE)) - 1
        self._write_catalog(
            root, before.replace("    format: custom\n", "    format: openai\n", 1)
        )
        result = self._run(root)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("providers$", result.stderr)
        for page in ("ai-gateway.md", "features.md", "providers.md"):
            self.assertIn(f"docs/{page}", result.stderr)
        self.assertIn(
            f"but the catalog has {remaining} custom-format entries", result.stderr
        )

    def test_the_generated_corpus_is_still_in_the_fixed_string_scan(self) -> None:
        """Excluding it for the derived check must not narrow the old one."""
        root = self._root()
        corpus = root / "docs" / "llms-full.txt"
        corpus.write_text(corpus.read_text() + "\nThe certpin module rejects it.\n")
        result = self._run(root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("stale string found: 'certpin'", result.stderr)
        self.assertIn("llms-full.txt", result.stderr)

    def test_a_corpus_lag_entry_that_covers_nothing_is_reported(self) -> None:
        # The real CORPUS_LAG list is empty whenever the corpus is fresh, so
        # the fixture runs a copy of the script with one entry seeded whose
        # needle the corpus does not carry.
        root = self._root()
        needle = "The 90+ AI provider catalog"
        corpus = root / "docs" / "llms-full.txt"
        self.assertNotIn(needle, corpus.read_text())
        script = REPOSITORY / "scripts" / "check-doc-drift.sh"
        seeded = root / "scripts" / "check-doc-drift.sh"
        seeded.parent.mkdir()
        text = script.read_text()
        self.assertEqual(text.count("CORPUS_LAG=(\n"), 1)
        seeded.write_text(
            text.replace(
                "CORPUS_LAG=(\n",
                f'CORPUS_LAG=(\n  "{needle} :: seeded by the test; the corpus never carried it"\n',
                1,
            )
        )
        result = subprocess.run(
            ["bash", str(seeded), "--root", str(root)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("drop it from", result.stderr)


class DocCaptureCheckerTests(unittest.TestCase):
    """Unit coverage for scripts/check-doc-captures.py.

    Parsing, normalization, and the empty-capture rule need no binary and
    no stack, so they are covered here rather than only in the opt-in lane
    that replays commands for real. The checker's own discovery bug (an
    anchored pattern searched with `re.MULTILINE` passed as the start
    POSITION, which reported zero captures across two documents that had
    eighteen) is exactly the class this catches.
    """

    @classmethod
    def setUpClass(cls) -> None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        sys.path.insert(0, str(repo_root / "scripts"))
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "check_doc_captures", repo_root / "scripts" / "check-doc-captures.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        # Registered before exec: @dataclass resolves annotations through
        # sys.modules[cls.__module__], so a module loaded by path alone
        # raises AttributeError on the first dataclass it defines.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        cls.mod = module

    def _doc(self, body: str) -> Path:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".md", delete=False, encoding="utf-8"
        )
        handle.write(textwrap.dedent(body))
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return Path(handle.name)

    def test_marker_and_block_are_paired(self) -> None:
        path = self._doc(
            """\
            # Doc

            <!-- CAPTURE: echo hello -->

            ```text
            hello
            ```
            """
        )
        captures = self.mod.parse_captures(path)
        self.assertEqual(len(captures), 1)
        self.assertEqual(captures[0].command, "echo hello")
        self.assertEqual(captures[0].body, "hello")

    def test_prose_between_marker_and_fence_means_no_block(self) -> None:
        """A block three paragraphs down is a formatting bug, not the output.

        Searching past prose would silently pair a marker with whatever
        fence came next, which is how a capture ends up compared against
        an unrelated YAML sample.
        """
        path = self._doc(
            """\
            <!-- CAPTURE: echo hello -->

            Some prose.

            ```text
            hello
            ```
            """
        )
        captures = self.mod.parse_captures(path)
        self.assertEqual(len(captures), 1)
        self.assertIsNone(captures[0].body)

    def test_an_empty_block_is_a_finding(self) -> None:
        path = self._doc(
            """\
            <!-- CAPTURE: echo -n '' -->

            ```text
            ```
            """
        )
        captures = self.mod.parse_captures(path)
        self.assertEqual(captures[0].body, "")
        results = self.mod.check_document(
            path, binary=None, logs=Path("/tmp"), only_stackless=True
        )
        self.assertEqual([r.status for r in results], ["empty"])

    def test_volatile_fields_normalize_so_two_real_runs_compare_equal(self) -> None:
        first = (
            "HTTP/1.1 402 Payment Required\n"
            "Date: Mon, 03 Aug 2026 22:08:10 GMT\n"
            "content-length: 189\n"
            "intent=sbpi_bJHUW8b9B_Re9FNzFOBTbjLCayknSRoXNdleBqkMHT4\n"
        )
        second = (
            "HTTP/1.1 402 Payment Required\n"
            "Date: Tue, 04 Aug 2026 01:11:02 GMT\n"
            "content-length: 204\n"
            "intent=sbpi_QQQQQQQQQ_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n"
        )
        self.assertEqual(self.mod.normalize(first), self.mod.normalize(second))

    def test_normalization_does_not_hide_a_real_difference(self) -> None:
        """The point of normalizing rather than skipping.

        A block carrying a volatile field must still fail on the part of
        the output that actually changed, or the check covers nothing.
        """
        documented = "HTTP/1.1 402 Payment Required\nDate: Mon, 03 Aug 2026 22:08:10 GMT\n"
        actual = "HTTP/1.1 503 Service Unavailable\nDate: Tue, 04 Aug 2026 01:11:02 GMT\n"
        self.assertNotEqual(self.mod.normalize(documented), self.mod.normalize(actual))

    def test_stack_need_is_detected_from_the_command(self) -> None:
        self.assertTrue(self.mod.needs_stack("curl -s http://127.0.0.1:8080/metrics"))
        self.assertTrue(
            self.mod.needs_stack("sqlite3 /tmp/sbproxy-settlement/payments.sqlite3 'select 1'")
        )
        self.assertTrue(self.mod.needs_stack("bash examples/x/bin/run.sh"))
        self.assertFalse(self.mod.needs_stack("sbproxy validate -f examples/x/sb.yml"))

    def _cap(self, command: str):
        return self.mod.Capture(
            path=Path("x"), line=1, command=command, body="", body_span=None
        )

    def test_sections_route_each_half_of_a_page_to_its_own_fixture(self) -> None:
        """One page can talk to two fixtures with opposite freshness needs.

        Both spellings of the metering half must route to it. The commands
        use the directory name in one place and the metric prefix in
        another, and matching only the directory name sent the metrics
        query to the settlement proxy, which answered with nothing while
        the doc showed three counter lines.
        """
        config = self.mod.MANIFEST["docs/payment-settlement.md"]
        settlement = self.mod.section_for(
            self._cap("curl -is http://127.0.0.1:8080/article"), config
        )
        self.assertEqual(settlement["stack"], "settlement")
        self.assertTrue(settlement["fresh_each"], "independent wire shapes need a fresh stack")

        for command in (
            "bash examples/usage-bridge-queue/bin/bill-one-call.sh",
            "curl -s http://127.0.0.1:8080/metrics | grep sbproxy_usage_bridge",
            "sqlite3 /tmp/sbproxy-usage-bridge/payments.sqlite3 'select 1'",
        ):
            section = self.mod.section_for(self._cap(command), config)
            self.assertEqual(
                section["stack"], "usage_bridge", f"{command!r} must reach the metering stack"
            )
            self.assertFalse(
                section["fresh_each"], "a sequence must share one stack or it reads an empty queue"
            )

    def test_a_signed_token_and_a_payment_hash_normalize(self) -> None:
        """Volatile per-request values must not read as drift.

        The quote token is a JWS whose issued-at, expiry, nonce and digests
        all move per request, and a Lightning payment hash is unique per
        invoice since #926.
        """
        jws = (
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImpXcyJ9."
            "eyJpc3MiOiJzYnByb3h5LXBheW1lbnRzIiwiaWF0IjoxNzg1Nzk0ODc5fQ."
            "WAHMWK0keVNhIzPFhKsKYB8IGAtK9wrMfWiSF-IcrCc"
        )
        other = (
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImpXcyJ9."
            "eyJpc3MiOiJzYnByb3h5LXBheW1lbnRzIiwiaWF0IjoxNzg1ODA4NjI1fQ."
            "tLyhWo3brLkGZeL4hyMZmj-mPFSl7IwLuaYtgsaU098"
        )
        self.assertEqual(
            self.mod.normalize(f"crawler-payment: {jws}"),
            self.mod.normalize(f"crawler-payment: {other}"),
        )
        self.assertEqual(
            self.mod.normalize('"payment_hash":"' + "1f" * 32 + '"'),
            self.mod.normalize('"payment_hash":"' + "9a" * 32 + '"'),
        )
        self.assertEqual(
            self.mod.normalize("requirement_id: req_01kz4tprft0pf62bk3drd79tpn"),
            self.mod.normalize("requirement_id: req_01kz57t7yk9kyh51ksvgd96j15"),
        )

    def test_the_usage_bridge_walkthrough_replays_every_step_it_shows(self) -> None:
        """Producer, both reads, and the metric scrape, in that order.

        The page bills a call, reads the row it wrote twice, and scrapes
        the counter the same call incremented. Three of the four were
        marked and the scrape was not (WOR-2643), so the page read as
        covered while its metric claim was a transcript. Order is pinned
        alongside the count because the producer has to run first: the
        stack wipes /tmp/sbproxy-usage-bridge on every boot, so a read
        that ran before the bill would read an empty database.
        """
        repo_root = Path(__file__).resolve().parent.parent.parent
        readme = repo_root / "examples" / "usage-bridge-queue" / "README.md"
        commands = [capture.command for capture in self.mod.parse_captures(readme)]
        self.assertEqual(
            len(commands),
            4,
            f"expected producer, two reads, and the metric scrape; got {commands}",
        )
        self.assertEqual(commands[0], "bash examples/usage-bridge-queue/bin/bill-one-call.sh")
        self.assertIn("from usage_reports order by created_at_ms", commands[1])
        self.assertIn("select event_jcs from usage_reports", commands[2])
        self.assertEqual(
            commands[3],
            "curl -s http://127.0.0.1:8080/metrics | grep sbproxy_usage_bridge",
        )

    def test_a_shown_output_with_no_marker_is_a_finding(self) -> None:
        path = self._doc(
            """\
            # Doc

            ```bash
            echo hello
            ```

            ```
            hello
            ```
            """
        )
        findings = self.mod.uncaptured_output_blocks(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][1], "echo hello")

    def test_a_marker_between_command_and_output_clears_the_finding(self) -> None:
        path = self._doc(
            """\
            # Doc

            ```bash
            echo hello
            ```

            <!-- CAPTURE: echo hello -->

            ```
            hello
            ```
            """
        )
        self.assertEqual(self.mod.uncaptured_output_blocks(path), [])

    def test_a_setup_block_that_shows_no_output_is_not_policed(self) -> None:
        """`mkdir`, `cargo build`, `kill %1` are outside the rule by shape.

        They print nothing the page shows, so no output block follows
        them and there is no claim to hold to the code. Exempting them
        by name would be a list that grows with every walkthrough.
        """
        path = self._doc(
            """\
            # Doc

            ```bash
            mkdir -p /tmp/demo
            ```

            Then, from the repository root:

            ```bash
            sbproxy serve -f sb.yml
            ```

            ```yaml
            proxy:
              listen: 127.0.0.1:8080
            ```
            """
        )
        self.assertEqual(self.mod.uncaptured_output_blocks(path), [])

    def test_a_command_separated_from_its_output_by_prose_is_a_finding(self) -> None:
        """"That returns:" is the shape, not an escape hatch.

        The rule used to drop any pair with a non-blank line between the
        two blocks, which is the commonest way this repo shows output.
        Five of the 32 command-and-output pairs on the covered pages are
        prose-separated and all five are genuine output.
        """
        path = self._doc(
            """\
            # Doc

            ```bash
            curl -sS http://127.0.0.1:9090/api/health | jq
            ```

            That returns:

            ```json
            {"status": "ok"}
            ```
            """
        )
        findings = self.mod.uncaptured_output_blocks(path)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("api/health", findings[0][1])

    def test_a_heading_between_command_and_output_is_out_of_scope(self) -> None:
        """A heading starts a new subject, so the block belongs to it."""
        path = self._doc(
            """\
            # Doc

            ```bash
            curl -sS http://127.0.0.1:9090/api/health | jq
            ```

            ## The response shape

            ```json
            {"status": "ok"}
            ```
            """
        )
        self.assertEqual(self.mod.uncaptured_output_blocks(path), [])

    def test_http_and_xml_blocks_count_as_shown_output(self) -> None:
        for lang in ("http", "xml"):
            with self.subTest(lang=lang):
                path = self._doc(
                    f"""\
                    # Doc

                    ```bash
                    curl -i http://127.0.0.1:9090/api/health
                    ```

                    ```{lang}
                    body
                    ```
                    """
                )
                self.assertEqual(len(self.mod.uncaptured_output_blocks(path)), 1)

    def test_a_fence_with_attributes_does_not_desynchronize_the_parser(self) -> None:
        """`rust,no_run` is an opener, and everything below it stays paired.

        The old pattern accepted only a bare lowercase language, so a
        comma in the info string made the walker skip the opener, read
        the block's closing fence as an opener, and pair off every fence
        below it by one. `docs/audit-log.md:1019` shipped that: the file
        has 31 blocks and the parser returned 30, reporting prose as code
        for the rest of the page. The uncaptured pair below is the thing
        that went invisible.
        """
        path = self._doc(
            """\
            # Doc

            ```rust,no_run
            let x = 1;
            ```

            ```bash
            echo hello
            ```

            ```
            hello
            ```
            """
        )
        blocks, problems = self.mod._fences(path.read_text().split("\n"))
        self.assertEqual(problems, [])
        self.assertEqual([lang for _, _, lang in blocks], ["rust", "bash", ""])
        findings = self.mod.uncaptured_output_blocks(path)
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0][1], "echo hello")

    def test_the_live_page_that_desynchronized_parses_whole(self) -> None:
        """`docs/audit-log.md` is a manifest page and had the bad fence."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        lines = (repo_root / "docs" / "audit-log.md").read_text().split("\n")
        blocks, problems = self.mod._fences(lines)
        self.assertEqual(problems, [])
        opener_lines = sum(1 for line in lines if line.lstrip().startswith("```"))
        self.assertEqual(
            len(blocks) * 2,
            opener_lines,
            "every triple-backtick line on the page should be an opener or a closer",
        )

    def test_an_unreadable_fence_is_reported_rather_than_skipped(self) -> None:
        """A parser that desynchronizes quietly is worse than one that errors."""
        path = self._doc(
            """\
            # Doc

            ```sh `inline`
            echo hi
            ```
            """
        )
        problems = self.mod.fence_problems(path)
        self.assertIn("cannot read", problems[0][1])
        self.assertEqual(problems[0][0], 3)
        # The cascade is the failure being made visible: the block's own
        # closing fence is read as an opener, so it runs to the end of
        # the file. That used to be the silent half.
        self.assertIn("never closed", problems[1][1])

    def test_an_unclosed_fence_is_reported_rather_than_skipped(self) -> None:
        path = self._doc(
            """\
            # Doc

            ```bash
            echo dangling
            """
        )
        problems = self.mod.fence_problems(path)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("never closed", problems[0][1])

    def test_no_manifest_page_carries_a_fence_this_parser_cannot_read(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        for rel in self.mod.MANIFEST:
            path = repo_root / rel
            if not path.exists():
                continue
            self.assertEqual(self.mod.fence_problems(path), [], rel)

    def test_no_manifest_page_shows_an_output_nothing_accounts_for(self) -> None:
        """The repo-level gate: every shown output is replayed or recorded.

        `check_block_coverage` also audits the other direction, so a note
        in `UNCAPTURED_BLOCKS` that stops matching a block fails here
        rather than sitting in the file excusing something that no longer
        exists.
        """
        self.assertEqual(self.mod.check_block_coverage(), [])

    def _coverage_on(self, body: str, recorded: dict) -> list[str]:
        """`check_block_coverage` over one synthetic page."""
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "page.md").write_text(textwrap.dedent(body))
        patcher = unittest.mock.patch.multiple(
            self.mod,
            ROOT=root,
            MANIFEST={"page.md": {}},
            UNCAPTURED_BLOCKS={"page.md": recorded},
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return self.mod.check_block_coverage()

    def test_a_needle_matching_two_blocks_is_its_own_error(self) -> None:
        """One excuse cannot spread to a block nobody wrote it for.

        The map keys on a substring, so a later block containing that
        substring used to be exempted silently while the reverse audit
        stayed satisfied by the original. That is the denylist this map
        replaced, wearing a different hat.
        """
        page = """\
            # Page

            ```bash
            curl -s 'http://127.0.0.1:9090/api/audit/chain?limit=5'
            ```

            ```json
            {"records": []}
            ```

            ```bash
            curl -s 'http://127.0.0.1:9090/api/audit/chain?limit=5&channel=security'
            ```

            ```json
            {"records": []}
            ```
            """
        errors = self._coverage_on(page, {"chain?limit=5": "the inline fixture"})
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("matches 2 uncaptured blocks", errors[0])

    def test_one_needle_per_block_is_clean_and_a_stale_needle_is_not(self) -> None:
        page = """\
            # Page

            ```bash
            curl -s 'http://127.0.0.1:9090/api/audit/chain?limit=5'
            ```

            ```json
            {"records": []}
            ```
            """
        self.assertEqual(
            self._coverage_on(page, {"chain?limit=5": "the inline fixture"}), []
        )
        stale = self._coverage_on(page, {"chain?limit=9": "the inline fixture"})
        self.assertEqual(len(stale), 2, stale)
        self.assertTrue(any("matches no uncaptured block" in error for error in stale))

    def test_an_unreadable_fence_stops_the_coverage_report_on_that_page(self) -> None:
        """Findings from a half-read page would name the wrong lines."""
        page = """\
            # Page

            ```sh `inline`
            echo hi
            ```
            """
        errors = self._coverage_on(page, {})
        self.assertTrue(errors)
        self.assertIn("page.md:3: opens a code fence this parser cannot read", errors[0])

    def test_every_uncaptured_block_note_names_a_manifest_page(self) -> None:
        for rel, blocks in self.mod.UNCAPTURED_BLOCKS.items():
            self.assertIn(
                rel,
                self.mod.MANIFEST,
                f"{rel} records uncaptured blocks but is not a covered page",
            )
            self.assertTrue(blocks, f"{rel} has an empty UNCAPTURED_BLOCKS entry")
            for needle, reason in blocks.items():
                self.assertTrue(reason.strip(), f"{rel}: '{needle}' gives no reason")

    def test_every_manifest_section_names_a_known_stack(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        for rel, config in self.mod.MANIFEST.items():
            self.assertTrue((repo_root / rel).exists(), f"{rel} is in the manifest but is gone")
            self.assertTrue(
                self.mod._has_marker(repo_root / rel),
                f"{rel} is in the manifest but carries no CAPTURE marker; "
                "the document glob would drop it from coverage without a word",
            )
            sections = config.get("sections") or []
            self.assertTrue(sections, f"{rel} has no sections")
            for section in sections:
                self.assertIn(section["stack"], self.mod.STACK_STARTERS)
            self.assertFalse(
                sections[-1].get("match"),
                f"{rel}'s last section must be the catch-all, or captures fall through unrouted",
            )

    def test_every_stack_declares_the_ports_it_binds(self) -> None:
        """A stack missing from STACK_PORTS gets no preflight at all.

        `_busy_ports` is what stops a stack from starting into ports
        something else already holds, and it reads the port list from
        `STACK_PORTS`. A starter added without an entry there looks
        guarded and is not: its proxy loses the bind, the readiness
        probe is answered by whatever is already listening, and the
        whole document replays against a foreign proxy without a word
        of complaint. That is the exact failure the guard exists to
        catch, so the two maps have to stay in step.
        """
        self.assertEqual(
            sorted(self.mod.STACK_STARTERS),
            sorted(self.mod.STACK_PORTS),
            "every stack starter needs a STACK_PORTS entry, and vice versa",
        )
        for name, ports in self.mod.STACK_PORTS.items():
            self.assertTrue(ports, f"{name} declares no ports")
            for port in ports:
                self.assertIsInstance(port, int, f"{name} lists a non-integer port")


if __name__ == "__main__":
    unittest.main()
