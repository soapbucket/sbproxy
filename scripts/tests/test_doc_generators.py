#!/usr/bin/env python3
"""Behavior tests for documentation recording and generation scripts."""

from __future__ import annotations

import os
import http.server
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]


def write_executable(path: Path, contents: str) -> None:
    path.write_text(textwrap.dedent(contents).lstrip())
    path.chmod(0o755)


class TemporaryRepository(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "scripts").mkdir()
        (self.root / "docs" / "tapes").mkdir(parents=True)
        (self.root / "docs" / "assets").mkdir(parents=True)
        (self.root / "examples").mkdir()

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
        (self.root / "main.yml").write_text("proxy:\n  http_bind_port: 18080\n")
        (self.root / "aux.yml").write_text("proxy:\n  http_bind_port: 18091\n")
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
                env=self.recorder_env(unrelated.pid, 18080),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("18080", result.stdout + result.stderr)
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

        server = http.server.HTTPServer(("127.0.0.1", 18888), UnrelatedHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = os.environ.copy()
            env["SBPROXY_BIN"] = "/usr/bin/true"
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
        self.assertIn("18888", result.stdout + result.stderr)
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

    def test_every_manifest_section_names_a_known_stack(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        for rel, config in self.mod.MANIFEST.items():
            self.assertTrue((repo_root / rel).exists(), f"{rel} is in the manifest but is gone")
            sections = config.get("sections") or []
            self.assertTrue(sections, f"{rel} has no sections")
            for section in sections:
                self.assertIn(section["stack"], self.mod.STACK_STARTERS)
            self.assertFalse(
                sections[-1].get("match"),
                f"{rel}'s last section must be the catch-all, or captures fall through unrouted",
            )


if __name__ == "__main__":
    unittest.main()
