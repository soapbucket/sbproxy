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


if __name__ == "__main__":
    unittest.main()
