#!/usr/bin/env python3
"""Re-run the commands a doc shows and diff them against the shown output.

A capture is a marker naming the command, followed by the block it
produced:

    <!-- CAPTURE: curl -is http://127.0.0.1:8080/article -->

    ```text
    HTTP/1.1 402 Payment Required
    ...
    ```

`--list` enumerates markers. `--check` replays them and reports drift.
`--update` replays them and rewrites the blocks.

Why this exists: WOR-2101's bar says "if we cannot produce the output,
the claim does not ship", and until now that was enforced by whoever
remembered to run the commands. The one pass that did (#924, 18 markers)
found three defects, including a CLI flag advertised in three places that
had never worked. Nothing else in the docs lanes can evaluate a command:
the drift check greps fixed strings, lychee runs offline, and tapes-check
proves a tape is wired rather than still true. See WOR-2297.

Two design points that are load bearing rather than incidental.

**Replay is in document order, against one stack.** A reader goes top to
bottom. `docs/payment-settlement.md` shipped four individually
reproducible blocks whose *order* was not reproducible: block two strands
a payment intent and never pays it, and an unresolved intent withholds
new challenges for that route, so everything after answered 503 where
block one showed 402. Per-block isolation would have called that
document correct. Freshness is therefore declared per SECTION, not per
document: one page can hold a sequence that must share a stack and a set
of independent shapes that must not, which `docs/payment-settlement.md`
does. That makes the requirement something the page states rather than
something this script hides.

**Volatile fields are normalized, not skipped.** Real output carries
dates, ULIDs, intent ids, ports. Skipping any block containing one would
silently cover nothing, so both sides are rewritten to placeholders and
compared.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import difflib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parent.parent

MARKER = re.compile(r"^[ \t]*<!--[ \t]*CAPTURE:[ \t]*(?P<command>.+?)[ \t]*-->[ \t]*$")
FENCE = re.compile(r"^(?P<fence>`{3,})(?P<lang>[a-z]*)[ \t]*$")

# Manifest of how to stand up what a document's commands talk to.
#
# Kept here rather than in a data file because it is executable intent
# and belongs next to the code that runs it. A document absent from this
# map still has its stack-free captures replayed.
MANIFEST: dict[str, dict] = {
    "examples/settlement-gate-local/README.md": {
        # One walkthrough, one stack. Its own script resets the fixture,
        # so every block reads the state the block above it left.
        "sections": [{"stack": "settlement", "fresh_each": False}],
    },
    "examples/usage-bridge-queue/README.md": {
        # The same worker as docs/payment-settlement.md's usage_bridge
        # section, reached by its own dedicated walkthrough. Both of this
        # page's captures are `sqlite3` reads against the queue that
        # section's config also drives, so they get the same stack,
        # match list, and settle wait rather than a second definition of
        # the same shape: a row written `queued` needs the recovery
        # worker's next sweep, 1000 ms in this example's config, before
        # it reads `terminal`.
        "sections": [
            {
                "match": ["usage-bridge", "usage_bridge"],
                "stack": "usage_bridge",
                "fresh_each": False,
                "settle_ms": 4000,
            },
            # Every capture this page has ever needed matches the section
            # above; unlike docs/payment-settlement.md there is no second
            # fixture on this page to fall through to. The manifest test
            # still requires a trailing catch-all, so this repeats the
            # same stack rather than routing a hypothetical future,
            # differently-worded capture at nothing.
            {"stack": "usage_bridge", "fresh_each": False, "settle_ms": 4000},
        ],
    },
    "examples/temp-budget-override/README.md": {
        # One ordered walkthrough, one stack (WOR-2561): spend accrues
        # across blocks and the grant's 60-second TTL is the subject, so
        # a fresh stack per block would reset the counters and a
        # re-ordered replay would find the raise already lapsed.
        "sections": [{"stack": "temp_budget_override", "fresh_each": False}],
    },
    "examples/transform-json-schema/README.md": {
        # One walkthrough, one stack, no fixture: both origins are static
        # actions, so the proxy alone is the whole stack. Marked because
        # this page spent an unknown stretch documenting the opposite of
        # what the code did: it recorded the generated-body fail-open as
        # a permanent "known limitation", and no lane could tell. The
        # example sweeps only compile the config, and the json_schema
        # e2e case uses `type: proxy`, so the one shape that rotted was
        # the one nothing replayed.
        "sections": [{"stack": "transform_json_schema", "fresh_each": False}],
    },
    "examples/api-deprecation/README.md": {
        # One walkthrough, one stack, no fixture: every origin in the
        # config is a static action, so the proxy alone is the whole
        # stack. Shared across the page because the metrics capture
        # reads the counters the earlier per-route captures produced.
        "sections": [{"stack": "api_deprecation", "fresh_each": False}],
    },
    "docs/payment-settlement.md": {
        # This page is two halves with opposite needs, which is why
        # freshness is per section rather than per document.
        "sections": [
            # The metering half is a sequence: bill a call, then read the
            # rows it queued, then read the counters. A fresh stack per
            # block would read an empty queue every time. Matched on both
            # spellings because the commands use the directory name
            # (`usage-bridge-queue`) and the metric prefix
            # (`sbproxy_usage_bridge`), and matching only the first sent
            # the metrics query to the settlement proxy, which answered
            # with nothing.
            {
                "match": ["usage-bridge", "usage_bridge"],
                "stack": "usage_bridge",
                "fresh_each": False,
                # The queue row is written `queued` and the recovery
                # worker moves it to `terminal` one sweep later, 1000 ms
                # in this example's config. The page deliberately shows
                # where the row comes to rest, so reading it the
                # instant the request returns shows `queued` and reads
                # as drift. Waiting here makes that dependency explicit
                # rather than a property of whoever captured it; the page
                # states it too.
                "settle_ms": 4000,
            },
            # The settlement half is four independent wire shapes, and the
            # page says so. Block two strands an intent it never pays,
            # which withholds challenges for that route, so sharing a
            # stack makes every later block answer 503.
            {"stack": "settlement", "fresh_each": True},
        ],
    },
}


@dataclass
class Capture:
    """One marker, its command, and the block beneath it."""

    path: Path
    line: int
    command: str
    body: str | None
    body_span: tuple[int, int] | None


@dataclass
class Result:
    capture: Capture
    status: str  # "ok" | "drift" | "empty" | "missing" | "skipped"
    detail: str = ""
    actual: str = ""


@dataclass
class Stack:
    """A running fixture plus proxy, torn down on exit."""

    procs: list[subprocess.Popen] = field(default_factory=list)

    def stop(self) -> None:
        for proc in reversed(self.procs):
            if proc.poll() is not None:
                continue
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.procs.clear()


# --- Normalization -----------------------------------------------------
#
# Each pattern replaces a field that changes every run with a stable
# placeholder. Anything genuinely volatile that is NOT listed here shows
# up as drift, which is the safe direction: a false failure gets a rule
# added, a false pass teaches nobody anything.

NORMALIZERS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^Date: .*$", re.MULTILINE), "Date: <DATE>"),
    # A signed quote token: three base64url segments, and every field
    # inside it (issued-at, expiry, nonce, digests) moves per request.
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "<JWS>",
    ),
    # A Lightning payment hash is 64 hex. It used to be a constant in the
    # stub, which is the bug #926 fixed, so a doc pinning one value is
    # showing output that can no longer occur.
    (re.compile(r"\b[0-9a-f]{64}\b"), "<HEX64>"),
    # `req_01kz...` / `quote_01kz...`: lowercase ULID, so the uppercase
    # ULID rule below does not see them.
    (re.compile(r"\b(req|quote)_[0-9a-z]{26}\b"), r"\1_<ULID>"),
    (re.compile(r"\bsbpi_[A-Za-z0-9_-]{8,}"), "sbpi_<INTENT>"),
    (re.compile(r"\bsbu-[0-9a-f]{8,}-[0-9a-f]{8,}"), "sbu-<USAGE>"),
    (re.compile(r"\b[0-9a-f]{32}\b"), "<HEX32>"),
    (re.compile(r"\b[0-9A-HJKMNP-TV-Z]{26}\b"), "<ULID>"),
    # RFC 3339 instants: grant/expiry/created/updated stamps and audit
    # timestamps move every run (WOR-2561's budget-override walkthrough
    # shows several per block).
    (
        re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})"),
        "<RFC3339>",
    ),
    (re.compile(r"\b17[0-9]{11}\b"), "<EPOCH_MS>"),
    (re.compile(r"\b1[0-9]{9}\b"), "<EPOCH_S>"),
    (re.compile(r"lnbcrt[0-9a-z]{20,}"), "lnbcrt<INVOICE>"),
    (re.compile(r"127\.0\.0\.1:\d{4,5}"), "127.0.0.1:<PORT>"),
    (re.compile(r"^content-length: \d+$", re.MULTILINE), "content-length: <LEN>"),
    # The recovery worker's admin status counters advance on its own
    # wall-clock tick interval, independent of what a walkthrough's steps
    # require of it, so their exact value at the moment a doc's capture
    # ran is a function of real elapsed time rather than of anything the
    # walkthrough asserts. `schema_version` is not in this group: it is a
    # fixed integer for a given build, not a runtime counter.
    (
        re.compile(
            r'"(ticks|challenges_expired|reconciliations_succeeded|'
            r'reconciliations_unresolved|leases_moved_to_needs_reconciliation|'
            r'leases_returned_to_retry_wait)":\d+'
        ),
        r'"\1":<N>',
    ),
]


def normalize(text: str) -> str:
    """Collapse volatile fields so two real runs compare equal."""
    out = text.replace("\r\n", "\n")
    for pattern, placeholder in NORMALIZERS:
        out = pattern.sub(placeholder, out)
    # Trailing whitespace per line, and one trailing newline at most.
    out = "\n".join(line.rstrip() for line in out.split("\n"))
    return out.strip("\n")


# --- Parsing -----------------------------------------------------------


def display_path(path: Path) -> str:
    """Repo-relative when possible, absolute otherwise.

    A path outside the repo root is normal (a test fixture in a temp
    dir), and `relative_to` raises rather than returning None, so the
    fallback is what keeps the checker usable on an arbitrary file.
    """
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _has_marker(path: Path) -> bool:
    """Whether a document contains at least one capture marker.

    Per line rather than a multiline search: `MARKER` is anchored and
    compiled without `re.MULTILINE`, and passing that flag to `search`
    silently sets the start POSITION instead, which found nothing and
    reported zero captures.
    """
    return any(MARKER.match(line) for line in path.read_text().split("\n"))


def parse_captures(path: Path) -> list[Capture]:
    """Find every marker in one document, with the block beneath it."""
    lines = path.read_text().split("\n")
    captures: list[Capture] = []
    for index, line in enumerate(lines):
        match = MARKER.match(line)
        if not match:
            continue
        command = match.group("command")
        body, span = _block_after(lines, index + 1)
        captures.append(
            Capture(
                path=path,
                line=index + 1,
                command=command,
                body=body,
                body_span=span,
            )
        )
    return captures


def _block_after(lines: list[str], start: int) -> tuple[str | None, tuple[int, int] | None]:
    """Return the fenced block following a marker, if it is the next thing.

    Only blank lines may sit between the marker and its block. Prose in
    between means the marker has no block, which is reported rather than
    silently searched past: a marker whose output landed three paragraphs
    down is a formatting bug worth seeing.
    """
    cursor = start
    while cursor < len(lines) and not lines[cursor].strip():
        cursor += 1
    if cursor >= len(lines):
        return None, None
    opening = FENCE.match(lines[cursor])
    if not opening:
        return None, None
    fence = opening.group("fence")
    body_start = cursor + 1
    for end in range(body_start, len(lines)):
        if lines[end].startswith(fence) and not lines[end][len(fence):].strip():
            return "\n".join(lines[body_start:end]), (body_start, end)
    return None, None


# --- Stacks ------------------------------------------------------------


def _wait_for_http(url: str, procs: list[subprocess.Popen], timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for proc in procs:
            if proc.poll() is not None:
                return False
        try:
            with urllib.request.urlopen(url, timeout=2):
                return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


def start_settlement_stack(binary: Path, logs: Path) -> Stack | None:
    """Stub Core Lightning node plus counting origin, then the proxy."""
    state = Path("/tmp/sbproxy-settlement")
    if state.exists():
        shutil.rmtree(state)
    state.mkdir(parents=True)
    stack = Stack()
    fixture_log = (logs / "settlement-fixture.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [sys.executable, "examples/settlement-gate-local/fixture.py"],
            cwd=ROOT,
            stdout=fixture_log,
            stderr=subprocess.STDOUT,
        )
    )
    time.sleep(3)
    proxy_log = (logs / "settlement-proxy.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [str(binary), "serve", "-f", "examples/settlement-gate-local/sb.yml"],
            cwd=ROOT,
            stdout=proxy_log,
            stderr=subprocess.STDOUT,
        )
    )
    if not _wait_for_http("http://127.0.0.1:8080/metrics", stack.procs):
        stack.stop()
        return None
    return stack


def start_usage_bridge_stack(binary: Path, logs: Path) -> Stack | None:
    """AI fixture plus the proxy, with the two secret files the config names."""
    state = Path("/tmp/sbproxy-usage-bridge")
    if state.exists():
        shutil.rmtree(state)
    state.mkdir(parents=True)
    (state / "binding.key").write_text("0123456789abcdef0123456789abcdef")
    (state / "stripe.key").write_text("sk_test_usage_bridge_demo")
    for name in ("binding.key", "stripe.key"):
        (state / name).chmod(0o600)
    stack = Stack()
    fixture_log = (logs / "usage-bridge-fixture.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [sys.executable, "examples/usage-bridge-queue/fixture.py"],
            cwd=ROOT,
            stdout=fixture_log,
            stderr=subprocess.STDOUT,
        )
    )
    time.sleep(3)
    proxy_log = (logs / "usage-bridge-proxy.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [str(binary), "serve", "-f", "examples/usage-bridge-queue/sb.yml"],
            cwd=ROOT,
            stdout=proxy_log,
            stderr=subprocess.STDOUT,
        )
    )
    if not _wait_for_http("http://127.0.0.1:8080/metrics", stack.procs):
        stack.stop()
        return None
    return stack


def start_temp_budget_override_stack(binary: Path, logs: Path) -> Stack | None:
    """OpenAI-shaped fixture plus the proxy with a fresh key store.

    The store file is removed first so the seeded key boots with its full
    base budget: accrued spend from a previous replay would refuse the
    walkthrough's first request, which the page shows being admitted.
    """
    Path("/tmp/sbproxy-temp-budget-override.redb").unlink(missing_ok=True)
    stack = Stack()
    fixture_log = (logs / "temp-budget-override-fixture.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [sys.executable, "examples/temp-budget-override/fixture.py"],
            cwd=ROOT,
            stdout=fixture_log,
            stderr=subprocess.STDOUT,
        )
    )
    time.sleep(3)
    proxy_log = (logs / "temp-budget-override-proxy.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [str(binary), "serve", "-f", "examples/temp-budget-override/sb.yml"],
            cwd=ROOT,
            stdout=proxy_log,
            stderr=subprocess.STDOUT,
            env={
                **os.environ,
                "SBPROXY_KEY_PEPPER": "doc-capture-pepper",
                "SBPROXY_KEY_MASTER": "doc-capture-master",
            },
        )
    )
    if not _wait_for_http("http://127.0.0.1:8080/metrics", stack.procs):
        stack.stop()
        return None
    return stack


def start_api_deprecation_stack(binary: Path, logs: Path) -> Stack | None:
    """Just the proxy: the example's origins are all static actions."""
    stack = Stack()
    proxy_log = (logs / "api-deprecation-proxy.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [str(binary), "serve", "-f", "examples/api-deprecation/sb.yml"],
            cwd=ROOT,
            stdout=proxy_log,
            stderr=subprocess.STDOUT,
        )
    )
    if not _wait_for_http("http://127.0.0.1:8080/metrics", stack.procs):
        stack.stop()
        return None
    return stack


def start_transform_json_schema_stack(binary: Path, logs: Path) -> Stack | None:
    """Just the proxy: both origins are static actions."""
    stack = Stack()
    proxy_log = (logs / "transform-json-schema-proxy.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [str(binary), "serve", "-f", "examples/transform-json-schema/sb.yml"],
            cwd=ROOT,
            stdout=proxy_log,
            stderr=subprocess.STDOUT,
        )
    )
    if not _wait_for_http("http://127.0.0.1:8080/metrics", stack.procs):
        stack.stop()
        return None
    return stack


STACK_STARTERS = {
    "settlement": start_settlement_stack,
    "usage_bridge": start_usage_bridge_stack,
    "temp_budget_override": start_temp_budget_override_stack,
    "api_deprecation": start_api_deprecation_stack,
    "transform_json_schema": start_transform_json_schema_stack,
}


def section_for(capture: Capture, doc_config: dict) -> dict:
    """The manifest section governing one capture.

    First section whose `match` list hits the command wins; a section
    without `match` is the default and catches the rest. Returns an empty
    dict for a document with no manifest entry, whose stack-free captures
    still get replayed.
    """
    for section in doc_config.get("sections") or []:
        needles = section.get("match")
        if not needles:
            return section
        if any(needle in capture.command for needle in needles):
            return section
    return {}


def needs_stack(command: str) -> bool:
    """Whether a command talks to a running proxy or its state."""
    return any(
        token in command
        for token in ("127.0.0.1", "localhost", "sqlite3", "bin/", "payments.sqlite3")
    )


# --- Replay ------------------------------------------------------------


def run_command(command: str, binary: Path) -> str:
    """Run one captured command and return its combined output.

    `sbproxy` on PATH resolves to the binary under test, so a doc that
    shows a bare `sbproxy ...` is checked against this build rather than
    whatever the host happens to have installed.
    """
    env_path = f"{binary.parent}:{os.environ.get('PATH', '')}"
    proc = subprocess.run(
        ["bash", "-c", command],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        env={**os.environ, "PATH": env_path},
    )
    return proc.stdout + proc.stderr


def check_document(
    path: Path,
    binary: Path | None,
    logs: Path,
    only_stackless: bool,
) -> list[Result]:
    config = MANIFEST.get(display_path(path), {})
    captures = parse_captures(path)
    results: list[Result] = []
    stack: Stack | None = None
    current_stack_name: str | None = None
    # Tracks whether the previous capture was in the same section, so a
    # settle wait applies to the reads that follow the write rather than
    # to the write itself.
    last_section: dict | None = None

    try:
        for capture in captures:
            if capture.body is None:
                results.append(
                    Result(capture, "missing", "no output block follows this marker")
                )
                continue
            if not capture.body.strip():
                results.append(
                    Result(
                        capture,
                        "empty",
                        "the block is empty; an empty capture is a finding, not a format nit",
                    )
                )
                continue

            section = section_for(capture, config)
            fresh_each = bool(section.get("fresh_each"))
            wanted = section.get("stack") if needs_stack(capture.command) else None
            if wanted and (only_stackless or binary is None):
                results.append(Result(capture, "skipped", "needs a live stack"))
                continue
            if binary is None:
                results.append(Result(capture, "skipped", "no binary supplied"))
                continue

            if wanted and (fresh_each or wanted != current_stack_name or stack is None):
                if stack is not None:
                    stack.stop()
                    stack = None
                starter = STACK_STARTERS[wanted]
                stack = starter(binary, logs)
                current_stack_name = wanted
                if stack is None:
                    results.append(
                        Result(capture, "skipped", f"{wanted} stack did not come up")
                    )
                    continue

            # A section whose output depends on a background worker waits
            # before every capture after the one that produced the work.
            settle_ms = int(section.get("settle_ms") or 0)
            if settle_ms and section is last_section:
                time.sleep(settle_ms / 1000)
            last_section = section

            actual = run_command(capture.command, binary)
            if normalize(actual) == normalize(capture.body):
                results.append(Result(capture, "ok", actual=actual))
            else:
                results.append(
                    Result(capture, "drift", "output changed", actual=actual)
                )
    finally:
        if stack is not None:
            stack.stop()
    return results


def render_diff(expected: str, actual: str) -> str:
    lines = difflib.unified_diff(
        normalize(expected).split("\n"),
        normalize(actual).split("\n"),
        fromfile="documented",
        tofile="actual",
        lineterm="",
    )
    return "\n".join(f"    {line}" for line in lines)


def apply_updates(path: Path, results: list[Result]) -> bool:
    """Rewrite drifted blocks in place, latest marker first."""
    lines = path.read_text().split("\n")
    changed = False
    for result in sorted(results, key=lambda r: r.capture.line, reverse=True):
        if result.status != "drift" or result.capture.body_span is None:
            continue
        start, end = result.capture.body_span
        replacement = normalize(result.actual).split("\n")
        lines[start:end] = replacement
        changed = True
    if changed:
        path.write_text("\n".join(lines))
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="enumerate markers and exit")
    parser.add_argument("--check", action="store_true", help="report drift, write nothing")
    parser.add_argument("--update", action="store_true", help="rewrite drifted blocks")
    parser.add_argument(
        "--binary",
        help="sbproxy binary to run captured commands against "
        "(default $SBPROXY_CAPTURE_BIN, else target/release/sbproxy)",
    )
    parser.add_argument(
        "--stackless-only",
        action="store_true",
        help="skip captures needing a live proxy; useful in a lane with no fixtures",
    )
    parser.add_argument("paths", nargs="*", help="documents to check (default: all)")
    args = parser.parse_args()

    if args.paths:
        docs = [Path(p) if Path(p).is_absolute() else ROOT / p for p in args.paths]
    else:
        docs = sorted(
            {
                path
                for pattern in ("docs/*.md", "examples/*/README.md")
                for path in ROOT.glob(pattern)
                if _has_marker(path)
            }
        )

    if args.list:
        total = 0
        for path in docs:
            for capture in parse_captures(path):
                total += 1
                rel = display_path(path)
                print(f"{rel}:{capture.line}: {capture.command}")
        print(f"\n{total} capture(s) in {len(docs)} document(s)")
        return 0

    raw_binary = args.binary or os.environ.get("SBPROXY_CAPTURE_BIN")
    binary: Path | None
    if raw_binary:
        binary = Path(raw_binary)
    else:
        default = ROOT / "target" / "release" / "sbproxy"
        binary = default if default.exists() else None
    if binary is not None and not binary.exists():
        print(f"capture check: binary not found at {binary}", file=sys.stderr)
        return 2

    logs = Path("/tmp/sbproxy-capture-logs")
    logs.mkdir(parents=True, exist_ok=True)

    all_results: list[Result] = []
    for path in docs:
        results = check_document(path, binary, logs, args.stackless_only)
        if args.update:
            apply_updates(path, results)
        all_results.extend(results)

    counts: dict[str, int] = {}
    for result in all_results:
        counts[result.status] = counts.get(result.status, 0) + 1

    failures = [r for r in all_results if r.status in ("drift", "empty", "missing")]
    for result in failures:
        rel = display_path(result.capture.path)
        print(f"\n{rel}:{result.capture.line}: {result.detail}")
        print(f"  $ {result.capture.command}")
        if result.status == "drift":
            print(render_diff(result.capture.body or "", result.actual))

    summary = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
    print(f"\ncapture check: {summary or 'nothing to check'}")

    skipped = counts.get("skipped", 0)
    if skipped:
        # A partial run must never read as full coverage.
        print(
            f"capture check: {skipped} capture(s) NOT verified. "
            "Supply a binary and run without --stackless-only to cover them.",
            file=sys.stderr,
        )

    if args.update:
        return 0
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        raise
