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
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parent.parent

MARKER = re.compile(r"^[ \t]*<!--[ \t]*CAPTURE:[ \t]*(?P<command>.+?)[ \t]*-->[ \t]*$")

# An opening code fence, near enough to CommonMark for a docs tree.
#
# CommonMark allows three or more backticks followed by an *info string*
# that may hold anything except a backtick, so `rust,no_run`, `text
# title="sb.yml"` and `console` are all openers. The old pattern here
# was `` `{3,}[a-z]*[ \t]*$ ``, which accepted only a bare lowercase
# language. That is not a narrower parse, it is a desynchronizing one:
# the opener is skipped, the block's own closing fence is then read as
# an opener, and every fence below it in the document is paired off by
# one. `docs/audit-log.md` shipped exactly that (a ```rust,no_run block
# at line 1019 cost the file one of its 31 blocks and inverted code and
# prose for the rest of the page) while every lane stayed green.
#
# Leading whitespace is accepted without CommonMark's three-space limit,
# because fences nested in list items here are indented four and five
# (`docs/admin-api-guide.md:122`). Refusing those would trade one silent
# desync for another.
FENCE = re.compile(r"^[ \t]*(?P<fence>`{3,})(?P<info>[^`]*)$")

# A closing fence: backticks and nothing else. The run must be at least
# as long as the opener's, which is what lets a four-backtick block hold
# three-backtick lines in its body.
FENCE_CLOSE = re.compile(r"^[ \t]*(?P<fence>`{3,})[ \t]*$")

# Anything that starts a run of three or more backticks. A line matching
# this but not `FENCE` is a fence the parser cannot read, and is
# reported rather than walked past: see `_fences`.
FENCE_LOOKALIKE = re.compile(r"^[ \t]*`{3,}")

# An ATX heading. `uncaptured_output_blocks` uses it as the one thing
# that separates a command from a block below it.
HEADING = re.compile(r"^ {0,3}#{1,6}(?:[ \t]|$)")


def _fence_lang(info: str) -> str:
    """The language out of a fence's info string.

    CommonMark's info string is the language followed by arbitrary
    attributes. Everything this script decides is keyed on the language,
    so `rust,no_run` is `rust` and `text title="sb.yml"` is `text`.
    """
    stripped = info.strip()
    if not stripped:
        return ""
    return re.split(r"[,\s]", stripped, maxsplit=1)[0].lower()


def _closes(line: str, fence: str) -> bool:
    """Whether `line` closes a block opened with `fence`."""
    closing = FENCE_CLOSE.match(line)
    return closing is not None and len(closing.group("fence")) >= len(fence)

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
        # section, reached by its own dedicated walkthrough. It drives
        # its own traffic: the page's first capture bills a call, the
        # two `sqlite3` reads below it read the row that produced, and
        # the `/metrics` scrape at the end reads the counter the same
        # call incremented (WOR-2643).
        #
        # That driver marker is load bearing rather than tidy. The two
        # reads used to be the only markers here, on the assumption that
        # docs/payment-settlement.md's section had already filled the
        # queue. It had, and then this page's own stack start wiped it:
        # `start_usage_bridge_stack` rmtree's /tmp/sbproxy-usage-bridge
        # before every boot, so both reads ran against an empty database
        # and this page could not go green in a full run no matter what
        # it claimed. A page's captures have to stand up on their own,
        # because the harness gives every document a fresh stack.
        #
        # Same stack, match list and settle wait as the settlement page
        # rather than a second definition of the same shape: a row
        # written `queued` needs the recovery worker's next sweep,
        # 1000 ms in this example's config, before it reads `terminal`.
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
    "docs/audit-log.md": {
        # The admin half of the page, against `examples/audit-log/`.
        # Shared rather than fresh per block because the second capture
        # asserts the admin-action ring is still empty after the first
        # one reloaded, which is the page's actual claim: a reload does
        # not write to that ring. A fresh proxy per block would show an
        # empty ring for a reason the page is not making.
        "sections": [{"stack": "audit_log", "fresh_each": False}],
    },
    "docs/admin-api-reference.md": {
        # Two sections, because this page is a route reference with a
        # walkthrough embedded in it.
        "sections": [
            # The "Worked example" blocks are the same five attributed
            # calls `examples/admin-reporting/README.md` drives, read
            # back through this page's routes, so they want that
            # walkthrough's stack rather than a second copy of it. They
            # are ordered among themselves: the export counters in the
            # last one exist because the two exports above it ran.
            {
                "match": ["api/requests", "admin_request_export"],
                "stack": "admin_reporting",
                "fresh_each": False,
            },
            # `/api/health` answers with a compile-time constant, so
            # this does not prove the body is current; the page says as
            # much two lines below the marker. What it holds is the
            # route: that the admin server binds, that basic auth on
            # these credentials is accepted, and that this path still
            # answers 200 with this shape rather than having moved or
            # grown a field. Any config with an admin block serves it,
            # so it rides the cheaper stack.
            {"stack": "audit_log", "fresh_each": False},
        ],
    },
    "examples/admin-reporting/README.md": {
        # One walkthrough, one stack, and every block after the first is
        # downstream of the one above it: the report reads the five
        # calls the stack drove, and the export counters and audit
        # records read the two exports. `fresh_each` would reset the
        # in-memory report ring between blocks and publish zeroes.
        #
        # The export marker writes its CSV to /tmp rather than to the
        # `acme-requests.csv` the page shows. Commands run with the repo
        # root as their working directory, so the documented spelling
        # would drop an untracked file into the tree on every check, and
        # a lane that dirties the tree it is checking fails the gate
        # that reads it. `head -3` prints the same three lines either
        # way, which is what the block holds.
        "sections": [{"stack": "admin_reporting", "fresh_each": False}],
    },
}

# Pages that carry command output and are deliberately NOT above.
#
# This list is here because the alternative is worse than useless. An
# unreplayed page looks identical to a page nobody got to yet, so the
# next person to sweep for gaps re-derives the same reasoning and, if
# they are unlucky, lands the flaky gate one of these notes exists to
# prevent. Two of these were decided in pull-request bodies, which are
# invisible from the code.
#
# `examples/health-and-budget-gauges/README.md`
#     Timing-dependent by design. Its walkthrough says "scrape right
#     after startup, before the dead target's third consecutive probe
#     failure", and the harness has no way to hold that window open.
#     A manifest entry buys a flaky gate rather than an honest one.
#     There is no ticket for this and that is deliberate: the only
#     remedies are to teach the harness to freeze a probe clock, or to
#     rewrite the walkthrough so it stops demonstrating the thing it
#     exists to demonstrate. A ticket saying "add this to the manifest"
#     reads as a to-do and gets actioned into the flake. If you are here
#     because you noticed the page is unreplayed: that is on purpose.
#
# `docs/audit-log.md`, the two stdout blocks
#     The `sbproxy::admin::audit` line and the `config_audit` envelope
#     are real output, but they arrive on the proxy's stdout, which this
#     script redirects into a log file and never hands to a capture
#     command. There is no command that produces them, so there is
#     nothing to put after a marker. Covering them needs an admin route
#     that reads them back, which is a feature rather than a manifest
#     entry.
#
# `docs/admin-api-reference.md`, its per-route response bodies
#     The worked examples on this page are captured; its per-route JSON
#     blocks are not, and should not be. They are response *shapes*
#     carrying deliberate placeholders (`abc123...`, `08ad73be-...`,
#     `key_9f2c...`), and several describe states you cannot produce on
#     demand, such as a reload whose `degraded` array names a subsystem
#     that failed. A shape is not a capture, and replaying one would
#     mean inventing a scenario to match it.
#
# `docs/admin-ui.md`
#     Nothing to replay on this branch. The page is prose plus
#     screenshots (see `scripts/capture-admin-screenshots.mjs`) and
#     three copy-paste blocks: a build recipe, a URL template, and a
#     three-terminal mesh launch. None of the three shows output.

#
# The two whole-page exemptions above are machine-checked below, so a
# marker landing on one of them is refused rather than quietly ignored.
#
# The block-level notes used to stay prose, on the reasoning that they
# name blocks and not pages. That reasoning is what WOR-2643 walked
# through: `examples/usage-bridge-queue/README.md` showed a `/metrics`
# scrape and its three-line output with no marker on it, and the block
# was neither replayed nor named here, which are the same thing to
# every lane that reads this file. Blocks that show output now go in
# `UNCAPTURED_BLOCKS` below and are held to the same standard as the
# page-level list: a reason, and exactly one match.
#
# What stays prose is the two notes above with no command to replay at
# all - the audit stdout lines, which no command produces, and the
# per-route response shapes, which are not output of anything. The
# routing-decisions note that used to sit here as a third one is gone:
# it has a command, so it lives in `UNCAPTURED_BLOCKS` and is audited.
# Two records of one decision is how the machine-read half and the
# prose half drift apart, which is the rot this whole map removes.
EXEMPT_DOCS: dict[str, str] = {
    "docs/admin-ui.md": (
        "nothing on the page is command output: prose, screenshots, and "
        "copy-paste blocks, plus one response keyed by a run-time request id"
    ),
    "examples/health-and-budget-gauges/README.md": (
        "timing-dependent: the walkthrough scrapes inside the window before a "
        "probe's third consecutive failure, which no replay can hold open"
    ),
}

# Fenced languages a block uses when it holds the output of the command
# above it. `bash` blocks are commands; `yaml`, `rust`, `toml` and the
# rest are source. A block in one of these, sitting under a `bash`
# block, is this repo's shape for "here is what that printed".
#
# `http` and `xml` are here because the tree shows raw responses in them
# eleven times (`docs/auth-oidc.md:110`,
# `examples/rail-x402-base-sepolia/README.md:91`). None of those pages
# is covered today, so they are latent rather than live, which is the
# reason to add them now rather than after one lands on a manifest page.
OUTPUT_FENCE_LANGS = frozenset({"", "text", "json", "http", "xml"})

# Command blocks on a MANIFEST page that show their output and are
# deliberately not replayed. Keyed on a substring of the command, so a
# rewritten block loses its entry and gets policed again.
#
# Every one of these is a page in the manifest, which is the point: the
# manifest says the page is covered, and a reader has no way to tell
# which blocks on it are. Recording the exceptions by command is what
# makes "this page is captured" mean something, and what makes adding an
# uncaptured block to a captured page a decision somebody has to write
# down rather than an omission nothing sees.
#
# A needle is a substring, so it must match exactly one block. Matching
# none means the block was captured or rewritten and the note is
# excusing nothing. Matching two means one excuse now covers a block
# nobody wrote it for: `chain?limit=5` would silently absorb a second,
# newer `chain?limit=5&channel=security` block and the page would report
# clean. Both are errors below. Widen the needle until it is unique
# rather than letting it spread, because a substring that can quietly
# over-match is the denylist this map replaced wearing a new hat.
UNCAPTURED_BLOCKS: dict[str, dict[str, str]] = {
    "docs/payment-settlement.md": {
        "/admin/payments/status": (
            "an operator's own deployment, not this page's fixture: it "
            "authenticates with ${SB_ADMIN_PASSWORD}, which nothing on the "
            "page sets, and the body shows two configured rails and six "
            "figures of worker ticks that a fixture started seconds ago "
            "cannot produce"
        ),
        "/admin/payments/reconcile": (
            "same deployment and same unset ${SB_ADMIN_PASSWORD} as the "
            "status block above it; the response claims a lightning_cln "
            "attempt that only a stranded real payment produces"
        ),
    },
    "docs/audit-log.md": {
        "chain?limit=5": (
            "runs against the hand-written /tmp/sbproxy-audit-demo/sb.yml the "
            "page prints inline, which has four chains and its own keystore; "
            "the audit_log stack boots examples/audit-log/sb.yml instead"
        ),
        "chain?channel=admin&limit=2": (
            "same inline /tmp/sbproxy-audit-demo walkthrough, and it pages "
            "through records the three calls above it wrote"
        ),
        "sed -i ''": (
            "tampers with a chained record on disk to show the walk stopping. "
            "Destructive by design, and the BSD spelling of sed -i is not "
            "portable to the Linux lanes"
        ),
        ": > /tmp/sbproxy-audit-demo": (
            "truncates the security chain to show what a deleted trail looks "
            "like. Destructive by design, against the same inline fixture"
        ),
    },
    "docs/admin-api-reference.md": {
        "api/routing-decisions": (
            "the one worked example on the page left out. Its setup is a "
            "config inline in the page rather than a directory under "
            "examples/, and it needs a second provider on 18591 plus a "
            "deliberately closed port to force the fallback it demonstrates: "
            "a fixture that exists nowhere else in the repo, so the example "
            "wants shipping before the stack does"
        ),
        "/admin/cache/purge": (
            "the fence below this command is not its output: it is the cache "
            "key's wire format, printed so an operator writing a `key` or a "
            "`prefix` by hand can see the field order. The purge call answers "
            "with a count, so there is nothing here for a marker to replay"
        ),
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
    status: str  # "ok" | "drift" | "empty" | "missing" | "blocked" | "skipped"
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
                # Reaped rather than left behind: `kill` only delivers
                # the signal, and a child still holding its listening
                # socket is a child the next stack's port preflight
                # will find and report as somebody else's.
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
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
    # Service time in milliseconds, as a float, in both export formats.
    # It is the one field on the reporting pages that is a measurement
    # rather than a value the config or the request determined, so it
    # moves every run and is the only thing normalized away there.
    (re.compile(r'"latency_ms":\s*\d+\.\d+'), '"latency_ms": <LATENCY>'),
    # The same field in the CSV export, where it has no name. Anchored
    # on the column that follows it rather than on a bare float, so it
    # cannot swallow the cost, token or retry columns.
    (re.compile(r"(?<=,)\d+\.\d+(?=,127\.0\.0\.1:)"), "<LATENCY>"),
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
        if _closes(lines[end], fence):
            return "\n".join(lines[body_start:end]), (body_start, end)
    return None, None


def _fences(lines: list[str]) -> tuple[list[tuple[int, int, str]], list[tuple[int, str]]]:
    """Every fenced block in a document, and every fence it could not read.

    Returns `(blocks, problems)`. Blocks are `(open, close, language)`
    with indices into `lines`. Problems are `(1-based line, why)`.

    The second half of that tuple is the point. This walker can lose
    sync with the document in exactly two ways, and both used to be
    silent:

    1. A line that opens a fence but does not match `FENCE` - an info
       string with a backtick in it. The walker steps over the opener,
       reads the block's closing fence as an opener, and pairs off every
       fence below it by one, reporting prose as code and code as prose.
    2. A fence that is never closed. Stopping at that point is right (a
       stray triple-backtick in prose should not swallow the rest of the
       file) but it means every block below it disappears.

    Both now come back as problems, so a caller that acts on the blocks
    can refuse instead of trusting a half-read document. Nothing else
    can desync it: a fence line inside a block body is either the closer
    or too short to be one, which is the same call CommonMark makes.
    """
    blocks: list[tuple[int, int, str]] = []
    problems: list[tuple[int, str]] = []
    cursor = 0
    while cursor < len(lines):
        line = lines[cursor]
        opening = FENCE.match(line)
        if not opening:
            if FENCE_LOOKALIKE.match(line):
                problems.append(
                    (
                        cursor + 1,
                        f"opens a code fence this parser cannot read: {line.strip()!r}. "
                        "An info string may not contain a backtick; every block below "
                        "this line would be paired off by one",
                    )
                )
            cursor += 1
            continue
        fence = opening.group("fence")
        for end in range(cursor + 1, len(lines)):
            if _closes(lines[end], fence):
                blocks.append((cursor, end, _fence_lang(opening.group("info"))))
                cursor = end + 1
                break
        else:
            problems.append(
                (
                    cursor + 1,
                    f"opens a code fence that is never closed: {line.strip()!r}. "
                    "Every block below this line is invisible to this check",
                )
            )
            cursor = len(lines)
    return blocks, problems


def fence_problems(path: Path) -> list[tuple[int, str]]:
    """Fences in a document that `_fences` cannot account for.

    Split out so the coverage gate can refuse an unreadable page rather
    than report on the wrong half of it.
    """
    return _fences(path.read_text().split("\n"))[1]


def uncaptured_output_blocks(path: Path) -> list[tuple[int, str]]:
    """Commands whose output the page shows and no marker replays.

    The shape this looks for is the one every captured block on every
    page here already has: a `bash` block, then the output it printed.
    A marker between the two means the harness re-runs the command and
    diffs it. No marker means the block is a transcript somebody typed
    once, and nothing in this repo can tell whether it is still true.

    Setup and teardown are outside the rule by construction rather than
    by exemption: `cargo build`, `mkdir`, `kill %1` show no output, so
    no output block follows them and there is nothing to hold to the
    code. This looks only at commands the page makes a claim about.

    What it can see, exactly: a `bash` block whose next fenced block is
    in `OUTPUT_FENCE_LANGS`, with no heading between the two. Prose
    between them is inside the rule, because "That returns:" followed by
    the body is this repo's most common shape for showing output, and
    exempting it made the check narrower than the sentence above claims.
    A heading is out, because a heading starts a new subject and the
    block under it belongs to that subject, not to the command above.

    What it cannot see: output shown under a heading, output the page
    describes in prose without fencing it, and output fenced in a
    language not in `OUTPUT_FENCE_LANGS` (`yaml`, `rust`, `toml` and the
    rest are source, and treating them as output would police every
    config sample in the tree).

    Returns `(line number of the command fence, the command text)`.
    """
    lines = path.read_text().split("\n")
    blocks, _ = _fences(lines)
    findings: list[tuple[int, str]] = []
    for index, (start, end, lang) in enumerate(blocks):
        if lang != "bash" or index + 1 >= len(blocks):
            continue
        next_start, _, next_lang = blocks[index + 1]
        if next_lang not in OUTPUT_FENCE_LANGS:
            continue
        between = [line for line in lines[end + 1:next_start] if line.strip()]
        if any(MARKER.match(line) for line in between):
            continue
        # A heading between the two means the second block is not this
        # command's output; it is the first thing the next section
        # shows. Prose is not that signal: five of the 32 command and
        # output pairs on the covered pages have a sentence between
        # them, and all five are genuine output of the command above.
        if any(HEADING.match(line) for line in between):
            continue
        findings.append((start + 1, "\n".join(lines[start + 1:end])))
    return findings


# --- Stacks ------------------------------------------------------------


def _busy_ports(ports: tuple[int, ...], timeout: int = 15) -> list[int]:
    """Which of these loopback ports still have a listener.

    Waits up to `timeout` for them to clear before answering, because
    the caller has usually just torn down the previous stack and a
    listener takes a moment to go.

    This exists because the failure it prevents is invisible. Every
    stack here binds 8080 and most also bind 9090. Start one while
    something else holds those ports and nothing reports an error: the
    proxy child dies on the bind, `_wait_for_http` gets its 200 from
    whatever is already listening, and every capture in the document
    then replays against a foreign proxy. That surfaced as a
    `config_revision` drift on `docs/audit-log.md` whose "actual" value
    belonged to a different example's config entirely, and it could just
    as easily have gone green against output that happened to match.
    A named skip is worth more than either.
    """
    deadline = time.time() + timeout
    while True:
        busy = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(1)
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    busy.append(port)
        if not busy or time.time() >= deadline:
            return busy
        time.sleep(1)


def _wait_for_port(port: int, procs: list[subprocess.Popen], timeout: int = 60) -> bool:
    """Wait for a listener on a loopback port without sending a request.

    `_wait_for_http` probes the data plane, and the proxy logs what the
    data plane serves. For most stacks that costs nothing, but a page
    that publishes a request count is a page the readiness probe can
    change: `examples/admin-reporting/` publishes `requests: 5`, and a
    GET to `127.0.0.1:8080/metrics` lands in the same report ring as an
    unattributed sixth row under the `__default__` tenant. A TCP connect
    answers the same question and leaves no trace.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        for proc in procs:
            if proc.poll() is not None:
                return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(1)
    return False


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
    # This page's captures call the admin listener on 9090, which
    # binds after the proxy service; readiness on 8080 alone can hand
    # the first capture a connection refused. 9090 up implies 8080 is
    # serving.
    if not _wait_for_port(9090, stack.procs):
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
    # Same readiness rule as the settlement stack: the captures here
    # drive 9090, which binds last, so wait on it directly.
    if not _wait_for_port(9090, stack.procs):
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


def start_audit_log_stack(binary: Path, logs: Path) -> Stack | None:
    """Just the proxy: these captures only ever call the admin server.

    `examples/audit-log/sb.yml` points its one origin at
    `test.sbproxy.dev`, which nothing here dials. Every command on the
    two pages this stack serves is an admin call on 9090, so the proxy
    alone is the whole stack and no fixture is needed.
    """
    stack = Stack()
    proxy_log = (logs / "audit-log-proxy.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [str(binary), "serve", "-f", "examples/audit-log/sb.yml"],
            cwd=ROOT,
            stdout=proxy_log,
            stderr=subprocess.STDOUT,
        )
    )
    # Both pages this stack serves only ever call the admin listener on
    # 9090, and the admin listener binds after the proxy service is up,
    # so readiness on 8080 can declare a stack whose admin port still
    # refuses connections. Wait on 9090 itself, the way the
    # admin-reporting stack does.
    if not _wait_for_port(9090, stack.procs):
        stack.stop()
        return None
    return stack


def _fixture_from_readme(readme: Path, opener: str, terminator: str) -> str:
    """Lift a heredoc fixture out of the page that documents it.

    `examples/admin-reporting/` ships no `fixture.py`, and that is on
    purpose: its `sb.yml` header used to carry a second copy of this
    fixture, the copy drifted, and a reader who ran that one got totals
    matching none of the published numbers. The README's heredoc is the
    only copy, so the stack runs that rather than a duplicate this file
    would then have to keep in step.
    """
    lines = readme.read_text().split("\n")
    for index, line in enumerate(lines):
        if line.strip() != opener:
            continue
        body = []
        for rest in lines[index + 1 :]:
            if rest.strip() == terminator:
                return "\n".join(body)
            body.append(rest)
        break
    raise RuntimeError(f"no {opener!r} fixture found in {readme}")


def start_admin_reporting_stack(binary: Path, logs: Path) -> Stack | None:
    """The reporting fixture, the proxy, and the five attributed calls.

    The driving calls belong to the stack rather than to a capture
    because they answer with nothing: the page's `drive()` sends output
    to `/dev/null`, and a marker over an empty block is a finding by
    this script's own rules. Everything the page then publishes, the
    report, both exports, the export counters and the audit records, is
    a read of what those five calls produced, so the stack has to have
    made them before the first capture runs.

    A fresh proxy per run matters here for the same reason: the report
    ring is in-memory and holds whatever has passed through it, so a
    second run against a live proxy would report ten calls and match
    none of the published figures.
    """
    stack = Stack()
    fixture_source = _fixture_from_readme(
        ROOT / "examples/admin-reporting/README.md", "python3 - <<'PY' &", "PY"
    )
    fixture_path = Path("/tmp/sbproxy-admin-reporting-fixture.py")
    fixture_path.write_text(fixture_source)
    fixture_log = (logs / "admin-reporting-fixture.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [sys.executable, str(fixture_path)],
            cwd=ROOT,
            stdout=fixture_log,
            stderr=subprocess.STDOUT,
        )
    )
    time.sleep(3)
    proxy_log = (logs / "admin-reporting-proxy.log").open("w")
    stack.procs.append(
        subprocess.Popen(
            [str(binary), "serve", "-f", "examples/admin-reporting/sb.yml"],
            cwd=ROOT,
            stdout=proxy_log,
            stderr=subprocess.STDOUT,
        )
    )
    # The admin listener binds after the proxy service starts, so a
    # listener on 9090 means 8080 is serving. See `_wait_for_port` for
    # why this stack cannot use the HTTP probe the others do.
    if not _wait_for_port(9090, stack.procs):
        stack.stop()
        return None

    # The five calls from the page's "Drive attributed traffic" block,
    # in the order it lists them. Order is not cosmetic: the CSV export
    # is newest-first and the page publishes its first two rows.
    drives = [
        ("acme.ai.local", "vk-acme-platform", "dev@acme.test", "gpt-4o-mini", "summarize"),
        ("acme.ai.local", "vk-acme-platform", "dev@acme.test", "gpt-4o-mini", "summarize"),
        ("acme.ai.local", "vk-acme-platform", "ops@acme.test", "gpt-4o", "incident-triage"),
        ("acme.ai.local", "vk-acme-research", "sci@acme.test", "gpt-4o-mini", "literature-scan"),
        (
            "globex.ai.local",
            "vk-globex-platform",
            "dev@globex.test",
            "gpt-4o-mini",
            "summarize",
        ),
    ]
    for host, key, user, model, feature in drives:
        result = subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null",
                "http://127.0.0.1:8080/v1/chat/completions",
                "-H", f"Host: {host}",
                "-H", f"Authorization: Bearer {key}",
                "-H", f"X-Sb-User-Id: {user}",
                "-H", f"X-Sb-Property-Feature: {feature}",
                "-H", "Content-Type: application/json",
                "-d",
                json.dumps({"model": model, "messages": [{"role": "user", "content": "Hi"}]}),
            ],
            cwd=ROOT,
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            stack.stop()
            return None
    return stack


STACK_STARTERS = {
    "settlement": start_settlement_stack,
    "usage_bridge": start_usage_bridge_stack,
    "temp_budget_override": start_temp_budget_override_stack,
    "api_deprecation": start_api_deprecation_stack,
    "transform_json_schema": start_transform_json_schema_stack,
    "audit_log": start_audit_log_stack,
    "admin_reporting": start_admin_reporting_stack,
}

# What each stack binds, checked before it starts. See `_busy_ports`
# for why a busy port has to be caught here rather than left to the
# readiness probe. Keep an entry per starter: a stack missing from this
# map binds nothing as far as the guard is concerned, which is the one
# way back to the silent-foreign-proxy failure.
STACK_PORTS: dict[str, tuple[int, ...]] = {
    "settlement": (8080, 9090, 18080),
    "usage_bridge": (8080, 9090, 18080),
    "temp_budget_override": (8080, 9090, 18080),
    "api_deprecation": (8080,),
    "transform_json_schema": (8080,),
    "audit_log": (8080, 9090),
    "admin_reporting": (8080, 9090, 18086),
}


def check_exemptions() -> list[str]:
    """Hold the exemption list to the same standard as the manifest.

    An exemption is a claim about a document, and a claim nothing checks
    rots the same way a number in a doc does. Two ways it can go wrong,
    both silent otherwise: the document is renamed or deleted and the
    note now describes nothing, or somebody adds a marker to an exempt
    page, at which point the file says two contradictory things and the
    reader has to guess which is current.
    """
    errors: list[str] = []
    for rel, reason in sorted(EXEMPT_DOCS.items()):
        path = ROOT / rel
        if not path.exists():
            errors.append(f"{rel} is exempt but does not exist; drop the entry")
            continue
        if not reason.strip():
            errors.append(f"{rel} is exempt with no reason given")
        if _has_marker(path):
            errors.append(
                f"{rel} is exempt but carries a CAPTURE marker; "
                "put it in MANIFEST or drop the marker"
            )
    for rel in MANIFEST:
        if rel in EXEMPT_DOCS:
            errors.append(f"{rel} is in both MANIFEST and EXEMPT_DOCS")
    return errors


def check_block_coverage() -> list[str]:
    """Refuse a shown output that neither a marker nor a note accounts for.

    Coverage here has always been per marker, which makes it per block
    that somebody remembered. A page in the MANIFEST reads as covered,
    and until now that could mean any fraction of it: WOR-2643's
    `/metrics` scrape sat three lines under a captured `sqlite3` read on
    a manifest page, showed a counter value, and was replayed by
    nothing. Every lane was green and the page was two thirds checked.

    So the unit of the decision moves from the page to the block. A
    command that shows its output on a manifest page is either replayed
    or named in `UNCAPTURED_BLOCKS` with a reason, and both halves are
    audited: a note that matches no block is reported the same way a
    missing marker is, so the exceptions cannot outlive the blocks they
    were written for, and a note that matches two is reported as well,
    so one excuse cannot spread to a block nobody wrote it for.

    The scope of "shows its output" is `uncaptured_output_blocks`, whose
    docstring says exactly what that sees and does not. Before reading
    any of it this refuses a page whose fences it cannot parse, because
    a half-read page reports clean for the wrong reason.
    """
    errors: list[str] = []
    for rel in sorted(UNCAPTURED_BLOCKS):
        if rel not in MANIFEST:
            errors.append(
                f"{rel} has UNCAPTURED_BLOCKS entries but is not in MANIFEST; "
                "an unlisted page is not covered, so the notes describe nothing"
            )
    for rel in sorted(MANIFEST):
        path = ROOT / rel
        if not path.exists():
            continue
        unreadable = fence_problems(path)
        for line, why in unreadable:
            errors.append(f"{rel}:{line}: {why}")
        if unreadable:
            # Every block index below the bad fence is suspect, so the
            # findings from this page would be about the wrong lines.
            continue
        recorded = UNCAPTURED_BLOCKS.get(rel, {})
        matches: dict[str, list[int]] = {needle: [] for needle in recorded}
        for line, command in uncaptured_output_blocks(path):
            hits = [needle for needle in recorded if needle in command]
            if hits:
                for needle in hits:
                    matches[needle].append(line)
                continue
            first = command.strip().split("\n")[0]
            errors.append(
                f"{rel}:{line}: shows the output of `{first}` and no CAPTURE "
                "marker replays it. Add a marker, or record the block in "
                "UNCAPTURED_BLOCKS with the reason it cannot be replayed"
            )
        for needle, reason in sorted(recorded.items()):
            if not reason.strip():
                errors.append(f"{rel}: UNCAPTURED_BLOCKS entry '{needle}' gives no reason")
            hit_lines = matches[needle]
            if not hit_lines:
                errors.append(
                    f"{rel}: UNCAPTURED_BLOCKS entry '{needle}' matches no "
                    "uncaptured block; the block was captured or rewritten, so "
                    "drop the entry rather than leave it excusing nothing"
                )
            elif len(hit_lines) > 1:
                where = ", ".join(str(line) for line in hit_lines)
                errors.append(
                    f"{rel}: UNCAPTURED_BLOCKS entry '{needle}' matches "
                    f"{len(hit_lines)} uncaptured blocks (lines {where}); the "
                    "reason was written for one of them. Narrow the needle and "
                    "give each block its own entry, or the next block to contain "
                    "this substring inherits an excuse nobody wrote for it"
                )
    return errors


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
                current_stack_name = wanted
                busy = _busy_ports(STACK_PORTS.get(wanted, ()))
                if busy:
                    ports = ", ".join(str(port) for port in busy)
                    results.append(
                        Result(
                            capture,
                            "blocked",
                            f"{wanted} stack needs port(s) {ports}, which are "
                            "still in use; nothing was replayed against them",
                        )
                    )
                    continue
                starter = STACK_STARTERS[wanted]
                stack = starter(binary, logs)
                if stack is None:
                    results.append(
                        Result(capture, "blocked", f"{wanted} stack did not come up")
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

    # A page in the MANIFEST whose CAPTURE markers were stripped (a doc
    # regen that drops HTML comments, say) falls out of the glob above
    # and out of coverage without a word, while the MANIFEST still
    # reads as covering it. Refuse that state by name.
    stripped = [rel for rel in MANIFEST if not _has_marker(ROOT / rel)]
    if stripped:
        for rel in stripped:
            print(
                f"capture check: {rel} is in MANIFEST but carries no "
                "CAPTURE marker; its coverage silently lapsed",
                file=sys.stderr,
            )
        return 2

    exempt_errors = check_exemptions()
    for error in exempt_errors:
        print(f"capture exemption: {error}", file=sys.stderr)

    coverage_errors = check_block_coverage()
    for error in coverage_errors:
        print(f"capture coverage: {error}", file=sys.stderr)

    # Both are static: they read the documents and the two maps, and
    # need no binary and no stack. So they run in every mode, including
    # `--list` and the `--stackless-only` lane CI uses, which is the
    # lane a missing marker has to be caught in.
    static_errors = exempt_errors + coverage_errors

    if args.list:
        total = 0
        for path in docs:
            for capture in parse_captures(path):
                total += 1
                rel = display_path(path)
                print(f"{rel}:{capture.line}: {capture.command}")
        print(f"\n{total} capture(s) in {len(docs)} document(s)")
        for rel, reason in sorted(EXEMPT_DOCS.items()):
            print(f"exempt: {rel}: {reason}")
        for rel, blocks in sorted(UNCAPTURED_BLOCKS.items()):
            for needle, reason in sorted(blocks.items()):
                print(f"uncaptured block: {rel}: `{needle}`: {reason}")
        return 1 if static_errors else 0

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
    if binary is None and not args.stackless_only:
        print(
            "capture check: a full replay was requested (no --stackless-only), "
            "but no proxy binary exists at target/release/sbproxy and "
            "SBPROXY_CAPTURE_BIN is unset. Every stack capture would be "
            "silently skipped and the run would read as coverage. Build the "
            "binary or point SBPROXY_CAPTURE_BIN at one.",
            file=sys.stderr,
        )
        return 2

    logs = Path("/tmp/sbproxy-capture-logs")
    logs.mkdir(parents=True, exist_ok=True)

    all_results: list[Result] = []
    for path in docs:
        started = time.monotonic()
        print(f"capture check: starting {display_path(path)}", flush=True)
        results = check_document(path, binary, logs, args.stackless_only)
        if args.update:
            apply_updates(path, results)
        all_results.extend(results)
        statuses = sorted({result.status for result in results})
        print(
            f"capture check: finished {display_path(path)}: {len(results)} capture(s), "
            f"{', '.join(statuses) or 'nothing to check'}, "
            f"{time.monotonic() - started:.1f}s",
            flush=True,
        )

    counts: dict[str, int] = {}
    for result in all_results:
        counts[result.status] = counts.get(result.status, 0) + 1

    # `blocked` is in this set on purpose. It means a stack this run was
    # asked to replay could not be started, so those captures were not
    # checked, and a run that verified nothing must not exit 0 and read
    # as coverage. `skipped` stays out of it: that is the deliberately
    # partial run, `--stackless-only`, which the local gate asks for by
    # name. A full run with no binary cannot get this far: it is
    # refused up front, before any capture is replayed, for the same
    # reason `blocked` fails.
    failures = [
        r for r in all_results if r.status in ("drift", "empty", "missing", "blocked")
    ]
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
        return 1 if static_errors else 0
    return 1 if (failures or static_errors) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        raise
