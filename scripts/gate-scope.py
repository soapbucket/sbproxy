#!/usr/bin/env python3
"""Decide which `scripts/check.sh` phases a diff can actually affect.

The gate runs every phase on every invocation. Most runs change one thing.
A docs-only branch pays a full workspace build, a full nextest run, clippy,
rustdoc, and the payments lane for a change that no compiler can see.

This module maps changed paths to gate phases so `scripts/check.sh
--scope-to-diff` can skip the phases the diff cannot reach.

The safety rule, and the only one that matters:

    AN UNRECOGNIZED PATH RUNS EVERYTHING.

"Unclassified" means "full gate". It never means "skip". The classifier is
an explicit allowlist of path patterns; a path that matches no rule falls
through to ALL, and so does an empty diff, a missing merge base, or a git
invocation that fails. Narrowing this file is how a gate stops gating, so
`--self-test` carries a corpus of failures that reached CI and asserts that
each one still selects the phase that catches it.

One simplification is worth stating, because it removes a whole class of
bug. `scripts/check.sh` has no per-crate mode: every cargo phase in it is
`--workspace`. So "run the touched crate and every crate that depends on
it" needs no reverse-dependency walk here. Any `.rs` change selects the
whole Rust tier, which builds, tests, lints, and documents every crate in
the workspace. A struct-literal or string change cannot escape a consumer,
because there is no narrowing to escape.

Usage:

    gate-scope.py --base origin/main          # classify the branch diff
    gate-scope.py --base origin/main --explain
    gate-scope.py --paths-from -              # classify a path list on stdin
    gate-scope.py --self-test
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys

# --- Phase vocabulary --------------------------------------------------
#
# Every name here is gated by exactly one place in scripts/check.sh. A
# phase that is not in this list always runs; that is the cheap tier and
# it is deliberately not skippable (see ALWAYS below).

# A phase is only allowed in here if it costs more than about ten
# seconds. Everything cheaper stays unconditional, because a check that
# takes a second and catches a real CI failure should never be something
# a classifier can be wrong about. Measured on this machine from four
# full gate runs: the fourteen read-only scans 19-22s as a parallel
# batch, the generator drift scans 1s, llms-full 0s, doc captures 0s,
# install.sh 1s, prometheus rules 2s, cargo-deny 1-2s, gate helper
# self-tests 4s. None of those are skippable. What is below is.
PHASES = [
    "TAPES",  # make tapes-check                      17-19s
    "DOCSCI",  # scripts/docs-ci.sh, code blocks and anchors
    "UI",  # npm typecheck and test                   6-7s
    "BUILD",  # cargo build                           116-149s
    "TEST",  # cargo test (nextest)                   112-668s
    "DOCTEST",  # cargo doctest                       23-41s
    "CLIPPY",  # cargo clippy                         107-212s
    "DOC",  # cargo doc                               84-146s
    "GENERATED",  # config schema, readers, metrics   25-29s
    "PAYMENTS",  # payments clippy and test
]

# The cheap tier. These run on every invocation no matter what changed:
# the fourteen read-only scans, fmt, the lockfile guards, npm audit, the
# conflict-marker scan, changelog fragments, the generator drift scans
# including the examples catalog, the gate helper self-tests, cargo-deny,
# and both halves of the working-tree guard. They cost seconds and they
# are what catch the staleness a merge from main leaves behind, which by
# definition is not in the diff you wrote.
#
# Six of the ten CI failures this classifier was built against are
# caught by that tier, so they survive any mistake made below.
ALWAYS = "the cheap read-only tier always runs"

# Anything that compiles, tests, lints, or documents the workspace, plus
# the generated-artifact checks that exec the binaries the build makes.
RUST = ["BUILD", "TEST", "DOCTEST", "CLIPPY", "DOC", "GENERATED", "PAYMENTS"]

# The documentation tier. DOCSCI is the one that compiles `rust` code
# blocks with rustc and resolves every in-tree anchor; TAPES regenerates
# the tape corpus. The examples catalog, the doc asset scan, the doc
# config scan, the capture scan, and the llms-full guard are all in the
# unconditional tier, so they are not named here.
DOCS = ["DOCSCI", "TAPES"]

# --- The allowlist -----------------------------------------------------
#
# Ordered. The first matching rule wins, so put the specific patterns
# above the general ones. Each entry is (glob, phases, why).
#
# `glob` is matched against a repository-relative POSIX path with
# fnmatch, where `*` crosses directory separators. That is deliberate:
# a pattern that under-matches sends a path to ALL, which is safe, while
# a pattern that over-matches would skip a phase, which is not.

RULES: list[tuple[str, list[str], str]] = [
    # ---- Things that redefine the gate itself. These run everything,
    # because the gate is checking its own change.
    ("scripts/*", None, "the gate is checking a change to itself"),
    (".config/nextest.toml", None, "the test runner's own configuration"),
    ("Makefile", None, "the gate calls make targets"),
    ("rust-toolchain.toml", None, "the compiler version changes every lane"),
    (".cargo/*", None, "cargo configuration changes every lane"),
    # ---- Manifests and lockfiles. A dependency change moves the feature
    # union, the NOTICE stanzas, the advisory surface, and the standalone
    # workspaces that path-depend on this one.
    ("Cargo.lock", RUST, "the dependency graph moved; NOTICE, cargo-deny, and the nested-lockfile guard are unconditional"),
    ("*/Cargo.lock", RUST, "a standalone workspace lockfile moved"),
    ("Cargo.toml", RUST, "the workspace manifest moved"),
    ("*/Cargo.toml", RUST, "a crate manifest moved"),
    ("*/build.rs", RUST, "a build script changes what the crate compiles to"),
    ("deny.toml", [], "cargo-deny is in the cheap tier, which always runs"),
    # ---- The config crate feeds the generated schema, the reader
    # coverage guard, and sync-doc-configs. It is Rust, so it takes the
    # whole Rust tier too.
    (
        "crates/sbproxy-config/*",
        RUST + ["DOCSCI"],
        "config types feed the generated schema, HOST_FILE_KEYS, and the doc configs",
    ),
    ("schemas/*", ["GENERATED"], "the committed schema is the check's input"),
    # ---- Rust. The whole tier, every time. See the module docstring for
    # why there is no reverse-dependency walk.
    ("*.rs", RUST, "Rust source: the gate's cargo phases are all --workspace"),
    # ---- The admin SPA. Its build output is embedded by admin_ui.rs, so
    # a UI change also has to rebuild and re-test the binary that carries
    # it.
    ("ui/*", ["UI", "BUILD", "TEST"], "the admin SPA and the crate that embeds it"),
    # ---- Documentation. docs-ci compiles the `rust` blocks and resolves
    # anchors; the capture and config drift scans read the same tree.
    ("docs/tapes/*", ["TAPES", "DOCSCI"], "a tape and its rendered asset"),
    ("docs/assets/*", ["DOCSCI"], "a doc asset a page embeds"),
    ("docs/*.md", DOCS, "documentation prose, code blocks, and anchors"),
    ("docs/*", DOCS, "the documentation tree"),
    ("*.md", ["DOCSCI"], "prose that another page may link into"),
    # ---- Examples are generated into examples/README.md and into the
    # tape corpus, and every OSS example is compiled by a workspace test.
    ("examples/*", ["TAPES", "DOCSCI", "TEST"], "the tape corpus and the test that compiles every OSS example"),
    # ---- Dashboards feed the metric-visibility ratchet, which lives in
    # the cheap tier and therefore always runs.
    ("dashboards/*", [], "metric visibility is in the cheap tier, which always runs"),
    ("deploy/prometheus/*", [], "the prometheus rule check is in the cheap tier, which always runs"),
    # ---- Metadata that no phase compiles or renders.
    ("NOTICE", [], "the NOTICE guard is in the cheap tier, which always runs"),
    ("LICENSE", [], "no phase reads it"),
    ("CODEOWNERS", [], "no phase reads it"),
    (".gitignore", [], "no phase reads it"),
    (".lycheeignore", ["DOCSCI"], "the link checker's own ignore list"),
    ("deploy/*", [], "no gate phase reads the deployment manifests"),
    ("docs/.changes/*", [], "changelog fragments are parsed in the cheap tier"),
    (".github/*", [], "CI definitions are not executed by the local gate"),
]


class Decision:
    """The set of phases a diff selects, and why each path selected them."""

    def __init__(self) -> None:
        self.run_all = False
        self.all_reason = ""
        self.selected: set[str] = set()
        self.rows: list[tuple[str, str, str]] = []

    def note(self, path: str, phases: str, why: str) -> None:
        self.rows.append((path, phases, why))

    def phases(self) -> list[str]:
        if self.run_all:
            return list(PHASES)
        return [p for p in PHASES if p in self.selected]


def classify(paths) -> Decision:
    """Map changed paths to gate phases. Unmatched paths select everything."""
    decision = Decision()
    paths = list(paths)

    if not paths:
        # No diff, or a diff we could not compute. Either way this is not
        # evidence that nothing changed.
        decision.run_all = True
        decision.all_reason = "no changed paths were resolved, so the diff is unknown"
        decision.note("(none)", "ALL", decision.all_reason)
        return decision

    for path in paths:
        matched = False
        for glob, phases, why in RULES:
            if not fnmatch.fnmatchcase(path, glob):
                continue
            matched = True
            if phases is None:
                decision.run_all = True
                if not decision.all_reason:
                    decision.all_reason = f"{path}: {why}"
                decision.note(path, "ALL", why)
            elif phases:
                decision.selected.update(phases)
                decision.note(path, " ".join(phases), why)
            else:
                decision.note(path, "-", why)
            break
        if not matched:
            decision.run_all = True
            if not decision.all_reason:
                decision.all_reason = f"{path}: no rule matches this path"
            decision.note(path, "ALL", "no rule matches this path, so the gate runs everything")

    return decision


def changed_paths(base: str) -> list[str] | None:
    """Paths this branch changed against `base`, plus anything uncommitted.

    Returns None when the diff cannot be computed, which the caller must
    treat as "run everything" rather than "nothing changed".
    """

    def git(*args: str) -> str | None:
        try:
            out = subprocess.run(
                ["git", *args],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return None
        if out.returncode != 0:
            return None
        return out.stdout

    merge_base = git("merge-base", "HEAD", base)
    if merge_base is None or not merge_base.strip():
        return None
    ref = merge_base.strip()

    paths: set[str] = set()
    committed = git("diff", "--name-only", ref, "HEAD")
    if committed is None:
        return None
    paths.update(line for line in committed.splitlines() if line)

    # The gate validates the working tree, not HEAD, so uncommitted and
    # untracked files are part of the diff it is scoping to.
    working = git("status", "--porcelain=v1", "--untracked-files=normal")
    if working is None:
        return None
    for line in working.splitlines():
        if len(line) > 3:
            entry = line[3:]
            # Renames are recorded as "old -> new"; both sides count.
            if " -> " in entry:
                left, right = entry.split(" -> ", 1)
                paths.add(left.strip('"'))
                paths.add(right.strip('"'))
            else:
                paths.add(entry.strip('"'))

    return sorted(paths)


# --- The corpus test ---------------------------------------------------
#
# Every row is a failure that reached CI on 2026-08-27 and cost a round
# trip of roughly forty minutes: the file it touched, and the phase that
# would have caught it locally. The assertion is that --scope-to-diff
# still selects that phase. This fails if someone narrows a rule above.
#
# ALWAYS_TIER is the honest answer for the three checks that live in the
# cheap read-only tier: they are not skippable at all, so the assertion
# is that the classifier never has the option of dropping them. Naming a
# compile phase for those instead would pass for the wrong reason.

ALWAYS_TIER = "@always"

CORPUS: list[tuple[str, str, str]] = [
    (
        "stale examples/README.md catalog after a merge from main",
        "examples/ai-budget/config.toml",
        ALWAYS_TIER,  # batch_examples_catalog
    ),
    (
        "missing NOTICE stanza after a lockfile change",
        "Cargo.lock",
        ALWAYS_TIER,  # batch_notice_coverage
    ),
    (
        "broken anchor in docs/mcp-oauth-gateway.md to a renamed heading in docs/mcp.md",
        "docs/mcp.md",
        "DOCSCI",
    ),
    (
        "three rust code blocks in a new doc that did not compile standalone",
        "docs/configuration.md",
        "DOCSCI",
    ),
    (
        "a private intra-doc link",
        "crates/sbproxy-core/src/server/proxy_http.rs",
        "DOC",
    ),
    (
        "clippy::items_after_test_module under the payment features",
        "crates/sbproxy-billing/src/x402.rs",
        "PAYMENTS",
    ),
    (
        "a stale secret-resolver-drift-exemptions.json entry",
        "crates/sbproxy-vault/src/resolver.rs",
        ALWAYS_TIER,  # batch_secret_resolver_drift
    ),
    (
        "stale nested lockfiles",
        "bench-synthetic/Cargo.lock",
        ALWAYS_TIER,  # batch_nested_lockfiles
    ),
    (
        "a new path-shaped config key missing from HOST_FILE_KEYS",
        "crates/sbproxy-config/src/confined_template.rs",
        "TEST",  # every_path_shaped_schema_key_is_covered_or_explained
    ),
    (
        "a new path-shaped config key whose schema was never regenerated",
        "crates/sbproxy-config/src/types.rs",
        "GENERATED",
    ),
]

# Shapes that must never narrow to less than the full gate.
FULL_GATE_CORPUS: list[tuple[str, str]] = [
    ("a change to the gate itself", "scripts/check.sh"),
    ("a change to the test runner config", ".config/nextest.toml"),
    ("a path no rule has ever seen", "some/brand/new/tree/thing.bin"),
    ("a new top-level directory", "terraform/main.tf"),
    ("the toolchain pin", "rust-toolchain.toml"),
]


def self_test() -> int:
    failures: list[str] = []

    for name, path, required in CORPUS:
        if required == ALWAYS_TIER:
            # Nothing to select: the cheap tier is unconditional. What is
            # asserted here is that the phase vocabulary has no name for
            # it, so no future rule can turn it off.
            if required in PHASES:
                failures.append(
                    f"corpus: {name}\n"
                    f"  {required} became a skippable phase; it must stay in the "
                    f"unconditional cheap tier"
                )
            continue
        got = classify([path]).phases()
        if required not in got:
            failures.append(
                f"corpus: {name}\n"
                f"  path {path} selected {' '.join(got) or '(nothing)'}\n"
                f"  but the phase that catches it, {required}, is not in that set"
            )

    for name, path in FULL_GATE_CORPUS:
        decision = classify([path])
        if not decision.run_all:
            failures.append(
                f"full-gate corpus: {name}\n"
                f"  path {path} did not select the full gate; it selected "
                f"{' '.join(decision.phases()) or '(nothing)'}"
            )

    # An empty diff is unknown, not empty.
    if not classify([]).run_all:
        failures.append("an empty path list must select the full gate")

    # One unclassified path in an otherwise docs-only diff still runs
    # everything. This is the property that makes the allowlist safe.
    mixed = classify(["docs/mcp.md", "vendor/thing.py"])
    if not mixed.run_all:
        failures.append("an unclassified path beside a classified one must select the full gate")

    # A docs-only diff must not select the Rust tier, or the whole
    # exercise is pointless.
    docs_only = classify(["docs/mcp.md", "docs/configuration.md"]).phases()
    for phase in ("BUILD", "TEST", "CLIPPY", "DOC", "PAYMENTS"):
        if phase in docs_only:
            failures.append(f"a docs-only diff must not select {phase}")
    if "DOCSCI" not in docs_only:
        failures.append("a docs-only diff must select DOCSCI")

    # Every phase this file names has to be one scripts/check.sh gates.
    for _, phases, _ in RULES:
        for phase in phases or []:
            if phase not in PHASES:
                failures.append(f"rule names unknown phase {phase}")

    if failures:
        print("gate-scope self-test FAILED\n", file=sys.stderr)
        for failure in failures:
            print(failure + "\n", file=sys.stderr)
        return 1

    print(
        f"gate-scope self-test passed "
        f"({len(CORPUS)} CI failures, {len(FULL_GATE_CORPUS)} full-gate shapes, "
        f"{len(RULES)} rules)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--paths-from")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if args.paths_from:
        stream = sys.stdin if args.paths_from == "-" else open(args.paths_from)
        paths = [line.strip() for line in stream if line.strip()]
    else:
        resolved = changed_paths(args.base)
        if resolved is None:
            decision = Decision()
            decision.run_all = True
            decision.all_reason = (
                f"the diff against {args.base} could not be computed "
                f"(no merge base, or not a git work tree)"
            )
            decision.note("(unknown)", "ALL", decision.all_reason)
            emit(decision, args)
            return 0
        paths = resolved

    emit(classify(paths), args)
    return 0


def emit(decision: Decision, args) -> None:
    if args.explain:
        print(f"Diff scope against {args.base}\n")
        width = max((len(row[0]) for row in decision.rows), default=4)
        width = min(width, 60)
        for path, phases, why in decision.rows:
            print(f"  {path:<{width}}  {phases:<28}  {why}")
        print()
        if decision.run_all:
            print(f"DECISION: run every phase. Reason: {decision.all_reason}")
        else:
            print(f"DECISION: run {' '.join(decision.phases()) or '(cheap tier only)'}")
            skipped = [p for p in PHASES if p not in decision.phases()]
            print(f"SKIPPED:  {' '.join(skipped) or '(none)'}")
        print(f"ALWAYS:   {ALWAYS}")
        return

    print(f"GATE_SCOPE_ALL={1 if decision.run_all else 0}")
    print(f"GATE_SCOPE_REASON={decision.all_reason or 'diff-scoped'}")
    selected = set(decision.phases())
    for phase in PHASES:
        print(f"GATE_PHASE_{phase}={1 if phase in selected else 0}")


if __name__ == "__main__":
    raise SystemExit(main())
