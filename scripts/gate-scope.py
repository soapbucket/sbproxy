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
invocation that fails.

Narrowing this file is how a gate stops gating, so `--self-test` does not
take the corpus on trust. It weakens every rule in the table, one at a
time, and requires the corpus to notice; a rule no row depends on is a
failure in itself. It also walks every path git tracks and reports any rule
that a broader rule above it silently claims, which is where both of this
file's real under-selections came from. A corpus that only looks thorough
is what let `*.md` take 248 example READMEs away from `examples/*` while
the self-test stayed green.

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
import re
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

# --- The rule shape ----------------------------------------------------


class Rule:
    """One line of the allowlist.

    `glob` is matched against a repository-relative POSIX path with fnmatch,
    where `*` crosses directory separators. `phases` is None for "run
    everything", a list of phase names, or an empty list for "the cheap tier
    is enough".

    `narrows` is the part that has to be written down. Because `*` crosses
    separators, an earlier rule can claim paths a later, broader rule also
    matches, and if the earlier rule selects less, that is an under-selection
    the ordering check would otherwise have to guess about. A rule that
    deliberately selects less than something below it lists those globs here,
    with the reason in `why`. An undeclared narrowing is a self-test failure.
    """

    __slots__ = ("glob", "phases", "why", "narrows")

    def __init__(self, glob, phases, why, narrows=()):
        self.glob = glob
        self.phases = phases
        self.why = why
        self.narrows = narrows

    def weakened(self):
        """This rule, made to select less. None when it cannot be weakened.

        Weakening is what the mutation harness applies. A rule that selects
        something (or everything) is weakened to selecting nothing. A rule
        that already selects nothing can only be weakened by no longer
        claiming its paths at all, which is expressed by returning None and
        deleting it.
        """
        if self.phases == []:
            return None
        return Rule(self.glob, [], self.why, self.narrows)


# --- The allowlist -----------------------------------------------------
#
# Ordered. The first matching rule wins, so put the specific patterns
# above the general ones. Each entry is (glob, phases, why).
#
# `glob` is matched against a repository-relative POSIX path with
# fnmatch, where `*` crosses directory separators. That is deliberate:
# a pattern that under-matches sends a path to ALL, which is safe, while
# a pattern that over-matches would skip a phase, which is not.

RULES: list[Rule] = [
    # ---- Things that redefine the gate itself. These run everything,
    # because the gate is checking its own change.
    Rule("scripts/*", None, "the gate is checking a change to itself"),
    Rule(".config/nextest.toml", None, "the test runner's own configuration"),
    Rule("Makefile", None, "the gate calls make targets"),
    Rule("rust-toolchain.toml", None, "the compiler version changes every lane"),
    Rule(".cargo/*", None, "cargo configuration changes every lane"),
    # ---- The config crate feeds the generated schema, the reader coverage
    # guard, and sync-doc-configs. Above the manifest rules on purpose: its
    # own Cargo.toml would otherwise match `*/Cargo.toml` first and lose
    # DOCSCI, which is the ordering class Blocker 2 came from.
    Rule(
        "crates/sbproxy-config/*",
        RUST + ["DOCSCI"],
        "config types feed the generated schema, HOST_FILE_KEYS, and the doc configs",
    ),
    # ---- Rust inside an example is both things at once. It compiles like
    # any other crate and it is part of the corpus the tape and catalog
    # generators read, so it takes the Rust tier plus the example tier.
    # Above the manifest rules and above `*.rs`, both of which would
    # otherwise claim it and drop TAPES. This is the same ordering class as
    # Blocker 2, found by the ordering check below rather than by reading.
    Rule(
        "examples/*.rs",
        RUST + ["TAPES", "DOCSCI"],
        "an example's own Rust source: the Rust tier plus the example corpus",
    ),
    Rule(
        "examples/*Cargo.toml",
        RUST + ["TAPES", "DOCSCI"],
        "an example crate's manifest: the Rust tier plus the example corpus",
    ),
    # ---- Manifests and lockfiles. A dependency change moves the feature
    # union, the NOTICE stanzas, the advisory surface, and the standalone
    # workspaces that path-depend on this one.
    #
    # There is no `*/build.rs` rule. It would be redundant with `*.rs`, which
    # already selects the whole Rust tier, and a redundant rule cannot be
    # mutation-tested: gutting it changes no answer. Redundant rules are
    # deleted here rather than kept as decoration.
    Rule("Cargo.lock", RUST, "the dependency graph moved; NOTICE, cargo-deny, and the nested-lockfile guard are unconditional"),
    Rule("*/Cargo.lock", RUST, "a standalone workspace lockfile moved"),
    Rule("Cargo.toml", RUST, "the workspace manifest moved"),
    Rule("*/Cargo.toml", RUST, "a crate manifest moved"),
    Rule("deny.toml", [], "cargo-deny is in the cheap tier, which always runs"),
    # ---- Committed generator output. A hand edit to any of these is caught
    # in exactly one place, the GENERATED phase, which execs the built
    # binary that produces them. Prose rules must not claim them: that was
    # Blocker 1, and the flow this repository documents (regenerate after a
    # merge, then gate) walks straight into it.
    Rule(
        "schemas/*",
        ["GENERATED"],
        "the committed schema is the check's input; docs-ci reads only docs/, "
        "so schemas/README.md cannot reach it",
        narrows=("*.md",),
    ),
    Rule(
        "docs/metrics-stability.md",
        DOCS + ["GENERATED"],
        "generator output: generate-metrics-stability, checked only by check-metrics-stability.sh",
    ),
    Rule(
        "docs/decision-records.md",
        DOCS + ["GENERATED"],
        "generator output: generate-decision-contract, checked only by check-decision-contract.sh",
    ),
    Rule(
        "docs/model-host-capabilities.md",
        DOCS + ["GENERATED"],
        "generator output: generate-model-host-capabilities, checked only by check-model-host-capabilities.sh",
    ),
    # ---- Rust. The whole tier, every time. See the module docstring for
    # why there is no reverse-dependency walk.
    Rule("*.rs", RUST, "Rust source: the gate's cargo phases are all --workspace"),
    # ---- The admin SPA. Its build output is embedded by admin_ui.rs, so
    # a UI change also has to rebuild and re-test the binary that carries
    # it.
    Rule(
        "ui/*",
        ["UI", "BUILD", "TEST"],
        "the admin SPA and the crate that embeds it",
        narrows=("*.md",),
    ),
    # ---- Examples, above `*.md`. There are 248 examples/<name>/README.md
    # in this tree and `*.md` claimed every one of them, dropping TAPES,
    # which is the only phase that runs wire-example-gifs.py --check over
    # them. That was Blocker 2.
    Rule(
        "examples/*",
        ["TAPES", "DOCSCI", "TEST"],
        "the tape corpus, the GIF wiring, and the test that compiles every OSS example",
    ),
    # ---- Changelog fragments, above the docs rules that would otherwise
    # claim them. Parsed by changelog-fragments.py in the cheap tier.
    Rule(
        "docs/.changes/*",
        [],
        "changelog fragments are parsed in the cheap tier",
        narrows=("docs/*", "*.md"),
    ),
    # ---- Documentation. docs-ci compiles the `rust` blocks and resolves
    # anchors; the capture and config drift scans read the same tree.
    # docs/tapes/*, docs/assets/*, and docs/*.md were all separate rules
    # selecting exactly this set, so they were redundant and are gone.
    Rule("docs/*", DOCS, "the documentation tree: prose, code blocks, anchors, tapes, and assets"),
    Rule("*.md", ["DOCSCI"], "prose that another page may link into"),
    # ---- Dashboards feed the metric-visibility ratchet, which lives in
    # the cheap tier and therefore always runs. docs-ci reads only docs/,
    # so a README out here cannot reach it.
    Rule("dashboards/*", [], "metric visibility is in the cheap tier, which always runs", narrows=("*.md",)),
    Rule("deploy/*", [], "the prometheus rule check is in the cheap tier, which always runs", narrows=("*.md",)),
    # ---- Metadata that no phase compiles or renders.
    Rule("NOTICE", [], "the NOTICE guard is in the cheap tier, which always runs"),
    Rule("LICENSE", [], "no phase reads it"),
    Rule("CODEOWNERS", [], "no phase reads it"),
    Rule(".gitignore", [], "no phase reads it"),
    Rule(".lycheeignore", ["DOCSCI"], "the link checker's own ignore list"),
    Rule(".github/*", [], "CI definitions are not executed by the local gate"),
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


def classify(paths, rules: list[Rule] | None = None) -> Decision:
    """Map changed paths to gate phases. Unmatched paths select everything.

    `rules` defaults to the table above. The mutation harness passes a
    modified table, which is the only reason this is a parameter.
    """
    rules = RULES if rules is None else rules
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
        for rule in rules:
            if not fnmatch.fnmatchcase(path, rule.glob):
                continue
            matched = True
            glob, phases, why = rule.glob, rule.phases, rule.why
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


# --- The corpus ---------------------------------------------------------
#
# Three tables, and the reason there are three is that a rule can be broken
# in three different directions.
#
#   SELECTS  a path that must select a named phase. Catches a rule that
#            stops selecting enough.
#   CHEAP    a path that must select nothing skippable. Catches a rule that
#            stops claiming its paths at all, which sends them to ALL.
#   FULL     a path that must select every phase.
#
# Every row names a real path in this repository or a real failure that
# reached CI. What makes the set trustworthy is not that it looks thorough,
# it is `mutation_failures()` below: every rule in the table is weakened,
# one at a time, and a weakening that no row notices is a self-test failure.
# Before that harness existed, 28 of 31 rules could be gutted with the
# self-test staying green, and both of this branch's under-selections lived
# in that unasserted set.

SELECTS: list[tuple[str, str, str]] = [
    # (what it catches, path, the phase that catches it)
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
        "a new path-shaped config key missing from HOST_FILE_KEYS",
        "crates/sbproxy-config/src/confined_template.rs",
        "TEST",
    ),
    (
        "a new path-shaped config key whose schema was never regenerated",
        "crates/sbproxy-config/src/types.rs",
        "GENERATED",
    ),
    (
        "a config type change that moves a documented config block",
        "crates/sbproxy-config/src/types.rs",
        # The rule under test is crates/sbproxy-config/*. Assert DOCSCI
        # rather than a Rust phase: *.rs below would supply every Rust
        # phase on its own, so a Rust assertion here would survive gutting
        # the config rule and prove nothing.
        "DOCSCI",
    ),
    (
        "a hand edit to the generated metrics stability table",
        "docs/metrics-stability.md",
        "GENERATED",
    ),
    (
        "a hand edit to the generated decision contract",
        "docs/decision-records.md",
        "GENERATED",
    ),
    (
        "a hand edit to the generated model-host capability matrix",
        "docs/model-host-capabilities.md",
        "GENERATED",
    ),
    (
        "a committed schema edited by hand instead of regenerated",
        "schemas/sb-config.schema.json",
        "GENERATED",
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
        "a doc edit that stales the tape corpus",
        # The rule under test is docs/*. DOCSCI alone would survive gutting
        # it, because *.md supplies DOCSCI; TAPES is what only docs/* gives.
        "docs/mcp.md",
        "TAPES",
    ),
    (
        "a root or nested markdown file another page links into",
        "README.md",
        "DOCSCI",
    ),
    (
        "an example README whose GIF wiring was hand-edited away",
        # Blocker 2. *.md claimed all 248 of these and dropped TAPES, which
        # is the only phase that runs wire-example-gifs.py --check.
        "examples/ai-budget/README.md",
        "TAPES",
    ),
    (
        "a new example that leaves examples/README.md stale",
        # Live failure: main's guards lane went red on 49145cbd with
        # "253 examples; catalog is STALE", because two pull requests each
        # regenerated the catalog against their own base.
        "examples/ai-budget/config.toml",
        "TAPES",
    ),
    (
        "an example's own Rust source, which is both a crate and corpus",
        "examples/wasm/echo-rust/src/main.rs",
        "TAPES",
    ),
    (
        "an example crate's manifest, which is both a manifest and corpus",
        "examples/wasm/echo-rust/Cargo.toml",
        "TAPES",
    ),
    (
        "an admin SPA change that the embedding crate has to rebuild for",
        "ui/src/main.tsx",
        "UI",
    ),
    (
        "a dependency change that moves the feature union",
        "Cargo.lock",
        "BUILD",
    ),
    (
        "a standalone workspace lockfile change",
        "bench-synthetic/Cargo.lock",
        "BUILD",
    ),
    (
        "a workspace manifest change",
        "Cargo.toml",
        "BUILD",
    ),
    (
        "a crate manifest change",
        "crates/sbproxy-core/Cargo.toml",
        "BUILD",
    ),
    (
        "an edit to the link checker's own ignore list",
        ".lycheeignore",
        "DOCSCI",
    ),
]

# Paths whose whole point is that the cheap tier is enough for them. A rule
# that stops claiming one of these sends it to ALL, which these rows catch.
CHEAP: list[tuple[str, str]] = [
    ("a cargo-deny policy change", "deny.toml"),
    ("a Grafana dashboard change", "dashboards/grafana/sbproxy-ai-gateway.json"),
    ("a deployment manifest change", "deploy/prometheus/rules.yml"),
    ("a NOTICE stanza", "NOTICE"),
    ("the license", "LICENSE"),
    ("the code owners file", "CODEOWNERS"),
    ("the ignore file", ".gitignore"),
    ("a changelog fragment", "docs/.changes/20260828-fix-something.md"),
    ("a CI workflow definition", ".github/workflows/ci.yml"),
]

# Shapes that must never narrow to less than the full gate.
FULL_GATE: list[tuple[str, str]] = [
    ("a change to the gate itself", "scripts/check.sh"),
    ("a change to the test runner config", ".config/nextest.toml"),
    ("a change to the Makefile the gate calls", "Makefile"),
    ("a change to cargo's own configuration", ".cargo/config.toml"),
    ("the toolchain pin", "rust-toolchain.toml"),
    ("a path no rule has ever seen", "some/brand/new/tree/thing.bin"),
    ("a new top-level directory", "terraform/main.tf"),
]

# Checks that live in the cheap tier and must stay there. Each row is a
# token that has to appear in scripts/check.sh. The old version of this
# table asserted `"@always" in PHASES`, a constant False that could not
# fail; what actually protects these is the pair of assertions in
# `unconditional_failures()`: the token is still called, and check.sh gates
# nothing this file has not heard of.
UNCONDITIONAL: list[tuple[str, str]] = [
    ("stale examples/README.md catalog after a merge from main", "batch_examples_catalog"),
    ("missing NOTICE stanza after a lockfile change", "batch_notice_coverage"),
    ("a stale secret-resolver-drift-exemptions.json entry", "batch_secret_resolver_drift"),
    ("stale nested lockfiles", "batch_nested_lockfiles"),
]


def repo_root():
    return __import__("pathlib").Path(__file__).resolve().parent.parent


def corpus_failures(rules: list[Rule]) -> list[str]:
    """Every rule-dependent assertion, against one rules table.

    This is the function the mutation harness re-runs. It must contain
    nothing that a change to the table cannot affect, or a mutation would
    look caught when it was not.
    """
    failures: list[str] = []

    for name, path, required in SELECTS:
        decision = classify([path], rules)
        if required not in decision.phases():
            failures.append(
                f"selects: {name}\n"
                f"  path {path} selected {' '.join(decision.phases()) or '(nothing)'}\n"
                f"  but the phase that catches it, {required}, is not in that set"
            )

    for name, path in CHEAP:
        decision = classify([path], rules)
        if decision.run_all or decision.phases():
            failures.append(
                f"cheap: {name}\n"
                f"  path {path} selected "
                f"{'ALL' if decision.run_all else ' '.join(decision.phases())}\n"
                f"  but the cheap tier is what checks it, so it must select nothing"
            )

    for name, path in FULL_GATE:
        decision = classify([path], rules)
        if not decision.run_all:
            failures.append(
                f"full gate: {name}\n"
                f"  path {path} did not select the full gate; it selected "
                f"{' '.join(decision.phases()) or '(nothing)'}"
            )

    # An empty diff is unknown, not empty.
    if not classify([], rules).run_all:
        failures.append("an empty path list must select the full gate")

    # One unclassified path in an otherwise docs-only diff still runs
    # everything. This is the property that makes the allowlist safe.
    if not classify(["docs/mcp.md", "vendor/thing.py"], rules).run_all:
        failures.append(
            "an unclassified path beside a classified one must select the full gate"
        )

    # A docs-only diff must not select the Rust tier, or the whole exercise
    # is pointless.
    docs_only = classify(["docs/mcp.md", "docs/configuration.md"], rules).phases()
    for phase in ("BUILD", "TEST", "CLIPPY", "DOC", "PAYMENTS"):
        if phase in docs_only:
            failures.append(f"a docs-only diff must not select {phase}")

    return failures


def mutation_failures() -> list[str]:
    """Weaken each rule in turn and require the corpus to notice.

    This is the property the whole scoped gate rests on. Every rule is
    load-bearing for at least one corpus row, so a rule that is narrowed,
    gutted, or deleted turns this self-test red instead of quietly turning a
    phase off on somebody else's branch.
    """
    failures: list[str] = []
    for index, rule in enumerate(RULES):
        weaker = rule.weakened()
        if weaker is None:
            # Already selects nothing. The only weakening left is to stop
            # claiming these paths, which sends them to ALL.
            mutated = RULES[:index] + RULES[index + 1 :]
            how = "deleted"
        else:
            mutated = RULES[:index] + [weaker] + RULES[index + 1 :]
            how = "weakened to select nothing"
        if not corpus_failures(mutated):
            failures.append(
                f"mutation: rule {index} ({rule.glob!r}) {how} and the corpus "
                f"stayed green.\n"
                f"  No row asserts anything this rule alone provides, so nobody "
                f"would notice it being narrowed.\n"
                f"  Add a row to SELECTS, CHEAP, or FULL_GATE that fails without it."
            )
    return failures


def tracked_paths() -> tuple[list[str], str | None]:
    """Every path git tracks, or a reason it could not be read.

    The ordering check below is only as good as the paths it runs over, so
    it runs over the real ones. Failing to enumerate them is a self-test
    failure rather than a silent skip: a check that degrades quietly is the
    defect this whole round is about.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root()), "ls-files"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        return [], f"git could not be run ({error})"
    if out.returncode != 0:
        return [], f"git ls-files exited {out.returncode}"
    paths = [line for line in out.stdout.splitlines() if line]
    if not paths:
        return [], "git ls-files listed nothing"
    return paths, None


def ordering_failures(paths: list[str]) -> list[str]:
    """Find rules that a broader rule above them silently claims.

    `*` crosses directory separators here, so a general glob placed above a
    specific one takes its paths. When the general one selects LESS, the
    specific rule's phases are lost for every path in the overlap and
    nothing says so. That is the class both Blockers came from: `*.md` above
    `examples/*` cost 248 example READMEs their TAPES phase.

    A rule is allowed to select less than something below it only if it says
    so in `narrows`. Everything else is reported with the concrete path.
    """
    failures: list[str] = []
    seen: set[tuple[str, str]] = set()
    for path in paths:
        matches = [rule for rule in RULES if fnmatch.fnmatchcase(path, rule.glob)]
        if len(matches) < 2:
            continue
        first = matches[0]
        if first.phases is None:
            continue  # ALL covers everything below it
        for later in matches[1:]:
            if later.glob in first.narrows:
                continue
            if later.phases is None:
                missing = {"(the full gate)"}
            else:
                missing = set(later.phases) - set(first.phases)
            if not missing:
                continue
            key = (first.glob, later.glob)
            if key in seen:
                continue
            seen.add(key)
            failures.append(
                f"ordering: {first.glob!r} sits above {later.glob!r} and selects less.\n"
                f"  {path} matches both. It gets {first.glob!r}, losing "
                f"{' '.join(sorted(missing))}.\n"
                f"  Move the specific rule above the general one, or declare the\n"
                f"  narrowing with narrows=({later.glob!r},) and say why."
            )
    return failures


def unconditional_failures() -> list[str]:
    """The cheap tier is still the cheap tier.

    Two assertions, and neither can be a constant. First, every check named
    in UNCONDITIONAL is still called in scripts/check.sh. Second, the set of
    phase names check.sh actually gates equals the vocabulary in this file,
    so a new `phase_wanted SOMETHING` over there cannot appear without this
    self-test going red. That is the scenario the old @always rows claimed
    to cover and did not: move batch_examples_catalog behind a new phase and
    the old test stayed green.
    """
    failures: list[str] = []
    check_sh = repo_root() / "scripts" / "check.sh"
    try:
        text = check_sh.read_text()
    except OSError as error:
        return [f"unconditional: could not read {check_sh} ({error})"]

    for name, token in UNCONDITIONAL:
        if token not in text:
            failures.append(
                f"unconditional: {name}\n"
                f"  scripts/check.sh no longer calls {token}, so the check that "
                f"catches it is gone or renamed"
            )

    gated = set(re.findall(r"phase_wanted\s+([A-Z][A-Z0-9_]*)", text))
    unknown = gated - set(PHASES)
    missing = set(PHASES) - gated
    if unknown:
        failures.append(
            "unconditional: scripts/check.sh gates phases this file has never "
            f"heard of: {' '.join(sorted(unknown))}.\n"
            "  A phase added over there without a rule here can turn a check off "
            "for a diff shape nobody classified."
        )
    if missing:
        failures.append(
            "unconditional: this file names phases scripts/check.sh does not "
            f"gate: {' '.join(sorted(missing))}.\n"
            "  Either the phase was removed over there, or the guard was dropped "
            "and the phase now always runs while this file claims it is skippable."
        )
    return failures


def self_test() -> int:
    failures: list[str] = corpus_failures(RULES)
    failures += mutation_failures()
    failures += unconditional_failures()

    paths, why = tracked_paths()
    if why:
        failures.append(
            f"ordering: the repository's tracked paths could not be read ({why}).\n"
            "  This check runs over the real tree on purpose; it does not have a "
            "reduced mode."
        )
    else:
        failures += ordering_failures(paths)

    # Every phase this file names has to be one scripts/check.sh gates. The
    # loop below is the local half; unconditional_failures() is the half
    # that reads check.sh.
    for rule in RULES:
        for phase in rule.phases or []:
            if phase not in PHASES:
                failures.append(f"rule {rule.glob!r} names unknown phase {phase}")

    if failures:
        print("gate-scope self-test FAILED\n", file=sys.stderr)
        for failure in failures:
            print(failure + "\n", file=sys.stderr)
        return 1

    print(
        f"gate-scope self-test passed: {len(RULES)} rules, all "
        f"{len(RULES)} mutation-proof; "
        f"{len(SELECTS)} phase, {len(CHEAP)} cheap-tier, {len(FULL_GATE)} full-gate "
        f"rows; {len(UNCONDITIONAL)} unconditional checks; ordering checked over "
        f"{len(paths)} tracked paths"
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
