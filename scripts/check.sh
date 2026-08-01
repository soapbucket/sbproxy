#!/usr/bin/env bash
# Run the local pre-commit gate from CLAUDE.md.
#
# This runner mirrors the CI lanes in .github/workflows/ci.yml,
# docs-ci.yml, and doc-drift.yml. Where a command here differs from the
# CI command it replicates, that is a bug in this file and not a local
# convenience: every divergence has cost a CI round trip at some point.
#
# Phases run cheapest first. The grep, git, python, and shell phases at
# the top cost seconds each and catch the failures that were previously
# only discovered nine minutes into a CI run.
#
# The test step runs through cargo-nextest, which is what CI uses. A
# missing nextest is a hard error rather than a silent fallback: serial
# `cargo test` turns a few-minute lane into a ~90-minute one, and is
# always a misconfigured shell rather than an intended path. Install
# with:
#
#   cargo install cargo-nextest --locked
#
# Defaults match the required PR lane: non-e2e workspace tests in the dev
# profile, plus doctests.
#
# Environment:
#
#   SBPROXY_RELEASE_TESTS=1              run test binaries in release mode
#   SBPROXY_CHECK_E2E=1                  include the sbproxy-e2e package
#   SBPROXY_CLEAN_AFTER_BUILD=0          keep all build artifacts after the run
#   SBPROXY_ALLOW_DIRTY_TREE=1           do not fail on an uncommitted tree
#   SBPROXY_ALLOW_CARGO_TEST_FALLBACK=1  permit the serial cargo test fallback
#   SBPROXY_CHECK_PRIVATE_DOCS=1         extra rustdoc pass over private items
#                                        (stricter than CI; see that phase)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() {
  printf '\n\033[1;34m==>\033[0m %s\n' "$*"
}

# Phases that did not run are collected here and reprinted as a block at
# the very end. "All checks passed" must never be able to hide a lane
# that never executed.
SKIPPED=''

note_skip() {
  SKIPPED="${SKIPPED}  * $1"$'\n'
  printf '\n\033[1;33m!!! SKIPPED:\033[0m %s\n' "$1"
}

print_skip_summary() {
  printf '\n\033[1;33m========================================================\033[0m\n'
  if [ -z "$SKIPPED" ]; then
    printf '\033[1;32mSKIPPED PHASES: none. Every phase in this gate ran.\033[0m\n'
  else
    printf '\033[1;33mSKIPPED PHASES (these did NOT run):\033[0m\n'
    printf '%s' "$SKIPPED"
    printf '\033[1;33mCI runs every one of these. A skip here is a lane you\n'
    printf 'have not actually checked on this machine.\033[0m\n'
  fi
  printf '\033[1;33m========================================================\033[0m\n'
}

cleanup() {
  if [ "${SBPROXY_CLEAN_AFTER_BUILD:-1}" != "0" ]; then
    "$ROOT/scripts/cleanup-build-artifacts.sh"
  fi
}
trap cleanup EXIT

# --- Working-tree guard, part 1 of 2 -----------------------------------
#
# This gate validates the working tree. `git push` ships HEAD. When the
# two disagree, a green run says nothing about the commit CI will build:
# PR #837 pushed a broken commit behind a gate that had passed against
# an uncommitted fix sitting in the tree.
#
# The state is recorded here, before anything runs, and re-checked after
# the last phase, so a tree that was already dirty is distinguishable
# from one a generator inside this gate rewrote.
#
# `git status --porcelain` is scoped to the current worktree, so it
# behaves correctly under .worktrees/<name>; it reports untracked files;
# and it honours .gitignore. `--untracked-files=normal` is the default
# and is passed explicitly so a user-level `status.showUntrackedFiles=no`
# cannot quietly narrow the guard.
GIT_AVAILABLE=1
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  GIT_AVAILABLE=0
fi

dirty_tree_lines() {
  [ "$GIT_AVAILABLE" = "1" ] || return 0
  git status --porcelain=v1 --untracked-files=normal
}

was_dirty_at_start() {
  [ -n "${1:-}" ] || return 1
  [ -n "$DIRTY_AT_START" ] || return 1
  printf '%s\n' "$DIRTY_AT_START" | cut -c4- | grep -Fxq -- "$1"
}

DIRTY_AT_START="$(dirty_tree_lines)"

if [ "$GIT_AVAILABLE" != "1" ]; then
  note_skip "working-tree guard (not inside a git work tree, so the tree cannot be compared against HEAD)"
elif [ -n "$DIRTY_AT_START" ]; then
  step "working tree is already dirty before the gate starts"
  printf '%s\n' "$DIRTY_AT_START" | sed 's/^/  /'
  printf '\nRecorded so the final check can tell your uncommitted work apart\n'
  printf 'from files this gate rewrites. The gate validates the working\n'
  # shellcheck disable=SC2016  # the backticks are prose, not a subshell
  printf 'tree; `git push` ships HEAD. Commit before pushing.\n'
fi

# =======================================================================
# Phase 1: seconds each. No cargo, no compile.
# =======================================================================

# CI: ci.yml lint lane, "no internal tracker placeholders". A literal
# WOR-XXX is an unfinished TODO that announces incomplete work without
# making it trackable.
step "no internal tracker placeholders"
if grep -rn 'WOR-XXX' crates/ --include='*.rs' --include='*.toml'; then
  printf '\nWOR-XXX placeholders are not allowed in crates/.\n' >&2
  printf 'Open a real ticket and cite it by full URL, or rewrite the line\n' >&2
  printf 'as prose. Reproduce with:\n\n' >&2
  printf "  grep -rn 'WOR-XXX' crates/ --include='*.rs' --include='*.toml'\n" >&2
  exit 1
fi
printf 'no WOR-XXX placeholders under crates/\n'

# CI: docs-ci.yml, "llms-full.txt is left to CI". CI asks the API for
# the PR's file list because its checkout is shallow. Locally the same
# question is a diff against the MERGE BASE with origin/main. It has to
# be the merge base and not origin/main's tip: main regenerates this
# file on every merge, so diffing against the tip would fail every
# branch the moment main moved ahead.
step "docs/llms-full.txt is left to CI"
if [ "$GIT_AVAILABLE" != "1" ]; then
  note_skip "docs/llms-full.txt guard (not inside a git work tree)"
else
  LLMS_BASE="$(git merge-base HEAD origin/main 2>/dev/null || true)"
  if [ -z "$LLMS_BASE" ]; then
    note_skip "docs/llms-full.txt guard (no merge base with origin/main; run 'git fetch origin main' first)"
  elif git diff --quiet "$LLMS_BASE" -- docs/llms-full.txt; then
    printf 'docs/llms-full.txt is unchanged since the merge base with origin/main\n'
  else
    printf '\nThis branch changes docs/llms-full.txt, which CI now owns.\n' >&2
    printf '\nllms-full-refresh.yml regenerates it on main after the merge, so a\n' >&2
    printf 'branch that carries it fails the docs lane and conflicts with every\n' >&2
    printf 'other doc branch on a 2 MB generated file. Drop it:\n\n' >&2
    printf '  git checkout origin/main -- docs/llms-full.txt\n' >&2
    printf "  git commit -m 'chore: drop generated llms-full.txt from the branch'\n\n" >&2
    printf 'Edit the source docs/*.md instead; never the corpus.\n' >&2
    exit 1
  fi
fi

# CI: ci.yml test lane, "no new pub items whose only consumer is a test".
# Pure python, a few seconds, and the highest value per second in this
# file: dead_code cannot see a pub item inside a pub mod, so write-only
# code otherwise lands with a green build.
step "pub items whose only consumer is a test (ratchet)"
bash "$ROOT/scripts/check-pub-item-ratchet.sh"

# CI: docs-ci.yml, "spec citation hygiene".
step "spec citation hygiene"
bash "$ROOT/scripts/check-spec-citations.sh"

# CI: ci.yml lint lane, "no process-global env mutation outside test
# helpers" (WOR-646). Pure grep. Production code must not call
# std::env::set_var / remove_var; tests go through the per-crate
# EnvVarGuard in src/test_env.rs.
step "no process-global env mutation outside test helpers"
bash "$ROOT/scripts/check-env-mutation.sh"

# CI: doc-drift.yml. Guards the provider-count, routing-strategy, and
# unimplemented-feature claims in user-facing docs.
step "doc drift"
bash "$ROOT/scripts/check-doc-drift.sh"

# CI: docs-ci.yml, "generated tapes and GIF wiring are current", which
# is `make tapes-check`. That target is three commands, the last of
# which is the whole scripts.tests.test_doc_generators module. This gate
# used to run a single class out of that module, so five of the six test
# classes had no local equivalent at all. Invoked through make so the
# Makefile stays the one definition of what the check is.
step "generated tapes and GIF wiring are current"
if ! command -v make >/dev/null 2>&1; then
  printf 'make not found on PATH; install it (Xcode Command Line Tools on\n' >&2
  printf 'macOS) to run the tapes check. CI requires this lane, so it cannot\n' >&2
  # shellcheck disable=SC2016  # the backticks are prose, not a subshell
  printf 'be skipped here. The target is `make tapes-check`.\n' >&2
  exit 1
fi
make tapes-check

# CI: docs-ci.yml, "documentation configs match canonical examples".
# The `every_oss_example_compiles` half of that CI step is covered by
# the workspace test lane below; do not add a `-p sbproxy-config`
# invocation here, because a narrow package selection resolves a
# different feature union than CI and reports failures CI never sees.
step "documentation configs match canonical examples"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/sync-doc-configs.py" --check

# Not a CI lane, because there isn't one. examples/README.md is generated
# by gen-examples-catalog.py, which has supported --check since it was
# written, and nothing has ever called it: not CI, not this gate, not the
# Makefile. It had silently drifted by two rows on main. A generated file
# with a drift checker nobody invokes is the same failure as having no
# checker at all.
step "examples catalog is current"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/gen-examples-catalog.py" --check

# CI: ci.yml test lane. No network, no cargo.
step "install.sh verifies its download"
sh "$ROOT/scripts/tests/install_verify.sh"

# CI: ci.yml test lane installs promtool and runs this. promtool is not
# always installed locally; the metric-name and label drift is already
# gated by the Rust test crates/sbproxy-observe/tests/metric_drift.rs,
# which runs in the test lane below. When promtool is present, also
# check PromQL semantics.
if command -v promtool >/dev/null 2>&1; then
  step "prometheus rules validate and the SLO burns"
  bash "$ROOT/scripts/check-prometheus-rules.sh"
else
  note_skip "prometheus rules PromQL semantics (promtool not on PATH; metric-name drift is still gated in Rust). Install prometheus to enable it."
fi

# =======================================================================
# Phase 2: seconds to about a minute. Resolves or type-checks, but does
# not compile the workspace.
# =======================================================================

step "cargo fmt --check"
cargo fmt --all -- --check

# CI: ci.yml lint lane. The bench harnesses and the config-source
# fixture are their own workspaces that path-depend on this one, so a
# dependency added here leaves their lockfiles stale. No cargo step in
# this gate opens them, which is why that drift used to reach CI
# untouched.
step "standalone workspace lockfiles are current"
bash "$ROOT/scripts/check-nested-lockfiles.sh"

# CI: ci.yml supply-chain lane, EmbarkStudios/cargo-deny-action with
# command `check` and arguments `--all-features`, which composes to
# `cargo deny --all-features check` against deny.toml. This resolves the
# dependency graph and reads advisory data; it does not compile the
# workspace. Conditional because cargo-deny is not part of a default
# Rust install, and a missing tool must not be reported as a policy
# violation.
if command -v cargo-deny >/dev/null 2>&1; then
  step "supply chain (cargo-deny)"
  cargo deny --all-features check
else
  note_skip "supply chain (cargo-deny not on PATH; advisories, bans, licenses, and sources are unchecked locally). Install with 'cargo install cargo-deny --locked'."
fi

# CI: ci.yml ui lane.
step "ui typecheck and test"
if ! command -v npm >/dev/null 2>&1; then
  printf 'npm not found on PATH; install Node.js (https://nodejs.org) to run the UI gate. This step is required by CI, so it cannot be skipped here.\n' >&2
  exit 1
fi
# npm writes node_modules/.package-lock.json reflecting the exact lockfile
# it last installed from; reuse an install that already matches the
# current lockfile instead of running `npm ci` (which deletes and
# reinstalls node_modules) on every gate run.
if [ ! -f ui/node_modules/.package-lock.json ] || [ ui/package-lock.json -nt ui/node_modules/.package-lock.json ]; then
  (cd ui && npm ci)
fi
(cd ui && npm run typecheck && npm run test -- --run)

# =======================================================================
# Phase 3: minutes. Compiles the workspace.
# =======================================================================

# One package selection for every cargo invocation below, which is the
# invariant ci.yml holds: under resolver = "2" the feature union is
# computed from the selected packages, so a different selection silently
# recompiles the graph.
test_package_args=(--workspace --locked)
if [ "${SBPROXY_CHECK_E2E:-0}" != "1" ]; then
  test_package_args+=(--exclude sbproxy-e2e)
fi

nextest_args=("${test_package_args[@]}" --profile ci)
cargo_test_args=("${test_package_args[@]}")
if [ "${SBPROXY_RELEASE_TESTS:-0}" = "1" ]; then
  nextest_args+=(--release --tests)
  cargo_test_args+=(--release --tests)
fi

# CI: `cargo build --workspace --exclude sbproxy-e2e --locked`.
#
# `--locked` is load bearing. Without it this build SILENTLY REWRITES
# the root Cargo.lock in place, and the `--locked` test step that
# follows then passes against the file this step just regenerated. Local
# lockfile drift was auto-repaired rather than reported, and with no
# working-tree guard nobody was ever told.
step "cargo build"
cargo build "${test_package_args[@]}"

step "cargo test"
if cargo nextest --version >/dev/null 2>&1; then
  cargo nextest run "${nextest_args[@]}"
elif [ "${SBPROXY_ALLOW_CARGO_TEST_FALLBACK:-0}" = "1" ]; then
  note_skip "nextest test lane (SBPROXY_ALLOW_CARGO_TEST_FALLBACK=1 ran serial 'cargo test' instead; this is not the lane CI runs)"
  cargo test "${cargo_test_args[@]}"
else
  cat >&2 <<'MSG'

cargo-nextest is not on PATH, and CI always runs the test lane through it.

Falling back to serial `cargo test` turns a few-minute lane into a
~90-minute one, so this is a hard error rather than a silent
substitution. It is a misconfigured shell essentially every time:
nextest is normally already installed at ~/.cargo/bin/cargo-nextest.

  export PATH="$HOME/.cargo/bin:$PATH"     # usual fix
  cargo install cargo-nextest --locked     # if it is genuinely absent

To take the slow path on purpose, re-run with
SBPROXY_ALLOW_CARGO_TEST_FALLBACK=1.
MSG
  exit 1
fi

# nextest does not execute doctests, so they need their own pass.
step "cargo doctest"
cargo test "${test_package_args[@]}" --doc

step "cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings

# CI: `RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc --workspace
# --no-deps --locked`. Matched exactly. `-D missing_docs` exists in
# exactly one other place in this repository, ci.yml, and it is the flag
# that bites.
#
# Note what is deliberately absent: `--document-private-items`. Combined
# with `-D missing_docs` it demands rustdoc on private items too, which
# is strictly stricter than CI and produces failures CI will never
# report. The private-items pass is available below, on its own, behind
# an env var.
step "cargo doc"
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc --workspace --no-deps --locked

if [ "${SBPROXY_CHECK_PRIVATE_DOCS:-0}" = "1" ]; then
  # Not a CI lane. Broken intra-doc links in private modules are real
  # bugs, so the pass has value, but it is opt-in and carries only
  # `-D warnings` so it cannot manufacture missing_docs failures on
  # private items that CI does not care about.
  step "cargo doc (private items, opt-in, NOT a CI lane)"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --document-private-items
fi

# CI: ci.yml test lane, "generated artifacts are current". These exec
# the binaries the build above produced.
step "config schema and reader coverage"
bash "$ROOT/scripts/check-config-schema.sh"
bash "$ROOT/scripts/check-config-readers.sh"

step "generated docs are current"
bash "$ROOT/scripts/check-metrics-stability.sh"
bash "$ROOT/scripts/check-model-host-capabilities.sh"

# =======================================================================
# Phase 4: what will actually be pushed.
# =======================================================================

# --- Working-tree guard, part 2 of 2 -----------------------------------
#
# Runs last, after every generator has had its chance to rewrite a file.
TREE_GUARD_FAILED=0

check_clean_tree() {
  local now line path preexisting created
  [ "$GIT_AVAILABLE" = "1" ] || return 0

  now="$(dirty_tree_lines)"
  if [ -z "$now" ]; then
    printf 'working tree is clean; HEAD is exactly the tree this gate validated\n'
    return 0
  fi

  preexisting=''
  created=''
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    path="${line:3}"
    if was_dirty_at_start "$path"; then
      preexisting="${preexisting}    ${line}"$'\n'
    else
      created="${created}    ${line}"$'\n'
    fi
  done <<<"$now"

  printf '\n'
  # shellcheck disable=SC2016  # the backticks are prose, not a subshell
  printf 'The gate validated the working tree; `git push` ships HEAD.\n'
  printf 'Those are different trees right now, so a green run here does not\n'
  printf 'describe the commit CI will build. This is how PR #837 shipped a\n'
  printf 'broken commit behind a gate that had passed.\n\n'

  if [ -n "$created" ]; then
    printf '  Rewritten during this run (a generator or formatter produced\n'
    printf '  these, so the committed copies were stale):\n'
    printf '%s' "$created"
    printf '\n'
  fi
  if [ -n "$preexisting" ]; then
    printf '  Already dirty before the gate started (uncommitted work):\n'
    printf '%s' "$preexisting"
    printf '\n'
  fi

  if [ "${SBPROXY_ALLOW_DIRTY_TREE:-0}" = "1" ]; then
    note_skip "working-tree guard (SBPROXY_ALLOW_DIRTY_TREE=1 was set, so the dirty tree above did not fail this run; the commit you push is NOT the tree that was validated)"
    return 0
  fi

  printf '  Fix it one of two ways:\n\n'
  printf '    git add -A && git commit ...\n'
  printf '      then re-run scripts/check.sh so the gate validates the tree\n'
  printf '      you are about to push.\n\n'
  printf '    SBPROXY_ALLOW_DIRTY_TREE=1 bash scripts/check.sh\n'
  printf '      for a deliberate work-in-progress run. The result then says\n'
  printf '      nothing about what CI will build.\n'
  TREE_GUARD_FAILED=1
  return 0
}

step "working tree matches HEAD"
check_clean_tree

print_skip_summary

if [ "$TREE_GUARD_FAILED" = "1" ]; then
  printf '\n\033[1;31mFAILED: the working tree is dirty (see above).\033[0m\n' >&2
  exit 1
fi

printf '\n\033[1;32mAll checks passed.\033[0m\n'
