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
#   SBPROXY_CHECK_E2E=1                  include the sbproxy-e2e package.
#                                        Test files needing a proxy binary
#                                        flavor this gate does not build are
#                                        skipped with the build command that
#                                        would enable them (WOR-2291).
#   SBPROXY_CHECK_PAYMENTS=0             skip the settlement feature union.
#                                        It runs by DEFAULT: it is a required
#                                        CI lane and the only place
#                                        clippy::items_after_test_module and
#                                        the feature-gated half of
#                                        sbproxy-billing are compiled at all.
#                                        Setting this to 0 is a deliberate
#                                        choice and is reprinted in the
#                                        SKIPPED PHASES block.
#   SBPROXY_CLEAN_AFTER_BUILD=0          keep all build artifacts after the run
#   SBPROXY_ALLOW_DIRTY_TREE=1           do not fail on an uncommitted tree
#   SBPROXY_ALLOW_CARGO_TEST_FALLBACK=1  permit the serial cargo test fallback
#   SBPROXY_CHECK_PRIVATE_DOCS=1         extra rustdoc pass over private items
#                                        (stricter than CI; see that phase)
#   SBPROXY_SKIP_CARGO=1                 dev-only: stop before the first
#                                        cargo compile phase so the script
#                                        phases can be exercised end to end
#                                        on their own. A run with this set
#                                        is not a gate result; the skipped
#                                        lanes are reprinted in the SKIPPED
#                                        PHASES block.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Wall clock for the GATE_EXIT line the cleanup trap prints.
GATE_STARTED="$(date +%s)"

# --- Diff scoping -------------------------------------------------------
#
# `--scope-to-diff [<base>]` runs only the phases the diff can reach.
# `--explain` prints that decision, per changed path, and runs nothing.
#
# The classifier is scripts/gate-scope.py and the rule it holds is the
# only one that makes this safe: AN UNRECOGNIZED PATH RUNS EVERYTHING.
# A path matching no rule, an empty diff, a missing merge base, and a
# failed git call all resolve to the full gate. Read that file before
# changing anything here.
#
# Two properties keep the blast radius small. First, only phases costing
# more than about ten seconds are skippable at all; the fourteen
# read-only scans, fmt, the lockfile guards, the generator drift scans,
# the changelog fragments, cargo-deny, and both halves of the
# working-tree guard run on every invocation regardless. Six of the ten
# CI failures of 2026-08-27 are in that unconditional set. Second, every
# cargo phase below is `--workspace`, so scoping never narrows a package
# selection: a phase either runs over the whole workspace or does not
# run. There is no partial build to get wrong.
#
# A skipped phase is recorded through note_skip like any other, so the
# SKIPPED PHASES block at the end lists exactly what did not run.

SCOPE_TO_DIFF=0
SCOPE_BASE='origin/main'
SCOPE_EXPLAIN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --scope-to-diff)
      SCOPE_TO_DIFF=1
      shift
      # An optional base follows, unless the next token is another flag.
      if [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; then
        SCOPE_BASE="$1"
        shift
      fi
      ;;
    --explain)
      SCOPE_EXPLAIN=1
      SCOPE_TO_DIFF=1
      shift
      ;;
    -h|--help)
      # The header, up to the first line of code. A fixed line number
      # went stale the first time the header grew and started printing
      # `set -euo pipefail` as if it were documentation.
      sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'
      printf 'usage: check.sh [--scope-to-diff [<base>]] [--explain]\n\n'
      printf '  --scope-to-diff [<base>]  run only the phases the diff against <base>\n'
      printf '                            (default origin/main) can reach. An\n'
      printf '                            unrecognized path runs everything.\n'
      printf '  --explain                 print that decision per changed path and\n'
      printf '                            run nothing.\n'
      exit 0
      ;;
    -p|--package|--exclude|--features|--all-features|--no-default-features)
      # The one wrong argument worth its own message. Every cargo phase
      # below is --workspace, and the payments phase says it in its own
      # comment: narrow the tests, never the packages. A package
      # selection changes the feature union, so a run scoped to one crate
      # resolves different features, compiles different code, and reports
      # a different lint set from the one CI runs. It is not this gate
      # with less in it; it is a different check wearing its name.
      printf 'check.sh takes no cargo package or feature selection (%s).\n\n' "$1" >&2
      printf 'Every cargo phase in this gate is --workspace. Narrowing the\n' >&2
      printf 'package selection changes the feature union, so the result is\n' >&2
      printf 'not a smaller gate run, it is a different one. For the scoped\n' >&2
      printf 'iteration loop use the per-crate commands in\n' >&2
      printf '.github/CONTRIBUTING-agents.md, and run this with no arguments\n' >&2
      printf 'before you push.\n' >&2
      exit 2
      ;;
    *)
      printf 'unknown argument: %s\n\n' "$1" >&2
      printf 'usage: check.sh [--scope-to-diff [<base>]] [--explain]\n' >&2
      exit 2
      ;;
  esac
done

if [ "$SCOPE_EXPLAIN" = "1" ]; then
  exec python3 "$ROOT/scripts/gate-scope.py" --base "$SCOPE_BASE" --explain
fi

# Default: every phase runs. Scoping can only ever turn entries off, and
# only after gate-scope.py has said so.
#
# A space-delimited list of the phases turned OFF rather than an
# associative array of every phase: `declare -A` is bash 4, macOS ships
# /bin/bash 3.2, and this file is run as `bash scripts/check.sh` by
# whatever bash is first on PATH. Recording only the off set also keeps
# the safe default structural rather than conditional: a name that is not
# in the list runs, and the empty list runs everything.
GATE_PHASES_OFF=''
GATE_PHASES_ON=''
SCOPE_REASON=''
if [ "$SCOPE_TO_DIFF" = "1" ]; then
  SCOPE_OUTPUT="$(python3 "$ROOT/scripts/gate-scope.py" --base "$SCOPE_BASE" || true)"
  if printf '%s' "$SCOPE_OUTPUT" | grep -q '^GATE_PHASE_'; then
    while IFS='=' read -r key value; do
      case "$key" in
        GATE_PHASE_*)
          if [ "$value" = "0" ]; then
            GATE_PHASES_OFF="$GATE_PHASES_OFF ${key#GATE_PHASE_}"
          else
            GATE_PHASES_ON="$GATE_PHASES_ON ${key#GATE_PHASE_}"
          fi
          ;;
        GATE_SCOPE_REASON) SCOPE_REASON="$value" ;;
      esac
    done <<EOF
$SCOPE_OUTPUT
EOF
  else
    # The classifier could not speak. That is not permission to skip.
    printf '\n\033[1;33mgate-scope.py produced no decision; running every phase.\033[0m\n'
    SCOPE_TO_DIFF=0
  fi
fi

# True when the phase should run. Unknown names run: a phase this script
# gates but gate-scope.py has never heard of must not vanish because the
# two files drifted.
phase_wanted() {
  [ "$SCOPE_TO_DIFF" = "1" ] || return 0
  case " $GATE_PHASES_OFF " in
    *" $1 "*) return 1 ;;
  esac
  return 0
}

# Per-phase wall-clock. Each `step` call closes out the previous phase
# with its duration, and `finish_step` closes the last one before the
# summary, so every serial phase's cost is visible in the log. Phases
# inside a parallel batch are timed by run_batch instead.
STEP_STARTED=''
STEP_LABEL=''

finish_step() {
  if [ -n "$STEP_STARTED" ]; then
    printf '\033[2m    (%ss: %s)\033[0m\n' \
      "$(( $(date +%s) - STEP_STARTED ))" "$STEP_LABEL"
  fi
  STEP_STARTED=''
  STEP_LABEL=''
}

step() {
  finish_step
  STEP_STARTED="$(date +%s)"
  STEP_LABEL="$*"
  printf '\n\033[1;34m==>\033[0m %s\n' "$*"
}

# Phases that did not run are collected here and reprinted as a block at
# the very end. "All checks passed" must never be able to hide a lane
# that never executed.
SKIPPED=''
SKIPPED_COUNT=0

note_skip() {
  SKIPPED="${SKIPPED}  * $1"$'\n'
  SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
  printf '\n\033[1;33m!!! SKIPPED:\033[0m %s\n' "$1"
}

# A phase --scope-to-diff turned off. Goes through note_skip so it lands
# in the same SKIPPED PHASES block as everything else: a run that skipped
# half the gate must say so in the same place and the same words as a run
# that was missing promtool.
#
# $1 is the classifier's own phase token and $2 the human label. The token
# is printed so the log can be diffed against `check.sh --explain`, which
# speaks in tokens; without it the two outputs shared no vocabulary and a
# reader had to map step labels back to phase names by hand.
scope_skip() {
  note_skip "$1: $2 (--scope-to-diff: nothing in this diff can reach it; run 'bash scripts/check.sh' with no arguments for the full gate)"
}

if [ "$SCOPE_TO_DIFF" = "1" ]; then
  printf '\n\033[1;34m==>\033[0m diff-scoped against %s\n' "$SCOPE_BASE"
  printf '    reason:  %s\n' "$SCOPE_REASON"
  # The reason line is `diff-scoped` on the only path where scoping
  # actually happens (the classifier only writes a sentence there when it
  # is running everything), so the phase lists are what carry the
  # information. Same tokens --explain prints, in the same order.
  printf '    running: %s\n' "${GATE_PHASES_ON# }"
  printf '    skipped: %s\n' "${GATE_PHASES_OFF# }"
  printf '    Plus the cheap read-only tier, which always runs.\n'
  printf '    scripts/check.sh --explain shows the decision per changed path.\n'
fi

print_skip_summary() {
  printf '\n\033[1;33m========================================================\033[0m\n'
  if [ -z "$SKIPPED" ]; then
    printf '\033[1;32mSKIPPED PHASES: none. Every phase in this gate ran.\033[0m\n'
  else
    printf '\033[1;33mSKIPPED PHASES (these did NOT run):\033[0m\n'
    printf '%s' "$SKIPPED"
    printf '\033[1;33mA skip here is a lane you have not actually checked on\n'
    printf 'this machine. Most of these have a CI lane behind them; do not\n'
    printf 'assume all of them do.\033[0m\n'
  fi
  printf '\033[1;33m========================================================\033[0m\n'
}

# Runs on every exit path, success or failure, and its last act is the
# one line a gate result should ever be quoted as.
#
# "It was green" is not a result. It cannot distinguish a full run from
# one that stopped at the first cargo phase, and it hides the SKIPPED
# PHASES block entirely. GATE_EXIT carries the exit code, the test counts
# the run actually produced, the phase it died in when it died, and how
# many phases did not run. Quote that line.
#
# The counts come from the junit file nextest's ci profile writes, read
# BEFORE cleanup-build-artifacts.sh prunes target/nextest, which is why
# this is the first thing the function does. Every step here tolerates
# its own failure: a cleanup trap that errors would mask the exit code it
# exists to report.
cleanup() {
  local rc=$?
  local junit tests failures head_bytes
  junit="${CARGO_TARGET_DIR:-$ROOT/target}/nextest/ci/junit.xml"
  tests='not-run'
  failures='not-run'
  if [ -f "$junit" ]; then
    head_bytes="$(head -c 4000 "$junit" 2>/dev/null || true)"
    tests="$(printf '%s' "$head_bytes" | tr ' ' '\n' \
      | sed -n 's/^tests="\([0-9]*\)"$/\1/p' | head -1)"
    failures="$(printf '%s' "$head_bytes" | tr ' ' '\n' \
      | sed -n 's/^failures="\([0-9]*\)"$/\1/p' | head -1)"
    tests="${tests:-unparsed}"
    failures="${failures:-unparsed}"
  fi

  if [ -n "${BATCH_DIR:-}" ]; then
    rm -rf "$BATCH_DIR"
  fi
  if [ "${SBPROXY_CLEAN_AFTER_BUILD:-1}" != "0" ]; then
    "$ROOT/scripts/cleanup-build-artifacts.sh" || true
  fi

  if [ "$rc" = "0" ]; then
    printf '\nGATE_EXIT=%s tests=%s failures=%s skipped_phases=%s elapsed=%ss\n' \
      "$rc" "$tests" "$failures" "${SKIPPED_COUNT:-0}" \
      "$(( $(date +%s) - GATE_STARTED ))"
  else
    printf '\nGATE_EXIT=%s tests=%s failures=%s failed_phase=%s skipped_phases=%s elapsed=%ss\n' \
      "$rc" "$tests" "$failures" "${STEP_LABEL:-unknown}" "${SKIPPED_COUNT:-0}" \
      "$(( $(date +%s) - GATE_STARTED ))"
  fi
  return "$rc"
}
trap cleanup EXIT

# --- Parallel batches for the pure-script phases ------------------------
#
# The phases that only read the tree run concurrently in small ordered
# batches instead of one long serial line. The rules:
#
#   * Only phases proven read-only against the repository are batched.
#     Every batched script was read before it was grouped; anything that
#     regenerates a file, writes even a temp sandbox, or binds a port
#     (the doc-generator tests have leaked a listener on 18091 before)
#     stays serial, exactly where it was.
#   * The batches themselves stay ordered cheapest first. Cheapest-first
#     fail-fast is lost inside a batch, but held between batches.
#   * Each member writes to its own file under BATCH_DIR and is printed
#     as one contiguous block after the batch settles, so a failure
#     surfaces under its own phase name with its output intact instead
#     of interleaved with its neighbors'.
#   * Every member is waited on individually and exit codes aggregate:
#     any failure fails the gate, after every member has reported.
#
# The EXIT trap above is process-scoped and does not fire when a
# subshell ends, so all cleanup stays in this shell: batch members
# install no traps and clean up nothing. None of them calls note_skip
# either, which could not propagate out of a subshell; every phase that
# can record a skip stays serial.

BATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-gate-batch.XXXXXX")"

# run_batch "<title>" <fn> "<phase name>" [<fn> "<phase name>"]...
run_batch() {
  local title="$1"
  shift

  local -a fns=() labels=() pids=()
  while [ "$#" -gt 0 ]; do
    fns+=("$1")
    labels+=("$2")
    shift 2
  done

  step "$title (${#fns[@]} checks in parallel)"

  local i out
  for i in "${!fns[@]}"; do
    out="$BATCH_DIR/${fns[$i]}"
    # shellcheck disable=SC2030  # rc/start are deliberately subshell-local
    (
      start="$(date +%s)"
      set +e
      ( set -e; "${fns[$i]}" ) >"$out.log" 2>&1
      rc=$?
      printf '%s' "$(( $(date +%s) - start ))" >"$out.time"
      exit "$rc"
    ) &
    pids+=("$!")
  done

  local rc elapsed failed=''
  for i in "${!fns[@]}"; do
    rc=0
    # shellcheck disable=SC2031  # rc here is the parent's, set from wait
    wait "${pids[$i]}" || rc=$?
    out="$BATCH_DIR/${fns[$i]}"
    elapsed="$(cat "$out.time" 2>/dev/null || printf '?')"
    if [ "$rc" -eq 0 ]; then
      printf '\n  \033[1;34m*\033[0m %s (%ss)\n' "${labels[$i]}" "$elapsed"
    else
      printf '\n  \033[1;31m* FAILED:\033[0m %s (exit %s after %ss)\n' \
        "${labels[$i]}" "$rc" "$elapsed"
      failed="${failed}  * ${labels[$i]}"$'\n'
    fi
    sed 's/^/    /' "$out.log"
  done

  if [ -n "$failed" ]; then
    printf '\n\033[1;31mFAILED in this batch:\033[0m\n%s' "$failed" >&2
    exit 1
  fi
}

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
#
# The read-only scans run as one parallel batch. Each script named in
# the batch was read and proven not to write inside the repository
# before it was grouped:
#
#   * tracker placeholders, spec citations, env mutation: grep only.
#   * pub-item and unwrap ratchets: python scans over the source plus a
#     read of their committed baselines; the scanners write nothing.
#   * NOTICE coverage: `cargo metadata --locked`, which refuses to
#     rewrite Cargo.lock rather than regenerating it.
#   * secret-resolver drift: python source scan.
#   * doc drift: grep/sed plus a python read of the generated schema.
#   * attribute placement: python source scan.
#   * attribute theft: `git diff` and `git show` against the merge base,
#     both read-only plumbing; the script writes nothing.
#
# The rest of this phase stays serial: the llms-full guard regenerates
# the corpus into a temp file when the branch carries it, the helper
# self-tests build mktemp sandboxes, the installer test builds a fake
# release and runs the installer against it, and `make tapes-check`
# runs the doc-generator test module, which binds listeners (it has
# leaked one on port 18091 before). Writers and port binders are not
# batched.
# =======================================================================

# CI: ci.yml lint lane, "no internal tracker placeholders". A literal
# WOR-XXX is an unfinished TODO that announces incomplete work without
# making it trackable.
batch_tracker_placeholders() {
  if grep -rn 'WOR-XXX' crates/ --include='*.rs' --include='*.toml'; then
    printf '\nWOR-XXX placeholders are not allowed in crates/.\n' >&2
    printf 'Open a real ticket and cite it by full URL, or rewrite the line\n' >&2
    printf 'as prose. Reproduce with:\n\n' >&2
    printf "  grep -rn 'WOR-XXX' crates/ --include='*.rs' --include='*.toml'\n" >&2
    exit 1
  fi
  printf 'no WOR-XXX placeholders under crates/\n'
}

# CI: ci.yml test lane, "no new pub items whose only consumer is a test".
# Pure python, a few seconds, and the highest value per second in this
# file: dead_code cannot see a pub item inside a pub mod, so write-only
# code otherwise lands with a green build.
batch_pub_item_ratchet() {
  bash "$ROOT/scripts/check-pub-item-ratchet.sh"
}

# CI: ci.yml test lane, "no new unwrap/expect/panic in production code".
# Each of these ends the process on a path a caller cannot catch, which in a
# proxy means a dropped request rather than an error a client can act on.
# Clippy's equivalent lints cannot express this: the lint lane runs with
# -D warnings, so warn and deny are one level and there is no ratchet to
# hold, and all three fire in test code where they are the correct thing to
# write. See the script header.
batch_unwrap_ratchet() {
  bash "$ROOT/scripts/check-unwrap-ratchet.sh"
}

# CI: ci.yml test lane, "no new operator URL at a log line" (WOR-2629,
# WOR-2640). Two counts. `raw-url` is a URL-named tracing field that did
# not go through sbproxy_security::url_redact; `raw-request-error` is
# `error = %e` next to an outbound reqwest call, whose Display ends with
# " for url ({url})" and so writes the whole URL with no url field in
# sight. The second is at zero, which means "no site of the shape the
# proximity detector can see" and not "no reqwest URL reaches a log"; the
# scanner's module header sets out both sets. Runs the scanner's own
# fixtures and the ratchet's, because a detector that stopped detecting
# reads like a clean tree.
batch_log_url_ratchet() {
  bash "$ROOT/scripts/check-log-url-ratchet.sh"
}

# CI: ci.yml test lane, "the AI dispatch path's stack budget only
# falls" (WOR-2699). The fourth ratchet of the same family and the same
# shape: one integer in one file, compared against the merge base.
#
# The budget is the worker stack that
# `the_ai_dispatch_path_stays_inside_its_stack_budget` runs a real
# dispatch on. The test enforces the number; this enforces the
# direction, which a test compiled against a raised baseline cannot. A
# stack overflow does not unwind, carries no backtrace and names no
# frame, so the only defence is a budget that keeps falling.
batch_stack_budget_ratchet() {
  bash "$ROOT/scripts/check-stack-budget-ratchet.sh"
}

# CI: ci.yml guards lane, "no insertion landed inside an attribute
# block". Diff-scoped: an item inserted between an attribute
# block and the item it was attached to takes the block with it, and the
# stolen lines stay context in the diff, so the review sees a new item
# with a doc comment above it. Three of these reached main in one day.
#
# Fails closed when no base resolves, for the reason
# check-stack-budget-ratchet.sh has written down next door.
batch_attribute_theft() {
  python3 "$ROOT/scripts/check-attribute-theft.py" --check
}

# CI: ci.yml guards lane, "attributes sit on items they can apply
# to". Tree-scoped, and the half rustc cannot cover: it refuses
# `#[test]` on a static, a const, a use, or a function taking arguments
# in every cfg rather than only in the ones a lane compiles with
# --test, and it refuses `#[ignore]` and `#[should_panic]` on a
# function carrying no test attribute, which nothing else reports at
# all. Fifteen to twenty-five seconds of python over 1,400 files.
batch_attribute_placement() {
  python3 "$ROOT/scripts/check-attribute-placement.py" --check
}

# CI: ci.yml guards lane and docs-ci.yml, "spec citation hygiene".
batch_spec_citations() {
  bash "$ROOT/scripts/check-spec-citations.sh"
}

# CI: ci.yml lint lane, "no process-global env mutation outside test
# helpers" (WOR-646). Pure grep. Production code must not call
# std::env::set_var / remove_var; tests go through the per-crate
# EnvVarGuard in src/test_env.rs.
batch_env_mutation() {
  bash "$ROOT/scripts/check-env-mutation.sh"
}

# CI: ci.yml lint lane, "no call site hands tract a model directory"
# (WOR-2694). Pure grep, in two tiers. Nothing may call tract's
# model_for_path / model_for_read, which parse and translate in one call
# and leave no point at which a caller can refuse an external_data
# reference; nor parse_with_template, Onnx::parse, or a hand-built
# ParsingContext, which take the model directory directly. That
# directory is the state GHSA-h668-6x6g-f8r5 turns into an arbitrary
# file read. The script's header states what a line-oriented grep
# cannot see, and its name is the property it actually verifies rather
# than the broader one the tests cover.
batch_onnx_model_loaders() {
  bash "$ROOT/scripts/check-onnx-model-loaders.sh"
}

# CI: ci.yml lint lane, "durable sinks create files owner-only"
# (WOR-2626). Pure grep, plus fixtures that prove the detector still
# detects. Production code in the four sink crates must reach
# sbproxy_util::secure_fs rather than File::create / OpenOptions /
# create_dir_all, and the helper itself must put the mode in the open
# rather than chmod after it.
batch_durable_file_modes() {
  bash "$ROOT/scripts/check-durable-file-modes.sh"
}

# CI: ci.yml lint lane, "runtime images keep /var/lib/sbproxy and
# debian13" (WOR-2705, WOR-2713). Pure grep plus fixtures. Fleet and
# Cloud Build Dockerfiles must COPY /var/lib/sbproxy into the runtime
# stage the way Dockerfile.ci already does, and every distroless
# runtime FROM must not still name cc-debian12. Dockerfile.worker is
# CUDA / Ubuntu, so it needs the COPY and is not required to name
# debian13.
batch_runtime_image_lockstep() {
  bash "$ROOT/scripts/check-runtime-image-lockstep.sh"
}

# CI: ci.yml guards lane, "secret-bearing types do not derive Debug"
# (WOR-2640). Pure grep over a committed registry, plus fixtures that
# prove the detector still detects. Every type listed in
# scripts/secret-debug-registry.txt must keep all three of: no `Debug`
# in its derive, a hand-written redacting impl, and the test that
# pushes a sentinel through it. Putting the derive back is a one-line
# change that compiles and reads like tidying, which is what this
# stops.
batch_secret_debug_registry() {
  bash "$ROOT/scripts/check-secret-debug-registry.sh"
}

# CI: ci.yml guards lane, "every stable metric has somewhere to be seen".
# A metric an operator can be alerted on but cannot look at is a gap the
# registry cannot see: it knows the family exists, not whether any
# dashboard draws it. Shrink-only baseline, so the number can only fall.
batch_metric_visibility() {
  bash "$ROOT/scripts/check-metric-visibility.sh"
}

# WOR-2449: Apache 2.0 section 4(d) attribution for Apache-2.0-only
# crates. cargo metadata, no compile. Shares one script with the CI
# lint lane. The CLAUDE.md / AGENTS.md snippet is no longer the check.
batch_notice_coverage() {
  bash "$ROOT/scripts/check-notice.sh"
}

# CI: ci.yml lint lane, "no hand-rolled secret-reference parsing".
# WOR-2287: guardrail for the WOR-2282 secret-resolver convergence. Pure
# python source scan. Refuses a hand-rolled env:/file:/provider-URI scheme
# match outside crates/sbproxy-vault/src/, and a secret-shaped function
# whose fallback hands a parameter back unchanged without first calling a
# reference-shape guard -- the bug class WOR-2283 fixed.
batch_secret_resolver_drift() {
  python3 "$ROOT/scripts/check-secret-resolver-drift.py"
}

# CI: ci.yml guards lane and doc-drift.yml, "doc drift (counts and
# stale claims)". Guards the provider-count, routing-strategy, and
# unimplemented-feature claims in user-facing docs.
batch_doc_drift() {
  bash "$ROOT/scripts/check-doc-drift.sh"
}

# CI: ci.yml guards lane, "no committed merge-conflict markers".
# A merge that commits its own conflict markers ships corrupted files;
# one reached main's CHANGELOG on 2026-08-19 through a gate that never
# looked. Scan every tracked text surface a merge can mangle. The
# pattern is anchored and paired so scripts discussing markers (like
# this one) do not self-trip. Read-only git grep, so it batches.
batch_conflict_markers() {
  if git grep -nE '^(<{7} |={7}$|>{7} )' -- ':!*.lock' ':!docs/llms-full.txt'; then
    printf '\ncommitted merge-conflict markers found; resolve the merge for real.\n' >&2
    return 1
  fi
  printf 'no conflict markers in tracked files\n'
}

# CI: ci.yml guards lane, "changelog entries are fragments, not
# CHANGELOG.md edits" (WOR-2108). Refuses a malformed fragment, any
# hand-written content under `## [Unreleased]`, and a commit that edits
# CHANGELOG.md without touching docs/.changes/ in the same diff. The
# diff half needs a merge base, and the script itself degrades to the
# parser and placeholder halves (saying so) when it is not run inside a
# git work tree, so there is nothing to branch on here.
batch_changelog_fragments() {
  python3 "$ROOT/scripts/changelog-fragments.py" --check
}

run_batch "read-only source and doc scans" \
  batch_tracker_placeholders "no internal tracker placeholders" \
  batch_pub_item_ratchet "pub items whose only consumer is a test (ratchet)" \
  batch_unwrap_ratchet "unwrap/expect/panic in production code (ratchet)" \
  batch_log_url_ratchet "operator URLs at log lines (ratchet)" \
  batch_stack_budget_ratchet "AI dispatch path stack budget (ratchet)" \
  batch_attribute_placement "attributes sit on items they can apply to" \
  batch_attribute_theft "no insertion landed inside an attribute block" \
  batch_spec_citations "spec citation hygiene" \
  batch_env_mutation "no process-global env mutation outside test helpers" \
  batch_onnx_model_loaders "no call site hands tract a model directory" \
  batch_durable_file_modes "durable sinks create files owner-only" \
  batch_runtime_image_lockstep "runtime images keep /var/lib/sbproxy and debian13" \
  batch_secret_debug_registry "secret-bearing types do not derive Debug" \
  batch_metric_visibility "every stable metric has a dashboard panel (ratchet)" \
  batch_notice_coverage "NOTICE covers Apache-2.0-only crates" \
  batch_secret_resolver_drift "secret-resolver drift (no new ad-hoc secret parsers)" \
  batch_doc_drift "doc drift" \
  batch_conflict_markers "no committed merge-conflict markers" \
  batch_changelog_fragments "changelog entries are fragments, not CHANGELOG.md edits"

# Serial: regen-llms-full.sh --check rebuilds the corpus into a temp
# file when the branch carries it, and this phase can record a skip.

# CI: docs-ci.yml, "llms-full.txt is current if carried". A branch may
# carry the corpus, and the rule is that it has to be what the generator
# produces rather than a hand edit. Nothing rejects the file any more:
# WOR-2119 kept it off branches because a workflow pushed it to main
# after every merge, and that push cannot exist now that main requires a
# pull request. Regeneration moved to release prep instead.
#
# `--check` reuses the committed `Generated:` line, so the timestamp in
# the header does not make a current file look stale.
step "docs/llms-full.txt is current if carried"
if [ "$GIT_AVAILABLE" != "1" ]; then
  note_skip "docs/llms-full.txt guard (not inside a git work tree)"
else
  LLMS_BASE="$(git merge-base HEAD origin/main 2>/dev/null || true)"
  if [ -z "$LLMS_BASE" ]; then
    note_skip "docs/llms-full.txt guard (no merge base with origin/main; run 'git fetch origin main' first)"
  elif git diff --quiet "$LLMS_BASE" -- docs/llms-full.txt; then
    printf 'docs/llms-full.txt untouched by this branch\n'
  elif bash scripts/regen-llms-full.sh --check; then
    printf 'docs/llms-full.txt matches the generator\n'
  else
    printf '\nThis branch changes docs/llms-full.txt and it does not match the\n' >&2
    printf 'generator, so it is a hand edit or a stale regeneration.\n\n' >&2
    printf '  bash scripts/regen-llms-full.sh\n\n' >&2
    printf 'Edit the source docs/*.md and regenerate; never edit the corpus.\n' >&2
    exit 1
  fi
fi

# Serial: each self-test builds and tears down a mktemp sandbox.
# These helpers steer the gate around expensive or destructive work, so run
# their branch tests before any Cargo build or CI-equivalent cleanup.
# CI: ci.yml lint lane, "gate helper self-tests"; the changelog fixtures
# run in the guards lane instead, beside the gate they arm.
step "gate helper self-tests"
bash "$ROOT/scripts/tests/workspace_bin_test.sh"
bash "$ROOT/scripts/tests/runner_disk_test.sh"
bash "$ROOT/scripts/tests/changelog_fragments_test.sh"
python3 "$ROOT/scripts/tests/release_notes_test.py"
python3 "$ROOT/scripts/lib/cert_record.py" --self-test
python3 "$ROOT/scripts/tests/test_cert_record.py"
python3 "$ROOT/scripts/lib/notice_coverage.py" --self-test
python3 "$ROOT/scripts/tests/test_notice_coverage.py"
# The --scope-to-diff classifier's corpus: ten CI failures, each
# asserted to still select the phase that catches it. Unconditional, so
# a rule narrowed in gate-scope.py fails here rather than silently
# turning a phase off on somebody else's branch.
python3 "$ROOT/scripts/gate-scope.py" --self-test
# The two attribute guards and the test-count helper. All three are
# detectors, and a detector that has quietly stopped detecting reads
# exactly like a clean tree, which is the one failure a gate cannot
# self-report. The theft fixtures are the two real hunks from cf77910e9
# and eb42165a5.
python3 "$ROOT/scripts/check-attribute-theft.py" --self-test
python3 "$ROOT/scripts/check-attribute-placement.py" --self-test
bash "$ROOT/scripts/lib/expect-tests.sh" --self-test

# Serial: the test_doc_generators module binds listeners and has
# leaked one on port 18091 before; nothing that opens a port runs
# concurrently with anything else in this gate.
# CI: ci.yml guards lane and docs-ci.yml, "generated tapes and GIF
# wiring are current", which
# is `make tapes-check`. That target is three commands, the last of
# which is the whole scripts.tests.test_doc_generators module. This gate
# used to run a single class out of that module, so five of the six test
# classes had no local equivalent at all. Invoked through make so the
# Makefile stays the one definition of what the check is.
if ! phase_wanted TAPES; then
  scope_skip TAPES "generated tapes and GIF wiring (make tapes-check)"
else
step "generated tapes and GIF wiring are current"
if ! command -v make >/dev/null 2>&1; then
  printf 'make not found on PATH; install it (Xcode Command Line Tools on\n' >&2
  printf 'macOS) to run the tapes check. CI requires this lane, so it cannot\n' >&2
  # shellcheck disable=SC2016  # the backticks are prose, not a subshell
  printf 'be skipped here. The target is `make tapes-check`.\n' >&2
  exit 1
fi
make tapes-check
fi

# The three generator --check drift scans only read the tree. Each was
# read before it was grouped: check-doc-assets.py never writes,
# sync-doc-configs.py writes only when --check is absent, and
# gen-examples-catalog.py --check compares in memory and writes nothing.

# CI: ci.yml lint lane and docs-ci.yml, "every promised doc asset exists".
# The tapes step above keeps each tape in sync with its example's config
# and never looks in docs/assets/, and wire-example-gifs.py only inserts
# an image that is already on disk. So neither of them can see a tape
# whose recording was never run, or a README embed pointing at the GIF
# that recording would have produced. Both shipped that way before this
# ran.
batch_doc_assets() {
  PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/check-doc-assets.py"
}

# CI: ci.yml guards lane and docs-ci.yml, "documentation configs
# match canonical examples".
# The `every_oss_example_compiles` half of that CI step is covered by
# the workspace test lane below; do not add a `-p sbproxy-config`
# invocation here, because a narrow package selection resolves a
# different feature union than CI and reports failures CI never sees.
batch_doc_configs() {
  PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/sync-doc-configs.py" --check
}

# CI: ci.yml guards lane, "examples catalog is current".
# examples/README.md is generated by gen-examples-catalog.py, which has
# supported --check since it was written, and for a long stretch nothing
# called it: not CI, not this gate, not the Makefile. It had silently
# drifted by two rows on main. A generated file with a drift checker
# nobody invokes is the same failure as having no checker at all.
batch_examples_catalog() {
  PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/gen-examples-catalog.py" --check
}

# CI: ci.yml guards lane, "review-evidence parser fixtures";
# review-evidence.yml also runs them before it parses a body.
# The parser reads attacker-controlled text and decides whether a PR
# carries review evidence, so a regression that loosened it would read
# green in exactly the place the gate is supposed to be strict. The
# fixtures are in-process and take under a second.
batch_review_evidence() {
  PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/check-review-evidence.py" --self-test
}

run_batch "generator --check drift scans" \
  batch_doc_assets "every promised doc asset exists" \
  batch_doc_configs "documentation configs match canonical examples" \
  batch_examples_catalog "examples catalog is current" \
  batch_review_evidence "review-evidence parser fixtures"

# CI: docs-ci.yml, both halves. This gate named docs-ci.yml in six
# comments as the lane a phase mirrors and never ran the script itself,
# so two of its checks had NO local equivalent at all: the `rust` code
# blocks in docs/*.md are type-checked by rustc, and every in-tree
# anchor is resolved offline by lychee. On 2026-08-27 that gap cost two
# CI round trips in one day, one for three code blocks that did not
# compile standalone and one for an anchor pointing at a heading another
# page had renamed.
#
# Serial, and not in a batch: run_code spawns one rustc per code block
# across its own pool and would fight anything running beside it.
# Needs rustc and lychee; a `rust` block that cannot compile standalone
# is tagged `rust,no_run` at the source rather than skipped here.
if ! phase_wanted DOCSCI; then
  scope_skip DOCSCI "docs-ci (rust code blocks and offline anchor resolution)"
elif ! command -v lychee >/dev/null 2>&1; then
  note_skip "docs-ci link half (lychee not on PATH; docs anchors and cross-page links are unchecked locally). Install with 'cargo install lychee --locked' or 'brew install lychee'."
  step "docs code blocks compile"
  bash "$ROOT/scripts/docs-ci.sh" --code
else
  step "docs code blocks compile and every anchor resolves"
  bash "$ROOT/scripts/docs-ci.sh"
fi

# Serial: the opt-in replay path spawns fixture and proxy processes on
# real ports, and the phase records a skip on the default path.
# CI: ci.yml guards lane runs the structural half on every pull request;
# release-checks.yml replays the commands on tags and nightly.
# Captures are the output blocks a doc shows under a CAPTURE marker. The
# structural half runs here always: every marker has a block, and no
# block is empty. Both are cheap and both have caught real defects, since
# all five empty blocks in the WOR-2158 batch were product bugs rather
# than formatting slips.
#
# Replaying the commands is opt-in, because it starts fixtures and needs a
# payments-featured binary. Without SBPROXY_CHECK_CAPTURES=1 the script
# prints how many captures it did NOT verify, so a structural pass cannot
# read as "the docs still produce this". See WOR-2297.
step "documented command output"
if [ "${SBPROXY_CHECK_CAPTURES:-0}" = "1" ]; then
  PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/check-doc-captures.py" --check
else
  PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/check-doc-captures.py" \
    --check --stackless-only
  note_skip "replaying documented commands (set SBPROXY_CHECK_CAPTURES=1, with a payments-featured binary in SBPROXY_CAPTURE_BIN, to re-run each captured command and diff it against the block the doc shows)"
fi

# Serial: builds a fake release under mktemp and runs the installer
# against it.
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
#
# fmt --check, the tape-secrets scan, the nested-lockfile guard, and the
# npm audit only read the tree, so they run as one batch:
# `cargo fmt -- --check` rewrites nothing, the lockfile guard runs
# `cargo metadata --locked` (which refuses to update a lockfile), and
# `npm audit --package-lock-only` resolves from ui/package-lock.json
# without installing anything. cargo-deny stays serial: it refreshes its
# advisory database on disk and resolves the full graph. The UI phase
# stays serial too: `npm ci` deletes and reinstalls node_modules when
# the lockfile moved, and vitest spawns its own worker pool.
# =======================================================================

batch_cargo_fmt() {
  cargo fmt --all -- --check
}

# Reads docs/tapes/*.tape and nothing else; see the script header for
# the credential-rendering bug class it guards against.
batch_tape_secrets() {
  bash "$ROOT/scripts/check-tape-secrets.sh"
}

# CI: ci.yml lint lane. The bench harnesses and the config-source
# fixture are their own workspaces that path-depend on this one, so a
# dependency added here leaves their lockfiles stale. No cargo step in
# this gate opens them, which is why that drift used to reach CI
# untouched.
batch_nested_lockfiles() {
  bash "$ROOT/scripts/check-nested-lockfiles.sh"
}

# CI: ci.yml supply-chain lane, second step. cargo-deny cannot see the
# admin SPA's npm graph, so a high-severity advisory there used to pass
# every gate in this file. `--package-lock-only` resolves the tree from
# ui/package-lock.json without installing anything, so this runs before
# the UI phase below and does not depend on node_modules existing.
# `--audit-level=high` matches CI; see SUPPLY-CHAIN.md section 4.3 for
# why the threshold sits there. Unconditional, because CI requires it and
# the UI phase below already hard-fails when npm is missing.
batch_npm_audit() {
  if ! command -v npm >/dev/null 2>&1; then
    printf 'npm not found on PATH; install Node.js (https://nodejs.org) to run the npm audit gate. This step is required by CI, so it cannot be skipped here.\n' >&2
    exit 1
  fi
  (cd ui && npm audit --package-lock-only --audit-level=high)
}

run_batch "fmt, lockfiles, npm audit" \
  batch_cargo_fmt "cargo fmt --check" \
  batch_tape_secrets "tapes do not render credentials" \
  batch_nested_lockfiles "standalone workspace lockfiles are current" \
  batch_npm_audit "supply chain (npm audit, admin UI)"

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
if ! phase_wanted UI; then
  scope_skip UI "ui typecheck and test (npm)"
else
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
fi

# =======================================================================
# Phase 3: minutes. Compiles the workspace.
#
# SBPROXY_SKIP_CARGO=1 skips everything from here to the working-tree
# re-check: every cargo compile/test/doc invocation, the generated
# artifact checks that exec built binaries, and the payments lane. It
# exists so a change to this script's cheap phases can be exercised end
# to end without paying a workspace build. It is never a substitute for
# the gate, and the skip is reprinted in the SKIPPED PHASES block.
# =======================================================================

if [ "${SBPROXY_SKIP_CARGO:-0}" = "1" ]; then
  note_skip "cargo build/test/doctest/clippy/doc, the generated-artifact checks, and the payments lane (SBPROXY_SKIP_CARGO=1 is a dev-only switch for exercising the script phases; a run with it set is not a gate result)"
else

# One package selection for every cargo invocation below, which is the
# invariant ci.yml holds: under resolver = "2" the feature union is
# computed from the selected packages, so a different selection silently
# recompiles the graph.
test_package_args=(--workspace --locked)

# Test binaries filtered out because the proxy binary flavor they spawn
# was never built. Stays empty on the default path. See the WOR-2291
# block below.
e2e_exclusion=''

if [ "${SBPROXY_CHECK_E2E:-0}" != "1" ]; then
  test_package_args+=(--exclude sbproxy-e2e)
else
  # WOR-2291. Until now `SBPROXY_CHECK_E2E=1` did exactly one thing: stop
  # passing `--exclude sbproxy-e2e`. But the `cargo build` below produces
  # one binary, target/debug/sbproxy, and four e2e files spawn a
  # *different* one. e2e/src/lib.rs carries three harness flavors that
  # search three separate trees:
  #
  #   Default             target/{release,debug}/sbproxy
  #   NoDefaultFeatures   target/no-default-features/{release,debug}/sbproxy
  #   Payments            target/payments/{release,debug}/sbproxy
  #
  # Only the first is a by-product of this gate. headless_detection_e2e
  # and tls_fingerprint_capture_e2e want the second; settlement_gate and
  # usage_bridge want the third. Neither has ever been built here, so
  # every test in those four files failed on "binary missing at ..." the
  # moment anyone set the variable, and the gate reported it as a test
  # failure rather than as missing setup.
  #
  # Building all three flavors would roughly triple the most expensive
  # phase in this file to cover a lane most runs cannot reach, so this
  # skips loudly instead: a flavor whose binary is not already on disk
  # has its test binaries filtered out of the nextest run and its build
  # command printed in the SKIPPED PHASES block. Build it once and the
  # tests run on every later gate for free.
  #
  # The probe reproduces the harness's own blind spot on purpose.
  # e2e/src/lib.rs's `workspace_root()` derives from CARGO_MANIFEST_DIR,
  # so the harness searches <repo>/target/... no matter what
  # CARGO_TARGET_DIR says. A probe that honored CARGO_TARGET_DIR would
  # green-light tests for a binary the harness then cannot find, turning
  # a clear skip into a confusing failure, so this looks exactly where
  # the harness looks and resolves the same SBPROXY_E2E_*_BIN overrides
  # with the same relative-path anchoring. The build commands quoted
  # below pin CARGO_TARGET_DIR themselves, which overrides an exported
  # one, so following them verbatim lands the binary where both this
  # probe and the harness will find it.
  #
  # Filtering is by test binary and nothing else. It does not touch -j,
  # and it does not touch the `sbproxy-e2e` test group in
  # .config/nextest.toml, which is what keeps settlement_gate off the
  # parallel path it is red on (WOR-2295).

  # Resolve one harness flavor the way e2e/src/lib.rs does: the override
  # variable wins when it is set and non-empty, with a relative value
  # anchored at the workspace root; otherwise the first existing
  # candidate wins. Prints the path only when a usable binary exists.
  resolve_e2e_binary() {
    local var="$1" configured candidate
    shift
    configured="${!var:-}"
    if [ -n "$configured" ]; then
      case "$configured" in
        /*) candidate="$configured" ;;
        *) candidate="$ROOT/$configured" ;;
      esac
      if [ -f "$candidate" ]; then
        printf '%s\n' "$candidate"
      fi
      return 0
    fi
    for candidate in "$@"; do
      if [ -f "$ROOT/$candidate" ]; then
        printf '%s\n' "$ROOT/$candidate"
        return 0
      fi
    done
    return 0
  }

  add_e2e_exclusion() {
    local bin
    for bin in "$@"; do
      if [ -z "$e2e_exclusion" ]; then
        e2e_exclusion="binary($bin)"
      else
        e2e_exclusion="${e2e_exclusion} + binary($bin)"
      fi
    done
  }

  if [ -z "$(resolve_e2e_binary SBPROXY_E2E_PAYMENTS_BIN \
    target/payments/release/sbproxy target/payments/debug/sbproxy)" ]; then
    add_e2e_exclusion settlement_gate usage_bridge
    # The feature list here is copied verbatim from e2e/src/lib.rs's own
    # `missing_hint()` and from the build step in
    # .github/workflows/e2e.yml, which are the two other places that name
    # it. It is deliberately NOT the five-rail `payment_features` list
    # further down this file: that one is the workspace feature union for
    # the payments clippy/test lane, this one builds the `sbproxy` binary
    # the e2e harness spawns, and the two have drifted apart on
    # `payment-lightning-lnd`. Matching the harness matters more than
    # matching the other list, because a developer who runs a command
    # this gate printed must end up with the binary the gate then looks
    # for.
    note_skip "e2e settlement_gate + usage_bridge (no payments-featured binary under target/payments/). Build it once with: CARGO_TARGET_DIR=target/payments cargo build --release -p sbproxy --locked --features payment-x402,payment-mpp,payment-stripe,payment-lightning-cln  -- or point SBPROXY_E2E_PAYMENTS_BIN at one. The e2e lane in .github/workflows/e2e.yml builds it, so these tests do run somewhere; they did not run here."
  fi

  if [ -z "$(resolve_e2e_binary SBPROXY_E2E_NO_DEFAULT_FEATURES_BIN \
    target/no-default-features/release/sbproxy target/no-default-features/debug/sbproxy)" ]; then
    add_e2e_exclusion headless_detection_e2e tls_fingerprint_capture_e2e
    note_skip "e2e headless_detection_e2e + tls_fingerprint_capture_e2e (no --no-default-features binary under target/no-default-features/). Build it once with: CARGO_TARGET_DIR=target/no-default-features cargo build -p sbproxy --no-default-features --locked  -- or point SBPROXY_E2E_NO_DEFAULT_FEATURES_BIN at one. The e2e lane in .github/workflows/e2e.yml builds it, so these tests do run somewhere; they did not run here."
  fi
fi

nextest_args=("${test_package_args[@]}" --profile ci)
cargo_test_args=("${test_package_args[@]}")
if [ "${SBPROXY_RELEASE_TESTS:-0}" = "1" ]; then
  nextest_args+=(--release --tests)
  cargo_test_args+=(--release --tests)
fi
if [ -n "$e2e_exclusion" ]; then
  nextest_args+=(-E "not (${e2e_exclusion})")
fi

# CI: `cargo build --workspace --exclude sbproxy-e2e --locked`.
#
# `--locked` is load bearing. Without it this build SILENTLY REWRITES
# the root Cargo.lock in place, and the `--locked` test step that
# follows then passes against the file this step just regenerated. Local
# lockfile drift was auto-repaired rather than reported, and with no
# working-tree guard nobody was ever told.
if ! phase_wanted BUILD; then
  scope_skip BUILD "cargo build"
else
  step "cargo build"
  cargo build "${test_package_args[@]}"
fi

if ! phase_wanted TEST; then
  scope_skip TEST "cargo test (the workspace nextest lane)"
else
step "cargo test"
if cargo nextest --version >/dev/null 2>&1; then
  cargo nextest run "${nextest_args[@]}"
elif [ "${SBPROXY_ALLOW_CARGO_TEST_FALLBACK:-0}" = "1" ]; then
  note_skip "nextest test lane (SBPROXY_ALLOW_CARGO_TEST_FALLBACK=1 ran serial 'cargo test' instead; this is not the lane CI runs)"
  if [ -n "$e2e_exclusion" ]; then
    # A filterset has no `cargo test` equivalent, and the alternative
    # spelling (`--test <name>` for every file that is *not* excluded)
    # would have to be hand-maintained, so a new e2e file would silently
    # stop running. The run therefore keeps the missing-binary failures
    # rather than hiding them behind a stale allow-list.
    note_skip "e2e binary-flavor filtering (no nextest, and 'cargo test' cannot express a filterset, so the tests named above ran and will fail on their missing binary rather than being skipped)"
  fi
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
fi

# nextest does not execute doctests, so they need their own pass.
if ! phase_wanted DOCTEST; then
  scope_skip DOCTEST "cargo doctest"
else
  step "cargo doctest"
  cargo test "${test_package_args[@]}" --doc
fi

if ! phase_wanted CLIPPY; then
  scope_skip CLIPPY "cargo clippy"
else
  step "cargo clippy"
  cargo clippy --workspace --all-targets -- -D warnings
fi

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
if ! phase_wanted DOC; then
  scope_skip DOC "cargo doc (rustdoc, -D missing_docs, and the intra-doc link check)"
else
  step "cargo doc"
  RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc --workspace --no-deps --locked
fi

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
# shellcheck source=scripts/lib/workspace-bin.sh
. "$ROOT/scripts/lib/workspace-bin.sh"

if ! phase_wanted GENERATED; then
  scope_skip GENERATED "config schema, reader coverage, metrics stability, decision contract, and model-host capabilities (all exec built binaries)"
else
  step "config schema and reader coverage"
  run_generated_artifact_checks \
    "$ROOT" \
    check-config-schema.sh \
    check-config-readers.sh

  step "generated docs are current"
  run_generated_artifact_checks \
    "$ROOT" \
    check-metrics-stability.sh \
    check-decision-contract.sh \
    check-model-host-capabilities.sh
fi

# CI: ci.yml payments lane (WOR-2222). Last in this phase because it is the
# most expensive thing in this file, so every cheaper failure above is found
# first.
#
# On by default since 2026-08-28. Every cargo call above resolves the
# workspace's default union, and no payment feature is in any default set, so
# without this phase the gate compiles none of the settlement path: not
# sbproxy-core's inline settle gate, not the recovery worker or the
# reconciliation sweep in billing_runtime, not the usage bridge's runtime
# half, and not the feature-gated majority of sbproxy-billing, which is most
# of that crate plus eleven of its twelve integration test files.
#
# It was opt-in until it cost a CI round trip. The settlement union has a
# different fingerprint from every cargo call above, so both commands below
# recompile the graph from scratch and reuse nothing, and that price bought
# an env var everyone forgot. clippy::items_after_test_module then landed on
# main from a lane no local run had ever executed. A gate whose most
# expensive check is the one people skip is not measuring what it claims to.
#
# `SBPROXY_CHECK_PAYMENTS=0` still skips it, and the skip is reprinted in the
# SKIPPED PHASES block naming the two CI lanes that will catch what was
# missed. `--scope-to-diff` skips it too when no Rust file changed, which is
# the case that made it expensive for no reason.
if ! phase_wanted PAYMENTS; then
  scope_skip PAYMENTS "payment settlement features (clippy + test)"
elif [ "${SBPROXY_CHECK_PAYMENTS:-1}" != "1" ]; then
  note_skip "payment settlement features (SBPROXY_CHECK_PAYMENTS=0 was set explicitly). No other phase in this gate compiles crates/sbproxy-billing's runtime, sbproxy-core's settlement gate, or the ~217 tests inside them, so all of it stayed unbuilt. CI's 'payments' and 'payments clippy (settlement features)' lanes both require it, and they are where clippy::items_after_test_module surfaces."
else
  # One feature selection for both commands, matching ci.yml's
  # PAYMENT_FEATURES exactly. It names the `sbproxy` binary's flags rather
  # than sbproxy-core's so the union is the released payments binary's:
  # everything the workspace lane already resolves, plus settlement. A
  # narrower `-p sbproxy-core` selection would resolve fewer features than CI
  # does, report dead-code failures CI never sees, and miss sbproxy-billing's
  # test targets outright.
  payment_features='sbproxy/payment-mpp,sbproxy/payment-stripe,sbproxy/payment-x402,sbproxy/payment-lightning-cln,sbproxy/payment-lightning-lnd'

  # clippy first: it compiles every target in the selection, so a type error
  # or a lint in never-built code surfaces before this phase pays for codegen.
  step "cargo clippy (payment settlement features)"
  cargo clippy --workspace --exclude sbproxy-e2e --all-targets --locked \
    --features "$payment_features" -- -D warnings

  # Narrow the tests, never the packages. The selection stays --workspace so
  # the feature union is the one clippy just checked; the filterset picks the
  # three crates carrying payment-gated code. `package(...)` rather than a
  # list of module names, because a payment test in a module nobody added to
  # a hand-maintained list would silently not run, which is this ticket's bug
  # wearing a different hat.
  step "cargo test (payment settlement features)"
  if cargo nextest --version >/dev/null 2>&1; then
    cargo nextest run --workspace --exclude sbproxy-e2e --locked --profile ci \
      --features "$payment_features" \
      -E 'package(sbproxy-billing) + package(sbproxy-core) + package(sbproxy-modules)'
  else
    # Reaching here means the main test phase already accepted the serial
    # fallback, so the missing nextest is not re-explained. What matters is
    # that filtersets have no `cargo test` equivalent: writing the same
    # narrowing as `-p sbproxy-billing -p sbproxy-core` would change the
    # package selection and therefore the feature union, so this runs the
    # whole selection rather than narrowing it wrong.
    note_skip "payment test narrowing (no nextest, so the serial fallback ran the whole workspace selection instead of the three payment-gated crates)"
    cargo test --workspace --exclude sbproxy-e2e --locked --features "$payment_features"
  fi
fi

# Closes the SBPROXY_SKIP_CARGO guard around every cargo phase.
fi

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
finish_step

print_skip_summary

if [ "$TREE_GUARD_FAILED" = "1" ]; then
  printf '\n\033[1;31mFAILED: the working tree is dirty (see above).\033[0m\n' >&2
  exit 1
fi

printf '\n\033[1;32mAll checks passed.\033[0m\n'
