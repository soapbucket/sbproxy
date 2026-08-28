#!/usr/bin/env bash
# The pre-push check. Every gate check that needs no workspace build,
# run in parallel, in under a minute.
#
# `scripts/check.sh` is the gate and stays the gate. This is what you run
# before you push, and after every merge from main, so the failures that
# need no compiler are found in seconds instead of forty minutes into a
# CI round trip.
#
# On 2026-08-27 ten CI failures cost a full round trip each. Six of them
# were catchable here:
#
#   examples/README.md catalog stale after a merge from main
#   NOTICE stanza missing after a lockfile change
#   a docs anchor pointing at a heading another page had renamed
#   three `rust` code blocks in a new doc that did not compile standalone
#   a stale secret-resolver-drift-exemptions.json entry
#   stale nested lockfiles
#
# That is not a claim, it is a measurement. All six were injected into a
# clean tree at once on 2026-08-28 (a decremented example count, three
# deleted NOTICE lines, an anchor at a heading that does not exist, a
# `rust` block calling an undefined function, an exemption entry naming a
# finding that is not there, and a bumped version in
# bench-synthetic/Cargo.lock). This script exited 1 with exactly six red
# checks and nineteen green, naming each one.
#
# The other four need a compiler and are named in the NOT COVERED block
# this script prints on every run. Read that block. A green run here is
# not a green gate, and the difference is written down rather than
# assumed.
#
# Two of the six were not checked by ANY local runner before this
# existed: `scripts/docs-ci.sh` compiles the `rust` code blocks and
# resolves every in-tree anchor, and `scripts/check.sh` never called it.
# It is named in six comments there as the CI lane a phase mirrors, and
# invoked in none of them.
#
# Usage:
#
#   bash scripts/check-fast.sh              # everything
#   bash scripts/check-fast.sh --list       # name the checks and exit
#   CHECK_FAST_JOBS=4 bash scripts/check-fast.sh
#
# Exits non-zero naming every check that failed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PYTHONDONTWRITEBYTECODE=1

# Every entry is "name|command". Order is display order; execution is
# concurrent. A check belongs here only if it needs no workspace build:
# reading the tree, running rustc on an isolated snippet, or resolving a
# lockfile with `cargo metadata --locked` all qualify, and anything that
# compiles a crate does not.
#
# `cargo fmt` and `cargo metadata` are the two cargo invocations in this
# list. Neither builds anything: rustfmt parses, and metadata resolves
# and refuses to rewrite the lockfile. Both finish in about a second on a
# cold tree.
CHECKS=(
  # --- Longest first. The pool launches in array order and the slowest
  # check sets the wall clock, so the three tree-wide ratchet scans go
  # ahead of twenty cheap ones that would otherwise delay them. Measured
  # standalone on the reference machine: 32.8s, 33.5s, 29.2s. Launched
  # last they finished at 58s, 52s, and 36s under contention and the run
  # took 60s; launched first the run is bounded by the slowest scan.
  "pub items whose only consumer is a test|bash scripts/check-pub-item-ratchet.sh"
  "operator URLs at log lines|bash scripts/check-log-url-ratchet.sh"
  "unwrap/expect/panic in production code|bash scripts/check-unwrap-ratchet.sh"
  "secret-resolver drift|python3 scripts/check-secret-resolver-drift.py"

  # --- The two docs-ci halves. These are the ones nothing ran locally.
  "docs rust and bash code blocks|bash scripts/docs-ci.sh --code"
  "docs anchors and links|bash scripts/docs-ci.sh --links"

  # --- Source scans. Pure grep and python.
  "durable sinks create files owner-only|bash scripts/check-durable-file-modes.sh"
  "secret-bearing types do not derive Debug|bash scripts/check-secret-debug-registry.sh"
  "tapes do not render credentials|bash scripts/check-tape-secrets.sh"
  "no env mutation outside test helpers|bash scripts/check-env-mutation.sh"
  "doc drift|bash scripts/check-doc-drift.sh"
  "spec citation hygiene|bash scripts/check-spec-citations.sh"

  # --- Formatting. rustfmt parses; it does not build.
  "cargo fmt --check|cargo fmt --all -- --check"

  # --- Dependency hygiene. cargo metadata resolves; it does not compile.
  "standalone workspace lockfiles are current|bash scripts/check-nested-lockfiles.sh"
  "NOTICE covers Apache-2.0-only crates|bash scripts/check-notice.sh"

  # --- Generated files that a merge from main leaves stale.
  "documented command output (structural)|python3 scripts/check-doc-captures.py --check --stackless-only"
  "examples catalog is current|python3 scripts/gen-examples-catalog.py --check"
  "doc configs match canonical examples|python3 scripts/sync-doc-configs.py --check"
  "every promised doc asset exists|python3 scripts/check-doc-assets.py"

  # --- Ratchets whose scan is cheap.
  "every stable metric has a dashboard panel|bash scripts/check-metric-visibility.sh"

  # --- Things a merge breaks.
  "no committed merge-conflict markers|check_conflict_markers"
  "no internal tracker placeholders|check_tracker_placeholders"
  "changelog entries are fragments|python3 scripts/changelog-fragments.py --check"

  # --- Parsers whose refusals the gate depends on.
  "review-evidence parser fixtures|python3 scripts/check-review-evidence.py --self-test"
  "diff-scope classifier corpus|python3 scripts/gate-scope.py --self-test"
)

check_conflict_markers() {
  if git grep -nE '^(<{7} |={7}$|>{7} )' -- ':!*.lock' ':!docs/llms-full.txt'; then
    printf '\ncommitted merge-conflict markers found; resolve the merge for real.\n' >&2
    return 1
  fi
  printf 'no conflict markers in tracked files\n'
}

check_tracker_placeholders() {
  if grep -rn 'WOR-XXX' crates/ --include='*.rs' --include='*.toml'; then
    printf '\nWOR-XXX placeholders are not allowed in crates/.\n' >&2
    return 1
  fi
  printf 'no WOR-XXX placeholders under crates/\n'
}

export -f check_conflict_markers check_tracker_placeholders 2>/dev/null || true

if [ "${1:-}" = "--list" ]; then
  for entry in "${CHECKS[@]}"; do
    printf '%s\n' "${entry%%|*}"
  done
  exit 0
fi

JOBS="${CHECK_FAST_JOBS:-0}"
if ! [ "$JOBS" -gt 0 ] 2>/dev/null; then
  JOBS="$( (getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) )"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-check-fast.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

START="$(date +%s)"

printf '\033[1mcheck-fast\033[0m: %s checks, %s at a time\n\n' "${#CHECKS[@]}" "$JOBS"

running=0
index=0
for entry in "${CHECKS[@]}"; do
  name="${entry%%|*}"
  command="${entry#*|}"
  slot="$WORK/$index"
  printf '%s\n' "$name" >"$slot.name"
  (
    started="$(date +%s)"
    # `bash -c` rather than eval so a check that is a shell function and
    # a check that is an external command run through the same path.
    bash -c "cd '$ROOT'; $command" >"$slot.log" 2>&1
    rc=$?
    printf '%s' "$rc" >"$slot.rc"
    printf '%s' "$(( $(date +%s) - started ))" >"$slot.time"
  ) &
  index=$((index + 1))
  running=$((running + 1))
  if [ "$running" -ge "$JOBS" ]; then
    wait -n 2>/dev/null || wait
    running=$((running - 1))
  fi
done
wait

FAILED=()
SLOWEST=''
for i in $(seq 0 $((index - 1))); do
  slot="$WORK/$i"
  name="$(cat "$slot.name")"
  rc="$(cat "$slot.rc" 2>/dev/null || echo 1)"
  elapsed="$(cat "$slot.time" 2>/dev/null || echo '?')"
  if [ "$rc" = "0" ]; then
    printf '  \033[32mok\033[0m    %5ss  %s\n' "$elapsed" "$name"
  else
    printf '  \033[1;31mFAIL\033[0m  %5ss  %s (exit %s)\n' "$elapsed" "$name" "$rc"
    FAILED+=("$name")
  fi
  SLOWEST="${SLOWEST}${elapsed} ${name}"$'\n'
done

ELAPSED=$(( $(date +%s) - START ))

for i in $(seq 0 $((index - 1))); do
  slot="$WORK/$i"
  rc="$(cat "$slot.rc" 2>/dev/null || echo 1)"
  [ "$rc" = "0" ] && continue
  printf '\n\033[1;31m--- %s ---\033[0m\n' "$(cat "$slot.name")"
  sed 's/^/  /' "$slot.log"
done

cat <<'MSG'

------------------------------------------------------------------------
NOT COVERED HERE. These four of the ten CI failures need a compiler,
so a green run above says nothing about them:

  * a private intra-doc link
      RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc --workspace
      --no-deps --locked  (the `cargo doc` phase of scripts/check.sh)
  * clippy::items_after_test_module under the payment features
      the payments phase of scripts/check.sh, which is on by default,
      and CI's `payments clippy (settlement features)` lane
  * a path-shaped config key missing from HOST_FILE_KEYS
      the every_path_shaped_schema_key_is_covered_or_explained test in
      crates/sbproxy-config, which the workspace test lane runs
  * a config key whose committed schema was never regenerated
      bash scripts/check-config-schema.sh, which execs a built
      generate-schema (the `generated artifacts are current` CI step);
      scripts/post-merge-rederive.sh rewrites it

Nor does anything here run the workspace build, test, clippy, or rustdoc
lanes, or the UI lane. Run `bash scripts/check.sh` before you push.
------------------------------------------------------------------------
MSG

printf '\n\033[1mslowest:\033[0m\n'
printf '%s' "$SLOWEST" | sort -rn | head -3 | sed 's/^/  /'

if [ "${#FAILED[@]}" -gt 0 ]; then
  printf '\n\033[1;31mcheck-fast FAILED in %ss: %s of %s checks red\033[0m\n' \
    "$ELAPSED" "${#FAILED[@]}" "${#CHECKS[@]}" >&2
  for name in "${FAILED[@]}"; do
    printf '  * %s\n' "$name" >&2
  done
  exit 1
fi

printf '\n\033[1;32mcheck-fast passed in %ss (%s checks).\033[0m\n' "$ELAPSED" "${#CHECKS[@]}"
