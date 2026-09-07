#!/usr/bin/env bash
# The SKIPPED PHASES block prints on the failing path as well as the
# passing one, exactly once on each, and the GATE_EXIT line names the
# phase that failed.
#
# WOR-2945: check.sh emitted the block only from the end of the script,
# which a failing phase never reaches, so a red gate printed
# `skipped_phases=N` with nothing naming those N phases and no command to
# run them. That line is what .github/CONTRIBUTING-agents.md tells every
# contributor to quote instead of saying "green", and a red gate is when
# a reader most needs to know what else did not run. WOR-2942 was the
# same instrument one step back, the count reading zero while two
# required lanes had not run.
#
# Nothing in this repository runs check.sh, so a fix to check.sh's own
# reporting has no lane behind it and reads exactly like a working one
# once it stops working. This file is that lane. It assembles harnesses
# out of the shipped lines rather than restating them: the head up to the
# EXIT trap, and the real end-of-script tail, cut on anchors that are
# asserted to be unique first. The fourth case mutates the fix back out
# and requires the failure to reappear, because a battery nobody has seen
# go red proves nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="$ROOT/scripts/check.sh"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-skip-summary-test.XXXXXX")"
# Kept on a red run. The failure messages below name logs inside this
# directory, and a trap that deletes it unconditionally makes every one
# of those pointers dead on the single run where somebody follows one.
trap 'rc=$?; if [ "$rc" = 0 ]; then rm -rf "$TEST_DIR"; else printf "harness kept at %s\n" "$TEST_DIR" >&2; fi' EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

# Cutting a harness out of a file on a pattern that matches twice, or
# zero times, assembles something that is not the code under test and
# then passes. Assert the anchor is unique before cutting on it.
anchor_line() {
  local pattern="$1" n
  n="$(grep -c "$pattern" "$CHECK" || true)"
  [ "$n" = "1" ] \
    || fail "anchor /$pattern/ matched $n lines in scripts/check.sh, expected exactly 1"
  grep -n "$pattern" "$CHECK" | cut -d: -f1
}

# Through `trap cleanup EXIT`: note_skip, print_skip_summary, cleanup,
# and the trap itself. Everything below it is phases.
head_end="$(anchor_line '^trap cleanup EXIT$')"
# The end-of-script call and the working-tree guard under it. The other
# print_skip_summary call site is indented inside cleanup, so a
# column-zero match picks out this one.
tail_start="$(anchor_line '^print_skip_summary$')"
# The tail restores STEP_LABEL from this constant, which is defined above
# the cut. Taken from the file rather than retyped here so the harness
# cannot disagree with the script about its own phase name.
tree_label_at="$(anchor_line '^TREE_GUARD_LABEL=')"

mkdir -p "$TEST_DIR/scripts"
sed -n "1,${head_end}p" "$CHECK" >"$TEST_DIR/head.sh"
sed -n "${tree_label_at}p" "$CHECK" >"$TEST_DIR/tree_label.sh"
sed -n "${tail_start},\$p" "$CHECK" >"$TEST_DIR/tail.sh"

PROBE_SKIP='PROBE LANE (required): did not run here. Run it with: probe-lane-command'

# A harness lives under $TEST_DIR/scripts/ so the head's ROOT resolves to
# $TEST_DIR and not to this repository. SBPROXY_CLEAN_AFTER_BUILD=0 keeps
# cleanup from reaching for the artifact pruner, which is not vendored
# into the sandbox.
run_harness() {
  local name="$1" rc=0
  ( cd "$TEST_DIR" && SBPROXY_CLEAN_AFTER_BUILD=0 bash "$TEST_DIR/scripts/$name.sh" ) \
    >"$TEST_DIR/$name.log" 2>&1 || rc=$?
  printf '%s' "$rc"
}

count_blocks() {
  grep -c 'SKIPPED PHASES' "$TEST_DIR/$1.log" || true
}

line_of() {
  grep -n "$2" "$TEST_DIR/$1.log" | head -1 | cut -d: -f1
}

require() {
  grep -q "$2" "$TEST_DIR/$1.log" \
    || fail "$3 (looked for /$2/ in $TEST_DIR/$1.log)"
}

# --- 1. a phase fails: the block prints, above the line it explains ----
{
  cat "$TEST_DIR/head.sh"
  printf 'note_skip "%s"\n' "$PROBE_SKIP"
  printf 'step "probe phase"\n'
  printf 'false\n'
} >"$TEST_DIR/scripts/red_phase.sh"

rc="$(run_harness red_phase)"
[ "$rc" = "1" ] || fail "red_phase: expected exit 1, got $rc"
[ "$(count_blocks red_phase)" = "1" ] \
  || fail "red_phase: expected exactly one SKIPPED PHASES block, got $(count_blocks red_phase)"
require red_phase 'PROBE LANE (required)' 'red_phase: the block does not name the skipped phase'
require red_phase 'probe-lane-command' 'red_phase: the block does not carry the enabling command'
require red_phase 'failed_phase=probe phase' 'red_phase: GATE_EXIT does not name the failing phase'
require red_phase 'skipped_phases=1' 'red_phase: GATE_EXIT does not count the skip'
require red_phase 'This run STOPPED in: probe phase' \
  'red_phase: the block does not say the run was cut short, so it reads as the whole unrun set'
block_at="$(line_of red_phase 'SKIPPED PHASES')"
exit_at="$(line_of red_phase 'GATE_EXIT=')"
[ "$block_at" -lt "$exit_at" ] \
  || fail "red_phase: the block printed at line $block_at, below GATE_EXIT at $exit_at"

# --- 2. the run finishes: one block, and the success line is unchanged -
{
  cat "$TEST_DIR/head.sh"
  printf 'note_skip "%s"\n' "$PROBE_SKIP"
  printf 'TREE_GUARD_FAILED=0\n'
  cat "$TEST_DIR/tree_label.sh"
  cat "$TEST_DIR/tail.sh"
} >"$TEST_DIR/scripts/green.sh"

rc="$(run_harness green)"
[ "$rc" = "0" ] || fail "green: expected exit 0, got $rc"
[ "$(count_blocks green)" = "1" ] \
  || fail "green: expected exactly one SKIPPED PHASES block, got $(count_blocks green)"
require green 'GATE_EXIT=0' 'green: no successful GATE_EXIT line'
require green 'All checks passed' 'green: the success line did not print'
grep -q 'This run STOPPED in' "$TEST_DIR/green.log" \
  && fail 'green: a finished run was told it stopped early'

# --- 3. the working-tree guard fails after the block already printed ---
# The one path that exits non-zero having already emitted the block. It
# is the reason the trap is guarded on a flag and not on the exit code,
# and it is where failed_phase= used to read `unknown` because
# finish_step had cleared the label.
{
  cat "$TEST_DIR/head.sh"
  printf 'note_skip "%s"\n' "$PROBE_SKIP"
  printf 'TREE_GUARD_FAILED=1\n'
  printf "STEP_LABEL=''\n"
  cat "$TEST_DIR/tree_label.sh"
  cat "$TEST_DIR/tail.sh"
} >"$TEST_DIR/scripts/red_tree_guard.sh"

rc="$(run_harness red_tree_guard)"
[ "$rc" = "1" ] || fail "red_tree_guard: expected exit 1, got $rc"
[ "$(count_blocks red_tree_guard)" = "1" ] \
  || fail "red_tree_guard: expected exactly one SKIPPED PHASES block, got $(count_blocks red_tree_guard); the print-once guard is not holding"
require red_tree_guard 'failed_phase=working tree matches HEAD' \
  'red_tree_guard: GATE_EXIT reports no phase for the failure this script diagnoses itself'

# --- 4. the same battery against a version known to be broken ----------
# Removing the trap's call reproduces the WOR-2945 shape: the count still
# reads 1 and no block explains it. If case 1 can pass here too, case 1
# is not testing anything. The mutation is proven to have applied before
# anything is drawn from the run, because a mutation that never landed is
# indistinguishable in the output from one the code survived.
# Matched as a fixed string, and only as far as the opening quote of its
# first argument, so a change to that argument does not silently stop the
# mutation from applying. If the call is reworded past this much, the
# count assertion below fails loudly rather than reporting a survived
# mutation that never landed.
mutant='print_skip_summary "'
[ "$(grep -cF "$mutant" "$TEST_DIR/head.sh" || true)" = "1" ] \
  || fail "mutation target [$mutant] is not present exactly once in the head; the fix moved and this case is checking nothing"
sed 's/print_skip_summary "/: "/' "$TEST_DIR/head.sh" >"$TEST_DIR/head_mutated.sh"
[ "$(grep -cF "$mutant" "$TEST_DIR/head_mutated.sh" || true)" = "0" ] \
  || fail "mutation did not apply"
if cmp -s "$TEST_DIR/head.sh" "$TEST_DIR/head_mutated.sh"; then
  fail "mutation produced an identical file"
fi

{
  cat "$TEST_DIR/head_mutated.sh"
  printf 'note_skip "%s"\n' "$PROBE_SKIP"
  printf 'step "probe phase"\n'
  printf 'false\n'
} >"$TEST_DIR/scripts/red_phase_mutated.sh"

rc="$(run_harness red_phase_mutated)"
[ "$rc" = "1" ] || fail "red_phase_mutated: expected exit 1, got $rc"
[ "$(count_blocks red_phase_mutated)" = "0" ] \
  || fail "red_phase_mutated: the block printed without the fix, so case 1 proves nothing"
require red_phase_mutated 'skipped_phases=1' \
  'red_phase_mutated: expected the WOR-2945 shape, a count with no block'

printf 'check.sh skip-summary self-test: 4 cases passed (3 behaviors, 1 mutation)\n'
