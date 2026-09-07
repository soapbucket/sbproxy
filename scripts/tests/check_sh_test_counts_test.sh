#!/usr/bin/env bash
# `tests=` and `failures=` on the GATE_EXIT line are the whole run's
# totals, summed across every nextest lane, and `test_lanes=` names what
# each lane contributed.
#
# WOR-2951: every nextest lane in check.sh runs `--profile ci`, and that
# profile writes one junit file. The second lane overwrote the first, and
# cleanup read the survivor at exit, so a green run of 16020 tests and
# then 5961 reported `tests=5961`. .github/CONTRIBUTING-agents.md tells
# every contributor to quote that line instead of saying "green", so the
# figure went into PR bodies in two repositories for a week. It is the
# third defect in this line: WOR-2942 was `skipped_phases=` reading zero
# while two required lanes had not run, WOR-2945 was the block that
# explains the count not printing on the failure path, and this is the
# count.
#
# The failure mode is a number that stays plausible while meaning
# something else, so one green run proves nothing about it. The cases
# below force lanes with DIFFERENT counts and then take a lane away, so
# the assertion is on which direction the number moves and not only on
# what it says once.
#
# Nothing in this repository runs check.sh, so a fix to check.sh's own
# reporting has no lane behind it and reads exactly like a working one
# once it stops working. This file is that lane, beside
# check_sh_skip_summary_test.sh and built the same way: harnesses
# assembled out of the shipped lines, cut on anchors asserted unique
# first, and two mutation cases that put the old symptom back and require
# it to reappear.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="$ROOT/scripts/check.sh"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-test-counts-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT

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

# Through `trap cleanup EXIT`: the lane counters, junit_path,
# record_test_lane, run_test_lane, cleanup, and the trap itself.
# Everything below it is phases.
head_end="$(anchor_line '^trap cleanup EXIT$')"

mkdir -p "$TEST_DIR/scripts"
sed -n "1,${head_end}p" "$CHECK" >"$TEST_DIR/head.sh"

# A stand-in lane. Writes the junit root element nextest's ci profile
# writes, with the counts this case wants, and exits with the code this
# case wants. The attribute order and spelling are nextest's own, because
# the reader under test splits that element on spaces.
LANE_HELPERS=$(cat <<'HELPERS'
write_junit() {
  local tests="$1" failures="$2" junit
  junit="$(junit_path)"
  mkdir -p "$(dirname "$junit")"
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<testsuites name="nextest-run" tests="%s" failures="%s" errors="0" uuid="6f1b0c3e-0000-4000-8000-000000000000" timestamp="2026-09-07T00:00:00.000+00:00" time="1.000">\n' \
      "$tests" "$failures"
    printf '</testsuites>\n'
  } >"$junit"
}

# A lane that runs tests: writes its junit, then exits $3.
junit_lane() {
  write_junit "$1" "$2"
  return "$3"
}

# A lane that runs and writes no junit of its own. The serial `cargo
# test` fallback is the real one; nextest killed before it reports is
# the other.
silent_lane() {
  return "$1"
}
HELPERS
)

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

# The GATE_EXIT line minus `elapsed=`, which is a clock reading. Compared
# as one fixed string rather than field by field, so a field that moves,
# changes spelling, or disappears fails here instead of being skipped
# over by a grep that was only looking for the fields it knew about.
gate_line() {
  grep -o 'GATE_EXIT=.* elapsed=' "$TEST_DIR/$1.log" | head -1
}

expect_gate_line() {
  local name="$1" want="$2" got
  got="$(gate_line "$name" || true)"
  [ "$got" = "$want" ] \
    || fail "$name: GATE_EXIT line was
  [$got]
expected
  [$want]
  (full log at $TEST_DIR/$name.log)"
}

# head + helpers + whatever this case does, written as one harness.
write_harness() {
  local name="$1" head="$2"
  shift 2
  {
    cat "$TEST_DIR/$head"
    printf '%s\n' "$LANE_HELPERS"
    printf '%s\n' "$@"
  } >"$TEST_DIR/scripts/$name.sh"
}

# --- 1. two lanes with DIFFERENT counts: the line reports the total ----
# The reproduction from the ticket, minus the third lane that writes no
# junit. Before the fix this said tests=5961.
write_harness two_lanes head.sh \
  'step "probe workspace lane"' \
  'run_test_lane workspace junit_lane 16020 0 0' \
  'step "probe payments lane"' \
  'run_test_lane payments junit_lane 5961 0 0'

rc="$(run_harness two_lanes)"
[ "$rc" = "0" ] || fail "two_lanes: expected exit 0, got $rc"
expect_gate_line two_lanes \
  'GATE_EXIT=0 tests=21981 failures=0 test_lanes=workspace:16020+payments:5961 skipped_phases=0 elapsed='

# --- 2. take a lane away: the number moves the way that says so --------
# The half a single green run cannot prove. A total that did not fall
# when a lane stopped running would be reporting something other than
# what ran, which is the whole defect.
write_harness one_lane head.sh \
  'step "probe workspace lane"' \
  'run_test_lane workspace junit_lane 16020 0 0'

rc="$(run_harness one_lane)"
[ "$rc" = "0" ] || fail "one_lane: expected exit 0, got $rc"
expect_gate_line one_lane \
  'GATE_EXIT=0 tests=16020 failures=0 test_lanes=workspace:16020 skipped_phases=0 elapsed='
grep -q 'payments' "$TEST_DIR/one_lane.log" \
  && fail 'one_lane: the removed lane is still named in the output'

two_lanes_total="$(sed -n 's/.*tests=\([0-9]*\) .*/\1/p' <<<"$(gate_line two_lanes)")"
one_lane_total="$(sed -n 's/.*tests=\([0-9]*\) .*/\1/p' <<<"$(gate_line one_lane)")"
[ "$one_lane_total" -lt "$two_lanes_total" ] \
  || fail "removing a lane did not lower tests= ($one_lane_total vs $two_lanes_total); the total is not monotone in the lanes that ran"

# --- 3. a lane that goes red is still counted --------------------------
# A red lane ran its tests. Reporting tests=not-run for it would be the
# WOR-2945 shape one field over: a failing run told less than a passing
# one, at the moment a reader needs more.
write_harness red_lane head.sh \
  'step "probe workspace lane"' \
  'run_test_lane workspace junit_lane 16020 0 0' \
  'step "probe payments lane"' \
  'run_test_lane payments junit_lane 5961 3 100'

rc="$(run_harness red_lane)"
[ "$rc" = "100" ] || fail "red_lane: expected exit 100, got $rc"
expect_gate_line red_lane \
  'GATE_EXIT=100 tests=21981 failures=3 test_lanes=workspace:16020+payments:5961 failed_phase=probe payments lane skipped_phases=0 elapsed='

# --- 4. a lane that writes no junit is not credited with the last one --
# This is the overwrite bug from the other side. The counts are read from
# one path, so a lane that writes nothing would read the previous lane's
# file and be counted twice unless the file is deleted first. `unparsed`,
# not zero: a lane that ran and cannot be counted is a different answer
# from a lane that ran no tests.
write_harness silent_second head.sh \
  'step "probe workspace lane"' \
  'run_test_lane workspace junit_lane 5 0 0' \
  'step "probe fallback lane"' \
  'run_test_lane workspace-serial silent_lane 0'

rc="$(run_harness silent_second)"
[ "$rc" = "0" ] || fail "silent_second: expected exit 0, got $rc"
expect_gate_line silent_second \
  'GATE_EXIT=0 tests=5 failures=0 test_lanes=workspace:5+workspace-serial:unparsed skipped_phases=0 elapsed='

# --- 5. a junit left by an EARLIER run is not this run's work ----------
# The counts no longer depend on a file surviving until the trap, so they
# no longer depend on a file from last week being gone either. A run
# whose test phase never executed says not-run with a stale junit sitting
# on disk beside it.
write_harness stale_junit head.sh \
  'write_junit 99999 7' \
  'step "probe phase that runs no tests"' \
  'true'

rc="$(run_harness stale_junit)"
[ "$rc" = "0" ] || fail "stale_junit: expected exit 0, got $rc"
expect_gate_line stale_junit \
  'GATE_EXIT=0 tests=not-run failures=not-run test_lanes=none skipped_phases=0 elapsed='

# --- 6. the same battery against a version known to be broken ----------
# Two mutations, one per property, because a battery nobody has seen go
# red proves nothing. Each is proven to have applied before anything is
# drawn from its run: a mutation that never landed is indistinguishable
# in the output from one the code survived, and it is the more likely of
# the two.
mutate() {
  local from="$1" to="$2" out="$3" n
  n="$(grep -cF "$from" "$TEST_DIR/head.sh" || true)"
  [ "$n" = "1" ] \
    || fail "mutation target [$from] occurs $n times in the head, expected exactly 1; the code moved and this case is checking nothing"
  # Spliced by index and substr, never by a regex substitution: the
  # targets carry `$`, `(`, `)` and `|`, so `sed s///` and awk's own
  # `sub()` would read them as a pattern and quietly match nothing,
  # reporting a survived mutation that never landed. That is the exact
  # shape section 10 of the review rubric names, and it happened here on
  # the first attempt at this case.
  FROM="$from" TO="$to" awk '
    {
      i = index($0, ENVIRON["FROM"])
      if (i > 0) {
        $0 = substr($0, 1, i - 1) ENVIRON["TO"] \
          substr($0, i + length(ENVIRON["FROM"]))
      }
      print
    }
  ' "$TEST_DIR/head.sh" >"$TEST_DIR/$out"
  [ "$(grep -cF "$from" "$TEST_DIR/$out" || true)" = "0" ] \
    || fail "mutation [$from] did not apply"
  if [ -n "$to" ]; then
    [ "$(grep -cF "$to" "$TEST_DIR/$out" || true)" = "1" ] \
      || fail "mutation [$from] -> [$to] did not land its replacement"
  fi
  if cmp -s "$TEST_DIR/head.sh" "$TEST_DIR/$out"; then
    fail "mutation [$from] produced an identical file"
  fi
  bash -n "$TEST_DIR/$out" \
    || fail "mutation [$from] produced a file that does not parse, so its run proves nothing"
}

# 6a. Stop accumulating: each lane replaces the total instead of adding
# to it, which is what reading the surviving junit at exit amounted to.
# Case 1 must not survive this.
mutate 'GATE_TESTS_TOTAL=$((GATE_TESTS_TOTAL + tests))' \
       'GATE_TESTS_TOTAL=$((0 + tests))' \
       head_last_lane_wins.sh

write_harness two_lanes_last_wins head_last_lane_wins.sh \
  'step "probe workspace lane"' \
  'run_test_lane workspace junit_lane 16020 0 0' \
  'step "probe payments lane"' \
  'run_test_lane payments junit_lane 5961 0 0'

rc="$(run_harness two_lanes_last_wins)"
[ "$rc" = "0" ] || fail "two_lanes_last_wins: expected exit 0, got $rc"
grep -q 'tests=21981' "$TEST_DIR/two_lanes_last_wins.log" \
  && fail 'two_lanes_last_wins: the total survived a mutation that stops the summing, so case 1 proves nothing'
grep -q 'tests=5961 ' "$TEST_DIR/two_lanes_last_wins.log" \
  || fail 'two_lanes_last_wins: expected the WOR-2951 symptom back, the last lane reported as the run'

# 6b. Stop deleting the previous lane's junit. Case 4's silent lane then
# inherits it and is counted twice, which is the same bug reading
# forwards instead of backwards.
mutate 'rm -f "$(junit_path)" 2>/dev/null || true' \
       ': WOR_2951_MUTATION_NO_DELETE' \
       head_no_delete.sh

write_harness silent_second_no_delete head_no_delete.sh \
  'step "probe workspace lane"' \
  'run_test_lane workspace junit_lane 5 0 0' \
  'step "probe fallback lane"' \
  'run_test_lane workspace-serial silent_lane 0'

rc="$(run_harness silent_second_no_delete)"
[ "$rc" = "0" ] || fail "silent_second_no_delete: expected exit 0, got $rc"
grep -q 'tests=5 ' "$TEST_DIR/silent_second_no_delete.log" \
  && fail 'silent_second_no_delete: the count held without the delete, so case 4 proves nothing'
grep -q 'tests=10 ' "$TEST_DIR/silent_second_no_delete.log" \
  || fail 'silent_second_no_delete: expected the silent lane to be credited with the previous lane double-counted'

printf 'check.sh test-count self-test: 7 cases passed (5 behaviors, 2 mutations)\n'
