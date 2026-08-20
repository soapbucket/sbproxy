#!/usr/bin/env bash
# Branch tests for scripts/lib/fuzz-cadence.sh.
#
# The fuzz phase in check.sh is the one phase most machines cannot run:
# cargo-fuzz is nightly-only and a plain cargo install has neither nightly
# nor cargo-fuzz. That makes its decision logic the part most likely to rot
# unnoticed, in either direction. A cadence that never fires reproduces the
# dead `run-fuzz` CI label this phase replaced; a skip that reads like a
# pass is worse than no phase at all. Both directions are asserted here,
# against fake toolchains and a sandbox stamp, so neither needs a nightly
# toolchain to test.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-fuzz-cadence-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_equal() {
  local expected="$1" actual="$2" label="$3"
  if [ "$actual" != "$expected" ]; then
    printf 'FAIL: %s\nexpected: %s\nactual:   %s\n' \
      "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

assert_contains() {
  local needle="$1" haystack="$2" label="$3"
  case "$haystack" in
    *"$needle"*) ;;
    *)
      printf 'FAIL: %s\nexpected to contain: %s\nactual:\n%s\n' \
        "$label" "$needle" "$haystack" >&2
      exit 1
      ;;
  esac
}

write_executable() {
  local path="$1"
  shift
  printf '%s\n' '#!/usr/bin/env bash' "$@" >"$path"
  chmod +x "$path"
}

# The caller's own fuzz settings must not leak into any case below.
unset SBPROXY_CHECK_FUZZ SBPROXY_FUZZ_STATE_DIR SBPROXY_FUZZ_TARGET_DIR \
  SBPROXY_FUZZ_CORPUS_DIR SBPROXY_FUZZ_MAX_AGE_DAYS SBPROXY_FUZZ_SECONDS

# shellcheck source=scripts/lib/fuzz-cadence.sh
. "$ROOT/scripts/lib/fuzz-cadence.sh"

STATE_DIR="$TEST_DIR/state"
mkdir -p "$STATE_DIR"
STAMP="$STATE_DIR/fuzz-last-pass"

# --- fake toolchains ----------------------------------------------------
#
# Four PATH sets, one per rung of the prerequisite ladder. PATH is replaced
# rather than prefixed so a real rustup, cargo, or cargo-fuzz on the
# developer's machine cannot decide the answer; /usr/bin and /bin stay on
# it because the library shells out to date and head.
mkdir -p "$TEST_DIR/bin-full" "$TEST_DIR/bin-no-rustup" \
  "$TEST_DIR/bin-no-nightly" "$TEST_DIR/bin-no-cargo-fuzz"

for dir in bin-full bin-no-nightly bin-no-cargo-fuzz; do
  write_executable "$TEST_DIR/$dir/rustup" 'printf "rustup 1.28.0\n"'
done
for dir in bin-full bin-no-rustup bin-no-nightly; do
  write_executable "$TEST_DIR/$dir/cargo-fuzz" 'printf "cargo-fuzz 0.12.0\n"'
done
for dir in bin-full bin-no-rustup bin-no-cargo-fuzz; do
  # The single quotes keep these expansions for the generated fixture.
  # shellcheck disable=SC2016
  write_executable "$TEST_DIR/$dir/cargo" \
    'if [ "${1:-}" = "+nightly" ]; then printf "cargo 1.99.0-nightly\n"; exit 0; fi' \
    'printf "cargo 1.95.0\n"'
done
# The shape a machine with rustup but no nightly toolchain installed has:
# cargo answers, `cargo +nightly` does not.
# shellcheck disable=SC2016  # same, for the generated fixture
write_executable "$TEST_DIR/bin-no-nightly/cargo" \
  'if [ "${1:-}" = "+nightly" ]; then' \
  '  printf "error: toolchain '"'"'nightly'"'"' is not installed\n" >&2' \
  '  exit 1' \
  'fi' \
  'printf "cargo 1.95.0\n"'

# --- helpers ------------------------------------------------------------

# write_stamp <days-ago>; a negative value dates the stamp into the future.
write_stamp() {
  printf '%s\n' "$(($(date +%s) - ($1 * 86400)))" >"$STAMP"
}

# plan <bin-dir> [VAR=VALUE]...
plan() {
  local bindir="$TEST_DIR/$1"
  shift
  (
    PATH="$bindir:/usr/bin:/bin"
    hash -r
    # shellcheck disable=SC2030  # subshell-local on purpose: each case gets
    # its own environment and must not leak into the next one
    export SBPROXY_FUZZ_STATE_DIR="$STATE_DIR"
    while [ "$#" -gt 0 ]; do
      export "${1?}"
      shift
    done
    fuzz_phase_plan
  )
}

# --- the cadence --------------------------------------------------------

rm -f "$STAMP"
assert_equal 'run|no recorded pass on this machine' "$(plan bin-full)" \
  'a machine that has never fuzzed is due'

write_stamp 0
assert_equal \
  'skip-fresh|last pass 0 day(s) ago, cadence is 7 day(s); next run due in 7. SBPROXY_CHECK_FUZZ=1 forces one now' \
  "$(plan bin-full)" \
  'a pass today is inside the window'

write_stamp 6
assert_equal \
  'skip-fresh|last pass 6 day(s) ago, cadence is 7 day(s); next run due in 1. SBPROXY_CHECK_FUZZ=1 forces one now' \
  "$(plan bin-full)" \
  'the last day inside the window is still a skip'

write_stamp 7
assert_equal 'run|last pass 7 day(s) ago, cadence is 7 day(s)' "$(plan bin-full)" \
  'the cadence boundary itself is due'

write_stamp 30
assert_equal 'run|last pass 30 day(s) ago, cadence is 7 day(s)' "$(plan bin-full)" \
  'a long-stale stamp is due'

write_stamp 3
assert_equal 'run|last pass 3 day(s) ago, cadence is 3 day(s)' \
  "$(plan bin-full SBPROXY_FUZZ_MAX_AGE_DAYS=3)" \
  'SBPROXY_FUZZ_MAX_AGE_DAYS moves the window'

write_stamp 3
assert_equal \
  'skip-fresh|last pass 3 day(s) ago, cadence is 30 day(s); next run due in 27. SBPROXY_CHECK_FUZZ=1 forces one now' \
  "$(plan bin-full SBPROXY_FUZZ_MAX_AGE_DAYS=30)" \
  'a wider window keeps a recent pass fresh'

# --- stamps this file cannot trust read as `never` ----------------------
#
# Every one of these could otherwise silence the phase forever, which is
# the failure this whole file exists to prevent.

printf 'not-a-number\n' >"$STAMP"
assert_equal 'run|no recorded pass on this machine' "$(plan bin-full)" \
  'a non-numeric stamp must not be trusted'

: >"$STAMP"
assert_equal 'run|no recorded pass on this machine' "$(plan bin-full)" \
  'an empty stamp must not be trusted'

write_stamp -1
assert_equal 'run|no recorded pass on this machine' "$(plan bin-full)" \
  'a stamp dated in the future must not be trusted'

# --- the overrides ------------------------------------------------------

write_stamp 0
assert_equal 'run|SBPROXY_CHECK_FUZZ=1 forced a run' \
  "$(plan bin-full SBPROXY_CHECK_FUZZ=1)" \
  'SBPROXY_CHECK_FUZZ=1 overrides a fresh stamp'

rm -f "$STAMP"
assert_equal 'skip-off|SBPROXY_CHECK_FUZZ=0' \
  "$(plan bin-full SBPROXY_CHECK_FUZZ=0)" \
  'SBPROXY_CHECK_FUZZ=0 overrides a due cadence'

write_stamp 30
assert_equal 'skip-off|SBPROXY_CHECK_FUZZ=0' \
  "$(plan bin-no-rustup SBPROXY_CHECK_FUZZ=0)" \
  'an explicit off is not overruled by a missing toolchain'

# --- the prerequisite ladder --------------------------------------------
#
# Each rung names the next thing to install rather than the last thing that
# failed. rustup is probed before nightly because without rustup the
# +nightly attempt reports `no such command: +nightly`, which sends the
# reader after the wrong problem.

write_stamp 30
assert_equal 'skip-missing|rustup' "$(plan bin-no-rustup)" \
  'no rustup names rustup'
assert_equal 'skip-missing|nightly' "$(plan bin-no-nightly)" \
  'rustup without a nightly toolchain names nightly'
assert_equal 'skip-missing|cargo-fuzz' "$(plan bin-no-cargo-fuzz)" \
  'a nightly toolchain without cargo-fuzz names cargo-fuzz'

# Inside the window a missing toolchain is not worth a word. The loud
# message is for a run that was actually due.
write_stamp 1
assert_equal \
  'skip-fresh|last pass 1 day(s) ago, cadence is 7 day(s); next run due in 6. SBPROXY_CHECK_FUZZ=1 forces one now' \
  "$(plan bin-no-rustup)" \
  'a fresh stamp does not nag about a missing toolchain'

# --- the install hint ---------------------------------------------------
#
# This text is the whole defense against a skip that reads like a pass, so
# assert that it names the three commands in install order.
hint="$(fuzz_prereq_hint rustup)"
assert_contains 'DID NOT run' "${hint/did NOT run/DID NOT run}" \
  'the hint must say the phase did not run'
assert_contains 'https://sh.rustup.rs' "$hint" 'the hint installs rustup'
assert_contains 'rustup toolchain install nightly' "$hint" \
  'the hint installs the nightly toolchain'
assert_contains 'cargo install cargo-fuzz' "$hint" 'the hint installs cargo-fuzz'
assert_contains 'SBPROXY_CHECK_FUZZ=0' "$hint" 'the hint names the mute'

# --- recording a pass ---------------------------------------------------

rm -rf "$STATE_DIR"
(
  # shellcheck disable=SC2031  # the subshell is the point; the assertions
  # below read the stamp off disk rather than out of the environment
  export SBPROXY_FUZZ_STATE_DIR="$STATE_DIR"
  fuzz_record_pass
)
[ -f "$STAMP" ] || fail 'fuzz_record_pass must create the stamp and its directory'
assert_equal '0' "$(SBPROXY_FUZZ_STATE_DIR="$STATE_DIR" fuzz_stamp_age_days)" \
  'a stamp just written reads as today'
assert_contains 'last clean scripts/check.sh fuzz phase' "$(cat "$STAMP")" \
  'the stamp explains itself to whoever opens it'
assert_equal \
  'skip-fresh|last pass 0 day(s) ago, cadence is 7 day(s); next run due in 7. SBPROXY_CHECK_FUZZ=1 forces one now' \
  "$(plan bin-full)" \
  'recording a pass closes the window'

# --- paths --------------------------------------------------------------
#
# The stamp and both cargo directories must be per machine and outside the
# repository. Inside the tree they would be per worktree, and this checkout
# carries about thirty worktrees at a time: every new branch directory
# would read as a machine that has never fuzzed and would pay a cold
# multi-gigabyte nightly build on its first gate.
default_stamp="$(XDG_STATE_HOME="$TEST_DIR/xdg-state" fuzz_stamp_path)"
assert_equal "$TEST_DIR/xdg-state/sbproxy/fuzz-last-pass" "$default_stamp" \
  'the stamp defaults under XDG_STATE_HOME'
default_target="$(XDG_CACHE_HOME="$TEST_DIR/xdg-cache" fuzz_target_dir)"
assert_equal "$TEST_DIR/xdg-cache/sbproxy/fuzz-target" "$default_target" \
  'the fuzz target dir defaults under XDG_CACHE_HOME'
default_corpus="$(XDG_CACHE_HOME="$TEST_DIR/xdg-cache" fuzz_corpus_dir)"
assert_equal "$TEST_DIR/xdg-cache/sbproxy/fuzz-corpus" "$default_corpus" \
  'the writable corpus dir defaults under XDG_CACHE_HOME'

for path in "$default_stamp" "$default_target" "$default_corpus"; do
  case "$path" in
    "$ROOT"/*) fail "fuzz state must not live inside the repository: $path" ;;
  esac
done

assert_equal '/tmp/override' "$(SBPROXY_FUZZ_TARGET_DIR=/tmp/override fuzz_target_dir)" \
  'SBPROXY_FUZZ_TARGET_DIR wins'
assert_equal '/tmp/override' "$(SBPROXY_FUZZ_CORPUS_DIR=/tmp/override fuzz_corpus_dir)" \
  'SBPROXY_FUZZ_CORPUS_DIR wins'
assert_equal '7' "$(fuzz_max_age_days)" 'the cadence defaults to a week'
assert_equal '15' "$(fuzz_seconds_per_target)" 'the budget defaults to 15s a target'
assert_equal '2' "$(SBPROXY_FUZZ_MAX_AGE_DAYS=2 fuzz_max_age_days)" \
  'SBPROXY_FUZZ_MAX_AGE_DAYS wins'
assert_equal '45' "$(SBPROXY_FUZZ_SECONDS=45 fuzz_seconds_per_target)" \
  'SBPROXY_FUZZ_SECONDS wins'

printf 'PASS: the fuzz cadence fires on schedule and never skips silently\n'
