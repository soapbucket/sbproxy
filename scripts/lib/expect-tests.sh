#!/usr/bin/env bash
# Assert how many tests a filtered selection actually ran.
#
# `cargo test` exits 0 when its filter matches nothing. So does `--exact`,
# and so does `--ignored`. The run prints
#
#     test result: ok. 0 passed; 0 failed; 0 ignored; 2857 filtered out
#
# and the step goes green having checked nothing. A renamed test, a
# removed `#[ignore]`, a `--test` target whose contents moved: any of
# those turns a named selection into a no-op that reports success.
#
# That is not hypothetical here. It reached `main` three times in one
# change on 2026-08-28, in a test helper, in a CI step, and in a
# workflow, and two of the three were caught by luck. One of them
# printed the line above, with 2,857 tests filtered out and a green
# exit, while claiming to enforce the stack budget of the request path
# that was overflowing at the time.
#
# The remedy is the one `.github/workflows/request-path-smoke.yml`
# reached for after the third: count the tests that ran and compare the
# count against what the selection is supposed to name. It is the same
# thing `scripts/check.sh` does with the junit `tests="N"` attribute
# when it prints GATE_EXIT, for the same reason: an exit code cannot
# tell a full run from an empty one.
#
# Usage:
#
#   . scripts/lib/expect-tests.sh
#   expect_tests 2 "request-path stack budget" -- \
#     cargo test -p sbproxy-core --locked --lib name -- --nocapture
#
#   expect_tests '>=1' "redis integration lane" -- \
#     cargo nextest run --profile ci -E 'binary(redis_secure)'
#
# The count spec is either an exact integer or `>=N`. Prefer the exact
# form: a selection that names two tests and runs one is as wrong as one
# that runs none, and `>=1` cannot see that. `>=N` is for a selection
# whose membership legitimately moves, such as a whole package or a
# binary, where the assertion worth having is "this selected something".
#
# It fails when the command fails, when the count does not satisfy the
# spec, and when no count can be read out of the output at all. That
# last one is the point: a helper that cannot tell how many tests ran
# has to say so rather than assume the answer it was hoping for.
#
# Run the fixtures with `bash scripts/lib/expect-tests.sh --self-test`.

# tests_run_from_output <file>
#
# Prints the number of tests that ran, or nothing when the output holds
# no count. Handles both harnesses:
#
#   libtest:  test result: ok. 12 passed; 0 failed; 0 ignored; 3 filtered out
#   nextest:  Summary [   1.815s] 14 tests run: 14 passed, 2580 skipped
#   nextest:  Summary [   0.014s] 1 test run: 1 passed, 2 skipped
#
# nextest pluralizes the noun and libtest does not, so the singular form
# is a real shape and not a hypothetical: it is what a filterset naming
# one test prints on a green tree, which is four of the twelve sites that
# name individual tests. The first version of this required ` tests run`
# and could
# not read it, so `.github/workflows/docs-ci.yml` would have failed
# closed on every clean run with "produced no test count to read". Both
# forms are in the fixtures below, taken verbatim from real
# `cargo nextest run` output rather than written by hand.
#
# `cargo test` prints one `test result:` line per test binary, so the
# libtest counts are summed. nextest prints one summary for the whole
# run, so its count is taken as it stands; a `Summary` line wins over
# any `test result:` line, because nextest also echoes the binaries'
# own output under some settings.
tests_run_from_output() {
  local file="$1"
  local plain nextest libtest

  # Strip ANSI colour first. Seven workflows call this now (ci.yml,
  # docs-ci.yml, payments-e2e.yml, release.yml, release-checks.yml,
  # request-path-smoke.yml, synthetic.yml) and six of the seven set
  # `CARGO_TERM_COLOR: always` at the workflow level; docs-ci.yml is the
  # one that does not. nextest colours its Summary line even when its
  # output is piped. An escape sequence between `Summary` and the count
  # makes the count unreadable, which fails closed rather than lying, but
  # fails every wrapped step on a green tree. Strip it and read the
  # numbers. If you add a caller, this sentence is a count: check it.
  plain="$(LC_ALL=C sed $'s/\033\\[[0-9;]*[A-Za-z]//g' "$file")"

  nextest="$(printf '%s\n' "$plain" \
    | sed -n 's/.*Summary \[[^]]*\] *\([0-9][0-9]*\) tests\{0,1\} run.*/\1/p' \
    | tail -1)"
  if [ -n "$nextest" ]; then
    printf '%s' "$nextest"
    return 0
  fi

  libtest="$(printf '%s\n' "$plain" \
    | sed -n 's/^test result: [a-zA-Z]*\. \([0-9][0-9]*\) passed.*/\1/p' \
    | awk '{ total += $1 } END { if (NR > 0) print total }')"
  if [ -n "$libtest" ]; then
    printf '%s' "$libtest"
    return 0
  fi

  return 1
}

# count_satisfies <spec> <count>
count_satisfies() {
  local spec="$1" count="$2"
  case "$spec" in
    '>='*)
      [ "$count" -ge "${spec#>=}" ]
      ;;
    *)
      [ "$count" -eq "$spec" ]
      ;;
  esac
}

# expect_tests <spec> <label> -- <command...>
expect_tests() {
  local spec="$1" label="$2"
  shift 2
  if [ "${1:-}" = "--" ]; then
    shift
  fi

  case "$spec" in
    '>='[0-9]*|[0-9]*) ;;
    *)
      echo "expect_tests: bad count spec '$spec' (want N or >=N)" >&2
      return 1
      ;;
  esac

  local log rc count
  log="$(mktemp "${TMPDIR:-/tmp}/expect-tests.XXXXXX")"

  # The command's own output still reaches the terminal: these runs print
  # measurements a reviewer reads out of the log.
  #
  # `errexit` is turned off around the pipeline so the exit code can be
  # read and reported rather than killing the shell, and restored to
  # whatever the caller had. A helper that switches `set -e` on for a
  # script that did not ask for it changes how every later line behaves.
  local had_errexit=0
  case "$-" in *e*) had_errexit=1 ;; esac
  set +e
  "$@" 2>&1 | tee "$log"
  rc="${PIPESTATUS[0]}"
  [ "$had_errexit" -eq 1 ] && set -e

  if [ "$rc" -ne 0 ]; then
    rm -f "$log"
    echo "expect_tests: $label failed with exit $rc" >&2
    return "$rc"
  fi

  if ! count="$(tests_run_from_output "$log")"; then
    rm -f "$log"
    echo "expect_tests: $label produced no test count to read." >&2
    echo >&2
    echo "Neither a libtest 'test result:' line nor a nextest 'Summary'" >&2
    echo "line was in the output, so how many tests ran is unknown and" >&2
    echo "this cannot report success for it. If the command is not a" >&2
    echo "test run, do not wrap it in expect_tests." >&2
    return 1
  fi
  rm -f "$log"

  if ! count_satisfies "$spec" "$count"; then
    echo "expect_tests: $label ran $count tests, expected $spec." >&2
    echo >&2
    echo "A filtered selection that matches nothing exits 0, so the count" >&2
    echo "is the assertion and the exit code is not. A renamed or deleted" >&2
    echo "test turns this step into a no-op that reports success." >&2
    echo >&2
    echo "Fix the filter, or update the expected count in the same commit" >&2
    echo "that changes what it selects." >&2
    return 1
  fi

  echo "expect_tests: $label ran $count tests (expected $spec)"
}

# --- Fixtures ----------------------------------------------------------
#
# The parser is the part with edge cases, and a parser that has quietly
# stopped reading counts would make every caller fail closed at best and
# read a wrong number at worst. Proved before it is trusted.

_expect_tests_self_test() {
  local failures=0 tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/expect-tests-selftest.XXXXXX")"

  _case() {
    local name="$1" want="$2" text="$3" got
    printf '%s\n' "$text" > "$tmp/out"
    if ! got="$(tests_run_from_output "$tmp/out")"; then
      got="unreadable"
    fi
    if [ "$got" != "$want" ]; then
      echo "self-test: $name read '$got', expected '$want'" >&2
      failures=$((failures + 1))
    fi
  }

  # The exact line the smoke lane printed on 2026-08-28.
  _case "the zero-match line that shipped" 0 \
    "test result: ok. 0 passed; 0 failed; 0 ignored; 2857 filtered out; finished in 0.00s"
  _case "a normal libtest run" 2 \
    "test result: ok. 2 passed; 0 failed; 0 ignored; 2855 filtered out"
  _case "several test binaries are summed" 5 \
    "test result: ok. 2 passed; 0 failed
test result: ok. 3 passed; 0 failed"
  _case "a nextest summary" 14 \
    "    Summary [   1.815s] 14 tests run: 14 passed, 2580 skipped"
  # nextest pluralizes. These four lines are copied out of real
  # `cargo nextest run` output, not composed here: a filterset naming one
  # test prints "1 test run", which is what four of the twelve wrapped
  # sites see on a green tree, and what the first version of this parser
  # could not read.
  _case "a nextest summary for exactly one test" 1 \
    "     Summary [   0.014s] 1 test run: 1 passed, 2 skipped"
  _case "a nextest summary for exactly two tests" 2 \
    "     Summary [   0.009s] 2 tests run: 2 passed, 1 skipped"
  _case "a one-test nextest run that failed" 1 \
    "     Summary [   0.014s] 1 test run: 0 passed, 1 failed, 2 skipped"
  _case "one of two matched, which is the miss the count exists to catch" 1 \
    "     Summary [   0.011s] 1 test run: 1 passed, 1 skipped"
  _case "a nextest zero-match summary" 0 \
    "    Summary [   0.012s] 0 tests run: 0 passed, 2857 skipped"
  _case "nextest wins over an echoed libtest line" 14 \
    "test result: ok. 99 passed; 0 failed
    Summary [   1.815s] 14 tests run: 14 passed, 2580 skipped"
  _case "a FAILED libtest line still counts what passed" 3 \
    "test result: FAILED. 3 passed; 1 failed; 0 ignored"
  # CARGO_TERM_COLOR=always. The bytes here are what nextest and libtest
  # actually emit; without the strip above, both read as unreadable and
  # every wrapped step fails on a green tree.
  _case "a coloured nextest summary" 14 \
    "$(printf '    \033[1m\033[32mSummary\033[0m [   1.815s] \033[1m14\033[0m tests run: 14 passed, 2580 skipped')"
  _case "a coloured libtest line" 2 \
    "$(printf 'test result: \033[32mok\033[0m. 2 passed; 0 failed; 0 ignored; 2855 filtered out')"
  _case "a coloured zero-match libtest line" 0 \
    "$(printf 'test result: \033[32mok\033[0m. 0 passed; 0 failed; 0 ignored; 2857 filtered out')"
  # Output with no count at all has to be unreadable, not zero: those two
  # are different answers and only one of them is honest.
  _case "a compile error" unreadable "error[E0433]: failed to resolve"
  _case "empty output" unreadable ""
  _case "a line that only mentions tests" unreadable \
    "running 3 tests
Compiling sbproxy-core v1.13.0"

  if count_satisfies 2 2 && ! count_satisfies 2 1 && ! count_satisfies 2 3; then
    :
  else
    echo "self-test: the exact spec is not exact" >&2
    failures=$((failures + 1))
  fi
  if count_satisfies '>=1' 1 && count_satisfies '>=1' 900 && ! count_satisfies '>=1' 0; then
    :
  else
    echo "self-test: the floor spec does not hold its floor" >&2
    failures=$((failures + 1))
  fi

  # End to end, against real commands rather than fixture strings.
  if ! (expect_tests 2 "a run that says 2" -- \
      printf 'test result: ok. 2 passed; 0 failed\n') >/dev/null 2>&1; then
    echo "self-test: refused a run that matched its count" >&2
    failures=$((failures + 1))
  fi
  if (expect_tests 2 "a zero-match run" -- \
      printf 'test result: ok. 0 passed; 0 failed; 2857 filtered out\n') >/dev/null 2>&1; then
    echo "self-test: accepted a run that matched nothing" >&2
    failures=$((failures + 1))
  fi
  if (expect_tests 2 "output with no count" -- \
      printf 'error: could not compile\n') >/dev/null 2>&1; then
    echo "self-test: accepted output it could not read a count from" >&2
    failures=$((failures + 1))
  fi
  if (expect_tests 1 "a failing command" -- false) >/dev/null 2>&1; then
    echo "self-test: accepted a command that exited non-zero" >&2
    failures=$((failures + 1))
  fi
  if (expect_tests 'two' "a bad spec" -- true) >/dev/null 2>&1; then
    echo "self-test: accepted a count spec that is not a count" >&2
    failures=$((failures + 1))
  fi

  rm -rf "$tmp"
  unset -f _case
  if [ "$failures" -ne 0 ]; then
    return 1
  fi
  echo "expect-tests self-test: all fixtures pass"
}

# Only when run directly. Sourced, this file must define functions and
# do nothing else: `certify-selfhost.sh run all` has its own `$1`.
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${1:-}" = "--self-test" ]; then
  set -uo pipefail
  _expect_tests_self_test
  exit $?
fi
