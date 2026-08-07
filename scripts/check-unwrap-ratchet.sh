#!/usr/bin/env bash
#
# Refuse a new `.unwrap()`, `.expect(..)`, or `panic!` in production code.
#
# Each of these ends the process on a path an operator cannot recover from
# and cannot catch. In a proxy that is a dropped connection at best and a
# dropped request mid-settlement at worst, so the count is allowed to fall
# and never to rise.
#
# # Why a script and not clippy
#
# `clippy::unwrap_used`, `clippy::expect_used`, and `clippy::panic` exist and
# would be the obvious answer. They cannot be used here.
#
# Both `scripts/check.sh` and CI's lint lane run
#
#     cargo clippy --workspace --all-targets -- -D warnings
#
# so `warn` and `deny` are the same level in this workspace. There is no
# "warn now, clean up later" setting to ratchet against: turning any of the
# three on fails the build immediately on all 758 existing sites.
#
# The three lints also fire in test code, where `.unwrap()` in a fixture is
# the correct thing to write. `#![cfg_attr(test, allow(..))]` in a library
# root does not reach `crates/*/tests/`, because each file there compiles as
# its own crate, so the exemption would have to be repeated across all 108 of
# them and re-added by hand every time someone writes a new test file.
#
# This scan enforces the same rule where the rule actually applies. The
# counting rules, including how test code is identified, are documented at
# the top of scripts/scan-unwrap-usage.py.
#
# # Two counts, not one
#
# `panic` is tracked separately and its baseline is 0. Production code has no
# `panic!` today, and that is worth locking rather than folding into a larger
# number where it could be traded away against an unwrap someone removed.
#
# # Why the count is committed
#
# Same reasoning as the pub-item ratchet: lowering it is a normal part of the
# cleanup and a reviewer should see the number move in the diff. A count this
# script recomputed and trusted would move invisibly.
#
# It is a single-line file for the reason WOR-2252 documents. A number stored
# among prose merges badly: two branches editing non-adjacent lines look like
# two independent hunks, git keeps both, and the reader squashes them into a
# ceiling no real count can exceed, so the check goes green forever while
# giving back every fix anyone landed. A one-line file makes both branches
# touch the same line, so git stops and asks.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER="$ROOT_DIR/scripts/scan-unwrap-usage.py"

cd "$ROOT_DIR"

fail=0

# Read a committed single-integer baseline, rejecting anything else.
#
# Taken exactly as it is: no comment stripping, no blank-line stripping. The
# file is the integer and nothing else, so anything longer than one line is a
# merge that kept both sides, and that must be an error rather than something
# this reader quietly reassembles. `|| [ -n "$line" ]` catches a final line
# with no trailing newline, which would otherwise be dropped and make a
# two-number file look like a one-number file.
read_baseline() {
  local file="$1" kind="$2"
  local -a lines=()
  local line

  if [ ! -f "$file" ]; then
    echo "missing baseline file: $file" >&2
    echo "It holds the integer only. Recompute with:" >&2
    echo "  python3 scripts/scan-unwrap-usage.py --count $kind" >&2
    return 1
  fi

  while IFS= read -r line || [ -n "$line" ]; do
    lines+=("$line")
  done < "$file"

  if [ "${#lines[@]}" -ne 1 ]; then
    echo "baseline count file must hold exactly one line, found ${#lines[@]}: $file" >&2
    if [ "${#lines[@]}" -gt 1 ]; then
      echo >&2
      echo "More than one line usually means a merge kept both sides. Recompute" >&2
      echo "against the merged tree rather than keeping either branch's number:" >&2
      printf '  %s\n' "${lines[@]}" >&2
      echo >&2
      echo "  python3 scripts/scan-unwrap-usage.py --count $kind" >&2
    fi
    return 1
  fi

  case "${lines[0]}" in
    ''|*[!0-9]*)
      echo "baseline file does not contain a single integer: $file" >&2
      echo "  found: ${lines[0]}" >&2
      return 1
      ;;
  esac

  printf '%s' "${lines[0]}"
}

check_one() {
  local kind="$1" file="$2" label="$3"
  local baseline actual

  baseline="$(read_baseline "$file" "$kind")" || return 1
  actual="$(python3 "$SCANNER" --count "$kind")"

  if [ "$actual" -gt "$baseline" ]; then
    echo "$label in production code: $actual (baseline $baseline)" >&2
    echo >&2
    echo "This change adds $((actual - baseline)). Production code cannot" >&2
    echo "recover from any of them: each one ends the process on a path a" >&2
    echo "caller cannot catch. Return a Result and let the call site decide." >&2
    echo >&2
    echo "See the new sites with:" >&2
    echo "  python3 scripts/scan-unwrap-usage.py" >&2
    echo >&2
    echo "If a site is genuinely unreachable, say why in a comment and use" >&2
    echo "expect() with a message naming the invariant, which still counts." >&2
    echo "The number is a budget, not a ban." >&2
    return 1
  fi

  if [ "$actual" -lt "$baseline" ]; then
    echo "$label in production code: $actual (baseline $baseline)" >&2
    echo >&2
    echo "Lower than the baseline, which is the good direction. Lock it in so" >&2
    echo "the ground is not given back:" >&2
    echo >&2
    echo "  printf '%s\\n' $actual > $file" >&2
    return 1
  fi

  echo "$label in production code: $actual (baseline $baseline)"
  return 0
}

check_one unwrap-expect "$ROOT_DIR/scripts/unwrap-ratchet-baseline.count" "unwrap/expect sites" || fail=1
check_one panic "$ROOT_DIR/scripts/panic-ratchet-baseline.count" "panic! sites" || fail=1

exit "$fail"
