#!/usr/bin/env bash
#
# Refuse to raise the stack budget the AI dispatch path runs against.
#
# `scripts/stack-budget-baseline.count` holds one number: the bytes of
# worker stack `the_ai_dispatch_path_stays_inside_its_stack_budget` runs
# a real dispatch on. That test builds a Pingora runtime whose worker
# stack is exactly this size and drives a streamed and a buffered AI
# request through it. A path that no longer fits overflows and the
# process aborts, which under nextest is that test and nothing else.
#
# # Why the number can only fall
#
# A stack overflow is not a test failure you can reason about. It does
# not unwind, it carries no backtrace, and it names no frame. All it
# leaves is
#
#     thread 'Pingora HTTP Proxy Service' has overflowed its stack
#     fatal runtime error: stack overflow, aborting
#
# The only way to stay ahead of it is to keep the budget falling, and
# the only way to make it fall is to take frames off the path. Raising
# it is always available and always the wrong first move, so it has to
# be a decision someone writes down rather than a number that drifts.
#
# Raising it is not forbidden. It is made visible: this script fails,
# and the commit that raises the number has to say why in the same diff
# that raises the worker stack it is half of.
#
# # Why the budget cannot be recovered by shrinking futures
#
# The frames on this stack belong to the whole call chain, not to one
# function in it, so there is no single place to cut. On the branch that
# most recently tried, two future extractions moved 528 bytes against a
# 2,097,152-byte stack: 0.025 percent, for an afternoon of work. Buying
# back a meaningful margin that way needs about two thousand of them.
# That is the arithmetic behind sizing the stack rather than the path.
#
# # Why a script and not a test assertion alone
#
# The test enforces the budget. This enforces the *direction*, which a
# test cannot: a test compiled against a raised baseline passes. The
# comparison is against the merge base, so a branch is measured against
# what it actually forked from rather than against whatever `main`
# happens to be right now.
#
# # Why the number is committed
#
# Same reasoning as the unwrap and pub-item ratchets: lowering it is a
# normal part of the work and a reviewer should see the number move in
# the diff. A count this script recomputed and trusted would move
# invisibly, which is how a budget stops being one.
#
# It is a single-line file for the reason WOR-2252 documents. A number
# stored among prose merges badly: two branches editing non-adjacent
# lines look like two independent hunks, git keeps both, and a reader
# squashes them into a ceiling no real measurement can exceed, so the
# check goes green forever. A one-line file makes both branches touch
# the same line, so git stops and asks.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_FILE="$ROOT_DIR/scripts/stack-budget-baseline.count"
BASELINE_REL="scripts/stack-budget-baseline.count"

cd "$ROOT_DIR"

# Read a single-integer baseline, rejecting anything else.
#
# Taken exactly as it is: no comment stripping, no blank-line stripping.
# The file is the integer and nothing else, so anything longer than one
# line is a merge that kept both sides, and that must be an error rather
# than something this reader quietly reassembles. `|| [ -n "$line" ]`
# catches a final line with no trailing newline, which would otherwise
# be dropped and make a two-number file look like a one-number file.
read_count() {
  local source="$1" label="$2"
  local -a lines=()
  local line

  while IFS= read -r line || [ -n "$line" ]; do
    lines+=("$line")
  done <<< "$source"

  if [ "${#lines[@]}" -ne 1 ]; then
    echo "$label must hold exactly one line, found ${#lines[@]}" >&2
    if [ "${#lines[@]}" -gt 1 ]; then
      echo >&2
      echo "More than one line usually means a merge kept both sides." >&2
      printf '  %s\n' "${lines[@]}" >&2
      echo >&2
      echo "Keep the lower number, not both, and rerun the budget test." >&2
    fi
    return 1
  fi

  case "${lines[0]}" in
    ''|*[!0-9]*)
      echo "$label does not contain a single integer" >&2
      echo "  found: ${lines[0]}" >&2
      return 1
      ;;
  esac

  printf '%s' "${lines[0]}"
}

if [ "${1:-}" = "--self-test" ]; then
  # The reader is the part with edge cases, so prove it rejects what it
  # claims to reject before trusting it with the real file.
  fail=0
  for bad in $'1\n2' 'not-a-number' '' '4 194 304'; do
    if read_count "$bad" "self-test" >/dev/null 2>&1; then
      echo "self-test: reader accepted a bad baseline: [$bad]" >&2
      fail=1
    fi
  done
  if [ "$(read_count '4194304' 'self-test')" != "4194304" ]; then
    echo "self-test: reader rejected a good baseline" >&2
    fail=1
  fi
  if [ "$fail" -eq 0 ]; then
    echo "check-stack-budget-ratchet self-test: ok"
  fi
  exit "$fail"
fi

if [ ! -f "$BASELINE_FILE" ]; then
  echo "missing baseline file: $BASELINE_REL" >&2
  echo "It holds the stack budget in bytes and nothing else." >&2
  exit 1
fi

current="$(read_count "$(cat "$BASELINE_FILE")" "$BASELINE_REL")"

# The merge base, not `origin/main`. A branch is answerable for what it
# changed, not for a number that moved under it while it was open.
base_ref=""
for candidate in origin/main main; do
  if git rev-parse --verify --quiet "$candidate" >/dev/null; then
    if base_ref="$(git merge-base HEAD "$candidate" 2>/dev/null)"; then
      break
    fi
  fi
  base_ref=""
done

if [ -z "$base_ref" ]; then
  echo "no merge base against main; checking the baseline format only" >&2
  echo "stack budget: $current bytes" >&2
  exit 0
fi

if ! previous_raw="$(git show "$base_ref:$BASELINE_REL" 2>/dev/null)"; then
  # The file is new on this branch. Nothing to ratchet against yet.
  echo "stack budget: $current bytes (new on this branch)"
  exit 0
fi

previous="$(read_count "$previous_raw" "$BASELINE_REL at the merge base")"

if [ "$current" -gt "$previous" ]; then
  echo "stack budget raised: $current bytes (was $previous at the merge base)" >&2
  echo >&2
  echo "This is the budget the AI dispatch path runs against, and it is" >&2
  echo "allowed to fall and not to rise. Raising it means one of two" >&2
  echo "things, and the diff has to say which:" >&2
  echo >&2
  echo "  * The request path grew and nobody took the frames back off." >&2
  echo "    Frames added anywhere in the workspace spend this budget, so" >&2
  echo "    look wider than the file that broke the test." >&2
  echo >&2
  echo "  * The worker stack itself was raised, deliberately, and this" >&2
  echo "    number follows it. That is an operator-visible change to" >&2
  echo "    reserved address space per worker thread, configured with" >&2
  echo "    runtime_thread_stack_size, and it belongs in a commit that" >&2
  echo "    explains the arithmetic." >&2
  echo >&2
  echo "Read the current depth with:" >&2
  echo "  cargo test -p sbproxy-core --lib \\" >&2
  echo "    the_ai_dispatch_path_stays_inside_its_stack_budget -- --exact --nocapture" >&2
  exit 1
fi

if [ "$current" -lt "$previous" ]; then
  echo "stack budget: $current bytes (down from $previous)"
else
  echo "stack budget: $current bytes (unchanged)"
fi
