#!/usr/bin/env bash
# Fail when the number of `pub` items whose only consumer is their own
# test suite goes up (WOR-2065).
#
# # Why a ratchet rather than a threshold
#
# `dead_code` cannot see a `pub` item inside a `pub mod` of a library
# crate, so write-only code lands with a green build. A 213-line CRDT sat
# unread for its whole life that way. The backlog of existing candidates
# is large enough that demanding zero would mean either a big-bang
# cleanup before anything else can merge, or an exception list nobody
# reads. A ratchet asks for neither: it only says the number must not
# grow, so the cleanup can happen at whatever pace it happens while new
# write-only code is stopped at the door.
#
# # What to do when this fails
#
# Either the change added a `pub` item nothing but a test names, or it
# removed the last production caller of one. Both are worth a look:
#
#   scripts/scan-pub-item-usage.py --tests-only \
#     --external-tree /path/to/api-consumer
#
# Then pick one:
#
#   * Wire the item to a production call site, if the capability is
#     wanted. That is the same choice WOR-1898 and WOR-1980 faced.
#   * Narrow it to `pub(crate)` or private, if its real callers are all
#     in-crate. This is the highest-leverage option: it shrinks the
#     public surface and hands the item back to `dead_code`, so rustc
#     polices it for free from then on.
#   * Delete it, but only after `--external-tree` confirms the optional
#     out-of-tree API consumer does not name it. In-tree unreferenced does
#     not necessarily mean unused by another checkout.
#   * Raise the baseline, with a sentence in scripts/pub-item-ratchet-baseline.txt
#     saying why the new item has to exist before its caller does.
#
# # Why the baseline is two files
#
# The number is a committed integer rather than something this script
# recomputes and trusts. Lowering it is a normal part of the cleanup, and
# a reviewer should see the number itself move in the diff; a derived
# count moves invisibly and nobody reviews it.
#
# It is committed as two files, though, because a number is a terrible
# thing to merge:
#
#   scripts/pub-item-ratchet-baseline.count   the integer, alone, one line
#   scripts/pub-item-ratchet-baseline.txt     why it has moved, prose only
#
# The count used to live on line 221 of the prose file's 289 lines. Two
# branches that both bumped it therefore edited non-adjacent lines, git
# read that as two independent hunks, and merged both. The old reader
# squashed the result into "287286", which passes the integer test and
# becomes a ceiling no real count can ever exceed, so the check goes
# green forever while quietly giving back every narrowing anyone lands.
# Eight conflicts in that file, and the guard below started as the
# detector for it (WOR-2252).
#
# A single-line file cannot merge that way. Two branches that both change
# the count change the same line, so git stops and asks, and the answer
# is always to recompute against the merged tree rather than to keep
# either side's number:
#
#   python3 scripts/scan-pub-item-usage.py --count tests-only
#
# The prose file keeps taking the append-only notes, where a merge that
# keeps both paragraphs is the right answer rather than a silent bug.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_FILE="$ROOT_DIR/scripts/pub-item-ratchet-baseline.count"
BASELINE_NOTES="$ROOT_DIR/scripts/pub-item-ratchet-baseline.txt"

cd "$ROOT_DIR"

if [ ! -f "$BASELINE_FILE" ]; then
  echo "missing baseline file: $BASELINE_FILE" >&2
  echo "It holds the integer only; the notes live in $BASELINE_NOTES." >&2
  exit 1
fi

# Read the value as lines, not as one squashed string, and take the file
# exactly as it is: no comment stripping, no blank-line stripping. The
# count file is the integer and nothing else, so anything that makes it
# longer than one line is a merge that kept both sides, and that has to
# be an error rather than something this reader quietly reassembles.
# `|| [ -n "$line" ]` catches a final line with no trailing newline,
# which would otherwise be dropped and make a two-number file look like
# a one-number file.
BASELINE_LINES=()
while IFS= read -r line || [ -n "$line" ]; do
  BASELINE_LINES+=("$line")
done < "$BASELINE_FILE"

if [ "${#BASELINE_LINES[@]}" -ne 1 ]; then
  echo "baseline count file must hold exactly one line, found ${#BASELINE_LINES[@]}: $BASELINE_FILE" >&2
  echo "It carries the integer and nothing else. Notes belong in $BASELINE_NOTES." >&2
  if [ "${#BASELINE_LINES[@]}" -gt 1 ]; then
    echo >&2
    echo "More than one line usually means a merge kept both sides. Pick" >&2
    echo "the recomputed count, not either branch's, and delete the rest:" >&2
    printf '  %s\n' "${BASELINE_LINES[@]}" >&2
    echo >&2
    echo "  python3 scripts/scan-pub-item-usage.py --count tests-only" >&2
  fi
  exit 1
fi

BASELINE="$(printf '%s' "${BASELINE_LINES[0]}" | tr -d '[:space:]')"
if ! [[ "$BASELINE" =~ ^[0-9]+$ ]]; then
  echo "baseline count file does not contain a single integer: $BASELINE_FILE" >&2
  echo "Found: ${BASELINE_LINES[0]}" >&2
  exit 1
fi

ACTUAL="$(python3 scripts/scan-pub-item-usage.py --count tests-only)"

if [ "$ACTUAL" -gt "$BASELINE" ]; then
  echo "pub items whose only consumer is their own test suite: $ACTUAL (baseline $BASELINE)" >&2
  echo >&2
  echo "This went up. Something landed that no production code calls." >&2
  echo "List them with:" >&2
  echo "  python3 scripts/scan-pub-item-usage.py --tests-only --external-tree /path/to/api-consumer" >&2
  echo >&2
  echo "See the header of this script for the four ways to resolve it." >&2
  exit 1
fi

if [ "$ACTUAL" -lt "$BASELINE" ]; then
  echo "pub items with only test consumers: $ACTUAL, below the baseline of $BASELINE." >&2
  echo "Lower the baseline to $ACTUAL so the ground gained is held:" >&2
  echo "  printf '%s\\n' $ACTUAL > $BASELINE_FILE" >&2
  echo "and add a note to $BASELINE_NOTES saying what gained a caller or was narrowed." >&2
  exit 1
fi

echo "pub items with only test consumers: $ACTUAL (baseline $BASELINE)"
