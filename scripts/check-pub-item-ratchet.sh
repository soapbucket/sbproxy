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
#   * Raise the baseline below, with a sentence in the commit message
#     saying why the new item has to exist before its caller does.
#
# The baseline is deliberately a number in a file rather than a
# generated artefact. Lowering it is a normal part of doing the cleanup,
# and a reviewer should see that number move in the diff.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_FILE="$ROOT_DIR/scripts/pub-item-ratchet-baseline.txt"

cd "$ROOT_DIR"

if [ ! -f "$BASELINE_FILE" ]; then
  echo "missing baseline file: $BASELINE_FILE" >&2
  exit 1
fi

# Read the value as lines, not as one squashed string. The old form
# piped every non-comment line through `tr -d '[:space:]'`, so a merge
# that kept both sides' numbers produced "284286", which still matches
# the integer test and becomes a baseline no real count can exceed. The
# check then passes forever while silently giving back every narrowing
# anyone lands. This file has hit six merge conflicts, so that is not a
# hypothetical (WOR-2252).
BASELINE_LINES=()
while IFS= read -r line; do
  BASELINE_LINES+=("$line")
done < <(grep -vE '^[[:space:]]*#' "$BASELINE_FILE" | grep -vE '^[[:space:]]*$')

if [ "${#BASELINE_LINES[@]}" -ne 1 ]; then
  echo "baseline file must hold exactly one non-comment line, found ${#BASELINE_LINES[@]}: $BASELINE_FILE" >&2
  if [ "${#BASELINE_LINES[@]}" -gt 1 ]; then
    echo >&2
    echo "More than one number usually means a merge kept both sides. Pick" >&2
    echo "the recomputed count, not either branch's, and delete the rest:" >&2
    printf '  %s\n' "${BASELINE_LINES[@]}" >&2
    echo >&2
    echo "  python3 scripts/scan-pub-item-usage.py --count tests-only" >&2
  fi
  exit 1
fi

BASELINE="$(printf '%s' "${BASELINE_LINES[0]}" | tr -d '[:space:]')"
if ! [[ "$BASELINE" =~ ^[0-9]+$ ]]; then
  echo "baseline file does not contain a single integer: $BASELINE_FILE" >&2
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
  echo "Lower the baseline in $BASELINE_FILE to $ACTUAL so the ground gained is held." >&2
  exit 1
fi

echo "pub items with only test consumers: $ACTUAL (baseline $BASELINE)"
