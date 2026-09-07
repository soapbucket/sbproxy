#!/usr/bin/env bash
# Fail when the number of `pub` items whose only consumer is their own
# test suite goes up, or when the wider count of `pub` items nothing
# outside their defining file names goes up (WOR-2065, WOR-2642).
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
#
# # The second bucket, and why it needed its own ratchet
#
# The test-only bucket is the narrow slice: an item some test names. It
# never moved while `sbproxy-vault/src/convergent.rs` sat in the tree,
# because a fingerprinter nothing calls at all, not even a test in
# another file, is not in that slice. Seven `pub` items, a documented
# HKDF derivation, a reserved vault path, and a read-then-write race in
# `load_or_generate`, all unreachable since the first commit and all
# invisible to the gate that exists to catch exactly that (WOR-2642).
#
# So the wider bucket gets a baseline too: every `pub` item that nothing
# outside its own file names. What that ratchet can see:
#
#   * A new `pub` item whose callers are all in its defining file, which
#     is over-exposure at best and scaffolding at worst.
#   * The last cross-file consumer of an existing item going away.
#
# What it cannot see, stated because a ratchet trusted past its detector
# is worse than none:
#
#   * The difference between a caller and a mention. Matching is
#     textual, so a comment naming the item counts as a reference.
#   * Anything `pub(crate)` or narrower, which rustc already polices.
#   * A dead module as one thing. It arrives as N items and leaves as N
#     items, so the number moves by its item count, not by one.
#
# One entry left that list on 2026-09-07. An item re-exported by a
# `pub use` in its own crate's `lib.rs` used to read as referenced,
# because the scanner counted the re-export line as a production
# consumer, so a `pub mod` wired to nothing but the crate facade never
# entered either bucket. That is how `sbproxy-ai/src/multimodal.rs`
# stayed invisible to both numbers (WOR-2550). `collect_definitions`
# already skipped `pub use` lines, on the stated grounds that a
# re-export names an item rather than defining one; `collect_references`
# now skips them on the same grounds, whole statement at a time because
# rustfmt wraps the wide ones. 620 items were sitting in that blind
# spot, which is why both baselines below moved up in the change that
# closed it and not because anything was added to the tree.
#
# This integer was one-directional until the inventory below arrived:
# it failed when the number went up and only advised when it went down.
# The measurement behind that asymmetry is still worth having. Replaying
# the scanner over the twenty merges before 1586de4c, the test-only
# bucket sat at 297 or 298 the whole way, so pinning it exactly costs
# almost nothing and holds every narrowing. The wider bucket climbed
# from 1415 to 1441 across the same span, eight of those in one merge,
# because it is a candidate list rather than a defect list and ordinary
# feature work adds to it. The argument against failing on a decrease
# was that it would put a single-integer file in the path of most
# branches, and a number bumped on reflex is worse than one that only
# has to be justified when it grows.
#
# The inventory settles that differently and now decides it. It fails in
# both directions, because a named line is not a number bumped on
# reflex: an addition is one reviewable line saying which item, and a
# removal is one line saying which item stopped being a candidate. So
# the decrease is refused after all, and the reason the old paragraph
# gave for allowing it no longer applies.
#
# Recompute either side against the merged tree rather than keeping
# a branch's number:
#
#   python3 scripts/scan-pub-item-usage.py --count tests-only
#   python3 scripts/scan-pub-item-usage.py --count unreferenced
#
# # The inventory, and why a number was not enough
#
# Both counts above fail without saying what moved. "2142, baseline
# 2141" tells an author a `pub` item they cannot name is now reachable
# only from its own file, and leaves them to re-run the scanner and
# diff two two-thousand-line lists by hand to find out which. So the
# candidate set is also committed by name:
#
#   scripts/pub-item-inventory.txt   one `file::name` per line, sorted
#
# and the check below diffs it against the tree, so a failure prints the
# item. Regenerate it with a plain redirect:
#
#   python3 scripts/scan-pub-item-usage.py --inventory > scripts/pub-item-inventory.txt
#
# This is the WOR-2252 shape done the way that ticket asked for. The
# integer was unmergeable because two branches lowering it edit one line
# with two different right answers, and neither is the answer for the
# merged tree. A sorted set of names has no such line: two branches that
# each add an item touch different lines, git takes both, and the union
# is exactly what the merged tree contains. Two branches that touch the
# same name conflict, and the conflict is at the name, which is where a
# human can actually decide. The check still recomputes from the tree
# and diffs, so a merge that somehow produced the wrong set fails on the
# next run naming every line it got wrong, rather than passing with a
# ceiling nothing can exceed.
#
# # The discovery floor
#
# Every number here is "how many of the things the scanner found look
# unused". A scanner that finds nothing therefore reports zero of
# everything, and the two counts above read that as the best result the
# repository has ever had. The tests-only check happens to catch it,
# because it fails on a decrease; the unreferenced check does not, and
# nor would the inventory diff if the walk returned an empty set for a
# reason the differ could not distinguish from real cleanup. So the
# scan reports how many definitions it discovered, and this script
# refuses a number that could not describe this workspace. That check
# is the one that has to fail when the guard breaks rather than when
# the code does.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE_FILE="$ROOT_DIR/scripts/pub-item-ratchet-baseline.count"
BASELINE_NOTES="$ROOT_DIR/scripts/pub-item-ratchet-baseline.txt"
UNREFERENCED_BASELINE_FILE="$ROOT_DIR/scripts/pub-item-unreferenced-baseline.count"

cd "$ROOT_DIR"

python3 scripts/tests/test_scan_pub_item_usage.py

# Read a one-line integer baseline, or explain what is wrong with it and
# fail. `$bucket` is the `--count` mode whose recompute command the
# error messages should suggest.
#
# Called through a command substitution, so `exit 1` here ends the
# subshell and the caller has to check the status rather than the empty
# string. Every call site does.
read_baseline_count() {
  local file="$1" bucket="$2"

  if [ ! -f "$file" ]; then
    echo "missing baseline file: $file" >&2
    echo "It holds the integer only; the notes live in $BASELINE_NOTES." >&2
    exit 1
  fi

  # Read the value as lines, not as one squashed string, and take the
  # file exactly as it is: no comment stripping, no blank-line
  # stripping. The count file is the integer and nothing else, so
  # anything that makes it longer than one line is a merge that kept
  # both sides, and that has to be an error rather than something this
  # reader quietly reassembles. `|| [ -n "$line" ]` catches a final line
  # with no trailing newline, which would otherwise be dropped and make
  # a two-number file look like a one-number file.
  local lines=()
  while IFS= read -r line || [ -n "$line" ]; do
    lines+=("$line")
  done < "$file"

  if [ "${#lines[@]}" -ne 1 ]; then
    echo "baseline count file must hold exactly one line, found ${#lines[@]}: $file" >&2
    echo "It carries the integer and nothing else. Notes belong in $BASELINE_NOTES." >&2
    if [ "${#lines[@]}" -gt 1 ]; then
      echo >&2
      echo "More than one line usually means a merge kept both sides. Pick" >&2
      echo "the recomputed count, not either branch's, and delete the rest:" >&2
      printf '  %s\n' "${lines[@]}" >&2
      echo >&2
      echo "  python3 scripts/scan-pub-item-usage.py --count $bucket" >&2
    fi
    exit 1
  fi

  local value
  value="$(printf '%s' "${lines[0]}" | tr -d '[:space:]')"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "baseline count file does not contain a single integer: $file" >&2
    echo "Found: ${lines[0]}" >&2
    exit 1
  fi

  printf '%s' "$value"
}

BASELINE="$(read_baseline_count "$BASELINE_FILE" tests-only)"
UNREFERENCED_BASELINE="$(read_baseline_count "$UNREFERENCED_BASELINE_FILE" unreferenced)"

# One scan for both counts and the inventory. This used to be two
# invocations for two integers, and the inventory would have made it
# three walks of the same tree for numbers that all come out of the
# same pass.
RATCHET_DATA="$(python3 scripts/scan-pub-item-usage.py --ratchet-data)"

# How many `pub` item definitions the scan discovered. Not a ratchet:
# a floor, far enough below the real number that ordinary work never
# reaches it, whose only job is to refuse a run where discovery broke.
# Without it, a scanner that walks the wrong directory, or matches
# nothing, or returns early, reports zero candidates, and every check
# below reads that as a clean tree and passes.
#
# What it catches, stated exactly, because a floor trusted past its
# reach is worse than none. It fires when discovery loses most of the
# FILES: dropping everything but the eight files that carry the recorded
# verdicts leaves 185 definitions, and this refuses that. It does not
# fire when discovery loses whole CRATES, because the tree is big enough
# that a fraction of it still clears any floor an honest tree also
# clears. Keeping only the seven crates the recorded verdicts live in
# leaves 5447 definitions, above this number, and that run reaches the
# inventory diff instead, where the bulk-removal branch below is what
# refuses it. The two together cover both classes; neither covers both
# on its own.
#
# The number cannot be raised much to close that gap. Anything above the
# smallest crate subset that keeps all 13 recorded verdicts as
# candidates would have to sit near the real count, and a floor that
# close to the true number fails on ordinary deletion work.
DEFINITION_FLOOR=5000

DEFINITIONS="$(printf '%s\n' "$RATCHET_DATA" | awk -F'\t' '$1 == "definitions" { print $2 }')"

if ! [[ "$DEFINITIONS" =~ ^[0-9]+$ ]]; then
  echo "the scan did not report a definition count; it cannot be trusted" >&2
  echo "Expected a 'definitions<TAB><integer>' line from:" >&2
  echo "  python3 scripts/scan-pub-item-usage.py --ratchet-data" >&2
  exit 1
fi

if [ "$DEFINITIONS" -lt "$DEFINITION_FLOOR" ]; then
  echo "the scan found only $DEFINITIONS pub item definitions, below the floor of $DEFINITION_FLOOR" >&2
  echo >&2
  echo "This is a broken scan, not a clean tree. Every count below is" >&2
  echo "'how many of the discovered items look unused', so a discovery" >&2
  echo "that returns nothing reports nothing wrong. Check that" >&2
  echo "scripts/scan-pub-item-usage.py still walks crates/ before" >&2
  echo "touching any baseline." >&2
  exit 1
fi

# The named half of the guard. Diffed rather than counted, so a failure
# says which item, which is the question an author actually has.
INVENTORY_FILE="$ROOT_DIR/scripts/pub-item-inventory.txt"
INVENTORY_ACTUAL="$(mktemp)"
trap 'rm -f "$INVENTORY_ACTUAL"' EXIT
printf '%s\n' "$RATCHET_DATA" | sed -n '/^--- items ---$/,$p' | tail -n +2 > "$INVENTORY_ACTUAL"

if [ ! -f "$INVENTORY_FILE" ]; then
  echo "missing inventory file: $INVENTORY_FILE" >&2
  echo "  python3 scripts/scan-pub-item-usage.py --inventory > $INVENTORY_FILE" >&2
  exit 1
fi

if ! diff -q "$INVENTORY_FILE" "$INVENTORY_ACTUAL" >/dev/null; then
  ADDED="$(LC_ALL=C comm -13 "$INVENTORY_FILE" "$INVENTORY_ACTUAL" || true)"
  REMOVED="$(LC_ALL=C comm -23 "$INVENTORY_FILE" "$INVENTORY_ACTUAL" || true)"
  if [ -n "$ADDED" ]; then
    echo "pub items nothing outside their own file names, new since the committed inventory:" >&2
    printf '%s\n' "$ADDED" | sed 's/^/  + /' >&2
    echo >&2
    echo "Each of these is public, and reachable only from the file that" >&2
    echo "defines it. See the header of this script for the four ways to" >&2
    echo "resolve it; narrowing to pub(crate) is usually the right one." >&2
    echo >&2
  fi
  # How many entries may leave at once before "an item gained a caller"
  # stops being the likelier story than "the scan stopped seeing them".
  # A tenth of the committed set is far above any real cleanup: the
  # moves recorded in pub-item-ratchet-baseline.txt are single digits,
  # and this whole branch removed none.
  INVENTORY_SIZE="$(wc -l < "$INVENTORY_FILE" | tr -d ' ')"
  REMOVED_COUNT=0
  [ -n "$REMOVED" ] && REMOVED_COUNT="$(printf '%s\n' "$REMOVED" | wc -l | tr -d ' ')"
  BULK_REMOVAL_LIMIT=$((INVENTORY_SIZE / 10))

  if [ -n "$REMOVED" ]; then
    echo "committed inventory entries that are no longer candidates:" >&2
    printf '%s\n' "$REMOVED" | sed 's/^/  - /' >&2
    echo >&2
  fi

  if [ "$REMOVED_COUNT" -gt "$BULK_REMOVAL_LIMIT" ]; then
    # The floor above cannot see this. It catches discovery collapsing
    # far enough to drop below a workspace-sized definition count; a walk
    # that loses most of crates/ but keeps enough files still clears it,
    # and then arrives here looking like a very large cleanup. Measured:
    # keeping only the seven crates that carry the recorded verdicts
    # leaves 5447 definitions, above the floor, and 1030 of 2141 entries
    # gone. Telling an author to regenerate at that point is the same
    # move as telling them to lower a baseline to a broken number, which
    # is what this script's own header criticises origin/main's
    # test-only branch for. Run the command and the corrupted set is
    # committed, after which nothing in it can ever be flagged again.
    echo "$REMOVED_COUNT of $INVENTORY_SIZE entries left the inventory at once." >&2
    echo >&2
    echo "That is too many to be cleanup. An item leaves this set when it" >&2
    echo "gains a caller or is narrowed, one edit at a time; a whole block" >&2
    echo "of them leaving usually means the scan stopped seeing the files" >&2
    echo "rather than that the code changed." >&2
    echo >&2
    echo "This scan found $DEFINITIONS pub item definitions. Check that" >&2
    echo "against the tree before believing the list above: a walk that" >&2
    echo "loses most of crates/ can still clear the floor of" >&2
    echo "$DEFINITION_FLOOR and land here." >&2
    echo >&2
    echo "Do not regenerate the inventory until you have confirmed the scan" >&2
    echo "is sound. Regenerating commits whatever it just saw, and an entry" >&2
    echo "that is not in the file can never be flagged again." >&2
    exit 1
  fi

  if [ -n "$REMOVED" ]; then
    echo "Ground gained, if the scan is sound. Confirm each of these gained" >&2
    echo "a production caller or was narrowed, rather than that the scan" >&2
    echo "stopped reaching it, then drop the lines." >&2
    echo >&2
  fi
  echo "Then regenerate, and recompute rather than keeping a branch's file:" >&2
  echo "  python3 scripts/scan-pub-item-usage.py --inventory > $INVENTORY_FILE" >&2
  exit 1
fi

echo "pub item inventory matches the tree: $(wc -l < "$INVENTORY_FILE" | tr -d ' ') items"

ACTUAL="$(printf '%s\n' "$RATCHET_DATA" | awk -F'\t' '$1 == "tests-only" { print $2 }')"

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

UNREFERENCED="$(printf '%s\n' "$RATCHET_DATA" | awk -F'\t' '$1 == "unreferenced" { print $2 }')"

if [ "$UNREFERENCED" -gt "$UNREFERENCED_BASELINE" ]; then
  echo "pub items nothing outside their own file names: $UNREFERENCED (baseline $UNREFERENCED_BASELINE)" >&2
  echo >&2
  echo "This went up. Something landed that is public, and reachable only" >&2
  echo "from the file that defines it. List the bucket with:" >&2
  echo "  python3 scripts/scan-pub-item-usage.py --json" >&2
  echo >&2
  echo "The four resolutions in this script's header apply here too, and" >&2
  echo "narrowing to pub(crate) is usually the right one: an item whose" >&2
  echo "callers are all in one file does not need to be public, and once" >&2
  echo "it is not, rustc polices it for free." >&2
  echo >&2
  echo "If the new items have to exist before their callers do, raise the" >&2
  echo "baseline and say why in $BASELINE_NOTES:" >&2
  echo "  printf '%s\\n' $UNREFERENCED > $UNREFERENCED_BASELINE_FILE" >&2
  exit 1
fi

# Both branches around this one are now reachable only when this count
# file and the inventory disagree, because the inventory holds one line
# per candidate and its diff runs first and fails on any difference in
# either direction. Nothing keeps the two in step automatically, so a
# stale-low count reports the upward message for a tree where nothing
# went up. The inventory is the authority; this integer is the headline
# a reader wants in the log, and it is kept for that and for the
# test-only bucket above, which the inventory does not carry.
if [ "$UNREFERENCED" -lt "$UNREFERENCED_BASELINE" ]; then
  echo "pub items nothing outside their own file names: $UNREFERENCED, below the baseline of $UNREFERENCED_BASELINE."
  echo "The inventory above already agreed with the tree, so this is the count"
  echo "file being stale rather than anything moving. Bring it into step:"
  echo "  printf '%s\\n' $UNREFERENCED > $UNREFERENCED_BASELINE_FILE"
  exit 0
fi

echo "pub items nothing outside their own file names: $UNREFERENCED (baseline $UNREFERENCED_BASELINE)"
