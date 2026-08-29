#!/usr/bin/env python3
"""Refuse an insertion that lands inside another item's attribute block.

An attribute block is everything attached to a Rust item ahead of the item
itself: its rustdoc, its `#[test]`, its `#[derive(...)]`, its `#[cfg]`.
Rust binds that block to whatever item comes next, so inserting a new item
between the block and its owner silently moves the whole block onto the
newcomer. The owner keeps its body and loses its meaning.

It reads as a clean diff. The stolen lines are context, unchanged and
green, and the review sees a new item with a doc comment above it, which
is what a new item is supposed to look like.

Twenty-one are in the last 260 first-parent merges, one every twelve, and
sixteen were still live when this was written; a seventeenth arrived from
main at `9a6c2b3e2` while the guard was in review, and is repaired with
them. Two of them:

    cf77910e9  crates/sbproxy-core/src/server/ai_dispatch.rs

    `the_dispatch_future_has_not_grown` was inserted between
    `a_non_streaming_dispatch_fits_a_pingora_worker_stack`'s rustdoc and
    its `#[test]`. That rustdoc is the one explaining why the test runs a
    real dispatch on a worker-sized thread, on the exact path that was
    overflowing its stack a day later. It now documents a `size_of` probe
    that does not run a dispatch at all, and the guard it was written for
    has no doc.

    eb42165a5  crates/sbproxy-core/src/config_rollback.rs

    `parses_as_config` was inserted between `plan_radius`'s rustdoc and
    `plan_radius`. `plan_radius` returns `Option<BlastRadius>` and its doc
    said "or `None` when either fails to parse"; that sentence now sits on
    a function returning `bool`. Both items are crate-private, so
    `-D missing_docs` cannot see either of them, and
    `--document-private-items` would not have helped either: after the
    theft *both* items are documented, just wrongly.

What this refuses
-----------------

One shape, and only one. An insertion at a point where the pre-image still
had an outer attribute block open, whose inserted text closes that block
by carrying an item of its own, **and** after which the victim item's
block is not what it was. The last clause is the one that takes reading
the file rather than the hunk; see `find_theft`.

That is a narrow claim on purpose. Ordinary edits do not land inside an
item's attribute block: a new item goes in at a `}` or a blank line
between items, where nothing is open. Extending a doc comment, adding a
`#[cfg]` beside an existing `#[test]`, or reflowing a rustdoc all leave
the block open at the end of the insertion and are not reported.

What it cannot see
------------------

* A theft committed by editing the stolen block in the same diff. The
  pre-image line before the insertion has to be an unchanged context line.
  A diff that rewrites the doc comment *and* inserts an item is a diff
  where the reviewer is already looking at the doc comment.
* A doc comment that describes the wrong item in prose without any
  insertion at all. That is a reading, not a shape, and a guard that
  judges prose gets trained away.
* Anything outside `.rs`. Attribute blocks are a Rust construct.
* A file added on this branch. There is no pre-image to have owned a
  block, and the whole file is the insertion.
* A theft an earlier commit landed. This is diff-scoped by design, so it
  polices what a branch adds and says nothing about what is already in
  the tree. Running it over a window of merges is how the ones already
  on `main` were found, and that is a sweep, not this gate.
* A block whose victim item cannot be found in the post-image at all,
  which is reported rather than dismissed: something moved, and guessing
  what is not this tool's job.

Renames used to be on this list. They are not any more: the diff is taken
with `--diff-filter=MR` and the pre-image path comes off the `--- a/`
line, so `git mv` plus an insertion is seen. It was on the list because
the first version could not see it, which is the same defect this script
exists to name, one level up.

Modes
-----

``--check``
    The gate. Diffs against the base and reports every theft-shaped
    insertion. Exits 1 on a finding, and exits 1 when it cannot resolve a
    base, because a diff-scoped guard with no diff has checked nothing and
    must not report success for it.

``--self-test``
    In-process fixtures for the classifier and the finder, including the
    two historical hunks above taken verbatim. A detector that has quietly
    stopped detecting reads exactly like a clean tree, so the fixtures run
    wherever the gate runs.

Base resolution
---------------

`ATTRIBUTE_THEFT_BASE_REF` names the ref CI wants the diff scoped to, the
way `CHANGELOG_BASE_REF` and `STACK_BUDGET_BASE_REF` do next door. It is
not trusted verbatim, and not for the reason those two give.

A pull request's `base.sha` is the base branch head at event time, so it
goes stale as soon as main moves, and re-running a job replays the old
payload. The obvious defence, taking the merge base of that ref with
HEAD, does nothing here: `actions/checkout` on a `pull_request` event
checks out `refs/pull/N/merge`, so a stale `base.sha` is an *ancestor* of
HEAD and the merge base is the stale ref right back. The branch would go
red on somebody else's commit.

So on that shape the base is the merge ref's own first parent, which is
the base branch as GitHub built the merge, and the override is used only
to confirm the shape. Elsewhere (a laptop, a `push`, a non-merge HEAD)
the merge base with the override is taken, and the override is used
verbatim when there is no merge base at all. A bad override is an error,
never a skip.

Without the override, `origin/main` then `main`, merge base with HEAD.
Nothing resolves, nothing runs, and the exit code says so.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


# --- The classifier ----------------------------------------------------
#
# One question, asked of every line: with this line consumed, is an outer
# attribute block still open, so that the next item will inherit it?
#
# It is a small state machine and not a regex because the states that
# matter span lines. A `#[cfg(all(` runs over three lines before its
# brackets balance. A raw string can hold a line that begins with `#[` or
# `///` and mean nothing by it, and this repository embeds Rust in raw
# strings in its doc-generator fixtures. A nested `/* /* */ */` comment
# ends where the outer one does.


class BlockState:
    """Whether an outer attribute block is open, line by line.

    `open` is the answer for the last line fed in. Inner attributes
    (`//!`, `#![...]`) are deliberately not open: they attach to the
    enclosing module, so an item inserted below one steals nothing.
    """

    def __init__(self) -> None:
        self.open = False
        self._comment_depth = 0
        self._string: str | None = None  # the delimiter that closes it
        self._attr_depth = 0
        self._attr_inner = False

    def feed(self, line: str) -> bool:
        """Consume one line and return whether a block is open after it."""
        if self._comment_depth or self._string is not None:
            self._scan(line)
            return self.open

        stripped = line.strip()

        if self._attr_depth:
            # Mid-attribute. `#[cfg(all(` runs over three lines before its
            # brackets balance, and every one of them is inside the block.
            self._scan(line)
            self.open = not self._attr_inner
            return self.open

        if not stripped:
            # A blank line does not end an attribute block: rustc binds
            # `/// doc\n\nfn f()` to `f`. Carry the state.
            return self.open

        if stripped.startswith("//!") or stripped.startswith("/*!"):
            self._scan(line)
            self.open = False
            return self.open

        if stripped.startswith("///") or stripped.startswith("/**"):
            self._scan(line)
            self.open = True
            return self.open

        if stripped.startswith("//"):
            # An ordinary comment between an attribute and its item does
            # not break the binding either. Carry the state.
            return self.open

        if stripped.startswith("#!["):
            self._attr_inner = True
            self._scan(line)
            self.open = False
            return self.open

        if stripped.startswith("#["):
            self._attr_inner = False
            self._scan(line)
            self.open = True
            return self.open

        self._scan(line)
        if self._comment_depth or self._string is not None:
            # The line opened a comment or a string that is still running.
            # Whatever it was, it was code, so the block is spent.
            self.open = False
            return self.open

        self.open = False
        return self.open

    def _scan(self, line: str) -> None:
        """Advance the lexical state across one line.

        Tracks nested block comments, string and raw-string literals, and
        the bracket depth of a multi-line attribute. Everything else is
        skipped: this is not a full Rust lexer and does not need to be,
        because the only question is which line a construct ends on.
        """
        i = 0
        n = len(line)
        while i < n:
            if self._comment_depth:
                if line.startswith("*/", i):
                    self._comment_depth -= 1
                    i += 2
                elif line.startswith("/*", i):
                    self._comment_depth += 1
                    i += 2
                else:
                    i += 1
                continue

            if self._string is not None:
                closer = self._string
                if closer == '"':
                    if line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == '"':
                        self._string = None
                    i += 1
                    continue
                if line.startswith(closer, i):
                    self._string = None
                    i += len(closer)
                    continue
                i += 1
                continue

            if line.startswith("//", i):
                return
            if line.startswith("/*", i):
                self._comment_depth = 1
                i += 2
                continue

            raw = self._raw_string_at(line, i)
            if raw is not None:
                hashes, width = raw
                self._string = '"' + "#" * hashes
                i += width
                continue

            if line[i] == '"':
                self._string = '"'
                i += 1
                continue

            if line[i] == "'":
                # A char literal or a lifetime. `'a'`, `'\n'` and
                # `'\u{1F600}'` close on this line; `'a` does not open
                # anything.
                match = re.match(r"'(\\u\{[0-9a-fA-F_]+\}|\\x[0-9a-fA-F]{2}|\\.|[^\\'])'", line[i:])
                if match:
                    i += match.end()
                    continue
                i += 1
                continue

            if self._attr_depth:
                if line[i] in "([{":
                    self._attr_depth += 1
                elif line[i] in ")]}":
                    # No clamp. The decrementing branch is only entered
                    # while the depth is already positive, so it cannot go
                    # negative on any input, valid Rust or not. An earlier
                    # version wrapped this in `max(0, ...)`; no input
                    # reaches it, and defensive code no fixture can
                    # exercise is the thing this branch exists to refuse.
                    self._attr_depth -= 1
            elif line.startswith("#[", i) or line.startswith("#![", i):
                self._attr_depth = 1
                i += 3 if line.startswith("#![", i) else 2
                continue

            i += 1

    @staticmethod
    def _raw_string_at(line: str, i: int) -> tuple[int, int] | None:
        """`(hash count, characters consumed)` if a raw string starts here."""
        match = re.match(r"(?:b|c)?r(#*)\"", line[i:])
        if not match:
            return None
        if i > 0 and (line[i - 1].isalnum() or line[i - 1] == "_"):
            return None
        return len(match.group(1)), match.end()


def block_open_at(lines: list[str], index: int) -> bool:
    """Is an outer attribute block open after `lines[:index]`?

    `index` is a count of lines, not an offset, so `block_open_at(lines, 3)`
    answers for the state after the third line.
    """
    state = BlockState()
    for line in lines[:index]:
        state.feed(line)
    return state.open


def block_states(lines: list[str]) -> list[bool]:
    """`open` after every line, computed in one pass over the file."""
    state = BlockState()
    return [state.feed(line) for line in lines]


def item_index(lines: list[str], start: int) -> int:
    """Index of the item head at or after `start`, or `len(lines)`."""
    state = BlockState()
    for i in range(start, len(lines)):
        state.feed(lines[i])
        if not state.open and lines[i].strip() and not lines[i].strip().startswith("//"):
            return i
    return len(lines)


def block_above(lines: list[str], states: list[bool], index: int) -> list[str]:
    """The attribute block bound to the item at `index`.

    Walks back over every line the classifier reports as leaving a block
    open, which is the doc comments, the attributes, and the blank lines
    and ordinary comments between them.
    """
    start = index
    while start > 0 and states[start - 1]:
        start -= 1
    return lines[start:index]


# --- The finder --------------------------------------------------------


class Theft:
    def __init__(self, path: str, line: int, owner: str, thief: str, stolen: str) -> None:
        self.path = path
        self.line = line
        self.owner = owner
        self.thief = thief
        self.stolen = stolen

    def render(self) -> str:
        return (
            f"{self.path}:{self.line}: an insertion landed inside an open attribute block\n"
            f"    the block ends with:  {self.stolen.strip()}\n"
            f"    it belonged to:       {self.owner.strip()}\n"
            f"    it now belongs to:    {self.thief.strip()}"
        )


def item_head(lines: list[str], start: int) -> str:
    """The first line at or after `start` that is not part of a block.

    Used only to name the owner and the thief in the report.
    """
    state = BlockState()
    for line in lines[start:]:
        state.feed(line)
        if not state.open and line.strip() and not line.strip().startswith("//"):
            return line
    return "<end of file>"


def find_theft(
    path: str,
    pre_lines: list[str],
    post_lines: list[str],
    hunks: list[tuple[int, int, list[str]]],
) -> list[Theft]:
    """Theft-shaped insertions in one file.

    `hunks` is a list of `(pre-image line to insert after, post-image line
    the insertion starts on, inserted lines)`, which is what a `-U0`
    unified diff's pure-insertion hunks carry. A hunk that also deletes is
    not here: the author edited the block, so the block is in the diff and
    the reviewer is looking at it.

    # Why the answer comes from the file and not from the hunk

    The hunk alone says whether the inserted text *closes* a block that
    was open at the insertion point. That is necessary and not sufficient,
    because git does not anchor a hunk where the author typed it. When the
    tail of an insertion is textually identical to the pre-image line above
    the insertion point, git rotates the hunk one line earlier, and
    appending

        #[test]
        fn new_one() { ... }

    immediately before an existing `#[test] fn` produces exactly that: the
    reported hunk starts with the `fn` and ends with the `#[test]`. Read as
    a hunk it looks like a `#[test]` being stolen. Read as a file, nothing
    moved, and that shape is the single most common insertion in this
    repository's test modules.

    So the decision is made on the two files: take the attribute block
    bound to the victim item before the change and the block bound to the
    same item after it, and report only when they differ. A rotation
    leaves them byte-identical; a real theft leaves the owner with less
    than it had.
    """
    findings: list[Theft] = []
    pre_states = block_states(pre_lines)
    post_states = block_states(post_lines)

    for after, new_start, inserted in hunks:
        # `after == 0` is an insertion at the very top of the file, where
        # there is no pre-existing block above the insertion point and so
        # nothing to take. It is checked here rather than left to the
        # state read because `pre_states[after - 1]` with `after == 0`
        # reads the *last* line of the file, which is a different question
        # with a different answer.
        if after == 0 or not pre_states[after - 1]:
            continue

        state = BlockState()
        for line in pre_lines[:after]:
            state.feed(line)
        closed = False
        for line in inserted:
            if not state.feed(line):
                closed = True
                break
        if not closed:
            # The insertion only extended the block: more rustdoc, another
            # `#[cfg]`. The item below still gets all of it.
            continue

        owner_pre = item_index(pre_lines, after)
        if owner_pre >= len(pre_lines):
            continue
        block_pre = block_above(pre_lines, pre_states, owner_pre)

        owner_post = locate_owner(
            post_lines,
            predicted=(new_start - 1) + len(inserted) + (owner_pre - after),
            head=pre_lines[owner_pre],
        )
        if owner_post is not None:
            block_post = block_above(post_lines, post_states, owner_post)
            if block_post == block_pre:
                # The owner kept its block. git rotated the hunk; nothing
                # was taken.
                continue

        findings.append(
            Theft(
                path=path,
                line=after,
                owner=pre_lines[owner_pre],
                thief=item_head(inserted, 0),
                stolen=pre_lines[after - 1],
            )
        )
    return findings


def locate_owner(post_lines: list[str], predicted: int, head: str) -> int | None:
    """Index of the victim item in the post-image, or `None`.

    The predicted index is exact for a pure insertion, because a `-U0`
    hunk's `+` start already carries every earlier hunk's shift and the
    victim sits immediately below the insertion. The window is there for
    the case where the same commit also edited the victim's own head line,
    and `None` (report it) is the honest answer when the item cannot be
    found at all: something moved, and this is not the place to guess what.
    """
    if 0 <= predicted < len(post_lines) and post_lines[predicted] == head:
        return predicted
    for offset in range(1, 6):
        for candidate in (predicted - offset, predicted + offset):
            if 0 <= candidate < len(post_lines) and post_lines[candidate] == head:
                return candidate
    return None


def parse_insertions(diff: str) -> dict[tuple[str, str], list[tuple[int, int, list[str]]]]:
    """Pure-insertion hunks per file, from a `-U0` unified diff.

    Keyed by `(pre-image path, post-image path)`. The two differ when the
    commit renamed the file, and both are needed: the pre-image blob is
    read at the old path and the post-image at the new one. Reading only
    `+++ b/` was the first version of this, and it made a theft inside a
    renamed file invisible.
    """
    per_file: dict[tuple[str, str], list[tuple[int, int, list[str]]]] = {}
    old_path: str | None = None
    new_path: str | None = None
    pending: tuple[int, int, list[str]] | None = None

    def flush() -> None:
        nonlocal pending
        if old_path is not None and new_path is not None and pending is not None and pending[2]:
            per_file.setdefault((old_path, new_path), []).append(pending)
        pending = None

    for line in diff.split("\n"):
        if line.startswith("diff --git"):
            flush()
            old_path = new_path = None
            continue
        if line.startswith("--- "):
            flush()
            rest = line[len("--- ") :]
            old_path = None if rest == "/dev/null" else rest[2:] if rest.startswith("a/") else rest
            continue
        if line.startswith("+++ "):
            flush()
            rest = line[len("+++ ") :]
            new_path = None if rest == "/dev/null" else rest[2:] if rest.startswith("b/") else rest
            continue
        match = HUNK.match(line)
        if match:
            flush()
            old_start = int(match.group(1))
            old_count = 1 if match.group(2) is None else int(match.group(2))
            new_start = int(match.group(3))
            if old_count == 0:
                pending = (old_start, new_start, [])
            continue
        if pending is not None:
            if line.startswith("+"):
                pending[2].append(line[1:])
            else:
                flush()
    flush()
    return per_file


# --- git ---------------------------------------------------------------


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    )


def inside_work_tree() -> bool:
    probe = _git("rev-parse", "--is-inside-work-tree")
    return probe.returncode == 0 and probe.stdout.strip() == "true"


def merge_ref_base(override_sha: str) -> str | None:
    """The base side of a `refs/pull/N/merge` checkout, when that is what
    HEAD is.

    `actions/checkout` on a `pull_request` event checks out a synthetic
    merge whose first parent is the base branch head *now* and whose
    second parent is the pull request head. On that shape `HEAD^1` is the
    base, exactly, and it is the only reading that does not depend on how
    old the event payload is.

    The three conditions are all necessary:

      * two parents, or HEAD is not a merge and `HEAD^1` means something
        else entirely (on a laptop it is the branch's previous commit);
      * the override is not HEAD, which is the `push` shape, where
        `github.sha` is HEAD and the empty diff is the right answer;
      * the override is an ancestor of HEAD, which is what says this
        merge really was built on top of the branch the override names.
    """
    parents = _git("rev-list", "--parents", "-n", "1", "HEAD")
    if parents.returncode != 0 or len(parents.stdout.split()) != 3:
        return None
    head = _git("rev-parse", "HEAD")
    if head.returncode != 0 or head.stdout.strip() == override_sha:
        return None
    if _git("merge-base", "--is-ancestor", override_sha, "HEAD").returncode != 0:
        return None
    first_parent = _git("rev-parse", "--verify", "HEAD^1")
    return first_parent.stdout.strip() if first_parent.returncode == 0 else None


def diff_base() -> tuple[str | None, str]:
    """The commit to diff against, and how it was chosen."""
    override = os.environ.get("ATTRIBUTE_THEFT_BASE_REF", "").strip()
    if override:
        resolved = _git("rev-parse", "--verify", f"{override}^{{commit}}")
        if resolved.returncode != 0:
            return None, f"ATTRIBUTE_THEFT_BASE_REF={override} does not resolve to a commit"
        base = resolved.stdout.strip()

        # On the event this runs on, the merge base is not a defence. A
        # `pull_request` checkout is `refs/pull/N/merge`, whose first
        # parent is the current base branch head, so a `base.sha` gone
        # stale behind a push to main is an *ancestor* of HEAD and
        # `merge-base(base.sha, HEAD) == base.sha`. Taking it would
        # attribute main's commits to this branch, which is precisely the
        # thing the merge base was supposed to prevent. Reachable by
        # re-running a job after main moves. Use the merge's own first
        # parent instead, which is the base as GitHub built it.
        pull_request_base = merge_ref_base(base)
        if pull_request_base is not None:
            return (
                pull_request_base,
                "first parent of the pull request merge ref "
                f"(ATTRIBUTE_THEFT_BASE_REF={override[:9]} is an ancestor of it)",
            )

        merge_base = _git("merge-base", base, "HEAD")
        if merge_base.returncode == 0:
            return merge_base.stdout.strip(), f"merge base with ATTRIBUTE_THEFT_BASE_REF ({override})"
        return base, f"ATTRIBUTE_THEFT_BASE_REF ({override}, verbatim: no merge base here)"

    for candidate in ("origin/main", "main"):
        resolved = _git("rev-parse", "--verify", f"{candidate}^{{commit}}")
        if resolved.returncode != 0:
            continue
        merge_base = _git("merge-base", resolved.stdout.strip(), "HEAD")
        if merge_base.returncode == 0:
            return merge_base.stdout.strip(), f"merge base with {candidate}"
    return None, "no base resolved; run `git fetch origin main`"


NO_BASE_HELP = """
This check is diff-scoped: it compares each inserted hunk against the
pre-image it landed in, so with no base it has nothing to say and must
not pretend otherwise. `scripts/check-stack-budget-ratchet.sh` exited 0
here once, which is how it ran on every pull request and checked nothing.

In CI: run this in a job whose checkout sets fetch-depth: 0, and pass
ATTRIBUTE_THEFT_BASE_REF (the pull request base commit).
On a laptop: git fetch origin main
"""


def check() -> int:
    if not inside_work_tree():
        print("check-attribute-theft: not inside a git work tree", file=sys.stderr)
        print(NO_BASE_HELP, file=sys.stderr)
        return 1

    base, how = diff_base()
    if base is None:
        print(f"check-attribute-theft: {how}", file=sys.stderr)
        print(NO_BASE_HELP, file=sys.stderr)
        return 1

    diff = _git(
        # A path git would otherwise quote and escape cannot be handed
        # back to `git show` verbatim.
        "-c",
        "core.quotePath=false",
        "diff",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        # M and R. Renames were dropped by the first version of this,
        # which made a theft inside a renamed file report clean: git
        # detects renames by default, so `git mv` plus an insertion was
        # invisible. The pre-image path comes off the `--- a/` line.
        "--diff-filter=MR",
        base,
        "--",
        "*.rs",
    )
    if diff.returncode != 0:
        print(f"check-attribute-theft: git diff against {base} failed", file=sys.stderr)
        print(diff.stderr.strip(), file=sys.stderr)
        return 1

    per_file = parse_insertions(diff.stdout)
    findings: list[Theft] = []
    for (old_path, new_path), hunks in sorted(per_file.items()):
        blob = _git("show", f"{base}:{old_path}")
        if blob.returncode != 0:
            # --diff-filter=MR promised a pre-image and git did not
            # produce one. Refuse rather than skip the file.
            print(
                f"check-attribute-theft: cannot read {old_path} at {base[:9]}",
                file=sys.stderr,
            )
            return 1
        try:
            post = (ROOT / new_path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            # The verdict needs both sides of the file, not just the hunk.
            # Without the post-image there is no verdict to give.
            print(
                f"check-attribute-theft: cannot read {new_path} in the work tree: {exc}",
                file=sys.stderr,
            )
            return 1
        findings.extend(
            find_theft(new_path, blob.stdout.split("\n"), post.split("\n"), hunks)
        )

    if not findings:
        print(
            f"no insertion landed inside an attribute block "
            f"({len(per_file)} Rust files carried an insertion, {how})"
        )
        return 0

    for finding in findings:
        print(finding.render(), file=sys.stderr)
        print(file=sys.stderr)
    print(
        "An item inserted between an attribute block and its owner takes the\n"
        "block with it. Move the insertion above the block or below the item\n"
        "it was meant to follow, and check that the doc comment still\n"
        "describes the function under it.",
        file=sys.stderr,
    )
    return 1


# --- Self-test ---------------------------------------------------------

# Verbatim from cf77910e9. The pre-image tail is the last three lines of
# `a_non_streaming_dispatch_fits_a_pingora_worker_stack`'s rustdoc plus the
# `#[test]` and `fn` it owned; the insertion is the head of the 55 lines
# that landed at `@@ -24032,0 +24033,55 @@`.
AI_DISPATCH_PRE = [
    "        /// What it still cannot see: the fixture provider is local",
    "        /// plaintext, so no TLS frames sit on this stack, and the release",
    "        /// binary's own path is not exercised here.",
    "        #[test]",
    "        fn a_non_streaming_dispatch_fits_a_pingora_worker_stack() {",
    "            const PINGORA_WORKER_STACK: usize = 2 * 1024 * 1024;",
    "        }",
]
AI_DISPATCH_INSERT = [
    "        /// The dispatch future's own size, pinned so a regression",
    "        /// fails here rather than in CI's request-path smoke lane.",
    "        ///",
    "        /// When this fails: box the new state or move it into its own",
    "        /// `async fn`, the way `d3c28199` did.",
    "        #[test]",
    "        fn the_dispatch_future_has_not_grown() {",
    "            const MEASURED: usize = 24_464;",
    "        }",
    "",
]

# Verbatim from eb42165a5, at `@@ -889,0 +1046,10 @@`.
ROLLBACK_PRE = [
    "/// The largest blast radius between two stored documents, or `None`",
    "/// when either fails to parse.",
    "///",
    "/// A parse failure is `None` rather than an error: an unparseable stored",
    "/// document is refused a few lines later by the reload transaction with",
    "/// a message that names the actual problem, and turning it into \"the",
    "/// blast radius is unknown\" here would refuse it with the wrong reason.",
    "pub(crate) fn plan_radius(baseline: &str, proposed: &str) -> Option<BlastRadius> {",
    "}",
]
ROLLBACK_INSERT = [
    "/// Whether one stored document still deserializes on this binary.",
    "///",
    "/// Used to tell the two unmeasurable-radius cases apart: a baseline that",
    "/// will not parse is a hazard, because nothing can then say what the",
    "/// change would do, while a target that will not parse is refused by the",
    "/// apply itself with a compile error worth more than a prompt.",
    "fn parses_as_config(text: &str) -> bool {",
    "    serde_yaml::from_str::<sbproxy_config::ConfigFile>(text).is_ok()",
    "}",
    "",
]


def self_test() -> int:
    failures: list[str] = []

    def expect(name: str, pre: list[str], after: int, inserted: list[str], caught: bool) -> None:
        """Apply the insertion to build the post-image, then judge it.

        The post-image is constructed rather than supplied so a fixture
        cannot describe a file that no insertion could produce, and so
        every fixture exercises the two-file comparison rather than the
        hunk alone.
        """
        post = pre[:after] + inserted + pre[after:]
        found = find_theft("fixture.rs", pre, post, [(after, after + 1, inserted)])
        if bool(found) != caught:
            verb = "missed" if caught else "invented"
            failures.append(f"{verb} a theft: {name}")

    # --- The two historical hunks. -------------------------------------
    expect("cf77910e9 ai_dispatch.rs", AI_DISPATCH_PRE, 3, AI_DISPATCH_INSERT, True)
    expect("eb42165a5 config_rollback.rs", ROLLBACK_PRE, 7, ROLLBACK_INSERT, True)

    # Same two insertions, moved one line later so they land after the
    # item head rather than inside the block. Nothing is stolen, and the
    # detector has to say so or it is reporting on the insertion rather
    # than on where it landed.
    expect("ai_dispatch, inserted below the item", AI_DISPATCH_PRE, 5, AI_DISPATCH_INSERT, False)
    expect("config_rollback, inserted below the item", ROLLBACK_PRE, 9, ROLLBACK_INSERT, False)

    # --- A stolen `#[cfg]`, from history. -------------------------------
    #
    # `45eafebfc crates/sbproxy/tests/listener_startup.rs:155`. A helper
    # was inserted between `#[cfg(unix)]` and the `#[test]` below it, so
    # `sigterm_cleanly_releases_a_prepared_public_listener` lost its unix
    # gate while the helper it calls, `serves_ok`, kept one. Nothing
    # observed the difference: no lane targets Windows, and on Windows
    # the test would have been a compile error rather than a silent run,
    # because `serves_ok` is `#[cfg(unix)]` too. The gate still had to
    # come back, because the next platform this builds on decides it.
    # The doc-comment cases are the ones history is full of; this is the
    # same shape on a `cfg`, and the guard has to be about the block
    # rather than about rustdoc.
    expect(
        "45eafebfc listener_startup.rs, a stolen #[cfg(unix)]",
        [
            "#[cfg(unix)]",
            "#[test]",
            "fn sigterm_cleanly_releases_a_prepared_public_listener() {",
            "}",
        ],
        1,
        [
            "/// Whether the proxy is serving on `port`, not merely listening.",
            "fn serves_ok(port: u16) -> bool {",
            "    true",
            "}",
            "",
        ],
        True,
    )

    # --- Positives that are not in history yet. ------------------------
    expect(
        "a stolen #[test]",
        ["    #[test]", "    fn the_guard() {", "    }"],
        1,
        ["    fn helper() -> u32 { 3 }", ""],
        True,
    )
    expect(
        "a stolen multi-line #[cfg]",
        [
            "#[cfg(all(",
            '    target_os = "linux",',
            '    feature = "gpu-cuda",',
            "))]",
            "fn on_cuda() {}",
        ],
        4,
        ["fn unconditional() {}", ""],
        True,
    )
    expect(
        "a stolen #[serde] on a struct field",
        [
            "struct Config {",
            '    #[serde(default = "one")]',
            "    retries: u32,",
            "}",
        ],
        2,
        ["    inserted: bool,"],
        True,
    )
    expect(
        "a block whose last line is an ordinary comment",
        ["/// doc", "// an aside", "fn owner() {}"],
        2,
        ["fn thief() {}", ""],
        True,
    )
    expect(
        "a block with a blank line inside it",
        ["/// doc", "", "fn owner() {}"],
        2,
        ["fn thief() {}", ""],
        True,
    )

    # --- The rotation git performs, which is not a theft. --------------
    #
    # Appending a `#[test] fn` immediately before an existing `#[test] fn`
    # is the commonest insertion in this repository's test modules, and
    # git reports it anchored one line early: the hunk starts with the
    # `fn` and ends with the `#[test]`, because the insertion's tail is
    # textually identical to the line above the insertion point. Read as a
    # hunk it is a stolen `#[test]`. Read as two files nothing moved.
    #
    # Taken from `1586de4cc crates/sbproxy-ai/src/failure_cause.rs`, hunk
    # `@@ -245,0 +314,25 @@`, reduced to its shape. `88953f9fc
    # handler.rs` is the same rotation. Those two are the whole of what
    # the file comparison suppresses over 260 merges: 23 findings from
    # the hunk alone, 21 from the files, and the delta is exactly them.
    #
    # `b9b0ac733 crates/sbproxy-core/src/policy_bus.rs`, hunk
    # `@@ -380,0 +381,44 @@`, was called the same rotation on a `///`
    # line by the first review of this script. It is not. Reading both
    # sides of the file shows `emit_decision_audit`'s block really did
    # end up on `emit_decision_audit_detailed`, and it reports, which is
    # the answer. The comparison is not a suppression list: it cuts both
    # ways, and this is the direction that matters.
    expect(
        "a #[test] fn appended before another, rotated by git",
        ["    #[test]", "    fn existing() {", "    }"],
        1,
        ["    fn appended() {", "    }", "", "    #[test]"],
        False,
    )
    expect(
        "a documented fn appended before another, rotated by git",
        ["/// doc for existing", "fn existing() {}"],
        1,
        ["fn appended() {}", "", "/// doc for existing"],
        False,
    )
    # The same rotation shape, except the owner really does lose lines:
    # the tail matches only the last line of a longer block.
    expect(
        "a rotation that still leaves the owner short",
        ["/// first line", "/// second line", "fn existing() {}"],
        2,
        ["fn thief() {}", "", "/// second line"],
        True,
    )

    # --- Negatives. ----------------------------------------------------
    expect(
        "a new item at a } boundary",
        ["fn first() {", "}", "", "/// doc", "fn second() {}"],
        2,
        ["", "fn inserted() {}"],
        False,
    )
    expect(
        "another line of rustdoc",
        ["/// doc", "fn owner() {}"],
        1,
        ["/// more doc"],
        False,
    )
    expect(
        "another attribute beside #[test]",
        ["    #[test]", "    fn owner() {}"],
        1,
        ['    #[ignore = "slow"]'],
        False,
    )
    expect(
        "an item below module docs",
        ["//! module docs", "//! more", "", "use std::io;"],
        2,
        ["", "use std::fmt;"],
        False,
    )
    expect(
        "an item below an inner attribute",
        ["#![allow(clippy::too_many_lines)]", "", "use std::io;"],
        1,
        ["", "use std::fmt;"],
        False,
    )
    expect(
        "a line that only looks like rustdoc inside a raw string",
        [
            "const FIXTURE: &str = r#\"",
            "/// this is data, not a doc comment",
            "\"#;",
            "fn after() {}",
        ],
        2,
        ["not code either, still inside the string"],
        False,
    )
    expect(
        "a line that only looks like an attribute inside a raw string",
        [
            "const FIXTURE: &str = r##\"",
            "#[test]",
            "\"##;",
            "fn after() {}",
        ],
        2,
        ["still data"],
        False,
    )
    expect(
        "an insertion at the top of the file",
        ["use std::io;"],
        0,
        ["//! new module docs"],
        False,
    )
    expect(
        "a block comment holding a doc-comment lookalike",
        ["/*", " /// not a doc comment", " */", "fn owner() {}"],
        2,
        ["fn thief() {}"],
        False,
    )

    # --- Fixtures that discriminate one lexer behavior each. ------------
    #
    # Each of these was checked against a build with the named behavior
    # reverted, and each goes red there. A fixture that passes either way
    # documents nothing, which is the failure this branch exists to name.

    # Hash-counted raw strings. Without them the `r#"` opens an ordinary
    # string that closes at the bare `"` inside, and the rest of the file
    # reads as one unterminated string, so the doc below is never seen.
    expect(
        "a raw string holding a bare quote, then a real theft below it",
        [
            'const S: &str = r#"a "b"#;',
            "/// real doc for owner",
            "fn owner() {}",
        ],
        2,
        ["fn thief() {}", ""],
        True,
    )

    # Nested block comments. `/* outer /* inner */ ... */` ends at the
    # second `*/`, not the first; ending early makes the commented-out
    # `#[derive]` look real.
    expect(
        "an attribute inside a nested block comment is not an attribute",
        ["/* outer", "   /* inner */", "   #[derive(Debug)] */", "struct Owner;"],
        3,
        ["struct Thief;"],
        False,
    )

    # Inner attributes attach to the enclosing module, so an item below
    # one steals nothing, and that has to hold across a multi-line inner
    # attribute as well as a single-line one.
    expect(
        "an item below a multi-line inner attribute",
        ["#![cfg_attr(", '    feature = "x",', "    allow(dead_code)", ")]", "use std::io;"],
        4,
        ["", "use std::fmt;"],
        False,
    )

    # A char literal holding a quote. Treated as a lifetime, the `"` opens
    # a string that never closes and the doc below is never seen.
    expect(
        "a char literal holding a quote, then a real theft below it",
        ["fn q() { let _ = '\"'; }", "/// real doc for owner", "fn owner() {}"],
        2,
        ["fn thief() {}", ""],
        True,
    )

    # An insertion at the very top of the file. There is no pre-existing
    # block above it, so nothing can be taken, and the guard is what says
    # so: without it the state read wraps to the last line of the file,
    # which here leaves a block open and would manufacture a finding.
    expect(
        "an insertion at the top of a file whose last line leaves a block open",
        ["/// doc for first", "fn first() {}", "", "/// a trailing doc comment"],
        0,
        ["fn inserted() {}", "", "/// extra"],
        False,
    )

    # --- The hunk parser. ----------------------------------------------
    diff = "\n".join(
        [
            "diff --git a/a.rs b/a.rs",
            "--- a/a.rs",
            "+++ b/a.rs",
            "@@ -10,0 +11,2 @@ mod x {",
            "+one",
            "+two",
            "@@ -20,2 +23,1 @@ mod x {",
            "-gone",
            "-gone",
            "+replacement",
            "@@ -30 +34 @@ mod x {",
            "-old",
            "+new",
        ]
    )
    parsed = parse_insertions(diff)
    if parsed != {("a.rs", "a.rs"): [(10, 11, ["one", "two"])]}:
        failures.append(f"hunk parser kept a hunk that is not a pure insertion: {parsed}")

    if parse_insertions("") != {}:
        failures.append("hunk parser invented a hunk from an empty diff")

    # A rename carries two different paths, and both are needed: the
    # pre-image blob is read at the old one. Reading only `+++ b/` made a
    # theft inside a renamed file report clean.
    renamed = "\n".join(
        [
            "diff --git a/src/old.rs b/src/new.rs",
            "similarity index 88%",
            "rename from src/old.rs",
            "rename to src/new.rs",
            "--- a/src/old.rs",
            "+++ b/src/new.rs",
            "@@ -4,0 +5,2 @@ mod x {",
            "+fn thief() {}",
            "+",
        ]
    )
    if parse_insertions(renamed) != {("src/old.rs", "src/new.rs"): [(4, 5, ["fn thief() {}", ""])]}:
        failures.append(
            f"hunk parser lost the pre-image path of a rename: {parse_insertions(renamed)}"
        )

    # A new file has no pre-image and nothing to steal from.
    added = "\n".join(
        [
            "diff --git a/src/new.rs b/src/new.rs",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/src/new.rs",
            "@@ -0,0 +1,2 @@",
            "+/// doc",
            "+fn f() {}",
        ]
    )
    if parse_insertions(added) != {}:
        failures.append("hunk parser kept a hunk from a file with no pre-image")

    # --- The classifier's own edges. -----------------------------------
    if block_open_at(["#[test]"], 1) is not True:
        failures.append("a single-line attribute did not open a block")
    if block_open_at(["#[cfg(all(", '    feature = "a",'], 2) is not True:
        failures.append("a multi-line attribute closed its block early")
    if block_open_at(["#[cfg(all(", '    feature = "a",', "))]"], 3) is not True:
        failures.append("a multi-line attribute did not open a block when it closed")
    if block_open_at(["/// doc", "fn f() {}"], 2) is not False:
        failures.append("an item did not consume its attribute block")
    if block_open_at(['let s = "a string with #[test] inside";'], 1) is not False:
        failures.append("an attribute inside a string literal opened a block")

    # --- `locate_owner`'s window. --------------------------------------
    # The predicted index is exact for a pure insertion, so every other
    # fixture here hits it and none of them reaches the window. That is
    # what let the window be narrowed to nothing with the self-test still
    # green: `None` means report, so shrinking it fails loud rather than
    # silently, but a behavior the docstring advertises and no fixture
    # exercises is an untested claim, which is the thing this file exists
    # to refuse. These land the victim's head off the prediction, both
    # ways and at the stated edge.
    owner_head = "fn victim() {}"
    if locate_owner([owner_head], 0, owner_head) != 0:
        failures.append("locate_owner missed the victim at the predicted index")
    for shift in (1, 5):
        below = ["filler"] * shift + [owner_head]
        if locate_owner(below, 0, owner_head) != shift:
            failures.append(f"locate_owner missed a victim {shift} line(s) below the prediction")
        above = [owner_head] + ["filler"] * shift
        if locate_owner(above, shift, owner_head) != 0:
            failures.append(f"locate_owner missed a victim {shift} line(s) above the prediction")
    if locate_owner(["filler"] * 6 + [owner_head], 0, owner_head) is not None:
        failures.append("locate_owner reached past the plus-or-minus-five window it advertises")
    if locate_owner([], 0, owner_head) is not None:
        failures.append("locate_owner found a victim in an empty post-image")

    for failure in failures:
        print(f"self-test: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("check-attribute-theft self-test: all fixtures pass")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="the gate; writes nothing")
    mode.add_argument("--self-test", action="store_true", help="run the fixtures")
    args = parser.parse_args()
    return self_test() if args.self_test else check()


if __name__ == "__main__":
    sys.exit(main())
