#!/usr/bin/env python3
"""One file per change, assembled into CHANGELOG.md at release time.

Every branch that appends to a shared `## [Unreleased]` heading edits the
same few lines, so every concurrent branch conflicts there, every time.
On 2026-08-20 five pull requests each needed a hand-resolution on that one
file and nothing else. A fragment directory removes the shared line: two
branches produce two files instead of two edits to one.

A fragment is a JSON object in `docs/.changes/`:

    docs/.changes/20260820-hmac-body-binding.json
    {
      "type": "security",
      "message": "`hmac_auth` now binds a signature to the body it covers."
    }

Modes
-----

``--new TYPE MESSAGE``
    Write a fragment and print its path. The filename is date-prefixed
    and slugged so two branches never pick the same name.

``--preview``
    Render the section the pending fragments would produce. Writes
    nothing.

``--release VERSION``
    Replace the `## [Unreleased]` placeholder with `## [VERSION] - DATE`
    carrying the assembled fragments, then delete the fragments it
    consumed. Released sections above and below are never touched.

``--check``
    The gate. Three rules, described under "What --check refuses".

``--self-test``
    In-process fixtures for the parser and the assembler. A gate whose
    parser quietly stopped refusing things reads green in exactly the
    place it is supposed to be strict, so the fixtures run wherever the
    gate does.

What --check refuses
--------------------

1. A malformed fragment: an unknown `type`, an empty `message`, an
   unexpected key, a filename that is not `YYYYMMDD-slug.json`.

2. Hand-written content under `## [Unreleased]`. The section body has to
   be the placeholder this script writes, byte for byte. This rule needs
   no git at all, so it holds identically on a laptop, in a shallow CI
   checkout, and on a rebased branch.

3. A commit that edits `CHANGELOG.md` without touching `docs/.changes/`
   in the same diff. Rule 2 already catches an appended entry; this one
   exists to deliver the message at the moment somebody reaches for the
   file, rather than after they have written the paragraph. A release
   assembly touches both (it deletes the fragments it consumed) and so
   passes, which is the exemption that keeps a release cut from having
   to disable the gate.

Why the two rules are both here: rule 3 alone is evadable by adding a
fragment and hand-editing the section anyway, and rule 2 alone says
nothing until after the entry is written. Each covers the other's hole.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
FRAGMENT_DIR = ROOT / "docs" / ".changes"

# Closed set, in the order a release section emits them. Ordered by what a
# reader upgrading needs first: what breaks, what was exploitable, then the
# ordinary Keep a Changelog run.
#
# The vocabulary is deliberately small. `[Unreleased]` carried two flavored
# headings before this existed ("Changed, and worth checking before you
# upgrade" and "Fixed, plan-time validation"); their entries migrated under
# `changed` and `fixed`, with the flavor kept in the entry text rather than
# in a heading only one release ever used. A release cut that wants a
# flavored heading edits it in the assembled section, which is a release
# commit and therefore already exempt from the direct-edit rule.
TYPES: dict[str, str] = {
    "breaking": "Breaking",
    "security": "Security",
    "added": "Added",
    "changed": "Changed",
    "deprecated": "Deprecated",
    "removed": "Removed",
    "fixed": "Fixed",
}

ALLOWED_KEYS = {"type", "message"}

FILENAME = re.compile(r"^(?P<date>\d{8})-(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)\.json$")

# CHANGELOG.md wraps its prose here. Assembly re-wraps every message to the
# same width so a fragment written as one long line and a fragment written
# with newlines in it render identically.
WRAP = 72

UNRELEASED_HEADING = "## [Unreleased]"
VERSION_HEADING = re.compile(r"^## \[\d+\.\d+\.\d+\] - \d{4}-\d{2}-\d{2}\s*$")

# The exact body `## [Unreleased]` must carry between releases. `--check`
# compares against this, so editing it here without editing the file (or
# the reverse) fails the gate rather than drifting quietly.
PLACEHOLDER = """\
Entries for the next version cut are not written here. Each one is a
separate file under [`docs/.changes/`](docs/.changes/), so two branches
landing the same night produce two files instead of one conflict.

Render what the next release will say with
`python3 scripts/changelog-fragments.py --preview`."""


class FragmentError(Exception):
    """A fragment that cannot be trusted to assemble."""


# --- Fragments ---------------------------------------------------------


def fragment_paths() -> list[Path]:
    """Every candidate fragment file, sorted by name.

    Sorted by name and not by mtime: the filename carries the date, and a
    checkout gives every file the same mtime, so mtime ordering would make
    the assembled section's order depend on which machine cut the release.
    Everything visible in the directory except the schema README is a
    candidate, including files with the wrong extension, so a fragment
    saved as `.txt` is reported rather than silently ignored. Hidden
    files are skipped as OS junk.
    """
    if not FRAGMENT_DIR.is_dir():
        return []
    return sorted(
        path
        for path in FRAGMENT_DIR.iterdir()
        # Hidden files are OS junk (.DS_Store on any checkout Finder
        # has visited), not authored fragments, and refusing a release
        # over one helps nobody. Everything visible except the schema
        # README stays a candidate, including wrong extensions, so a
        # fragment saved as `.txt` is reported rather than ignored.
        if path.is_file() and path.name != "README.md" and not path.name.startswith(".")
    )


def parse_fragment(path: Path, text: str) -> tuple[str, str]:
    """Validate one fragment and return `(type, message)`.

    Raises `FragmentError` with a message naming the fix. Every rule here
    is a shape the assembler would otherwise have to guess at.
    """
    name_match = FILENAME.match(path.name)
    if not name_match:
        raise FragmentError(
            f"filename must be YYYYMMDD-slug.json (lowercase slug), got {path.name!r}"
        )
    try:
        dt.date(
            int(name_match.group("date")[0:4]),
            int(name_match.group("date")[4:6]),
            int(name_match.group("date")[6:8]),
        )
    except ValueError as exc:
        raise FragmentError(f"filename date is not a real date: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FragmentError(f"not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FragmentError("must be a JSON object with `type` and `message`")

    unknown = sorted(set(data) - ALLOWED_KEYS)
    if unknown:
        raise FragmentError(
            f"unexpected key(s) {', '.join(unknown)}; only `type` and `message` are read"
        )
    missing = sorted(ALLOWED_KEYS - set(data))
    if missing:
        raise FragmentError(f"missing key(s): {', '.join(missing)}")

    kind = data["type"]
    if not isinstance(kind, str) or kind not in TYPES:
        raise FragmentError(
            f"type must be one of {', '.join(sorted(TYPES))}, got {kind!r}"
        )

    message = data["message"]
    if not isinstance(message, str) or not message.strip():
        raise FragmentError("message must be a non-empty string")
    return kind, message


def load_fragments() -> tuple[list[tuple[Path, str, str]], list[str]]:
    """Every fragment, plus one error line per fragment that failed."""
    loaded: list[tuple[Path, str, str]] = []
    errors: list[str] = []
    for path in fragment_paths():
        rel = path.relative_to(ROOT).as_posix()
        try:
            kind, message = parse_fragment(path, path.read_text(encoding="utf-8"))
        except FragmentError as exc:
            errors.append(f"{rel}: {exc}")
            continue
        except OSError as exc:
            errors.append(f"{rel}: unreadable: {exc}")
            continue
        loaded.append((path, kind, message))
    return loaded, errors


# --- Rendering ---------------------------------------------------------


def unwrap(message: str) -> list[str]:
    """Split a message into paragraphs with their soft line breaks removed.

    A migrated fragment carries the line breaks the CHANGELOG had; a
    hand-written one is usually a single long line. Both have to render
    the same, so the breaks inside a paragraph are dropped here and put
    back by `wrap_entry` at a single width. Blank lines survive as
    paragraph boundaries.
    """
    paragraphs: list[str] = []
    for block in re.split(r"\n\s*\n", message.strip()):
        collapsed = " ".join(part.strip() for part in block.split("\n") if part.strip())
        if collapsed:
            paragraphs.append(collapsed)
    return paragraphs


def wrap_entry(message: str) -> list[str]:
    """One fragment as CHANGELOG list-item lines."""
    lines: list[str] = []
    for index, paragraph in enumerate(unwrap(message)):
        wrapped = textwrap.wrap(
            paragraph,
            width=WRAP,
            initial_indent="- " if index == 0 else "  ",
            subsequent_indent="  ",
            break_long_words=False,
            break_on_hyphens=False,
        )
        if index:
            lines.append("")
        lines.extend(wrapped)
    return lines


def render_body(fragments: list[tuple[Path, str, str]]) -> list[str]:
    """The `### ` groups a set of fragments assembles into."""
    if not fragments:
        return ["No user-visible changes."]
    lines: list[str] = []
    for kind, heading in TYPES.items():
        group = [message for _, fragment_kind, message in fragments if fragment_kind == kind]
        if not group:
            continue
        if lines:
            lines.append("")
        lines.append(f"### {heading}")
        for message in group:
            lines.append("")
            lines.extend(wrap_entry(message))
    return lines


# --- CHANGELOG surgery -------------------------------------------------


def changelog_lines() -> list[str]:
    return CHANGELOG.read_text(encoding="utf-8").split("\n")


def unreleased_span(lines: list[str]) -> tuple[int, int]:
    """Line indices of the `## [Unreleased]` body, heading excluded.

    The end is the next `## ` heading, which is the first released
    section. Everything from that line down is never read or written by
    this script.
    """
    try:
        start = lines.index(UNRELEASED_HEADING)
    except ValueError as exc:
        raise FragmentError(
            f"CHANGELOG.md has no {UNRELEASED_HEADING!r} heading"
        ) from exc
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("## "):
            return start + 1, index
    return start + 1, len(lines)


def unreleased_body(lines: list[str]) -> str:
    start, end = unreleased_span(lines)
    return "\n".join(lines[start:end]).strip("\n")


def release(version: str, date: str) -> int:
    """Assemble the pending fragments into a new version section."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"--release wants a bare x.y.z version, got {version!r}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        print(f"--date wants YYYY-MM-DD, got {date!r}", file=sys.stderr)
        return 2

    fragments, errors = load_fragments()
    if errors:
        for error in errors:
            print(f"changelog fragment: {error}", file=sys.stderr)
        return 1

    lines = changelog_lines()
    if any(line.startswith(f"## [{version}] ") for line in lines):
        print(f"CHANGELOG.md already has a [{version}] section", file=sys.stderr)
        return 1

    start, end = unreleased_span(lines)
    section = [
        "",
        *PLACEHOLDER.split("\n"),
        "",
        f"## [{version}] - {date}",
        "",
        *render_body(fragments),
        "",
    ]
    lines[start:end] = section
    CHANGELOG.write_text("\n".join(lines), encoding="utf-8")

    for path, _, _ in fragments:
        path.unlink()

    print(f"assembled {len(fragments)} fragment(s) into CHANGELOG.md as [{version}]")
    if fragments:
        print("removed:")
        for path, _, _ in fragments:
            print(f"  {path.relative_to(ROOT).as_posix()}")
    return 0


# --- The gate ----------------------------------------------------------


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    )


def inside_work_tree() -> bool:
    """Whether git can answer questions about this checkout at all.

    A source tarball is not a work tree, and the direct-edit rule is
    meaningless there because there is nothing to diff against. This is
    the ONLY thing that turns that rule off, and it is deliberately not
    an environment variable: a knob that disables half a gate is a knob a
    workflow can set. GitHub checkouts are always work trees.
    """
    probe = _git("rev-parse", "--is-inside-work-tree")
    return probe.returncode == 0 and probe.stdout.strip() == "true"


def diff_base() -> tuple[str | None, str]:
    """The commit to diff against, and how it was chosen.

    `CHANGELOG_BASE_REF` names the ref CI wants the diff scoped to, but
    it is not trusted as the merge base itself: a pull request's
    `base.sha` is the base branch head at event time, and the checkout
    is a synthetic merge carrying current main, so a `base.sha` gone
    stale behind a direct push to main would attribute main's commits
    to this branch. Take the merge base with HEAD when history allows
    it (the guards lane checks out with full depth) and fall back to
    the ref verbatim in a shallow checkout. Without the override,
    resolve `origin/main` and take the merge base with HEAD, which is
    what a laptop or a worktree wants.
    """
    override = os.environ.get("CHANGELOG_BASE_REF", "").strip()
    if override:
        resolved = _git("rev-parse", "--verify", f"{override}^{{commit}}")
        if resolved.returncode != 0:
            return None, f"CHANGELOG_BASE_REF={override} does not resolve to a commit"
        base = resolved.stdout.strip()
        merge_base = _git("merge-base", base, "HEAD")
        if merge_base.returncode == 0:
            return (
                merge_base.stdout.strip(),
                f"merge base with CHANGELOG_BASE_REF ({override})",
            )
        return base, f"CHANGELOG_BASE_REF ({override}, verbatim: no merge base here)"

    resolved = _git("rev-parse", "--verify", "origin/main^{commit}")
    if resolved.returncode != 0:
        return None, "origin/main is not present; run `git fetch origin main`"
    merge_base = _git("merge-base", resolved.stdout.strip(), "HEAD")
    if merge_base.returncode != 0:
        return None, "no merge base with origin/main; run `git fetch origin main`"
    return merge_base.stdout.strip(), "merge base with origin/main"


def changed_paths(base: str) -> list[str] | None:
    """Paths this branch changed, working tree and new files included.

    `git diff` only reports tracked files, and a fragment is a brand new
    file: on a laptop, before `git add`, the whole directory is invisible
    to it. Untracked-but-not-ignored paths are therefore listed
    separately and unioned in, so a local run sees the fragment the
    author just wrote rather than telling them they hand-edited the
    CHANGELOG.
    """
    diff = _git("diff", "--name-only", base)
    if diff.returncode != 0:
        return None
    untracked = _git("ls-files", "--others", "--exclude-standard")
    if untracked.returncode != 0:
        return None
    combined = diff.stdout.split("\n") + untracked.stdout.split("\n")
    return sorted({line for line in combined if line.strip()})


def check() -> int:
    status = 0

    fragments, errors = load_fragments()
    for error in errors:
        print(f"changelog fragment: {error}", file=sys.stderr)
        status = 1
    if errors:
        print(
            "\nA fragment is a JSON object with exactly `type` and `message`.\n"
            f"Types: {', '.join(sorted(TYPES))}.\n"
            "See docs/.changes/README.md.",
            file=sys.stderr,
        )

    try:
        body = unreleased_body(changelog_lines())
    except FragmentError as exc:
        print(f"CHANGELOG.md: {exc}", file=sys.stderr)
        return 1
    if body != PLACEHOLDER:
        print(
            "CHANGELOG.md: the [Unreleased] section carries hand-written content.\n"
            "\n"
            "Entries go in one file per change so concurrent branches stop\n"
            "conflicting on this one heading. Move each entry into its own\n"
            "fragment and restore the placeholder:\n"
            "\n"
            "  python3 scripts/changelog-fragments.py --new added 'what changed'\n"
            "\n"
            "See docs/.changes/README.md for the schema.",
            file=sys.stderr,
        )
        status = 1

    if not inside_work_tree():
        print(
            "changelog guard: not a git work tree, so the direct-edit rule has\n"
            "nothing to diff against. The fragment schema and the [Unreleased]\n"
            "placeholder were still checked."
        )
        return status

    base, how = diff_base()
    if base is None:
        print(f"changelog guard: cannot determine a base commit: {how}", file=sys.stderr)
        return 1
    paths = changed_paths(base)
    if paths is None:
        print(f"changelog guard: `git diff` against {base} failed", file=sys.stderr)
        return 1
    touched_changelog = "CHANGELOG.md" in paths
    touched_fragments = any(path.startswith("docs/.changes/") for path in paths)
    if touched_changelog and not touched_fragments:
        print(
            f"CHANGELOG.md is edited directly (base: {how}).\n"
            "\n"
            "Add a fragment instead. One file per change means two branches\n"
            "landing the same night produce two files rather than one\n"
            "conflict on this heading:\n"
            "\n"
            "  python3 scripts/changelog-fragments.py --new fixed 'what changed'\n"
            "\n"
            "A release cut is the exception, and it needs no flag: assembling\n"
            "fragments deletes them, so the same diff touches docs/.changes/.\n"
            "\n"
            "A correction to an already-released section is also legitimate.\n"
            "Its fragment is gone (assembling a release deletes them), so\n"
            "pair the edit with a note in docs/.changes/README.md saying what\n"
            "you corrected and this guard stands down. Do not add a new\n"
            "fragment for a released-section fix; it would ship as a fresh\n"
            "entry in the next release's notes.",
            file=sys.stderr,
        )
        status = 1

    if status == 0:
        print(
            f"changelog: {len(fragments)} pending fragment(s), "
            "[Unreleased] untouched, CHANGELOG.md not hand-edited"
        )
    return status


# --- Authoring ---------------------------------------------------------


def slugify(message: str, limit: int = 6) -> str:
    words = re.findall(r"[a-z0-9]+", message.lower())
    slug = "-".join(words[:limit])
    return slug or "change"


def new(kind: str, message: str, slug: str | None) -> int:
    if kind not in TYPES:
        print(
            f"type must be one of {', '.join(sorted(TYPES))}, got {kind!r}",
            file=sys.stderr,
        )
        return 2
    if not message.strip():
        print("message must not be empty", file=sys.stderr)
        return 2

    FRAGMENT_DIR.mkdir(parents=True, exist_ok=True)
    stem = slugify(slug or message)
    date = dt.date.today().strftime("%Y%m%d")
    path = FRAGMENT_DIR / f"{date}-{stem}.json"
    suffix = 2
    while path.exists():
        path = FRAGMENT_DIR / f"{date}-{stem}-{suffix}.json"
        suffix += 1

    payload = {"type": kind, "message": " ".join(message.split())}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(path.relative_to(ROOT).as_posix())
    return 0


# --- Self-test ---------------------------------------------------------


def self_test() -> int:
    """Fixtures for the parser and the assembler."""
    failures: list[str] = []

    def expect_refused(name: str, filename: str, text: str) -> None:
        try:
            parse_fragment(FRAGMENT_DIR / filename, text)
        except FragmentError:
            return
        failures.append(f"accepted a fragment it must refuse: {name}")

    def expect_accepted(name: str, filename: str, text: str) -> None:
        try:
            parse_fragment(FRAGMENT_DIR / filename, text)
        except FragmentError as exc:
            failures.append(f"refused a valid fragment ({name}): {exc}")

    good = '{"type": "fixed", "message": "It works."}'
    expect_accepted("minimal", "20260820-ok.json", good)
    expect_refused("bad filename", "ok.json", good)
    expect_refused("uppercase slug", "20260820-OK.json", good)
    expect_refused("impossible date", "20261340-ok.json", good)
    expect_refused("not json", "20260820-ok.json", "type: fixed")
    expect_refused("not an object", "20260820-ok.json", '["fixed"]')
    expect_refused("unknown type", "20260820-ok.json", '{"type": "nope", "message": "x"}')
    expect_refused("empty message", "20260820-ok.json", '{"type": "fixed", "message": "  "}')
    expect_refused(
        "extra key",
        "20260820-ok.json",
        '{"type": "fixed", "message": "x", "pr": 1}',
    )
    expect_refused("missing message", "20260820-ok.json", '{"type": "fixed"}')
    expect_refused("non-string message", "20260820-ok.json", '{"type": "fixed", "message": 3}')

    # A fragment carrying the line breaks a migrated CHANGELOG entry had
    # and one written as a single line must render to the same lines.
    wrapped = wrap_entry("alpha bravo charlie\ndelta echo foxtrot")
    flat = wrap_entry("alpha bravo charlie delta echo foxtrot")
    if wrapped != flat:
        failures.append(f"soft line breaks changed the render: {wrapped} != {flat}")

    # Paragraph breaks survive.
    para = wrap_entry("first para.\n\nsecond para.")
    if "" not in para or para[0] != "- first para." or para[-1] != "  second para.":
        failures.append(f"paragraph break not preserved: {para}")

    # No line the assembler emits exceeds the wrap width, and continuation
    # lines are indented so the list item holds together.
    long_entry = wrap_entry("word " * 60)
    if any(len(line) > WRAP for line in long_entry):
        failures.append("assembled a line wider than the wrap width")
    if any(line and not line.startswith("  ") for line in long_entry[1:]):
        failures.append("a continuation line lost its indent")

    # Groups come out in TYPES order regardless of fragment order.
    body = render_body(
        [
            (FRAGMENT_DIR / "a.json", "fixed", "f"),
            (FRAGMENT_DIR / "b.json", "added", "a"),
            (FRAGMENT_DIR / "c.json", "security", "s"),
        ]
    )
    headings = [line for line in body if line.startswith("### ")]
    if headings != ["### Security", "### Added", "### Fixed"]:
        failures.append(f"group order wrong: {headings}")

    if render_body([]) != ["No user-visible changes."]:
        failures.append("an empty release must still say something")

    # The placeholder this script writes has to be the placeholder it
    # accepts, or --release leaves the tree failing --check.
    if unreleased_body(("x\n" + UNRELEASED_HEADING + "\n" + PLACEHOLDER + "\n\n## [1.0.0] - 2026-01-01").split("\n")) != PLACEHOLDER:
        failures.append("placeholder does not round-trip through unreleased_body")

    for failure in failures:
        print(f"self-test: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("changelog-fragments self-test: all fixtures pass")
    return 0


# --- Entry point -------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="the gate; writes nothing")
    mode.add_argument("--preview", action="store_true", help="render the pending section")
    mode.add_argument("--release", metavar="VERSION", help="assemble into CHANGELOG.md")
    mode.add_argument("--new", nargs=2, metavar=("TYPE", "MESSAGE"), help="write a fragment")
    mode.add_argument("--self-test", action="store_true", help="run the parser fixtures")
    parser.add_argument("--date", default=dt.date.today().isoformat(), help="release date")
    parser.add_argument("--slug", help="filename slug for --new")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.new:
        return new(args.new[0], args.new[1], args.slug)
    if args.release:
        return release(args.release, args.date)
    if args.preview:
        fragments, errors = load_fragments()
        for error in errors:
            print(f"changelog fragment: {error}", file=sys.stderr)
        print("\n".join(render_body(fragments)))
        return 1 if errors else 0
    return check()


if __name__ == "__main__":
    sys.exit(main())
