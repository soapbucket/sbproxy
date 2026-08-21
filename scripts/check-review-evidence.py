#!/usr/bin/env python3
"""Refuse a pull request whose body carries no adversarial-review evidence.

# Why this exists

`CLAUDE.md` and `AGENTS.md` have required an adversarial review against
`.github/code-review-rubric.md` before a branch becomes a PR, with the
findings and their resolutions recorded in the PR body, since 2026-08-14.
Nothing enforced it. An audit on 2026-08-20 found 31 pull requests merged
since 2026-08-19, 30 of them with no GitHub review at all and 26 with no
review evidence anywhere in the body. Retrospective rubric runs against
three of those merged branches then turned up an auth forgery primitive,
four Blockers, and eight Majors, all on code that had shipped with every
mechanical gate green.

This script is the checkable half. It cannot know whether a review
actually happened, and does not pretend to: what it checks is that the
author made a specific, attributable claim about one, in a shape a reader
can audit later against the diff it shipped with.

It does not block a merge on its own. `main-protection` requires one
status check, `build / test`, and until `adversarial review evidence`
joins it this script produces a visible red X and nothing more. The
header of `.github/workflows/review-evidence.yml` carries the reasoning
and what has to happen first. Saying so here as well, because a reader
who opens only this file would otherwise conclude the rule now blocks
merges, and that conclusion is the exact thing this change exists to
stop shipping.

# What it requires

An `## Adversarial review` heading, and beneath it:

  1. A `Reviewer:` line naming who or what ran the rubric. Placeholders
     (`TBD`, `TODO`, `N/A`, `none`, `?`) are refused.
  2. A `Findings:` line carrying a count for each of Blocker, Major, and
     Minor, or the literal `Findings: none`.
  3. One list item per declared finding, leading with its severity and
     carrying a disposition sentence that starts `Fixed`, `Accepted`, or
     `Filed`. The item count per severity must equal the declared count
     in both directions, so an undercounted summary fails the same way
     an undocumented finding does.
  4. A `Verification:` line when the counts are not all zero, because
     CLAUDE.md requires a verification round on the fixes whenever the
     first round finds anything. Without this the rule would be one more
     documented-and-unenforced sentence, which is the failure this whole
     script exists to stop repeating.

Whitespace alone never satisfies anything here. Every requirement is a
positive match against content, so an empty section fails all of them.

# Reading the body the way a human reads it

An author's evidence has to be evidence to the *reader* of the PR, which
means the checker has to agree with GitHub's renderer about what is
prose and what is not. Four places where a naive parser disagrees, all
of them found by an adversarial review of this file:

  - An HTML comment that is never closed runs to the end of the document
    (CommonMark HTML block type 2). A body ending `<!-- notes` followed
    by a perfect evidence block renders as nothing at all.
  - A closing code fence has to be at least as long as the one that
    opened it, so ``` inside a ```` block is content, not a close.
  - Leading tabs are four columns, not one character, so a tab-indented
    heading is an indented code block to the reader. Indentation is
    counted in columns and only ordinary spaces count, because NBSP and
    form feed are not indentation in CommonMark either.
  - A heading may carry a closing `##` sequence, doubled spaces, or a
    suffix like `(round 2)` and still render as the same heading.

# What it does not check

Whether the review happened, whether the reviewer was adversarial, and
whether the findings are real. Those are unfalsifiable from a PR body.
The rubric's own "How to run it" section is the instruction; this is the
receipt.

Pull requests opened by Renovate or Dependabot pass without evidence:
they raise lockfile and action-digest bumps on a schedule and merge some
of them automatically, and a check no bot can ever satisfy would deadlock
those rather than gate them. The exemption is an allowlist of two logins
and also demands `user.type == "Bot"`, so the repository's own
`github-actions[bot]` automation, which opens PRs that change vendored
fixtures, still has to carry evidence like anyone else.

Usage:

    python3 scripts/check-review-evidence.py --event-path "$GITHUB_EVENT_PATH"
    python3 scripts/check-review-evidence.py --body-file body.md
    python3 scripts/check-review-evidence.py --stdin < body.md
    python3 scripts/check-review-evidence.py --self-test

Exit codes: 0 the body carries usable evidence (or the author is an
exempt bot), 1 it does not, 2 the invocation itself was wrong.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
import unicodedata
from pathlib import Path

DOC_POINTER = (
    "The expected shape is documented in the \"Code review\" section of\n"
    "CLAUDE.md and AGENTS.md, and the rubric itself is\n"
    ".github/code-review-rubric.md."
)

# The three severities the rubric defines as findings. `Sound` is
# deliberately absent: it is the rubric's word for "checked, no finding",
# and counting it here would let a wall of Sound lines stand in for the
# findings list.
SEVERITIES = ("Blocker", "Major", "Minor")

# The dispositions a finding may end in. Small on purpose: a closed
# vocabulary is what makes the line machine-checkable, and the failure
# message prints the whole set, so nobody has to guess.
DISPOSITIONS = ("Fixed", "Accepted", "Filed")

# Values that look like an answer and are not one. Compared against the
# whole field value, lowercased and stripped of trailing periods, so a
# real answer that happens to contain the word "none" is unaffected.
PLACEHOLDERS = {
    "",
    "-",
    "--",
    "?",
    "???",
    "n/a",
    "na",
    "none",
    "no",
    "nobody",
    "tbd",
    "tk",
    "todo",
    "who",
    "x",
    "xxx",
    "fill in",
    "fill this in",
    "name",
    "reviewer",
}

# Renovate and Dependabot only. Not `user.type == "Bot"`, which would also
# exempt `github-actions[bot]`; licensing-conformance.yml opens PRs under
# that identity that rewrite vendored fixtures and whose own commit
# message asks for a human to review the diff.
EXEMPT_BOTS = frozenset({"renovate[bot]", "dependabot[bot]"})

SECTION_TITLE = "adversarial review"

# Indentation is columns, and only ordinary spaces produce it. Tabs are
# expanded to four-column stops before any of these run.
HEADING = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*$")

# A line that opens a CommonMark HTML block comment (type 2).
BLOCK_COMMENT_OPEN = re.compile(r"^ {0,3}<!--")

# ``` or ~~~ opening or closing a fence, with an optional info string.
# The run length is captured because a closing fence must be at least as
# long as the fence that opened the block.
FENCE = re.compile(r"^ {0,3}((`{3,})|(~{3,}))\s*(.*)$")


def field_pattern(key: str) -> re.Pattern[str]:
    """A `Key: value` line, tolerating a list marker and emphasis.

    `**Reviewer:**` and `**Reviewer**:` both appear in the wild and both
    render identically, so both have to match.
    """
    return re.compile(
        r"^ {0,3}(?:[-*+]\s+)?[*_`]{0,3}\s*"
        + key
        + r"\s*[*_`]{0,3}\s*:\s*(.*?)\s*$",
        re.IGNORECASE,
    )


REVIEWER_LINE = field_pattern("Reviewer")
FINDINGS_LINE = field_pattern("Findings")
VERIFICATION_LINE = field_pattern("Verification")
FIELD_LINES = (REVIEWER_LINE, FINDINGS_LINE, VERIFICATION_LINE)

# A markdown list item. Ordered and unordered both, since people write
# either and neither is more honest than the other.
ITEM_START = re.compile(r"^ {0,3}(?:[-*+]|\d+[.)])\s+(.*)$")

# A markdown table row, and the `|---|---|` line under a header. A table
# is what a real reviewer reaches for once the finding count passes about
# five: PR #1178 recorded 21 findings that way, with a Disposition
# column. Refusing that shape would refuse the only body in this
# repository's history that actually documented its dispositions.
TABLE_ROW = re.compile(r"^ {0,3}\|(.+)\|\s*$")
TABLE_SEPARATOR = re.compile(r"^[\s|:-]+$")

# `2 Blocker`, `2 Blockers`, `2 **Major**`. Order-independent.
COUNT = re.compile(r"(\d+)\s*[*_`]{0,3}\s*(blocker|major|minor)s?\b", re.IGNORECASE)

# The severity a list item leads with, which is the only position that
# counts. Prose elsewhere in the item that happens to say "Major" is not
# a second finding.
ITEM_SEVERITY = re.compile(r"^[*_`]{0,3}\s*(blocker|major|minor)\b", re.IGNORECASE)

# A disposition has to be capitalized and start a clause, so that an
# ordinary finding description ("the endpoint accepted a forged token")
# cannot pass for one. Deliberately not IGNORECASE.
#
# The clause boundaries are wider than sentence-enders because people
# write `boom, Fixed in this branch`, `boom; Fixed`, `boom: Fixed`,
# `boom [Fixed]`, and a bare line break where a period would go. Refusing
# those is how a gate teaches people to route around it. The trailing
# `(?![\w-])` is what keeps `Fixed-size columns are the cause` from
# reading as a disposition.
#
# Residual and accepted: `Accepted values are only a and b` at a clause
# start still counts. Separating that from a real disposition needs to
# understand English, and the cost of guessing wrong is refusing an
# honest author.
DISPOSITION_SENTENCE = re.compile(
    r"(?:^|[.!?]\)?\s+|[,;:]\s+|\n\s*|\s-\s+|[(\[]\s*)[*_`]{0,3}("
    + "|".join(DISPOSITIONS)
    + r")(?![\w-])"
)


def strip_html_comments(text: str) -> str:
    """Blank out HTML comments, preserving line numbering.

    Two constructs share the syntax and they end differently, which is
    the whole difficulty.

    A line whose content starts with `<!--` opens a CommonMark HTML block
    (type 2). It ends at the end of the line containing `-->`, or at the
    end of the document when there is none. The second half matters: a
    body that trails off after `<!-- notes` renders as nothing from there
    on, so a perfect evidence block underneath is invisible to every
    human reader.

    Anywhere else on a line, `<!--` is inline raw HTML, and inline
    content is not confined to one line. `note <!--` followed by an
    evidence block and a `-->` two lines later is one paragraph holding
    one comment, and cmark plus `html.parser` agree that the only
    visible token is `note`. Scoping the closer search to a single line
    let exactly that through. So an inline opener is paired against the
    rest of the *document*.

    An inline `<!--` with no `-->` anywhere after it is not a comment at
    all: CommonMark leaves it as literal text and GitHub shows it. That
    case has to stay live, because this repository's own pull request
    body says `<!--` inside backticks while describing this function,
    and blanking to end of document there made the gate refuse its own
    PR.

    The pull request template is largely HTML comments, and documenting
    the evidence shape inside one is the obvious thing to do. If a
    commented-out example satisfied the gate, the template would defeat
    it on every PR that left the stub untouched.
    """
    out: list[str] = []
    pos = 0
    while True:
        idx = text.find("<!--", pos)
        if idx == -1:
            out.append(text[pos:])
            return "".join(out)
        line_start = text.rfind("\n", 0, idx) + 1
        prefix = text[line_start:idx]
        opens_block = prefix == " " * len(prefix) and len(prefix) <= 3
        close = text.find("-->", idx + 4)
        if close == -1:
            if not opens_block:
                # Literal text. The reader sees it, so the checker does.
                out.append(text[pos:])
                return "".join(out)
            # An HTML block with no closer runs to the end of the document.
            out.append(text[pos:idx])
            out.append("\n" * text.count("\n", idx))
            return "".join(out)
        if opens_block:
            # The block swallows the remainder of the closing line too.
            line_end = text.find("\n", close)
            stop = len(text) if line_end == -1 else line_end
        else:
            stop = close + 3
        out.append(text[pos:idx])
        out.append("\n" * text.count("\n", idx, stop))
        pos = stop


def live_lines(text: str) -> list[tuple[int, str]]:
    """Return `(lineno, line)` for every line outside a fenced block.

    Fenced content is shown, not asserted. A body that pastes the
    documented example into a ```markdown block has quoted the format,
    not filled it in. A closing fence must use the same character and be
    at least as long as the opening one, so a shorter run inside a longer
    block stays content.
    """
    out: list[tuple[int, str]] = []
    fence_char: str | None = None
    fence_len = 0
    for lineno, line in enumerate(text.split("\n"), start=1):
        m = FENCE.match(line)
        if m:
            run = m.group(1)
            info = m.group(4).strip()
            if fence_char is None:
                fence_char, fence_len = run[0], len(run)
                continue
            if run[0] == fence_char and len(run) >= fence_len and not info:
                fence_char, fence_len = None, 0
                continue
        if fence_char is None:
            out.append((lineno, line))
    return out


def heading_title(raw: str) -> str:
    """Normalize a heading to what a reader sees.

    `## Adversarial review ##`, `## Adversarial  review`, and
    `## **Adversarial review**` all render the same, so all three have to
    resolve to the same title.
    """
    title = raw.strip().strip("*_`").strip().rstrip(":").strip()
    # A trailing ATX close (`## Title ##`) needs no special handling: the
    # title is matched as a prefix, so `Adversarial review ##` still
    # starts with `adversarial review`. The fixture for that shape is
    # kept anyway, because it protects the behavior if the match ever
    # tightens.
    return re.sub(r"\s+", " ", title)


def find_sections(
    lines: list[tuple[int, str]],
) -> list[tuple[int, list[tuple[int, str]]]]:
    """Every `Adversarial review` heading and the lines beneath it.

    A section ends at the next heading of the same level or higher, which
    is what a reader's eye does. Subheadings stay inside it, because a
    real review with more than a handful of findings groups them: PR
    #1178 put its 21 under `### Majors` and `### Minors`, and ending the
    section at the first subheading would have hidden every one of them.

    The exception is a `Checked and sound` subsection, which the rubric
    asks for and which is a list of things that are *not* findings. A
    line there reading `- Blocker: none in the config reader` is a clean
    bill of health, and counting it as a finding that forgot its
    disposition would refuse an author for following the rubric.

    The title is matched as a prefix, so `## Adversarial review evidence`
    and `## Adversarial review (round 2)` both count. Refusing an honest
    heading over a suffix would teach people the gate is capricious, and
    a gate people route around is worse than no gate.
    """
    sections: list[tuple[int, list[tuple[int, str]]]] = []
    start: int | None = None
    level = 0
    body: list[tuple[int, str]] = []
    skipping = False
    for lineno, line in lines:
        m = HEADING.match(line)
        if m:
            here = len(m.group(1))
            title = heading_title(m.group(2)).lower()
            if start is not None and here <= level:
                sections.append((start, body))
                start, body, skipping = None, [], False
            if start is not None:
                # A subheading inside the block.
                skipping = title.startswith("checked")
                continue
            if title.startswith(SECTION_TITLE):
                start, level, body, skipping = lineno, here, [], False
            continue
        if start is not None and not skipping:
            body.append((lineno, line))
    if start is not None:
        sections.append((start, body))
    return sections


def indent_columns(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def collect_items(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Group list items, folding wrapped continuation lines into one.

    A finding's disposition routinely lands on the second line of a
    wrapped bullet, and the rubric's own two-part finding style invites a
    blank line before it. Checking line by line, or closing an item at
    the first blank, would reject the shape this repository documents.
    """
    items: list[list] = []
    current: list | None = None
    pending_blank = False
    for lineno, line in lines:
        m = ITEM_START.match(line)
        if m:
            if current is not None:
                items.append(current)
            current = [lineno, m.group(1).strip()]
            pending_blank = False
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped == "":
            pending_blank = True
            continue
        is_break = (
            HEADING.match(line) is not None
            or TABLE_ROW.match(line) is not None
            or any(pattern.match(line) for pattern in FIELD_LINES)
        )
        # After a blank line only an indented line continues the item;
        # a flush-left paragraph has left the list.
        if is_break or (pending_blank and indent_columns(line) < 2):
            items.append(current)
            current = None
            pending_blank = False
            continue
        # Joined with a newline, not a space: the line break is where a
        # reader sees a sentence end, and erasing it made a wrapped
        # bullet whose disposition sat on the next line read as having
        # none.
        current[1] = current[1] + "\n" + stripped
        pending_blank = False
    if current is not None:
        items.append(current)
    return [(lineno, text) for lineno, text in items]


def collect_table_findings(
    lines: list[tuple[int, str]],
) -> list[tuple[int, str, str, bool]]:
    """Findings recorded as table rows: `(lineno, severity, text, disposed)`.

    A row counts only when one whole cell is exactly a severity, so a
    header row, a separator, and a prose cell that happens to say "major"
    are all left alone.
    """
    out: list[tuple[int, str, str, bool]] = []
    for lineno, line in lines:
        m = TABLE_ROW.match(line)
        if not m or TABLE_SEPARATOR.match(line):
            continue
        cells = [clean_value(c) for c in m.group(1).split("|")]
        index = next(
            (i for i, c in enumerate(cells) if c.lower().rstrip(".") in
             {s.lower() for s in SEVERITIES}),
            None,
        )
        if index is None:
            continue
        rest = [c for i, c in enumerate(cells) if i != index]
        disposed = any(DISPOSITION_SENTENCE.search(c) for c in rest)
        out.append((lineno, cells[index].capitalize(), " | ".join(rest), disposed))
    return out


def match_field(
    lines: list[tuple[int, str]], pattern: re.Pattern[str]
) -> list[tuple[int, str]]:
    return [(lineno, m.group(1)) for lineno, line in lines if (m := pattern.match(line))]


def clean_value(value: str) -> str:
    """Strip emphasis and invisible formatting characters.

    A zero-width space after `TBD` renders as `TBD` and would otherwise
    walk straight past the placeholder list.
    """
    value = "".join(c for c in value if unicodedata.category(c) != "Cf")
    return value.strip().strip("*_`").strip()


def placeholder_problem(lineno: int, raw: str, key: str) -> list[str]:
    value = clean_value(raw)
    if value.lower().rstrip(".") in PLACEHOLDERS or not re.search(r"[A-Za-z0-9]", value):
        return [
            f"line {lineno}: `{key}:` is a placeholder, not an answer:"
            f" {value if value else '(empty)'}"
        ]
    if len(value) < 3:
        return [f"line {lineno}: `{key}:` value is too short to be an answer: {value}"]
    return []


def single_field(
    section: list[tuple[int, str]], pattern: re.Pattern[str], key: str
) -> tuple[tuple[int, str] | None, list[str]]:
    """Exactly one occurrence of a field, or a problem describing why not."""
    hits = match_field(section, pattern)
    if len(hits) > 1:
        at = ", ".join(f"line {lineno}" for lineno, _ in hits)
        return None, [f"{len(hits)} `{key}:` lines ({at}); expected one."]
    return (hits[0] if hits else None), []


def check_body(body: object) -> list[str]:
    """Return a list of problems. Empty means the body carries evidence."""
    if not isinstance(body, str) or not body.strip():
        return ["The pull request body is empty, so it carries no review evidence."]

    text = body.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.expandtabs(4) for line in strip_html_comments(text).split("\n"))
    sections = find_sections(live_lines(text))

    if not sections:
        return [
            "No `## Adversarial review` heading in the pull request body.",
            "  (A heading inside a fenced code block, inside an HTML comment,",
            "   or indented as a code block does not count; the checker reads",
            "   only what renders as live prose.)",
        ]

    # The title is matched as a prefix, so a section called
    # `Adversarial review methodology` also lands here. What separates
    # the record from a section merely about the review is whether it
    # carries one of the fields, so filter on that before counting
    # duplicates. Two blocks that both carry fields is the genuinely
    # ambiguous case and still fails.
    carrying = [
        s
        for s in sections
        if any(
            REVIEWER_LINE.match(line) or FINDINGS_LINE.match(line)
            for _, line in s[1]
        )
    ]
    if len(carrying) > 1:
        at = ", ".join(f"line {lineno}" for lineno, _ in carrying)
        return [
            f"{len(carrying)} `Adversarial review` blocks in the body ({at}).",
            "  Keep one, so there is no question which is the record.",
            "  The pull request template already carries the heading; fill that",
            "  one in rather than appending a second.",
        ]

    # No block carries a field: fall back to the first heading so the
    # diagnostics name the missing fields instead of the missing heading.
    section = (carrying[0] if carrying else sections[0])[1]
    problems: list[str] = []

    # --- Reviewer -------------------------------------------------------
    reviewer, dup = single_field(section, REVIEWER_LINE, "Reviewer")
    problems += dup
    if reviewer is None and not dup:
        problems.append("No `Reviewer:` line under the `## Adversarial review` heading.")
        problems.append(
            "  Name who or what ran the rubric, for example:"
            "\n    Reviewer: feature-dev:code-reviewer against"
            " .github/code-review-rubric.md"
        )
    elif reviewer is not None:
        problems += placeholder_problem(reviewer[0], reviewer[1], "Reviewer")

    # --- Findings -------------------------------------------------------
    findings, dup = single_field(section, FINDINGS_LINE, "Findings")
    problems += dup
    declared: dict[str, int] | None = None
    if findings is None and not dup:
        problems.append("No `Findings:` line under the `## Adversarial review` heading.")
        problems.append(
            "  Give a count per severity, or say so explicitly when there were none:"
            "\n    Findings: 1 Blocker, 2 Major, 0 Minor"
            "\n    Findings: none"
        )
    elif findings is not None:
        lineno, value = findings[0], clean_value(findings[1])
        if value.lower().rstrip(".") == "none":
            declared = {s: 0 for s in SEVERITIES}
        else:
            counts: dict[str, list[int]] = {s: [] for s in SEVERITIES}
            for number, severity in COUNT.findall(value):
                counts[severity.capitalize()].append(int(number))
            missing = [s for s in SEVERITIES if not counts[s]]
            repeated = [s for s in SEVERITIES if len(counts[s]) > 1]
            if missing:
                problems.append(
                    f"line {lineno}: `Findings:` gives no count for "
                    + ", ".join(missing)
                    + f": {value}"
                )
                problems.append(
                    "  The severities are Blocker, Major, and Minor; the rubric has"
                    "\n  no Critical. Every one needs a number, including the zeroes,"
                    "\n  so a silent omission cannot read as a clean review. Use"
                    "\n  `Findings: none` when the review found nothing at all."
                )
            elif repeated:
                problems.append(
                    f"line {lineno}: `Findings:` counts "
                    + ", ".join(repeated)
                    + " more than once."
                )
            else:
                declared = {s: counts[s][0] for s in SEVERITIES}

    # --- Dispositions ---------------------------------------------------
    listed: dict[str, list[tuple[int, str]]] = {s: [] for s in SEVERITIES}
    undisposed: list[tuple[int, str]] = []
    for lineno, item in collect_items(section):
        m = ITEM_SEVERITY.match(item)
        if not m:
            continue
        severity = m.group(1).capitalize()
        if DISPOSITION_SENTENCE.search(item):
            listed[severity].append((lineno, item))
        else:
            undisposed.append((lineno, item))
    for lineno, severity, text, disposed in collect_table_findings(section):
        if disposed:
            listed[severity].append((lineno, text))
        else:
            undisposed.append((lineno, text))

    for lineno, item in undisposed:
        flat = " ".join(item.split())
        problems.append(f"line {lineno}: finding has no disposition: {flat[:96]}")
    if undisposed:
        problems.append(
            "  End each finding with a sentence starting "
            + ", ".join(DISPOSITIONS[:-1])
            + f", or {DISPOSITIONS[-1]}."
            "\n  It has to start the sentence and keep its capital, so that an"
            "\n  ordinary description (\"the endpoint accepted a forged token\")"
            "\n  cannot pass for a disposition."
        )

    if declared is not None:
        for severity in SEVERITIES:
            want, got = declared[severity], len(listed[severity])
            if want == got:
                continue
            plural = "" if want == 1 else "s"
            if got < want:
                problems.append(
                    f"`Findings:` declares {want} {severity}{plural}"
                    f" but the block lists {got}."
                )
                problems.append(
                    f"  Give each one its own line, leading with `{severity}`"
                    " and ending in a disposition."
                )
            else:
                at = ", ".join(str(lineno) for lineno, _ in listed[severity])
                problems.append(
                    f"`Findings:` declares {want} {severity}{plural}"
                    f" but the block lists {got}"
                    f" (line{'' if got == 1 else 's'} {at})."
                )
                problems.append(
                    "  The summary and the list disagree; correct whichever is wrong."
                )

    # --- Verification round ---------------------------------------------
    verification, dup = single_field(section, VERIFICATION_LINE, "Verification")
    problems += dup
    if verification is not None:
        problems += placeholder_problem(verification[0], verification[1], "Verification")
    elif not dup and declared is not None and sum(declared.values()) > 0:
        problems.append(
            "No `Verification:` line, and the review reported findings."
        )
        problems.append(
            "  CLAUDE.md requires a verification round on the fixes whenever the"
            "\n  first round finds anything. Record it, for example:"
            "\n    Verification: second round by the same reviewer against the"
            " fixed tree, no new findings"
        )

    return problems


def report(problems: list[str]) -> int:
    if not problems:
        print("review evidence: ok")
        return 0
    print(
        "Pull request body is missing usable adversarial-review evidence.",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    for problem in problems:
        # Indent every line, not just the first: a diagnostic whose
        # continuation lines drift left is harder to read than one line.
        for line in problem.split("\n"):
            print(f"  {line}", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "A body that satisfies this gate looks like:\n"
        "\n"
        "    ## Adversarial review\n"
        "\n"
        "    Reviewer: feature-dev:code-reviewer against .github/code-review-rubric.md\n"
        "    Findings: 1 Blocker, 0 Major, 1 Minor\n"
        "    Verification: second round by the same reviewer, no new findings\n"
        "\n"
        "    - Blocker - `crates/sbproxy-core/src/router.rs:214` - a 5xx retries\n"
        "      against the same dead peer forever. Fixed in this branch.\n"
        "    - Minor - `crates/sbproxy-core/src/router.rs:88` - doc comment names\n"
        "      a field that moved. Fixed in this branch.\n"
        "\n"
        "or, when the review turned up nothing:\n"
        "\n"
        "    ## Adversarial review\n"
        "\n"
        "    Reviewer: feature-dev:code-reviewer against .github/code-review-rubric.md\n"
        "    Findings: none\n"
        "\n" + DOC_POINTER,
        file=sys.stderr,
    )
    return 1


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GOOD_WITH_FINDINGS = """\
## What this PR does

Rewrites the retry path.

## Adversarial review

Reviewer: feature-dev:code-reviewer against .github/code-review-rubric.md
Findings: 1 Blocker, 1 Major, 0 Minor
Verification: second round by the same reviewer against the fixed tree

- Blocker - `crates/sbproxy-core/src/router.rs:214` - an upstream 5xx retries
  against the same dead peer forever. Fixed in this branch.
- Major - `crates/sbproxy-core/src/router.rs:301` - the retry budget is held by
  convention rather than by the type. Accepted; the type change is separate scope.

### Checked and sound
- Metrics: label sets go through the cardinality limiter.
- Blocker: none in the config reader.
"""

GOOD_NONE = """\
## Adversarial review

Reviewer: feature-dev:code-reviewer against .github/code-review-rubric.md
Findings: none
"""

GOOD_EXPLICIT_ZEROES = """\
## Adversarial review

**Reviewer:** an agent with shell access, against the rubric
**Findings:** 0 Blocker, 0 Major, 0 Minor
"""


def _self_test() -> int:
    """Fixtures for the parser. Reads no network and writes no files."""

    failures: list[str] = []

    def expect_ok(name: str, body: str) -> None:
        problems = check_body(body)
        if problems:
            failures.append(f"{name}: expected pass, got {problems}")

    def expect_fail(name: str, body: str, needle: str) -> None:
        problems = check_body(body)
        if not problems:
            failures.append(f"{name}: expected failure, got a pass")
            return
        if needle.lower() not in "\n".join(problems).lower():
            failures.append(f"{name}: expected {needle!r} in diagnostics, got {problems}")

    # --- Accepted shapes ---
    expect_ok("findings with dispositions", GOOD_WITH_FINDINGS)
    expect_ok("explicit none", GOOD_NONE)
    expect_ok("explicit zeroes", GOOD_EXPLICIT_ZEROES)
    expect_ok("crlf line endings", GOOD_NONE.replace("\n", "\r\n"))
    expect_ok("lone cr line endings", GOOD_NONE.replace("\n", "\r"))
    expect_ok("h3 heading", GOOD_NONE.replace("## Adversarial", "### Adversarial"))
    expect_ok("lowercase heading", GOOD_NONE.replace("Adversarial review", "adversarial REVIEW"))
    expect_ok("atx closing sequence", GOOD_NONE.replace("## Adversarial review", "## Adversarial review ##"))
    expect_ok("doubled space in heading", GOOD_NONE.replace("Adversarial review", "Adversarial  review"))
    expect_ok("heading with a suffix", GOOD_NONE.replace("Adversarial review", "Adversarial review (round 2)"))
    expect_ok("bold heading", GOOD_NONE.replace("## Adversarial review", "## **Adversarial review**"))
    expect_ok(
        "ordered list dispositions",
        GOOD_WITH_FINDINGS.replace("- Blocker", "1. Blocker").replace("- Major", "2. Major"),
    )
    expect_ok(
        "bold severities",
        GOOD_WITH_FINDINGS.replace("- Blocker -", "- **Blocker** -").replace(
            "- Major -", "- **Major** -"
        ),
    )
    expect_ok(
        "blank line before the disposition",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 1 Blocker, 0 Major, 0 Minor\nVerification: second round\n\n"
        "- Blocker - `a.rs:1` - unchecked index.\n\n"
        "  Failure scenario: a 5 byte body panics the worker.\n\n"
        "  Fixed in this branch.\n",
    )
    expect_ok(
        "bold disposition",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 1 Blocker, 0 Major, 0 Minor\nVerification: second round\n\n"
        "- Blocker - `a.rs:1` - unchecked index. **Fixed** in this branch.\n",
    )
    expect_ok(
        "findings grouped under subheadings, as a table",
        "## Adversarial review evidence\n\nReviewer: an independent reviewer\n"
        "Findings: 0 Blocker, 1 Major, 1 Minor\nVerification: second round\n\n"
        "### Majors\n\n| # | Severity | Finding | Disposition |\n|---|---|---|---|\n"
        "| M1 | Major | teardown seam missed a surface | **Fixed.** both surfaces now |\n\n"
        "### Minors\n\n| # | Severity | Finding | Disposition |\n|---|---|---|---|\n"
        "| m1 | Minor | swallowed a store error | **Fixed.** debug! naming the key id |\n\n"
        "## Gates\n\ncargo test\n",
    )
    expect_ok(
        "checked-and-sound subsection is not scanned for findings",
        GOOD_NONE + "\n### Checked and sound\n- Blocker: none in the config reader.\n"
        "- Major: none in the reload path.\n",
    )
    expect_fail(
        "a table row with no disposition still fails",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 0 Blocker, 1 Major, 0 Minor\nVerification: second round\n\n"
        "| # | Severity | Finding | Disposition |\n|---|---|---|---|\n"
        "| M1 | Major | teardown seam missed a surface | still looking at it |\n",
        "no disposition",
    )
    expect_fail(
        "table rows are counted against the declared total",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 0 Blocker, 3 Major, 0 Minor\nVerification: second round\n\n"
        "| # | Severity | Finding | Disposition |\n|---|---|---|---|\n"
        "| M1 | Major | a claim | **Fixed.** done |\n",
        "declares 3 Majors but the block lists 1",
    )
    expect_ok(
        "a header row is not a finding",
        GOOD_NONE + "\n| # | Severity | Finding | Disposition |\n|---|---|---|---|\n",
    )
    expect_ok(
        "trailing section after the block",
        GOOD_WITH_FINDINGS + "\n## Notes for reviewers\n\nLook hard at the retry budget.\n",
    )
    expect_ok(
        "four-backtick fence quoting a three-backtick block",
        "## Testing\n\n````markdown\n```\nsample\n```\n````\n\n" + GOOD_NONE,
    )

    # --- Refused shapes ---
    expect_fail("empty body", "", "empty")
    expect_fail("whitespace body", "   \n\n\t\n", "empty")
    expect_fail("non-string body", 12345, "empty")
    expect_fail("no heading", "## What this PR does\n\nA change.\n", "No `## Adversarial review` heading")
    expect_fail("heading only", "## Adversarial review\n", "No `Reviewer:` line")
    for name, needle in (("reviewer", "No `Reviewer:` line"), ("findings", "No `Findings:` line")):
        expect_fail(
            f"whitespace-only section, {name}",
            "## Adversarial review\n\n   \n\t\n\n## Testing\n\ncargo test\n",
            needle,
        )
    expect_fail(
        "missing findings",
        "## Adversarial review\n\nReviewer: an agent with shell access\n",
        "No `Findings:` line",
    )
    expect_fail("missing reviewer", "## Adversarial review\n\nFindings: none\n", "No `Reviewer:` line")
    for placeholder in ("TBD", "todo", "N/A", "none", "-", "?", "TBD\u200b"):
        expect_fail(
            f"placeholder reviewer {placeholder!r}",
            f"## Adversarial review\n\nReviewer: {placeholder}\nFindings: none\n",
            "placeholder",
        )
    expect_fail(
        "empty reviewer value",
        "## Adversarial review\n\nReviewer:\nFindings: none\n",
        "placeholder",
    )
    expect_fail(
        "severity missing from counts",
        "## Adversarial review\n\nReviewer: an agent\nFindings: 2 Blocker, 1 Major\n",
        "no count for Minor",
    )
    expect_fail(
        "Critical is not a severity",
        "## Adversarial review\n\nReviewer: an agent\nFindings: 1 Critical, 0 Major, 0 Minor\n",
        "no Critical",
    )
    expect_fail(
        "counts declared, no dispositions",
        "## Adversarial review\n\nReviewer: an agent\nFindings: 2 Blocker, 0 Major, 0 Minor\n"
        "Verification: second round\n",
        "declares 2 Blockers but the block lists 0",
    )
    expect_fail(
        "undercounted dispositions",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 2 Blocker, 0 Major, 0 Minor\nVerification: second round\n\n"
        "- Blocker - `a.rs:1` - boom. Fixed in this branch.\n",
        "declares 2 Blockers but the block lists 1",
    )
    expect_fail(
        "none contradicted by a listed finding",
        "## Adversarial review\n\nReviewer: an agent\nFindings: none\n\n"
        "- Blocker - `a.rs:1` - boom. Fixed in this branch.\n",
        "declares 0 Blockers but the block lists 1",
    )
    expect_fail(
        "finding without a disposition",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 1 Blocker, 0 Major, 0 Minor\nVerification: second round\n\n"
        "- Blocker - `a.rs:1` - boom.\n",
        "no disposition",
    )
    for label, tail in (
        ("line break where a period would go", "the loop never exits\n  Fixed in this branch."),
        ("comma", "boom, Fixed in this branch."),
        ("semicolon", "boom; Fixed in this branch."),
        ("colon", "boom: Fixed in this branch."),
        ("bracketed", "boom [Fixed]"),
        ("parenthesized", "boom (Accepted, separate scope)"),
    ):
        expect_ok(
            f"disposition after a {label}",
            "## Adversarial review\n\nReviewer: an agent with shell access\n"
            "Findings: 1 Blocker, 0 Major, 0 Minor\nVerification: second round\n\n"
            f"- Blocker - `a.rs:1` - {tail}\n",
        )
    for label, tail in (
        ("hyphenated Fixed-size", "the id truncates. Fixed-size columns are the cause."),
        ("hyphenated Accepted-encoding", "the header drops. Accepted-encoding is unset."),
    ):
        expect_fail(
            f"{label} is not a disposition",
            "## Adversarial review\n\nReviewer: an agent with shell access\n"
            "Findings: 1 Blocker, 0 Major, 0 Minor\nVerification: second round\n\n"
            f"- Blocker - `a.rs:1` - {tail}\n",
            "no disposition",
        )
    expect_fail(
        "a table cell reading Fixed-size does not dispose the row",
        "## Adversarial review\n\nReviewer: an agent with shell access\n"
        "Findings: 0 Blocker, 1 Major, 0 Minor\nVerification: second round\n\n"
        "| # | Severity | Finding | Disposition |\n|---|---|---|---|\n"
        "| M1 | Major | the id truncates | Fixed-size columns are the cause |\n",
        "no disposition",
    )
    expect_fail(
        "lowercase disposition word inside prose",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 1 Blocker, 0 Major, 0 Minor\nVerification: second round\n\n"
        "- Blocker - `a.rs:1` - the endpoint accepted a forged token and served it.\n",
        "no disposition",
    )
    expect_fail(
        "findings without a verification round",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 1 Blocker, 0 Major, 0 Minor\n\n"
        "- Blocker - `a.rs:1` - boom. Fixed in this branch.\n",
        "No `Verification:` line",
    )
    expect_fail(
        "placeholder verification",
        "## Adversarial review\n\nReviewer: an agent\n"
        "Findings: 1 Blocker, 0 Major, 0 Minor\nVerification: TBD\n\n"
        "- Blocker - `a.rs:1` - boom. Fixed in this branch.\n",
        "`Verification:` is a placeholder",
    )
    expect_fail(
        "block inside a fenced code block",
        "## Testing\n\n```markdown\n" + GOOD_NONE + "```\n",
        "No `## Adversarial review` heading",
    )
    expect_fail(
        "block inside a tilde fence",
        "## Testing\n\n~~~markdown\n" + GOOD_NONE + "~~~\n",
        "No `## Adversarial review` heading",
    )
    expect_fail(
        "block behind a short fence inside a long one",
        "## Testing\n\n````markdown\n```\n" + GOOD_NONE + "````\n",
        "No `## Adversarial review` heading",
    )
    expect_fail(
        "block behind a short tilde fence inside a long one",
        "## Testing\n\n~~~~~markdown\n~~~\n" + GOOD_NONE + "~~~~~\n",
        "No `## Adversarial review` heading",
    )
    expect_fail(
        "block inside an HTML comment",
        "## Testing\n\n<!--\n" + GOOD_NONE + "-->\n",
        "No `## Adversarial review` heading",
    )
    expect_fail(
        "block after an unterminated HTML comment",
        "## What this PR does\n\nA change.\n\n<!-- notes\n" + GOOD_NONE,
        "No `## Adversarial review` heading",
    )
    expect_ok(
        "unclosed `<!--` inside backticks is literal text, not a comment",
        GOOD_NONE + "\n- Note: an unterminated `<!--` used to blank the rest.\n",
    )
    expect_ok(
        "paired inline comment does not eat the line",
        "## Adversarial review\n\nReviewer: an agent <!-- note --> with shell access\n"
        "Findings: none\n",
    )
    expect_fail(
        "an inline comment cannot supply a disposition",
        "## Adversarial review\n\nReviewer: an agent with shell access\n"
        "Findings: 1 Blocker, 0 Major, 0 Minor\nVerification: second round\n\n"
        "- Blocker - `a.rs:1` - boom <!-- - Fixed -->\n",
        "no disposition",
    )
    expect_fail(
        "an inline comment cannot hide a contradicting count",
        "## Adversarial review\n\nReviewer: an agent with shell access\n"
        "Findings: none <!-- really 3 Blockers -->\n\n"
        "- Blocker - `a.rs:1` - boom. Fixed in this branch.\n",
        "declares 0 Blockers but the block lists 1",
    )
    expect_ok(
        "a comment spliced into a field key still reads as that field",
        "## Adversarial review\n\nRevie<!-- x -->wer: an agent\nFindings: none\n",
    )
    expect_fail(
        "a multi-line inline comment cannot hide the whole block",
        "## Adversarial review\n\nnote <!--\nReviewer: an agent with shell access\n"
        "Findings: none\n-->\n",
        "No `Reviewer:` line",
    )
    expect_fail(
        "a multi-line inline comment cannot hide the heading too",
        "x <!--\n## Adversarial review\n\nReviewer: an agent with shell access\n"
        "Findings: none\n-->\n",
        "No `## Adversarial review` heading",
    )
    expect_fail(
        "fields commented out under a live heading",
        "## Adversarial review\n\n<!--\nReviewer: an agent\nFindings: none\n-->\n",
        "No `Reviewer:` line",
    )
    expect_fail(
        "tab-indented block is an indented code block",
        "\t## Adversarial review\n\n\tReviewer: an agent\n\tFindings: none\n",
        "No `## Adversarial review` heading",
    )
    expect_fail(
        "four-space-indented block",
        "    ## Adversarial review\n\n    Reviewer: an agent\n    Findings: none\n",
        "No `## Adversarial review` heading",
    )
    for prefix, label in (("\xa0", "nbsp"), ("\x0c", "form feed")):
        expect_fail(
            f"{label}-prefixed heading is not a heading",
            f"{prefix}## Adversarial review\n\n{prefix}Reviewer: an agent\n{prefix}Findings: none\n",
            "No `## Adversarial review` heading",
        )
    expect_fail(
        "two blocks that both carry fields",
        GOOD_NONE + "\n" + GOOD_NONE,
        "2 `Adversarial review` blocks",
    )
    expect_ok(
        "an unfilled stub above the real block is not a second record",
        "## Adversarial review\n\n<!-- stub -->\n\n" + GOOD_NONE,
    )
    expect_ok(
        "a section merely about the review is not a second record",
        GOOD_NONE + "\n## Adversarial review methodology\n\nWe ran it twice.\n",
    )
    expect_fail(
        "duplicate reviewer lines",
        "## Adversarial review\n\nReviewer: an agent\nReviewer: another agent\nFindings: none\n",
        "2 `Reviewer:` lines",
    )
    expect_fail(
        "duplicate findings lines",
        "## Adversarial review\n\nReviewer: an agent\nFindings: none\nFindings: 1 Blocker, 0 Major, 0 Minor\n",
        "2 `Findings:` lines",
    )
    expect_fail(
        "duplicate verification lines",
        "## Adversarial review\n\nReviewer: an agent\nFindings: none\n"
        "Verification: a round\nVerification: another round\n",
        "2 `Verification:` lines",
    )

    # --- Line numbers in diagnostics point at the offending line ---
    body = "line one\n\n## Adversarial review\n\nReviewer: TBD\nFindings: none\n"
    if not any("line 5" in p for p in check_body(body)):
        failures.append("placeholder diagnostic did not name line 5")

    # --- The report renders without crashing and points at the docs ---
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        failing = report(check_body(""))
        passing = report([])
    if failing != 1:
        failures.append("report() on a failing body did not return 1")
    if passing != 0:
        failures.append("report() on a clean body did not return 0")
    for needle in ("code-review-rubric.md", "CLAUDE.md"):
        if needle not in err.getvalue():
            failures.append(f"failure report does not point at {needle}")

    # --- Both worked examples in the failure report satisfy the gate ---
    # Split first: the report prints two, and running them together would
    # trip the duplicate-heading rule instead of checking either one.
    halves = err.getvalue().split("or, when the review turned up nothing:")
    if len(halves) != 2:
        failures.append("failure report no longer prints two worked examples")
    for label, half in zip(("with findings", "without findings"), halves):
        example = "\n".join(
            line[4:] for line in half.split("\n") if line.startswith("    ")
        )
        if check_body(example):
            failures.append(
                f"printed example ({label}) does not pass: {check_body(example)}"
            )

    # --- Invocation errors report as 2, never as a failed review ---
    missing = "/nonexistent-directory-for-self-test/event.json"
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        codes = {
            "--event-path": main(["--event-path", missing]),
            "--body-file": main(["--body-file", missing]),
            "no source": main([]),
        }
    for label, code in codes.items():
        if code != 2:
            failures.append(f"{label} returned {code}, expected 2")

    # --- Malformed payloads are misuse, not a failed review ---
    for label, payload in (
        ("no pull_request", {}),
        ("body is a number", {"pull_request": {"body": 1, "user": {"login": "a", "type": "User"}}}),
        ("user is a string", {"pull_request": {"body": "x", "user": "nope"}}),
    ):
        try:
            body_from_event_payload(payload, label)
        except Misuse:
            continue
        failures.append(f"{label}: expected Misuse, got none")

    # --- The bot exemption is an allowlist, not `type == Bot` ---
    for login, expected in (
        ("renovate[bot]", True),
        ("dependabot[bot]", True),
        ("github-actions[bot]", False),
        ("Copilot", False),
    ):
        payload = {"pull_request": {"body": "", "user": {"login": login, "type": "Bot"}}}
        _, exempt = body_from_event_payload(payload, "fixture")
        if (exempt is not None) != expected:
            failures.append(f"bot exemption for {login} was {exempt!r}, expected exempt={expected}")

    if failures:
        sys.stderr.write("FAIL\n")
        for failure in failures:
            sys.stderr.write(f"  - {failure}\n")
        return 1
    sys.stdout.write("OK\n")
    return 0


class Misuse(Exception):
    """The invocation was wrong, as opposed to the body being wrong.

    Kept distinct so a broken workflow or a malformed payload reports as
    exit 2 and never as a body that failed review, which would send the
    author hunting through a PR description for a problem that is not
    there.
    """


def body_from_event_payload(payload: object, source: str) -> tuple[object, str | None]:
    """Return `(body, exempt_bot_login)` from a `pull_request` event payload."""
    if not isinstance(payload, dict) or not isinstance(payload.get("pull_request"), dict):
        raise Misuse(
            f"{source} has no `pull_request` object. This check only runs on the\n"
            "`pull_request` event; see .github/workflows/review-evidence.yml."
        )
    pull = payload["pull_request"]
    user = pull.get("user")
    if user is not None and not isinstance(user, dict):
        raise Misuse(f"{source}: `pull_request.user` is not an object.")
    body = pull.get("body")
    if body is not None and not isinstance(body, str):
        raise Misuse(f"{source}: `pull_request.body` is not a string.")
    user = user or {}
    login = user.get("login")
    if user.get("type") == "Bot" and isinstance(login, str) and login in EXEMPT_BOTS:
        return body, login
    return body, None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Require adversarial-review evidence in a pull request body."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--event-path", help="GitHub event payload JSON, normally $GITHUB_EVENT_PATH."
    )
    source.add_argument("--body-file", help="File holding the pull request body.")
    source.add_argument("--stdin", action="store_true", help="Read the body from stdin.")
    source.add_argument(
        "--self-test",
        action="store_true",
        help="Run in-process fixtures. Reads no network and writes no files.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    try:
        if args.event_path:
            payload = json.loads(Path(args.event_path).read_text(encoding="utf-8"))
            body, bot = body_from_event_payload(payload, args.event_path)
            if bot is not None:
                print(f"review evidence: skipped, pull request opened by {bot}")
                return 0
        elif args.body_file:
            body = Path(args.body_file).read_text(encoding="utf-8")
        elif args.stdin:
            body = sys.stdin.read()
        else:
            parser.print_help()
            return 2
    except (Misuse, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"check-review-evidence: {exc}", file=sys.stderr)
        return 2

    return report(check_body(body))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
