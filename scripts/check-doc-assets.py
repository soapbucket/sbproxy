#!/usr/bin/env python3
"""Refuse a documentation asset that was promised and never produced.

# Why this exists

Two checks, both cheap, and both about one failure seen from two sides: a
document names a file nobody ever generated.

1. A tape whose output was never recorded. Writing `docs/tapes/<name>.tape`
   and recording it are separate acts, and only the first one is a commit.
   The tape lands, `scripts/record-tapes.sh` is never run against it, and
   the result is a doc asset nobody has ever looked at.

2. A markdown image that does not resolve. This is what a reader actually
   hits: a broken-image icon in the middle of a walkthrough, with nothing
   anywhere that says it is broken. Usually it is the other half of the
   first failure, an embed written in anticipation of a recording that did
   not happen.

Nothing else in this repository asks either question. `make tapes-check`
(`scripts/gen-example-tapes.py --check`) keeps each tape in sync with its
example's configuration and never looks in `docs/assets/` at all.
`scripts/wire-example-gifs.py` inserts an image reference only when the GIF
is already on disk, so it is silent by construction about one that is not.
Between them, both passed on a repository where
`docs/tapes/payment-settlement.tape` named
`docs/assets/payment-settlement.gif`, that GIF had never been recorded, and
`examples/rail-x402-base-sepolia/README.md` embedded it anyway.

# What it does not check

External URLs (`http:`, `https:`, `data:`, and anything else with a scheme)
are skipped: reaching the network from a pre-commit gate would make the
check flaky and slow, and link rot is a different problem with a different
tool. Images inside fenced code blocks are skipped because they are being
shown as syntax rather than rendered. Relative paths resolve against the
directory of the file that references them, the same way a markdown
renderer resolves them; a leading `/` resolves against the repository root.

Usage: python3 scripts/check-doc-assets.py
"""
import os
import re
import sys
from urllib.parse import unquote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAPE_DIR = os.path.join(ROOT, "docs", "tapes")
ASSET_PREFIX = "docs/assets/"
SEARCH_ROOTS = ("docs", "examples")
PRUNE_DIRS = {".git", "node_modules", "target", "dist", "__pycache__"}

# VHS writes one file per `Output` directive; a tape may carry several.
# Both the quoted and bare forms are legal, and both appear upstream.
OUTPUT_LINE = re.compile(r'^\s*Output\s+"?([^"\n]+?)"?\s*$')

# Inline markdown image. The target stops at whitespace so that the
# optional `![alt](path "title")` title is not mistaken for the path.
IMAGE = re.compile(r"!\[[^\]]*\]\(\s*([^)\s]+)")

FENCE = re.compile(r"^\s*(?:```|~~~)")

# Any URI scheme, plus the protocol-relative `//host/path` form.
EXTERNAL = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.\-]*:|//)")


def repo_relative(path):
    """Report paths from the repository root, with forward slashes."""
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as stream:
        return stream.read().split("\n")


def tape_output_failures():
    """Tapes naming a docs/assets/ output that is not on disk."""
    failures, checked = [], 0
    if not os.path.isdir(TAPE_DIR):
        return failures, checked
    for name in sorted(os.listdir(TAPE_DIR)):
        if not name.endswith(".tape"):
            continue
        tape = os.path.join(TAPE_DIR, name)
        if not os.path.isfile(tape):
            continue
        for lineno, line in enumerate(read_lines(tape), 1):
            match = OUTPUT_LINE.match(line)
            if not match:
                continue
            target = os.path.normpath(match.group(1).strip()).replace(os.sep, "/")
            # A tape is recorded from the repository root, so its Output is
            # relative to that. Anything written outside docs/assets/ is a
            # scratch file rather than a committed doc asset.
            if not target.startswith(ASSET_PREFIX):
                continue
            checked += 1
            if not os.path.isfile(os.path.join(ROOT, target)):
                failures.append((repo_relative(tape), lineno, target))
    return failures, checked


def markdown_files():
    for base in SEARCH_ROOTS:
        top = os.path.join(ROOT, base)
        if not os.path.isdir(top):
            continue
        for dirpath, dirnames, filenames in os.walk(top):
            dirnames[:] = sorted(d for d in dirnames if d not in PRUNE_DIRS)
            for filename in sorted(filenames):
                if filename.endswith(".md"):
                    yield os.path.join(dirpath, filename)


def image_failures():
    """Markdown images under docs/ and examples/ that resolve to nothing."""
    failures, checked, scanned = [], 0, 0
    for path in markdown_files():
        scanned += 1
        in_fence = False
        for lineno, line in enumerate(read_lines(path), 1):
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for match in IMAGE.finditer(line):
                raw = match.group(1)
                if EXTERNAL.match(raw):
                    continue
                # Anchors and query strings are meaningless on an image and
                # are not part of the filename either way.
                target = unquote(raw.split("#", 1)[0].split("?", 1)[0])
                if not target:
                    continue
                checked += 1
                if target.startswith("/"):
                    resolved = os.path.join(ROOT, target.lstrip("/"))
                else:
                    resolved = os.path.join(os.path.dirname(path), target)
                if not os.path.isfile(os.path.normpath(resolved)):
                    failures.append(
                        (
                            repo_relative(path),
                            lineno,
                            raw,
                            repo_relative(os.path.normpath(resolved)),
                        )
                    )
    return failures, checked, scanned


def main():
    tapes, tapes_checked = tape_output_failures()
    images, images_checked, files_scanned = image_failures()

    for tape, lineno, target in tapes:
        print(f"{tape}:{lineno} names an output that was never produced", file=sys.stderr)
        print(f"    {target}", file=sys.stderr)
    if tapes:
        print(
            "\n"
            "A tape whose output does not exist is a recording that was committed\n"
            "and never run. Record it:\n"
            "\n"
            "    scripts/record-tapes.sh <name>\n"
            "\n"
            "or delete the tape together with every reference to its output.\n"
            "Leaving it as it is is the worst of the three, because the\n"
            "repository then claims a walkthrough that no reader can ever see.\n",
            file=sys.stderr,
        )

    for path, lineno, raw, resolved in images:
        print(f"{path}:{lineno} embeds an image that does not exist", file=sys.stderr)
        print(f"    {raw}  ->  {resolved}", file=sys.stderr)
    if images:
        print(
            "\n"
            "A markdown image that does not resolve renders as a broken-image\n"
            "icon. The reader gets no error and no explanation, only a hole in\n"
            "the middle of the page. Fix the path, produce the asset, or drop\n"
            "the embed.\n"
            "\n"
            "Relative paths resolve against the directory of the file that\n"
            "references them, so a README under examples/<name>/ reaches a GIF\n"
            "as ../../docs/assets/<name>.gif.\n",
            file=sys.stderr,
        )

    if tapes or images:
        return 1

    print(
        f"doc assets: ok ({tapes_checked} tape outputs, "
        f"{images_checked} markdown images across {files_scanned} files)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
