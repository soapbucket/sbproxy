#!/usr/bin/env python3
"""Regenerate the catalog table in examples/README.md.

Walks every directory under examples/ that contains an sb.yml (or, for
bundle-style examples such as observability-stack/ and wasm/, at least a
README.md). Each directory becomes one table row:

    | [name](name/) | first sentence(s) of the example's description |

The description is taken from the first paragraph of the example's
README.md (after the title and the *Last modified* line), falling back
to the sb.yml header comment when no README exists.

Only the table between the `## Catalog` heading and the end of the
table (plus the trailing `_N examples on disk._` count line) is
rewritten; everything else in examples/README.md is preserved.

Usage:
    python3 scripts/gen-examples-catalog.py          # rewrite in place
    python3 scripts/gen-examples-catalog.py --check  # exit 1 if stale
"""

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"
CATALOG_FILE = EXAMPLES_DIR / "README.md"
MAX_DESC_LEN = 300

LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
IMAGE_RE = re.compile(r"^!\[[^\]]*\]\([^)]*\)\s*$")
LAST_MODIFIED_RE = re.compile(r"^\*Last modified:.*\*$")
COUNT_LINE_RE = re.compile(r"^_\d+ examples on disk\._$")


def clean(text: str) -> str:
    """Flatten to one table-safe line, truncated on a word boundary."""
    text = LINK_RE.sub(r"\1", text)
    text = " ".join(text.split())
    text = text.replace("|", "\\|")
    if len(text) > MAX_DESC_LEN:
        cut = text.rfind(" ", 0, MAX_DESC_LEN)
        if cut <= 0:
            cut = MAX_DESC_LEN
        text = text[:cut].rstrip(" ,;:")
    return text


def desc_from_readme(readme: Path) -> str:
    lines = readme.read_text(encoding="utf-8").splitlines()
    para: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            if para:
                break
            continue
        if not para and (
            not stripped
            or LAST_MODIFIED_RE.match(stripped)
            or IMAGE_RE.match(stripped)
        ):
            continue
        if para and not stripped:
            break
        para.append(stripped)
    return clean(" ".join(para))


def desc_from_sbyml(sbyml: Path, name: str) -> str:
    """First meaningful paragraph of the leading comment block."""
    paras: list[list[str]] = [[]]
    for line in sbyml.read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            break
        text = line.lstrip("#").strip()
        if "yaml-language-server" in text:
            continue
        if not text:
            if paras[-1]:
                paras.append([])
            continue
        paras[-1].append(text)
    for para in paras:
        joined = " ".join(para)
        # Skip a bare title line such as "30 - rail-x402-base-sepolia"
        # or the directory name itself.
        bare = re.sub(r"^\d+\s*-\s*", "", joined).strip().rstrip(".")
        if not joined or bare == name or len(joined.split()) < 3:
            continue
        return clean(joined)
    return ""


def example_dirs() -> list[Path]:
    dirs = []
    for entry in sorted(EXAMPLES_DIR.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            continue
        if (entry / "sb.yml").is_file() or (entry / "README.md").is_file():
            dirs.append(entry)
    return dirs


def build_rows() -> list[str]:
    rows = ["| Example | Description |", "|---|---|"]
    for d in example_dirs():
        readme = d / "README.md"
        sbyml = d / "sb.yml"
        desc = ""
        if readme.is_file():
            desc = desc_from_readme(readme)
        if not desc and sbyml.is_file():
            desc = desc_from_sbyml(sbyml, d.name)
        rows.append(f"| [{d.name}]({d.name}/) | {desc} |")
    return rows


def rewrite(content: str, rows: list[str]) -> str:
    lines = content.split("\n")
    try:
        h = next(i for i, l in enumerate(lines) if l.strip() == "## Catalog")
    except StopIteration:
        sys.exit("error: no '## Catalog' heading in examples/README.md")

    # Locate the existing table (first run of '|' lines after the heading).
    t0 = None
    for i in range(h + 1, len(lines)):
        if lines[i].startswith("|"):
            t0 = i
            break
        if lines[i].startswith("## "):
            break
    n_examples = len(rows) - 2
    section = rows + ["", f"_{n_examples} examples on disk._"]

    if t0 is None:
        # No table yet: append the section at the end of the Catalog intro.
        end = next(
            (i for i in range(h + 1, len(lines)) if lines[i].startswith("## ")),
            len(lines),
        )
        return "\n".join(lines[:end] + section + lines[end:])

    t1 = t0
    while t1 + 1 < len(lines) and lines[t1 + 1].startswith("|"):
        t1 += 1
    # Consume a trailing blank line + old count line if present.
    tail = t1 + 1
    if tail < len(lines) and not lines[tail].strip():
        if tail + 1 < len(lines) and COUNT_LINE_RE.match(lines[tail + 1].strip()):
            tail += 2
    return "\n".join(lines[:t0] + section + lines[tail:])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if examples/README.md would change, without writing",
    )
    args = parser.parse_args()

    rows = build_rows()
    n = len(rows) - 2
    old = CATALOG_FILE.read_text(encoding="utf-8")
    new = rewrite(old, rows)

    if args.check:
        if new != old:
            print(f"{n} examples; catalog is STALE (run scripts/gen-examples-catalog.py)")
            sys.exit(1)
        print(f"{n} examples; catalog is up to date")
        return

    if new != old:
        CATALOG_FILE.write_text(new, encoding="utf-8")
        print(f"{n} examples; catalog rewritten")
    else:
        print(f"{n} examples; catalog already up to date")


if __name__ == "__main__":
    main()
