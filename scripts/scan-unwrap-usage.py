#!/usr/bin/env python3
"""Count `.unwrap()`, `.expect(..)` and `panic!` in production code only.

# Why a script rather than a clippy lint

`clippy::unwrap_used`, `clippy::expect_used` and `clippy::panic` are the
lints that would do this, and they cannot be turned on here. Both CI's
lint lane and `scripts/check.sh` run

    cargo clippy --workspace --all-targets -- -D warnings

so `warn` and `deny` are the same level in this workspace: there is no
"warn now, fix later" setting. All three lints also fire in test code,
where `.unwrap()` in a fixture is the correct thing to write, and the
exemption would have to be repeated at the top of every one of the 287
integration-test roots under `crates/*/tests/` because those compile as
their own crates and a `cfg_attr(test, allow(..))` in the library root
does not reach them.

This scan enforces the same rule where the rule actually applies. It
reads only `crates/*/src`, and it removes test code before counting, so
a test may unwrap freely and a production call site cannot be added
without the number moving.

# What counts as test code

Removed before counting:

  * any item under `#[cfg(test)]`, including the compound forms, so
    `#[cfg(all(test, unix))]` and `#[cfg(all(test, feature = "x"))]` are
    removed too. `#[cfg(any(test, feature = "mock"))]` is *kept*: that
    item compiles in a normal build, so it is production code.
  * the file behind a `#[cfg(test)] mod name;` declaration, and anything
    that file declares in turn. There are twelve of these, and they hold
    a third of the workspace's raw `.unwrap()` hits between them. A
    scanner that only understands the inline `#[cfg(test)] mod tests {}`
    form counts every one of them as production code.
  * comments and the interiors of string literals, so a `.unwrap()` in a
    doc example or in a Rust snippet embedded in a string is not a call
    site.

The cfg predicate is evaluated three-valued with `test` forced false and
every other atom unknown. An item is test-only when the result is
definitely false, which is what makes `all(..)` remove and `any(..)`
keep without special-casing either.

# What is not scanned

`crates/*/tests`, `crates/*/benches`, `crates/*/examples`, `build.rs`,
and the `e2e` harness crate. Every one of those is test or build
scaffolding by construction, and a panic in them fails the run that
built them rather than a request in production.

# Usage

    scripts/scan-unwrap-usage.py                        # listing
    scripts/scan-unwrap-usage.py --count unwrap-expect  # one integer, for CI
    scripts/scan-unwrap-usage.py --count panic          # one integer, for CI
    scripts/scan-unwrap-usage.py --by-file              # per-file totals
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

RAW_STRING = re.compile(r'(b?)r(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\.|[^\\'])'")
CFG_ATTRIBUTE = re.compile(r"#(!?)\[\s*cfg\s*\(")
MOD_DECLARATION = re.compile(
    r"\A\s*(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
STRUCT_FIELD = re.compile(r"\A\s*(?:pub\s*(?:\([^)]*\)\s*)?)?[A-Za-z_][A-Za-z0-9_]*\s*:")
ITEM_KEYWORD = re.compile(
    r"\A\s*(?:pub\s*(?:\([^)]*\)\s*)?)?"
    r"(?:fn|impl|mod|use|const|static|type|let|struct|enum|trait|union"
    r"|async|unsafe|extern|macro_rules|if|match|for|while|loop)\b"
)
PLAIN_MOD_DECLARATION = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")

PATTERNS = {
    "unwrap": re.compile(r"\.unwrap\(\)"),
    "expect": re.compile(r"\.expect\("),
    "panic": re.compile(r"\bpanic!"),
}

TRUE, FALSE, UNKNOWN = "true", "false", "unknown"


def blank_noncode(source: str) -> str:
    """Replace comments and literal interiors with spaces, same length.

    Offsets and line numbers survive, so a match found in the result can
    be reported against the original file without a second pass.
    """
    out = list(source)
    length = len(source)
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if out[position] != "\n":
                out[position] = " "

    while index < length:
        char = source[index]
        if char == "/" and index + 1 < length and source[index + 1] == "/":
            end = source.find("\n", index)
            end = length if end < 0 else end
            blank(index, end)
            index = end
            continue
        if char == "/" and index + 1 < length and source[index + 1] == "*":
            depth = 1
            end = index + 2
            while end < length and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(index, end)
            index = end
            continue
        match = RAW_STRING.match(source, index)
        if match:
            terminator = '"' + match.group(2)
            end = source.find(terminator, match.end())
            end = length if end < 0 else end + len(terminator)
            blank(index, end)
            index = end
            continue
        if char == '"':
            end = index + 1
            while end < length:
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == '"':
                    end += 1
                    break
                end += 1
            end = min(end, length)
            blank(index, end)
            index = end
            continue
        match = CHAR_LITERAL.match(source, index)
        if match:
            blank(index, match.end())
            index = match.end()
            continue
        index += 1
    return "".join(out)


def read_parenthesized(text: str, open_paren: int) -> tuple[str, int]:
    """Return the contents of a parenthesized run and the index past it."""
    depth = 0
    index = open_paren
    while index < len(text):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index], index + 1
        index += 1
    return "", len(text)


def parse_predicate(text: str):
    """Parse a cfg predicate into ('atom', str) or ('all'|'any'|'not', [children])."""
    text = text.strip()
    match = re.match(r"\A(all|any|not)\s*\(", text)
    if not match:
        return ("atom", text)
    inner, end = read_parenthesized(text, match.end() - 1)
    if text[end:].strip():
        return ("atom", text)
    parts = []
    current = ""
    depth = 0
    for char in inner:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current)
    return (match.group(1), [parse_predicate(part) for part in parts if part.strip()])


def evaluate_without_test(node) -> str:
    """Three-valued evaluation with `test` false and every other atom unknown."""
    kind, value = node
    if kind == "atom":
        return FALSE if value.strip() == "test" else UNKNOWN
    children = [evaluate_without_test(child) for child in value]
    if kind == "not":
        result = children[0] if children else UNKNOWN
        return {TRUE: FALSE, FALSE: TRUE, UNKNOWN: UNKNOWN}[result]
    if kind == "all":
        if FALSE in children:
            return FALSE
        return UNKNOWN if UNKNOWN in children else TRUE
    if kind == "any":
        if TRUE in children:
            return TRUE
        return UNKNOWN if UNKNOWN in children else FALSE
    return UNKNOWN


def is_test_only(predicate: str) -> bool:
    return evaluate_without_test(parse_predicate(predicate)) == FALSE


def item_extent(code: str, start: int) -> tuple[int, str]:
    """End offset of the item an attribute applies to, plus its leading text."""
    index = start
    length = len(code)
    # Skip any further attributes stacked under the cfg.
    while index < length:
        while index < length and code[index].isspace():
            index += 1
        if index < length and code[index] == "#":
            probe = index + 1
            if probe < length and code[probe] == "!":
                probe += 1
            if probe < length and code[probe] == "[":
                depth = 0
                while probe < length:
                    if code[probe] == "[":
                        depth += 1
                    elif code[probe] == "]":
                        depth -= 1
                        if depth == 0:
                            probe += 1
                            break
                    probe += 1
                index = probe
                continue
        break

    head = code[index : index + 200]
    # A struct field or an enum variant ends at a comma; every other form
    # ends at a brace-matched body or a semicolon. Requiring the field
    # shape to not also be a keyword keeps `fn f() -> Result<A, B> {}`
    # out of the comma branch.
    is_field = bool(STRUCT_FIELD.match(head)) and not ITEM_KEYWORD.match(head)
    depth = 0
    probe = index
    while probe < length:
        char = code[probe]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "{" and depth == 0:
            brace_depth = 0
            scan = probe
            while scan < length:
                if code[scan] == "{":
                    brace_depth += 1
                elif code[scan] == "}":
                    brace_depth -= 1
                    if brace_depth == 0:
                        return scan + 1, head
                scan += 1
            return length, head
        elif char == ";" and depth == 0:
            return probe + 1, head
        elif char == "," and depth == 0 and is_field:
            return probe + 1, head
        probe += 1
    return length, head


def merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not spans:
        return []
    ordered = sorted(spans)
    merged = [list(ordered[0])]
    for start, end in ordered[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def resolve_module(path: Path, name: str) -> Path | None:
    base = path.parent if path.name in ("lib.rs", "main.rs", "mod.rs") else path.parent / path.stem
    for candidate in (base / f"{name}.rs", base / name / "mod.rs"):
        if candidate.exists():
            return candidate.resolve()
    return None


def analyze(path: Path) -> tuple[str, list[tuple[int, int]], list[str], bool]:
    """Return (blanked source, test-only spans, test-only mod names, file is test-only)."""
    code = blank_noncode(path.read_text(errors="replace"))
    spans: list[tuple[int, int]] = []
    modules: list[str] = []
    whole_file = False
    for match in CFG_ATTRIBUTE.finditer(code):
        predicate, after = read_parenthesized(code, match.end() - 1)
        if not is_test_only(predicate):
            continue
        close = code.find("]", after)
        if close < 0:
            continue
        if match.group(1) == "!":
            # An inner `#![cfg(test)]` gates the whole file.
            whole_file = True
            continue
        end, head = item_extent(code, close + 1)
        declaration = MOD_DECLARATION.match(head)
        if declaration:
            modules.append(declaration.group(1))
        spans.append((match.start(), end))
    return code, merge_spans(spans), modules, whole_file


def production_code(repo: Path):
    """Yield `(path, blanked code, test-only spans)` per production file.

    Shared with the other scanners in this directory, because "which of
    these bytes are production code" is the expensive half of every scan
    over this tree and a second copy of it would drift.
    """
    files = sorted((repo / "crates").glob("*/src/**/*.rs"))
    analyzed = {path: analyze(path) for path in files}

    excluded: set[Path] = set()
    for path, (_, _, modules, whole_file) in analyzed.items():
        if whole_file:
            excluded.add(path.resolve())
        for name in modules:
            resolved = resolve_module(path, name)
            if resolved:
                excluded.add(resolved)

    # A test-only module file may declare submodules of its own; those are
    # test code too.
    changed = True
    while changed:
        changed = False
        for path, (code, _, _, _) in analyzed.items():
            if path.resolve() not in excluded:
                continue
            for match in PLAIN_MOD_DECLARATION.finditer(code):
                resolved = resolve_module(path, match.group(1))
                if resolved and resolved not in excluded:
                    excluded.add(resolved)
                    changed = True

    kept = [
        (path, analyzed[path][0], analyzed[path][1])
        for path in files
        if path.resolve() not in excluded
    ]
    return kept, sorted(excluded)


def collect(repo: Path):
    kept, excluded = production_code(repo)

    hits = []
    for path, code, spans in kept:
        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(code):
                start = match.start()
                if any(begin <= start < end for begin, end in spans):
                    continue
                line = code.count("\n", 0, start) + 1
                hits.append((kind, path.relative_to(repo), line))
    hits.sort(key=lambda hit: (str(hit[1]), hit[2]))
    return hits, sorted(excluded)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=None, help="workspace root (default: this script's repo)")
    parser.add_argument(
        "--count",
        choices=["unwrap-expect", "panic", "unwrap", "expect"],
        help="print one integer and nothing else",
    )
    parser.add_argument("--by-file", action="store_true", help="per-file totals instead of sites")
    parser.add_argument(
        "--excluded", action="store_true", help="list the test-only files that were skipped"
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve() if args.repo else Path(__file__).resolve().parent.parent
    hits, excluded = collect(repo)

    if args.count:
        wanted = {
            "unwrap-expect": ("unwrap", "expect"),
            "panic": ("panic",),
            "unwrap": ("unwrap",),
            "expect": ("expect",),
        }[args.count]
        print(sum(1 for kind, _, _ in hits if kind in wanted))
        return 0

    if args.excluded:
        for path in excluded:
            print(path.relative_to(repo))
        return 0

    totals = Counter(kind for kind, _, _ in hits)
    if args.by_file:
        per_file: dict[str, Counter] = {}
        for kind, path, _ in hits:
            per_file.setdefault(str(path), Counter())[kind] += 1
        for name in sorted(per_file, key=lambda key: -sum(per_file[key].values())):
            counts = per_file[name]
            print(
                f"{sum(counts.values()):5d}  unwrap={counts['unwrap']:<4d} "
                f"expect={counts['expect']:<4d} panic={counts['panic']:<3d}  {name}"
            )
    else:
        for kind, path, line in hits:
            print(f"{path}:{line}: {kind}")

    print(
        f"\nproduction unwrap={totals['unwrap']} expect={totals['expect']} "
        f"panic={totals['panic']} (test-only files skipped: {len(excluded)})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
