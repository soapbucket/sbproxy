#!/usr/bin/env python3
"""Find `pub` items that nothing outside their own file ever names.

# Why this exists

`dead_code` cannot see a `pub` item inside a `pub mod` of a library
crate, because by definition those are public API and something outside
the crate might call them. That blind spot is most of this workspace. A
213-line CRDT (`sbproxy-mesh/src/state/sliding_window.rs`) sat unread for
its whole life without a single warning, and `MeshKeyCounters` before it.
Anything `pub(crate)` or narrower does get caught, so this scan
deliberately ignores those: rustc already polices them.

The question that finds these is not "is it dead" but "does anything
outside the defining file ever name this symbol, and if so, is it only
tests".

# What the output is, and is not

**A candidate list, not a defect list.** Four different things land in
it, and only one of them is a deletion:

1. Consumed by an optional out-of-tree API consumer. Pass `--external-tree`
   to cross-check; without it, this script cannot tell you and says so.
2. Over-exposed rather than dead: used inside its own file, so the fix is
   narrowing visibility, which also hands the item back to `dead_code`.
   Read the caller before believing this one. An integration test under
   `crates/<name>/tests/`, or a `cargo run --example` demo under
   `crates/<name>/examples/`, compiles as its own crate and links against
   the library's public API, so an item either reaches cannot be narrowed
   at all: `pub` is the only visibility that compiles. That is most of
   this list, and the scan now says so rather than proposing an
   impossible narrowing.
3. Reachable through serde or schemars rather than a Rust caller. Config
   types are named in YAML and built by deserialization. `--json` carries
   a `derives` field so a reviewer can spot these.
4. Genuinely dead: written, tested, never wired.

The matching is textual. An identifier is "named" if it appears as a word
anywhere in another file, which over-counts (a comment mentioning the
name counts) and therefore under-reports candidates. That bias is the
right one: this list should be safe to work through, not exhaustive.

# Usage

    scripts/scan-pub-item-usage.py                    # summary
    scripts/scan-pub-item-usage.py --tests-only       # the highest-value slice
    scripts/scan-pub-item-usage.py --json             # machine-readable
    scripts/scan-pub-item-usage.py --count tests-only # one integer, for CI
    scripts/scan-pub-item-usage.py --external-tree /path/to/api-consumer
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# `pub` followed by an item keyword and its name. Deliberately excludes
# `pub(crate)`, `pub(super)`, and `pub(in ...)`: rustc's own dead_code
# lint already reports those, so they are not this scan's blind spot.
ITEM_RE = re.compile(
    r"^\s*pub\s+"
    r"(?:(?:async|unsafe|extern\s+\"[^\"]*\"|const)\s+)*"
    r"(?P<kind>fn|struct|enum|trait|type|const|static|union)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)

# Re-exports name an item, they do not define one. Counting them as
# definitions would report every façade module as dead.
REEXPORT_RE = re.compile(r"^\s*pub\s+use\b")

# `pub mod x;` is deliberately not a candidate. A module declaration and
# the `pub use x::...` that re-exports it both live in the same `lib.rs`,
# so the "named outside its defining file" test reports every module as
# dead no matter how heavily its contents are used. Nothing is lost by
# skipping it: the items *inside* the module are scanned on their own
# merits, which is where the real signal was in every case that prompted
# this scan.

DERIVE_RE = re.compile(r"^\s*#\[derive\((?P<derives>[^)]*)\)\]")

# Names common enough that a word-boundary search says nothing useful.
# Reporting them would drown the real signal without adding any.
NOISE = {"new", "default", "from", "into", "get", "set", "len", "is_empty", "fmt", "next"}


def is_test_path(path: Path) -> bool:
    """Whether a whole file is non-shipping by its location: a test, a
    bench, or a `cargo run --example` demo.

    An `examples/*.rs` file compiles as its own binary target and links
    against the crate's public API exactly like an integration test
    under `tests/` does, and it is exercised the same way: a human runs
    it, nothing in CI does. Before this included `examples`, a `pub` item
    named only from its own crate's example file counted as a genuine
    production reference and cleared both ratchet buckets entirely,
    which is precisely the "wire it to a test/demo, not a caller" gap
    this scan exists to catch. WOR-2672 shipped roughly 60 new `pub`
    items across five unwired modules this way: each module's example
    was extended to name every new item at least once, which read as
    "no test-only items added" and moved `pub-item-unreferenced-baseline.count`
    down instead of up. See the note dated the day this changed in
    `scripts/pub-item-ratchet-baseline.txt` for the corrected count.
    """
    parts = path.parts
    return (
        "tests" in parts
        or "benches" in parts
        or "examples" in parts
        or path.name.startswith("test_")
        or path.name.endswith("_test.rs")
    )


def cfg_test_line_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """Line ranges (1-based, inclusive) covered by a `#[cfg(test)]` block.

    Brace-counted rather than parsed. Braces inside string or char
    literals throw the count off, and not in a safe direction. An
    unbalanced opening brace in a literal inside the block extends the
    range past the block's real end, which files the production
    references that follow it as test consumers and drives this count
    UP. A test fixture that matched on the byte string `data: {` did
    exactly that and moved `sbproxy_ai::model_group::routing_name` into
    the test-only pile. Only an unbalanced *closing* brace ends the
    range early, and that is the direction that makes an item look more
    used rather than less.

    The attribute does not always sit on a braced item. `#[cfg(test)] mod
    test_env;` and `#[cfg(test)] type Alias = ...;` carry no block at all,
    and searching forward for a brace from one of those runs past it into
    whatever unrelated construct opens the next `{`. In `sbproxy-config`
    that was the `pub use config_authority::{...}` façade ten lines below,
    so three genuinely public re-exported constants were filed as
    test-only. Stop at the first `;` reached before any brace: that is the
    end of a brace-less item.
    """
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(lines):
        if "#[cfg(test)]" in lines[index]:
            depth = 0
            started = False
            start = index + 1
            cursor = index
            while cursor < len(lines):
                depth += lines[cursor].count("{") - lines[cursor].count("}")
                if "{" in lines[cursor]:
                    started = True
                if started and depth <= 0:
                    ranges.append((start, cursor + 1))
                    index = cursor
                    break
                if not started and lines[cursor].rstrip().endswith(";"):
                    # A brace-less item. When it shares the attribute's own
                    # line there is nothing after it to cover.
                    if cursor > index:
                        ranges.append((start, cursor + 1))
                    index = cursor
                    break
                cursor += 1
            else:
                ranges.append((start, len(lines)))
                break
        index += 1
    return ranges


def rust_files(root: Path) -> list[Path]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"target", ".git", "node_modules"}]
        for name in filenames:
            if name.endswith(".rs"):
                found.append(Path(dirpath) / name)
    return sorted(found)


def collect_definitions(files: list[Path], repo: Path) -> dict[str, list[dict]]:
    """Map identifier -> the definitions that declare it."""
    definitions: dict[str, list[dict]] = defaultdict(list)
    for path in files:
        if is_test_path(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        test_ranges = cfg_test_line_ranges(lines)
        pending_derives: list[str] = []
        for lineno, line in enumerate(lines, start=1):
            derive_match = DERIVE_RE.match(line)
            if derive_match:
                pending_derives = [d.strip() for d in derive_match.group("derives").split(",")]
                continue
            if REEXPORT_RE.match(line):
                pending_derives = []
                continue
            match = ITEM_RE.match(line)
            if not match:
                if line.strip() and not line.strip().startswith(("#", "//", "///")):
                    pending_derives = []
                continue
            # An item defined inside `#[cfg(test)]` is test scaffolding,
            # not shipping surface, so it is not a candidate.
            if any(lo <= lineno <= hi for lo, hi in test_ranges):
                pending_derives = []
                continue
            name = match.group("name")
            if name in NOISE:
                pending_derives = []
                continue
            definitions[name].append(
                {
                    "name": name,
                    "kind": match.group("kind"),
                    "file": str(path.relative_to(repo)),
                    "line": lineno,
                    "crate": crate_of(path, repo),
                    "derives": pending_derives,
                }
            )
            pending_derives = []
    return definitions


def crate_of(path: Path, repo: Path) -> str:
    rel = path.relative_to(repo).parts
    if len(rel) >= 2 and rel[0] == "crates":
        return rel[1]
    return rel[0] if rel else "?"


def collect_references(
    files: list[Path], names: set[str], repo: Path
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Per name, the files that mention it in production and in test code."""
    production: dict[str, set[str]] = defaultdict(set)
    tests: dict[str, set[str]] = defaultdict(set)
    # Tokenise once per line and intersect with the candidate set. A
    # single alternation over several thousand names is correct but
    # roughly two orders of magnitude slower, which matters because this
    # runs in CI on every push.
    word = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel = str(path.relative_to(repo))
        whole_file_is_tests = is_test_path(path)
        test_ranges = [] if whole_file_is_tests else cfg_test_line_ranges(lines)
        range_iter = iter(test_ranges)
        current = next(range_iter, None)
        for lineno, line in enumerate(lines, start=1):
            hits = names.intersection(word.findall(line))
            # Advance through the sorted `#[cfg(test)]` spans rather than
            # rescanning them per line.
            while current is not None and lineno > current[1]:
                current = next(range_iter, None)
            if not hits:
                continue
            in_tests = whole_file_is_tests or (
                current is not None and current[0] <= lineno <= current[1]
            )
            bucket = tests if in_tests else production
            for hit in hits:
                bucket[hit].add(rel)
    return production, tests


def external_tree_names(root: Path) -> set[str]:
    """Every identifier an optional external consumer tree mentions.

    In-tree unreferenced does not mean unused. A public item can be absent
    from this repository's call sites while remaining part of an API consumed
    by another checkout; deleting it would break a build this scan cannot see.
    """
    found: set[str] = set()
    word = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    for path in rust_files(root):
        try:
            found.update(word.findall(path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return found


def load_recorded_verdicts(repo: Path) -> dict[str, dict]:
    """Human verdicts that override the class rule.

    The scan can see whether a name is referenced. It cannot see why an item
    exists, so a small registry carries the cases where a person looked and
    disagreed with the inference.
    """
    path = repo / "scripts" / "pub-item-verdicts.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("verdicts", {})


def verdict_for(item: dict) -> tuple[str, str]:
    """The class-based verdict for one candidate, and why.

    Four classes, from the ticket that prompted this scan. Only the last
    is a deletion, which is the whole reason the list is triaged rather
    than swept.
    """
    if item.get("recorded"):
        return (item["recorded"]["verdict"], item["recorded"]["reason"])
    if item.get("in_external_tree"):
        return (
            "keep",
            "named by the out-of-tree consumer tree; deleting it breaks a build "
            "that does not live in this repository",
        )
    if item.get("cross_crate_test"):
        where = item["cross_crate_test"][0]
        return (
            "keep",
            f"reached from `{where}`, which compiles as its own crate and links "
            "against this one's public API, so `pub` is the only visibility that "
            "resolves; narrowing it would not compile",
        )
    if any("Deserialize" in d or "JsonSchema" in d for d in item.get("derives", [])):
        return (
            "keep",
            "reached through serde or schemars rather than a Rust caller, so it is "
            "live even though nothing names it",
        )
    if item.get("used_in_own_file"):
        return (
            "narrow",
            f"used {item['used_in_own_file']}x inside its own file, so this is wrong "
            "visibility rather than dead code; `pub(crate)` hands it back to dead_code",
        )
    return (
        "wire-or-delete",
        "no consumer in either tree and no in-file use; either give it a production "
        "call site or remove it",
    )


def emit_triage(tests_only: list[dict], unreferenced: list[dict], cross_checked: bool) -> None:
    """Print the committed triage table."""
    counts: dict[str, int] = defaultdict(int)
    for item in tests_only:
        counts[verdict_for(item)[0]] += 1
    all_counts: dict[str, int] = defaultdict(int)
    for item in unreferenced:
        all_counts[verdict_for(item)[0]] += 1

    print("# Triage: `pub` items with no consumer outside their own file")
    print()
    print("*Generated by `scripts/scan-pub-item-usage.py --triage`. Do not hand-edit.*")
    print()
    print("Regenerate with:")
    print()
    print("```bash")
    print("python3 scripts/scan-pub-item-usage.py --triage \\")
    print("  --external-tree /path/to/api-consumer > scripts/pub-item-triage.md")
    print("```")
    print()
    if not cross_checked:
        print("**This table was generated without the external-tree cross-check, so its")
        print("`keep` column is wrong. Regenerate it with `--external-tree` before acting")
        print("on anything here.**")
        print()
    print("## Verdicts")
    print()
    meanings = {
        "keep": "Live through a consumer `pub(crate)` would not reach: an integration "
        "test that compiles as its own crate, the out-of-tree tree, serde/schemars, or "
        "a reason recorded in scripts/pub-item-verdicts.json.",
        "narrow": "Used inside its own file. Wrong visibility, not dead code. Narrowing "
        "to `pub(crate)` shrinks the public surface and lets `dead_code` police it from "
        "then on.",
        "wire-or-delete": "No consumer anywhere and no in-file use. Give it a production "
        "call site or remove it.",
        "escalated": "A finding too big to settle inside a cleanup PR. Tracked "
        "separately; see scripts/pub-item-verdicts.json for the reason.",
    }
    print("| Verdict | Meaning | Tests-only | All |")
    print("| --- | --- | --- | --- |")
    for verdict in sorted(set(counts) | set(all_counts)):
        meaning = meanings.get(verdict, "See scripts/pub-item-verdicts.json.")
        print(f"| `{verdict}` | {meaning} | {counts[verdict]} | {all_counts[verdict]} |")
    print()
    print(f"Tests-only total: **{len(tests_only)}**. Full candidate list: **{len(unreferenced)}**.")
    print()
    print("`narrow` is the highest-leverage verdict and should be preferred over deletion")
    print("wherever it applies. It converts an item rustc cannot see into one it polices for")
    print("free, so the same item can never rot silently a second time.")
    print()
    print("## Tests-only items")
    print()
    print("The slice with the highest density of real findings and the lowest risk of a")
    print("false positive, so it is where the cleanup starts. A symbol whose only consumer")
    print("is its own test suite is not shipping behaviour.")
    print()
    current_crate = None
    for item in tests_only:
        if item["crate"] != current_crate:
            current_crate = item["crate"]
            print()
            print(f"### {current_crate}")
            print()
            print("| Item | Location | Verdict | Why |")
            print("| --- | --- | --- | --- |")
        verdict, why = verdict_for(item)
        location = f"{item['file']}:{item['line']}"
        print(f"| `pub {item['kind']} {item['name']}` | `{location}` | `{verdict}` | {why} |")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=None, help="workspace root (default: this script's repo)")
    parser.add_argument(
        "--external-tree",
        default=None,
        help="path to an out-of-tree API consumer, cross-checked before any deletion",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--tests-only",
        action="store_true",
        help="only items whose sole outside consumer is test code",
    )
    parser.add_argument(
        "--triage",
        action="store_true",
        help="emit the committed triage table for the tests-only slice",
    )
    parser.add_argument(
        "--count",
        choices=["unreferenced", "tests-only"],
        help="print one integer and exit, for a CI ratchet",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve() if args.repo else Path(__file__).resolve().parent.parent
    crates = repo / "crates"
    if not crates.is_dir():
        print(f"no crates/ directory under {repo}", file=sys.stderr)
        return 2

    all_files = rust_files(crates) + rust_files(repo / "e2e") if (repo / "e2e").is_dir() else rust_files(crates)
    definitions = collect_definitions(rust_files(crates), repo)
    production, tests = collect_references(all_files, set(definitions), repo)

    external_names = (
        external_tree_names(Path(args.external_tree).resolve()) if args.external_tree else None
    )

    # How often each name appears in its own defining file beyond the
    # definition itself. A non-zero count means the item is used, just
    # over-exposed, and the fix is `pub(crate)` rather than deletion.
    in_file_uses: dict[str, int] = {}
    word = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    for name, defs in definitions.items():
        if len(defs) != 1:
            continue
        try:
            text = (repo / defs[0]["file"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Minus one for the definition line's own occurrence.
        in_file_uses[name] = max(0, word.findall(text).count(name) - 1)

    unreferenced = []
    tests_only = []
    for name, defs in definitions.items():
        # A name defined in more than one file cannot be attributed
        # unambiguously by text matching, so it is not reported.
        if len(defs) != 1:
            continue
        definition = defs[0]
        own = definition["file"]
        outside_prod = production.get(name, set()) - {own}
        outside_test = tests.get(name, set()) - {own}
        if external_names is not None:
            definition["in_external_tree"] = name in external_names
        definition["used_in_own_file"] = in_file_uses.get(name, 0)
        if not outside_prod and not outside_test:
            unreferenced.append(definition)
        elif not outside_prod and outside_test:
            definition["test_consumers"] = sorted(outside_test)
            # Consumers outside the defining crate's own `src/` cannot see a
            # `pub(crate)` item. An integration test under `tests/` is a
            # separate crate, and so is any other workspace member's test
            # module, so those items are not narrowable at any price.
            own_src = f"crates/{definition['crate']}/src/"
            definition["cross_crate_test"] = [
                consumer
                for consumer in definition["test_consumers"]
                if not consumer.startswith(own_src)
            ]
            tests_only.append(definition)
            unreferenced.append(definition)

    recorded = load_recorded_verdicts(repo)
    known_keys = set()
    for entry in unreferenced:
        key = f"{entry['file']}::{entry['name']}"
        known_keys.add(key)
        if key in recorded:
            entry["recorded"] = recorded[key]
    # A recorded verdict for an item that no longer exists is an excuse for
    # code that was already dealt with. Fail rather than carry it forward.
    stale = sorted(set(recorded) - known_keys)
    if stale:
        print(
            "recorded verdicts name items that are no longer candidates; "
            "remove them from scripts/pub-item-verdicts.json:",
            file=sys.stderr,
        )
        for key in stale:
            print(f"  {key}", file=sys.stderr)
        return 2

    unreferenced.sort(key=lambda d: (d["crate"], d["file"], d["line"]))
    tests_only.sort(key=lambda d: (d["crate"], d["file"], d["line"]))

    if args.count:
        print(len(tests_only if args.count == "tests-only" else unreferenced))
        return 0

    selected = tests_only if args.tests_only else unreferenced

    if args.triage:
        emit_triage(tests_only, unreferenced, external_names is not None)
        return 0

    if args.json:
        print(json.dumps({"items": selected, "total": len(selected)}, indent=2))
        return 0

    by_crate: dict[str, int] = defaultdict(int)
    for item in unreferenced:
        by_crate[item["crate"]] += 1

    print(f"pub items never named outside their own file: {len(unreferenced)}")
    print(f"pub items named only by test code:            {len(tests_only)}")
    if external_names is None:
        print("external-tree cross-check:                    NOT RUN (pass --external-tree)")
        print("  Nothing here is safe to delete without it.")
    else:
        shared = sum(1 for i in unreferenced if i.get("in_external_tree"))
        print(f"external-tree cross-check:                    {shared} of these appear out of tree")
    print()
    print("By crate, worst first:")
    for crate, count in sorted(by_crate.items(), key=lambda kv: -kv[1]):
        print(f"  {crate:<28} {count}")
    print()
    for item in selected:
        flag = ""
        if item.get("in_external_tree"):
            flag = "  [in external tree, do not delete]"
        elif item.get("cross_crate_test"):
            flag = f"  [reached from {item['cross_crate_test'][0]}: pub is required]"
        elif item.get("derives") and any(
            "Deserialize" in d or "JsonSchema" in d for d in item["derives"]
        ):
            flag = "  [reachable via serde/schemars]"
        elif item.get("used_in_own_file"):
            flag = f"  [used {item['used_in_own_file']}x in-file: narrow, do not delete]"
        if item.get("recorded"):
            flag = f"  [recorded: {item['recorded']['verdict']}]"
        print(f"{item['file']}:{item['line']}  pub {item['kind']} {item['name']}{flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
