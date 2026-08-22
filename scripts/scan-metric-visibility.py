#!/usr/bin/env python3
"""Report `stable` metric families that no shipped dashboard queries.

# Why this exists

`crates/sbproxy-observe/src/metric_registry.rs` proves that a declared
metric has a live writer. Nothing proved that anybody could ever see it.
Nine PRs merged on 2026-08-21 added six families between them; every one
reached production with no panel anywhere, and no gate noticed, because
a registry entry and a dashboard are maintained in different trees by
different reviews.

An unseen metric is not a small gap. The reason to emit a counter is so
an operator can answer a question with it during an incident, and a
family nobody has ever drawn is a family whose labels, units and
cardinality have never been looked at by a human. It is also the cheapest
possible fix at the time the metric is added and an expensive one later.

# What counts as covered

A family is covered when its name appears literally in a query-bearing
field of a dashboard JSON in one of the shipped dashboard directories:
`expr`, `query`, or `definition` (template variable queries). Prose is
deliberately not searched, so naming a family in a panel `description`
does not make it covered.

The name may carry a Prometheus histogram or summary suffix, so the
family `sbproxy_x_seconds` is covered by `sbproxy_x_seconds_bucket`,
`_sum` or `_count`. It is matched on identifier boundaries, so the
family `sbproxy_x` is NOT covered by an expression that only mentions
`sbproxy_x_retries_total`. That distinction is the whole point: the loose
version of this check reports a family as covered because a longer,
different family shares its prefix, which is precisely how a guard ends
up green while enforcing nothing.

# What is judged

Only `SupportLevel::Stable` families. `ConfigOnly` is a declared,
permitted state meaning nothing increments the family, and the registry
already forbids dashboarding one; requiring a panel for it would ask for
the flat-zero panel this whole rule exists to prevent.

# What this cannot see

  * A metric surfaced in the admin console and not in Grafana. The
    console reads the registry through Rust, not through these JSON
    files, so a family with a console card and no panel still reports as
    uncovered.
  * A panel that reaches a family through a recording rule
    (`job:sbproxy_x:rate5m`) rather than by name. The raw family is never
    written in the dashboard, so it reports as uncovered even though an
    operator can see it. Use `--list` to see which uncovered families at
    least have an alerting or recording rule; those are marked, and are
    the likeliest false positives.
  * A panel that matches by wildcard (`{__name__=~"sbproxy_.*"}`) or by
    a Grafana template variable that is substituted at render time. Both
    cover families this scan calls uncovered.
  * Whether the panel is any good. A family named in an expression that
    is broken, mislabeled, or on a dashboard nobody imports counts as
    covered here. This checks reachability, not usefulness.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# The three shipped dashboard trees. All three must exist: a rename that
# empties one would otherwise read as a large, silent coverage loss that
# the ratchet reports as a count change with no explanation.
DASHBOARD_DIRS = (
    "dashboards/grafana",
    "deploy/dashboards",
    "crates/sbproxy-observe/dashboards",
)

# The Helm chart mirrors `deploy/dashboards`. It cannot add coverage
# today, and it is read anyway so that a copy which drifts ahead of its
# source still counts rather than being invisible.
OPTIONAL_DASHBOARD_DIRS = ("deploy/helm/sbproxy/dashboards",)

# Prometheus rule files. Never coverage on their own; read only to mark
# the uncovered families that an operator can still be paged about.
RULE_FILES = (
    "deploy/alerts/alerting-rules.yml",
    "deploy/alerts/recording-rules.yml",
)

REGISTRY = "crates/sbproxy-observe/src/metric_registry.rs"

# JSON keys whose string values are PromQL. `description` is excluded on
# purpose: naming a family in prose is not showing it to anybody.
QUERY_KEYS = frozenset({"expr", "query", "definition"})

# Suffixes Prometheus appends to a histogram or summary family.
SERIES_SUFFIXES = ("_bucket", "_sum", "_count", "_created")

ARRAY_START = "pub const METRICS: &[MetricCapability] = &["


def parse_registry(path: Path) -> list[tuple[str, str]]:
    """Return (name, support) for every entry of the METRICS array.

    Bounded by the array itself, not by the file. `metric_registry.rs`
    also holds `TENANT_SCOPED_METRICS`, a bare `&[&str]` of metric names
    with no support level; reading past the closing bracket would pull
    those in as entries with an unknown support level, and reading only
    to the first blank line or the first `#[cfg(test)]` would silently
    drop most of the array. Both failures are quiet, so the array is
    delimited by bracket depth and the entry count is returned to the
    caller to assert against.
    """
    text = path.read_text(encoding="utf-8")
    start = text.find(ARRAY_START)
    if start < 0:
        raise SystemExit(f"{path}: cannot find `{ARRAY_START}`")

    # Walk from the opening `[` to its match, ignoring brackets inside
    # string literals (descriptions contain them).
    open_at = start + len(ARRAY_START) - 1
    depth = 0
    in_string = False
    escaped = False
    end = None
    for index in range(open_at, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        raise SystemExit(f"{path}: METRICS array is never closed")

    body = text[open_at : end + 1]

    entries: list[tuple[str, str]] = []
    for block in re.finditer(r"MetricCapability\s*\{(.*?)\n    \}", body, re.DOTALL):
        fields = block.group(1)
        name = re.search(r'\bname:\s*"([^"]+)"', fields)
        support = re.search(r"\bsupport:\s*SupportLevel::(\w+)", fields)
        if not name or not support:
            raise SystemExit(
                f"{path}: a MetricCapability entry is missing name or support:\n{fields[:200]}"
            )
        entries.append((name.group(1), support.group(1)))

    declared = body.count("MetricCapability {")
    if len(entries) != declared:
        raise SystemExit(
            f"{path}: parsed {len(entries)} entries but the array declares {declared}. "
            "The entry shape changed and this parser is now reading less than the registry holds."
        )
    return entries


def _collect_queries(node: object, out: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in QUERY_KEYS and isinstance(value, str):
                out.append(value)
            _collect_queries(value, out)
    elif isinstance(node, list):
        for value in node:
            _collect_queries(value, out)


def dashboard_queries(root: Path) -> tuple[list[str], list[Path]]:
    """Every PromQL string in every shipped dashboard, and the files read."""
    queries: list[str] = []
    read: list[Path] = []
    for relative in DASHBOARD_DIRS:
        directory = root / relative
        if not directory.is_dir():
            raise SystemExit(
                f"{relative} is a shipped dashboard directory and is missing. "
                "If it moved, update DASHBOARD_DIRS in this scanner in the same change."
            )
    for relative in DASHBOARD_DIRS + OPTIONAL_DASHBOARD_DIRS:
        directory = root / relative
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.json")):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                raise SystemExit(f"{path}: not valid JSON, so Grafana cannot import it: {error}")
            _collect_queries(document, queries)
            read.append(path)
    return queries, read


def rule_text(root: Path) -> str:
    parts = []
    for relative in RULE_FILES:
        path = root / relative
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def covered_by(name: str, haystack: str) -> bool:
    suffixes = "|".join(SERIES_SUFFIXES)
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(name)}(?:{suffixes})?(?![A-Za-z0-9_])"
    return re.search(pattern, haystack) is not None


def uncovered(root: Path) -> tuple[list[tuple[str, bool]], int, int]:
    """Uncovered stable families, each flagged with whether a rule names it."""
    entries = parse_registry(root / REGISTRY)
    queries, _ = dashboard_queries(root)
    haystack = "\n".join(queries)
    rules = rule_text(root)

    stable = [name for name, support in entries if support == "Stable"]
    missing = [(name, covered_by(name, rules)) for name in stable if not covered_by(name, haystack)]
    return missing, len(stable), len(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=None, help="workspace root (default: this script's repo)")
    parser.add_argument("--count", action="store_true", help="print the number of uncovered stable families only")
    args = parser.parse_args()

    root = Path(args.repo).resolve() if args.repo else Path(__file__).resolve().parent.parent
    missing, stable_total, declared_total = uncovered(root)

    if args.count:
        print(len(missing))
        return 0

    for name, alerted in missing:
        print(f"{name}\t{'alerted' if alerted else 'no-rule'}")
    print(
        f"\n{len(missing)} of {stable_total} stable families "
        f"({declared_total} declared) appear in no dashboard query.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
