#!/usr/bin/env python3
"""Compute perf-regression deltas between two bench runs (WOR-32).

Reads two JSON files emitted by `scripts/perf-regression-run.sh` (the
"baseline" and the "candidate") and:

  1. Prints a markdown comment to stdout (or `--out FILE`) summarising
     the delta on rps, p50, p95, p99, idle RSS, and max RSS.
  2. Writes a `regressed=true|false` line to `$GITHUB_OUTPUT` when
     `--github-output` is set, where `regressed` is `true` iff one of
     {p99 latency, idle RSS, max RSS} is more than `THRESHOLD_PCT`
     worse than the baseline.

Self-test mode (`--self-test`) runs a handful of in-process fixtures
without touching the filesystem and prints `OK` on success, `FAIL`
plus a diagnostic on failure. Used by CI before the workflow runs.

Bench JSON shape (must match what `perf-regression-run.sh` emits):

    {
      "rps":       <float, requests/sec>,
      "p50_ms":    <float>,
      "p95_ms":    <float>,
      "p99_ms":    <float>,
      "idle_rss_kb": <int>,
      "max_rss_kb":  <int>,
      "schema_version": "1"
    }

The script does not read or import any sbproxy crate; it is pure
stdlib so the `--self-test` step has no Python deps to install.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# 5% threshold per WOR-32. Bumping this value requires a corresponding
# README update because the regression gate is what backs the README's
# "sub-millisecond p99 overhead" claim.
THRESHOLD_PCT = 5.0

# Metrics where "higher is better" (only rps today). All other metrics
# are latency or memory, where lower is better.
HIGHER_IS_BETTER = {"rps"}

# Subset of metrics that gate the PR. The comment reports every metric
# in `ALL_METRICS`, but only these three trip the failing check. Adding
# a new gating metric: append here AND update the ticket / README.
GATING_METRICS = ("p99_ms", "idle_rss_kb", "max_rss_kb")

ALL_METRICS = (
    "rps",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "idle_rss_kb",
    "max_rss_kb",
)

PRETTY = {
    "rps": "RPS",
    "p50_ms": "p50 latency (ms)",
    "p95_ms": "p95 latency (ms)",
    "p99_ms": "p99 latency (ms)",
    "idle_rss_kb": "idle RSS (KB)",
    "max_rss_kb": "max RSS (KB)",
}


@dataclass
class MetricRow:
    """One row in the comment table."""

    name: str
    baseline: float
    candidate: float
    delta_pct: float
    regressed: bool


def percent_change(baseline: float, candidate: float, higher_is_better: bool) -> float:
    """Signed percentage change where positive means "worse for the user".

    For latency / RSS (lower-is-better): (candidate - baseline) / baseline.
    For RPS (higher-is-better): (baseline - candidate) / baseline. So a
    positive number always means "regressed", a negative means "improved".
    A baseline of zero is treated as zero change to keep the sign well
    defined; in practice the bench never produces zero rps or zero p99.
    """

    if baseline == 0:
        return 0.0
    if higher_is_better:
        return (baseline - candidate) / baseline * 100.0
    return (candidate - baseline) / baseline * 100.0


def compute_rows(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[MetricRow]:
    rows: list[MetricRow] = []
    for m in ALL_METRICS:
        b = float(baseline.get(m, 0))
        c = float(candidate.get(m, 0))
        delta = percent_change(b, c, m in HIGHER_IS_BETTER)
        regressed = (m in GATING_METRICS) and delta > THRESHOLD_PCT
        rows.append(MetricRow(name=m, baseline=b, candidate=c, delta_pct=delta, regressed=regressed))
    return rows


def render_markdown(rows: list[MetricRow], baseline_ref: str, candidate_ref: str) -> str:
    """Render the rows as a markdown comment block.

    The first line is a single sentence that triages the PR at a glance.
    The table follows with the per-metric numbers. The threshold and the
    override-label hint are spelled out in the footer so reviewers can
    self-serve without reading the workflow source.
    """

    any_regressed = any(r.regressed for r in rows)
    headline = (
        "Performance regression detected (one or more gating metrics over "
        f"{THRESHOLD_PCT:.0f}% vs baseline)."
        if any_regressed
        else f"No regression beyond the {THRESHOLD_PCT:.0f}% gate."
    )

    lines: list[str] = []
    lines.append("### sbproxy perf-regression report")
    lines.append("")
    lines.append(headline)
    lines.append("")
    lines.append(f"- baseline: `{baseline_ref}`")
    lines.append(f"- candidate: `{candidate_ref}`")
    lines.append("")
    lines.append("| Metric | Baseline | Candidate | Delta | Gate |")
    lines.append("|---|---:|---:|---:|:---:|")
    for r in rows:
        # Show RPS as integer (whole requests/sec read better), and the
        # latency / RSS values with their natural precision.
        if r.name == "rps":
            base_s = f"{r.baseline:,.0f}"
            cand_s = f"{r.candidate:,.0f}"
        elif r.name.endswith("_ms"):
            base_s = f"{r.baseline:.3f}"
            cand_s = f"{r.candidate:.3f}"
        else:
            base_s = f"{r.baseline:,.0f}"
            cand_s = f"{r.candidate:,.0f}"
        sign = "+" if r.delta_pct > 0 else ""
        delta_s = f"{sign}{r.delta_pct:.2f}%"
        gating = "yes" if r.name in GATING_METRICS else "no"
        marker = "FAIL" if r.regressed else ("OK" if r.name in GATING_METRICS else "info")
        lines.append(
            f"| {PRETTY[r.name]} | {base_s} | {cand_s} | {delta_s} | {marker} ({gating}) |"
        )
    lines.append("")
    lines.append(
        f"Gating metrics: p99 latency, idle RSS, max RSS. Threshold: {THRESHOLD_PCT:.0f}% over baseline."
    )
    lines.append(
        "Override: add the `perf-regression-ok` label to the PR. The comment still posts so reviewers can see the regression."
    )
    return "\n".join(lines) + "\n"


def write_github_output(rows: list[MetricRow]) -> None:
    """Emit `regressed=true|false` plus a CSV of regressed metric names.

    GitHub Actions reads `$GITHUB_OUTPUT`; the workflow's gate step
    pivots on the `regressed` value. The CSV is informational so the
    workflow can mention the offending metrics in an annotation if it
    wants to.
    """

    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    any_regressed = any(r.regressed for r in rows)
    regressed_names = ",".join(r.name for r in rows if r.regressed)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(f"regressed={'true' if any_regressed else 'false'}\n")
        f.write(f"regressed_metrics={regressed_names}\n")


def cmd_compare(args: argparse.Namespace) -> int:
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    candidate = json.loads(Path(args.candidate).read_text(encoding="utf-8"))
    rows = compute_rows(baseline, candidate)
    md = render_markdown(rows, args.baseline_ref, args.candidate_ref)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    else:
        sys.stdout.write(md)
    if args.github_output:
        write_github_output(rows)
    # Exit code is always 0 for `compare`; the gate step in the workflow
    # decides whether to fail the check based on the `regressed` output.
    # That keeps the comment-posting step independent of the gate.
    return 0


def cmd_self_test(_args: argparse.Namespace) -> int:
    """In-process fixtures. No filesystem, no network."""

    failures: list[str] = []

    # Fixture 1: identical numbers should produce no regression.
    baseline = {
        "rps": 70000.0,
        "p50_ms": 0.27,
        "p95_ms": 0.44,
        "p99_ms": 0.69,
        "idle_rss_kb": 50000,
        "max_rss_kb": 80000,
    }
    rows = compute_rows(baseline, baseline)
    if any(r.regressed for r in rows):
        failures.append("identical inputs flagged a regression")
    if not all(abs(r.delta_pct) < 1e-9 for r in rows):
        failures.append("identical inputs produced non-zero delta")

    # Fixture 2: 6% p99 regression should trip the gate.
    cand = dict(baseline)
    cand["p99_ms"] = 0.69 * 1.06
    rows = compute_rows(baseline, cand)
    p99 = next(r for r in rows if r.name == "p99_ms")
    if not p99.regressed:
        failures.append("6% p99 regression did not trip the gate")
    if any(r.regressed for r in rows if r.name != "p99_ms"):
        failures.append("non-p99 metrics flagged a regression in fixture 2")

    # Fixture 3: 4% p99 regression should pass.
    cand = dict(baseline)
    cand["p99_ms"] = 0.69 * 1.04
    rows = compute_rows(baseline, cand)
    if any(r.regressed for r in rows):
        failures.append("4% p99 regression incorrectly tripped the gate")

    # Fixture 4: rps drop is reported but not gated (rps is informational).
    cand = dict(baseline)
    cand["rps"] = 70000.0 * 0.5
    rows = compute_rows(baseline, cand)
    rps = next(r for r in rows if r.name == "rps")
    if rps.regressed:
        failures.append("rps drop incorrectly tripped the gate (rps is informational)")
    if abs(rps.delta_pct - 50.0) > 1e-6:
        failures.append(f"rps delta_pct expected ~50.0, got {rps.delta_pct}")

    # Fixture 5: RSS regression should trip the gate.
    cand = dict(baseline)
    cand["max_rss_kb"] = int(80000 * 1.10)
    rows = compute_rows(baseline, cand)
    max_rss = next(r for r in rows if r.name == "max_rss_kb")
    if not max_rss.regressed:
        failures.append("10% max_rss regression did not trip the gate")

    # Fixture 6: RPS improvement reads as a negative delta (improvement).
    cand = dict(baseline)
    cand["rps"] = 70000.0 * 1.10
    rows = compute_rows(baseline, cand)
    rps = next(r for r in rows if r.name == "rps")
    if rps.delta_pct >= 0:
        failures.append(f"rps improvement should report negative delta, got {rps.delta_pct}")

    # Fixture 7: markdown rendering smoke (does not crash, contains the headline).
    rows = compute_rows(baseline, baseline)
    md = render_markdown(rows, "main@abc123", "pr@def456")
    if "perf-regression report" not in md:
        failures.append("markdown missing report header")
    if "perf-regression-ok" not in md:
        failures.append("markdown missing override-label hint")

    # Fixture 8: zero baseline does not divide by zero.
    zero = dict(baseline)
    zero["p99_ms"] = 0.0
    rows = compute_rows(zero, baseline)
    p99 = next(r for r in rows if r.name == "p99_ms")
    if p99.delta_pct != 0.0:
        failures.append("zero baseline did not produce zero delta")

    if failures:
        sys.stderr.write("FAIL\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        return 1
    sys.stdout.write("OK\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Compute perf-regression deltas (WOR-32).")
    sub = p.add_subparsers(dest="cmd")

    cmp_p = sub.add_parser("compare", help="Compare two bench JSON files.")
    cmp_p.add_argument("--baseline", required=True, help="Path to baseline JSON.")
    cmp_p.add_argument("--candidate", required=True, help="Path to candidate JSON.")
    cmp_p.add_argument(
        "--baseline-ref",
        default="main",
        help="Human-readable baseline ref (e.g. main@<sha>). Shown in the comment.",
    )
    cmp_p.add_argument(
        "--candidate-ref",
        default="pr",
        help="Human-readable candidate ref. Shown in the comment.",
    )
    cmp_p.add_argument("--out", help="Write markdown to FILE instead of stdout.")
    cmp_p.add_argument(
        "--github-output",
        action="store_true",
        help="Write `regressed=...` to $GITHUB_OUTPUT.",
    )
    cmp_p.set_defaults(func=cmd_compare)

    st_p = sub.add_parser("self-test", help="In-process fixtures. No filesystem.")
    st_p.set_defaults(func=cmd_self_test)

    # Top-level convenience: `--self-test` is sugar for `self-test`.
    p.add_argument(
        "--self-test",
        action="store_true",
        help="Shortcut for the `self-test` subcommand.",
    )
    return p


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "self_test", False):
        return cmd_self_test(args)
    if not args.cmd:
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
