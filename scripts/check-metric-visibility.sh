#!/usr/bin/env bash
#
# Refuse a growing number of `stable` metric families that no dashboard
# ever draws.
#
# # Why this exists
#
# `crates/sbproxy-observe/src/metric_registry.rs` already proves a
# declared metric has a live writer outside `#[cfg(test)]`, and
# `scripts/check-metrics-stability.sh` proves `docs/metrics-stability.md`
# still matches it. Between them they prove the metric is real and
# documented. Neither proves an operator can ever see it.
#
# Nine PRs merged on 2026-08-21 added six families. Every one reached
# production with no panel in any of the three shipped dashboard trees
# and no reference in the admin console, and nothing went red. The
# registry knew the metric existed; nothing checked that the number
# reaches a human. A counter exists so somebody can answer a question
# with it at 3am, and a family nobody has drawn is one whose labels,
# units and cardinality no human has looked at.
#
# # Shrink-only, not a wall
#
# 260 stable families are uncovered as this lands. Failing the world on
# day one would mean turning the check off, so the committed baseline is
# today's real number and it may only fall. Adding a family without a
# panel pushes the count up and this goes red; adding the panel later
# pushes it down and the baseline is lowered in the same diff, where a
# reviewer sees the number move.
#
# The count lives in `scripts/metric-visibility-baseline.count` as a
# single line holding nothing but the integer, for the reason WOR-2252
# documents: a number stored among prose merges badly, two branches
# raise it in non-adjacent hunks, git keeps both, and the ratchet goes
# green forever at a ceiling no real count can reach.
#
# # What this cannot see
#
# The scanner's docstring carries the full list. The four that matter to
# somebody reading a failure:
#
#   * A family surfaced only in the admin console counts as uncovered.
#     The console reads the registry through Rust; this check reads JSON.
#     Console coverage is real coverage and this check is blind to it.
#   * A panel that queries a recording rule (`job:sbproxy_x:rate5m`)
#     instead of the raw family counts as uncovered, because the family
#     name is never written in the dashboard. `--list` marks the
#     uncovered families that at least appear in `deploy/alerts/`; those
#     are the likeliest false positives.
#   * A panel matching by wildcard (`{__name__=~"sbproxy_.*"}`) or
#     through a Grafana template variable covers families this calls
#     uncovered.
#   * `config_only` families are not judged at all. Nothing increments
#     them, the registry already forbids dashboarding one, and demanding
#     a panel would produce exactly the flat-zero line this rule exists
#     to prevent.
#
# This checks reachability, not quality. A family named in a broken
# expression on a dashboard nobody imports counts as covered.
#
# # Usage
#
#   scripts/check-metric-visibility.sh              # exit 1 if the count rose
#   scripts/check-metric-visibility.sh --list       # the uncovered families
#   scripts/check-metric-visibility.sh --self-test  # prove the detector detects

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER="$ROOT_DIR/scripts/scan-metric-visibility.py"
BASELINE_FILE="$ROOT_DIR/scripts/metric-visibility-baseline.count"

# Read a committed single-integer baseline, rejecting anything else.
#
# Taken exactly as it is: no comment stripping, no blank-line stripping.
# Anything longer than one line is a merge that kept both sides, and
# that has to be an error rather than something this reader quietly
# reassembles. `|| [ -n "$line" ]` catches a final line with no trailing
# newline, which would otherwise be dropped and make a two-number file
# look like a one-number file.
read_baseline() {
  local file="$1"
  local -a lines=()
  local line

  if [ ! -f "$file" ]; then
    echo "missing baseline file: $file" >&2
    echo "It holds the integer only. Recompute with:" >&2
    echo "  python3 scripts/scan-metric-visibility.py --count" >&2
    return 1
  fi

  while IFS= read -r line || [ -n "$line" ]; do
    lines+=("$line")
  done < "$file"

  if [ "${#lines[@]}" -ne 1 ]; then
    echo "baseline count file must hold exactly one line, found ${#lines[@]}: $file" >&2
    if [ "${#lines[@]}" -gt 1 ]; then
      echo >&2
      echo "More than one line usually means a merge kept both sides. Recompute" >&2
      echo "against the merged tree rather than keeping either branch's number:" >&2
      printf '  %s\n' "${lines[@]}" >&2
      echo >&2
      echo "  python3 scripts/scan-metric-visibility.py --count" >&2
    fi
    return 1
  fi

  case "${lines[0]}" in
    ''|*[!0-9]*)
      echo "baseline file does not contain a single integer: $file" >&2
      echo "  found: ${lines[0]}" >&2
      return 1
      ;;
  esac

  printf '%s' "${lines[0]}"
}

# Compare a measured count against a baseline file. Split out from
# run_check so the self-test can drive both directions without a real
# tree.
compare_to_baseline() {
  local actual="$1" file="$2"
  local baseline

  baseline="$(read_baseline "$file")" || return 1

  if [ "$actual" -gt "$baseline" ]; then
    echo "stable metric families with no dashboard panel: $actual (baseline $baseline)" >&2
    echo >&2
    echo "This change leaves $((actual - baseline)) more families that an" >&2
    echo "operator cannot see. See which ones with:" >&2
    echo >&2
    echo "  scripts/check-metric-visibility.sh --list" >&2
    echo >&2
    echo "Add a panel in one of the shipped dashboard trees:" >&2
    echo "  dashboards/grafana/                    product dashboards" >&2
    echo "  deploy/dashboards/                     chart dashboards, mirrored into deploy/helm/sbproxy/dashboards/" >&2
    echo "  crates/sbproxy-observe/dashboards/     mesh and proxy internals" >&2
    echo >&2
    echo "If the family is genuinely absent until a feature is configured, say" >&2
    echo "so in the panel description and draw it with absent() rather than a" >&2
    echo "rate() that renders a healthy-looking zero. If nothing increments it" >&2
    echo "at all, the registry entry is config_only, not stable, and this check" >&2
    echo "stops asking." >&2
    return 1
  fi

  if [ "$actual" -lt "$baseline" ]; then
    echo "stable metric families with no dashboard panel: $actual (baseline $baseline)" >&2
    echo >&2
    echo "Lower than the baseline, which is the good direction. Lock it in so" >&2
    echo "the ground is not given back:" >&2
    echo >&2
    printf "  printf '%%s\\\\n' %s > %s\n" "$actual" "$file" >&2
    return 1
  fi

  echo "stable metric families with no dashboard panel: $actual (baseline $baseline)"
  return 0
}

run_check() {
  local actual
  actual="$(python3 "$SCANNER" --repo "$ROOT_DIR" --count)"
  compare_to_baseline "$actual" "$BASELINE_FILE"
}

# ---------------------------------------------------------------------
# Self-test
#
# A detector that stopped detecting reads exactly like a covered tree.
# Six guards shipped in this workspace on 2026-08-21 that were narrower
# than the claim they made, and the one that cost the most scanned each
# file only up to the first column-zero `#[cfg(test)]`, which in two
# files was a helper near the top; everything below it, including the
# code the guard existed to protect, was never read. It was green and
# enforcing nothing.
#
# The equivalent failure here is a registry parser that stops early, or
# a name match loose enough that a longer family covers a shorter one.
# Both are fixtures below.
# ---------------------------------------------------------------------

# Build a fixture workspace with the same relative layout the scanner
# expects. Families are passed as `name:Support` pairs.
fixture_tree() {
  local root="$1"
  shift
  mkdir -p "$root/crates/sbproxy-observe/src" \
           "$root/crates/sbproxy-observe/dashboards" \
           "$root/dashboards/grafana" \
           "$root/deploy/dashboards" \
           "$root/deploy/alerts"

  {
    echo 'pub const METRICS: &[MetricCapability] = &['
    local pair name support
    for pair in "$@"; do
      name="${pair%%:*}"
      support="${pair##*:}"
      cat <<ENTRY
    MetricCapability {
        name: "$name",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("R"),
        support: SupportLevel::$support,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Fixture family, \"quoted\", with a stray ] and a { brace.",
        dead_reason: None,
    },
ENTRY
    done
    echo '];'
    echo
    # Reading past the array end would pull these in as families with no
    # support level. They are metric names, and they are not entries.
    echo 'pub const TENANT_SCOPED_METRICS: &[&str] = &["fixture_tenant_scoped_total"];'
  } > "$root/crates/sbproxy-observe/src/metric_registry.rs"

  echo '{"panels":[]}' > "$root/dashboards/grafana/empty.json"
}

# Put a PromQL expression on a panel in one of the fixture dashboard dirs.
# The expression carries label matchers, so it is quoted into the JSON by
# json.dumps rather than interpolated into a heredoc.
fixture_panel() {
  local root="$1" relative="$2" expression="$3"
  mkdir -p "$(dirname "$root/$relative")"
  EXPR="$expression" OUT="$root/$relative" python3 - <<'PANEL'
import json, os

document = {
    "schemaVersion": 39,
    "uid": "fixture",
    "tags": ["sbproxy"],
    "panels": [
        {
            "title": "Fixture",
            "description": "Prose naming fixture_prose_only_total, which is not a query.",
            "targets": [{"expr": os.environ["EXPR"]}],
        }
    ],
}
with open(os.environ["OUT"], "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2)
PANEL
}

self_test() {
  local scratch failures=0 status output
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-metric-visibility-selftest.XXXXXX")"
  trap 'rm -rf "$scratch"' RETURN

  # Assert the scanner's uncovered count for a fixture tree.
  expect_count() {
    local label="$1" want="$2" root="$3" got
    if ! got="$(python3 "$SCANNER" --repo "$root" --count 2>&1)"; then
      echo "self-test: $label: scanner failed: $got" >&2
      failures=1
      return
    fi
    if [ "$got" != "$want" ]; then
      echo "self-test: $label expected $want uncovered, got $got" >&2
      python3 "$SCANNER" --repo "$root" >&2 || true
      failures=1
    fi
  }

  # Assert an exit status.
  expect_status() {
    local label="$1" want="$2"
    shift 2
    set +e
    output="$("$@" 2>&1)"
    status=$?
    set -e
    if [ "$status" -ne "$want" ]; then
      echo "self-test: $label expected exit $want, got $status" >&2
      echo "$output" >&2
      failures=1
    fi
  }

  # 1. A stable family in no dashboard is reported, and a covered one is not.
  local one="$scratch/one"
  fixture_tree "$one" fixture_seen_total:Stable fixture_unseen_total:Stable
  fixture_panel "$one" dashboards/grafana/seen.json \
    'sum(rate(fixture_seen_total{outcome="deny"}[5m]))'
  expect_count "an uncovered stable family is reported" 1 "$one"

  # 2. config_only is not judged. Nothing increments it, so a panel would
  #    draw the flat zero this whole rule exists to prevent.
  local two="$scratch/two"
  fixture_tree "$two" fixture_dead_total:ConfigOnly
  expect_count "a config_only family is not demanded" 0 "$two"

  # 3. The prefix trap. A loose substring match calls `fixture_p_total`
  #    covered because a longer, different family shares its prefix.
  #    That is the shape of a guard that is green while enforcing nothing.
  local three="$scratch/three"
  fixture_tree "$three" fixture_p_total:Stable
  fixture_panel "$three" dashboards/grafana/longer.json \
    'sum(rate(fixture_p_total_retries_total[5m]))'
  expect_count "a longer family sharing a prefix is not coverage" 1 "$three"

  # 4. Histogram and summary suffixes are the same family.
  local four="$scratch/four"
  fixture_tree "$four" fixture_h_seconds:Stable
  fixture_panel "$four" dashboards/grafana/hist.json \
    'histogram_quantile(0.95, sum by (le) (rate(fixture_h_seconds_bucket[5m])))'
  expect_count "a _bucket series covers its family" 0 "$four"

  # 5. All three shipped trees count, not just the first one found.
  local five="$scratch/five"
  fixture_tree "$five" fixture_a_total:Stable fixture_b_total:Stable fixture_c_total:Stable
  fixture_panel "$five" dashboards/grafana/a.json 'rate(fixture_a_total[5m])'
  fixture_panel "$five" deploy/dashboards/b.json 'rate(fixture_b_total[5m])'
  fixture_panel "$five" crates/sbproxy-observe/dashboards/c.json 'rate(fixture_c_total[5m])'
  expect_count "every shipped dashboard tree counts" 0 "$five"

  # 6. Prose is not a panel. Naming a family in a description shows an
  #    operator nothing.
  local six="$scratch/six"
  fixture_tree "$six" fixture_prose_only_total:Stable
  fixture_panel "$six" dashboards/grafana/prose.json 'rate(fixture_other_total[5m])'
  expect_count "a name only in a description is not coverage" 1 "$six"

  # 7. The parser reads the whole array. Every fixture description holds
  #    an unmatched `]`, an escaped quote and a brace, so a parser that
  #    counts brackets without skipping string literals closes the array
  #    on the first entry and never sees the other two. That is the
  #    early-stopping bug in its local form: two thirds of the registry
  #    silently unjudged, and green. The `&[&str]` name list after the
  #    array is the other direction, for a parser that runs past the
  #    close and reads bare names as entries.
  local seven="$scratch/seven"
  fixture_tree "$seven" fixture_1_total:Stable fixture_2_total:Stable fixture_3_total:Stable
  expect_count "every entry after a bracketed description is read" 3 "$seven"
  if grep -q 'fixture_tenant_scoped_total' <(python3 "$SCANNER" --repo "$seven" 2>/dev/null); then
    echo "self-test: a name list after the array was parsed as a family" >&2
    failures=1
  fi

  # 8. A dashboard Grafana cannot import must fail loudly. Swallowing the
  #    parse error would drop that file's coverage silently and read as a
  #    coverage regression nobody can explain.
  local eight="$scratch/eight"
  fixture_tree "$eight" fixture_x_total:Stable
  printf '{ "panels": [ ' > "$eight/dashboards/grafana/broken.json"
  expect_status "malformed dashboard JSON is refused" 1 \
    python3 "$SCANNER" --repo "$eight" --count

  # 9. A shipped dashboard directory that has been renamed away must fail
  #    loudly rather than reporting its families as uncovered.
  local nine="$scratch/nine"
  fixture_tree "$nine" fixture_y_total:Stable
  rm -rf "$nine/deploy/dashboards"
  expect_status "a missing dashboard tree is refused" 1 \
    python3 "$SCANNER" --repo "$nine" --count

  # 10. The ratchet direction, both ways, plus a merge that kept two
  #     numbers.
  printf '5\n' > "$scratch/baseline.count"
  expect_status "a count above the baseline fails" 1 compare_to_baseline 6 "$scratch/baseline.count"
  expect_status "a count at the baseline passes" 0 compare_to_baseline 5 "$scratch/baseline.count"
  expect_status "a count below the baseline asks for the baseline to be lowered" 1 \
    compare_to_baseline 4 "$scratch/baseline.count"
  printf '5\n7\n' > "$scratch/merged.count"
  expect_status "a two-line baseline is refused" 1 compare_to_baseline 5 "$scratch/merged.count"

  if [ "$failures" -ne 0 ]; then
    echo "self-test failed: the detector is narrower than the enforcer" >&2
    return 1
  fi
  echo "self-test passed: 14 fixtures"
  return 0
}

case "${1:-}" in
  --self-test) self_test ;;
  --list) python3 "$SCANNER" --repo "$ROOT_DIR" ;;
  "") self_test && run_check ;;
  *)
    echo "usage: $0 [--self-test|--list]" >&2
    exit 2
    ;;
esac
