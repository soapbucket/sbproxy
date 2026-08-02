#!/usr/bin/env bash
# Validate the Prometheus recording and alerting rules (WOR-1894).
#
# Two layers, because one without the other is a false sense of safety:
#
#   1. `promtool check rules` parses the YAML and type-checks the PromQL. It
#      catches a malformed rule file, which nothing in this repo did before.
#   2. `promtool test rules` replays synthetic series through the rules and
#      asserts the SLIs come out right. This is the layer that catches the bug
#      promtool's parser cannot: `promtool check rules` was perfectly happy with
#      `status_class!="5xx"`, because the label name is syntactically fine. Only
#      feeding it a real 5xx burn and demanding the availability SLO drop below
#      1.0 proves the rule measures what it claims to.
#
# The metric-name and label drift itself is caught in Rust by
# crates/sbproxy-observe/tests/metric_drift.rs, which does not need promtool and
# runs on every build. This script is the PromQL-semantics half.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v promtool >/dev/null 2>&1; then
  echo "promtool not found on PATH; install prometheus to run this check" >&2
  exit 1
fi

promtool check rules \
  deploy/alerts/recording-rules.yml \
  deploy/alerts/alerting-rules.yml \
  dashboards/prometheus/recording-rules.yml \
  dashboards/prometheus/alerts.yml

promtool test rules deploy/alerts/tests/availability_slo_test.yml

echo "prometheus rules validate and the availability SLO burns under a 5xx load"
