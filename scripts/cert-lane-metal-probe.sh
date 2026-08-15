#!/usr/bin/env bash
# Compile and test the Metal GPU probe (WOR-2200).
#
# `probe_metal.rs` sits behind `cfg(all(target_os = "macos", feature =
# "gpu-apple"))` and is never compiled by the Linux CI jobs or by the
# crate-default `deterministic` / `cpu` lanes. This is the named lane
# that turns the feature on explicitly on Apple Silicon.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export PATH="$HOME/.cargo/bin:$PATH"

python3 "$REPO_ROOT/scripts/lib/cert_record.py" --self-test

cargo nextest run --profile ci -p sbproxy-model-host --features gpu-apple \
  -E 'test(probes_this_apple_machine) | test(live_rss_at_the_planned_envelope_agrees)' \
  --no-fail-fast

cargo run --example gpu_cert -p sbproxy-model-host --features gpu-apple -- \
  metal-probe
