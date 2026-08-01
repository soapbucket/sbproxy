#!/usr/bin/env bash
# WOR-1976: every generated config key must have a non-test Rust reader or a
# reviewed capability-registry override. Keep this as an explicit CI/local
# lane even though the test also runs in the workspace suite: the named command
# makes config-reader coverage visible and difficult to skip accidentally.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TEST_NAME='key_registry::tests::every_schema_key_has_a_production_reader_or_reviewed_override'

# `--workspace --exclude sbproxy-e2e` rather than `-p sbproxy-config`. Under
# resolver = "2" the package selection determines the feature union, so the
# narrower `-p` form resolves different features than the workspace build and
# recompiles the graph to run one test. Matching the workspace selection makes
# this reuse whatever the lane already built.
#
# nextest is preferred because it fails when a filter matches nothing, so
# renaming the test cannot silently turn this gate into a no-op.
if cargo nextest --version >/dev/null 2>&1; then
  cargo nextest run --workspace --exclude sbproxy-e2e --locked \
    -E "test(=${TEST_NAME})"
else
  cargo test --workspace --exclude sbproxy-e2e --locked --lib \
    "${TEST_NAME}" -- --exact
fi
