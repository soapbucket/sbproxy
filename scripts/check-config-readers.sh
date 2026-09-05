#!/usr/bin/env bash
# WOR-1976: every generated config key must have a non-test Rust reader or a
# reviewed capability-registry override. Keep this as an explicit CI/local
# lane even though the test also runs in the workspace suite: the named command
# makes config-reader coverage visible and difficult to skip accidentally.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

READER_TEST='key_registry::tests::every_schema_key_has_a_production_reader_or_reviewed_override'

# WOR-2245: the reader test only sees the keys it is given, and the module
# and AI-gateway subtrees only reach it through the roots declared in
# MODULE_CONFIG_ROOTS. This second test is what makes that registry
# impossible to leave behind: it reads the config compiler's own dispatch
# tables and fails when a module an operator can name has no classification.
# Running it in the same lane keeps the two halves from drifting apart.
COVERAGE_TEST='key_registry::tests::every_dispatchable_module_declares_whether_its_config_is_guarded'

# `--workspace --exclude sbproxy-e2e` rather than `-p sbproxy-config`. Under
# resolver = "2" the package selection determines the feature union, so the
# narrower `-p` form resolves different features than the workspace build and
# recompiles the graph to run one test. Matching the workspace selection makes
# this reuse whatever the lane already built.
# Both assertions live in libraries. Restrict targets with --lib so this
# audit does not discover hundreds of unrelated integration-test binaries.
#
# nextest is preferred because it fails when a filter matches nothing, so
# renaming either test cannot silently turn this gate into a no-op. That
# is only half the property, though: nextest refuses zero matches and
# accepts one of two, and the `cargo test` fallback below accepts zero
# outright. `0 passed; 2857 filtered out` with a green exit is what that
# looks like, and it shipped on 2026-08-28. Both arms assert the count.
. "$ROOT/scripts/lib/expect-tests.sh"

if cargo nextest --version >/dev/null 2>&1; then
  expect_tests 2 "config-reader coverage (nextest)" -- \
    cargo nextest run --workspace --exclude sbproxy-e2e --locked --lib \
      -E "test(=${READER_TEST}) + test(=${COVERAGE_TEST})"
else
  expect_tests 1 "$READER_TEST" -- \
    cargo test --workspace --exclude sbproxy-e2e --locked --lib \
      "${READER_TEST}" -- --exact
  expect_tests 1 "$COVERAGE_TEST" -- \
    cargo test --workspace --exclude sbproxy-e2e --locked --lib \
      "${COVERAGE_TEST}" -- --exact
fi
