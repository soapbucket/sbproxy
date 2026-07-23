#!/usr/bin/env bash
# WOR-1976: every generated config key must have a non-test Rust reader or a
# reviewed capability-registry override. Keep this as an explicit CI/local
# lane even though the test also runs in the workspace suite: the named command
# makes config-reader coverage visible and difficult to skip accidentally.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo test -p sbproxy-config --lib \
  key_registry::tests::every_schema_key_has_a_production_reader_or_reviewed_override \
  -- --exact
