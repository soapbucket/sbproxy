#!/usr/bin/env bash
# Fail when an Apache-2.0-only crate is not named in NOTICE (WOR-2449).
#
# Apache 2.0 section 4(d) requires a copyright notice and the URL of
# the project's source for each such dependency. The check used to live
# as a copy-paste snippet in CLAUDE.md / AGENTS.md, which means a miss
# only showed up if someone remembered to run it. This script is the
# same rule, invoked by scripts/check.sh and the CI lint job.
#
# `cargo metadata --all-features` is the union the snippet always used:
# a crate that only appears behind an optional feature still ships in
# some binaries, so it still needs a stanza. The call does not compile
# anything and does not change the package selection of later cargo
# invocations in the same job.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "${1:-}" = "--self-test" ]; then
  python3 "$ROOT/scripts/lib/notice_coverage.py" --self-test
  python3 "$ROOT/scripts/tests/test_notice_coverage.py"
  exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is not on PATH; NOTICE coverage cannot run" >&2
  exit 1
fi

# --locked: do not rewrite Cargo.lock as a side effect of the scan.
# No --offline: a cold CI cache still has to fetch git `[patch]` sources
# such as the pinned Pingora fork, and a fetch miss must not look like
# a NOTICE gap.
cargo metadata --format-version 1 --all-features --locked \
  | python3 "$ROOT/scripts/lib/notice_coverage.py" --notice "$ROOT/NOTICE"
