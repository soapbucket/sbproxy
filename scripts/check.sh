#!/usr/bin/env bash
# Run the local pre-commit gate from CLAUDE.md.
#
# The test step uses cargo-nextest when it is installed and falls back to plain
# cargo test otherwise. Install with:
#
#   cargo install cargo-nextest --locked
#
# Defaults match the required PR lane: non-e2e workspace tests in the dev
# profile, plus doctests. Set SBPROXY_RELEASE_TESTS=1 to run test binaries in
# release mode, and SBPROXY_CHECK_E2E=1 to include the sbproxy-e2e package.
# Set SBPROXY_CLEAN_AFTER_BUILD=0 to keep all build artifacts after the run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() {
  printf '\n\033[1;34m==>\033[0m %s\n' "$*"
}

cleanup() {
  if [ "${SBPROXY_CLEAN_AFTER_BUILD:-1}" != "0" ]; then
    "$ROOT/scripts/cleanup-build-artifacts.sh"
  fi
}
trap cleanup EXIT

step "cargo fmt --check"
cargo fmt --all -- --check

step "cargo build"
cargo build --workspace

test_package_args=(--workspace --locked)
if [ "${SBPROXY_CHECK_E2E:-0}" != "1" ]; then
  test_package_args+=(--exclude sbproxy-e2e)
fi

nextest_args=("${test_package_args[@]}" --profile ci)
cargo_test_args=("${test_package_args[@]}")
if [ "${SBPROXY_RELEASE_TESTS:-0}" = "1" ]; then
  nextest_args+=(--release --tests)
  cargo_test_args+=(--release --tests)
fi

step "cargo test"
if cargo nextest --version >/dev/null 2>&1; then
  cargo nextest run "${nextest_args[@]}"
else
  printf "cargo-nextest not installed, falling back to cargo test. Install with 'cargo install cargo-nextest --locked'.\n"
  cargo test "${cargo_test_args[@]}"
fi

step "cargo doctest"
cargo test "${test_package_args[@]}" --doc

step "cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings

step "cargo doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items

printf '\n\033[1;32mAll checks passed.\033[0m\n'
