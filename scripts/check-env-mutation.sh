#!/usr/bin/env bash
# Reject process-global environment mutation outside the documented
# test helpers (WOR-646).
#
# # Why this exists
#
# `std::env::set_var` / `remove_var` mutate state shared by every
# thread in the process. A mutation that races any concurrent `getenv`
# is undefined behavior on POSIX, which is why Rust 2024 makes both
# functions `unsafe`. This repository has been bitten twice:
#
# * Production wiring once used the environment as an implicit IPC
#   channel (`main.rs` exported `SB_GRACE_TIME` for `sbproxy-core` to
#   read back; `sbproxy-vault` exported `KUBECONFIG` for the kube
#   client to re-read, racing concurrent backends onto the wrong
#   cluster).
# * Tests mutated the environment ad hoc under cargo's parallel
#   runner, without restore on panic.
#
# The rule this script enforces: production code never calls
# `set_var` / `remove_var`; test code goes through the documented
# per-crate `EnvVarGuard` helper (`src/test_env.rs`), which serializes
# mutation per test binary and restores previous values on drop. The
# only files allowed to contain a call are the helper implementations
# themselves plus the three example-sweep fixtures that export
# constant dummy values exactly once, inside a `OnceLock` initializer,
# before any test reads the environment.
#
# Child-process environment construction (`Command::env`,
# `Command::env_clear`) is not mutation of this process and is not
# matched here.
#
# # Usage
#
#   scripts/check-env-mutation.sh    # exit 1 on any violation

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Files permitted to call set_var / remove_var, with the reason each
# earns its exemption. Grow this list only for a new crate's
# `src/test_env.rs` guard or a new one-shot, pre-read test fixture.
ALLOWED=(
  # The documented per-crate test guards: one lock per test binary,
  # restore on drop, panic included.
  "crates/sbproxy/src/test_env.rs"
  "crates/sbproxy-config/src/test_env.rs"
  "crates/sbproxy-core/src/test_env.rs"
  "crates/sbproxy-k8s-operator/src/test_env.rs"
  "crates/sbproxy-mcp-gateway/src/test_env.rs"
  "crates/sbproxy-middleware/src/test_env.rs"
  "crates/sbproxy-model-host/src/test_env.rs"
  "crates/sbproxy-modules/src/test_env.rs"
  "crates/sbproxy-vault/src/test_env.rs"
  # Example-sweep fixtures: constant dummy values exported exactly
  # once per test binary inside a OnceLock initializer, before any
  # test reads the environment. Nothing to restore; the process exits.
  "crates/sbproxy-config/tests/validate_examples.rs"
  "crates/sbproxy-config/tests/compression_examples.rs"
  "crates/sbproxy-core/tests/construct_examples.rs"
)

is_allowed() {
  local file="$1"
  for allowed in "${ALLOWED[@]}"; do
    if [[ "$file" == "$allowed" ]]; then
      return 0
    fi
  done
  return 1
}

VIOLATIONS=0

# Match real call sites: an optional path prefix, then set_var( or
# remove_var(. Lines whose first non-space characters start a line
# comment are skipped so prose about the functions does not trip the
# gate.
while IFS=: read -r file line text; do
  trimmed="${text#"${text%%[![:space:]]*}"}"
  case "$trimmed" in
    //*) continue ;;
  esac
  if is_allowed "$file"; then
    continue
  fi
  if [[ "$VIOLATIONS" -eq 0 ]]; then
    printf 'Process-global environment mutation outside the documented helpers:\n\n' >&2
  fi
  printf '  %s:%s: %s\n' "$file" "$line" "$trimmed" >&2
  VIOLATIONS=$((VIOLATIONS + 1))
done < <(grep -rn --include='*.rs' -E '(^|[^[:alnum:]_])(set_var|remove_var)[[:space:]]*\(' crates/ e2e/ || true)

if [[ "$VIOLATIONS" -gt 0 ]]; then
  printf '\n%s call site(s) mutate the process environment directly.\n' "$VIOLATIONS" >&2
  printf 'Production code must not call std::env::set_var / remove_var at all;\n' >&2
  printf 'thread the value as a parameter instead (see WOR-646). Tests go\n' >&2
  printf 'through the crate'\''s cfg(test) EnvVarGuard in src/test_env.rs, which\n' >&2
  printf 'serializes mutation and restores prior values on drop. For a child\n' >&2
  printf 'process, build the environment on the Command instead.\n' >&2
  exit 1
fi

printf 'env-mutation check: no direct set_var/remove_var outside the allowlist.\n'
