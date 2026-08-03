#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-workspace-bin-test.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_equal() {
  local expected="$1" actual="$2" label="$3"
  if [ "$actual" != "$expected" ]; then
    printf 'FAIL: %s\nexpected: %s\nactual:   %s\n' \
      "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

write_executable() {
  local path="$1"
  shift
  printf '%s\n' '#!/usr/bin/env bash' "$@" >"$path"
  chmod +x "$path"
}

# shellcheck source=scripts/lib/workspace-bin.sh
. "$ROOT/scripts/lib/workspace-bin.sh"

fixture_root="$TEST_DIR/generated-checks"
mkdir -p "$fixture_root/scripts"
checks_log="$TEST_DIR/generated-checks.log"
for check in \
  check-config-schema.sh \
  check-config-readers.sh \
  check-metrics-stability.sh \
  check-model-host-capabilities.sh
do
  # The single quotes preserve these variables for the generated fixture.
  # shellcheck disable=SC2016
  write_executable "$fixture_root/scripts/$check" \
    'printf "%s:%s\n" "${SBPROXY_PREBUILT_BINS:-unset}" "$(basename "$0")" >>"$SBPROXY_TEST_LOG"'
done

SBPROXY_TEST_LOG="$checks_log" run_generated_artifact_checks \
  "$fixture_root" \
  check-config-schema.sh \
  check-config-readers.sh \
  check-metrics-stability.sh \
  check-model-host-capabilities.sh
expected_checks='1:check-config-schema.sh
1:check-config-readers.sh
1:check-metrics-stability.sh
1:check-model-host-capabilities.sh'
assert_equal "$expected_checks" "$(cat "$checks_log")" \
  'generated checks must opt into workspace binaries'

target_dir="$TEST_DIR/target"
fake_bin="$TEST_DIR/bin"
mkdir -p "$target_dir/debug" "$fake_bin"
cargo_log="$TEST_DIR/cargo.log"

write_executable "$target_dir/debug/generate-schema" \
  'printf "prebuilt\n"'
# shellcheck disable=SC2016
write_executable "$fake_bin/cargo" \
  'printf "cargo called\n" >>"$SBPROXY_TEST_CARGO_LOG"' \
  'exit 99'

output="$({
  CARGO_TARGET_DIR="$target_dir" \
  SBPROXY_PREBUILT_BINS=1 \
  SBPROXY_TEST_CARGO_LOG="$cargo_log" \
  PATH="$fake_bin:$PATH" \
    run_workspace_bin generate-schema -p sbproxy-config --bin generate-schema
})"
assert_equal 'prebuilt' "$output" 'an existing workspace binary must run directly'
[ ! -s "$cargo_log" ] || fail 'Cargo ran despite an executable workspace binary'

rm "$target_dir/debug/generate-schema"
# shellcheck disable=SC2016
write_executable "$fake_bin/cargo" \
  'printf "%s\n" "$*" >>"$SBPROXY_TEST_CARGO_LOG"' \
  'printf "cargo fallback\n"'

output="$({
  CARGO_TARGET_DIR="$target_dir" \
  SBPROXY_PREBUILT_BINS=1 \
  SBPROXY_TEST_CARGO_LOG="$cargo_log" \
  PATH="$fake_bin:$PATH" \
    run_workspace_bin generate-schema -p sbproxy-config --bin generate-schema
})"
assert_equal 'cargo fallback' "$output" 'a missing workspace binary must use Cargo'
assert_equal 'run --quiet -p sbproxy-config --bin generate-schema' \
  "$(tail -n 1 "$cargo_log")" 'the Cargo fallback must keep its full invocation'

write_executable "$fake_bin/cargo" 'exit 23'
set +e
CARGO_TARGET_DIR="$target_dir" \
SBPROXY_PREBUILT_BINS=1 \
PATH="$fake_bin:$PATH" \
  run_workspace_bin generate-schema -p sbproxy-config --bin generate-schema \
  >/dev/null 2>&1
status=$?
set -e
assert_equal '23' "$status" 'a failed Cargo fallback must fail the check'

printf 'PASS: workspace binaries are preferred and Cargo remains fail-closed\n'
