#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET="$ROOT/.github/actions/rust-setup/reclaim-disk.sh"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sbproxy-runner-disk-test.XXXXXX")"
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

fake_bin="$TEST_DIR/bin"
mkdir -p "$fake_bin"

# The single quotes preserve variables for the fake commands.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [ "${1:-}" = "-h" ]; then' \
  '  printf "Filesystem Size Used Avail Capacity Mounted on\n/dev/test 100G 1G 99G 1%% /\n"' \
  '  exit 0' \
  'fi' \
  'if [ "${FAKE_DF_FAIL:-0}" = "1" ]; then exit 17; fi' \
  'printf "Filesystem 1024-blocks Used Available Capacity Mounted on\n"' \
  'if [ -n "${FAKE_DF_AVAILABLE_KIB:-}" ]; then' \
  '  printf "/dev/test 100000000 1 %s 1%% /\n" "$FAKE_DF_AVAILABLE_KIB"' \
  'fi' >"$fake_bin/df"
chmod +x "$fake_bin/df"

# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" "$*" >>"$SBPROXY_TEST_SUDO_LOG"' >"$fake_bin/sudo"
chmod +x "$fake_bin/sudo"

expected_cleanup='rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc /usr/local/.ghcup
docker image prune --all --force'

run_case() {
  local label="$1" available="$2" df_fails="$3" expect_cleanup="$4"
  local sudo_log="$TEST_DIR/$label.sudo.log"
  local output="$TEST_DIR/$label.output"
  : >"$sudo_log"

  FAKE_DF_AVAILABLE_KIB="$available" \
  FAKE_DF_FAIL="$df_fails" \
  SBPROXY_TEST_SUDO_LOG="$sudo_log" \
  PATH="$fake_bin:$PATH" \
    bash "$TARGET" >"$output"

  if [ "$expect_cleanup" = 'yes' ]; then
    assert_equal "$expected_cleanup" "$(cat "$sudo_log")" \
      "$label must use the literal cleanup allowlist once"
  elif [ -s "$sudo_log" ]; then
    fail "$label reclaimed disk above the floor"
  fi
}

# The floor is 40 GiB expressed in the KiB units returned by df -Pk.
floor_kib=41943040
run_case above-floor "$((floor_kib + 1))" 0 no
run_case high-space 104857600 0 no
run_case below-floor "$((floor_kib - 1))" 0 yes
run_case at-floor "$floor_kib" 0 yes
run_case empty-measurement '' 0 yes
run_case nonnumeric-measurement 'unknown' 0 yes
run_case failed-measurement '' 1 yes

printf 'PASS: runner disk cleanup is thresholded and fails closed\n'
