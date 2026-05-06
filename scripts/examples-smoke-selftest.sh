#!/usr/bin/env bash
# Self-tests for scripts/examples-smoke.sh. These use fake compose/curl
# binaries so the runner contract is covered without starting containers.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/examples-smoke.sh"

fail() {
  echo "examples-smoke-selftest: $*" >&2
  exit 1
}

make_fake_bin_dir() {
  local dir="$1"
  mkdir -p "$dir"

  cat > "$dir/fake-compose" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  up|down) exit 0 ;;
  *) exit 0 ;;
esac
SH
  chmod +x "$dir/fake-compose"

  cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
url="${*: -1}"
case "$url" in
  */healthz)
    exit 0
    ;;
  */json)
    printf 'HTTP/1.1 201 Created\r\nx-smoke-token: abc-123\r\ncontent-type: application/json\r\n\r\n{"ok":true,"nested":{"count":3},"extra":"kept"}'
    exit 0
    ;;
  *)
    printf 'HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n\r\n{"error":"not found"}'
    exit 0
    ;;
esac
SH
  chmod +x "$dir/curl"
}

test_missing_smoke_manifest_fails() {
  local tmp fake_bin output status
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  make_fake_bin_dir "$fake_bin"
  mkdir -p "$tmp/examples/99-missing-smoke"
  cat > "$tmp/examples/99-missing-smoke/docker-compose.yml" <<'YAML'
services:
  proxy:
    image: example/proxy
    ports:
      - "18080:8080"
YAML

  set +e
  output="$(
    PATH="$fake_bin:$PATH" \
    COMPOSE_BIN="$fake_bin/fake-compose" \
    "$SCRIPT" "$tmp/examples/99-missing-smoke" 2>&1
  )"
  status=$?
  set -e

  [ "$status" -ne 0 ] || fail "missing smoke.json unexpectedly passed"
  grep -q "missing smoke.json" <<<"$output" || fail "missing-smoke output did not explain failure: $output"
}

test_cases_assert_status_headers_and_json_shape() {
  local tmp fake_bin output
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  make_fake_bin_dir "$fake_bin"
  mkdir -p "$tmp/examples/98-with-cases"
  cat > "$tmp/examples/98-with-cases/docker-compose.yml" <<'YAML'
services:
  proxy:
    image: example/proxy
    ports:
      - "18080:8080"
YAML
  cat > "$tmp/examples/98-with-cases/smoke.json" <<'JSON'
{
  "admin_port": 18080,
  "data_plane_port": 18080,
  "health_path": "/healthz",
  "cases": [
    {
      "name": "created json response",
      "request": {
        "method": "GET",
        "path": "/json",
        "headers": {
          "Host": "example.localhost"
        }
      },
      "expect": {
        "status": 201,
        "headers": {
          "x-smoke-token": "^abc-[0-9]+$"
        },
        "body": {
          "type": "jsonShape",
          "shape": {
            "ok": true,
            "nested": {
              "count": 3
            }
          }
        }
      }
    }
  ]
}
JSON

  output="$(
    PATH="$fake_bin:$PATH" \
    COMPOSE_BIN="$fake_bin/fake-compose" \
    "$SCRIPT" "$tmp/examples/98-with-cases" 2>&1
  )"

  grep -q "case 'created json response' -> 201 OK" <<<"$output" || fail "case assertion did not run: $output"
  grep -q "summary: 1 passed, 0 failed" <<<"$output" || fail "runner did not report success: $output"
}

case "${1:-all}" in
  missing-smoke) test_missing_smoke_manifest_fails ;;
  cases) test_cases_assert_status_headers_and_json_shape ;;
  all)
    test_missing_smoke_manifest_fails
    test_cases_assert_status_headers_and_json_shape
    ;;
  *)
    fail "unknown test selector: $1"
    ;;
esac
