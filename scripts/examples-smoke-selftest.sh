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
url=""
request_body=""
request_body_set=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --data-binary)
      [ "$#" -ge 2 ] || {
        echo "missing --data-binary value" >&2
        exit 1
      }
      request_body="$2"
      request_body_set=1
      shift 2
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done
case "$url" in
  */healthz)
    exit 0
    ;;
  */json)
    [ "$request_body_set" -eq 1 ] || {
      echo "missing serialized request body" >&2
      exit 1
    }
    [ "$request_body" = '{"message":"hello"}' ] || {
      echo "incorrect serialized request body: $request_body" >&2
      exit 1
    }
    printf 'HTTP/1.1 201 Created\r\nx-smoke-token: abc-123\r\ncontent-type: application/json\r\n\r\n{"ok":true,"nested":{"count":3},"extra":"kept"}'
    exit 0
    ;;
  */nested)
    # Asserts the exact compact serialization of a nested object, then
    # echoes it back so the jsonShape expectation proves the round trip.
    [ "$request_body_set" -eq 1 ] || {
      echo "missing serialized nested body" >&2
      exit 1
    }
    [ "$request_body" = '{"outer":{"flag":true,"list":[1,2,3],"text":"hello"},"note":"kept"}' ] || {
      echo "nested body was altered in flight: $request_body" >&2
      exit 1
    }
    printf 'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n%s' "$request_body"
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
        },
        "body": {"message": "hello"}
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

test_nested_json_body_reaches_fixture_unchanged() {
  local tmp fake_bin output
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  make_fake_bin_dir "$fake_bin"
  mkdir -p "$tmp/examples/97-nested-body"
  cat > "$tmp/examples/97-nested-body/docker-compose.yml" <<'YAML'
services:
  proxy:
    image: example/proxy
    ports:
      - "18080:8080"
YAML
  cat > "$tmp/examples/97-nested-body/smoke.json" <<'JSON'
{
  "admin_port": 18080,
  "data_plane_port": 18080,
  "health_path": "/healthz",
  "cases": [
    {
      "name": "nested json body",
      "request": {
        "method": "POST",
        "path": "/nested",
        "headers": {
          "Host": "example.localhost",
          "Content-Type": "application/json"
        },
        "body": {"outer": {"flag": true, "list": [1, 2, 3], "text": "hello"}, "note": "kept"}
      },
      "expect": {
        "status": 200,
        "body": {
          "type": "jsonShape",
          "shape": {
            "outer": {
              "flag": true,
              "list": [1, 2, 3],
              "text": "hello"
            },
            "note": "kept"
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
    "$SCRIPT" "$tmp/examples/97-nested-body" 2>&1
  )"

  grep -q "case 'nested json body' -> 200 OK" <<<"$output" || fail "nested body case did not pass: $output"
  grep -q "summary: 1 passed, 0 failed" <<<"$output" || fail "runner did not report success: $output"
}

test_non_serializable_body_fails_before_curl() {
  local tmp fake_bin output status
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  make_fake_bin_dir "$fake_bin"
  mkdir -p "$tmp/examples/96-bad-body"
  cat > "$tmp/examples/96-bad-body/docker-compose.yml" <<'YAML'
services:
  proxy:
    image: example/proxy
    ports:
      - "18080:8080"
YAML
  # 1e1000 is a valid JSON number literal that Python's json.load parses
  # as Infinity. json.dumps(..., allow_nan=False) must reject it before
  # any curl runs, instead of sending the invalid literal upstream.
  cat > "$tmp/examples/96-bad-body/smoke.json" <<'JSON'
{
  "admin_port": 18080,
  "data_plane_port": 18080,
  "health_path": "/healthz",
  "cases": [
    {
      "name": "non-serializable body",
      "request": {
        "method": "POST",
        "path": "/never-reached",
        "headers": {
          "Host": "example.localhost"
        },
        "body": {"ratio": 1e1000}
      },
      "expect": {
        "status": 200
      }
    }
  ]
}
JSON

  set +e
  output="$(
    PATH="$fake_bin:$PATH" \
    COMPOSE_BIN="$fake_bin/fake-compose" \
    "$SCRIPT" "$tmp/examples/96-bad-body" 2>&1
  )"
  status=$?
  set -e

  [ "$status" -ne 0 ] || fail "non-serializable body unexpectedly passed"
  grep -q "request.body must be JSON-serializable" <<<"$output" || fail "encoder guard did not fire: $output"
  # The fake curl answers /never-reached with a 404, so a status
  # mismatch in the output would mean curl ran despite the bad body.
  if grep -q "returned 404" <<<"$output"; then
    fail "curl ran despite non-serializable body: $output"
  fi
}

case "${1:-all}" in
  missing-smoke) test_missing_smoke_manifest_fails ;;
  cases) test_cases_assert_status_headers_and_json_shape ;;
  nested-body) test_nested_json_body_reaches_fixture_unchanged ;;
  non-serializable) test_non_serializable_body_fails_before_curl ;;
  all)
    test_missing_smoke_manifest_fails
    test_cases_assert_status_headers_and_json_shape
    test_nested_json_body_reaches_fixture_unchanged
    test_non_serializable_body_fails_before_curl
    ;;
  *)
    fail "unknown test selector: $1"
    ;;
esac
