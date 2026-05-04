# sbproxy-e2e
*Last modified: 2026-04-27*

End-to-end integration tests for the OSS sbproxy binary. The crate
ships a small `ProxyHarness` library plus per-feature integration
test files. Each test spawns the release `sbproxy` binary against a
temporary YAML config on an ephemeral port, exercises documented
HTTP behaviour via reqwest, and tears the child down on Drop.

## Prerequisites

```bash
cargo build --release -p sbproxy
```

## Run the suite

```bash
cargo test --release -p sbproxy-e2e
```

Each test owns its own ephemeral TCP port, so the suite parallelises
cleanly. There are no shared fixtures.

## What is covered

| Test file | Scenario |
|-----------|----------|
| `tests/admin_endpoints.rs` | Admin server bind, basic-auth gate, `/api/health`, `/api/openapi.json` |
| `tests/cors.rs` | Preflight against allowlisted origin; unlisted origin not echoed |
| `tests/openapi_emission.rs` | `/.well-known/openapi.{json,yaml}` and parameter round-trip |
| `tests/pii_redaction.rs` | Email + credit card + Anthropic key shapes are redacted before forwarding |
| `tests/rate_limiting.rs` | Token-bucket burst yields 429 with `Retry-After` |
| `tests/static_action.rs` | Configured static body + 404 for unknown host |
| `tests/storage_action.rs` | object_store backend serves index, content-type, range, and 404s |

## ProxyHarness API

```rust
use sbproxy_e2e::{ProxyHarness, MockUpstream};

// Spawn the binary against an inline YAML config; the harness picks
// an ephemeral port and rewrites proxy.http_bind_port.
let harness = ProxyHarness::start_with_yaml(yaml)?;

// Issue requests with a Host header.
let resp = harness.get("/path", "host.local")?;
assert_eq!(resp.status, 200);

// Captured upstream for assertions on what the proxy forwarded.
let upstream = MockUpstream::start(serde_json::json!({"ok": true}))?;
// Point the proxy's upstream at upstream.base_url(), then inspect
// upstream.captured() after the test exercises the config.
```

## Vendored case fixtures

The `cases/` directory holds the small set of `sb.yml` fixtures
that lower-level Rust unit tests load directly. They are vendored
(not symlinked) so the suite stays self-contained:

- `cases/09-forwarding-rules/sb.yml` - loaded by
  `sbproxy-core::pipeline::load_case09_forward_rules`
- `cases/25-request-modifiers-advanced/sb.yml` - loaded by
  `sbproxy-config::types::parse_case25_request_modifiers_yaml`
- `cases/26-response-modifiers-advanced/sb.yml` - loaded by
  `sbproxy-config::types::parse_case26_response_modifiers_yaml`

If a new lower-level test needs a case from the upstream Go suite:

1. Copy only the `sb.yml` from
   `github.com/soapbucket/sbproxy/e2e/cases/<case>/`.
2. Keep the directory name identical so path references resolve.
3. Do not copy the Go-only assets (server binaries, traces, assertion
   scripts) - those are out of scope for the Rust suite.

The end-to-end harness above does **not** use these fixtures - each
integration test inlines its own config.
