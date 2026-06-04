# sbproxy-e2e
*Last modified: 2026-06-04*

End-to-end integration tests for the OSS sbproxy binary. The crate
ships a small `ProxyHarness` library plus per-feature integration
test files. Each test spawns the release `sbproxy` binary against a
temporary YAML config on an ephemeral port, exercises documented
HTTP behaviour via reqwest, and tears the child down on Drop.

## Prerequisites

```bash
cargo build --release -p sbproxy
```

The e2e suite spawns `target/release/sbproxy` directly; rebuild
after any code change or the suite silently runs stale code.

## Run the suite

```bash
cargo test --release -p sbproxy-e2e
```

Each test owns its own ephemeral TCP port, so the suite parallelises
cleanly. There are no shared fixtures. Run a single test file:

```bash
cargo test --release -p sbproxy-e2e --test rate_limiting_e2e
```

Force serial execution (handy when a known parallel-build CPU spike
false-fails a sidecar-shutdown test):

```bash
cargo test --release -p sbproxy-e2e -- --test-threads=1
```

The required CI gate covers the OSS workspace's unit + lib tests;
e2e runs occasionally and locally, not on every PR.

## What is covered

135 test files grouped by feature family. Run
`ls tests/ | grep <prefix>` for the full list inside a family.

| Family | Tests | Example scenarios |
|---|---|---|
| AI gateway (`ai_*`) | 16 | Provider routing, fallback / cascade / cost-optimized / lowest-latency, streaming, virtual keys, guardrails, budgets, context relay, model rate limits, OpenAI / Anthropic / Bedrock / Gemini direct |
| AI surface matrix (`matrix_*`) | 2 | Every (provider × surface) cell from `provider_supports_surface` returns the expected pass / 501 verdict end-to-end |
| Policies (`policy_*` + named) | 13 | CEL expression, WAF + OWASP CRS, CSRF, IP filter, content-shape, accept_payment + AP2, exposed_credentials, openapi_validation, object_authz BOLA / BFLA, content_digest, agent_budget, semantic_constraint |
| Auth (`auth_*` + `api_key_*`, `basic_auth_*`, `bearer_*`, `jwt_*`, `oidc_*`, `forward_auth_*`, `dpop_*`, `bot_auth_*`) | 12 | API key, basic, bearer (+ DPoP-bound + mTLS-bound), JWT (JWKS + introspection), forward_auth subrequest, OIDC RP login + session cookie, Web Bot Auth signed-request verification + key-directory refresh |
| Transforms (`transform_*`) | 5 | HTML, Markdown, JSON projection, Lua, JavaScript (QuickJS), WASM (wasmtime + WASI preview-1) |
| Rate limiting + concurrency (`rate_*`, `concurrent_*`) | 3 | Token-bucket burst → 429 + Retry-After; per-key CEL bucketing; concurrent-limit cap |
| Caching (`cache_*`, `semantic_cache_*`) | 3 | Response cache hit / miss / stale / bypass; semantic cache vector similarity hit |
| Compression + content negotiation (`compress_*`, `content_*`) | 5 | brotli + gzip + zstd algorithm selection; content-shape negotiation per `Accept` |
| Load balancing + circuit breaker (`load_balancer_*`, `circuit_*`, `health_*`) | 3 | Round-robin + weighted + fallback chain; active health probes; circuit-breaker open / half-open / closed |
| MCP (`mcp_*`) | 4 | Initialize handshake, tools/list + tools/call, federation discovery, schema-drift detection |
| A2A (`a2a_*`) | 1 | Agent card discovery + skill invocation |
| Agent detect + budget (`agent_*`) | 5 | ADRF rule-pack identification (claude-cli, codex, cursor), trust-tier classification, per-agent budget |
| Web Bot Auth (`web_*`) | 3 | RFC 9421 verify, publish key directory, signature-agent header resolution |
| TLS (`tls_*`) | 3 | TLS fingerprint extraction, mTLS client cert binding, certificate expiry probe |
| Idempotency (`idempotency_*`) | 3 | Replay protection on `Idempotency-Key`; nonce store hits |
| gRPC (`grpc_*`) | 3 | grpc + grpc-web; transcode REST → gRPC; status mapping |
| Robots Service License (`rsl_*`) | 3 | `/.well-known/rsl.xml` projection; per-route license stance; content-hash binding |
| OpenAPI emission + validation (`openapi_*`) | 2 | `/.well-known/openapi.{json,yaml}` round-trip; openapi_validation policy gates request body |
| Bulk redirects (`bulk_*`) | 2 | O(1) path-keyed lookup; row-list compilation at config load |
| Prompt injection v2 (`prompt_*`) | 2 | Heuristic detector default; sidecar detector via UDS or TCP |
| Virtual keys / credentials (`virtual_key_*`, `credentials_*`) | 4 | Per-team budget + allow-list; credentials block lowering. Two assertions in `virtual_key_*` carry `#[ignore]` pending WOR-1110 + WOR-1111. |
| Sessions (`session*`) | 1 | Encrypted cookie issue + verify + rotate |
| Object authz (`object_authz_*`) | 1 | BOLA + BFLA enforcement + tenant isolation |
| Listings (`listing_*`) | 1 | Listing primitive: schema + loader + three pinning modes |
| AI crawl / 402 (`crawl_*`, `pricing_*`) | 2 | `ai_crawl_control` + peer_pricing_preflight |
| Storage + static actions | 2 | object_store backend (S3, GCS, Azure, local FS); static action body |
| Observability / access log / audit | 2 | Access-log JSON emission + filter / sample; admin-mutation audit envelope |
| Scripting (`cel*`, `lua*`, `js*`, `wasm*` non-transform) | 2 | CEL helpers under `request.*`; Lua + JS sandbox limits |
| Webhooks (`webhook_*`) | 1 | HMAC-signed `on_request` / `on_response` envelope round-trip |
| Trusted proxies + client IP (`trusted_*`) | 1 | Post-trust-boundary client IP resolution from X-Forwarded-For |
| Variables + templating (`variables_*`) | 1 | `{{ variables.<name> }}` substitution + env-var interpolation |
| Upstream retries + connect (`upstream_*`) | 1 | DNS failure, refused, unreachable, TLS handshake fail → retry behaviour |
| HTTP basics (`http_*`, `proxy_*`) | 4 | HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket upgrade |
| Headers (`header_*`) | 1 | Vary, Cache-Control + secret-redaction passthrough |
| Admin (`admin_*`) | 2 | Admin server bind + basic-auth + `/api/*` + `/admin/reload` |
| Misc cross-cutting | rest | Plug-in registry, classifier sidecar lifecycle, sidecar transport, ledger + 402, vault backend, well-known projections |

Total: 135 files × multiple test functions = ~580 assertions. 5
tests carry `#[ignore]`: the three `virtual_key_*` runtime assertions
pending WOR-1110 + WOR-1111, plus two pre-existing
network-bound-flake quarantined tests in the classifier suite.

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
