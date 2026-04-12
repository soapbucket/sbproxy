# SBproxy E2E Test Suite

End-to-end tests that exercise every OSS feature of sbproxy using curl against a running proxy instance with local mock backends.

## Quick Start

```bash
# Run all 71 test cases
./e2e/run-tests.sh

# Run specific tests by number
./e2e/run-tests.sh 01 02 05 37

# Run load test (direct vs proxied comparison)
./e2e/load-test.sh
```

## Prerequisites

- **Go** (to build sbproxy)
- **Node.js** (for mock backend servers)
- **curl** (for HTTP assertions)
- **jq** (for JSON body assertions)
- **python3** (for JWT token generation in auth tests)

## Directory Structure

```
e2e/
  run-tests.sh              # Main test orchestrator
  load-test.sh              # Performance comparison tool
  generate-certs.sh         # TLS certificate generator
  servers/
    test-server.js           # Echo/callback/auth mock server
    mock-ai.js               # Mock OpenAI API server
  cases/
    01-basic-proxy/sb.yml    # Test case configs (one per feature)
    ...
    71-ai-failure-modes/sb.yml
  certs/                     # Generated (gitignored)
  logs/                      # Generated (gitignored)
```

## How It Works

1. Builds sbproxy from source
2. Starts local Node.js mock servers (test-server on :18888, mock-ai on :18889)
3. For each test case: starts sbproxy with the case's `sb.yml`, runs curl assertions, stops sbproxy
4. Reports pass/fail with color-coded output

All tests use local backends only - no external network calls.

## Test Cases

### Core Proxy (01-16)

| # | Test | Features Tested |
|---|------|-----------------|
| 01 | Basic Proxy | Reverse proxy, health check, unknown host rejection |
| 02 | Authentication | API key, basic auth, bearer token, JWT (valid/expired/invalid) |
| 03 | Rate Limiting | Sliding window, rate limit headers, 429 after limit |
| 04 | IP Filtering | Whitelist/blacklist CIDR ranges |
| 05 | WAF | OWASP CRS (SQLi, XSS, path traversal), custom rules with variables |
| 06 | CEL/Lua Scripting | CEL expression policy, Lua JSON transform |
| 07 | Transforms | JSON projection, template wrapping |
| 08 | Caching | Response cache with TTL, stale-while-revalidate |
| 09 | Forwarding Rules | Path-based routing with inline origins (remote backend) |
| 10 | Load Balancer | Round-robin, health checks, response modifier |
| 11 | CORS & Security | CORS preflight, HSTS, CSP, X-Frame-Options, Referrer-Policy |
| 12 | Compression | gzip negotiation |
| 13 | Error Pages | Custom JSON error templates |
| 14 | Static & Echo | Static JSON response, echo action |
| 15 | WebSocket | WebSocket upgrade handshake |
| 16 | Header Modifiers | Request/response header set/delete |

### Security & Policies (17-24)

| # | Test | Features Tested |
|---|------|-----------------|
| 17 | CSRF | Token cookie, header validation, exempt paths |
| 18 | DDoS Protection | Flood detection, auto-block |
| 19 | Request Limiting | URL length, query string length limits |
| 20 | Allowed Methods | GET/HEAD only, 405 on POST/PUT/DELETE |
| 21 | Redirect Action | 301/302 redirects, preserve query string |
| 22 | Force SSL | HTTP to HTTPS redirect |
| 23 | Threat Protection | JSON depth, key count, string length limits |
| 24 | Bot Detection | Allow/deny list by User-Agent |

### Advanced Modifiers (25-36)

| # | Test | Features Tested |
|---|------|-----------------|
| 25 | Request Modifiers | URL rewrite, query inject, method override, body replace, Lua |
| 26 | Response Modifiers | Status override, header inject, body replace, Lua |
| 27 | Text Transforms | HTML minify, markdown to HTML, HTML to markdown |
| 28 | Validation Transforms | JSON schema, payload limit, discard |
| 29 | Callbacks | on_request/on_response to webhook server |
| 30 | Forward Auth | Delegate auth to external service, trust headers |
| 31 | Digest Auth | HTTP Digest with HA1 hash, challenge-response |
| 32 | Session | Session cookie set/accepted |
| 33 | Fallback Origin | Fallback on backend error (static fallback) |
| 34 | Noop & Mock | No-op and mock action handlers |
| 35 | Replace Strings | Find/replace in response body |
| 36 | Response Assertion | CEL assertion on response |

### AI Gateway (37-46)

| # | Test | Features Tested |
|---|------|-----------------|
| 37 | AI Basic | Chat completions, model listing, default model |
| 38 | AI Streaming | SSE streaming with data chunks and [DONE] terminator |
| 39 | AI Multi-Provider | Round-robin routing across providers |
| 40 | AI Failover | Primary fails, fallback succeeds |
| 41 | AI Model Mapping | Model name remapping (custom-model -> gpt-4o-mini) |
| 42 | AI Model Filtering | Allowed/blocked model lists |
| 43 | AI Input Guardrails | Regex deny, secrets detection, prompt injection, jailbreak |
| 44 | AI Output Guardrails | Regex flagging on responses |
| 45 | AI Budget | Token limit enforcement |
| 46 | AI Error Handling | Upstream 500/429, invalid JSON, recovery |

### CEL Expressions (47-49, 55)

| # | Test | Features Tested |
|---|------|-----------------|
| 47 | CEL Policies | Header, path, method, query, combined expressions |
| 48 | CEL Callbacks | Conditional callback execution via CEL |
| 49 | CEL AI Routing | CEL in AI provider routing |
| 55 | CEL Advanced | Multi-assertion chains, content-type enforcement |

### Lua Scripting (50-54, 56)

| # | Test | Features Tested |
|---|------|-----------------|
| 50 | Lua Request Modifiers | Header injection, conditional logic, method/path access |
| 51 | Lua Response Modifiers | Response header injection, status code access |
| 52 | Lua JSON Transforms | Field add/rename/remove, computed fields |
| 53 | Lua Callbacks | Lua in on_request callbacks |
| 54 | Lua WAF Rules | Custom WAF rules with Lua matching |
| 56 | Lua Advanced | Full chain: request mod + response mod + JSON transform |

### Variables & Config (57-64)

| # | Test | Features Tested |
|---|------|-----------------|
| 57 | Template Variables | {{request.id}}, {{vars.key}}, {{request.method}} |
| 58 | Env Variables | ${ENV_VAR} interpolation in config |
| 59 | Feature Flags | X-Sb-Flags header, query param flags, no-cache |
| 60 | Cache Headers | Response cache, X-Cache MISS/HIT |
| 61 | HTTP/2 | h2c upgrade, HTTP/1.1 fallback |
| 62 | Variables in Modifiers | {{vars.*}} in request headers and error pages |
| 63 | Forward Rules (Local) | Path routing with inline origins, static, redirect |
| 64 | Transform Chain | Sequential replace_strings transforms |

### Failure Modes (65-71)

| # | Test | Features Tested |
|---|------|-----------------|
| 65 | WAF Fail Open/Closed | fail_open: true vs false behavior |
| 66 | Callback on_error | on_error: fail/warn/ignore with dead endpoint |
| 67 | Transform fail_on_error | fail_on_error: true vs false on schema mismatch |
| 68 | Fallback Triggers | on_error (dead backend), on_status (503 trigger) |
| 69 | Circuit Breaker | Healthy/dead targets, circuit open recovery |
| 70 | Forward Auth Failure | Dead auth service returns 503 |
| 71 | AI Failure Modes | failure_mode: open vs closed |

## Writing New Tests

1. Create a new directory: `cases/NN-feature-name/`
2. Add `sb.yml` with proxy config (use `http://127.0.0.1:18888` as backend)
3. Add a `run_NN_feature_name()` function in `run-tests.sh`
4. Use assertion helpers: `assert_status`, `assert_header`, `assert_body_contains`, `assert_body_json_field`

## Mock Servers

### test-server.js (port 18888)

General-purpose echo/callback server:
- `GET /echo` - Echo request details as JSON
- `GET /health` - Health check (200)
- `POST /callback/*` - Record webhook callbacks
- `GET /requests` - List recorded callbacks
- `GET /auth/forward` - Forward auth (200 if X-Auth-Token: valid-token)
- `GET /status/:code` - Return specified HTTP status
- `GET /delay/:ms` - Delayed response
- `GET /html` - Sample HTML page
- `GET /markdown` - Sample Markdown
- `GET /fail` - Always 502 (for fallback tests)
- `*` - Default echo for any path

### mock-ai.js (port 18889)

Mock OpenAI-compatible API:
- `POST /v1/chat/completions` - Chat completions (streaming + non-streaming)
- `GET /v1/models` - List models
- `POST /v1/embeddings` - Text embeddings
- Special models: `error-model` (500), `rate-limited` (429), `timeout-model` (10s delay)
