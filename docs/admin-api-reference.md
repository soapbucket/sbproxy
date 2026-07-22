# Admin API reference

*Last modified: 2026-07-21*

The embedded admin server publishes the full control-plane HTTP surface for
operator tooling: liveness probes, session login, key and credential
lifecycle, the request log and its live stream, recent sessions, alert
operations, per-target health, spend and audit, config read/write and hot reload/drift, model-host catalog and
deployment lifecycle, the response/semantic/key-policy caches, cluster
status and the replicated-state substrate, prompts, the chat playground, and
the emitted OpenAPI document.

This page is the per-route reference: every path, its auth/role
requirement, request and response shape, and status codes. For a
task-oriented walkthrough (enabling the server, logging in, a curl
cookbook), see [admin-api-guide.md](admin-api-guide.md). For the
built-in dashboard over this same API, see [admin-ui.md](admin-ui.md).

## Contents

- [Enabling the admin server](#enabling-the-admin-server)
- [Authentication](#authentication)
- [Rate limiting](#rate-limiting)
- [Error envelope](#error-envelope)
- [Probe routes](#probe-routes-unauthenticated) (unauthenticated)
- [Session routes](#session-routes) - login, logout, whoami
- [API keys and credentials](#api-keys-and-credentials) - full virtual-key and upstream-credential lifecycle
- [Read routes](#read-routes-authenticated) - request log + stream, alerts, health, spend, audit, rate-limit budget, UI settings, OpenAPI
- [AI compression session state](#ai-compression-session-state)
- [Config and control routes](#config-and-control-routes-authenticated) - reload, drift, config read/write, log level
- [Model host admin](#model-host-admin) - catalog, deployments, lifecycle, artifact cache
- [Cache admin](#cache-admin) - response cache and key-policy cache
- [Cluster control plane](#cluster-control-plane) - status, deployments, enrollment, replicated state
- [Admin UI](#admin-ui-get-adminui-get-) - static asset serving
- [Prompt store admin](#prompt-store-admin-get-adminprompts-post-adminprompts) - prompt overlay
- [Chat playground](#chat-playground)
- [Curl recipes](#curl-recipes)

## Enabling the admin server

```yaml
proxy:
  admin:
    enabled: true
    port: 9090
    username: admin
    password: ${ADMIN_PASSWORD}
    max_log_entries: 1000
```

The password resolves from the environment at config load
(`export ADMIN_PASSWORD=...` before starting the proxy). YAML tags
like `!env` are not a supported form and are rejected at compile.

When `enabled: false` (the default) the admin listener does not bind
and every route below is unreachable. The server binds on
`127.0.0.1:<port>` so the admin surface is loopback-only by default;
expose it via a reverse proxy or sidecar with an IP allowlist when an
operator console needs remote access.

## Authentication

Routes split into two tiers:

- **Unauthenticated utility routes** are reachable without credentials so
  load balancers and orchestrators can probe liveness without
  configuring secrets: `/healthz`, `/health`, `/readyz`, `/ready`,
  `/livez`, `/live`, and `/.well-known/sbproxy/quote-keys.json`. The login,
  logout, and session-discovery routes also run before the general auth gate;
  they establish, revoke, or describe a browser session rather than exposing
  protected control-plane data.

- **Protected routes** accept HTTP Basic auth using the configured top-level
  identity, or the signed browser session created by `POST /admin/login`.
  Configured operator credentials are accepted by login and then use the
  session cookie; they are not accepted directly as HTTP Basic credentials on
  protected routes. The top-level identity has the `admin` role; configured
  operators may have `admin` or `read_only`. The one-time-token exchange at
  `POST /admin/cluster/enroll` is a separate documented exception.

Send credentials with `curl -u admin:secret <url>` or an
`Authorization: Basic <base64(user:pass)>` header.

Protected state-changing routes require the `admin` role. When authentication
came from the browser session cookie, the request must also echo the CSRF token
returned at login in the `X-CSRF-Token` header. HTTP Basic requests are
CSRF-exempt. Login, logout, session discovery, and enrollment have their own
route-specific rules. Individual read routes may impose a stricter role, as
the compression-content route does.

## Rate limiting

The admin server enforces an in-process rate limit with both per-IP
and global caps. The per-IP cap is 240 requests / minute by default;
the global cap is 10x that (2400 / minute). A request that exceeds
either cap returns `429` and is not counted against future windows.
The per-IP tracking map is capped at 10000 entries to prevent
unique-IP floods from growing memory.

## Error envelope

All authenticated routes return JSON errors as:

```json
{"error":"<reason>"}
```

Status codes follow conventional HTTP: `401` for missing or invalid
credentials, `403` for an insufficient role or failed session CSRF check,
`405` for wrong method on a method-gated route, `409` when a hot reload is
already in flight, `429` when rate-limited, and `5xx` for server-side failures.

---

## Probe routes (unauthenticated)

### `GET /healthz`

Kubernetes-style liveness probe. Returns `200` with body
`{"status":"ok"}` whenever the process is up. Does **not** consult
the live config or any dependency; treat it as "the process is
running and the listener accepted my connection".

### `GET /health`

Component-aware health report with version and build metadata.
Returns `200` with top-level `"status": "ok"` when every check is
ready, `503` with `"status": "unready"` otherwise:

```json
{
  "status": "ok",
  "version": "1.5.0",
  "build_hash": "abc1234",
  "timestamp": "2026-07-09T10:15:32Z",
  "uptime_seconds": 86400,
  "checks": [
    {"name": "ledger", "status": "healthy"},
    {"name": "bot_auth_directory", "status": "not_configured"}
  ]
}
```

Each entry in `checks` carries a `name`, a `status`, and an optional
`detail` string. Statuses are `healthy`, `degraded`, `unhealthy`, and
`not_configured`. A `degraded` or `not_configured` check still counts
as ready, so the route keeps returning `200`; an `unhealthy` check
flips the top-level status to `unready` and the response to `503`.

### `GET /readyz`, `GET /ready`

Kubernetes-style readiness probe. Returns `200` once all required
components are ready to serve traffic, `503` while any required
component is still initialising or has failed. K8s polls this to
gate traffic shifting during rolling restarts.

### `GET /livez`, `GET /live`

Bare liveness probe. Like `/healthz` but with a different name for
load balancers that hardcode this path.

### `GET /.well-known/sbproxy/quote-keys.json`

JWKS document publishing every Ed25519 public key the live config
uses to sign Wave 3 quote tokens (the `402 Payment Required` flow's
agent-verifiable payment quotes). External verifiers (ledger
clients, agent SDKs) fetch this to verify a quote without contacting
the issuer.

Response:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "<key-id>",
      "x": "<base64url public key>"
    }
  ]
}
```

Served unauthenticated because the keys themselves are public. The
document aggregates keys across every `ai_crawl_control` policy so a
multi-tenant deployment publishes one document for all of its
issuers.

---

## Session routes

`POST /admin/login`, `POST /admin/logout`, and `GET /admin/session` run
before the general auth gate: they establish, revoke, or describe a
browser session rather than exposing protected control-plane data. See
[admin-api-guide.md](admin-api-guide.md#authenticating-basic-vs-session--csrf)
for the full login/CSRF walkthrough.

### `POST /admin/login`

Verifies credentials — an `Authorization: Basic` header, or a JSON
`{"username": "...", "password": "..."}` body — against the top-level
admin or a configured `operators[]` entry.

Success (`200`) sets `Set-Cookie: sb_admin_session=<token>; HttpOnly;
SameSite=Strict; Path=/` (adds `; Secure` when TLS is on), good for 8
hours, and returns:

```json
{"role": "admin", "csrf_token": "3f9c1a...", "username": "admin"}
```

`400` for a missing/unparseable body, `401` for invalid credentials
(emits an `sbproxy::admin::audit` failure event).

### `POST /admin/logout`

Revokes the session and clears the cookie. Always `200`. Does not
require an `X-CSRF-Token` header (it is one of the route-specific CSRF
exceptions, alongside login and session discovery).

### `GET /admin/session`

Reports whether the request carries a valid session, without ever
returning `401` — it distinguishes "please log in" from an error so
the UI can render a login form on a fresh visit:

```json
{"authenticated": true, "username": "admin", "role": "admin", "via_session": true, "csrf_token": "3f9c1a..."}
```

or `{"authenticated": false}`. `via_session` is `false` for a request
authenticated by HTTP Basic (a Basic caller is "authenticated" here
too, so a Basic-authenticated browser session can still recover a
usable CSRF token: the server mints and `Set-Cookie`s a session token
automatically on a Basic-authenticated request that lacks one — the
Basic-to-session upgrade — but the RBAC/CSRF gate still treats
`via_session: false` requests as CSRF-exempt).

---

## API keys and credentials

Full CRUD-plus-lifecycle over dynamic virtual keys and upstream
provider credentials. Mounted on the shared admin listener; every
mutation writes through the configured keystore and invalidates the
policy cache so it takes effect on the next request without a reload.
Responses never carry a secret hash or plaintext, except the one-time
minted/rotated token. See [key-management.md](key-management.md) for
the policy model these records drive.

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/keys` | List keys (no secrets). |
| POST | `/admin/keys` | Mint a key; the plaintext token is returned once. |
| GET | `/admin/keys/policy-schema` | The server-driven policy field contract the UI renders forms from. |
| GET | `/admin/keys/{id}` | Fetch one key. |
| PATCH | `/admin/keys/{id}` | Update policy/attribution fields (optimistic concurrency via `expected_revision`). |
| DELETE | `/admin/keys/{id}` | Delete a key. |
| GET | `/admin/keys/{id}/usage` | Governed usage snapshot (requests/tokens/budget counters) and backend health. |
| POST | `/admin/keys/{id}/effective-policy/preview` | Evaluate the key's effective policy against a hypothetical request, without dispatching one. |
| POST | `/admin/keys/{id}/revoke` | Mark revoked (terminal — no further mutation). |
| POST | `/admin/keys/{id}/block` | Mark blocked (reversible). |
| POST | `/admin/keys/{id}/unblock` | Mark active. |
| POST | `/admin/keys/{id}/rotate` | Mint a new secret with a grace-window dual-key transition. |
| GET | `/admin/credentials` | List upstream credentials (no secrets). |
| POST | `/admin/credentials` | Create a credential (`vault_ref` or `secret`, envelope-sealed at rest). |
| GET | `/admin/credentials/{id}` | Fetch one credential. |
| PATCH | `/admin/credentials/{id}` | Update credential metadata, provider, or material. |
| DELETE | `/admin/credentials/{id}` | Delete a credential. |
| POST | `/admin/credentials/{id}/revoke`, `/block`, `/unblock` | Same lifecycle actions as keys. |

All of these return `409 {"error":"key_management is not enabled"}`
when the process has no dynamic key plane configured (no `keystore:`
backend wired). List/get failures against the store are `500`; a
missing key/credential id is `404`.

### Key record shape (`KeyView`)

`GET`/`POST`/`PATCH` responses wrap a `KeyView` under `"key"`:

```json
{
  "key_id": "key_9f2c...",
  "policy_revision": 3,
  "policy_digest": "sha256:...",
  "name": "checkout-service",
  "status": "active",
  "max_requests_per_minute": 600,
  "max_tokens_per_minute": null,
  "priority": null,
  "budget": {"max_tokens": null, "max_cost_usd": 25.0},
  "allowed_models": ["gpt-4o-mini", "claude-haiku-4-5"],
  "blocked_models": [],
  "allowed_providers": [],
  "blocked_providers": [],
  "allowed_tools": null,
  "require_pii_redaction": [],
  "principal_selectors": [],
  "inject_tools": [],
  "bypass_prompt_injection": false,
  "project": null,
  "user": null,
  "tags": ["team:checkout"],
  "metadata": {},
  "tenant_id": null,
  "expires_at": null,
  "created_at": "2026-07-01T00:00:00Z",
  "updated_at": "2026-07-01T00:00:00Z",
  "source": "api",
  "rotation_pending": false
}
```

`status` is `active`, `blocked`, or `revoked`. `policy_digest` is only
populated for records that own a tenant (`tenant_id` set); a tenantless
record inherits the request's origin tenant, so it has no single
runtime digest — get one per-origin from the effective-policy preview
instead. `rotation_pending` is true while a prior secret is still
valid inside its rotation grace window.

`POST /admin/keys` accepts the same policy fields as `PATCH` (name,
budgets, allow/block lists, `route_to_model`, `compression_profile`,
`inject_tools`, `inject_mcp`, `principal_selectors`, `tags`, `metadata`,
`tenant`, `expires_at`, ...) and returns `201` with
`{"token": "<plaintext, shown once>", "key": <KeyView>}`.

### Optimistic concurrency and terminal state

`PATCH`, `revoke`, `block`, `unblock`, and `rotate` all read the
record's current `policy_revision` and require the caller's
`expected_revision` to match (omit it on `block`/`unblock`/`rotate` to
default to the server-read value; `PATCH` requires it explicitly). A
mismatch returns `409`:

```json
{"error": "key policy revision conflict", "key_id": "key_9f2c...", "expected_revision": 2, "current_revision": 3}
```

A `revoked` key is terminal: any further mutation returns
`409 {"error": "revoked key is terminal", "key_id": "...", "current_revision": N}`.
A keystore backend that cannot perform an atomic compare-and-swap
returns `409 {"error": "configured key store does not support atomic key policy mutation"}`.

### `POST /admin/keys/{id}/rotate`

Body: `{"expected_revision": <optional>, "grace_secs": <optional, default 3600>}`.
Mints a fresh secret, keeps the prior hash valid for `grace_secs`
(both authenticate during the window), and returns:

```json
{"token": "sk-key_9f2c...-<new secret>", "grace_expires_at": "2026-07-01T01:00:00Z", "key": {"...": "..."}}
```

### `GET /admin/keys/{id}/usage`

Returns `{"usage": <GovernanceSnapshot>}` — the same request/token/
budget counters the AI gateway's governance seam reserves against,
read live rather than derived from the log. Returns
`503 {"error":"governance backend unavailable"}` if the governance
store (Redis, for a shared/cluster deployment) cannot be reached; the
key record itself is not at fault in that case.

### `POST /admin/keys/{id}/effective-policy/preview`

Body is an optional sample request shape (`model`, `provider`, `tools`,
`principal`, `origin_tenant_id`, `active_pii_rules`,
`prompt_injection_detected`, `usage`, `at`) — every field optional; an
empty body still returns the resolved policy. Response:

```json
{
  "effective_policy": {"...": "the full secret-free effective policy"},
  "policy_version": "...",
  "decisions": {
    "allowed": true,
    "lifecycle": {"allowed": true, "reason_code": "active", "status": "active", "expires_at": null},
    "tenant": {"allowed": true, "reason_code": "match", "origin_tenant_id": "...", "effective_tenant_id": "..."},
    "model": {"allowed": true, "reason_code": "not_sampled", "requested": null, "effective": null, "routed": false},
    "provider": {"...": "..."},
    "tools": {"...": "..."},
    "principal": {"...": "..."},
    "rate_limits": {"...": "..."},
    "budget": {"...": "..."},
    "priority": {"...": "..."},
    "guardrails": {"pii": {"...": "..."}, "prompt_injection": {"...": "..."}}
  }
}
```

Each decision block carries `allowed` plus a stable `reason_code`
(`active`, `revoked`, `blocked`, `expired`, `not_sampled`, `blocked`,
`not_allowed`, `allowed`, `match`, `mismatch`, `inherited`, ...) so the
UI can render *why* a hypothetical request would be denied without
needing a live upstream call. This never dispatches a request or
reserves budget; it is pure evaluation against the stored record.

### Credential record shape (`CredentialView`)

```json
{
  "id": "cred_a1b2...",
  "name": "openai-prod",
  "provider": "openai",
  "kind": "ai_provider",
  "status": "active",
  "tenant_id": null,
  "storage": "vault_ref",
  "vault_ref": "vault://secret/data/openai#key",
  "created_at": "2026-07-01T00:00:00Z",
  "updated_at": "2026-07-01T00:00:00Z",
  "source": "api"
}
```

`storage` is `vault_ref`, `encrypted` (envelope-sealed plaintext at
rest), or `plaintext` (legacy records only). The actual secret is
never present in any response; `vault_ref` only appears for
vault-referenced credentials, since the reference itself is not a
secret. `POST`/`PATCH` bodies accept `vault_ref` *or* `secret` (a
plaintext value the server envelope-seals immediately); supplying
neither is a `400`.

---

## Read routes (authenticated)

### `GET /api/requests`

Returns the most recent request log entries, newest first. The ring
buffer size is `proxy.admin.max_log_entries` (default `1000`).

Response body: an array of `RequestLogEntry`:

```json
[
  {
    "timestamp": "2026-05-12T10:15:32.456Z",
    "origin": "api.example.com",
    "method": "POST",
    "path": "/v1/chat/completions",
    "status": 200,
    "latency_ms": 42.7,
    "client_ip": "10.0.0.5",
    "request_id": "08ad73be-...",
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "session_id": "01K0SESSION0000000000000000",
    "parent_session_id": "01K0PARENT00000000000000000",
    "properties": {"feature": "assistant", "tier": "gold"},
    "cache_status": "miss",
    "retry_count": 1,
    "failover_engaged": true,
    "failover_from": "openai",
    "failover_to": "anthropic",
    "load_balancer_strategy": "lowest_latency",
    "load_balancer_target": "anthropic",
    "provider": "anthropic",
    "model": "claude-sonnet-4",
    "tokens_in": 315,
    "tokens_out": 82,
    "cost_usd_micros": 1840,
    "guardrail_category": "pii",
    "guardrail_action": "block"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | RFC 3339 timestamp when the request finished. |
| `origin` | string | Configured origin hostname that handled the request. |
| `method` | string | HTTP method. |
| `path` | string | Request path including query string. |
| `status` | int | Response status code. |
| `latency_ms` | float | End-to-end latency in milliseconds. |
| `client_ip` | string | Client IP as observed by the proxy. |
| `request_id`, `trace_id` | string | Correlation identifiers when available. |
| `session_id`, `parent_session_id` | string | Captured session ULIDs. Optional when session capture produced no value. |
| `properties` | object | Bounded, normalized custom properties after redaction. Empty maps are omitted. |
| `cache_status` | string | Gateway cache decision: `disabled`, `miss`, `hit`, or `semantic_hit`. |
| `retry_count` | int | Additional upstream attempts after the first. Zero means no retry. |
| `failover_engaged` | bool | Whether fallback or AI provider failover ran. |
| `failover_from`, `failover_to` | string | First failed and final selected provider or target, when known. |
| `load_balancer_strategy`, `load_balancer_target` | string | Bounded routing strategy and selected target. |
| `provider`, `model` | string | AI provider and model when the AI gateway handled the request. |
| `tokens_in`, `tokens_out` | int | Parsed prompt and completion tokens. |
| `cost_usd_micros` | int | Estimated AI cost in millionths of a US dollar. |
| `guardrail_category`, `guardrail_action` | string | Bounded guardrail outcome when a guardrail intervened. |

This is an in-memory ring buffer; entries are lost when the process
exits. For durable request logs, enable the structured access log
(see [access-log.md](access-log.md)).

Supported query parameters: `status` (exact match), `method`
(case-insensitive), `path` (substring), `guardrail_action`,
`guardrail_category`, `cache_status`, `retried`, `property_key`,
`property_value`, `offset`, and `limit` (defaults to and is clamped at
`max_log_entries`). `cache_status` accepts the four values listed above.
`retried` accepts only `true` or `false`. Property matching is exact after
URL decoding; `property_value` requires `property_key`. No parameters returns
the newest entries.

The admin UI derives its Sessions list and detail pages from this ring. Those
pages are a recent operational view, not durable trace storage, a timing
waterfall, or a request replay facility.

### `GET /api/requests/stream`

Server-Sent-Events tail of the same ring buffer: one `data: <json>`
event per request as it completes, plus a leading `: connected`
comment. `Content-Type: text/event-stream`; the connection stays open
until the client disconnects. Handled directly by the async connection
handler (not the blocking dispatcher) so it can own the socket for the
stream's lifetime; requires authentication like every other route, but
does not accept query filters. Each event has the same enriched
`RequestLogEntry` shape as the snapshot; filter the stream client-side.

```bash
curl -N -u "admin:${SB_ADMIN_PASSWORD}" "${SB_ADMIN_URL}/api/requests/stream"
```

### `GET /api/health`

Aggregate liveness summary. Returns `200` with:

```json
{"status":"ok","origins":[]}
```

The `origins` array is currently a placeholder; per-origin health
detail lives at `/api/health/targets` below.

### `GET /api/health/targets`

Per-target health for every origin whose action is a
`load_balancer`. Walks the live pipeline and reports the exact state
that `select_target` consults: active health probe result, outlier
detector eject state, and circuit breaker state. Use this to confirm
that an upstream operators believe is healthy actually is, or to
diagnose why a load balancer is short on candidates.

```json
{
  "config_revision": "abc123...",
  "origins": [
    {
      "hostname": "api.example.com",
      "origin_id": "api",
      "targets": [
        {
          "index": 0,
          "url": "https://upstream-1.internal:8443",
          "eligible": true,
          "healthy": true,
          "outlier_ejected": false,
          "circuit_breaker_state": "closed",
          "weight": 10,
          "backup": false,
          "group": null,
          "zone": "us-west-1a"
        }
      ]
    }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `config_revision` | string | Current pipeline revision; matches the `x-sbproxy-debug-config-rev` header when debug mode is on. |
| `origins[].hostname` | string | Origin hostname. |
| `origins[].origin_id` | string | Stable identifier for this origin within its workspace. |
| `origins[].targets[].index` | int | Position in the configured target list. |
| `origins[].targets[].url` | string | Upstream URL. |
| `origins[].targets[].eligible` | bool | True when `healthy && !outlier_ejected && circuit_breaker_state != "open"`; matches what `select_target` honours. |
| `origins[].targets[].healthy` | bool | Latest active-health-check verdict. |
| `origins[].targets[].outlier_ejected` | bool | True when the outlier detector has temporarily ejected this target. |
| `origins[].targets[].circuit_breaker_state` | string \| null | `"closed"`, `"open"`, `"half_open"`, or null when the breaker is unconfigured. |
| `origins[].targets[].weight` | int | Authored weight. |
| `origins[].targets[].backup` | bool | True when this is a backup target. |
| `origins[].targets[].group` | string \| null | Authored group tag, if any. |
| `origins[].targets[].zone` | string \| null | Authored zone tag, if any. |

Origins whose action is not `load_balancer` (e.g. `proxy`,
`ai_proxy`, `static`, `redirect`) are omitted from `origins`.

### `GET /api/stats`

Basic counters summary.

```json
{"request_log_entries": 42}
```

This is a placeholder; the authoritative metrics surface is the
Prometheus `/metrics` endpoint, served on the data-plane port and
mirrored on the admin port so ops can scrape via the
access-controlled admin listener (see
[metrics-stability.md](metrics-stability.md)).

### `GET /api/openapi.json`, `GET /api/openapi.yaml`

The live pipeline's emitted OpenAPI 3.0 document. The proxy renders
the document once per pipeline revision and caches both JSON and
YAML renderings; the cache invalidates on hot reload.

The shape and the per-origin mapping are documented in
[openapi-emission.md](openapi-emission.md). The `.json` route
returns `Content-Type: application/json`; the `.yaml` route returns
`Content-Type: application/yaml`.

### `GET /api/usage/spend`

Token and USD spend totals from the AI cost/token metrics.

With no query parameters, returns the legacy process-lifetime shape
from the live counters:

```json
{"tokens": 1284213, "cost_usd": 41.27}
```

Passing any of `window` (`1h`, `24h`, `7d`, `30d`), `group_by`
(`total`, `model`, `provider`, `tenant`, `team`, `api_key`, `project`,
`origin`, or `property:<key>`), `from`, or `to` (Unix seconds)
switches to the windowed shape served from the durable usage rollups
(these survive a restart, unlike the process-lifetime counters):

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/api/usage/spend?window=24h&group_by=model" | jq
```

The windowed response contains `from`, `to`, `group_by`, `bucket_secs`,
`buckets`, `totals`, and `property_keys`. `property_keys` lists the promoted
property dimensions available in that window. A syntactically invalid or
unavailable `property:<key>` is `400`; keys must first be configured through
the origin's bounded `properties.rollup_keys` list.

An invalid `window` value is `400`; a valid windowed request when no
rollup store is configured is `503` naming the config knob.

### `GET /api/alerts`

Returns the latest secret-free alert runtime snapshot. Both `read_only` and
`admin` operators may read it. The response is valid even when alerting is not
configured:

```json
{
  "enabled": true,
  "authority": "file",
  "read_only": true,
  "rules": [
    {
      "rule": "error_rate_spike",
      "description": "Provider error rate over the latest evaluation window",
      "thresholds": [0.1, 0.2],
      "minimum_samples": 10,
      "state": "inactive",
      "sample_count": 4
    }
  ],
  "channels": [
    {
      "index": 0,
      "type": "slack",
      "target": "https://hooks.slack.com",
      "health": {"status": "untested"}
    }
  ],
  "history": []
}
```

Rules report `inactive`, `ok`, or `firing`, their thresholds, latest reading,
sample count, and evaluation timestamp. Provider error-rate evaluation stays
inactive until at least 10 provider attempts contribute to the interval.
Channels report only their type, stable index, sanitized scheme and host, or
whether a PagerDuty routing key is configured. URLs, paths, credentials,
headers, and routing keys are never returned. Delivery health is `untested`,
`healthy`, or `failing`, with a bounded error summary and latest-attempt time.

History retains at most 200 fired, resolved, and channel-test events for the
life of the process. It is not durable. `authority: "file"` and
`read_only: true` mean that `sb.yml` remains the only configuration authority.

### `POST /api/alerts/test`

Queues one asynchronous test delivery to a configured channel. This route
requires the `admin` role. Browser-session callers must include their current
`X-CSRF-Token`; HTTP Basic callers remain CSRF-exempt.

```json
{"channel_index": 0}
```

Success is `202 {"queued":true,"channel_index":0}`. A malformed body is
`400`, an unknown index is `404`, an unavailable runtime is `409`, and a full
bounded command queue is `503`. Poll `GET /api/alerts` until that channel's
`health.last_attempt_at` changes to observe the delivery result. This endpoint
tests delivery only and cannot create, edit, or delete rules or channels.

### `GET /api/audit/recent`

Recent rate-limit budget audit rows (suspend, throttle, resume
transitions), newest first. `?limit=` bounds the count (default 50).
Returns `[]` (not an error) when no `rate_limits:` block is
configured — there is nothing to have audited.

### `GET /api/rate_limits/budget`

Per-workspace rate-limit budget state: tier (`normal`, `throttle`,
`auto_suspend`) and any active suspend cool-down, from the
`RateLimitBudgetRegistry` snapshot. `404 {"error":"no rate_limits: block configured"}`
when the workspace-budget feature is off.

### `POST /api/rate_limits/resume`

Manually clears a workspace's escalation state back to `normal`.
Body: `{"workspace": "<id>"}`. `400` for a missing/empty workspace,
`404` when the workspace has not been tracked (no traffic seen) or no
`rate_limits:` block is configured.

### `GET /api/rate_limits/effective`

Effective requests-per-second ceiling and tier for one workspace right
now: `?workspace=<id>` (defaults to `default`).

```json
{"workspace": "default", "effective_rps": 1000, "tier": "normal"}
```

`404 {"error":"no rate_limits: block configured"}` when unconfigured.

### `POST /api/rate_limits/clock/advance`

**Test/dev-only.** Advances the rate limiter's clock by `?secs=N`
seconds. This only does anything when `proxy.rate_limits.clock:
manual` is set — a mode that exists so integration tests can assert
token-bucket refill and suspend-cooldown behavior deterministically,
without sleeping in wall time. Production configs use the default
`system` clock, for which this route returns
`400 {"error":"clock is not in manual mode"}`. There is no reason to
call this against a real deployment.

### `GET /api/ui-settings`

Small settings block the admin UI reads once at load:

```json
{"trace_url_template": "https://jaeger.internal/trace/{trace_id}"}
```

`trace_url_template` is `proxy.admin.trace_url_template`; `null` when
unset, in which case the UI renders trace IDs as plain text instead of
a broken link.

---

## AI compression session state

These routes operate on the external running-summary state used by
`origins[].action.compression` policies on `ai_proxy` handlers. They expose only
the globally configured Redis compression store for metadata, deletion, and
purge operations. Summary-content inspection additionally requires an active
origin policy that opts in. Records use opaque, canonical 64-character
lowercase hexadecimal IDs. See
[AI context compression](ai-context-compression.md) for the data-plane policy,
session identity, and request eligibility rules.

Authorization is deliberately narrower than the general read/write split:

| Route | Required role | Session CSRF requirement |
|---|---|---|
| `GET /admin/compression/sessions` | `read_only` or `admin` | None |
| `GET /admin/compression/sessions/{id}` | `read_only` or `admin` | None |
| `GET /admin/compression/sessions/{id}/content` | `admin` only, plus handler opt-in | None because this is a GET |
| `DELETE /admin/compression/sessions/{id}` | `admin` | Required for session auth; Basic auth is exempt |
| `POST /admin/compression/sessions/purge` | `admin` | Required for session auth; Basic auth is exempt |

A valid route request with missing authentication returns `401`. A `read_only`
caller on an Admin-only route, or a session mutation with a missing or invalid
`X-CSRF-Token`, returns `403`.

### Metadata schema

The list response places these fields in each `records[]` entry. The single
record endpoint places the same object in `record`.

| Field | Type | Description |
|---|---|---|
| `id` | string | Opaque canonical record ID, 64 lowercase hexadecimal characters. |
| `backend` | string | `redis` or `mesh`. |
| `consistency` | string | `serialized` for Redis records, `eventual_lww` for mesh records. |
| `schema_version` | int | External record serialization schema version. |
| `tenant_id` | string | Tenant isolation and filtering boundary. |
| `origin` | string | Normalized AI handler hostname. |
| `logical_version` | int | Monotonic version within the current retained record lineage. Delete or expiry allows a later lineage to restart at 1. |
| `protected_prefix_count` | int | Count of leading system or developer messages protected verbatim. |
| `covered_history_count` | int | Count of original history messages represented by the summary. |
| `covered_input_tokens` | int | SBproxy model-aware token estimate represented by that covered history. |
| `summary_tokens` | int | Bounded summarizer output token count, not its content. |
| `summarizer_provider` | string | Configured internal summarizer provider name. |
| `summarizer_model` | string | Configured internal summarizer model name. |
| `writer_node` | string | Configured cluster node ID, or the literal `standalone` outside cluster mode. It is not a credential or guaranteed unique process ID. |
| `conflict_detected` | bool | Always `false` for the serialized Redis backend. On the mesh backend, `true` when the record survived a deterministic merge of competing equal-version updates. |
| `created_at_unix_ms` | int | Creation time in Unix milliseconds. |
| `updated_at_unix_ms` | int | Last update time in Unix milliseconds. |
| `expires_at_unix_ms` | int | Backend expiration time in Unix milliseconds. |
| `kind` | string | `live` for Redis records returned by these endpoints. Mesh records can also report `tombstone` while a replicated deletion marker is retained; tombstone entries carry empty content metadata. |

Metadata never contains `summary`, a raw session ID, raw messages, protected or
covered message digests, or credential material. The opaque ID is derived from
the tenant, normalized origin, captured session ID, and stable summary-policy
fingerprint without retaining that raw session ID.

### `GET /admin/compression/sessions`

Returns one bounded metadata page:

```json
{
  "records": [
    {
      "id": "cee8c51340c1413d8b85a56c6f51928a92b12fa00e1e8cfd761c3cd0fb28ce47",
      "backend": "redis",
      "consistency": "serialized",
      "schema_version": 1,
      "tenant_id": "tenant-a",
      "origin": "api.example.com",
      "logical_version": 4,
      "protected_prefix_count": 1,
      "covered_history_count": 6,
      "covered_input_tokens": 300,
      "summary_tokens": 40,
      "summarizer_provider": "anthropic",
      "summarizer_model": "claude-haiku-4-5",
      "writer_node": "node-a",
      "conflict_detected": false,
      "created_at_unix_ms": 1784300000000,
      "updated_at_unix_ms": 1784300300000,
      "expires_at_unix_ms": 1784386700000,
      "kind": "live"
    }
  ],
  "next_cursor": null
}
```

Supported query parameters:

| Parameter | Values | Meaning |
|---|---|---|
| `tenant` | non-empty string | Exact tenant filter. |
| `origin` | non-empty hostname | Origin filter. Input is trimmed, lowercased, and has a trailing dot removed. |
| `backend` | `redis`, `mesh` | Restrict the scan to one configured backend. Any other value returns `400`. |
| `conflict` | `true`, `false` | Match `conflict_detected`. |
| `cursor` | opaque string | Continue from `next_cursor` returned by the preceding list call. |
| `limit` | positive integer | Page size. Defaults to 100; values above the maximum of 500 are clamped to 500. |

Parameters may appear only once. Unknown or duplicate parameters, invalid
booleans or backends, a zero or non-integer limit, and an invalid cursor return
`400`. Redis listing scans the shared Redis namespace through bounded pages and
an opaque cursor. Redis expires records at their TTL, so expired records are
not retained as a separate Admin-visible collection and cannot be filtered.
Mesh listing walks the replicated substrate's topology-safe fleet pagination:
a record held by any current cluster member is listed, a cursor keeps working
while nodes join or leave, and a record replicated on several nodes can appear
in more than one page, so collapse results by `id`. If a current member cannot
be queried the mesh listing fails with `503` instead of returning a silently
partial page.

### `GET /admin/compression/sessions/{id}`

Returns `200` with `{"record": <metadata>}`. The endpoint returns `400` for an
ID that is not canonical lowercase hexadecimal and `404` when no configured
store has the record. It does not expose summary content, even to an Admin.

### `GET /admin/compression/sessions/{id}/content`

This is the only route that can return a generated running summary. It is
denied by default and succeeds only when all of the following are true:

1. The caller is authenticated with the `admin` role.
2. The ID is valid and resolves to a `live`, unexpired record.
3. The current AI handler for that record's normalized origin and backend sets
   `allow_admin_content_inspection: true`.
4. The audit sink accepts the content-free inspection event before the response
   is returned.

Success returns the usual metadata plus the only content-bearing field:

```json
{
  "record": {
    "id": "cee8c51340c1413d8b85a56c6f51928a92b12fa00e1e8cfd761c3cd0fb28ce47",
    "backend": "redis",
    "consistency": "serialized",
    "schema_version": 1,
    "tenant_id": "tenant-a",
    "origin": "api.example.com",
    "logical_version": 4,
    "protected_prefix_count": 1,
    "covered_history_count": 6,
    "covered_input_tokens": 300,
    "summary_tokens": 40,
    "summarizer_provider": "anthropic",
    "summarizer_model": "claude-haiku-4-5",
    "writer_node": "node-a",
    "conflict_detected": false,
    "created_at_unix_ms": 1784300000000,
    "updated_at_unix_ms": 1784300300000,
    "expires_at_unix_ms": 1784386700000,
    "kind": "live"
  },
  "summary": "Bounded generated running summary."
}
```

Successful content responses include all three safety headers:

```text
Cache-Control: no-store
Pragma: no-cache
X-Content-Type-Options: nosniff
```

Every content-inspection attempt that reaches the compression route is emitted
on the `sbproxy::admin::audit` tracing target before its response is returned,
including invalid IDs, missing or expired records, disabled inspection,
backend errors, and success. Authentication and role failures handled by the
outer Admin gate do not reach this route. The audit event carries only
`operator`, `role`, `record_id`, `tenant_id`, `origin`,
`action=inspect_compression_content`, and a closed outcome. It never carries
the summary, raw messages, bearer material, or CSRF token. The built-in sink
emits tracing events, so durable retention depends on the configured tracing
collector. If an installed sink reports failure, the route returns
`503 {"error":"audit unavailable"}` and withholds the summary. Missing or
expired records return `404`; a disabled handler returns
`403 {"error":"content inspection is disabled"}`.

### `DELETE /admin/compression/sessions/{id}`

Deletion runs against the globally configured Redis compression store. Success is always
`200`, including when no live record existed:

```json
{
  "deleted": true,
  "logical_versions": {}
}
```

`deleted` is true when Redis removed live state. Redis does not return a
logical version, so `logical_versions` is empty. Repeating the delete is safe
and returns `"deleted": false`.

Redis atomically removes the record and active lease, then increments a
retained fence so an in-flight writer cannot recreate deleted state. A later
eligible request with the same captured session can create a new record;
deletion clears summary state, not the caller's session identity.

### `POST /admin/compression/sessions/purge`

Purge deletes one bounded Redis page. The JSON body is strict and
accepts only these fields:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `tenant` | string | unset | Exact tenant scope. Must not be empty. |
| `origin` | string | unset | Normalized origin scope. Must not be empty. |
| `conflict` | bool | unset | Match the record's `conflict_detected` value. This narrows a tenant or origin scope but is not a destructive boundary by itself. |
| `backend` | string | unset | `redis`. This narrows execution but is not, by itself, a destructive scope. |
| `cursor` | string | unset | Opaque `next_cursor` from the preceding purge call. It is not a destructive scope. |
| `limit` | int | 100 | Positive page size. Values above the maximum of 500 are clamped to 500. It is not a destructive scope. |
| `all` | bool | `false` | Permit an otherwise unscoped purge. When true, exact confirmation is mandatory. |
| `confirmation` | string | unset | Must equal `purge-compression-sessions` whenever `all` is true. |

Without `all`, at least one of `tenant` or `origin` must be present. `conflict`,
backend, cursor, and limit may narrow that scope but do not establish a deletion
boundary. Requests such as `{"conflict":false}` or `{"backend":"redis"}` are
rejected. An all-record purge
must use this exact shape, optionally with `backend`, `cursor`, or `limit`:

```json
{
  "all": true,
  "confirmation": "purge-compression-sessions"
}
```

Success returns the number affected in this page and an opaque continuation:

```json
{"deleted":100,"next_cursor":"<opaque>"}
```

Continue with the returned purge cursor until `next_cursor` is `null`.
Repeating a deletion is safe.

### Compression state errors

Invalid requests and cursors return `400`. An unavailable backend returns
`503 {"error":"compression state unavailable"}`. Corrupt or unsupported
record bytes return `503` when an operation must decode them, including list,
detail, purge, and content inspection. Delete removes the addressed Redis bytes
without decoding them. List and detail never return a partial metadata body on
those errors. Delete and purge are idempotent; retry with the same ID, scope,
and cursor after a transient backend failure.

### Curl examples

These examples use the documented HTTP Basic convention, so mutation requests
do not need a CSRF header. They assume at least one record exists for
`tenant-a`.

```bash
export SB_ADMIN_URL=http://127.0.0.1:9090
export SB_ADMIN_PASSWORD='replace-me'

# List content-free metadata and capture one opaque ID.
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/compression/sessions?tenant=tenant-a&limit=100" \
  | jq '{records,next_cursor}'
SB_COMPRESSION_RECORD_ID="$(
  curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" \
    "${SB_ADMIN_URL}/admin/compression/sessions?tenant=tenant-a&limit=1" \
    | jq -er '.records[0].id'
)"

# With the default handler opt-in set to false, this returns 403 and no summary.
curl -sS -i -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/compression/sessions/${SB_COMPRESSION_RECORD_ID}/content"

# Delete one record. Repeating the command returns deleted=false.
curl -fsS -X DELETE -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/compression/sessions/${SB_COMPRESSION_RECORD_ID}" \
  | jq

# Purge one bounded page for this tenant.
curl -fsS -X POST -u "admin:${SB_ADMIN_PASSWORD}" \
  -H 'Content-Type: application/json' \
  --data '{"tenant":"tenant-a","limit":100}' \
  "${SB_ADMIN_URL}/admin/compression/sessions/purge" \
  | jq
```

---

## Config and control routes (authenticated)

### `GET`, `PUT` `/admin/config`

Reads and writes the raw on-disk config text.

`GET` returns the current YAML plus the loaded revision:

```json
{"config": "proxy:\n  http_bind_port: 8080\n...", "revision": "abc123..."}
```

`PUT`/`POST` validates the submitted YAML, persists it, and hot-swaps
the running pipeline — the same swap `POST /admin/reload` performs,
just sourced from the request body instead of re-reading the file.
Add `?if_match=<revision>` for optimistic concurrency (the write is
rejected with `409` if the loaded revision has moved since the caller
last read it). `400` for a YAML parse failure or a failed pipeline
compile; the config path itself is scrubbed from any error message.
Env-var interpolation (`${VAR}`) and secret-backend references are
stored and echoed back exactly as written — a secret is never
resolved into the saved config or exposed in this editor. See
[secrets.md](secrets.md).

### `GET`, `PUT` `/admin/log-level`

Runtime tracing-filter control, no restart required.

`GET` returns `{"level": "info"}` (or whatever directive is active,
e.g. `sbproxy_ai=debug`). `PUT`/`POST` body `{"level": "debug"}` (or a
per-target directive like `{"level": "sbproxy_ai=debug"}`) sets it
immediately:

```bash
curl -u "admin:${SB_ADMIN_PASSWORD}" -X PUT "${SB_ADMIN_URL}/admin/log-level" \
  -H 'content-type: application/json' -d '{"level":"debug"}'
```

`400` for a missing/empty `level` or a directive the tracing filter
rejects.

### `POST /admin/reload`

Re-reads the config file the proxy booted with (the `-f/--config`
path, or `SB_CONFIG_FILE`) from disk, recompiles the pipeline, and
hot-swaps the in-memory pipeline. There is no separate
config-path setting on the admin block; the admin server is handed
the boot path at startup. The route uses the same single-flight
guard as the file watcher, so a manual reload during a file-watcher
reload returns `409`.

`GET /admin/reload` returns `405`; the route is gated on POST.

Success response (`200`):

```json
{
  "config_revision": "abc123...",
  "loaded_at": "2026-05-12T10:15:32.456Z"
}
```

| Status | When |
|---|---|
| `200` | Reload succeeded; pipeline swapped. |
| `400` | YAML parse failed. Error body carries the parse error with the config path scrubbed. |
| `405` | Method other than POST. |
| `409` | Another reload is already in flight. |
| `500` | Could not read the config file (permissions, ENOENT), or pipeline compile failed. |
| `503` | The admin server has no `config_path` wired (in-memory / test mode). |

See [manual.md section 9](manual.md#9-hot-reload) for the full
operator workflow including curl examples and the Kubernetes
operator integration.

### `GET /admin/drift`

Compares the on-disk config file the proxy booted with against the
content hash captured the last time the proxy loaded a config
(startup, file-watcher reload, or `POST /admin/reload`). Use
this to detect when the running proxy has diverged from the
declared config without triggering a reload.

```json
{
  "config_path": "/etc/sbproxy/sb.yml",
  "loaded_revision": "abc123...",
  "loaded_content_hash": "sha256:...",
  "on_disk_content_hash": "sha256:...",
  "drift": false,
  "on_disk_size_bytes": 8421,
  "checked_at": "2026-05-12T10:15:32.456Z"
}
```

| Field | Type | Description |
|---|---|---|
| `config_path` | string | Absolute path the admin server reads. |
| `loaded_revision` | string | Pipeline `config_revision` of the running proxy. |
| `loaded_content_hash` | string | Content hash of the bytes that produced the running pipeline. |
| `on_disk_content_hash` | string | Content hash of the bytes the admin server just read off disk. |
| `drift` | bool | True when `loaded_content_hash != on_disk_content_hash`. |
| `on_disk_size_bytes` | int | Size in bytes of the on-disk config. |
| `checked_at` | string | RFC 3339 timestamp of this check. |

| Status | When |
|---|---|
| `200` | Drift check completed. The body always describes the comparison. |
| `500` | Could not read the on-disk config file. Path is scrubbed from the error message. |
| `503` | The admin server has no `config_path` wired, or no content-hash baseline has been captured yet. |

Operators typically scrape this every few seconds from their dashboard
or alert pipeline. When `drift: true` is sustained for more than the
expected reload window, page the operator: either the watcher is
stuck, the deploy pipeline forgot to call `POST /admin/reload`, or
someone hand-edited the file out of band.

---

## Model host admin

Routes over the `proxy.model_host` runtime: what the local process can
serve, what is desired, what is actually running, and lifecycle
control. All authenticated, mounted on the shared admin listener. See
[model-host.md](model-host.md#authenticated-catalog-and-local-deployment-api)
for the config block these adapt and the authority model
(`admin_managed` vs. `file_managed` vs. cluster) that governs which
mutations are accepted.

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/model-host/catalog` | Bundled model + exact-variant evidence, with the rendered catalog revision. |
| GET | `/admin/model-host/deployments` | Complete local desired-state document: authority, read-only flag, revision, digest, deployment map. |
| PUT | `/admin/model-host/deployments` | Replace the desired-state map under `admin_managed` authority (compare-and-swap on `expected_revision`). |
| GET | `/admin/model-host/status` | Per-deployment runtime state, lifecycle, engine, artifact, memory, device, port, queue, job. |
| GET | `/admin/model-host/value` | Local-serving + compression value report (tokens/cost saved). |
| GET | `/admin/model-host/files` | Verified artifact cache inventory: cache root, total bytes, per-artifact size/residency. |
| POST | `/admin/model-host/gc` | On-demand protected LRU collection down to the configured cache budget. |
| DELETE | `/admin/model-host/artifacts/{digest}` | Remove one exact cached artifact by its 64-hex-char digest. |
| POST | `/admin/model-host/load` | Start (or confirm ready) one configured deployment. Body: `{"deployment": "<id>"}`. |
| POST | `/admin/model-host/stop`, `/drain` | Drain and stop one deployment (aliases of the same operation). |
| POST | `/admin/model-host/evict` | Compatibility alias for stop/drain. |
| POST | `/admin/model-host/reset` | Clear retained crash-loop/failure state so a configured deployment can start again. |

`load`, `stop`/`drain`/`evict`, and `reset` all accept `{"deployment":
"<id>"}` (the legacy key `model` is still accepted as an alias) and
operate only on a deployment ID that already exists in desired state —
none of them create or delete a deployment; that is what the
`deployments` PUT and `sb.yml` are for.

### `GET`/`PUT /admin/model-host/deployments` errors

`PUT` is only served on this process when a runtime manager is
installed at all (`404` otherwise, from the model-host manager not
being present). A stale `expected_revision` is `409 revision_conflict`;
an invalid or secret-bearing body is `400 invalid_bundle`; a
non-`admin_managed` authority (i.e. `file_managed` or a cluster
verifier node) returns `403` explaining the deployment map is managed
elsewhere. See [model-host.md](model-host.md#authenticated-catalog-and-local-deployment-api)
for the full request schema and validation order.

### `GET /admin/model-host/value`

```json
{
  "models": [{"model": "gpt-4o-mini", "local_completions": 0, "cloud_completions": 42}],
  "compression": [{"model": "gpt-4o-mini", "lever": "window_fit", "tokens_saved": 18432, "gross_cost_saved_micros": 2765, "token_count_precision": "model_tokenizer"}],
  "compression_totals": {"window_fit": {"tokens_saved": 18432, "gross_cost_saved_micros": 2765}},
  "total_compression_tokens_saved": 18432,
  "total_compression_gross_cost_saved_micros": 2765
}
```

Empty (all-zero) until a locally served or compressed request
completes successfully. `compression` is sorted by model and lever;
`compression_totals` aggregates by lever name. A known target-model
tokenizer produces `model_tokenizer` precision; the UTF-8
byte-length fallback produces `heuristic` — both are sbproxy estimates,
not provider billing totals. The ledger is a bounded in-memory
structure (at most 1,000 model lanes, with overflow folded into
`__other__`) unless a qualifying `providers[].serve` block with
`cache_dir` set has initialized a durable `value-ledger.redb` path, in
which case it persists across restarts. See
[ai-context-compression.md](ai-context-compression.md) for the
data-plane policy that produces these savings.

### `GET /admin/model-host/files`

```json
{
  "schema_version": 1,
  "cache_root": "/var/lib/sbproxy/models",
  "total_bytes": 4831838208,
  "artifacts": [
    {"logical_model": "qwen2.5-0.5b-instruct", "variant_id": "q4_k_m", "artifact_digest": "9f2c...", "total_size_bytes": 402653184, "last_accessed_ms": 1784300000000, "resident": true}
  ]
}
```

`cache_root: null` and an empty `artifacts` array when no model host
is configured — an honest empty inventory, not an error.

### `POST /admin/model-host/gc`

Runs the same protected LRU sweep the post-pull path runs
automatically, on demand. Protects configured, resident, pinned,
leased, and file-locked artifacts identically to the automatic sweep
and to `DELETE .../artifacts/{digest}`. Returns the collection report
(bytes reclaimed, artifacts removed). `409` when no cache budget is
configured — there is no target to collect toward.

### `DELETE /admin/model-host/artifacts/{digest}`

`digest` must be 64 lowercase hex characters (a SHA-256); anything
else is `400`. Removal shares the exact protection rules `sbproxy
models remove` enforces, so the API and CLI can never disagree. `404`
when the digest is not in the verified cache; `409` with a stable
`reason` when removal is blocked (e.g. the artifact backs a ready
replica); a manager-open or filesystem failure is `502`.

---

## Cache admin

Two independent operator surfaces on the admin server (WOR-1754 /
WOR-1755), unrelated to the model-host artifact cache above:

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/cache` | Response-cache status: enabled, backend, whether prefix purge is supported. |
| POST | `/admin/cache/purge` | Evict response-cache entries: by exact key, by prefix, or all. |
| POST | `/admin/cache/key-policy/evict` | Drop one (or all) cached key policies so the next request re-reads the keystore. |
| GET | `/admin/cache/semantic` | Recent semantic (embedding) cache lookup decisions per AI origin. |

### `GET /admin/cache`

```json
{"enabled": true, "backend": "redis", "prefix_purge_supported": true}
```

`{"enabled": false}` when no origin turned on response caching.
`prefix_purge_supported` is true only for `memory` and `redis`
backends (`file` hashes keys into filenames and cannot scan by
prefix; `memcached` has no scan primitive).

### `POST /admin/cache/purge`

Body selects the scope — `{"key": "..."}` deletes one entry,
`{"prefix": "..."}` deletes a prefix, an empty body `{}` clears the
whole cache:

```bash
curl -u "admin:${SB_ADMIN_PASSWORD}" -X POST "${SB_ADMIN_URL}/admin/cache/purge" \
  -H 'content-type: application/json' -d '{"prefix":"gpt-4o-mini:"}'
```

`409 {"error":"response cache not enabled"}` when no origin enabled
caching.

### `POST /admin/cache/key-policy/evict`

Body `{"id": "<key_id>"}` evicts one key's cached policy; an empty
body `{}` evicts every cached policy. On the Redis key-plane tier this
publishes the invalidation to every replica in the fleet, not just the
node that received the request. `409 {"error":"dynamic key plane not enabled"}`
when `key_management` has no keystore backend configured.

### `GET /admin/cache/semantic`

`?limit=N` (default 50, max 100) recent lookup decisions per AI origin
that has a semantic (embedding) cache configured:

```json
{"caches": [{"origin": "ai.example.com", "recent": [{"reason": "hit", "score": 0.94, "threshold": 0.85}]}]}
```

`reason` is `hit`, `no_entry`, `expired`, `below_threshold`, or
`cross_scope`. `caches: []` when no origin has an embedding cache
configured. See [local-inference.md](local-inference.md) for the
semantic-cache feature this debugs.

---

## Cluster control plane

### `GET /admin/cluster/status`

Returns one versioned snapshot for the complete cluster view. This is an
authenticated read route and returns `405` for other methods.

```json
{
  "schema_version": 1,
  "configured": true,
  "mode": "distributed",
  "cluster_id": "production-models",
  "local_node_id": "gateway-a",
  "generated_at_unix_ms": 1783790000000,
  "directory_collected_at_unix_ms": 1783789999500,
  "directory_age_ms": 500,
  "summary": {
    "total_nodes": 4,
    "healthy_nodes": 3,
    "degraded_nodes": 0,
    "unhealthy_nodes": 1,
    "eligible_workers": 1,
    "eligible_replicas": 1,
    "deployment_digest_mismatch": false,
    "deployments": 1,
    "ready_deployments": 1,
    "rollouts_in_progress": 0,
    "unplaced_replicas": 0
  },
  "deployment_authority": {
    "configured": true,
    "read_only": true,
    "verifying_key_id": "<key-id>",
    "active_revision": 7,
    "active_content_digest": "<sha256>",
    "signer_node_id": "authority-a"
  },
  "deployments": [],
  "nodes": [],
  "unhealthy_nodes": [
    {
      "node_id": "worker-b",
      "health": "unhealthy",
      "reasons": ["membership_dead"],
      "membership_state": "dead",
      "last_ack_age_ms": 8200,
      "snapshot_age_ms": 8400,
      "model_endpoint": "https://worker-b.internal:9443"
    }
  ]
}
```

`nodes` always contains every current membership record, including failed and
excluded members. A node row carries `membership_state`, `last_ack_age_ms`,
`incarnation`, `health`, `unhealthy`, `unhealthy_reasons`, roles, labels,
endpoint, `model_eligible`, exclusion reason, snapshot age/generation/schema,
reported health, engine/device/ready-artifact counts, and replica observations.
The smaller `unhealthy_nodes` array is the alert feed for operator consoles; it
does not replace the complete table. `nodes` retains a bounded tombstone after
dead-peer routing GC, including the last safe snapshot and current stable
reason code.

Each deployment row includes the desired and placed counts, generation, phase,
readiness, timeout and handoff deadline, target assignments, retained and
draining assignments, unplaced count, and per-node rejection reasons. Suspect,
dead, unreachable, stale, incompatible, and unhealthy workers are visible but
ineligible.

### `GET`, `POST /admin/cluster/deployments`

`GET` returns the locally active verified restricted bundle, signer node and
key, and whether this process is read-only. It returns `404` with code
`deployment_bundle_missing` before any bundle is active.

`POST` accepts a strict draft on the configured signing authority only:

```json
{
  "catalog_revision": "builtin-2026-07-10",
  "revision": 8,
  "deployments": {
    "local-qwen": {
      "model": "qwen2.5-0.5b-instruct",
      "variant": "q4_k_m",
      "replicas": 2,
      "spread_by": ["zone"],
      "pull": "on_boot",
      "warm": true,
      "engine": "llama_cpp",
      "rollout": "rolling"
    }
  }
}
```

Success is `202` with revision, content digest, signer node/key, and
`status: "published"`. Unknown or secret-bearing fields return
`400 invalid_bundle`; stale revisions return `409 stale_revision`; equal revision
with different content returns `409 revision_conflict`; a non-authority returns
`403 deployment_authority_read_only`.

### `POST /admin/cluster/enroll`

This is the only `/admin/cluster/*` route that does not use an existing admin
credential. It accepts a bounded CSR request carrying an expiring one-time
enrollment token. Successful token consumption is atomic and returns the
CA-signed node identity material. Token replay, role or label escalation,
authority-role escalation, malformed CSRs, and oversized requests fail closed.
Use `sbproxy cluster enroll` instead of constructing this wire document by
hand.

### `GET /admin/cluster/metrics`

Fleet-aggregated metrics (mesh tier). See [observability.md](observability.md)
for the aggregation model; `404` when the mesh metrics tier is not
configured.

### `GET /admin/cluster/artifacts`

Fleet-wide artifact-cache usage: total bytes and artifact count per
node, and total bytes per model across the fleet. Aggregates each
node's latest accepted snapshot from the model directory; a node with
no accepted snapshot yet is omitted from `nodes` and flips the
top-level `partial: true` flag rather than silently under-reporting.
Outside a configured cluster (or when the directory has no other
members), reports the local node's own artifact cache — the same
inventory as `GET /admin/model-host/files`, reshaped for the fleet
view. `405` for a method other than GET.

### `GET /admin/cluster/state`

Fleet-complete listing of the replicated state substrate (see
[mesh-replication.md](mesh-replication.md)). Requires
`proxy.cluster.replication`; without it every `/admin/cluster/state*`
route returns `404` with code `replication_disabled`. Query parameters:
`prefix` (default empty, meaning everything), `page_token` (opaque, from
the previous page), `limit` (default 200, capped at 1000).

```json
{
  "schema_version": 1,
  "entries": [
    {
      "key": "session:tenant-a:42",
      "holder": "gateway-b",
      "logical_version": 7,
      "tombstone": false,
      "timestamp_ms": 1783790000000,
      "written_by": "gateway-a"
    }
  ],
  "next_page_token": "eyJub2RlIjoi...",
  "unreachable": []
}
```

A key replicated on N nodes appears once per holder; collapse by `key`
client-side. Members that could not be queried are named in
`unreachable` instead of being silently skipped. Pagination survives
topology changes: a token pointing at a departed member resumes at the
next surviving member.

### `GET`, `PUT /admin/cluster/state/key?key=<key>`

Single-record quorum read and write. `GET` reconciles the configured
number of replicas, repairs stale ones in line, and returns `404` with
`"found": false` for missing or deleted keys:

```json
{
  "schema_version": 1,
  "key": "session:tenant-a:42",
  "found": true,
  "value_base64": "eyJzdW1tYXJ5IjoiLi4uIn0",
  "value_utf8": "{\"summary\":\"...\"}",
  "replicas_answered": 2,
  "repaired": 0
}
```

`PUT` takes the raw record value as the request body plus an optional
`ttl_secs` query parameter (`0` or absent means no expiry), and reports
the acknowledged replica count and the record's logical version:

```json
{"schema_version": 1, "key": "session:tenant-a:42", "acked_replicas": 2, "logical_version": 8}
```

A write that cannot meet the configured write consistency returns `502`
with code `replication_write_failed`.

### `DELETE /admin/cluster/state?key=<key>`

Replicated delete: replicates a tombstone through the same quorum path
as writes, so the deletion holds across restarts, healed partitions,
and rebalances. Returns `{"schema_version": 1, "deleted": "<key>",
"acked_replicas": 2}`.

### `POST /admin/cluster/state/purge`

Bounded replicated purge. Body: `{"prefix": "session:tenant-a:", "max": 1000}`
(`max` defaults to 1000, capped at 10000). Every distinct live key under
the prefix is deleted through the replicated tombstone path:

```json
{"schema_version": 1, "deleted": 412, "failed": 0, "truncated": false}
```

`truncated: true` means the key budget ran out first; repeat the call to
continue.

---

## Admin UI (`GET /admin/ui`, `GET /`)

The admin server serves a full operator dashboard under `/admin/ui/`:
keys and credentials, config editing and drift, the request log (with
live tail), metrics, spend, AI performance, guardrails, prompts, a
chat playground, the response/semantic cache, model host (catalog,
desired-state editing, lifecycle actions), artifact storage, the audit
and rate-limit view, and — despite older notes to the contrary — the
full cluster roster, health rail, and unhealthy-node alerts, reading
`GET /admin/cluster/status` and `GET /admin/cluster/metrics`. See
[admin-ui.md](admin-ui.md) for the page-by-page reference. `GET /`
does not redirect there; it returns a small static HTML landing page
(`200 text/html`) that lists the main API endpoints. Both routes are
authenticated like the rest of `/api/*` and `/admin/*`.

The dashboard is only present when the binary was built with it
embedded: build the UI assets first (`cd ui && npm ci && npm run
build`), then compile the proxy with `--features embed-admin-ui`.
Default builds skip the embed and `/admin/ui` returns a `404` whose
body spells out those two steps.

---

## Prompt store admin (`GET /admin/prompts`, `POST /admin/prompts/...`)

Exposes the runtime prompt-store overlay. `GET /admin/prompts`
returns the in-memory snapshot (every active prompt + pinned
version + last-mutation metadata) as JSON. `POST /admin/prompts`
mutators add a new version, pin a version, or roll back; mutations
persist to the operator-configured redb file when
`admin.prompt_persistence_path` is set, so changes survive restart.

The full set of POST shapes and request schemas is documented in
[ai-gateway.md](./ai-gateway.md) under "Stored prompts". This
reference only catalogues the route surface; the request/response
contracts live with the feature.

---

## Chat playground

Two routes back the dashboard's interactive chat surface. Both sit
behind the admin auth and RBAC gate; the chat route is a mutation, so
it requires the `admin` role.

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/api/playground/endpoints` | List every AI origin the live pipeline serves, with each provider's declared models and default model. Read-only, sourced from the compiled pipeline, so a config reload updates it without a restart. |
| POST | `/admin/api/playground/chat` | Run a chat completion against a chosen endpoint through the same AI client the data plane uses. Returns the upstream response plus token usage, cost, and latency. |

The playground is live: a chat call goes out to the real upstream
through the same AI client the data plane uses, and the response
carries actual token usage, cost, and latency. It calls the AI client
directly, though, so it does not traverse the data-plane pipeline:
per-origin policies, guardrails, transforms, and the
`x-sbproxy-debug-*` header stamping do not apply. Pass `"debug": true`
in the request body to get a `debug` block with a server-logged
request id and the config revision for correlation instead.

Unauthenticated requests see `401 Unauthorized`; other verbs return
`405 Method Not Allowed`.

---

## Curl recipes

```bash
# Reload the running config.
curl -s -X POST -u admin:secret \
  http://127.0.0.1:9090/admin/reload

# Check for config drift.
curl -s -u admin:secret \
  http://127.0.0.1:9090/admin/drift | jq

# Watch per-target health.
curl -s -u admin:secret \
  http://127.0.0.1:9090/api/health/targets | jq '.origins[].targets'

# Show the full cluster roster and unhealthy-node alerts.
curl -s -u admin:secret \
  http://127.0.0.1:9090/admin/cluster/status \
  | jq '{summary,nodes,unhealthy_nodes}'

# Inspect the last 50 requests.
curl -s -u admin:secret \
  http://127.0.0.1:9090/api/requests | jq '.[0:50]'

# Pull the emitted OpenAPI spec for a Postman import.
curl -s -u admin:secret \
  http://127.0.0.1:9090/api/openapi.json > openapi.json
```

---

## See also

- [admin-api-guide.md](admin-api-guide.md) - task-oriented walkthrough: enabling the server, login/CSRF, a curl cookbook.
- [admin-ui.md](admin-ui.md) - the built-in dashboard, page by page.
- [manual.md](manual.md) - install, CLI, hot reload workflow.
- [admin.md](admin.md) - admin listener, authentication, roles, TLS, and operator workflows.
- [configuration.md](configuration.md) - the `proxy.admin:` block.
- [key-management.md](key-management.md) - the virtual-key policy model `/admin/keys` and `/admin/credentials` drive.
- [model-host.md](model-host.md) - the `proxy.model_host` config the model-host admin routes adapt.
- [ai-context-compression.md](ai-context-compression.md) - compression policy, external state, and degradation behavior.
- [openapi-emission.md](openapi-emission.md) - the emitted OpenAPI document's shape and per-origin mapping.
- [access-log.md](access-log.md) - the durable structured request log.
- [metrics-stability.md](metrics-stability.md) - the Prometheus `/metrics` surface.
- [audit-log.md](audit-log.md) - tamper-evident log of admin actions.
