# Admin API reference

*Last modified: 2026-08-18*

The embedded admin server publishes the full control-plane HTTP surface for
operator tooling: liveness probes, session login, key and credential
lifecycle, the running extension inventory, the request log and its live stream, recent sessions, alert
operations, per-target health, spend and audit, config read/write and hot reload/drift, the local config-revision
history ring, model-host catalog and deployment lifecycle, the
response/semantic/key-policy caches, cluster status and the replicated-state
substrate, prompts, the chat playground, and the emitted OpenAPI document.

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
- [Read routes](#read-routes-authenticated) - request log + stream, extension inventory, alerts, health, spend, audit, egress inventory, rate-limit budget, UI settings, OpenAPI
- [AI compression session state](#ai-compression-session-state)
- [Config and control routes](#config-and-control-routes-authenticated) - reload, drift, config read/write, config history, log level
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

The credentials default to `admin` / `changeme`, which validation refuses
once the surface is reachable off loopback (a non-loopback `bind`, or an
`allow_ips` entry outside loopback). See
[admin.md](admin.md#the-default-credentials-are-refused-off-loopback).

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
    {"name": "usage_ledger", "status": "healthy"},
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
component is still initializing or has failed. K8s polls this to
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

There are two unrelated reasons the `keys` array holds more than one
entry, so read it by `kid` rather than by position. Several issuers is
the multi-tenant case above. Two entries for one issuer is a rotation
window: the key that origin signs under now, plus the
`quote_token.previous_key_id` it keeps verifying until the last quote
signed under the old key has passed its TTL.

---

## Session routes

`POST /admin/login`, `POST /admin/logout`, and `GET /admin/session` run
before the general auth gate: they establish, revoke, or describe a
browser session rather than exposing protected control-plane data. See
[admin-api-guide.md](admin-api-guide.md#authenticating-basic-vs-session--csrf)
for the full login/CSRF walkthrough.

### `POST /admin/login`

Verifies credentials (an `Authorization: Basic` header, or a JSON
`{"username": "...", "password": "..."}` body) against the top-level
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
returning `401`. It distinguishes "please log in" from an error so
the UI can render a login form on a fresh visit:

```json
{"authenticated": true, "username": "admin", "role": "admin", "via_session": true, "csrf_token": "3f9c1a..."}
```

or `{"authenticated": false}`. `via_session` is `false` for a request
authenticated by HTTP Basic (a Basic caller is "authenticated" here
too, so a Basic-authenticated browser session can still recover a
usable CSRF token: the server mints and `Set-Cookie`s a session token
automatically on a Basic-authenticated request that lacks one (the
Basic-to-session upgrade), but the RBAC/CSRF gate still treats
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
| POST | `/admin/keys/{id}/revoke` | Mark revoked (terminal, no further mutation). |
| POST | `/admin/keys/{id}/block` | Mark blocked (reversible). |
| POST | `/admin/keys/{id}/unblock` | Mark active. |
| POST | `/admin/keys/{id}/rotate` | Mint a new secret with a grace-window dual-key transition. |
| GET | `/admin/credentials` | List upstream credentials (no secrets). |
| POST | `/admin/credentials` | Create a credential (`vault_ref` or `secret`, envelope-sealed at rest). |
| GET | `/admin/credentials/{id}` | Fetch one credential. |
| PATCH | `/admin/credentials/{id}` | Update credential metadata, provider, or material. |
| DELETE | `/admin/credentials/{id}` | Delete a credential. `409` while any key's `credential_id` still points at it. |
| POST | `/admin/credentials/{id}/revoke`, `/block`, `/unblock` | Set the credential's status. Unlike the key lifecycle actions below, this has no `expected_revision` check and no terminal-state guard: a revoked credential can still be blocked or unblocked again. |

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
  "budget": {"max_cost_usd": 25.0},
  "allowed_models": ["gpt-4o-mini", "claude-haiku-4-5"],
  "blocked_models": [],
  "allowed_providers": [],
  "blocked_providers": [],
  "allowed_tools": null,
  "require_pii_redaction": [],
  "principal_selectors": [],
  "inject_tools": [],
  "bypass_prompt_injection": false,
  "allow_content_capture": false,
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
runtime digest. Get one per-origin from the effective-policy preview
instead. `rotation_pending` is true while a prior secret is still
valid inside its rotation grace window. `allow_content_capture` gates
whether `GET /api/requests/{request_id}/content` can sample this key's
traffic; it is always present. `max_tokens_per_minute`, `priority`,
`route_to_model`, `compression_profile`, `inject_mcp`, and
`budget.max_tokens` are omitted from the response entirely when unset,
rather than serialized as `null`.

`POST /admin/keys` accepts the same policy fields as `PATCH` (name,
budgets, allow/block lists, `route_to_model`, `compression_profile`,
`inject_tools`, `inject_mcp`, `principal_selectors`, `tags`, `metadata`,
`tenant`, `expires_at`, `allow_content_capture`, ...) and returns `201`
with `{"token": "<plaintext, shown once>", "key": <KeyView>}`.

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

Returns `{"usage": <GovernanceSnapshot>}`, the same request/token/
budget counters the AI gateway's governance seam reserves against,
read live rather than derived from the log. Returns
`503 {"error":"governance backend unavailable"}` if the governance
store (Redis, for a shared/cluster deployment) cannot be reached; the
key record itself is not at fault in that case.

### `POST /admin/keys/{id}/effective-policy/preview`

Body is an optional sample request shape (`model`, `provider`, `tools`,
`principal`, `origin_tenant_id`, `active_pii_rules`,
`prompt_injection_detected`, `estimated_tokens`, `estimated_micro_usd`,
`usage`, `at`). Every field is optional; an empty body still returns
the resolved policy. Response:

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
  "header": "authorization",
  "scheme": "Bearer ",
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
secret. `header` and `scheme` name the upstream header this credential
is presented in (default `authorization` / `Bearer `; send an empty
`scheme` for a raw-value header such as `x-api-key`); both are set at
creation time and are not among the fields `PATCH` can change.

`POST` bodies accept `vault_ref` *or* `secret` (a plaintext value the
server envelope-seals immediately); supplying neither is a `400`.
`PATCH` also accepts `vault_ref` or `secret` to rotate the material,
but unlike `POST` it does not require either: a `PATCH` body with
neither field present succeeds (`200`) and leaves the existing
material unchanged.

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
| `api_key_id` | string | Canonical public id of the key that governed the request, when one resolved. Matches the access log column, the `sbproxy_inbound_key_requests_total{api_key_id}` label, and the `sbproxy.key_id` span attribute. Never the secret. |
| `key_mode` | string | Inbound credential mode: `none`, `minted`, or `native`. |
| `key_provider` | string | Recognized native provider label, present on `native` rows. |
| `tenant_id` | string | Origin-scoped tenant label (`__default__` when the origin declares none). |
| `user_id` | string | Resolved end-user identifier when user capture resolved one, already capped and redacted. |
| `error_class` | string | Coarse failure class (`auth_denied`, `rate_limited`, `upstream_5xx`, ...). Absent on success. |
| `config_revision` | string | Config revision of the pipeline generation that served the request. |
| `policy_version` | string | Governed key-policy revision that applied, when a key policy resolved. Same vocabulary as the `sbproxy.policy_version` span attribute. |
| `policy_decisions` | array | Bounded, ordered `policy_type:verdict` pairs recorded as enforcers decided. Explains what applied, not just what denied. |
| `deny_reason` | string | Machine-readable reason from the policy, guardrail, or auth layer that denied the request, when one did. |

This is an in-memory ring buffer; entries are lost when the process
exits. For durable request logs, enable the structured access log
(see [access-log.md](access-log.md)).

Supported query parameters: `status` (exact match), `method`
(case-insensitive), `path` (substring), `guardrail_action`,
`guardrail_category`, `cache_status`, `retried`, `property_key`,
`property_value`, `api_key_id` (exact canonical key id), `key_mode`
(`none`, `minted`, or `native`), `session_id` (exact ULID), `offset`,
and `limit` (defaults to and is clamped at
`max_log_entries`). `cache_status` accepts the four values listed above.
`retried` accepts only `true` or `false`. Property matching is exact after
URL decoding; `property_value` requires `property_key`. No parameters returns
the newest entries.

To answer "what did this key do", filter by `api_key_id`; every row a
governed request produced carries the same canonical id across this
ring, the access log, the inbound-key metric, and exported spans.

### `GET /api/requests/{request_id}/content`

Fetch one request's redacted content sample: the prompt messages and
response text retained when the AI origin sets `capture_content: true`
AND the governed key's policy sets `allow_content_capture`. Both flags
default to off and both must be on; unkeyed and native-key traffic is
never sampled.

Admin role required (a read-only operator receives `403`). Every read
is audited before the content is returned: an `inspect_request_content`
event naming the operator lands on the `sbproxy::admin::audit` tracing
target and the `/api/audit/events` sample. `404` means no sample exists
for that request id, either because a gate was off or because the
bounded store (200 samples, at most 50 per tenant, cleared on restart)
has already evicted it.

Samples are redacted before storage: the secret redactor, the origin's
PII redactor when configured, and an 8 KiB payload cap all apply, and
configured credential carriers never reach capture surfaces. The
durable content path is OTLP `trace_content:`; this endpoint is a
runtime inspection sample.

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
| `origins[].targets[].eligible` | bool | True when `healthy && !outlier_ejected && circuit_breaker_state != "open"`; matches what `select_target` honors. |
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

### `GET /api/extensions`

Returns the versioned extension inventory pinned to the pipeline generation
currently serving traffic. The request does not reread `sb.yml` or the bundle
directories, so a rejected reload does not change this view.
Both `admin` and `read_only` operators may call the route.

A shortened response with one directory bundle looks like this:

```json
{
  "schema_version": 1,
  "scope": {
    "mode": "running",
    "proxy_version": "1.9.0",
    "config_revision": "abc123..."
  },
  "summary": {
    "bundles": 1,
    "hooks": 1,
    "active": 1,
    "available": 0,
    "failed": 0,
    "collisions": 0
  },
  "bundles": [
    {
      "id": "hello-javascript",
      "name": "hello-javascript",
      "version": "1.0.0",
      "package": "entry.js",
      "source": "directory",
      "runtime": "javascript",
      "state": "active",
      "hook_ids": ["hello-javascript:action:hello_javascript"],
      "load": {"phase": "candidate_load", "status": "ok", "detail": null}
    }
  ],
  "hooks": [
    {
      "id": "hello-javascript:action:hello_javascript",
      "bundle_id": "hello-javascript",
      "kind": "action",
      "registration": "directory",
      "dispatch": "exclusive",
      "match_key": "hello_javascript",
      "position": 0,
      "state": "active",
      "detail": null,
      "runtime": "javascript",
      "execution": {
        "phase": "request",
        "body_mode": "buffered",
        "timeout_ms": 50,
        "max_buffer_bytes": 1048576
      },
      "capabilities": []
    }
  ],
  "collisions": []
}
```

| Field | Meaning |
|---|---|
| `schema_version` | Version of this response contract. |
| `scope.mode` | Always `running` on this endpoint. `doctor` is the stopped diagnostic mode. |
| `scope.proxy_version` | Proxy binary version that built the snapshot. |
| `scope.config_revision` | Config revision of the serving generation. Use it to correlate reload and request data. |
| `summary` | Counts of bundles, hooks, active hooks, available hooks, failures, and collisions. `failed` counts failed bundles plus failed hooks. |
| `bundles[]` | Stable identity, version, entry filename, registration source, runtime, lifecycle state, hook IDs, and bounded load result. |
| `hooks[]` | Stable identity, hook kind, attachment key, dispatch shape, chain position, state, runtime, execution plan, and declared capabilities. |
| `collisions[]` | Match key, claiming registration IDs, optional winner, and a bounded resolution. A healthy dynamic candidate normally has none. |

Registration sources are `link_time`, `directory`, or `git`. Runtimes are
`rust`, `javascript`, `wasm`, or `proxy_wasm`. Hook states are:

| State | Meaning in the running view |
|---|---|
| `installed` | Linked into the binary, without a more specific running attachment observation. |
| `available` | Loaded and ready for attachment. |
| `active` | Attached to this pipeline generation. `position` is present when the hook participates in a resolved chain. |
| `unconsumed` | Loaded successfully but not attached by this config. |
| `failed` | Load, validation, initialization, or unresolved collision failed. |
| `shadowed` | A higher-precedence registration won a resolved collision. |
| `not_evaluated` | Used by the loader-level doctor fallback when candidate attachment could not be evaluated. |

The response deliberately omits executable bytes, artifact digests, source
paths, hook attachment config, and secrets. A Git bundle's bounded
`load.detail` includes its redacted repository, requested reference, verified
commit, and latest refresh health. A failed refresh reports that the last
verified generation is still serving, without copying the rejected error,
credential reference, or resolved value. This route serves operational metadata
only.

| Status | When |
|---|---|
| `200` | Running snapshot serialized successfully. |
| `401` | Missing or invalid admin authentication. |
| `405` | Method other than GET. |
| `500` | The in-memory snapshot could not be serialized. |

For preflight, run `sbproxy doctor <config> --format json` and inspect its
top-level `extensions` field. That snapshot has `scope.mode: "doctor"` and
uses `active` for hooks selected and wired in the successfully compiled stopped
candidate. This state does not claim traffic execution, runtime health, or a
published generation. Loaded hooks without an attachment are `unconsumed`.
`not_evaluated` means doctor fell back to loader-level inspection because full
candidate construction did not finish. See the
[extension bundle runbook](operator-runbook.md#extension-bundles).

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
`origin`, `agent`, or `property:<key>`), `from`, or `to` (Unix seconds)
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

### `GET /api/admin/users`

The accounts that can sign in to the admin server, with their roles.

```json
{"users": [
  {"username": "admin", "role": "admin", "primary": true},
  {"username": "viewer", "role": "read_only", "primary": false}
]}
```

`primary` marks the top-level `admin.username` credential, which always
carries the full-access `admin` role; the remaining rows are
`admin.operators` entries. Passwords are never included in the response.

This route is read-only by design. Accounts are config, not API state:
add, remove, or re-role one by editing `admin.username` /
`admin.operators` and reloading. The list is built from the same config
`POST /admin/login` authenticates against, so it cannot report an
account that does not work.

### `GET /api/operators`

The operator accounts declared under `admin.operators`, each with its
role. Read-only, like `/api/admin/users`; accounts are config, not API
state. Passwords are never included.

```json
[{"username": "viewer", "role": "read_only"}]
```

An operator scoped to one billing tenant on the meter routes carries an
additional `tenant` field naming that scope; it is omitted for an
operator who may read the whole deployment.

### `GET /api/audit/recent`

Recent rate-limit budget audit rows (suspend, throttle, resume
transitions), newest first. `?limit=` bounds the count (default 50).
Returns `[]` (not an error) when no `rate_limits:` block is
configured, so there is nothing to have audited.

### `GET /api/audit/events`

Unified audit sample across five channels, newest first: `security`
(auth denials and policy violations), `key` (key and credential
lifecycle mutations), `config` (config writes and reloads), `admin`
(sign-ins and every mutating admin action), and `policy` (non-allow
policy verdicts).

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | RFC 3339 timestamp of the event. |
| `channel` | string | One of `security`, `key`, `config`, `admin`, `policy`. |
| `kind` | string | Channel-specific kind: the security event type, the lifecycle operation, the config source, the admin action, or the denying policy type. |
| `actor` | string | Operator who performed the change, on change channels. |
| `tenant_id` | string | Tenant scope, when known. |
| `api_key_id` | string | Canonical public key id the event is attributed to, when one resolved. Never the secret. |
| `request_id` | string | Request correlation id for request-scoped events. |
| `detail` | string | Bounded machine-readable detail: the deny reason, the revision pair, or the status diff. |

Query parameters: `limit` (default 100, capped at 1000), `channel`,
`kind`, and `key_id` (all exact matches).

This is a bounded in-memory sample for runtime inspection: the ring
holds the most recent 1,000 events and clears on restart. The durable
audit trail is whatever your log pipeline or OTel collector ships the
`security_audit`, `key_audit`, `config_audit`, and
`sbproxy::admin::audit` tracing targets to.

### `GET /api/egress`

Returns the versioned egress inventory: every upstream destination the
gateway has reached (or attempted to reach) since process start, with its
most recent authorization outcome. Both `admin` and `read_only` operators
may call the route.

```json
{
  "schema_version": 1,
  "summary": {"total": 3, "denied": 1, "ungated": 1},
  "endpoints": [
    {
      "purpose": "ai_provider",
      "host": "api.openai.com",
      "port": 443,
      "scheme": "https",
      "status": "allowed",
      "last_reason": null,
      "origin": "openai-primary",
      "first_seen_unix_ms": 1755000000000,
      "last_seen_unix_ms": 1755003600000,
      "allowed_count": 42,
      "denied_count": 0
    }
  ]
}
```

| Field | Description |
|---|---|
| `schema_version` | Version of this response contract. |
| `summary.total` | Number of distinct `(purpose, host, port)` destinations tracked. |
| `summary.denied` | Destinations whose most recent sighting was denied. |
| `summary.ungated` | Destinations reached with no authorizer attached. |
| `endpoints[].purpose` | Egress purpose label, for example `ai_provider`. |
| `endpoints[].host`, `port`, `scheme` | Destination, parsed from the reached URL. Never the full URL, query string, or credentials. |
| `endpoints[].status` | `allowed`, `denied`, or `ungated`, the most recent sighting's outcome; `ungated` means no authorizer was attached for that call. |
| `endpoints[].last_reason` | Denial reason, present only when `status` is `denied`. |
| `endpoints[].origin` | Configuration-scoped attribution: an origin id, provider name, or sink name. Never a request-scoped value. |
| `endpoints[].first_seen_unix_ms`, `last_seen_unix_ms` | First and most recent sighting, in Unix milliseconds. |
| `endpoints[].allowed_count`, `denied_count` | Sighting counts by outcome; `allowed` and `ungated` sightings both count toward `allowed_count`. |

The inventory is process-lifetime and in-memory: it clears on restart and
is capped at 1,024 tracked destinations, after which a new destination
stops being tracked while every already-tracked one keeps updating. Every
wired egress purpose writes here: AI providers, the dual-LLM quarantine
judge, OpenAPI-backed MCP tools, token exchange, webhooks, usage sinks,
model and engine artifact downloads, extension bundle hooks, and the
OTLP telemetry exporters. `mcp_upstream` covers the base MCP connect
for a plain `type: mcp` federated server, gated and DNS-pinned at the
dial.

The top-level `egress:` section (see
[Egress allowlists](configuration.md#egress-allowlists)) arms six of
the purposes above through five sub-blocks: `ai_providers` (AI
providers), `usage_sinks` (usage sinks and webhooks, one allowlist for
both), `model_artifacts`, `token_exchange` (the non-MCP token-exchange
resolver only), and `telemetry`. Until a sub-block sets
`mode: deny_by_default`, its purpose stays `ungated`: reached, but
nothing was ever denied because nothing was armed.

Four more purposes arm outside that section, per-tool or per-action:
MCP upstream connects, OpenAPI-backed MCP tools, and the MCP
token-exchange path each take a per-server `egress:` block (see [mcp-security.md](mcp-security.md));
the dual-LLM quarantine judge takes a per-action `egress:` block.
Extension bundle hooks are armed automatically from the bundle's own
outbound grant and never appear as `ungated`.

One purpose cannot be armed by any config today: engine-artifact
downloads pass no authorizer, so they stay `ungated` regardless of
configuration.

| Status | When |
|---|---|
| `200` | Snapshot serialized successfully. |
| `401` | Missing or invalid admin authentication. |
| `405` | Method other than GET. |

### `GET /api/rate_limits/budget`

Per-workspace rate-limit budget state: tier (`Normal`, `Soft`,
`Throttle`, or `AutoSuspend`; capitalized, not the lowercase form the
rest of this API uses) and any active suspend cool-down, from the
`RateLimitBudgetRegistry` snapshot. `404 {"error":"no rate_limits: block configured"}`
when the workspace-budget feature is off.

### `POST /api/rate_limits/resume`

Manually clears a workspace's escalation state back to normal.
Body: `{"workspace": "<id>"}`. Success is `200 {"workspace": "<id>",
"tier": "normal"}`: this route's success body hardcodes a lowercase
`"normal"` literal rather than reusing the capitalized `Normal` value
`GET /api/rate_limits/budget` and `GET /api/rate_limits/effective`
report, so do not pattern-match `tier` case-sensitively across these
three routes. `400` for a missing/empty workspace, `404` when the
workspace has not been tracked (no traffic seen) or no `rate_limits:`
block is configured.

### `GET /api/rate_limits/effective`

Effective requests-per-second ceiling and tier for one workspace right
now: `?workspace=<id>` (defaults to `__default__`).

```json
{"workspace": "__default__", "effective_rps": 1000, "tier": "Normal"}
```

`tier` is `Normal`, `Soft`, `Throttle`, or `AutoSuspend`, same
capitalized vocabulary as `GET /api/rate_limits/budget`. `effective_rps`
drops to `1` while `tier` is `AutoSuspend`.
`404 {"error":"no rate_limits: block configured"}` when unconfigured.

### `POST /api/rate_limits/clock/advance`

**Test/dev-only.** Advances the rate limiter's clock by `?secs=N`
seconds. Success is `200 {"advanced_secs": N}`. This only does
anything when `proxy.rate_limits.clock: manual` is set, a mode that
exists so integration tests can assert token-bucket refill and
suspend-cooldown behavior deterministically, without sleeping in wall
time. Production configs use the default `system` clock, for which
this route returns `400 {"error":"clock is not in manual mode"}`.
`404 {"error":"no rate_limits: block configured"}` when no
`rate_limits:` block is configured at all. There is no reason to call
this against a real deployment.

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

These routes operate on the durable running-summary state used by
`origins[].action.compression` policies on `ai_proxy` handlers. They expose only
the Local, Redis, and mesh adapters captured by the current immutable pipeline
for metadata, deletion, and purge operations. Admin requests never open a Local
database themselves. An existing process-owned Local database remains
discoverable after its last active `summary_buffer` policy is removed, while a
missing dormant path is not created for Admin. Summary-content inspection
additionally requires an active origin policy that opts in. Records use opaque,
canonical 64-character lowercase hexadecimal IDs. See
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
| `backend` | string | `local`, `redis`, or `mesh`. |
| `consistency` | string | `serialized` for Local and Redis records, `eventual_lww` for mesh records. |
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
| `conflict_detected` | bool | Always `false` for serialized Local and Redis backends. On the mesh backend, `true` when the record survived a deterministic merge of competing equal-version updates. |
| `created_at_unix_ms` | int | Creation time in Unix milliseconds. |
| `updated_at_unix_ms` | int | Last update time in Unix milliseconds. |
| `expires_at_unix_ms` | int | Backend expiration time in Unix milliseconds. |
| `kind` | string | `live` for Local and Redis records returned by these endpoints. Mesh records can also report `tombstone` while a replicated deletion marker is retained; tombstone entries carry empty content metadata. |

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
| `backend` | `local`, `redis`, `mesh` | Restrict the scan to one configured backend. Any other value returns `400`. |
| `conflict` | `true`, `false` | Match `conflict_detected`. |
| `cursor` | opaque string | Continue from `next_cursor` returned by the preceding list call. |
| `limit` | positive integer | Page size. Defaults to 100; values above the maximum of 500 are clamped to 500. |

Parameters may appear only once. Unknown or duplicate parameters, invalid
booleans or backends, a zero or non-integer limit, and an invalid cursor return
`400`. Without a backend filter, the cross-store order is Redis, mesh, then
Local, and the Admin cursor carries both the selected store and its opaque
store cursor. Local listing performs a bounded redb scan and returns only
content-free metadata; it never serializes a summary into the
response. Redis listing scans the shared Redis namespace through bounded pages.
Local and Redis expire records at their TTL, so expired records are not
retained as a separate Admin-visible collection and cannot be filtered. Mesh
listing walks the replicated substrate's
topology-safe fleet pagination:
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

`summary` passes through the secret redactor (the same one applied to
captured AI trace content) before it is returned: a summarizer that
echoed a secret the caller pasted into the conversation does not leak
it back out through this route. The stored record itself keeps the
exact, unredacted bytes; only this read path redacts.

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

Deletion runs against every adapter captured by the current pipeline snapshot.
Success is always `200`, including when no live record existed:

```json
{
  "deleted": true,
  "logical_versions": {}
}
```

`deleted` is true when Local or Redis removed live state, or mesh committed a
new tombstone. Local and Redis do not return a logical version. Mesh includes
its tombstone version as `logical_versions.mesh`; with no mesh store the map is
empty. Repeating the delete is safe and returns `"deleted": false` after every
selected backend has already removed or tombstoned the record.

Local atomically removes the record and active lease in one redb transaction;
an in-flight permit then fails closed. Redis atomically removes the record and
lease and advances its retained deletion fence. Mesh writes a replicated
tombstone. A later eligible request with the same captured session can create a
new record; deletion clears summary state, not the caller's session identity.

### `POST /admin/compression/sessions/purge`

Purge deletes one bounded page from the selected adapter. With no backend
filter, continuation advances through Redis, mesh, then Local. The JSON body is
strict and accepts only these fields:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `tenant` | string | unset | Exact tenant scope. Must not be empty. |
| `origin` | string | unset | Normalized origin scope. Must not be empty. |
| `conflict` | bool | unset | Match the record's `conflict_detected` value. This narrows a tenant or origin scope but is not a destructive boundary by itself. |
| `backend` | string | unset | `local`, `redis`, or `mesh`. This narrows execution but is not, by itself, a destructive scope. |
| `cursor` | string | unset | Opaque `next_cursor` from the preceding purge call. It is not a destructive scope. |
| `limit` | int | 100 | Positive page size. Values above the maximum of 500 are clamped to 500. It is not a destructive scope. |
| `all` | bool | `false` | Permit an otherwise unscoped purge. When true, exact confirmation is mandatory. |
| `confirmation` | string | unset | Must equal `purge-compression-sessions` whenever `all` is true. |

Without `all`, at least one of `tenant` or `origin` must be present. `conflict`,
backend, cursor, and limit may narrow that scope but do not establish a deletion
boundary. Requests such as `{"conflict":false}` or `{"backend":"local"}` are
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
detail, purge, and content inspection. Local and Redis deletion can remove
addressed corrupt bytes without returning content. List and detail never return
a partial metadata body on those errors. Delete and purge are idempotent; retry
with the same ID, scope, and cursor after a transient backend failure.

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

Reads and writes the raw on-disk config text. **This node's own file,
not necessarily what is running.** On a node with a `source:` block or
an upstream config authority, see
[`GET /admin/config/effective`](#get-adminconfigeffective) for the
document actually in force; the local file there may be nothing but the
`source:` pointer that selected a repository.

`GET` returns the current YAML plus the loaded revision:

```json
{"yaml": "proxy:\n  http_bind_port: 8080\n...", "revision": "abc123..."}
```

The returned YAML is redacted: any value matching a known secret shape
(API keys, tokens, `password:` and `api_key:` values) comes back as
`[REDACTED]` instead of the plaintext. The same redaction applies to
the `yaml` field of
[`GET /admin/config/effective`](#get-adminconfigeffective). Comments,
formatting, and everything the patterns do not match are returned
byte-for-byte. A config that inlines a secret therefore cannot be
round-tripped through this editor; move the value to a `${VAR}` or
secret-backend reference first (see [secrets.md](secrets.md)).

`PUT`/`POST` validates the submitted YAML, persists it, and hot-swaps
the running pipeline, the same swap `POST /admin/reload` performs,
just sourced from the request body instead of re-reading the file.
Add `?if_match=<revision>` for optimistic concurrency (the write is
rejected with `409` if the loaded revision has moved since the caller
last read it). `400` for a YAML parse failure or a failed pipeline
compile; the config path itself is scrubbed from any error message.
Env-var interpolation (`${VAR}`) and secret-backend references are
stored and echoed back exactly as written. A secret is never
resolved into the saved config or exposed in this editor. See
[secrets.md](secrets.md).

**Ownership guard.** A write whose edits the node's remote layers would
silently discard is refused with `409` and a body naming the paths and
where they are actually set:

```json
{
  "error": "this node does not own the edited path: origins.api.action.url",
  "code": "config_not_locally_owned",
  "conflicts": [{"path": "origins.api.action.url", "owner": "authority"}],
  "layers": {
    "base": {"kind": "local"},
    "authority": {"authority_id": "control-plane", "revision": 12, "mode": "overlay"}
  },
  "remedy": "authority control-plane owns these paths at revision 12; publish the change through the authority with `sbproxy authority publish`"
}
```

Two `409` bodies are possible and they need opposite responses, so
branch on `code` rather than on the status. A revision mismatch has no
`code` and means reload and reapply. `config_not_locally_owned` means
reapplying will fail identically; change it at the source instead.
`config_ownership_unknown` means the merge could not be evaluated, so
the write was refused rather than persisted on a guess.

The guard is per-setting, not per-node. Under `mode: overlay` a write
confined to settings the authority does not set succeeds as it always
did, and adding a setting the authority has never mentioned is allowed.
Under `mode: replace` the subscriber-owned paths (`proxy.admin`,
`proxy.tls`, `proxy.secrets`, and the rest of the deny list) stay
editable, because the authority provably cannot take them. A whole
request is rejected or applied; there is no partial write. See
[configuration.md](configuration.md#the-editor-is-only-live-where-the-node-owns-its-config)
for the full table.

Refusals are recorded in the audit log
(`target=sbproxy::admin::audit`, `outcome=rejected_not_locally_owned`)
alongside the writes that land, so an operator repeatedly editing
configuration they do not own is visible.

| Status | When |
|---|---|
| `200` | Read succeeded, or the write was validated, persisted, and hot-swapped. |
| `400` | Empty body, YAML parse failure, or the config does not compile or construct. |
| `409` | Revision mismatch, or the write touches paths this node does not own. |
| `500` | Could not read or write the config file. The path is scrubbed from the message. |
| `503` | The admin server has no `config_path` wired. |

---

### `GET /admin/config/effective`

The configuration this node is actually running, after the base
document and any authority overlay are merged, plus which layer set
each setting. On a node that owns its own configuration this is the
local file merged with nothing and every setting reports `local`, which
is the answer that tells an editor it may offer a write at all.

```json
{
  "yaml": "proxy:\n  http_bind_port: 8080\n...",
  "provenance": {
    "proxy.http_bind_port": "local",
    "origins.api.action.url": "authority"
  },
  "layers": {
    "base": {"kind": "git", "repo": "https://git.example.com/fleet.git", "reference": "main", "commit": "3f2a9c1..."},
    "authority": {"authority_id": "control-plane", "revision": 12, "mode": "overlay"}
  },
  "locally_owned": false,
  "locally_owned_leaves": 4,
  "total_leaves": 61
}
```

| Field | Type | Description |
|---|---|---|
| `yaml` | string | The merged document. Re-serialized, so comments and original key order are not preserved even when the merge changed nothing. Redacted the same way as [`GET /admin/config`](#get-put-adminconfig): values matching known secret shapes come back as `[REDACTED]`. |
| `provenance` | object | Dotted setting path to the layer that set it. `"local"`, `"authority"`, or `{"git": {"repo", "reference", "commit"}}`. |
| `layers.base` | object | `{"kind": "local"}`, or `{"kind": "git", ...}` with the **resolved** commit rather than the configured reference. |
| `layers.authority` | object | The applied authority payload, or `null`. Reports what is applied, not what is configured; the two differ during exactly the incidents where it matters. |
| `locally_owned` | bool | True only when this node's own file is the whole configuration. An authority configured but never reached reports `false`, because the next poll can claim any path. |
| `locally_owned_leaves` | number | Settings whose provenance is `local`. |
| `total_leaves` | number | Settings in the merged document. |

Read-only operators may call this. A setting reported with owner
`suppressed` in a write conflict has no provenance entry here: under
`mode: replace` a local-only setting is discarded rather than
overwritten.

| Status | When |
|---|---|
| `200` | The effective document was assembled. |
| `500` | The merge failed, so the node is serving whatever it last applied. Body carries `code: effective_config_unavailable` and the layers. |
| `503` | The admin server has no `config_path` wired. |

---

### `GET /admin/config/schema`

The JSON Schema for the config file, generated from the running
binary's own types rather than read off disk. A form built from a stale
schema is wrong in the most expensive way, offering fields the proxy
will reject and hiding fields it would accept, so the served document
cannot be older or newer than the binary serving it. The committed copy
at `schemas/sb-config.schema.json` is byte-identical and CI proves it.

Around 300KB, and immutable for a given build. It is served with a
content-derived `ETag` and `Cache-Control: private, no-cache`, so a
client that sends `If-None-Match` gets `304` on every load after the
first:

```bash
curl -u "admin:${SB_ADMIN_PASSWORD}" -D- -o /dev/null \
  "${SB_ADMIN_URL}/admin/config/schema"
# ETag: "a1b2c3d4e5f6"

curl -u "admin:${SB_ADMIN_PASSWORD}" -o /dev/null -w '%{http_code}\n' \
  -H 'If-None-Match: "a1b2c3d4e5f6"' "${SB_ADMIN_URL}/admin/config/schema"
# 304
```

`no-cache` rather than a long `max-age` is deliberate: the URL carries
no revision, so a cached copy that outlived a binary upgrade would
describe the previous build. Content type is
`application/schema+json`. Read-only operators may call this.

| Status | When |
|---|---|
| `200` | Schema body, with `ETag` and `Cache-Control`. |
| `304` | `If-None-Match` matched the current build's schema. No body. |
| `401` | Not authenticated. |
| `405` | Anything other than `GET`. |

---

### `GET /admin/config/history`

The durable local ring of every config this proxy has applied: content-addressed
entries, newest first, plus the ring's lineage id and which entry (if any) is
marked last-known-good. Requires `proxy.config_history.enabled: true`; see
[configuration.md](configuration.md#config_history) for the block that turns it
on and the retention it applies.

```json
{
  "lineage": "b2b1b8b0-4b8e-4f7a-9b8b-1f0a2c3d4e5f",
  "lkg_revision": 41,
  "entries": [
    {
      "revision": 42,
      "digest": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a5",
      "provenance": "local_file",
      "state": "applied",
      "applied_at": "2026-08-16T10:15:32.456Z",
      "actor": "admin",
      "blast_radius": "reload",
      "degraded": []
    }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `lineage` | string | UUID minted the first time this ring was created. Stable across restarts and `source:` repoints. |
| `lkg_revision` | number or null | Revision number of the entry marked last-known-good, or `null` when nothing has been marked yet. |
| `entries` | array | Newest first. |
| `entries[].revision` | number | Node-local, monotonic. Durable across restart, never reused. |
| `entries[].digest` | string | SHA-256 of the pre-resolution document, lowercase hex, no scheme prefix. |
| `entries[].provenance` | string | `local_file`, `git`, `authority`, or `merged`. |
| `entries[].state` | string | `applied`, `good`, `failed`, or `reverted`. |
| `entries[].applied_at` | string | RFC 3339. |
| `entries[].actor` | string | Operator id, `"boot"`, or the config authority's identity, when known. May be empty. |
| `entries[].blast_radius` | string or null | `hitless`, `reload`, `restart`, or `breaking`, against the previous entry. `null` for the ring's first entry. |
| `entries[].degraded` | array of strings | Subsystems that did not apply cleanly when this revision applied. Empty for a fully applied revision. |

Read-only operators may call this.

| Status | When |
|---|---|
| `200` | Ring read successfully. |
| `404` | `proxy.config_history` is absent or `enabled: false`. Body: `{"error": "config history is not enabled"}`. |

The ring is a local audit trail today. Nothing in this response promotes an
entry, and nothing here moves the `lkg_revision` pointer; see
[operator-runbook.md](operator-runbook.md#config-history-ring) for what the
ring does and does not do yet.

---

### `GET /admin/config/history/{digest}`

One ring entry in full, by its content digest: the entry's metadata, the
stored pre-resolution YAML, and the rendered `plan()` diff against the
config currently running.

```json
{
  "entry": {
    "revision": 42,
    "digest": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a5",
    "provenance": "local_file",
    "state": "applied",
    "applied_at": "2026-08-16T10:15:32.456Z",
    "actor": "admin",
    "blast_radius": "reload",
    "degraded": []
  },
  "document": "proxy:\n  http_bind_port: 8080\n...",
  "plan_text": "~ origins.api.action.url: https://old -> https://new (reload)\n"
}
```

| Field | Type | Description |
|---|---|---|
| `entry` | object | Same shape as one element of `entries[]` in [`GET /admin/config/history`](#get-adminconfighistory). |
| `document` | string | The stored pre-resolution YAML, byte-for-byte. `${VAR}` and `vault://`/`secret://` references appear exactly as written; nothing is resolved. |
| `plan_text` | string | The same terraform-style text diff `sbproxy plan` renders by default, computed between this revision and the config running now. |

Read-only operators may call this.

| Status | When |
|---|---|
| `200` | Entry found. |
| `404` | `proxy.config_history` is absent or `enabled: false` (`{"error": "config history is not enabled"}`), or `digest` names no entry in the ring. |

### `GET`, `PUT` `/admin/log-level`

Runtime tracing-filter control, no restart required.

Official release binaries compile SBproxy's own `debug!` and `trace!` events
out with a static maximum of `info`. This endpoint changes the runtime filter;
it cannot restore events absent from the binary. A `debug` or `trace` filter
may still reveal dependency events compiled without that ceiling. Use a
development build when troubleshooting requires SBproxy-internal debug or
trace events.

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
  "loaded_at": "2026-05-12T10:15:32.456Z",
  "fully_applied": true,
  "degraded": []
}
```

A reload swaps the pipeline as one step, and every check that can
refuse the config runs before that swap. If any of them refuses, the
previous config keeps serving and nothing from the candidate is left
installed.

A few subsystems are allowed to fail without refusing the reload,
because a stale AI catalog is better than a proxy pinned on an old
config: the AI provider registry (`ai_provider_registry`), the dynamic
key plane (`key_plane`), the listings registry (`listings`), and the
sink dispatcher (`sink_dispatcher`). When one of them fails, the swap
still happens, `fully_applied` is `false`, and `degraded` names what
did not take effect:

`degraded` can also carry `pipeline_lifecycle_hook`, kept only as a
compatibility label for older reload responses: atomic candidate
publication now rejects a lifecycle-hook failure before the swap, so
that failure refuses the reload outright (see the status table below)
rather than ever landing in this array on a current build.

```json
{
  "config_revision": "abc123...",
  "loaded_at": "2026-05-12T10:15:32.456Z",
  "fully_applied": false,
  "degraded": ["ai_provider_registry"]
}
```

Treat that as a partial success. The status code is still `200`,
because the config did load, so automation that only checks the status
code will miss it. Check `fully_applied` if you need to know that
everything took effect.

| Status | When |
|---|---|
| `200` | Reload succeeded; pipeline swapped. Check `fully_applied` for whether every subsystem took effect. |
| `400` | YAML parse failed. Error body carries the parse error with the config path scrubbed. |
| `405` | Method other than POST. |
| `409` | Another reload is already in flight. |
| `500` | Could not read the config file (permissions, ENOENT), or pipeline compile failed. |
| `503` | The admin server has no `config_path` wired (in-memory / test mode). |

Two changes need a restart rather than a reload, and both are refused
with a message saying so rather than being applied by halves. Cluster
identity, discovery, listeners, and peer security are process-owned
(see `proxy.cluster`), and so are the secret backends under
`proxy.secrets`: the resolver holding live connections to Vault, AWS,
GCP, or Kubernetes is built once at startup, so a reload that changed
that block would otherwise be ignored while references to a new backend
failed with an unrelated-looking error.

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

**What it means per config source.** This route compares the **local
file** against the last-loaded content hash, which is narrower than
"is this node's configuration current":

| Node shape | `drift: true` means | What it does not tell you |
|---|---|---|
| Local file only | The file changed and has not been reloaded. The full answer. | Nothing missing. |
| `source:` resolving to git | The local `source:` pointer itself changed. | Whether the repository moved. Watch `sbproxy_config_source_revision_info{sha}` and compare against the resolved commit in `GET /admin/config/effective`. |
| Upstream authority | The local base file changed. | Whether the authority published a newer revision. Watch `sbproxy_config_bundle_revision` and `sbproxy_config_bundle_age_seconds`. |
| Git base with an authority overlay | The pointer changed, which is rare and usually a deploy mistake. | Either remote layer. Use both metrics above. |

A node whose repository moved is not "drifted" by this measure, and a
node serving a stale bundle because the authority is unreachable is not
either. Alert on the age gauge for those.

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
operate only on a deployment ID that already exists in desired state,
none of them create or delete a deployment; that is what the
`deployments` PUT and `sb.yml` are for.

### `GET`/`PUT /admin/model-host/deployments` errors

Both routes are served from an always-present runtime handle, even
when `proxy.model_host` is unconfigured (an empty desired state
answers `GET`); there is no manager-absent `404` here. A stale
`expected_revision` is `409 revision_conflict`; a malformed or
unparseable body is `400 invalid_body`; a body that parses but fails
semantic validation (including a deployment referencing an unknown
catalog model or variant) is `400 invalid_desired`,
`400 unknown_catalog_model`, or `400 unknown_catalog_variant`; a
non-`admin_managed` authority (the default `file_managed`, or a
cluster verifier node) returns `403 authority_read_only` explaining
the deployment map is managed elsewhere. See
[model-host.md](model-host.md#authenticated-catalog-and-local-deployment-api)
for the full request schema and validation order.

### `GET /admin/model-host/value`

```json
{
  "models": [{"model": "gpt-4o-mini", "local_completions": 0, "cloud_completions": 42, "saved_micros": 0, "cloud_spent_micros": 8400}],
  "total_saved_micros": 0,
  "total_cloud_spent_micros": 8400,
  "total_local_completions": 0,
  "total_cloud_completions": 42,
  "compression": [{"model": "gpt-4o-mini", "lever": "window_fit", "tokens_saved": 18432, "gross_cost_saved_micros": 2765, "token_count_precision": "model_tokenizer"}],
  "compression_totals": {"window_fit": {"tokens_saved": 18432, "gross_cost_saved_micros": 2765, "token_count_precision": "model_tokenizer"}},
  "total_compression_tokens_saved": 18432,
  "total_compression_gross_cost_saved_micros": 2765
}
```

Empty (all-zero) until a request that is served locally, spills to a
cloud provider, or is compressed completes successfully. A model's
`local_completions` / `saved_micros` and its `cloud_completions` /
`cloud_spent_micros` are the two halves of one split, priced against the
same configured `reference`, so the saved figure is gross and the
difference is net. Both halves are keyed on the model the caller asked
for rather than the id the answering provider billed under. The four
`total_saved_micros` / `total_cloud_spent_micros` /
`total_local_completions` / `total_cloud_completions` fields sum those
same two halves across every model line. See
[model-host.md](model-host.md#value-delivered) for the lane rules.
`compression` is sorted by model and lever;
`compression_totals` aggregates by lever name, carrying the same
`token_count_precision` signal as each `compression[]` entry. A known
target-model tokenizer produces `model_tokenizer` precision; the UTF-8
byte-length fallback produces `heuristic`. Both are sbproxy estimates,
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
is configured, an honest empty inventory rather than an error.

### `POST /admin/model-host/gc`

Runs the same protected LRU sweep the post-pull path runs
automatically, on demand. Protects configured, resident, pinned,
leased, and file-locked artifacts identically to the automatic sweep
and to `DELETE .../artifacts/{digest}`. Returns the collection report
(bytes reclaimed, artifacts removed). `409` when no cache budget is
configured, so there is no target to collect toward.

### `DELETE /admin/model-host/artifacts/{digest}`

`digest` must be 64 lowercase hex characters (a SHA-256); anything
else is `400`. Removal shares the exact protection rules `sbproxy
models remove` enforces, so the API and CLI can never disagree. `404`
when the digest is not in the verified cache; `409` with a stable
`reason` when removal is blocked (e.g. the artifact backs a ready
replica); a manager-open or filesystem failure is `502`.

### `GET /admin/model-host/jobs`, `GET /admin/model-host/jobs/{id}`

Durable async job records for load, evict, stop, drain, and reset:
queued, in-flight, and retained terminal jobs. `POST /admin/model-host/load`
(and its evict/stop/drain/reset siblings) return `202` with a
`{job_id, poll_url}` when a job store is configured; poll the job by id
for state and progress. `404` for an unknown id.

### `GET /admin/model-host/jobs/{id}/stream`

Server-sent-events tail of one durable job: `id:` lines for
`Last-Event-ID` replay, closing when the job reaches a terminal state.
Use it instead of polling to follow a long load to completion.

---

## Cache admin

Two independent operator surfaces on the admin server, unrelated to the
model-host artifact cache above:

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

Body selects the scope. `{"key": "..."}` deletes one entry,
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
that has a semantic (embedding) cache configured, one entry per origin
*and* forward rule (a forward rule with its own `semantic_cache:` block
reports separately rather than being folded into its origin):

```json
{"caches": [{"origin": "ai.example.com", "backend": "redis", "recent": [{"reason": "hit", "score": 0.94, "threshold": 0.85, "at_unix": 1784300000}]}]}
```

A cache scoped to a forward rule additionally carries a `forward_rule`
index alongside `origin` and `backend`. `reason` is `hit`, `no_entry`,
`expired`, `below_threshold`, `incompatible`, or `backend_error`.
`score` is the matched cosine score on a hit, or the closest
candidate's score on a `below_threshold` miss; `null` otherwise.
`at_unix` is the Unix-seconds timestamp of the lookup. `caches: []`
when no origin has an embedding cache configured. See
[local-inference.md](local-inference.md) for the semantic-cache
feature this debugs.

---

## Cluster control plane

### `GET /admin/cluster/status`

Returns one versioned snapshot for the complete cluster view. This is an
authenticated read route and returns `405` for other methods, and
`503 {"error":"cluster owner is not initialized"}` if the process's
cluster owner has not finished starting up yet.

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
configured. The published set is a small, additive allowlist: request
and connection totals, attributed AI tokens and cost, model-host
cold-load and placement signals, the inbound-key request counter
(governed vs native traffic split), and the mesh convergence and health
families (anti-entropy rounds and keys, replication writes and
read-repairs, peer-state transitions, node-isolated, handoff keys).

### `GET /admin/cluster/vram`

Cluster-wide GPU VRAM aggregation per node: total and free bytes per
device, summed across the fleet. Sourced from each node's latest
model-host status snapshot; a node that has reported none is omitted.
`405` for a method other than GET.

### `GET /admin/cluster/artifacts`

Fleet-wide artifact-cache usage: total bytes and artifact count per
node, and total bytes per model across the fleet. Aggregates each
node's latest accepted snapshot from the model directory; a node with
no accepted snapshot yet is omitted from `nodes` and flips the
top-level `partial: true` flag rather than silently under-reporting.
Outside a configured cluster (or when the directory has no other
members), reports the local node's own artifact cache, the same
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

## Config authority

Mounted on the admin listener when the node runs as a config authority.
The authority validates a configuration exactly as boot does, signs it,
stores it under a monotonic revision, and serves it to subscribers.
See [configuration.md](configuration.md) for the authority/subscriber
model.

| Method | Path | Purpose |
|---|---|---|
| POST | `/admin/config-authority/publish?mode=overlay\|replace` | Publish the request body as a signed bundle. Returns the new revision, content digest, and ETag. |
| POST | `/admin/config-authority/rollback` | Republish a previous revision under a new revision number. |
| GET | `/admin/config-authority/status` | Current revision, digest, ETag, signing key id, and each subscriber's last-seen revision. |
| GET, POST | `/admin/config-authority/subscribers` | List subscribers, or register one with `{"subscriber_id": ...}`. |
| POST | `/admin/config-authority/subscribers/revoke` | Revoke by `credential_id`, or all credentials for a `subscriber_id`. |

---

## Admin UI (`GET /admin/ui`, `GET /`)

The admin server serves a full operator dashboard under `/admin/ui/`:
keys and credentials, config editing and drift, the request log (with
live tail), metrics, spend, AI performance, guardrails, prompts, a
chat playground, the response/semantic cache, model host (catalog,
desired-state editing, lifecycle actions), artifact storage, the audit
and rate-limit view, and (despite older notes to the contrary) the
full cluster roster, health rail, and unhealthy-node alerts, reading
`GET /admin/cluster/status` and `GET /admin/cluster/metrics`. See
[admin-ui.md](admin-ui.md) for the page-by-page reference. `GET /`
(and `GET /admin`, `GET /admin/`) redirects with a `302` to
`/admin/ui/`. The redirect is dispatched before the auth gate: the
target carries no data, and requiring credentials just to be told
where the login page lives is a dead end. The SPA then gates itself
and shows its own login. `/admin/ui/` itself, and the rest of
`/admin/*` and `/api/*`, are authenticated as documented above.

The dashboard is only present when the binary was built with it
embedded: build the UI assets first (`cd ui && npm ci && npm run
build`, matching the committed `ui/package-lock.json`), then compile
the proxy with `--features embed-admin-ui`. Default builds skip the
embed and `/admin/ui` returns a `404`. Its body currently tells
operators to run `pnpm install && pnpm build` instead, which does not
match this repo's npm-based `ui/` tree; use the npm commands above.

---

## Prompt store admin (`GET /admin/prompts`, `POST /admin/prompts/...`)

Exposes the runtime prompt-store overlay. `GET /admin/prompts`
returns the in-memory snapshot (every active prompt + pinned
version + last-mutation metadata) as JSON. Two sub-path mutators act
on one `<host>/<name>` prompt: `POST
/admin/prompts/<host>/<name>/versions` adds a new version, and `PUT
/admin/prompts/<host>/<name>/pin` pins which version is the active
default, which is also how an operator rolls back, by pinning a version
older than the current default. Both are `404
{"error":"unknown prompt admin action"}` for any other action segment,
and `405` on the wrong method for the action they do recognize.
Mutations persist to the operator-configured redb file when
`admin.prompt_persistence_path` is set, so changes survive restart.

The full set of request/response shapes is documented in
[ai-gateway.md](./ai-gateway.md) under "Stored prompts". This
reference only catalogs the route surface; the request/response
contracts live with the feature.

---

## Chat playground

Three routes back the dashboard's interactive chat surface. All sit
behind the admin auth and RBAC gate; the two POST routes are mutations,
so they require the `admin` role.

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/api/playground/endpoints` | List every AI origin the live pipeline serves, with each provider's declared models and default model. Read-only, sourced from the compiled pipeline, so a config reload updates it without a restart. |
| POST | `/admin/api/playground/chat` | Run a chat completion against a chosen endpoint by calling the AI client directly. Returns the upstream response plus token usage, cost, and latency. Bypasses the data-plane pipeline (see below). |
| POST | `/admin/api/playground/dispatch` | Run a chat completion as a chosen virtual key by minting a single-use `sbpgtkt_` ticket and making a real loopback call to the data-plane listener, so the full request pipeline applies: the key's policy, governance, routing, guardrails, and transforms. |

The two POST routes differ in what they exercise. `/chat` calls the AI
client directly and does not traverse the data-plane pipeline:
per-origin policies, guardrails, transforms, and the
`x-sbproxy-debug-*` header stamping do not apply. Use it to check that
an upstream and model answer at all.

`/dispatch` is the governed path: it impersonates a virtual key through
a single-use ticket and loops back through the data-plane listener, so
the key's full policy and every pipeline stage apply exactly as they
would for real traffic. It returns `409` when key management is off,
`404` for an unknown key or origin, `403` when the key is not active,
and `501` when the origin requires TLS (`force_ssl`), which the
loopback call cannot satisfy. Pass `"debug": true` in either POST body
to get a `debug` block with a server-logged request id and the config
revision for correlation.

Unauthenticated requests see `401 Unauthorized`. These three routes
match on exact method-and-path pairs in the async connection handler;
a request with the right path but the wrong verb (`GET` on `/chat` or
`/dispatch`, `POST` on `/endpoints`) does not hit a dedicated
"wrong method" branch, falls through to the same catch-all as an
unrecognized path, and comes back `404 {"error":"Not Found"}` rather
than `405`.

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

# Inspect extensions attached to the serving generation.
curl -s -u admin:secret \
  http://127.0.0.1:9090/api/extensions \
  | jq '{scope,summary,bundles,hooks,collisions}'

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
