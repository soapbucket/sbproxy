# Admin API reference

*Last modified: 2026-07-19*

The embedded admin server publishes a small set of HTTP routes for
operator tooling: liveness probes, request log, per-target health, managed
model and cluster state, hot reload, drift detection, and the emitted OpenAPI
document.

This page is the per-route reference. For the operator workflow
(enabling the server, picking a port, IP allowlisting), see
[manual.md section 9 - Hot reload](manual.md#9-hot-reload) and
[manual.md section 5 - Metrics and observability](manual.md#5-metrics-and-observability).

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
and global caps. The per-IP cap is 60 requests / minute by default;
the global cap is 10x that (600 / minute). A request that exceeds
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
    "method": "GET",
    "path": "/v1/orders?limit=10",
    "status": 200,
    "latency_ms": 42.7,
    "client_ip": "10.0.0.5"
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

This is an in-memory ring buffer; entries are lost when the process
exits. For durable request logs, enable the structured access log
(see [access-log.md](access-log.md)).

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
| `backend` | string | `redis`. |
| `consistency` | string | `serialized`. |
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
| `conflict_detected` | bool | Always `false` for the current serialized Redis backend. Retained for metadata compatibility. |
| `created_at_unix_ms` | int | Creation time in Unix milliseconds. |
| `updated_at_unix_ms` | int | Last update time in Unix milliseconds. |
| `expires_at_unix_ms` | int | Backend expiration time in Unix milliseconds. |
| `kind` | string | `live` for Redis records returned by these endpoints. |

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
| `backend` | `redis` | Restrict the scan to Redis. Any other value returns `400`. |
| `conflict` | `true`, `false` | Match `conflict_detected`. |
| `cursor` | opaque string | Continue from `next_cursor` returned by the preceding list call. |
| `limit` | positive integer | Page size. Defaults to 100; values above the maximum of 500 are clamped to 500. |

Parameters may appear only once. Unknown or duplicate parameters, invalid
booleans or backends, a zero or non-integer limit, and an invalid cursor return
`400`. Redis listing scans the shared Redis namespace through bounded pages and
an opaque cursor. Redis expires records at their TTL, so expired records are
not retained as a separate Admin-visible collection and cannot be filtered.

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

## Control routes (authenticated)

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

The admin server serves a browser dashboard at `/admin/ui` for
configuration inspection, drift status, recent requests, and the
runtime prompt-store overlay (see `/admin/prompts` below). `GET /`
does not redirect there; it returns a small static HTML landing page
(`200 text/html`) that lists the main API endpoints. Both routes are
authenticated like the rest of `/api/*` and `/admin/*`.

The dashboard is only present when the binary was built with it
embedded: build the UI assets first (`cd ui && pnpm install && pnpm
build`), then compile the proxy with `--features embed-admin-ui`.
Default builds skip the embed and `/admin/ui` returns a `404` whose
body spells out those two steps.

The current UI does not yet render the cluster roster or mutate model desired
state. The operator-product PR will consume `GET /admin/cluster/status` for a
cluster summary, complete node table, and prominent unhealthy-node callouts,
then add mode-aware model selection and deployment management. The API and CLI
contracts above are available before that UI lands.

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

- [manual.md](manual.md) - install, CLI, hot reload workflow.
- [admin.md](admin.md) - admin listener, authentication, roles, TLS, and operator workflows.
- [configuration.md](configuration.md) - the `proxy.admin:` block.
- [ai-context-compression.md](ai-context-compression.md) - compression policy, external state, and degradation behavior.
- [openapi-emission.md](openapi-emission.md) - the emitted OpenAPI document's shape and per-origin mapping.
- [access-log.md](access-log.md) - the durable structured request log.
- [metrics-stability.md](metrics-stability.md) - the Prometheus `/metrics` surface.
- [audit-log.md](audit-log.md) - tamper-evident log of admin actions.
