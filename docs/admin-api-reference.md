# Admin API reference

*Last modified: 2026-06-06*

The embedded admin server publishes a small set of HTTP routes for
operator tooling: liveness probes, request log, per-target health,
hot reload, drift detection, and the emitted OpenAPI document.

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
    password: !env ADMIN_PASSWORD
    max_log_entries: 1000
```

When `enabled: false` (the default) the admin listener does not bind
and every route below is unreachable. The server binds on
`127.0.0.1:<port>` so the admin surface is loopback-only by default;
expose it via a reverse proxy or sidecar with an IP allowlist when an
operator console needs remote access.

## Authentication

Routes split into two tiers:

- **Unauthenticated probe routes** are reachable without credentials so
  load balancers and orchestrators can probe liveness without
  configuring secrets: `/healthz`, `/health`, `/readyz`, `/ready`,
  `/livez`, `/live`, `/.well-known/sbproxy/quote-keys.json`.

- **Authenticated routes** require HTTP Basic auth using the
  `username` and `password` from the config block. Every route under
  `/api/*` and `/admin/*` is in this tier.

Send credentials with `curl -u admin:secret <url>` or an
`Authorization: Basic <base64(user:pass)>` header.

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
credentials, `405` for wrong method on a method-gated route, `409`
when a hot reload is already in flight, `429` when rate-limited,
`5xx` for server-side failures.

---

## Probe routes (unauthenticated)

### `GET /healthz`

Kubernetes-style liveness probe. Returns `200` with body
`{"status":"ok"}` whenever the process is up. Does **not** consult
the live config or any dependency; treat it as "the process is
running and the listener accepted my connection".

### `GET /health`

Component-aware liveness with version and git SHA. Returns `200`
with a JSON document that includes the proxy version, build commit,
and a per-component status table:

```json
{
  "status": "ok",
  "version": "1.1.0",
  "commit": "abc1234",
  "components": [
    {"name": "config", "status": "ok"},
    {"name": "cache_store", "status": "ok"}
  ]
}
```

A component reporting `"status": "degraded"` returns the same `200`
because the proxy still serves traffic on degraded components.
Components in `"status": "failed"` flip the top-level status.

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
Prometheus `/metrics` endpoint exposed on the health port (see
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

## Control routes (authenticated)

### `POST /admin/reload`

Re-reads `proxy.admin.config_path` from disk, recompiles the
pipeline, and hot-swaps the in-memory pipeline. The route uses the
same single-flight guard as the file watcher, so a manual reload
during a file-watcher reload returns `409`.

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

Compares the on-disk config file at `proxy.admin.config_path`
against the content hash captured the last time the proxy loaded a
config (startup, file-watcher reload, or `POST /admin/reload`). Use
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

## Admin UI (`GET /admin/ui`, `GET /`)

The OSS admin server serves a minimal browser UI at `/admin/ui` for
configuration inspection, drift status, recent requests, and the
runtime prompt-store overlay (see `/admin/prompts` below). `GET /`
redirects to `/admin/ui` so browsing to the admin port lands on the
UI without typing the path. Both routes are authenticated like the
rest of `/api/*` and `/admin/*`.

Response: `200 text/html`. The UI is a static SPA bundled into the
binary; it does not require a separate build step or asset directory.

---

## Prompt store admin (`GET /admin/prompts`, `POST /admin/prompts/...`)

Exposes the runtime prompt-store overlay. `GET /admin/prompts`
returns the in-memory snapshot (every active prompt + pinned
version + last-mutation metadata) as JSON. `POST /admin/prompts`
mutators add a new version, pin a version, or roll back; mutations
persist to the operator-configured redb file when `admin.prompt_store_path`
is set, so changes survive restart.

The full set of POST shapes and request schemas is documented in
[ai-gateway.md](./ai-gateway.md) under "Stored prompts". This
reference only catalogues the route surface; the request/response
contracts live with the feature.

---

## Chat playground (`POST /admin/api/playground/chat`)

A stub handler for the dashboard's interactive chat surface. The
admin UI scaffold + cargo feature ship today; the wiring that
routes the request through `proxy_router.oneshot` and streams a
model's response back is deferred to a follow-up ticket so the
front-end scaffold and the production integration can land
independently.

Today the route returns `501 Not Implemented` with a JSON envelope
naming the follow-up:

```json
{
  "error": "not implemented",
  "detail": "chat playground stub; real handler will route through proxy_router.oneshot and stream the model response back to /admin/ui"
}
```

Other verbs return `405 Method Not Allowed`. The route shares the
admin port's basic-auth gate, so a curious operator pinging it
without credentials still sees `401 Unauthorized` first.

This route is OSS, ships in every build, and lives on the admin
server (next to `/admin/reload`) rather than the production proxy
listener. The path is stable; the follow-up that lights up the
real handler does not move it.

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
- [configuration.md](configuration.md) - the `proxy.admin:` block.
- [openapi-emission.md](openapi-emission.md) - the emitted OpenAPI document's shape and per-origin mapping.
- [access-log.md](access-log.md) - the durable structured request log.
- [metrics-stability.md](metrics-stability.md) - the Prometheus `/metrics` surface.
- [audit-log.md](audit-log.md) - tamper-evident log of admin actions.
