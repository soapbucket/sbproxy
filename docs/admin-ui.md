# Admin UI

*Last modified: 2026-07-19*

The built-in admin UI is a Vue 3 + Vite single-page app that drives the
same [admin API](admin-api-reference.md) any curl script can call — it
adds no server-side behavior of its own. This page is the operator
guide: what each page shows, what it can mutate, and which API paths
back it. For enabling the admin server itself (port, TLS, roles), see
[admin.md](admin.md); for the raw route contracts, see
[admin-api-reference.md](admin-api-reference.md).

## Build and enable it

The UI is off by default and lives behind a cargo feature, so a lean
binary carries no front-end assets:

```bash
cd ui
npm ci
npm run build          # writes ui/dist/

cd ..
cargo build -p sbproxy --release --features embed-admin-ui
```

`npm run build` produces a hashed `index.html` plus `assets/*` under
`ui/dist/`; the `embed-admin-ui` feature embeds that directory into
the binary via `include_dir!` at compile time and mounts
`/admin/ui/*` on the admin server. Skip the feature and `/admin/ui`
returns a `404` whose body names the two commands above — the default
build never requires a prior `npm run build` to succeed.

Then, with the admin server enabled (see [admin.md](admin.md#enabling-it)),
open:

```text
http(s)://<bind>:<port>/admin/ui/
```

The UI is served under the `/admin/ui/` base (Vue Router runs in
history mode with that base; the admin server does SPA fallback to
`index.html` so deep links and page refreshes resolve without a
server-side rewrite map).

## Login

![The admin sign-in form: username and password fields on a plain card](assets/admin-login.png)

On load, the app calls `GET /admin/session` to recover an existing
session (surviving a page refresh); while that is in flight it shows a
brief loading state rather than flashing the login form. Unauthenticated,
it renders a username/password form that calls `POST /admin/login`.
Success sets the `HttpOnly` session cookie and stores the returned CSRF
token in memory for subsequent mutations; a wrong password surfaces
"Invalid username or password," other failures show the raw error. The
signed-in identity's username and role (`admin` or `read_only`) render
in the sidebar footer, with a Sign out control that calls
`POST /admin/logout`.

The UI does not hide pages or controls based on role — a `read_only`
operator sees every page and every button. Attempting a mutation as
`read_only` still round-trips to the server, which returns `403`; the
page's error state renders that response rather than pre-empting it
client-side. See [admin-api-guide.md](admin-api-guide.md#authenticating-basic-vs-session--csrf)
for the full login/CSRF contract this drives.

## Overview (`/`)

![The Overview page: health ok, per-component checks, a request-log count, and the model host section](assets/admin-overview.png)

Live health with per-component checks, version and uptime, a
request-log count, and the local model host at a glance.

- **Shows:** `GET /health` (status, version, build, uptime,
  per-component checks), `GET /api/stats` (request-log entry count),
  `GET /admin/model-host/status` (serving summary).
- **Mutations:** none.
- **Empty/error notes:** a component reporting `not_configured` is
  expected on a minimal config and renders as informational, not an
  error; only an `unhealthy` component or a fetch failure renders the
  error state.

## Keys (`/keys`)

![The Keys page: three active keys in a table with per-key Edit, Rotate, Block, Revoke, and Delete buttons](assets/admin-keys.png)

Every virtual key with its status, policy summary, budget, and expiry,
with the full lifecycle inline.

- **Shows:** `GET /admin/keys` (the table), `GET /admin/keys/policy-schema`
  (drives the create/edit form's fields and validation, read once).
- **Mutations:** `POST /admin/keys` (create — the plaintext token
  renders once in a copy-once modal and is never retrievable again),
  `PATCH /admin/keys/{id}` (edit policy, gated by `expected_revision`),
  `POST /admin/keys/{id}/revoke|block|unblock|rotate`,
  `DELETE /admin/keys/{id}`. The edit modal also calls
  `POST /admin/keys/{id}/effective-policy/preview` live as you edit, so
  you can see the resolved policy before saving. A usage panel calls
  `GET /admin/keys/{id}/usage` for live request/token/budget counters.
- **Empty/error notes:** a revision conflict on save (someone else
  edited the key concurrently) shows the conflicting server state
  inline rather than silently overwriting it; a `409` on revoke/block
  on an already-revoked key surfaces as "revoked key is terminal." No
  keys configured renders an empty-table state, not an error — this is
  normal until `key_management` mints its first key. If
  `key_management` has no keystore backend configured at all, every
  call here returns `409`, surfaced as "Policy controls unavailable."

## Credentials (`/credentials`)

Upstream provider secrets: metadata only, never the secret itself.

- **Shows:** `GET /admin/credentials`.
- **Mutations:** `POST /admin/credentials` (create — a secret is
  either a `vault_ref` or a plaintext value the server envelope-seals
  immediately; either way it is sent once and never shown back),
  `PATCH /admin/credentials/{id}`, `POST /admin/credentials/{id}/revoke|block|unblock`,
  `DELETE /admin/credentials/{id}`.
- **Empty/error notes:** same `409` behavior as Keys when no key plane
  is configured; an empty list is normal, not an error.

## Config (`/config`)

The running configuration: the emitted OpenAPI surface, on-disk drift,
per-target health, and a raw config editor.

![The Config page: OpenAPI summary, a drift badge, and a reload control](assets/admin-config.png)

- **Shows:** `GET /api/openapi.json` (a readable summary plus the raw
  JSON), `GET /admin/drift` (in-sync or drifted badge with the
  content-hash diff), `GET /api/health/targets` (per-target health),
  `GET /admin/config` (the raw on-disk YAML, loaded into an editor on
  demand).
- **Mutations:** `POST /admin/reload` (behind a confirm dialog — this
  re-reads the config file from disk and hot-swaps the pipeline),
  `PUT /admin/config` (writes the editor's text back, with `if_match`
  set to the revision it was loaded at, so a concurrent edit surfaces
  as a conflict instead of clobbering).
- **Empty/error notes:** `GET /admin/drift` returning `503` (no
  `config_path` wired — an in-memory/test boot) renders as "drift
  unavailable," not an error banner; a reload while another reload is
  in flight (`409`) surfaces as "reload already in progress."

## Logs (`/logs`)

![The Logs page: recent requests with method, path, status, and duration, plus a tracing-level control](assets/admin-logs.png)

The queryable view over the recent-request ring buffer, with a live
tail and a runtime log-level control.

- **Shows:** `GET /api/requests` as a client-filterable table (method,
  status, path substring; a `guardrail_action` query param arrives
  pre-filled when you follow the "Blocked requests" link from
  Guardrails), `GET /api/ui-settings` (the trace-URL template used to
  link a request's trace id out to your tracing backend).
- **Mutations:** none directly on request data; `GET`/`PUT
  /admin/log-level` reads and sets the live tracing filter (e.g.
  `debug` or `sbproxy_ai=debug`) without a restart.
- **Live tail:** toggling it opens `GET /api/requests/stream`
  (Server-Sent Events) and appends new rows as they complete; the UI
  shows a "reconnecting" state if the stream drops and retries.
- **Empty/error notes:** an empty ring buffer (fresh process, no
  traffic yet) renders an empty state; the ring buffer is in-memory
  and resets on restart — for durable logs, see [access-log.md](access-log.md).

## Metrics (`/metrics`)

![Metrics: stat tiles and bars summarizing key sbproxy_* series, plus a raw view](assets/admin-metrics.png)

A read of the Prometheus `/metrics` endpoint, parsed client-side.

- **Shows:** `GET /metrics` (the full Prometheus exposition text),
  summarized into stat tiles and simple bars for a handful of key
  `sbproxy_*` series, plus a raw-text view for anything not
  summarized.
- **Mutations:** none.
- **Empty/error notes:** a series with no samples yet (no traffic of
  that kind) simply does not render its tile — this page never treats
  "no data" as an error, only a fetch failure does.

## Spend (`/spend`)

*Screenshot pending for Spend by model, provider, and key, plus a windowed history chart (`assets/admin-spend.png`). Capture with `node scripts/capture-admin-screenshots.mjs` against a live `embed-admin-ui` binary.*

Estimated AI cost: live totals since process start, plus durable
windowed history.

- **Shows:** `GET /metrics` for live totals and breakdowns (by model,
  provider, API key, team, project — attribution partitions are
  omitted from a breakdown when the label is absent, not shown as a
  zero row), `GET /api/usage/spend?window=...&group_by=...` for the
  durable rollup history chart, which survives a restart unlike the
  live counters.
- **Mutations:** none.
- **Empty/error notes:** no AI traffic yet renders an empty state; a
  `window`/`group_by` combination with no matching rollup data renders
  an empty chart, not an error.

## AI performance (`/ai-performance`)

*Screenshot pending for Latency percentiles and provider health tiles (`assets/admin-ai-performance.png`). Capture with `node scripts/capture-admin-screenshots.mjs` against a live `embed-admin-ui` binary.*

Serving latency (time-to-first-token, inter-token latency, throughput)
and provider health from the live counters.

- **Shows:** `GET /metrics`, specifically the TTFT/TPOT/throughput
  histograms, per-provider request/error counts and error rate,
  failover reasons, cascade-tier outcomes, and router-strategy
  decisions.
- **Mutations:** none.
- **Empty/error notes:** no AI traffic renders an empty state
  explaining that panels light up after the first request through an
  `ai_proxy` origin; streaming-latency panels specifically need at
  least one streamed completion (TPOT needs at least two tokens in
  that stream) and say so rather than showing a misleading zero.

## Guardrails (`/guardrails`)

*Screenshot pending for Guardrail block counts by category, plus wasted-spend panels (`assets/admin-guardrails.png`). Capture with `node scripts/capture-admin-screenshots.mjs` against a live `embed-admin-ui` binary.*

Governance outcomes: what the guardrail, WAF, and object-authz planes
blocked, and what wasted spend the gateway flagged.

- **Shows:** `GET /metrics` — guardrail blocks by category, streaming
  guardrail violations, context-poisoning findings, WAF/HTTP-framing/
  object-authz blocks, and wasted tokens/cost by kind (duplicate
  requests, abandoned streams, validation failures, context bloat,
  failover losers).
- **Mutations:** none. A "Blocked requests in Logs" action link jumps
  to Logs pre-filtered by `guardrail_action=block`.
- **Empty/error notes:** no guardrail activity since start renders an
  empty state pointing at the AI gateway guardrails config, not an
  error — this is the expected state for a config with no guardrails
  declared.

## Prompts (`/prompts`)

The prompt overlay snapshot: managed prompt versions per host and
name, and which version is pinned.

- **Shows:** `GET /admin/prompts`.
- **Mutations:** `POST /admin/prompts/{host}/{name}/versions` (add a
  version), `PUT /admin/prompts/{host}/{name}/pin` (pin the default).
  Persisted to the operator-configured redb file only when
  `proxy.admin.prompt_persistence_path` is set; otherwise mutations
  are in-memory and reset on restart.
- **Empty/error notes:** no prompts registered is an empty state, not
  an error.

## Playground (`/playground`)

![The Playground page: endpoint picker, chat input, and a response panel with usage/cost/latency](assets/admin-playground.png)

Send a chat completion to any AI endpoint this server is configured
with, and see the response, token usage, cost, and latency.

- **Shows:** `GET /admin/api/playground/endpoints` (every AI origin
  the live pipeline serves, with each provider's declared models).
- **Mutations:** `POST /admin/api/playground/chat` — requires the
  `admin` role (a `read_only` operator gets `403` here even though the
  endpoint list is read-only). Calls the same AI client the data plane
  uses, so usage, cost, and latency are real, but it does **not**
  traverse the data-plane pipeline: per-origin guardrails, transforms,
  and routing policy do not apply here. A debug toggle adds a
  `request_id` and the config revision to the response for
  server-log correlation.
- **Empty/error notes:** no AI origins configured is an empty state
  ("nothing to talk to yet"); an upstream failure surfaces the
  provider's error, not a generic one.

## Cache (`/cache`)

![Response-cache status with purge controls, plus semantic-cache decisions](assets/admin-cache.png)

Response-cache status and eviction, plus dynamic key-policy cache
invalidation and semantic-cache debugging.

- **Shows:** `GET /admin/cache` (enabled, backend, whether prefix
  purge is supported), `GET /admin/cache/semantic` (recent embedding
  cache hit/miss decisions per AI origin), `GET /metrics` (cache-
  related counters shown alongside).
- **Mutations:** `POST /admin/cache/purge` (all / by exact key / by
  prefix — prefix purge is disabled in the UI when the backend does
  not support it), `POST /admin/cache/key-policy/evict` (one key or
  all).
- **Empty/error notes:** `{"enabled": false}` (no origin turned on
  response caching) renders as "not enabled," not an error; purge
  against a disabled cache returns `409` and renders the same way; no
  origin has a semantic cache configured renders that panel empty.

## Model host (`/model-host`)

![Model host: catalog, desired deployments, and runtime status in one view](assets/admin-model-host.png)

Desired model deployments and local runtime residency, controlled from
one operational view — including, on a cluster authority node, signed
fleet-wide deployment publication.

- **Shows:** `GET /admin/model-host/catalog` (bundled models and exact
  variants with support evidence), `GET /admin/model-host/deployments`
  (the desired-state document: authority, read-only flag, revision),
  `GET /admin/model-host/status` (runtime state per deployment),
  `GET /admin/cluster/status` and `GET /admin/cluster/deployments`
  (cluster roster and the signed deployment bundle, when clustered).
- **Mutations:** `PUT /admin/model-host/deployments` (add/edit/remove
  a deployment — only under `admin_managed` authority; compare-and-
  swap on `expected_revision`), `POST /admin/cluster/deployments` (on
  an authority node, publish the signed complete map),
  `POST /admin/model-host/load|stop|reset` (per-deployment lifecycle).
- **Empty/error notes:** under `file_managed` authority (the deployment
  map is owned by `sb.yml`) or as a cluster verifier node, the save
  action is replaced with an explanation of why this node is read-only
  instead of a form. A revision conflict on save keeps the submitted
  form and the conflicting server state both visible and requires an
  explicit retry — it never silently discards your edit or silently
  overwrites the server's. Removal is blocked while a deployment's
  runtime evidence is stale or it is ready/preparing/draining, with the
  reason shown inline.

## Storage (`/storage`)

Verified model weights in the artifact cache: what is on disk, what is
resident, and what can be reclaimed.

- **Shows:** `GET /admin/model-host/files` (cache root, total bytes,
  per-artifact size, last-accessed time, and whether it currently
  backs a ready replica).
- **Mutations:** `DELETE /admin/model-host/artifacts/{digest}` (remove
  one artifact — blocked with a stated reason if it is configured,
  resident, pinned, leased, or file-locked), `POST /admin/model-host/gc`
  (protected LRU collection down to the configured cache budget).
- **Empty/error notes:** no model host configured renders an empty
  inventory (`cache_root: null`), not an error; GC with no configured
  cache budget returns `409` and disables the control with a tooltip
  explaining there is no target to collect toward.

## Audit (`/audit`)

Rate-limit budget actions (suspend, throttle, resume) with the reason
each fired.

- **Shows:** `GET /api/audit/recent?limit=100`, `GET /api/rate_limits/budget`
  (per-workspace tier and cool-down state).
- **Mutations:** `POST /api/rate_limits/resume` (manually clear a
  workspace's escalation back to `normal`).
- **Empty/error notes:** no `rate_limits:` block configured returns an
  empty audit list and a `404` on the budget snapshot — both render as
  "not configured," not an error, since there is nothing to audit.

## Cluster (`/cluster`)

*Screenshot pending for Cluster roster, health rail, and unhealthy-node alerts (`assets/admin-cluster.png`). Capture with `node scripts/capture-admin-screenshots.mjs` against a live `embed-admin-ui` binary.*

Membership, model placement, and rollout health across the fleet.

- **Shows:** `GET /admin/cluster/status` (the complete node roster —
  including failed/excluded members, never hidden to make the fleet
  look healthier — a health rail, prominent unhealthy-node alerts, and
  per-deployment placement/rollout detail), `GET /admin/cluster/metrics`
  (fleet-aggregated metrics, shown separately so a metrics-tier outage
  never hides roster or rollout evidence).
- **Mutations:** none on this page — publishing a signed deployment
  bundle happens from Model host. This page is read-only status and
  alerting.
- **Empty/error notes:** outside a configured cluster, this renders a
  single-node view rather than an error (there is a "fleet" of one).
  A metrics-endpoint `404` (mesh metrics tier not configured) renders
  "metrics not enabled" without blocking the roster/health sections,
  which come from a separate call.

## See also

- [admin-api-guide.md](admin-api-guide.md) - the task-oriented API walkthrough this UI is a client of.
- [admin-api-reference.md](admin-api-reference.md) - every route this UI calls, in full.
- [admin.md](admin.md) - enabling the admin server, TLS, roles, and the security checklist.
- [key-management.md](key-management.md) - the policy model behind the Keys page.
- [model-host.md](model-host.md) - the config behind the Model host and Storage pages.
