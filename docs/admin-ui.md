# Admin UI

*Last modified: 2026-08-20*

The built-in admin UI is a Vue 3 + Vite single-page app that drives the
same [admin API](admin-api-reference.md) any curl script can call. It
adds no server-side behavior of its own. This page is the operator
guide: what each page shows, what it can mutate, and which API paths
back it. For enabling the admin server itself (port, TLS, roles), see
[admin.md](admin.md); for the raw route contracts, see
[admin-api-reference.md](admin-api-reference.md).

The chrome is constant across pages. A top bar shows the admin host,
a live dot that turns red if `GET /health` stops answering, and the
cluster size from `GET /admin/cluster/status` ("live · 3 nodes"), so
a mesh that loses a node is visible from any page. Actions confirm or
fail through toast notifications in the bottom-right corner: a
mutation that succeeds says what it did ("Key revoked"), and one that
fails names the action and carries the server's hint. Validation
detail that belongs next to a form (a config document that failed to
compile, a policy revision conflict) stays inline instead.

Every page header includes a Documentation link for that view. These
are passive external anchors to `https://sbproxy.dev/docs/`: the
console does not fetch or preload documentation, and the destination
opens in a new tab. This is an intentional air-gapped behavior. If the
browser cannot reach the public site, only the new tab fails to load;
the console and every control in it remain operational. Air-gapped
operators can mirror the same Markdown from this repository's `docs/`
directory into an internal documentation service.

Pages that refresh on a timer keep the last good data on screen when a
refresh fails, rather than blanking a dashboard over one bad response.
Because that would otherwise go stale in silence, the first failure of
a streak raises an error toast naming what stopped refreshing
("Refreshing alerts failed"); recovery is silent, and a second failure
after a recovery reports again. Polling pauses while the browser tab is
hidden and catches up immediately when you return, so a console left
open overnight neither burns requests nor shows you yesterday's numbers.

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
returns a `404` whose body names the two commands above; the default
build never requires a prior `npm run build` to succeed.

`crates/sbproxy-core/build.rs` declares `ui/dist` as an input, so
changing the UI invalidates the crate and the next `cargo build` picks
it up. That script exists because cargo cannot see through
`include_dir!` to the files it reads: without it, `npm run build`
followed by `cargo build` produced a binary carrying the *previous* UI,
with nothing failing and nothing warning. The browser simply served a
stale page, and rebuilding again did not help, because cargo still
considered the crate fresh. If you are debugging a UI change that will
not appear, check that you rebuilt with the feature on before
suspecting the cache.

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

Hitting the admin server's root (`/`, `/admin`) redirects to the
console at `/admin/ui/`, so the bare host in a browser lands somewhere useful
instead of on an API 404. From there, any page you open without a live
session sends you to `/admin/ui/login` with the page you wanted preserved in
the `next` query parameter, and signing in returns you to it.

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

A session that expires while you are working is caught wherever it
surfaces: any request answered `401` clears the stored session and
redirects to the login form with a note that the session expired,
instead of leaving a page half-loaded with an error nobody can act on.

The UI does not hide pages or controls based on role: a `read_only`
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

## Get started (`/get-started`)

The shortest path from an empty model host to a running local model.
It presents deployable catalog variants, writes the selected deployment
to desired state, starts it, and follows the resulting durable job.

- **Shows:** `GET /admin/model-host/catalog`,
  `GET /admin/model-host/deployments`, `GET /admin/model-host/status`,
  and `GET /admin/model-host/jobs`.
- **Mutations:** `PUT /admin/model-host/deployments` followed by
  `POST /admin/model-host/load` for the chosen deployment.
- **Empty/error notes:** an empty catalog explains that no deployable
  variants are configured. File-managed or cluster-verifier desired
  state remains read-only and names the authority that must be changed.
  Once a load is queued, the page shows its current job state and links
  to the Jobs view for the full history.

## Keys (`/keys`)

![The Keys page: three active keys in a table with per-key Edit, Rotate, Block, Revoke, and Delete buttons](assets/admin-keys.png)

Every virtual key with its status, policy summary, budget, and expiry,
with the full lifecycle inline.

- **Shows:** `GET /admin/keys` (the table), `GET /admin/keys/policy-schema`
  (drives the create/edit form's fields and validation, read once).
- **Mutations:** `POST /admin/keys` (create: the plaintext token
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
  keys configured renders an empty-table state, not an error; this is
  normal until `key_management` mints its first key. If
  `key_management` has no keystore backend configured at all, every
  call here returns `409`, surfaced as "Policy controls unavailable."

## Credentials (`/credentials`)

![The Credentials page: provider secrets as metadata rows with lifecycle actions](assets/admin-credentials.png)

Upstream provider secrets: metadata only, never the secret itself.

- **Shows:** `GET /admin/credentials`.
- **Mutations:** `POST /admin/credentials` (create: a secret is
  either a `vault_ref` or a plaintext value the server envelope-seals
  immediately; either way it is sent once and never shown back),
  `PATCH /admin/credentials/{id}`, `POST /admin/credentials/{id}/revoke|block|unblock`,
  `DELETE /admin/credentials/{id}`.
- **Empty/error notes:** same `409` behavior as Keys when no key plane
  is configured; an empty list is normal, not an error.

## Config (`/config`)

The running configuration: where it comes from, the emitted OpenAPI
surface, on-disk drift, per-target health, and a raw config editor.

![The Config page: OpenAPI summary, a drift badge, and a reload control](assets/admin-config.png)

- **Shows:** `GET /admin/config/effective` (a Configuration source
  panel: a Local or Managed elsewhere badge, the resolved git commit
  and the applied authority revision where they apply, how many
  settings this node owns, and an expandable list of the ones set
  elsewhere), `GET /api/openapi.json` (a readable summary plus the raw
  JSON), `GET /admin/drift` (in-sync or drifted badge with the
  content-hash diff), `GET /api/health/targets` (per-target health),
  `GET /admin/config` (the raw on-disk YAML, loaded into an editor on
  demand).
- **Mutations:** `POST /admin/reload` (behind a confirm dialog; this
  re-reads the config file from disk and hot-swaps the pipeline),
  `PUT /admin/config` (writes the editor's text back, with `if_match`
  set to the revision it was loaded at, so a concurrent edit surfaces
  as a conflict instead of clobbering).
- **The editor locks itself where the node does not own its config.**
  When `locally_owned` is `false`, the textarea goes read-only, the save
  button is disabled, and a banner names the repository or the authority
  and says to change it there. This is a courtesy, not the enforcement:
  the server refuses the same write with a `409` whether it arrives from
  this page or from `curl`, and showing the lock only means an operator
  finds out before typing an edit rather than after. The lock requires a
  definite answer, so a request still in flight or one that failed
  leaves the editor usable rather than making an admin-API hiccup look
  like a permanent loss of control over the node.
- **Two different conflicts share `409`.** A revision mismatch renders
  as "reload the editor and reapply." An ownership refusal
  (`code: config_not_locally_owned`) names the settings at fault and the
  place they are actually set, because reapplying would fail the same
  way. In the form view the refusal also renders on the offending
  fields: a `409` naming six paths as one banner is a puzzle, and the
  same information attached to six fields is a to-do list.

### Form and raw YAML

The editor has two views of the same document, switched with the
Form / Raw YAML buttons.

**The form is generated from `GET /admin/config/schema`**, never from a
hand-maintained field list, so a field added to the config types
appears without a UI change. Fields carry the doc comment from the
Rust type as help text, enums render as pickers, and a value that
cannot be the declared type (a port typed as a word) is a red field
rather than a round trip and a `400`.

**It does not render everything, and says so where it stops.** Four
fields are `serde_json::Value` in the config types (`origins[].action`,
`policies`, `transforms`, `authentication`), so the schema describes no
shape for them and no form can. Those drop to a YAML box scoped to that
one node, labeled with why. The detection is by shape rather than by a
list of known paths, so a fifth opaque field added later falls back the
same way instead of rendering as a section with no settings in it.

**Switching views never loses an edit**, because there is only one
document: a form edit applies its change to the same text the raw view
shows. That change goes through the YAML document tree rather than a
parse and re-serialize, so **comments and key order survive an edit**.
A form that rewrote the file on every change would be a worse editor
than the textarea it replaced, and operators would be right to call it
data loss.

Fields the node does not own render locked with an `authority <id> rev
<n>` or `git <commit>` badge. One case is deliberately locked without a
definite answer: a path whose key contains a dot, which is every origin
hostname. The server's provenance map joins path segments with dots, so
`origins["api.test"].action` and `origins.api.test.action` are the same
string and a lookup cannot tell them apart. The form reports "ownership
unclear" and sends the operator to the raw editor, where the server
judges the write properly. Guessing would either lock a field they own
or unlock one they do not.

The raw textarea remains, and on a node with no remote config layer
nothing above changes anything: every field is editable, exactly as
before.
- **Empty/error notes:** `GET /admin/drift` returning `503` (no
  `config_path` wired, an in-memory/test boot) renders as "drift
  unavailable," not an error banner; a reload while another reload is
  in flight (`409`) surfaces as "reload already in progress." On a node
  with no remote layers the Configuration source panel still renders,
  reading "This node owns its configuration," because the affirmative
  answer is what tells an operator the editor is trustworthy.

### Config history

A read-only timeline of every revision this node has applied, present when
[`proxy.config_history.enabled`](configuration.md#config_history) is
turned on. It is off by default, and the panel says so with an empty-state
message naming the config key rather than rendering an error.

- **Shows:** `GET /admin/config/history` as a table (revision, state --
  `applied`, `good`, `failed`, or `reverted` -- blast radius, provenance,
  when it applied, and the actor), with the ring's `lineage` id and the
  `lkg_revision` pointer in the section header. Clicking a row fetches
  `GET /admin/config/history/{digest}` and expands a detail row showing
  the `plan_text` diff between that revision and the config running now.
- **No mutations.** There is no button here to promote a revision to
  last-known-good or to roll one back; `mark_good` is storage with no
  caller yet, so the panel is a diagnostic and audit trail, not a rollback
  control. See [configuration.md](configuration.md#config_history) and
  [admin-api-reference.md](admin-api-reference.md#get-adminconfighistory)
  for what the ring records today and what it does not do yet.

## Extensions (`/extensions`)

Use Extensions after startup or a reload to verify which extension code the
running proxy actually accepted. The page reports the active pipeline
generation, not another read of the files on disk, so it also tells you when a
candidate reload failed and the previous generation stayed live.

Start with the generation revision and the six summary counts. A nonzero
**failed** or **collisions** count opens a **Failures and collisions** section:

- For a failed bundle, read the loader phase and bounded error detail, fix the
  bundle or config, reload, then confirm that the running revision changed.
- For a collision, read the match key, competing registrations, resolution,
  and winner. This tells you which implementation receives requests without
  requiring a `doctor` run on the host.

The **Bundle ledger** is sorted by stable bundle ID. Find a bundle there to
check its version, source, runtime, artifact, and load result. Its hooks show
where that code can run: dispatch mode and chain position, request phase, body
access, timeout, buffer limit, and granted host capabilities. An **active**
hook is attached to this generation; **available** means it loaded but is not
attached; **failed** and **shadowed** rows include the reason or winning
registration when available.

The inventory refreshes every 15 seconds, or use **Refresh** after a reload.
If refresh fails, the last successful generation remains visible with a stale
warning. Extension installation and attachment are configured in `sb.yml`;
this page is read-only.

## Logs (`/logs`)

![The Logs page: requests with a Gateway decision column reading cache, routing, and guardrail outcomes, two custom-property columns, and the filter bar](assets/admin-logs.png)

The queryable view over the recent-request ring buffer, with a live
tail and a runtime log-level control.

- **Shows:** `GET /api/requests` as a table filterable by method,
  status, path, cache result, retry presence, guardrail action, exact
  session ID, and exact custom property. A `guardrail_action` query
  param arrives pre-filled when you follow the "Blocked requests"
  link from Guardrails, and an `origin` param when you follow an
  origin from the Spend breakdown. `GET /api/ui-settings` supplies the trace-URL
  template used to link a trace ID to the tracing backend.
- **Columns and grouping:** a persisted property-column picker shows
  only redacted values from the current ring. "Group by session"
  renders roots, descendants, parents outside the ring, and ungrouped
  requests with per-session summaries. The Gateway column reads cache,
  retry, failover, load-balancer, and guardrail decisions as one causal
  rail; expanding a row shows every bounded field. For `admin`
  operators, an expanded AI-dispatched row also offers "Replay in
  playground", which re-runs the entry through the governed dispatch
  path (see [Replay a logged request](#replay-a-logged-request)).
- **Mutations:** none directly on request data; `GET`/`PUT /admin/log-level`
  reads and sets the live tracing filter (e.g.
  `debug` or `sbproxy_ai=debug`) without a restart.
- **Live tail:** toggling it opens `GET /api/requests/stream`
  (Server-Sent Events) and appends new rows as they complete; the UI
  shows a "reconnecting" state if the stream drops and retries.
- **Empty/error notes:** an empty ring buffer (fresh process, no
  traffic yet) renders an empty state; the ring buffer is in-memory
  and resets on restart; for durable logs, see [access-log.md](access-log.md).

### Debugging a request

The Logs page is the first debug loop for a misbehaving proxy:

1. Raise the tracing level. The level control accepts a plain level
   (`debug`, `trace`) or a `tracing` filter directive like
   `sbproxy_ai=debug`, which turns on AI-path detail while the rest
   of the process stays at `info`. It applies immediately via
   `PUT /admin/log-level` and confirms with a toast. Official release binaries
   compile SBproxy's own `debug!` and `trace!` events out with a static maximum
   of `info`; raising the filter cannot restore those events. It can still
   expose more detail from dependencies compiled without that ceiling. Use the
   structured request decision fields below, or reproduce with a development
   build when SBproxy-internal debug events are required.
2. Turn on Live tail and reproduce the problem. New requests stream
   in as they complete, with the same properties and gateway decisions
   as snapshot rows. The active filter predicate is applied to both.
3. Filter to the failure: by status (`5xx`), path substring, cache,
   retry, guardrail action, session, or custom property. The "Blocked
   requests" link from Guardrails arrives here pre-filtered.
4. Correlate with the server log. Every row carries a `request_id`
   and, when tracing is exporting, a `trace_id` that deep-links to
   your tracing backend via the `trace_url_template` setting. The
   Playground's debug toggle returns the same `request_id` plus the
   config revision, so a test request is easy to find in both
   places.
5. Drop the level back to `info` when done; leaving `trace` on is a
   log-volume hazard, not a correctness one.

## Sessions (`/sessions`, `/sessions/:sessionId`)

![The session index: rollup tiles over the ring, then one row per session with child sessions indented under their parent](assets/admin-sessions.png)

Recent logical interactions reconstructed entirely from the request ring.

- **Shows:** `GET /api/requests`, grouped by `session_id` and linked by
  `parent_session_id`. The index rolls up request count, input and output
  tokens, cost, wall-clock duration, and worst HTTP status. Detail pages show
  one session's calls oldest first, their gateway decision rails, properties,
  request and trace IDs, and links to a parent or child that remains in the
  ring.
- **Mutations:** none. "Open in Logs" applies the exact session filter there.
![A session detail page: child links, rollup tiles, and a numbered call chain where each call shows its gateway decision rail, IDs, AI route, tokens, and property chips](assets/admin-session-detail.png)

- **Retention boundary:** this is not durable trace storage, a span waterfall,
  or replay. A restart or request-ring eviction can remove some or all of a
  session, and the UI labels parents that fall outside the current ring.

### Attributing a spike to a customer

The observability surfaces compose into one attribution loop. Send
`X-Sb-Session-Id` (and `X-Sb-Parent-Session-Id` for a sub-agent) plus any
`X-Sb-Property-*` headers your callers can supply, then:

1. **Spend** shows the money. Group the window by a promoted property
   (`Property: feature`) to see which product surface moved, or by origin
   for which tenant.
2. **Logs** shows the requests behind it. Filter by that exact property key
   and value, and read the Gateway column: a run of `cache miss` where you
   expected hits, or `fallback chain` engaging, explains a cost or latency
   change without opening a single body.
3. **Sessions** shows the shape of the work. One agent task is usually many
   calls; the index ranks sessions by cost and duration, and a detail page
   reads the call chain oldest first with each call's gateway decisions.
4. **Alerts** shows whether anyone was told. Rule state and channel delivery
   health answer "should this have paged us, and did it?"

Only properties listed in the origin's `properties.rollup_keys` become
durable spend dimensions; every captured property stays filterable in Logs
for the life of the ring. Redacted keys show as `[redacted]` everywhere.

## Metrics (`/metrics`)

![Metrics: live stat tiles with sparklines, request-rate and latency charts, and per-origin activity](assets/admin-metrics.png)

A live read of the Prometheus `/metrics` endpoint, parsed
client-side. While the page is open it samples the endpoint every
five seconds and charts what happened *between* samples: counter
deltas become per-second rates, histogram bucket deltas become
per-interval latency percentiles. The raw scrape stays one click away
and remains the source of truth. Requests to `/metrics` are excluded
from the proxy traffic totals and latency histograms, so leaving this
page open does not inflate the values it displays.

- **Shows:** `GET /metrics`, rendered as three layers.
  - *Numeric tiles* with trend sparklines: requests/s, total
    requests, error rate, p95 latency, active connections, AI tokens,
    and AI cost.
  - *Line charts*: requests per second and error rate over the
    sampled window, p50/p95/p99 latency, and AI token throughput
    split by direction. Hovering shows a crosshair with exact values.
  - *Bar breakdowns and tables*: requests by status (2xx green, 4xx
    amber, 5xx red) and method, errors by type, cache and auth
    results, bytes by direction, tokens by provider and direction,
    per-model token throughput, and model-host gauges. An **origins
    table** lists requests, success rate, and p50/p95 latency per
    configured origin, the first place to look when several tenants
    share one gateway.
- **Filters:** with more than one configured origin, an origin picker
  scopes the page to one `Host`; "all origins" is the default. The
  tiles, traffic charts, latency percentiles, and the status, method,
  errors, cache, auth, bytes, and token panels all honor it (the AI
  panels via the `origin` label on the attributed counters). A panel
  whose series carry no origin dimension (provider errors, per-model
  throughput, model-host gauges) stays an aggregate and says
  "all origins" while a filter is active.
- **Live control:** the Live toggle pauses and resumes sampling.
  Three consecutive failed scrapes pause it automatically and say so.
- **Mutations:** none.
- **Empty/error notes:** a series with no samples yet (no traffic of
  that kind) simply does not render its tile or panel; the page never
  treats "no data" as an error. The initial fetch failing renders the
  error state; a background sample failing raises a toast instead of
  blanking charts that already have data.

## Spend (`/spend`)

![Spend: the window grouped by a promoted custom property, with per-model, per-provider, and per-origin breakdowns below](assets/admin-spend.png)

Estimated AI cost: live totals since process start, plus durable
windowed history.

- **Shows:** `GET /metrics` for live totals and breakdowns (by model,
  provider, origin, API key, team, project; attribution partitions
  are omitted from a breakdown when the label is absent, not shown as
  a zero row), `GET /api/usage/spend?window=...&group_by=...` for the
  durable rollup history chart, which survives a restart unlike the
  live counters. History groups by provider, model, tenant, team,
  API key, project, or origin; rollup rows recorded by builds that
  predate the origin dimension fold into the unattributed segment. The
  response also advertises promoted property keys, which appear as
  `Property: <key>` groupings and query as `group_by=property:<key>`.
  Labels in the by-origin breakdown link through to Logs filtered to
  that origin, which is the one spend dimension the request log can
  filter on; the other breakdowns are deliberately not linked, because
  landing on an unfiltered log is worse than no link.
- **Mutations:** none.
- **Empty/error notes:** no AI traffic yet renders an empty state; a
  `window`/`group_by` combination with no matching rollup data renders
  an empty chart, not an error. If a selected property disappears in
  another window, the selector preserves it with an unavailable hint
  rather than changing the operator's query.

## AI performance (`/ai-performance`)

![AI performance: TTFT and streaming latency histograms with provider health](assets/admin-ai-performance.png)

Serving latency (time-to-first-token, inter-token latency, throughput)
and provider health from the live counters.

- **Shows:** `GET /metrics`, specifically the TTFT/TPOT/throughput
  histograms, per-provider request/error counts and error rate,
  gateway admission/rejection rate with rejection reasons, failover
  reasons, cascade-tier outcomes, and router-strategy decisions. When
  context-compression policies are active, a
  compression section reports compressed requests, tokens and cost
  saved, per-lever savings, request outcomes, and the average
  compression ratio per lever.
- **Mutations:** none.
- **Empty/error notes:** no AI traffic renders an empty state
  explaining that panels light up after the first request through an
  `ai_proxy` origin; streaming-latency panels specifically need at
  least one streamed completion (TPOT needs at least two tokens in
  that stream) and say so rather than showing a misleading zero.

## Guardrails (`/guardrails`)

![Guardrails: block counts by category and wasted-spend panels](assets/admin-guardrails.png)

Governance outcomes: what the guardrail, WAF, and object-authz planes
blocked, and what wasted spend the gateway flagged.

- **Shows:** `GET /metrics`: guardrail blocks by category, streaming
  guardrail violations, context-poisoning findings, WAF/HTTP-framing/
  object-authz blocks, and wasted tokens/cost by kind (duplicate
  requests, abandoned streams, validation failures, context bloat,
  failover losers).
- **Mutations:** none. A "Blocked requests in Logs" action link jumps
  to Logs pre-filtered by `guardrail_action=block`.
- **Empty/error notes:** no guardrail activity since start renders an
  empty state pointing at the AI gateway guardrails config, not an
  error; this is the expected state for a config with no guardrails
  declared.

## Alerts (`/alerts`)

![The Alerts page: rule evaluation state, one healthy and one failing channel with its delivery error, and the test-event history](assets/admin-alerts.png)

Read-only alert operations over the runtime installed from `sb.yml`.

- **Shows:** `GET /api/alerts`: built-in rules with thresholds, current
  reading, sample floor, state, and latest evaluation; sanitized channels with
  delivery health and bounded errors; and up to 200 process-lifetime fired,
  resolved, and test events. Webhook and Slack targets include only scheme and
  host. PagerDuty exposes only whether a routing key is configured.
- **Mutations:** `POST /api/alerts/test` queues one targeted channel test. The
  page polls briefly until that channel's `last_attempt_at` changes and then
  reports the delivery result. It cannot edit rules or channels.
- **Authority and retention:** `sb.yml` is authoritative. Rule state, channel
  health, and history reset with the process. The provider error-rate rule
  remains inactive below 10 attempts in an evaluation window; the gateway
  rejection-rate rule remains inactive below 10 decisions.
- **Empty/error notes:** no `proxy.alerting` block renders a disabled state;
  an enabled runtime with no channels keeps tests unavailable; no history is a
  normal process-lifetime empty state. A webhook channel pointed at a private
  or loopback address reports `failing` with "target rejected by SSRF policy":
  the delivery path enforces the same egress guard as the rest of the proxy, so
  test a local receiver through a routable address.

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
- **Mutations:** `POST /admin/api/playground/dispatch`, which requires
  the `admin` role (a `read_only` operator gets `403` here even though
  the endpoint list is read-only). The page has you pick an active
  virtual key, and the request then runs through the real data-plane
  pipeline as that key: key policy, governance, routing, and
  guardrails all apply exactly as they would for the key's own
  traffic. Plain-HTTP AI origins only; an origin with `force_ssl`
  answers `501`. A debug toggle adds a `request_id` and the config
  revision to the response for server-log correlation.
- **Not used by the UI:** `POST /admin/api/playground/chat`, the
  direct engine call that skips the pipeline entirely. It refuses to
  run unless the body carries `bypass_governance: true`, and every
  completion it does run is audited. See
  [admin-api-reference.md](admin-api-reference.md#chat-playground)
  before scripting against it.
- **Empty/error notes:** no AI origins configured is an empty state
  ("nothing to talk to yet"); an upstream failure surfaces the
  provider's error, not a generic one.

### Replay a logged request

An expanded row on the Logs page offers "Replay in playground" on any
AI-dispatched entry (`admin` role only; the dispatch route refuses
`read_only` operators). It opens this page with the entry's request id
in the URL and pre-fills the form with what the request log actually
retains:

- **Always reconstructable:** the origin, the model, and the minted
  virtual key the request ran as. These live on the ring entry itself,
  so they survive even when no content was captured.
- **The body, only when it was captured:** the prompt loads from the
  redacted content sample retained when the AI origin sets
  `capture_content: true` and the governed key's policy consents with
  `allow_content_capture`. The page reads it through
  `GET /api/requests/{request_id}/content`, the same audited admin
  read behind the "View captured content" button on the Logs page, so
  a replay surfaces nothing a normal log read would not. A captured
  replay carries every captured message in order; the Prompt box edits
  the last user message. Capture redacts before storage, so the replay
  sends the redacted text, not the original bytes.
- **Never reconstructable:** sampling parameters (temperature, token
  limits) are not retained in the log, so the replay dispatches with
  the playground's defaults. When no content sample exists (capture
  not enabled, key consent absent, or the bounded sample store evicted
  or restarted), the page states the gap and pre-fills only origin,
  model, and key. It never fabricates a prompt.

```mermaid
flowchart LR
    A[Logs: expanded AI request row] -->|Replay in playground| B[Playground, request id in the URL]
    B --> C{"Content sample retained?\n(capture_content AND\nallow_content_capture)"}
    C -->|yes, read is audited| D["Origin, model, key, and the\nredacted messages pre-fill"]
    C -->|no| E["Origin, model, and key pre-fill;\nthe body gap is stated"]
    D --> F["POST /admin/api/playground/dispatch"]
    E --> F
    F --> G["Governed pipeline: key policy, budgets,\nrouting, guardrails, like the original run"]
```

The dispatch is the governed one described above, pre-selected to the
original request's virtual key when that key is still active. A
replayed request is a new request: it runs the full policy chain
again, spends real budget, and lands in the log under its own request
id. The replay never touches the ungoverned `/chat` route.

## Cache (`/cache`)

![Response-cache status with purge controls, plus semantic-cache decisions](assets/admin-cache.png)

Response-cache status and eviction, plus dynamic key-policy cache
invalidation and semantic-cache debugging.

- **Shows:** `GET /admin/cache` (enabled, backend, whether prefix
  purge is supported), `GET /admin/cache/semantic` (recent embedding
  cache hit/miss decisions per AI origin), `GET /metrics` (cache-
  related counters shown alongside). With more than one origin in
  play, an origin picker scopes the hit/miss tiles and the semantic
  decisions to one origin; purge controls always act on the whole
  backend and stay global.
- **Mutations:** `POST /admin/cache/purge` (all / by exact key / by
  prefix; prefix purge is disabled in the UI when the backend does
  not support it), `POST /admin/cache/key-policy/evict` (one key or
  all).
- **Empty/error notes:** `{"enabled": false}` (no origin turned on
  response caching) renders as "not enabled," not an error; purge
  against a disabled cache returns `409` and renders the same way; no
  origin has a semantic cache configured renders that panel empty.

## Compression (`/compression`)

![Compression: three live records with covered tokens, summary size, and compression ratio](assets/admin-compression.png)

Externalized conversation context: which sessions have a stored
summary standing in for their history, and how much that saves.

- **Shows:** `GET /admin/compression/sessions`, refreshed every 20
  seconds. Per record: origin, tenant, kind, covered input tokens,
  summary tokens, the resulting ratio, the summarizer model, and the
  storage backend. The cards above total the records, the tokens saved
  (covered minus summary, floored at zero), and the count of records
  whose last write hit a concurrent-write conflict.
- **Mutations:** none.
- **Empty/error notes:** summary *text* is never listed here, only its
  size and provenance, so the page stays safe to leave open on a
  shared screen. No records renders an empty state pointing at the
  requirement: a route with a compression profile has to handle a
  conversation before anything appears. Records expire on their own,
  so a row vanishing between refreshes is expected, not a fault.

See [ai-context-compression.md](ai-context-compression.md) for what
populates these records and how to configure a profile.

## Model host (`/model-host`)

![Model host: catalog, desired deployments, and runtime status in one view](assets/admin-model-host.png)

Desired model deployments and local runtime residency, controlled from
one operational view, including, on a cluster authority node, signed
fleet-wide deployment publication.

- **Shows:** `GET /admin/model-host/catalog` (bundled models and exact
  variants with support evidence), `GET /admin/model-host/deployments`
  (the desired-state document: authority, read-only flag, revision),
  `GET /admin/model-host/status` (runtime state per deployment),
  `GET /admin/cluster/status` and `GET /admin/cluster/deployments`
  (cluster roster and the signed deployment bundle, when clustered).
- **Mutations:** `PUT /admin/model-host/deployments` (add/edit/remove
  a deployment, allowed only under `admin_managed` authority; compare-and-
  swap on `expected_revision`), `POST /admin/cluster/deployments` (on
  an authority node, publish the signed complete map),
  `POST /admin/model-host/load|stop|reset` (per-deployment lifecycle).
- **Empty/error notes:** under `file_managed` authority (the deployment
  map is owned by `sb.yml`) or as a cluster verifier node, the save
  action is replaced with an explanation of why this node is read-only
  instead of a form. A revision conflict on save keeps the submitted
  form and the conflicting server state both visible and requires an
  explicit retry; it never silently discards your edit or silently
  overwrites the server's. Removal is blocked while a deployment's
  runtime evidence is stale or it is ready/preparing/draining, with the
  reason shown inline.

## Jobs (`/jobs`)

Durable model-host work, including model loads and evictions, artifact
pulls, and verification.

- **Shows:** `GET /admin/model-host/jobs`, newest first, with filters
  for deployment, kind, state, and job ID. Expanding a non-terminal row
  follows `GET /admin/model-host/jobs/{id}/stream`; the browser resumes
  the server-sent event stream after a dropped connection.
- **Mutations:** none.
- **Empty/error notes:** no retained jobs is a normal empty state.
  Terminal jobs remain inspectable without holding an event stream
  open, and a stream reconnect never blocks the list's regular refresh.

## Storage (`/storage`)

![Storage: the verified weight cache with per-artifact size, residency, and delete controls](assets/admin-storage.png)

Verified model weights in the artifact cache: what is on disk, what is
resident, and what can be reclaimed.

- **Shows:** `GET /admin/model-host/files` (cache root, total bytes,
  per-artifact size, last-accessed time, and whether it currently
  backs a ready replica).
- **Mutations:** `DELETE /admin/model-host/artifacts/{digest}` (remove
  one artifact, blocked with a stated reason if it is configured,
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
  empty audit list and a `404` on the budget snapshot; both render as
  "not configured," not an error, since there is nothing to audit.

## Users (`/users`)

![Users: the top-level admin credential plus two configured operators, with role and capability per row](assets/admin-users.png)

Who can sign in to this console, and what each account may do.

- **Shows:** `GET /api/admin/users`. One row per account: username,
  role (`admin` or `read_only`), whether it is the top-level admin
  credential or a configured operator, and a plain-language note on
  what that role may do. The cards count accounts by role.
- **Mutations:** none. Accounts live in config, under `admin.username`
  and `admin.operators`; add, remove, or re-role one by editing config
  and reloading. The [Config](#config-config) page can do that edit.
- **Empty/error notes:** passwords are never sent to this page and
  cannot be read back anywhere in the console, so this answers "who
  has access", not "what is the secret". The list is built from the
  same config the login route authenticates against, so it cannot
  drift from the accounts that actually work. The admin server always
  has at least the top-level credential, so an empty list means the
  build could not read its own config.

## Operators (`/operators`)

The configured RBAC operator subset, separated from Users so an
operator can quickly audit delegated accounts without the top-level
admin credential in the table.

- **Shows:** `GET /api/operators`, with each configured username and
  its `admin` or `read_only` role.
- **Mutations:** none. Edit `proxy.admin.operators` in config and
  reload to add, remove, or re-role an operator.
- **Empty/error notes:** an empty list means no delegated operators
  are configured; the top-level admin credential can still sign in.
  Passwords never leave the server and are not returned by this route.

## Cluster (`/cluster`)

Membership, model placement, and rollout health across the fleet.
For a runnable example that lights this page up, see
[a three-node mesh on one machine](#example-a-three-node-mesh-on-one-machine).

- **Shows:** `GET /admin/cluster/status` (the complete node roster,
  including failed/excluded members, never hidden to make the fleet
  look healthier, plus a health rail, prominent unhealthy-node alerts, and
  per-deployment placement/rollout detail), `GET /admin/cluster/metrics`
  (fleet-aggregated metrics, shown separately so a metrics-tier outage
  never hides roster or rollout evidence).
- **Mutations:** none on this page; publishing a signed deployment
  bundle happens from Model host. This page is read-only status and
  alerting.
- **Empty/error notes:** outside a configured cluster, this renders a
  single-node view rather than an error (there is a "fleet" of one).
  A metrics-endpoint `404` (mesh metrics tier not configured) renders
  "metrics not enabled" without blocking the roster/health sections,
  which come from a separate call.

## Example: a three-node mesh on one machine

The Cluster page (and the node count in the top bar) come alive with
a real mesh. `examples/model-cluster-symmetric/` runs the same config
file once per node with per-node environment. The example's own
README walks through two nodes; a third follows the identical
pattern (its own id, ports, state dir, and a seed pointing at an
existing node), which is what the roster below shows:

```bash
# Terminal 1 (node a, also the seed)
SB_ADMIN_PASSWORD=local-admin \
SB_NODE_ID=node-a SB_HTTP_PORT=8081 SB_ADMIN_PORT=9091 \
SB_GOSSIP_PORT=17946 SB_TRANSPORT_PORT=18946 SB_MODEL_PORT=19443 \
SB_STATE_DIR=./state/node-a SB_SEED=127.0.0.1:17947 \
sbproxy -f examples/model-cluster-symmetric/sb.yml

# Terminal 2 (node b)
SB_ADMIN_PASSWORD=local-admin \
SB_NODE_ID=node-b SB_HTTP_PORT=8082 SB_ADMIN_PORT=9092 \
SB_GOSSIP_PORT=17947 SB_TRANSPORT_PORT=18947 SB_MODEL_PORT=19444 \
SB_STATE_DIR=./state/node-b SB_SEED=127.0.0.1:17946 \
sbproxy -f examples/model-cluster-symmetric/sb.yml

# Terminal 3 (node c)
SB_ADMIN_PASSWORD=local-admin \
SB_NODE_ID=node-c SB_HTTP_PORT=8083 SB_ADMIN_PORT=9093 \
SB_GOSSIP_PORT=17948 SB_TRANSPORT_PORT=18948 SB_MODEL_PORT=19445 \
SB_STATE_DIR=./state/node-c SB_SEED=127.0.0.1:17946 \
sbproxy -f examples/model-cluster-symmetric/sb.yml
```

Open any node's admin UI (they each run their own admin server; node
a is `http://127.0.0.1:9091/admin/ui/`) and:

- The top bar reads "live · 3 nodes" once gossip converges, usually
  within a few seconds.
- **Cluster** shows the full roster with membership state,
  per-node health, roles, and last-ack age. Kill one node
  (`Ctrl-C` in its terminal) and its row degrades to `suspect`, then
  `dead`, and an unhealthy-node alert appears. The roster keeps the
  dead row visible rather than hiding failed members.
- **Keys** minted on one node propagate: the example wires the key
  cache's mesh tier, so revoking a key on node a is enforced on
  node b without a restart.
- **Model host** on a cluster-authority setup is where a signed
  deployment bundle is published fleet-wide; see
  [model-host.md](model-host.md) for that flow.

One local-topology quirk: browsers scope cookies by host, not port,
so signing into one node's admin UI on `127.0.0.1` signs you out of
the others (each login overwrites the shared session cookie). When
you want several node dashboards open side by side, use separate
browser profiles or give each node its own loopback address
(`127.0.0.2`, `127.0.0.3`).

![Cluster page with a three-node roster, health rail, and placement summary](assets/admin-cluster.png)

![The same cluster after killing node-c: the health rail marks it unhealthy and an alert reports membership as dead](assets/admin-cluster-degraded.png)

## See also

- [admin-api-guide.md](admin-api-guide.md) - the task-oriented API walkthrough this UI is a client of.
- [admin-api-reference.md](admin-api-reference.md) - every route this UI calls, in full.
- [admin.md](admin.md) - enabling the admin server, TLS, roles, and the security checklist.
- [key-management.md](key-management.md) - the policy model behind the Keys page.
- [model-host.md](model-host.md) - the config behind the Model host and Storage pages.
