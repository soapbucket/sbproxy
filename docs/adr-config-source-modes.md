# ADR: config source modes (file / git / git+overlay / db) (WOR-133)

*Last modified: 2026-05-08*

## Status

Proposed. This document is the audit + design half. The
implementation ticket is filed separately and references this ADR as
the spec.

## Summary

The Catalog PRD §4 declares three Repo source modes: `git`, `db`,
and `git+overlay`. The OSS proxy today loads from a single YAML
file on disk and treats that as the entire source-of-truth
surface. The PRD specifically calls `git+overlay` "the answer" to
operational reality and uses it to differentiate sbproxy from
Kong, Apigee, and Gravitee, none of which expose a TTL'd narrow
override on top of a versioned source. This ADR audits the
current loader, proposes the three new source modes, and
enumerates the open questions the implementation ticket has to
resolve before any of them ship.

## Current state

There is no `loader.rs` in `sbproxy-config`. Loading is
file-shaped and lives in three places:

- `sbproxy_core::server::run` (`crates/sbproxy-core/src/server.rs:11357`)
  is the bootstrap entry point. It is called from `main.rs` once
  the CLI / `SB_CONFIG_FILE` env var has resolved a path. The
  function takes `config_path: &str`, calls
  `std::fs::read_to_string`, hands the YAML to
  `sbproxy_config::compile_config`, and runs the rest of bootstrap.
- `reload_from_config_path` (`server.rs:11203`) is the single
  reload primitive. It does the same `read_to_string` +
  `compile_config` + build `CompiledPipeline` + invoke the
  enterprise `startup.on_reload` hook + `reload::load_pipeline`
  publish.
- `compile_config(yaml: &str) -> Result<CompiledConfig>`
  (`crates/sbproxy-config/src/compiler.rs:451`) is the only
  shape-checking entry point. It runs env-var interpolation, then
  the legacy `features.*` to `extensions.*` migration, then serde
  deserialisation into `ConfigFile`, then per-origin compilation,
  then constructs the optional L2 cache and messenger handles.

The `ConfigFile` (`crates/sbproxy-config/src/types.rs:14`) is the
top-level shape: a `proxy:` block, a `HashMap<hostname,
RawOriginConfig>` under `origins:`, an optional `access_log`, and
an optional `agent_classes` block. There is no `source:`
discriminator in the type today; the ticket assumed a stub but
none exists. The `AgentClassesConfig.catalog` field
(`types.rs:48`) is the closest precedent: it accepts `builtin`,
`hosted-feed`, or `merged` and is the model the new top-level
discriminator should mirror.

The reload state machine (`crates/sbproxy-core/src/reload.rs`)
holds an `ArcSwap<CompiledPipeline>` with a packed in-flight
counter. Two callers wake reload: the `notify`-based file watcher
(`server.rs:11257`, modify events), and the SIGHUP handler
(`server.rs:11311`, `kill -HUP $(pgrep sbproxy)`). Both are
file-path-shaped: they read from disk and re-run
`reload_from_config_path`. There is no abstraction over "where
did the config bytes come from."

The admin surface (`crates/sbproxy-core/src/admin.rs`) exposes
`POST /admin/reload` and `GET /admin/drift`. Reload reads the
file at `state.config_path` and reuses `reload_from_config_path`.
Drift compares the loaded pipeline's content hash against the
on-disk file. Both are file-shaped and would need a
source-mode-aware redirection to support git or db sources.

The plan / apply CLI (just landed via WOR-180, audited in
`docs/adr-config-plan-apply.md`) takes either a `-f <yaml>` or a
`-p <plan-file>`. It is also file-shaped today. Its open
question 7 ("future config-source-of-truth integration") is the
explicit hand-off to this ADR.

Three properties of the existing surface matter for the source-mode
design:

- **There is no source abstraction.** Every reload is "read a file
  by path." A new source mode requires a small trait and a single
  call site swap in `reload_from_config_path` plus the bootstrap
  in `run`.
- **Reload is single-phase.** A new source has nowhere to stage a
  candidate config and nowhere to diff against the running one
  without re-reading. The plan/apply ADR (WOR-131 / 180) already
  picked a posture here: plan diffs at the
  `sbproxy_config::plan(baseline, proposed)` library API, not at
  the bytes layer. Source modes inherit that posture.
- **The file watcher and the SIGHUP handler are redundant by
  design.** Either one is enough to react to a change. Source
  modes other than file replace the file watcher (no inotify on a
  remote git repo) but keep SIGHUP as the operator's
  break-glass.

## The Catalog PRD shape

The PRD §4 declares the canonical wire shape as a top-level `repo:`
block with a `source:` discriminator:

```yaml
repo:
  source: file        # default; preserves today's behaviour.
  path: /etc/sbproxy/sb.yml
```

```yaml
repo:
  source: git
  url: https://github.com/example/sbproxy-config.git
  ref: main           # branch | tag | sha; sha pins are immutable.
  refresh: 30s        # how often to re-fetch; 0 disables polling.
```

```yaml
repo:
  source: git+overlay
  git:
    url: https://github.com/example/sbproxy-config.git
    ref: main
    refresh: 30s
  overlay:
    backend: in-memory   # `in-memory` | `redis` | `embedded`
    allowlist:
      - origins.*.rate_limits.requests_per_second
      - origins.*.policies[*].enabled
```

```yaml
repo:
  source: db
  url: postgres://...   # or sqlite://, mysql://
  table: sbproxy_config
  watermark: updated_at
  refresh: 30s
```

The new `repo:` block sits at the top level of `ConfigFile`
alongside `proxy:`, `origins:`, `access_log:`, and
`agent_classes:`. When `repo:` is absent, the loader falls back
to today's "the path on the CLI is the YAML" behaviour;
`source: file` is the explicit name for that behaviour.

## Proposed `source: git`

The git mode pulls config bytes from a remote repo on a refresh
schedule, hands them to `compile_config`, and reuses
`reload_from_config_path`'s publish path. The git fetch replaces
the `notify` file watcher; the SIGHUP handler keeps working
(every SIGHUP forces an immediate fetch + reload).

### Clone shape

The Catalog PRD does not commit to a clone topology, so we pick the
narrowest one that works.

- **Bare clone of one ref.** On startup, the loader does a
  shallow `clone --depth 1 --branch <ref>` into
  `${SB_STATE_DIR:-/var/lib/sbproxy}/repo/<config-id>`. The
  `<config-id>` is the SHA-256 of the repo URL so multiple repos
  on the same host don't collide.
- **Subsequent refreshes are `fetch + reset --hard origin/<ref>`**
  against the same on-disk clone. Disk usage is bounded by the
  shallow depth plus the per-fetch pack.
- **Single-file mode.** A `path:` field under `repo:` selects one
  file inside the repo; the rest of the working tree is ignored.
  Default is `sb.yml` at the root.
- **Multi-file mode (later).** The directory-of-yaml shape is a
  follow-up. Today's `compile_config` takes a single `&str`; a
  multi-file mode would require either YAML stitching at the
  loader or a multi-file API on the compiler. Out of scope for
  the first landing; the PRD explicitly allows single-file as the
  v1 shape.

### Refresh cadence

Three modes, chosen per `refresh:`:

- `0s` or `off`: pull once at startup, never again. Operator drives
  reloads via SIGHUP. This is the safest mode for production
  air-gapped clusters and is the recommended default for
  high-traffic deployments.
- `<duration>` (e.g. `30s`): polling refresh. The loader spawns a
  tokio task that fetches every interval, runs `compile_config`,
  and publishes via `reload_from_config_path` only when the
  resolved commit SHA differs from the last-applied one. No-op
  fetches do not touch `ArcSwap`.
- `webhook` (later): the loader exposes
  `POST /admin/repo/refresh` (gated by the existing admin auth)
  and refreshes on demand. Useful for GitHub / GitLab webhooks
  that want push-driven updates without polling. Out of scope for
  the first landing.

### Auth

Three options, picked by the presence of fields under `repo:`:

- **HTTPS + deploy key**: `auth.kind: deploy_key`,
  `auth.key_file: /etc/sbproxy/repo-deploy-key`. The loader
  writes a temporary `~/.ssh/config` entry that points at the key
  and runs git over SSH. Recommended for self-hosted git.
- **HTTPS + PAT**: `auth.kind: pat`, `auth.token_secret:
  secrets.GIT_PAT`. The token is read from the existing
  `proxy.secrets.*` block (or a Vault backend) and passed via
  `git`'s `credential.helper` shim. Operator never types the
  token.
- **HTTPS + GitHub App**: `auth.kind: github_app`,
  `auth.app_id`, `auth.installation_id`,
  `auth.private_key_secret`. The loader mints an installation
  token at fetch time and passes it via the same
  `credential.helper` shim. Recommended for fleet deployments
  (per-installation tokens have shorter lifetimes than PATs).

Public repos work with `auth: none` (the default). Plain HTTP
URLs are rejected unless the host is `127.0.0.1` or `localhost`,
matching the existing rule on `HostedFeedConfig`.

### Signature verification

The PRD does not commit to a verification scheme. Three options,
in order of operator overhead:

- **None.** Trust the transport. Acceptable for self-hosted git
  on a private network. Default when `verify:` is absent.
- **Signed commits via PGP / SSH.** `verify.kind: signed_commits`,
  `verify.allowed_keys: [ed25519-pubkey-1, ed25519-pubkey-2]`.
  The loader runs `git verify-commit HEAD` and rejects refreshes
  whose tip is not signed by one of the listed keys. Cheap,
  battle-tested, but relies on the git client.
- **Sigstore / cosign.** `verify.kind: sigstore`,
  `verify.identity: rick@soapbucket.com`,
  `verify.issuer: https://accounts.google.com`. The loader
  verifies a detached signature on the resolved commit SHA against
  the Sigstore public good instance. Heavier dependency
  (cosign-rs or sigstore-rs), and the dependency surface is large
  enough to need its own audit pass (see open questions).

The first landing of `source: git` ships with `none` and
`signed_commits`. Sigstore is reserved for a follow-up.

### Error handling on fetch failure

The fetch loop is responsible for keeping the proxy serving. Three
behaviours, in priority order:

- **Network or auth failure.** Log a warning, increment a
  `sbproxy_config_repo_fetch_failures_total` counter, keep
  serving the last successful pipeline. The operator can wire a
  Prometheus alert against the counter and / or against the
  `sbproxy_config_repo_last_fetch_age_seconds` gauge.
- **Compile failure on a freshly fetched config.** Log an error,
  increment `sbproxy_config_repo_compile_failures_total`, keep
  serving the last successful pipeline. This matches today's
  file-watcher behaviour; the difference is the input is now a
  remote repo, so the operator's only fix is to push a corrected
  commit.
- **Signature verification failure.** Treat as a hard refusal:
  log an error, increment a dedicated
  `sbproxy_config_repo_verify_failures_total` counter, keep
  serving the last successful pipeline, and do **not** retry
  until the operator either updates `verify.allowed_keys` or
  pushes a signed commit. The fetch loop continues to refresh on
  schedule but every fetch fails verification until then.

There is no "block startup on first fetch failure" mode; the
proxy boots from the last on-disk clone if one exists, otherwise
exits with a clear error before opening the listener. An air-gapped
cluster that loses connectivity at boot still serves the
last-known-good pipeline once the on-disk clone is present.

## Proposed `source: git+overlay`

The hybrid mode is the positioning-relevant one. It pairs the git
source above with a runtime override store that lives next to the
arc-swap pipeline. The overlay applies on top of the
git-resolved config at compile time, before
`reload_from_config_path` publishes. Overlay entries have TTLs and
revert to the git state on expiry. A narrow allowlist declares
which fields can be overlaid; everything else is rejected at
plan time so the overlay cannot be used to escalate permissions.

### Overlay backend

Three backends, chosen by `overlay.backend:`:

- **`in-memory`** (default). The overlay store is a per-process
  `BTreeMap<OverlayKey, OverlayEntry>` behind an `ArcSwap`.
  Cheap, no extra dependency. Single-process by design: each
  proxy instance has its own overlay state, and applying an
  override on one instance does not propagate to the others. Best
  for single-node deployments and per-pod canary overrides.
- **`redis`**. The overlay store is a Redis hash keyed by
  `sbproxy:overlay:<config-id>`. Each entry stores the JSON
  patch and the absolute expiry timestamp. The proxy polls the
  hash on the same cadence as the git refresh and rebuilds the
  in-memory cache. Multi-process: applying an override on one
  proxy instance is visible to every other instance polling the
  same Redis. Best for multi-node deployments and fleet-wide
  rollouts. Reuses the existing `proxy.l2_cache_settings.driver:
  redis` pool when configured.
- **`embedded`**. The overlay store is a `redb` table at
  `${SB_STATE_DIR}/overlay.redb`. Survives process restarts.
  Single-process by design. Best for single-node deployments
  that want overrides to survive a SIGTERM. `redb` is already
  the workspace's embedded KV per CLAUDE.md.

Picking a backend is a per-deployment call. The default
`in-memory` is the safest place to start because it does not
introduce a new failure domain.

### TTL semantics

Every overlay entry has a TTL. Three rules:

- **Absolute expiry**, not relative. The TTL is recorded at
  apply time as a wall-clock timestamp. A clock skew between the
  applying operator and the proxy is the operator's problem;
  this matches Redis `EXAT` / `PEXPIREAT` semantics rather than
  `EX` / `PX`.
- **Expiry triggers a reload.** The overlay store wakes on
  expiry (per-entry tokio sleep when `in-memory`,
  `BZPOPMIN`-style polling when `redis`, scheduled task when
  `embedded`) and runs `reload_from_config_path` so the live
  pipeline reverts to the git state. The reload is idempotent.
- **`ttl: 0`** is rejected at apply time. There is no "permanent
  overlay" knob: an operator who wants a permanent change pushes
  it to git. This is the differentiating constraint that makes
  the overlay useful for incidents and not for drift.

The maximum allowed TTL is configurable under `overlay.max_ttl`
and defaults to 24 hours. This stops an operator from setting a
year-long override that effectively forks the live config from
git.

### Allowable-key declaration

The PRD calls this "narrow override enforcement." It is a config-time
allowlist that lists the JSONPath shapes that overlays may touch.
The compiler rejects any overlay that targets a path not in the
allowlist; plan-time validation reports the rejection without
applying. Nine bands cover the realistic incident response surface:

| Path pattern                                 | Why it is on the allowlist                          |
|---|---|
| `origins.*.rate_limits.requests_per_second`  | Tighten or loosen rate limits during traffic spikes |
| `origins.*.rate_limits.burst`                | Same band                                            |
| `origins.*.policies[*].enabled`              | Quickly disable a misbehaving policy                |
| `origins.*.threat_protection.*`              | Tighten WAF rules during an active incident         |
| `origins.*.bot_detection.*`                  | Same band                                            |
| `origins.*.fallback_origin.*`                | Cut over to a fallback during an upstream outage    |
| `origins.*.action.url`                       | Repoint a single origin during an incident          |
| `proxy.metrics.*`                            | Toggle a metric without a git push                  |
| `proxy.access_log.*`                         | Toggle access-log emission for triage               |

The defaults are the union of the above. Operators may narrow
the allowlist further per deployment but may not widen it; widening
is reserved for git pushes. Anything not on the allowlist
(authentication, TLS, secrets, listener ports, the entire
`agent_classes` block) is overlay-forbidden by design.

### Operator API

Three admin endpoints, gated by the existing basic-auth check:

- `POST /admin/overlays`. Body is a JSON object:
  ```json
  {
    "path": "origins.api.example.com.rate_limits.requests_per_second",
    "value": 50,
    "ttl_seconds": 1800,
    "reason": "incident-2026-05-08"
  }
  ```
  Validates against the allowlist, writes the overlay, schedules
  the expiry reload, and returns the resolved entry. The `reason`
  field is required and is appended to the audit log
  (`docs/audit-log.md`).
- `GET /admin/overlays`. Lists every active overlay with its
  `path`, `value`, `expires_at`, `applied_by` (the basic-auth
  user), and `reason`. Read-only. Operator workflow ticket-1.
- `DELETE /admin/overlays/<path>`. Force-revert a single overlay
  before its TTL expires. Audit-log entry includes the
  `revoked_by` and `original_reason`. This is the "force-revert"
  path the WOR-133 ticket calls out.

A fourth endpoint (`POST /admin/overlays/clear-all`) is reserved
for the implementation ticket to argue about: the safer position
is "use repeated DELETE per path" so revert is intentional.

### Plan / apply integration

The plan / apply CLI from WOR-131 / 180 already abstracts over the
source. The integration shape is:

- **`sbproxy plan -f new-sb.yml`** in a git+overlay deployment
  diffs the proposed YAML against the **git tip after overlays
  are applied**. This is the only honest baseline: the operator
  is comparing what they would push to git against what is
  actually serving traffic right now.
- **`sbproxy apply -f new-sb.yml`** in a git+overlay deployment
  is rejected with an explanatory error. Apply against a git
  source must go through git (commit and push); the proxy does
  not write back to the upstream repo. The error message points
  at `POST /admin/overlays` for incident-class changes and at
  `git push` for everything else.
- **`sbproxy overlay plan` / `sbproxy overlay apply`** are the
  overlay-equivalent verbs (open question on naming). They diff
  a proposed overlay against the active overlays + git tip and
  apply via the admin endpoint above. Out of scope for the first
  landing; the first landing ships the admin endpoint and a
  `curl` example.

## Proposed `source: db`

The PRD lists database-backed config as the third Repo source. The
shape:

```yaml
repo:
  source: db
  url: postgres://sbproxy@db.internal:5432/sbproxy_config
  table: sbproxy_config
  schema_version: 1
  refresh: 30s
```

### Table shape

One row per config blob. Schema (PostgreSQL flavour, the SQLite
flavour drops `JSONB` for `BLOB`):

| Column         | Type        | Notes                                          |
|---|---|---|
| `id`           | `BIGSERIAL` | Primary key                                    |
| `revision`     | `TEXT`      | Operator-assigned label, e.g. `v123` or a SHA  |
| `yaml`         | `TEXT`      | The full YAML body                              |
| `applied_at`   | `TIMESTAMPTZ` | When the row was inserted                     |
| `applied_by`   | `TEXT`      | Operator identity                              |
| `is_active`    | `BOOLEAN`   | True for exactly one row                       |

The loader reads the active row on a polling schedule, hands the
`yaml` to `compile_config`, and reuses
`reload_from_config_path`. The active-row constraint is enforced
by a partial unique index (`CREATE UNIQUE INDEX ... WHERE
is_active`).

### Migration path

Three steps, all automated:

1. Loader notices `repo.source: db` and the table does not exist.
2. Loader creates the table from the schema bundled in the
   binary (versioned by `schema_version` so a future schema
   change is forward-compatible).
3. Loader copies the file at `repo.bootstrap_file` (or
   `SB_CONFIG_FILE`) into the active row and starts polling. The
   bootstrap file is a one-time seed; subsequent updates go
   through the database directly.

A `sbproxy migrate-to-db` subcommand wraps the three steps so an
operator can flip the source without writing SQL by hand.

### Watermarking

The polling loop is keyed off `applied_at` (the
`watermark` column). The loader caches the latest seen
`applied_at` and only re-fetches when the database row is newer.
This is cheaper than re-parsing YAML on every poll. SQLite uses
the same shape; the reduction in poll cost is per-driver
optimisation.

### vs git for the same workload

Three trade-offs:

- **Blast radius.** A bad git push fans out to every proxy on
  the next refresh. A bad db update lands the same way but is
  reversible with a single `UPDATE WHERE is_active = TRUE` (and
  the K8s operator can roll back with one CRD edit). Git
  rollback is `git revert + push`, which is two operations and
  is gated on git server availability.
- **Auditability.** Git is the gold standard for change history.
  The db schema records `applied_at` / `applied_by` per row and
  retains every revision in `is_active = false` rows, so
  auditability is comparable. Git wins on tooling (blame, diff,
  branch protection, signed commits); db wins on programmability
  (a deploy script can `INSERT` from CI without needing
  push permissions).
- **Operator workflow.** Git is review-first: every change goes
  through a PR. Db is API-first: an SDK or CRD posts a new row.
  Both are supported; they coexist in the same source enum so
  operators pick the workflow that fits.

Db is the recommended source for fleet-managed deployments where
a control plane (the K8s operator or sbproxy-enterprise) writes
the row. Git is the recommended source for self-managed
deployments where the operator wants a PR-shaped review loop.

## Operator workflow

How `sbproxy plan` and `sbproxy apply` interact per source:

| Source         | `plan -f new.yml`                                                                                         | `apply -f new.yml`                                       |
|---|---|---|
| `file`         | Diff against `repo.path`'s on-disk YAML.                                                                  | Replace the on-disk YAML and reload.                     |
| `git`          | Diff against the latest fetched commit's YAML.                                                            | Reject. Operator must `git push`.                        |
| `git+overlay`  | Diff against (git tip + active overlays).                                                                 | Reject. Use `git push` for git-class changes; use `POST /admin/overlays` for overlay-class changes. |
| `db`           | Diff against the active row's YAML.                                                                       | `INSERT` a new row, mark active, and reload.             |

The plan command never mutates anything in any source; it only
reads. The apply command's mutation surface depends on the
source and is intentionally narrow: file mode keeps today's
behaviour; db mode writes a row; git and git+overlay refuse to
write upstream.

The overlay `POST /admin/overlays` path has its own diff. Open
question on whether to add a `sbproxy overlay plan` /
`sbproxy overlay apply` pair or to ship a single
`/admin/overlays/plan` endpoint that returns the same diff
shape. The first landing ships the apply endpoint and a `curl`
example; the CLI sugar is a follow-up.

## Open questions

These are the items the implementation ticket has to resolve before
any of the three new source modes ships:

1. **Secrets in git.** A YAML in a git repo includes the
   `proxy.secrets.*` block. The block already supports vault-backed
   secrets (`{{secrets.X}}` is a runtime lookup, not a literal),
   but operators can also put literal values in the YAML for
   development. Proposal: the loader rejects literal secret
   values when `source: git`; the only allowed shape is
   `{{secrets.X}}` referencing a vault backend. The error fires
   at compile time so a bad PR is caught before the proxy
   reloads.
2. **Multi-region replication.** A git source polled on 30s
   intervals from N regions can have one region see a refresh
   before the others. Proposal: the polling loop is per-process,
   so cross-region consistency is the operator's job (typically
   via a regional canary). The plan / apply CLI does not assume
   cluster-wide state; this matches the WOR-131 posture
   (open question 6: multi-environment workflow).
3. **Conflict between git refresh and overlay TTL.** A git push
   lands while an overlay is active. The overlay was applied
   against an older git tip; should it survive the refresh?
   Proposal: yes. The overlay applies on top of whatever git tip
   is current. The allowlist guarantees the overlay only touches
   narrow keys; the broader git change is still picked up. If
   the overlay's path no longer exists in the new git tip
   (origin removed), the overlay is auto-revoked and an audit
   entry is emitted. This is the only "auto-revoke" path; every
   other revoke is operator-driven.
4. **Observer notifications.** Today's reload path is "ArcSwap
   publishes; readers see new config." Some downstream consumers
   (the OpenAPI emitter, the projection cache, enterprise reload
   hooks) want to know which fields changed so they can do
   targeted recomputation. The plan/apply ADR handles this for
   the CLI; this ADR needs to thread the same change-set through
   the in-process reload. Proposal: extend
   `reload_from_config_path` to take an optional pre-computed
   `PlanReport`; when supplied, observers can subscribe to the
   change set. When absent (file source, no plan run),
   observers fall back to "reload happened, recompute from
   scratch." Out of scope for the first landing of source modes.
5. **Blast-radius reporting through plan.** Each source carries
   its own blast-radius shape. A git refresh can change anything
   in the config; a single overlay can only change allowlisted
   keys. The plan/apply ADR's blast-radius hint already covers
   the field-level shape; this ADR needs to thread a top-level
   "is this change `git` or `overlay`" flag into the plan body.
   Proposal: extend `PlanReport` with a `source_kind` tag at the
   top and a per-change `source_kind` discriminator. Backwards
   compatible: existing readers ignore the new fields.
6. **Auth secrets in the loader's bootstrapping path.** When
   `source: git` uses a PAT pulled from a vault backend, the
   vault has to be initialised before the loader runs. Today the
   vault is initialised inside `compile_config` because the
   secrets block is part of the compiled config. Bootstrapping
   is circular: we need the vault to read the config that
   defines the vault. Proposal: a thin `repo:` block at the YAML
   root accepts an `auth.token_env` env-var fallback so a fresh
   process can boot from `GITHUB_TOKEN` in the environment, then
   transition to a vault-backed token on the next refresh. This
   is the same shape `proxy.secrets.bootstrap_env` uses today.
7. **What does the K8s operator do?** The K8s operator already
   manages a CRD that holds the YAML. It is effectively a
   `source: db` mode where the database is etcd. Proposal: the
   K8s operator does not adopt any of the three new source modes
   in its first iteration. The CRD continues to write YAML to a
   ConfigMap that the proxy reads via `source: file`; a future
   iteration may add a `source: kubernetes-cm` mode that reads
   directly from the ConfigMap and reacts to update events.
8. **Plan staleness across overlay TTL expiries.** A plan
   computed at T0 that includes "diff against git+overlay" may
   stale before apply at T1 because an overlay expired in
   between. Apply replans (per WOR-131 open question 1); the
   second plan sees the overlay-less baseline and the change set
   shrinks. This is correct behaviour: the operator wants the
   overlay-less view if the overlay is gone. No new mechanism
   needed; the WOR-131 staleness check already covers this.

## Out of scope

For the implementation ticket, not for this audit:

- Full GitHub App auth wiring (open question 6 reserves the
  bootstrap-env path; the rest lands in a follow-up).
- Sigstore / cosign signature verification (`signed_commits` is
  the first landing's only verification mode).
- Per-tenant fleet state (the K8s operator and sbproxy-enterprise
  own this; the OSS proxy is per-process).
- Webhook-driven git refresh (`POST /admin/repo/refresh` is
  reserved but not in the first landing).
- A `kubernetes-cm` source mode (open question 7).
- A `clear-all` overlay endpoint (force-revoke is per-path).
- Multi-file git mode (single-file is the v1 shape).
- Cross-region overlay replication (overlay is per-region by
  design; cross-region consistency is the operator's CI/CD job).

## Land in this order

The implementation ticket ships the modes in five steps. Each
step is independently shippable and falls back to today's
behaviour when its config is absent.

1. **Config types.** Add the `Repo` enum to
   `crates/sbproxy-config/src/types.rs` with the four variants
   (`file`, `git`, `git+overlay`, `db`). Default is `file` with
   the path resolved from the existing CLI / env-var path so
   today's deployments are unaffected. Update
   `crates/sbproxy-config/tests/v1_compat.rs` to cover every new
   variant. No behaviour change yet.
2. **In-process git loader.** Add a `crates/sbproxy-config-git`
   crate (gated by a `git` cargo feature) that wraps `git2-rs`
   (libgit2 bindings). The crate exposes `fn fetch_yaml(repo:
   &GitRepo) -> Result<String>` and is the only git-aware
   surface. Wire it into `sbproxy_core::server::run` and
   `reload_from_config_path` behind a `match repo.source`. Keep
   the file path the default. Smoke test against a local fake
   git server (one of the tokio-based test fixtures already in
   the workspace).
3. **Overlay store.** Add a `crates/sbproxy-config-overlay`
   crate (gated by an `overlay` cargo feature). Expose
   `OverlayStore` as a trait with three impls: `InMemoryStore`
   (default), `RedisStore` (reuses the `proxy.l2_cache` Redis
   handle when configured), `EmbeddedStore` (`redb`). Plug into
   `compile_config` so the overlay applies after env-var
   interpolation but before the structural rewrites. Allowlist
   enforcement happens here; failure is a compile-time error.
4. **Admin API.** Add `POST /admin/overlays`,
   `GET /admin/overlays`, and `DELETE /admin/overlays/<path>` to
   `crates/sbproxy-core/src/admin.rs`. Reuse the existing
   basic-auth gate. Audit-log every mutation through the
   existing audit-log path (`docs/audit-log.md`). Tests cover
   the allowlist, the TTL semantics, and the force-revert path.
5. **db source mode.** Add a `crates/sbproxy-config-db` crate
   (gated by a `db` cargo feature) with a `DbLoader` that reads
   the active row, polls on a watermark, and triggers reloads.
   Bundle the schema migration. Add the `sbproxy migrate-to-db`
   subcommand to `crates/sbproxy/src/main.rs`.
6. **Plan / apply integration.** Extend
   `sbproxy_config::plan(baseline, proposed)` to accept a
   `source_kind` discriminator and per-change `source_kind`
   tags. Extend the CLI to handle the per-source apply
   semantics (file: replace; git: refuse; git+overlay: refuse
   with overlay hint; db: insert). Extend the WOR-131 ADR's
   open-question section with a cross-link to this ADR.
7. **Docs.** Update `docs/configuration.md` to document the
   `repo:` block alongside `proxy:` and `origins:`. Replace the
   implicit "the path on the CLI is the YAML" prose with an
   explicit "this is `source: file`, here are the alternatives"
   pointer. Add `docs/configuration-source-modes.md` (a
   buyer-facing reference; this ADR is the design doc) once the
   implementation lands.

The first three steps unlock the positioning win: an operator
can run `source: git+overlay` against a self-hosted git server,
declare an allowlist, and apply a TTL'd override during an
incident. Steps 4 and 5 round out the surface; step 6 is the
ergonomic polish; step 7 is the public-facing rollout.

## Cross-references

- `crates/sbproxy-config/src/compiler.rs:451` -- `compile_config`,
  the entry point every source feeds.
- `crates/sbproxy-config/src/types.rs:14` -- the `ConfigFile`
  shape that grows a top-level `repo:` block.
- `crates/sbproxy-config/src/types.rs:48` -- the
  `AgentClassesConfig.catalog` precedent for a discriminator
  with `builtin` / `hosted-feed` / `merged`.
- `crates/sbproxy-core/src/server.rs:11203` --
  `reload_from_config_path`, the single mutating reload call.
- `crates/sbproxy-core/src/server.rs:11257` --
  `start_config_watcher`, the file-shaped notify watcher that
  the git source replaces.
- `crates/sbproxy-core/src/server.rs:11311` --
  `install_sighup_handler`, the operator-driven reload that
  every source mode preserves.
- `crates/sbproxy-core/src/reload.rs` -- the `ArcSwap` reload
  state machine every source mode publishes through.
- `crates/sbproxy-core/src/admin.rs:864` --
  `handle_admin_request`, the admin route table that grows the
  three overlay endpoints.
- `docs/adr-config-plan-apply.md` -- the plan / apply CLI ADR
  this ADR threads source modes through.
- `docs/configuration.md` -- the public-facing reference that
  grows a `repo:` section once the implementation lands.
- `docs/audit-log.md` -- the audit-log path every overlay
  mutation writes to.
- `docs/adr-classifier-supply-chain-oss.md`,
  `docs/adr-fast-track-amendment.md` -- prior ADRs in this
  repo; same shape and cadence.
