# ADR: plan / apply CLI for sbproxy config (WOR-131)

*Last modified: 2026-05-08*

> Implementation note (WOR-180): scope 1+2 (CLI library + basic
> subcommands), scope 3 (semantic validation), and scope 4+5 (per-path
> blast-radius matrix + plan-file with `flock(2)`) have all shipped.
> See appendix A "Blast-radius matrix" at the end of this document for
> the path-to-radius mapping the implementation walks at plan time.

## Status

Proposed. This document is the audit + design half. The implementation
ticket is filed separately and references this ADR as the spec.

## Summary

The Catalog PRD commits to a Terraform-style `plan` / `apply` workflow
as the canonical config UX for sbproxy. The OSS proxy today reads a
YAML file, hot-swaps the compiled pipeline through `arc-swap`, and
calls that the entire UX. There is no diff-and-confirm path, no
plan-time dependency-graph validation beyond what the YAML parser
catches, and no signal to the operator about whether a change is
hitless or restart-class. This ADR audits the current load + reload
surface, proposes the `sbproxy plan` and `sbproxy apply` subcommands
on top of it, and enumerates the open questions that the
implementation ticket will need to resolve before a user-facing
release.

## Current state

The config-load pipeline today has three call sites and one shape:
`compile_config(yaml: &str) -> Result<CompiledConfig>` in
`crates/sbproxy-config/src/compiler.rs`. It is invoked at startup
inside `sbproxy_core::server::run` (line 11367), inside the file
watcher and SIGHUP handler via `reload_from_config_path` (line
11203), and inside the existing `sbproxy validate <path>`
subcommand (`crates/sbproxy/src/main.rs:378`). The same compiler
runs on every load. A `validate` invocation is the closest existing
analogue to a future `plan`: it loads the YAML, compiles it, and
returns Ok / Err. It does not diff against the running pipeline.

The hot-reload surface lives in `crates/sbproxy-core/src/reload.rs`
and is intentionally simple:

- A process-wide `ArcSwap<CompiledPipeline>` holds the current
  compiled pipeline. `current_pipeline()` returns a guard cheaply for
  the request path; `load_pipeline(new)` atomically replaces the
  pointer.
- A 64-bit atomic `DRAIN_STATE` packs an in-flight request counter
  with a single drain bit. `increment_active` / `decrement_active`
  fence each request; `begin_drain` and `is_draining` allow the
  outside world to wait for in-flight requests to finish.
- `load_pipeline` also re-renders the Wave 4 projection cache
  (robots.txt, llms.txt, llms-full.txt, licenses.xml, tdmrep.json)
  and atomically swaps it. Two atomics, back to back. Per-request
  reads can briefly observe a mismatched pair, but the projections
  are derived from the same source so the skew is sub-microsecond.

The reload itself is invoked from two places (and one optional third):

1. `start_config_watcher` (`server.rs:11257`) installs a `notify`
   file watcher on the config path. Modify events trigger
   `reload_from_config_path`.
2. `install_sighup_handler` (`server.rs:11311`) installs a tokio
   signal task on `SignalKind::hangup()` that calls
   `reload_from_config_path` for every `kill -HUP $(pgrep sbproxy)`.
3. The synthetic-traffic test harness in
   `crates/sbproxy-core/src/synthetic.rs:240` calls
   `reload::load_pipeline` directly to install a fixture pipeline.

Three properties of the existing reload matter for the plan / apply
design:

- **Reload is single-phase.** `reload_from_config_path` reads the
  file, compiles it, runs the optional `startup.on_reload` enterprise
  hook, then publishes through `ArcSwap`. There is no two-phase
  prepare / commit handshake. A consumer that wants to "stage and then
  decide" has nowhere to put the staged pipeline today.
- **Reload is best-effort on failure.** A parse or compile error is
  logged and the previous pipeline keeps serving. There is no
  exit-code surface; an operator script that ran `kill -HUP` cannot
  tell from the signal call whether the new config landed.
- **There is no plan / dry-run output.** `sbproxy validate` is
  yes/no. There is no machine-readable summary of what changed
  between the on-disk YAML and the running pipeline.

These three together are why a real `plan` subcommand cannot be a
thin wrapper over `validate` plus a `diff` of YAML strings. It needs
two compiled snapshots in hand at the same time: the running one and
the proposed one.

## Proposed CLI surface

Two new subcommands, parallel to `serve`, `validate`, and
`projections`:

```text
sbproxy plan  -f <yaml> [--against <yaml>|--running] [--out <plan-file>]
              [--format json|text] [--no-color]
sbproxy apply -f <yaml> | -p <plan-file>
              [--auto-approve] [--reload-only|--restart-required]
```

### `sbproxy plan`

`sbproxy plan -f sb.yml` compiles the proposed YAML, loads a baseline
to diff against, and emits a structured plan plus a human-readable
summary.

Arguments:

| Flag | Meaning |
|---|---|
| `-f <yaml>` / `--config <yaml>` | The proposed config. Required. |
| `--against <yaml>` | Baseline config file. Default: see below. |
| `--running` | Force baseline = running pipeline (only valid when invoked on a host running sbproxy and with the admin socket reachable). |
| `--out <plan-file>` | Write the JSON plan to disk for later `apply -p`. |
| `--format json|text` | Default `text` to stdout; `json` is the machine-readable plan body. |
| `--no-color` | Disable ANSI colour. |

Baseline resolution order:

1. `--running` set: read current pipeline from the admin socket. (See
   open question on admin-socket plan-export.) Requires an in-tree
   sbproxy process and `proxy.admin.enabled: true`.
2. `--against <yaml>` set: compile and use that file.
3. Default: the file at the path stored in `SB_CONFIG_FILE`, or the
   path passed to the running process via `--config`. If neither is
   readable, fall back to "empty baseline" and emit every origin in
   the proposed config as `Added`.

Exit codes (Terraform-shaped):

- `0`: no changes between baseline and proposed.
- `1`: CLI / IO error (file not readable, malformed argv).
- `2`: changes present (informational, not an error).
- `3`: semantic-validation failure (orphan ref, missing secret,
  unknown policy). Plan is not written.

Output format. JSON body, stable schema:

```jsonc
{
  "plan_version": 1,
  "generated_at": "2026-05-08T14:22:01Z",
  "baseline_kind": "running" | "file" | "empty",
  "baseline_revision": "<sha256-12 of baseline yaml>",
  "proposed_revision": "<sha256-12 of proposed yaml>",
  "changes": [
    {
      "path": "origins.api.example.com.policies[2]",
      "kind": "added" | "changed" | "removed",
      "old": <json|null>,
      "new": <json|null>,
      "blast_radius": "hitless" | "reload" | "restart" | "breaking",
      "reason": "added rate_limit policy"
    }
  ],
  "summary": {
    "added":   { "origins": 1, "policies": 3, "transforms": 0 },
    "changed": { "origins": 0, "policies": 1, "transforms": 2 },
    "removed": { "origins": 0, "policies": 0, "transforms": 0 }
  },
  "max_blast_radius": "reload"
}
```

The text format is a column-aligned summary mirroring `terraform
plan`: leading `+` / `~` / `-` per change, blast-radius badge in
square brackets, and a footer line with totals.

### `sbproxy apply`

`sbproxy apply -f sb.yml` is the single mutating verb. It composes
`plan` (against the running pipeline if reachable, otherwise against
the on-disk previous config) and the existing
`reload_from_config_path` call.

Arguments:

| Flag | Meaning |
|---|---|
| `-f <yaml>` | Proposed config. Mutually exclusive with `-p`. |
| `-p <plan-file>` | Plan file from a prior `plan --out`. The file embeds the proposed-config bytes so the plan and apply see the exact same input. |
| `--auto-approve` | Skip the interactive confirmation. Required in non-TTY contexts. |
| `--reload-only` | Refuse to apply if any change has `blast_radius >= restart`. |
| `--restart-required` | Refuse to apply if any change has `blast_radius == hitless` or `reload` (operator wants to bundle this with a restart). |

Exit codes:

- `0`: applied cleanly. The pipeline now serves the proposed config.
- `1`: CLI / IO error.
- `3`: semantic-validation failure.
- `4`: blast-radius gate hit (`--reload-only` with a restart-class
  change present, or vice versa).
- `5`: the plan file is stale (the running pipeline's revision no
  longer matches the plan's `baseline_revision`). The operator must
  rerun `plan`.

Apply semantics:

- Re-runs `plan` internally even when `-p plan-file` is supplied;
  the second plan must produce an identical change set or apply fails
  with exit code 5. This is the staleness check.
- Calls `reload_from_config_path` exactly once on success. The
  enterprise `startup.on_reload` hook runs as it does today.
- Apply is idempotent: re-running with the same config against the
  same baseline produces a zero-change plan and a no-op reload.
- Apply is **not** atomic across multiple proxy processes. Each
  process applies its own reload independently. Cluster-wide rollout
  is the operator's job (or the K8s operator's) and is out of scope
  for this CLI.

### Diff format

Each `change` entry is the four-tuple `(path, kind, old, new)` plus
`blast_radius` and `reason`. `path` is a JSONPath-shaped string
rooted at the YAML document. `kind` is `added` / `changed` /
`removed`. `old` and `new` are the raw JSON values; for `added`,
`old` is null; for `removed`, `new` is null.

The diff operates over the **raw `ConfigFile`** (parsed YAML), not
the `CompiledConfig`. Diffing the compiled form would expose internal
restructuring (the `auto_content_negotiate` synthesis in
`compile_origin`, the `features.*` -> `extensions.*` migration, the
template-variable interpolation pass) as user-visible changes when
they are not. Diffing the raw `ConfigFile` after env-var
interpolation but before structural rewrites gives the operator a
diff that maps one-to-one to what they edited.

## Plan-time semantic validation

Each rule below is enforced at plan time. Any failure produces exit
code 3 and writes no plan file. The set is derived from what the
current `compile_config` already catches lazily (and reports as a
runtime error today) plus what Terraform-style users expect from
plan-time validation:

- **Orphan origin reference.** A `forward_rule.target` or
  `fallback_origin.url` that names a hostname not present in
  `origins.*`. Failure shape: `orphan_ref { from: "<path>", target:
  "<hostname>" }`.
- **Missing secret.** A `{{secrets.X}}` template reference where `X`
  does not appear under `proxy.secrets.*`. Failure shape:
  `missing_secret { reference: "<path>", name: "X" }`.
- **Missing variable.** A `{{vars.X}}` template reference where `X`
  is not in the origin's `variables:` block (or any parent scope).
  Failure shape: `missing_var { reference: "<path>", name: "X" }`.
- **Unknown policy / action / auth / transform type.** A `type:`
  value not registered in the `sbproxy-plugin` registry at the time
  `plan` runs. Failure shape: `unknown_module { kind: "policy" |
  "action" | "auth" | "transform", name: "X", at: "<path>" }`.
- **Schema-incompatible field.** Any field that fails serde
  deserialisation in `RawOriginConfig` or `ConfigFile`. Failure
  shape: `schema_error { path: "<path>", message: "<serde error>" }`.
- **Conflicting legacy + new shape.** The same conflict that
  `migrate_features_to_extensions` already reports today (operator
  has both `features.anomaly_detection` and the
  `proxy.extensions.anomaly_detection` block). Failure shape:
  `conflicting_shape { legacy: "<path>", canonical: "<path>" }`.
- **L2 cache / messenger driver unknown.** `l2_cache.driver` or
  `messenger_settings.driver` value that `build_l2_store` /
  `build_messenger` would reject at compile time. Failure shape:
  `unknown_driver { component: "l2_cache" | "messenger", value: "X" }`.
- **Trust boundary regression.** Any change that flips
  `proxy.tls.verify_client = false` or removes a `mtls:` block
  flagged with `--require-mtls`. Soft warning by default; hard error
  under `--strict`. Failure shape: `trust_regression { path: "<path>",
  before: <json>, after: <json> }`.

The first six are land-now rules that the existing compiler already
implies. The last two are scope creep for the implementation ticket
to push back on if the engineering bill grows.

## Blast-radius hint

Every `change` carries one of four labels:

- **`hitless`**: the change can be applied without re-routing any
  in-flight or future request. Examples: log-level only, access-log
  filter tweaks, observability `properties.capture[*]` adjustments.
- **`reload`**: the change requires `arc-swap` to publish a new
  pipeline. In-flight requests finish on the old pipeline; new
  requests pick up the new pipeline. This is what the existing
  hot-reload path does today. Examples: any origin add / remove,
  any policy add / change / remove, any auth change, any transform
  change, any forward_rule change, any rate_limits change.
- **`restart`**: the change requires the OS process to restart
  because the listener or process-global state cannot be hot-swapped.
  Examples: `proxy.http_bind_port`, `proxy.https_bind_port`,
  `proxy.http3.enable`, `proxy.tls.cert_file` (cert reload via SIGHUP
  is supported, but switching providers / paths is restart-class
  today), `proxy.admin.port`, `agent_classes.*` (the resolver is
  installed once per process per the comment at `reload.rs:194`).
- **`breaking`**: the change is `restart`-class **and** would drop
  in-flight connections beyond the existing graceful-shutdown
  budget. Examples: changing the bind address, switching the worker
  thread count, changing the `proxy.protocols` set in a way that
  invalidates connection pools.

Mapping rule, by config path:

| Path prefix | Default blast-radius |
|---|---|
| `proxy.http_bind_port`, `proxy.https_bind_port`, `proxy.bind_addr` | restart |
| `proxy.http3.*`, `proxy.admin.port` | restart |
| `proxy.tls.cert_file`, `proxy.tls.key_file` | reload (cert hot-swap is supported) |
| `proxy.tls.verify_client`, `proxy.tls.ca_file` | reload |
| `proxy.l2_cache_settings.driver` | restart (driver swap rebuilds the KV handle) |
| `proxy.l2_cache_settings.params.*` | reload |
| `proxy.messenger_settings.driver` | restart |
| `proxy.messenger_settings.params.*` | reload |
| `proxy.metrics.*`, `proxy.access_log.*` | hitless |
| `proxy.alerting.*` | hitless |
| `agent_classes.*` | restart (resolver is OnceLock today) |
| `origins.*` (add / remove / change of any nested field) | reload |

Tooling override: the operator can pass `--treat-as-reload <path>`
to downgrade a `restart` entry to `reload` when they know the field
is safe to hot-swap on their build (e.g. they applied a patch that
made the agent-class resolver rebuild on reload). The override is
recorded in the plan body so apply can replay it.

## Open questions

These are the items that the implementation ticket has to resolve
before the CLI ships to operators:

1. **Plan staleness window.** A plan file written at T0 references
   `baseline_revision = R0`. At T1 the operator runs `apply -p`. If
   the running pipeline is now at R1 (someone else applied), apply
   exits 5. What is the right TTL for a plan file on disk before we
   stop trusting it? Terraform refuses any plan whose state lineage
   has changed; we propose the same posture but flagged via
   `--ignore-staleness` for emergencies.
2. **State file vs no state file.** Terraform's plan/apply story
   leans on a state file. sbproxy today has no equivalent; the
   running pipeline's `ArcSwap` snapshot is the only "state." Do we
   introduce a `~/.sbproxy/state.json` (or `/var/lib/sbproxy/state`)
   to record the last applied revision per host, or do we always
   diff against the running pipeline via the admin socket? Proposal:
   **no state file in the OSS path**; always diff against either
   `--against <yaml>` (the on-disk last-applied) or `--running` (the
   admin socket). The state file is reserved for the fleet-management
   layer (out of scope, lives in the K8s operator or in
   sbproxy-enterprise).
3. **Lock semantics.** Terraform takes a state lock for the
   duration of an apply to prevent concurrent applies. Our analogue
   would be a single-process apply lock so two operators running
   `apply` against the same on-host config don't race each other.
   Proposal: file lock at the config path's parent (`flock(2)` on
   `<config-dir>/.sbproxy.lock`) for the duration of plan + apply.
4. **Admin-socket plan-export.** `--running` requires sbproxy to
   expose the currently-running compiled config so a peer process
   can diff against it. The admin server today exposes metrics and
   a few debug endpoints but not the compiled config. Adding it
   means deciding what to redact (secret values, vault tokens, the
   `proxy.secrets.*` block). Proposal: ship `--running` in a follow-up
   under `proxy.admin.expose_config: true`, default off; the first
   landing of `plan` ships with `--against <yaml>` only.
5. **Plan-vs-apply staleness vs the file watcher.** The `notify`
   file watcher reloads on file modify. If an operator runs
   `sbproxy plan -f new.yml --out plan.json`, then writes `new.yml`
   over the live config path, the file watcher fires and reloads
   before `apply -p plan.json` runs. The plan was correct at T0; the
   apply now runs against a moving baseline. Proposal: when invoked
   under a config path that the running process is watching,
   `apply` writes to a temp file, runs the plan against the live
   pipeline, and atomically `rename(2)`s the temp file into place
   only after the staleness check passes. The file watcher's reload
   becomes idempotent against the apply.
6. **Multi-environment workflow.** Terraform handles staging vs prod
   via workspaces. Our operators today juggle multiple `sb.yml`
   files (e.g. `staging.yml`, `prod.yml`) and run separate proxy
   processes. The CLI should not assume a single global config path.
   Proposal: every plan / apply invocation is scoped to a single
   `-f`; cross-environment workflows are the operator's CI / CD job.
7. **Future config-source-of-truth integration.** The Catalog PRD
   anticipates a config source that is not "single YAML on disk"
   (database row, git+overlay, K8s CRD). The plan / apply CLI must
   not assume the file system; the JSON plan body's
   `baseline_revision` and `proposed_revision` already abstract
   over the source. Proposal: keep the CLI surface YAML-first for
   v1; the K8s CRD path uses the same plan/apply machinery in-process
   via a `sbproxy_config::plan(baseline, proposed)` library API that
   the CLI is a thin wrapper around.
8. **Two-phase apply for `restart`-class changes.** The current
   reload state machine is one-phase. For `restart`-class changes,
   apply today would have to spawn a fresh `sbproxy` process and
   hand off the listener. Pingora has built-in graceful-shutdown
   support, but the CLI has no way to drive a restart from the
   outside. Proposal: `apply --restart-required` runs the plan, prints
   "restart required", and exits 4; the operator (or systemd /
   supervisord) handles the actual restart. A future enhancement
   could exec a fresh binary using `pingora-core`'s upgrade path.

## Migration / rollout

The new subcommands land behind the existing `serve`, `validate`,
and `projections` verbs without changing any of them. Specifically:

- `sbproxy --config <path>` (the bareword form) keeps starting a
  proxy. Unchanged.
- `sbproxy serve -f <path>` keeps starting a proxy. Unchanged.
- `sbproxy validate <path>` and `sbproxy --check` keep doing
  parse + compile, no diff. Unchanged.
- `sbproxy projections render` keeps emitting per-host preview
  documents. Unchanged.
- The `notify`-based file watcher and the SIGHUP handler keep
  reloading on file change. Unchanged. `apply` and the file watcher
  use the same `reload_from_config_path` plumbing; they are
  redundant by design (an operator who has not adopted the CLI yet
  keeps the existing UX).
- `sbproxy plan` is purely additive. It compiles two configs and
  writes to stdout / a plan file. It never touches the running
  pipeline.
- `sbproxy apply` calls `reload_from_config_path` exactly the way
  the file watcher does. The reload state machine does not
  distinguish between "watcher fired" and "apply called."

The release notes for the version that ships these subcommands will
recommend adopting `apply` over editing-and-saving as the standard
operator workflow, but they will not deprecate the file-watcher
path. The two coexist indefinitely.

`docs/configuration.md` § Validation grows a cross-link to this ADR
and a one-paragraph "for production deployments, prefer `sbproxy
plan` + `sbproxy apply` over editing in place" note. The ADR itself
is the long-form reference.

## Out of scope

For the implementation ticket, not for this audit:

- Implementing the actual CLI parser, diff engine, and reload
  integration.
- Building the admin-socket `--running` path (deferred per open
  question 4).
- The `flock(2)` apply lock (deferred per open question 3).
- A persistent state file (rejected per open question 2).
- Plan TTL enforcement and timestamp-based staleness (deferred per
  open question 1).
- Remote-state backends (rejected for OSS; lives in
  sbproxy-enterprise or the K8s operator).
- Two-phase apply with process exec / listener handoff (open
  question 8).
- Multi-tenant fleet apply and CI/CD integration patterns.

## Cross-references

- `crates/sbproxy-config/src/compiler.rs:451` -- `compile_config`,
  the entry point both subcommands wrap.
- `crates/sbproxy-config/src/snapshot.rs` -- the `CompiledConfig`
  shape that the diff projects through.
- `crates/sbproxy-core/src/reload.rs` -- the `ArcSwap` reload state
  machine `apply` integrates with.
- `crates/sbproxy-core/src/server.rs:11203` --
  `reload_from_config_path`, the single mutating call apply makes.
- `crates/sbproxy/src/main.rs:378` -- existing `validate`
  subcommand, the structural template for `plan` and `apply`.
- `docs/configuration.md` § Validation -- the public-facing doc that
  grows a cross-link to this ADR.
- `docs/adr-classifier-supply-chain-oss.md`,
  `docs/adr-fast-track-amendment.md` -- prior ADRs in this repo;
  same shape and cadence.

## Appendix A: Blast-radius matrix

Step 4 of the WOR-180 implementation replaces the per-top-level-key
mapping with a per-path matrix. The matrix lives in
`crates/sbproxy-config/src/plan.rs` as the `BLAST_RADIUS_MATRIX`
constant. The diff walker enumerates every changed JSON leaf within
each `PlanEntry` (the `proxy` block, each origin, `access_log`,
`agent_classes`), looks each leaf up in the matrix, and takes the
worst-case radius across the set.

Path syntax:

- `*` matches exactly one segment.
- `**` (only at the end of a pattern) matches one or more trailing
  segments, used for "anything under this subtree."
- Origin hostnames are substituted with `*` upstream of the lookup
  because hostnames are themselves dot-separated and cannot be split
  out reliably from a path string. Array indices are substituted with
  `*` by `canonicalise_path`.

Default radius for any leaf that does not match a pattern: `Reload`.
The reload state machine is the cheapest non-no-op operation, so an
unmatched future field defaults to "publish a new pipeline through
arc-swap" rather than "restart the process."

The full matrix at first land:

| Pattern | Blast radius | Why |
|---|---|---|
| `proxy.http_bind_port` | `Restart` | listener port is bound once at startup |
| `proxy.https_bind_port` | `Restart` | listener port is bound once at startup |
| `proxy.http2_cleartext` | `Restart` | h2c preface detection is wired at bind time |
| `proxy.http3.**` | `Restart` | QUIC listener is bound once at startup |
| `proxy.admin.port` | `Restart` | admin server listener is bound once at startup |
| `proxy.admin.bind_addr` | `Restart` | admin server listener is bound once at startup |
| `proxy.admin.enabled` | `Restart` | toggling the admin server requires a fresh listener |
| `proxy.admin.**` | `Reload` | admin auth / TLS settings re-read on reload |
| `proxy.tls_cert_file` | `Reload` | cert reload is supported through SIGHUP |
| `proxy.tls_key_file` | `Reload` | key reload is supported through SIGHUP |
| `proxy.acme.**` | `Reload` | ACME state lives in the arc-swapped pipeline |
| `proxy.mtls.**` | `Reload` | mTLS handshake config reloads via arc-swap |
| `proxy.l2_cache.driver` | `Restart` | driver swap rebuilds the KV handle |
| `proxy.l2_cache_settings.driver` | `Restart` | driver swap rebuilds the KV handle |
| `proxy.l2_cache.**` | `Reload` | L2 parameters re-read on reload |
| `proxy.l2_cache_settings.**` | `Reload` | L2 parameters re-read on reload |
| `proxy.messenger_settings.driver` | `Restart` | driver swap rebuilds the bus handle |
| `proxy.messenger_settings.**` | `Reload` | messenger parameters re-read on reload |
| `proxy.metrics.**` | `Hitless` | metrics config is read per request |
| `proxy.alerting.**` | `Hitless` | alert channels reload via arc-swap |
| `proxy.correlation_id.**` | `Hitless` | correlation-id policy is read per request |
| `access_log.**` | `Hitless` | access-log filter is read per request |
| `proxy.trusted_proxies.**` | `Reload` | trusted-proxy CIDRs re-read on reload |
| `proxy.secrets.**` | `Reload` | secret store reloads via arc-swap |
| `proxy.cache_reserve.**` | `Reload` | cache reserve handles reload via arc-swap |
| `proxy.synthetic_probe.**` | `Reload` | probe task respawns on reload |
| `agent_classes.**` | `Restart` | resolver is `OnceLock`-globaled |
| `origins.*.authentication.type` | `Breaking` | auth-type swap breaks wire compatibility |
| `origins.*.action.type` | `Breaking` | action-type swap (e.g. `proxy` to `static`) breaks wire compatibility |
| `origins.*.action.**` | `Reload` | action body re-read on reload |
| `origins.*.policies.**` | `Reload` | policy chain re-compiles on reload |
| `origins.*.transforms.**` | `Reload` | transform chain re-compiles on reload |
| `origins.*.authentication.**` | `Reload` | auth body (keys, JWKS URL) re-read on reload |
| `origins.*.rate_limits.**` | `Reload` | rate-limit budget re-read on reload |
| `origins.*.properties.**` | `Hitless` | properties capture is read per request |
| `origins.*.sessions.**` | `Hitless` | session capture is read per request |
| `origins.*.user.**` | `Hitless` | user-id capture is read per request |
| `origins.*.connection_pool.**` | `Reload` | connection pool rebuilds on reload |

In addition to the matrix, two structural rules apply:

- **Origin removal is `Breaking`.** An origin present in the baseline
  but absent in the proposed config drops in-flight clients in a way
  that the reload's connection-drain budget cannot recover from. The
  walker hard-codes this case (no matrix lookup) so operators see it
  distinctly from a hot-reload-friendly tweak.
- **Unknown future fields are `Reload`.** When no pattern matches a
  changed leaf, the walker assigns `Reload` and surfaces a
  "no specific rule matched" reason. Adding a new server-level field
  to `ConfigFile` should land alongside a matrix entry that captures
  its true blast radius; the default keeps the system safe in the
  meantime.

## Appendix B: plan-file format

Step 5 of the WOR-180 implementation adds an on-disk plan-file format
written by `sbproxy plan -f <yaml> --out <plan-file>` and consumed by
`sbproxy apply -p <plan-file>`. The format is a JSON envelope with
three fields:

```jsonc
{
  "plan_file_version": 1,
  "baseline_revision": "<sha256-hex of canonical baseline ConfigFile>",
  "report": {
    "plan_version": 1,
    "entries": [...],
    "summary": {...},
    "max_blast_radius": "...",
    "findings": [...]
  }
}
```

The `baseline_revision` is `SHA256` of `serde_json::to_vec(&baseline)`
hex-encoded. `serde_json` orders map keys lexicographically, so the
same logical baseline hashes identically across runs even when the
source YAML reorders keys.

Apply semantics:

- `apply -p <plan-file>` requires the operator to supply the proposed
  YAML path through `SB_APPLY_CONFIG` (the plan-file does not embed
  it). Mirrors the `SB_CONFIG_FILE` pattern used elsewhere in the
  binary.
- The baseline at apply time defaults to the empty config; operators
  who diffed against an explicit `--against <yaml>` at plan time
  should set `SB_APPLY_BASELINE` to the same path.
- Apply recomputes `baseline_revision` against the live baseline. If
  the recomputed hash differs from the value in the plan-file, apply
  exits **5** ("plan file is stale") and asks the operator to rerun
  `plan` and re-apply. This implements the staleness check in the
  ADR's apply-side exit-code table.
- Apply takes an exclusive `flock(2)` on `<yaml_path>.applylock` for
  the duration of the run (per ADR open question 3). On contention
  apply exits **6** ("apply is in progress").
- Plan-file writes are atomic via temp-file + `rename(2)` (per ADR
  open question 5). A crash mid-write leaves the previous
  plan-file's bytes in place rather than a half-written truncated
  file.
