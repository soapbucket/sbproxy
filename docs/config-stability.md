# Config stability tiers

*Last modified: 2026-08-21*

This page defines the stability tiers and applies them to representative or
high-impact configuration leaves. It also lists the current reviewed
`config-only` registry. It is not an exhaustive field matrix:
[`configuration.md`](configuration.md) is the complete field inventory.

An unlisted field has no implicit stability promise. Before depending on one,
review its Rust source and the changelog for the release you plan to run.

---

## Stability tiers

### `stable`

A `stable` field is part of the committed public API of SBproxy.

- The field name, type, and default value will not change in a minor or patch release.
- Removing or renaming a `stable` field requires a major version bump (e.g. v1 -> v2) and a migration guide.
- Behavioral changes to a `stable` field require at least a minor version bump and a changelog entry.

### `beta`

A `beta` field is functional and tested but may still change.

- Available for production use. Monitor the changelog before upgrading.
- Renames or semantic changes may happen in a minor release with a deprecation notice.
- Beta fields are not silently removed. A one-release deprecation period applies.

### `alpha`

An `alpha` field is experimental.

- May be renamed, restructured, or removed in any release without prior notice.
- Do not depend on `alpha` fields in critical production paths.
- Feedback on alpha fields is welcome and influences their stabilization.

### `disabled`

A `disabled` field is retained in the schema but cannot activate runtime behavior today.

- An omitted block or its disabled value remains valid for config compatibility.
- Attempting to enable unavailable behavior fails config compilation instead of being ignored.
- Currently applies to the `http3` block. Native HTTP/3 support is not implemented.

`disabled` is a tier in this document, not a level in the build-time key
registry. That registry has four levels (`stable`, `preview`,
`config_only`, `unsupported`) and pins the three `proxy.http3` leaves
`config_only`, which is the accurate level for them: the keys parse and
nothing reads them. `unsupported` would be wrong, because that level
means the compiler rejects a document for containing the key at all, and
`http3:` with `enabled: false` compiles. `disabled` is those
`config_only` keys plus the one refused value, so `config_only` for
`proxy.http3.*` in registry-backed output is not a contradiction.

### `config-only`

A `config-only` field remains parseable for compatibility but has no live
consumer in the open-source runtime.

- Do not use it to satisfy an operational requirement.
- An explicitly authored config-only key emits a boot/config-validation warning
  naming the complete schema path and the reason it has no effect.
- The build-time config-reader guard requires an explicit registry entry and
  an operator-facing reason for every such field.
- The field is removed from examples that purport to demonstrate working
  behavior. Its reference entry states the live alternative, when one exists.

---

## Stabilization rules

1. A field moves from `alpha` to `beta` once its interface is reviewed, it has integration tests, and it has been in at least one release.
2. A field moves from `beta` to `stable` once it has been in production use by at least one internal deployment for one full release cycle without interface changes.
3. Stable fields are never silently removed. The process is: deprecate (the config compiler logs a structured deprecation warning at load time naming the legacy and canonical field), then remove in the next major version. A schema-level `x-deprecated` annotation is planned but not shipped.

## Build-time reader coverage

CI walks the generated `ConfigFile` JSON Schema and requires every key to have
either a non-test Rust field read or a reviewed entry in
`CONFIG_KEY_OVERRIDES`. Indirect serde consumers name their concrete runtime
consumer. Deliberately inert fields are marked `config-only` with a reason.
Run the same lane locally with:

```bash
scripts/check-config-readers.sh
```

Adding a key to `types.rs` without wiring it now fails with the complete dotted
schema path. Adding a reviewed `ConfigOnly` entry makes the exception explicit
and stale entries fail when their schema path is removed or renamed.

### Module and AI-gateway keys

The generated schema stops at `action:`, `authentication:`, `policies:` and
`transforms:`, because modules are pluggable and the configuration crate does
not name their types. Keys below those four are covered by a second input: a
registry of subtrees, each naming the Rust type the subtree deserializes into,
which the same scan walks directly.

Coverage is deliberately incremental. Every module an operator can name must
say whether its configuration is walked, and a module that reaches the config
compiler without saying so fails the build. Saying "not yet" is a valid answer
and requires a reason.

A module may also warn for its own config-only field rather than route it
through the registry, using the same message and the same `config_key` field
the registry uses, so an operator reads one boot log rather than two. No
module field does this today: `origins.*.action.sticky`, the one field that
did, was removed in favor of the `ring_hash` load-balancer algorithm and is
now refused at config compile with an error naming the replacement.

#### Unknown keys inside an `authentication` block

**Upgrade-affecting.** A configuration that carried a key the proxy did not
recognize inside an `authentication:` block used to compile, boot, and serve.
It now fails to compile, at `serve`, `validate`, and hot reload alike, with an
error naming the key and the ones the provider accepts:

```
unknown field `require_dp0p`, expected `tokens` or `require_dpop`
```

What that changed. `authentication:` is an opaque value on the typed
envelope, so neither of the two schema-level unknown-key passes reaches
inside it, and each provider deserialized permissively: serde dropped a key
it did not know and the setting that key was meant to be took its default.
Every optional switch on an auth provider defaults to the permissive value,
so a single mistyped character produced a config that read as though a
control were on and ran with it off. `require_dp0p: true` on a `bearer` block
served with DPoP proof-of-possession disabled; `require_mtls_bnd: true` on
`jwt` served with RFC 8705 certificate binding disabled. The same shape
applied to `tls_verify` on `ldap_auth`, `require_agent_binding` on `cap`,
`nonce_policy` on `bot_auth`, and `clock_skew_seconds` on `hmac_auth`.

The refusal rides the existing config-compile error path, so a rejected hot
reload leaves the last-good configuration serving; only a boot on a rejected
file stops the proxy.

What to do on upgrade: run `sbproxy validate <path>` before rolling. Any key
it names is one the proxy was already ignoring, so correcting the spelling
gives you the control the file claimed, and deleting the line gives you the
behavior you were actually running. Neither is a silent change.

Two surfaces stay permissive on purpose. `noop` has no configuration to
check. And the per-credential entries under `api_keys:`, `tokens:`, `users:`,
and `hmac_auth`'s `keys:` fold free-form attribution metadata (`project`,
`team`, `tags`, `metadata`) into the same mapping as the secret, so an
unknown key there cannot be told apart from an intended one.

The same change made `proxy.extensions.agent_detect` refuse unknown keys, and
made a malformed block that sets `enabled: true` a hard compile error rather
than a warning that left the scorer off. An absent `agent_detect` block is
unchanged: detection stays off and nothing is logged. A malformed block that
does not set `enabled: true` also keeps warning and disabling, since disabled
is what it asked for. This matches `proxy.extensions.tls_fingerprint`, which
already behaves this way.

#### Module keys refused at config compile

A module key that names behavior the runtime does not have is refused rather
than warned about, because a key nobody can make work is not a compatibility
surface. The error names the key, says what it did not do, and points at the
surface that does the job. Boot and reload both refuse the document.

| Key | Why it is refused | What to use instead |
|---|---|---|
| `origins.*.action.context_overflow` (`ai_proxy`) | Never a field on the AI handler and never read by anything. The decision layer behind it (error, fall back to a larger model, truncate) had no caller in the life of the tree, and the AI gateway guide described the block as ignored, which left operators free to write it. | A `window_fit` lever under `compression.levers`, or the `resilience.llm_aware.context_compress` shorthand, to fit the prompt in place. To reroute it to a larger-window model instead, name that provider in `context_window_fallbacks:` on the action. |
| `origins.*.action.sticky` (`load_balancer`) | No affinity cookie was ever issued. | `algorithm: ring_hash` keyed on `cookie`, `header`, `ip`, or `uri`. |
| `transforms[].allowed_hosts` (`type: wasm`) | Never enforced, and unenforceable: WASM modules have no network surface at all here, so the allowlist described a boundary nothing checked. | Keep the reaching on the proxy side. Gate the origin with an `expression` policy, or route the callout through an origin the proxy controls. The key returns as an enforced one if a host callout ever lands. |
| `transforms[].on_request` (`type: cel`) | Compiled at config load and never evaluated. Transforms run on the response body, so there is no request phase for it to run in. | An `expression` policy to gate the request, a rate-limit or WAF `key:` expression to key on it, or a forward rule to route on it. |
| `transforms[].on_response`, and its `expression` alias (`type: cel`) | Replaced the entire response body with whatever scalar the expression evaluated to. No partial edit, no structure-aware change, no streaming. CEL is for deciding; producing a payload is a different job, and no config in the tree ever authored the key. | A `javascript`, `lua_json`, or WASM transform, each of which parses the body, edits part of it, and re-emits. The same transform's `headers:` rules still set response headers from CEL. |
| `sandbox.memory_mb` (bundle manifest, `runtime: rego`) | Reached nothing. A Rego hook evaluates on the Regorus interpreter inside the proxy's own process, so there is no guest heap to bound, and the interpreter's allocator guards compile to `Ok(())` unless a Cargo feature this workspace does not enable is on. The number an operator wrote bounded nothing at all while reading as a sandbox control. | `sandbox.budget_ms` bounds evaluation time, and `sandbox.max_buffer_bytes` plus `sandbox.max_output_bytes` bound the body in and the replacement out. The key is still honored on `runtime: wasm`, `proxy_wasm`, and `javascript`, which do have a guest to bound. |
| `sandbox.stack_kb` (bundle manifest, `runtime: rego`) | Same: no guest stack exists to bound, and 0.11 exposes no stack-depth knob the key could have been mapped to. | The same three keys as `memory_mb` above, and the key keeps working on the three runtimes that have a guest stack. |

#### Schema keys refused at config compile

These parsed, warned once at boot, and then governed nothing. A warning
can be the proportionate response to a key that does less than its name
promises while still doing something, but the promise has to be small.
`origins.*.action.targets[].zone` is the surface that walked every
state this page names: it started as a warned-about display label
(rendering a column in the admin target-health view), moved to the
refused table once it was clear the column was not what operators were
writing the key for, and left that table when zone-aware selection
shipped and the label started steering traffic. A key leaves the
refused table in exactly one direction: by gaining the enforcement its
name promises in the same change that re-admits it.

Refusal is for two other shapes. The first is a key with nothing behind
it at all, where a config that sets it keeps claiming a property the
proxy does not have: a connection cap nothing enforces, a retention
window nothing retires on, a catalog file nothing opens. The second is a
key that reads as the opposite of what it does. `cors.enable` was the
second one. The runtime turns CORS on when the `cors:` block is present
and never looks at the boolean inside it, so an operator who wrote
`enable: false` to switch CORS off switched it on. A boot warning next
to headers the proxy is already sending does not fix that.

Three of the rows below name a value rather than a key, because only one
of the accepted values misdescribed the build and the other agreed with
it. Those three keys stay writable at the value the proxy actually does.

Two further rows name a value for a different reason. The response
cache's `key_event` and `admit_event` take an inline script, and two of
the engine names an operator might reach for cannot answer the event at
all: one returns the wrong shape, the other is not inline source.
Neither is inert, so neither is a warning. They are refused where every
other engine mistake is caught, at config compile.

| Key | Why it is refused | What to use instead |
|---|---|---|
| `origins.*.connection_pool.max_connections` | Pingora sizes the upstream keepalive pool once per connector, not per origin, so there was no per-origin limit for the value to become and upstream connections were never capped at it. | A `concurrent_limit` policy, which caps in-flight requests per origin and rejects over the cap rather than queueing. |
| `origins.*.connection_pool.max_lifetime_secs` | Pingora's connection pool has no age-based eviction, so no pooled connection was ever retired for being old. | `timeouts.idle_ms`, the deadline that does retire pooled connections once they go unused. |
| `origins.*.cors.enable: false` (alias `enabled`) | Both entry points, the preflight responder and the response header pass, gate on the presence of the `cors:` block and neither reads the boolean. An operator who wrote `false` to switch CORS off ran with CORS fully on. `true` stays accepted, because it agrees with what the block already does. | Delete the whole `cors:` block to turn CORS off for that origin. To keep CORS on, delete just the `enable` line and narrow `allowed_origins` instead. |
| `origins.*.forward_rules[].origin.hostname` | The request has already been matched to the parent origin by the time a rule fires, so this tag selected no upstream and changed no header. The inline origin's `action`, `request_modifiers`, and `id` are the only three fields anything reads. | The rule's own `origin.action.url`, to send the matched request to a different host. To label the rule, use `origin.id`, which does reach metrics and the emitted OpenAPI document. |
| `origins.*.forward_rules[].origin.version` | The compiled child origin carries no version label, so the value reached neither routing, logs, metrics, nor the emitted OpenAPI document. | Match the version in the path instead (`rules: - path: { prefix: /v2/ }`). To version the rule for your own records, fold it into `origin.id`. |
| `origins.*.forward_rules[].origin.workspace_id` | The compiled child origin has no workspace field, so nothing scoped, attributed, or logged a request by it. | `origins.*.tenant_id`, naming an id declared under `proxy.tenants[]`. That one is checked at compile and labels the request everywhere downstream. |
| `origins.*.response_cache.key_event.engine: cel`, and the same value on `admit_event` | These events return a document, a list of key dimensions for `cache.key` and `store` plus `ttl_secs` for `cache.admit`, and CEL evaluates to a single scalar. Accepting it would mean a token grammar for packing a document into a string, which is what `route_to:gpt-4o-mini` already did once. | `lua` or `js`, which return documents natively. CEL keeps every surface where a scalar is the answer: `expression` and `assertion` policies, rate-limit and WAF keys, custom log fields, and the `cel` transform's header rules. |
| `origins.*.response_cache.key_event.engine: wasm`, and the same value on `admit_event` | The field takes an inline `source`, and a compiled module is not inline source, so there was nothing for the engine to evaluate. | `lua` or `js` for an inline script. For a compiled hook, attach it through an [extension bundle](extension-bundles.md), which is the surface that gives a module a path, a version, and a load step. |
| `origins.*.sessions.ttl_seconds` | There is no sessions index to retain. Sessions appear in the admin recent-request ring, which is bounded by entry count and evicts the oldest entry when full, so a session aged out on request volume and never on this deadline. | `sessions.budget.max_per_window` with `sessions.budget.window_seconds`, both enforced. |
| `origins.*.traffic_capture` | No capture consumer exists. The block was accepted as an untyped value, so nothing validated its contents either and a misspelled field inside it looked exactly like a working setting. | `mirror`, which forwards a fire-and-forget copy of each request to a second upstream without delaying or failing the real one. |
| `proxy.device_parser_file` | The device parser matches on compiled-in rules and has no code path that opens a catalog file, so a maintained catalog and a missing one behaved identically. | Nothing for device detection. `proxy.ai_providers_file` is the neighboring override that does work, and it applies to the AI provider catalog. |
| `proxy.key_management.governance.key_introspection: true` | No build installs a caller-facing introspection route, so the holder of a minted key had nothing to call and got the same 404 with the flag as without it. `false` is the default and is what the build does, so it stays accepted. | `GET /admin/keys/{id}` and `GET /admin/keys/{id}/usage` on the admin API, which read a key's policy and usage under an operator credential rather than the caller's own key. |
| `proxy.key_management.store.redis_source_of_truth: true` | The key plane picks its system of record from `store.backend` and from nothing else, so the flag offered a choice that does not exist: it could neither promote Redis under another backend nor demote it under its own. `false` stays accepted. | `proxy.key_management.store.backend`. Set `redis` with a `store.url` for a Redis-backed key store, or keep the default `embedded`, which is the local redb file. |
| `proxy.secrets.backend`, `proxy.secrets.fallback` | The resolver walks the named entries under `proxy.secrets.backends` and nothing else. The single-backend selector selected no backend, and the fallback selector was never reached, because an unresolved provider URI fails loudly instead of falling through to a second backend. | Declare each backend as a named entry under `proxy.secrets.backends` and reference it by name: `secret://<name>/<key>` for a local backend, `vault://<name>/<path>` for HashiCorp. The reference you write is what picks the backend. |
| `proxy.secrets.hashicorp.addr`, `.mount`, `.token` | The legacy inline HashiCorp block was parsed and never turned into a backend, so an address, a mount, and a token sat in the config while the resolver had no Vault registered to reach. | A `type: hashicorp` entry under `proxy.secrets.backends`. It takes the same `addr` and `mount` and reads its credential from the entry's `auth:` block, and references to it are `vault://<name>/<path>`. |

`origins.*.connection_pool.idle_timeout_secs` is not refused. It is the
legacy spelling of `timeouts.idle_ms` and feeds the resolved upstream
idle deadline.

`proxy.secrets.map` is not refused either, and it is no longer
config-only: the key registry pins it `stable`. Two things read it. A
non-empty map installs the process secret resolver on its own, with no
`backends` entry present. Its keys are also what `sbproxy plan` checks a
legacy `secret:<name>` reference against, so a config that declares the
block and leaves a referenced name out of it is a `missing-vault-key`
error and exits 3. What the map no longer does is resolve anything at
request time, because the `secret:<name>` reference form it served was
removed, and boot warns about that when the map is set. Write
`secret://<backend>/<name>` for live references.

#### Top-level values refused at config compile

The same rule reaches a key the schema does describe when it is one
accepted *value* of that key that does nothing. No reader-based check can
see that case, because the key is read.

| Key | Why it is refused | What to use instead |
|---|---|---|
| `audit.sink: tracing` | It never selected anything. Emission to the `config_audit`, `security_audit`, and `key_audit` targets has always been unconditional, so `tracing` and `memory` described the same proxy. | `memory` for the same behavior under an honest name, or `chain` with a `path` and a `sign_with` for a hash-chained, signed trail that survives a restart. |
| `audit.path`, `audit.sign_with` under any sink but `chain` | Nothing would write to the file or sign anything. A path nothing writes to is the more dangerous of the two shapes, because it looks configured. | Set `sink: chain`, or remove the key. |
| `attestation.role: claim` and `attestation.role: both`, proxy-wide or on an origin | Both promise the claim half of attestation and this build does not implement it. No claim is written before a call is served, nothing ever reads `proxy.attestation.queue`, and no ceiling is computed for `proxy.attestation.enforcement_mode` to act on, so a config declaring either role compiled clean and served traffic producing neither a claim nor a receipt. That is worse than not offering the role: the operator believes their spend is bounded. Both spellings stay in the vocabulary so the refusal can name the missing half instead of reporting an unknown value. | `receipt`, which is the half that works: a receipt is written after the call is served and carries the settled cost. Leave `off` if you want neither. |

#### Rego base data that collides with a rule (upgrade-affecting)

`policies[].data` and `ai_routing_policy.data` are unchanged as keys and stay
`stable`. What narrowed is the set of documents they accept, and a config that
compiled before this change can refuse after it.

Rego resolves a base-data value over a rule's computed value at the same path,
per rule rather than per query. The load-time check used to compare the data
document against the queried rule's path only, so a document that landed on a
helper rule several references away from the query compiled clean and then made
that helper a constant: the query still evaluated, the decision still looked
computed, and a `deny` rule that stopped running failed open with nothing in
the logs to say so. The check now compares against every rule head the module
defines. Four shapes refuse where three of them did not before:

| Base data | Rule the module defines | Previously |
|---|---|---|
| `data.<pkg>.<helper>` | a rule at that path that is not the query's | compiled, helper silently dead |
| `data.<pkg>.<rule>` set to JSON `null` | a rule at that path | compiled, rule silently dead |
| `data.<pkg>` set to a scalar | a rule beneath that path | refused at load with an opaque `previous value is not an object` from the interpreter, or compiled with the rule dead if the query never reached it |
| `data.<pkg>.<table>` holding any key | a partial rule computing its own keys at that path (`table[k] := ...`) | compiled and behaved correctly whenever the base keys and the computed keys were disjoint |

The fourth row is the one where a config that was working refuses, and it is
the only one. Rego indexes a partial rule by the key it computes, so a base
table of `{"POST": "no"}` beside a rule that only ever produces `GET` merged
and both entries were readable. Load time sees the fixed part of the path and
no further, so it cannot separate that document from `{"GET": "no"}` beside the
same rule, which kills the rule's only output and says nothing. The check keeps
the wide side, because that second document is the silent failure this whole
change exists to catch, and it fails open. An empty object at the same path
still loads, since no key there can beat a computed one.

The refusal names the data path, the rule it landed on, and the reference chain
from the query to that rule:

```
policy `rego`: base data defines `data.sbproxy.trusted`, and the module defines a rule at
that path, so Rego resolves the base document there and the rule never evaluates. The query
`data.sbproxy.allow` reaches it: data.sbproxy.allow -> data.sbproxy.trusted. Move the base
data under a key no rule in the module produces.
```

The fix is to move the table off the rule's path. A sibling key inside the
package (`data.sbproxy.roles` next to an `allow` rule) still loads, and a
top-level key (`data.allowed_methods`) always did. See
[`scripting.md`](scripting.md#base-data-the-table-the-rule-reads).

### Current config-only compatibility fields

| Field or subtree | What happens today |
|---|---|
| `agent_classes.hosted_feed.url`, `.bootstrap_keys` | The resolver uses builtin or inline catalogs; it does not fetch or verify a hosted feed. No fetcher is installed, and no signature check is installed for one either, so the bootstrap keys verify nothing. |
| `origins.*.agent_skills[].max_clock_skew_secs` | Reserved for signed artifact freshness headers that are not emitted yet. |
| `origins.*.credentials[].attrs.budget.reset` | Credential lowering copies `max_tokens` and `max_cost_usd` and nothing else, so the cap is cumulative and never resets. For a resetting cap today, use the AI action's `budget.limits[]`, which does take a `period`. The same leaf is config-only at proxy and tenant credential scopes. |
| `proxy.observability.log.sampling.info`, `.debug`, `.trace` | The process logger has no sampling call site, so no rate is applied at any level and every line is emitted. Throttle request logs with `access_log.sample_rate` instead. The sibling `log.level` and `log.format` are live; see [observability.md](observability.md) for where they sit against the CLI flags and `RUST_LOG`. |

`origins.*.action.resilience.circuit_breaker` and
`.outlier_detection` used to be listed here and are not config-only any
more. The AI router installs both when the config asks for them, so they
are live and are pinned `stable` in the key registry.

`proxy.secrets.rotation.grace_period_secs` and `.re_resolve_interval_secs`
used to be listed here too. WOR-2327 wired both into
`KeyPlane::resolve_credential_secret`, which now reads them for real: the
interval gates how long a resolved credential is cached before the backend
is consulted again, and the grace period covers a re-resolution failure
with the last-known-good value. Both are `stable` in the key registry; see
[configuration.md](configuration.md#secret-rotation) for the current
behavior.

---

## Upgrade-affecting behavior changes

A field whose meaning did not change can still change what your proxy does,
when a code path that was supposed to read it starts reading it. Nothing here
is a schema change: the same file compiles before and after. What changes is
which traffic the value you already wrote now refuses.

### `egress.usage_sinks` now gates the `events:` webhook sink

**Who this reaches.** Any config that has both `egress.usage_sinks` set to
`mode: deny_by_default` and an `events:` block with `sink: webhook`. A config
with no `egress:` section, or one whose `usage_sinks` is absent or left at the
default `allow_by_default`, is unaffected: that sink stays `ungated` and
delivers exactly as before.

**What changes.** `usage_sinks` has always compiled its allowlist under two
purposes, `usage_sink` and `webhook`, and the events sink has always
authorized under `webhook`. The `webhook` half was never installed into the
process registry, so the events sink read an empty slot and dialed with no
allowlist whatever the block said. It is installed now, so the block applies:
your collector's host has to be on `egress.usage_sinks.hosts`, on a scheme and
port that list permits (`ports` defaults to `[80, 443]`, so a collector on
`:8088` needs an explicit `ports:`), and resolving onto a private address needs
`allow_private: true`.

**What an operator sees when it bites.** The SIEM feed stops and every surface
says why: a `warn` on the `events` target carrying the closed reason
(`unlisted_host`, `disallowed_port`, `private_address`, and the rest of
[the egress vocabulary](admin-api-reference.md#get-apiegress)), one
`sbproxy_events_dropped_total{sink="webhook",reason="egress_denied"}` per event
in each dropped batch, one
`sbproxy_egress_refused_total{purpose="webhook",reason=...}`, and a `denied`
row for the collector in `GET /api/egress`. Nothing is dropped silently, and
no surface carries the URL.

**What to do before upgrading.** Read `GET /api/egress` on the running proxy,
find the `webhook` row for your collector, and add that host (and its port, if
it is not 80 or 443) to `egress.usage_sinks.hosts`.

### The usage ledger now `fsync`s every entry

**Who this reaches.** Any config with a metering role, which is what makes
the proxy open `proxy.attestation.ledger.path`. A deployment with no metering role
never writes the file and is unaffected.

**What changes.** Each ledger append now forces its entry to stable storage
before returning, where before it called `Write::flush`, which `std::fs::File`
documents as a no-op. Nothing about the file format, the hash chain, or the
signatures changes; a file written by the previous release replays and
verifies exactly as it did. What changes is throughput: the ledger's append
rate is now bounded by how fast the filesystem under `proxy.attestation.ledger.path`
can `fsync`, and appends are serialized behind one mutex, so a ledger on a
network filesystem or a spinning disk is a new ceiling on metered request
rate.

**What an operator sees when it bites.** `sbproxy_meter_append_duration_seconds`
moves, because it measures the whole critical section including the sync.
Metering never fails a request, so the symptom is queueing on the metering
path rather than errors.

**What to do before upgrading.** Put `proxy.attestation.ledger.path` on local
storage. If the histogram's tail is unacceptable there, the honest answer is
that this deployment wants an unsigned usage sink rather than a receipt chain,
because a chain whose entries are not durable cannot answer the dispute it
exists for: a truncated hash chain verifies clean, so the lost entries leave
no marker anywhere.

### `agent_classes.resolver.rdns_enabled` now runs under fixed lookup bounds

**Who this reaches.** Any config that leaves `agent_classes.resolver.rdns_enabled`
at its default `true` and whose crawlers publish more than four PTR names for a
single address. A config that sets it to `false`, or whose crawler zones publish
one PTR per address as vendors do, resolves exactly as before.

**What changes.** Resolver step 2 queries a zone the client being identified
controls, and it previously followed that zone wherever it led: every PTR name
it returned got its own forward lookup, serially, with the host resolver's
default timeout and no ceiling on the total. Five bounds now apply. At most four
PTR names per address are forward-confirmed; each query is capped at two
seconds; the forward-confirm loop stops issuing new lookups once two seconds of
it have elapsed; at most 32 queries are in flight process-wide; and a DNS
failure is cached for 30 seconds instead of being re-queried on the next
request. Nothing about the config schema changes.

**What an operator sees when it bites.** A crawler that used to resolve with an
`rdns` agent-id source resolves from its `User-Agent` instead, which is the same
degradation path an unreachable resolver has always taken. The agent is still
classified; only the source stamp and the confidence change. A policy that keys
on the rDNS source specifically stops matching for that vendor. The
in-flight cap can produce the same demotion transiently, under a burst of
traffic from addresses the verdict cache has never seen; the next request from
that address, 30 seconds later, verifies normally.

**What to do before upgrading.** If a crawler you verify by rDNS publishes more
than four PTR names per address, verify it by Web Bot Auth `keyid` instead
(resolver step 1, and higher confidence than rDNS), or accept the UA-based
classification. There is no knob to raise the cap: it is a bound on what a
remote party can spend of your request path.

### `egress.token_exchange` now gates the MCP run-as-user token exchange

**Who this reaches.** Any config with `egress.token_exchange` set to
`mode: deny_by_default` and an MCP server whose `upstream_auth` uses the
token-exchange mode with `run_as_user_auth`.

**What changes.** That exchange passed no authorizer at all, so it ran ungated
regardless of this sub-block. It now reads the same slot the non-MCP
outbound-credential resolver does, and a per-server `egress:` block does not
substitute for it: a per-server block gates that server's upstream connects and
OpenAPI tool calls, never its token endpoint.

**What an operator sees when it bites.** The tool call fails with
`token exchange egress denied`, plus
`sbproxy_egress_refused_total{purpose="token_exchange",reason=...}` and a
`denied` row in `GET /api/egress` naming the token endpoint's host.

**What to do before upgrading.** Add every MCP token endpoint host to
`egress.token_exchange.hosts` alongside the non-MCP ones already there.

### `mcp.rbac_policies[].tool_quotas[].rate.per` is now validated at load

**Who this reaches.** Any config with an `mcp` action whose `rbac_policies`
declare a `tool_quotas[]` rule with a `per:` value the duration parser cannot
read. The accepted suffixes are `ms`, `s`, `m`, `h`, and `d`; `per: 1hour`,
`per: 60`, and `per: 1 hour` are all outside them. A config whose windows all
use a documented suffix is unaffected.

**What changes.** Nothing validated the string. The value was read for the
first time on the request path, where a parse failure was treated as "this
tool has no quota" and every `tools/call` passed, with no log line and no
counter, so the operator's dashboard showed the quota configured and zero
rejections. The action now refuses the config with an error naming the policy
label, the tool, and the string it could not read. The request-path branch
survives as a backstop and now denies the call instead of allowing it.

**What an operator sees when it bites.** Startup or reload fails with
`mcp action: rbac_policies['<label>']: tool_quotas rule for tool '<tool>' has
an unparseable rate.per '<value>'`, listing the accepted suffixes. A reload
leaves the previous generation serving.

**What to do before upgrading.** Grep your configs for `per:` under
`tool_quotas` and confirm every value ends in one of the five suffixes. A
quota that has never rejected anything is the one to check first: under the
old behavior an unreadable window and an unreached limit looked identical.

### `proxy.scripting.lua.sandbox.allow_patterns: false` now also gates `string.gsub`

**Who this reaches.** Any config that sets `allow_patterns: false` and whose
Lua scripts call `string.gsub`. A config leaving `allow_patterns` at its
`true` default is unaffected, and so is one whose scripts never call `gsub`.

**What changes.** The gate stubbed `string.find`, `string.match`, and
`string.gmatch` and left `string.gsub` reachable, so the knob whose stated
purpose is containing the pattern engine left the same C-level matcher open.
`gsub` is stubbed now, alongside the other three, which is the whole set of
`string` functions that take a pattern.

**What an operator sees when it bites.** The script fails with
`Lua pattern API disabled by sandbox
(proxy.scripting.lua.sandbox.allow_patterns)`, the same error the other three
already raised, and the request fails closed the way any Lua error on that
surface does.

**What to do before upgrading.** Grep your Lua for `gsub`. Rewrite the call
with `string.sub` and plain-text search, or set `allow_patterns: true` and
accept that the pattern engine is on. Note what the flag buys either way:
`max_execution_ms` cannot preempt a backtracking pattern, because the matcher
runs inside the C string library where the interrupt the timer relies on never
fires. Refusing the call is the only containment there is.

### Circuit breakers now admit one probe at a time in half-open

**Who this reaches.** Any config with a `circuit_breaker:` block on a
`load_balancer` action, an AI router with circuit breaking enabled, or the AI
crawl-control HTTP ledger client. A config with no breaker configured is
unaffected.

**What changes.** Half-open admitted every request that arrived. At high
concurrency that meant the full request rate was pointed back at the upstream
the instant `open_duration_secs` lapsed, before any of those requests had
returned a verdict, once per open duration for as long as the upstream stayed
down. Half-open now hands out one probe slot at a time: the request that takes
it goes through, everything else is refused as if the breaker were still open,
and the slot returns when that probe reports success or failure. A probe whose
caller never reports an outcome is written off after one more open duration, so
the breaker cannot get stuck refusing.

**What an operator sees when it bites.** Fewer requests reach a recovering
upstream, and recovery takes `success_threshold` sequential probes rather than
one concurrent burst. On a load balancer the breaker is one narrowing stage
among several and stays advisory: when it filters out every target in the pool,
the request is still routed rather than failed, so a single-target pool behaves
as before.

**What to do before upgrading.** Nothing, unless you were relying on a
recovering upstream absorbing a burst. If your upstream needs more than one
concurrent probe to warm up, raise `success_threshold` rather than expecting
concurrency.

### Outlier ejection restarts the endpoint's measurement window

**Who this reaches.** Any config with an `outlier_detection:` block whose
`window_secs` is longer than its `ejection_duration_secs`, which is the
default shape (60 s window, 30 s ejection).

**What changes.** The failures that caused an ejection kept counting against
the endpoint after it was re-admitted, until `window_secs` expired from the
original window start. A re-admitted endpoint was therefore graded on
pre-ejection traffic and was usually re-ejected on its first later error, so a
configured 30 s ejection behaved as a `window_secs`-long one. Ejection now
zeroes the endpoint's counters and starts a fresh window, so the post-ejection
probe is graded only on post-ejection traffic.

**What an operator sees when it bites.** Endpoints come back into the pool at
the cooldown you configured instead of at the end of the window, and a healthy
endpoint that takes one unrelated 5xx after re-admission stays in the pool.
Endpoints that are genuinely still broken are re-ejected after `min_requests`
fresh requests rather than immediately.

**What to do before upgrading.** If you were leaning on the old behavior to
keep a bad endpoint out for the length of the window, set
`ejection_duration_secs` to the duration you actually want.

### There is no PROXY protocol configuration key

**Who this reaches.** Anyone deploying behind an AWS NLB, HAProxy, or another
load balancer configured to send a PROXY protocol preamble.

**What changes.** Nothing in the product. What changes is the claim:
`comparison.md` listed PROXY protocol v1 as supported. It is not. A v1 parser
exists in the source tree, no listener calls it, and no configuration key
enables it. The comparison table now says so.

**What an operator sees when it bites.** Every connection fails. The
`PROXY TCP4 ...\r\n` line is handed to the HTTP parser as the request line and
returns 400, and the client address that reaches the access log, the WAF, and
the IP-filter policy is the load balancer's rather than the client's.

**What to do before upgrading.** Turn PROXY protocol off on the load balancer
in front of SBproxy and pass the client address in a header
(`X-Forwarded-For`) instead.

### Redis-backed idempotency entries move to a new keyspace

**Who this reaches.** Any origin with `idempotency.backend: redis`. The
`memory` backend keeps its entries in process and is unaffected.

**What changes.** The storage key was `sbproxy:idem::<Idempotency-Key>`
for every origin in the cluster, because the workspace segment it was
scoped by is a field nothing ever fills. It now carries the owning
origin's `tenant_id` and origin id in length-delimited segments. That
closes the cross-origin read, and it also means entries written by the
old build are not readable by the new one. They are not deleted either:
they sit in the store until their TTL (24 h by default) expires them.

**What an operator sees when it bites.** For the first request under any
given `Idempotency-Key` after the upgrade, the proxy reports a miss and
contacts the upstream, even if the pre-upgrade build had already cached a
response for that key. A client retrying across the restart therefore
gets its request executed a second time. On a rolling upgrade the two
builds do not share entries at all, so the window lasts until the last
old node is drained.

**What to do before upgrading.** Treat it as a cache flush on a path
where a repeat is a real repeat. Drain in-flight idempotent retries
before the restart on anything that settles money, or accept one
re-execution per key. Nothing in the config changes.

### `compression.algorithms` now selects in the order you wrote

**Who this reaches.** Any origin with a `compression.algorithms` list of
more than one codec, where a client accepts more than one of them. An
origin with an empty list, or one codec, or one whose clients accept only
one, sees no change.

**What changes.** The list was documented as a priority order on three
surfaces and read as a membership set by the negotiator, which then
walked its own hardcoded `zstd` > `br` > `gzip` ladder. It is a priority
order now: the list is walked as authored and the first entry the client
accepts is the one served. `algorithms: [gzip, br]` sent Brotli to a
browser that accepts both and sends gzip after the upgrade.

**What an operator sees when it bites.** The `Content-Encoding` on
responses changes to the codec listed first, and
`sbproxy_compression_decisions_total` moves between codecs. Nothing
fails.

**What to do before upgrading.** Read your `algorithms` lists as the
preference they now are. If a list was written to mean "these three are
allowed, pick the best", reorder it to `[zstd, br, gzip]` or empty it,
which selects the same way it always did.

Two smaller refusals ride along, both load-time. An entry naming no codec
(`algorithms: [deflate]`) fails config compile instead of silently
disabling compression for the origin, and a client `Accept-Encoding`
qvalue of zero is honored as the refusal RFC 9110 §12.5.3 says it is, so
a client sending `identity;q=1, *;q=0` gets an uncompressed response
where it used to get zstd it could not decode.

### `cors.allowed_origins: ["*"]` with `allow_credentials: true` fails config load

**Who this reaches.** Any origin whose `cors:` block sets both. Nothing
else.

**What changes.** Browsers reject that pair per the Fetch standard, and
the CORS middleware has always refused to emit any header for it. The
refusal was a runtime no-op plus one `warn` line per request, so
`sbproxy validate` exited 0 on a config that served a broken browser app
forever. It fails config compile now, and the runtime guard that remains
logs once per process and counts every occurrence on
`sbproxy_cors_refusals_total{reason="wildcard_with_credentials"}`, which the
"CORS Refusals by Reason" panel on the `sbproxy-security` dashboard reads.

**What an operator sees when it bites.** The proxy refuses to start (or
refuses the reload) naming the origin and both keys.

**What to do before upgrading.** Run `sbproxy validate` against your
config. If it names this pair, list the origins you actually mean in
`allowed_origins`, or drop `allow_credentials`.

### A plain `OPTIONS` request now reaches the upstream

**Who this reaches.** Any origin with a `cors:` block whose upstream
implements `OPTIONS` itself: a discovery endpoint answering with
`Allow:`, a capability document, anything WebDAV.

**What changes.** The proxy treated every `OPTIONS` carrying an `Origin`
header as a CORS preflight, answered 204 from the edge, and never
contacted the upstream. `Origin` rides on every cross-origin request of
every method, so adding a `cors:` block silently deleted that endpoint. A
preflight is now what the Fetch standard defines it as: an `OPTIONS`
request carrying `Access-Control-Request-Method`. Everything else is a
normal request and is proxied.

**What an operator sees when it bites.** `OPTIONS` requests that used to
return an empty 204 now return whatever the upstream returns. A browser
preflight is unaffected, because a browser always sends
`Access-Control-Request-Method`.

**What to do before upgrading.** Nothing, unless something depended on
the proxy answering a non-preflight `OPTIONS` without the upstream.

### RFC 9421 signature verification refuses a stale `created`

**Who this reaches.** Any origin with `authentication: {type: bot_auth}`
or a `message_signatures:` verifier. `hmac_auth` already enforced this
by hand and is unchanged in behavior.

**What changes.** The freshness check refused a `created` in the future
and an `expires` in the past, and had no lower bound on `created` at all.
A captured `Signature-Input` / `Signature` pair with no `expires` and no
`nonce` therefore verified forever: an unexpiring bearer token for
whatever identity it carried. The window is symmetric now, which is what
`clock_skew_seconds` has always been documented as: `created` may be at
most `clock_skew_seconds` old and at most `clock_skew_seconds` in the
future. `expires` can only shorten that window, never extend it.

**What an operator sees when it bites.** A signer whose clock is behind,
or whose signatures are minted well before they are sent, gets a 401
whose reason names the stale timestamp.

**What to do before upgrading.** If your signers legitimately mint a
signature more than 30 seconds before sending it, raise
`clock_skew_seconds` on that origin to cover the real gap.

### `@target-uri` is the absolute URI RFC 9421 defines

**Who this reaches.** Any signer or verifier whose covered component set
includes `@target-uri` or `@request-target`. The shipped Web Bot Auth
wiring covers `@authority`, `@method`, and `@path`, so a config that took
those defaults is unaffected.

**What changes.** `@target-uri` emitted the origin-form request target
(`/v1/orders`) where RFC 9421 §2.2.2 defines it as the full absolute URI
(`https://api.example.com/v1/orders`), so no conformant peer could
interoperate in either direction. `@request-target` emitted
`GET /v1/orders`, which is draft-cavage's shape, where RFC 9421 §2.2.5 is
the request target alone. Both are correct now. For a deprecation
window, inbound verification retries the old derivation when the
conformant base fails and the covered set names one of the two, so a
signer built against the old shape keeps verifying and the proxy logs the
deprecation once per process.

**What an operator sees when it bites.** Nothing immediately: both bases
verify. Every acceptance of the old derivation counts on
`sbproxy_signature_legacy_derivation_total{component}` and logs one
`warn` per process naming the verifier's key id. The old one stops being
accepted in a future release.

**What to do before upgrading.** Move signers onto a conformant RFC 9421
library, and watch
`sbproxy_signature_legacy_derivation_total` go to zero before the release
that removes the fallback. The "Legacy Signature Derivations (24h)" panel on
the `sbproxy-security` dashboard is the number to hold at zero across a full
traffic cycle, weekly and monthly batch callers included. Outbound signatures the proxy produces are
already on the new derivation.

### `acme.storage_backend` on a shared store now refuses to start when it cannot be opened

**Who this reaches.** Any config with `proxy.acme.enabled: true` and
`storage_backend` set to `file`, `redis`, `s3`, `gcs`, or `azure`, where the
value in `storage_path` does not actually open: a DSN the Redis parser
rejects, a bucket URL the object store cannot parse, a shared directory that
is not mounted in this container. A config whose backend opens is unaffected,
and so is every pod-local backend (`redb`, `sqlite`, `memory`).

**What changes.** Each of those open failures used to log one `warn` reading
"certs will NOT persist (in-memory fallback)" and hand back an in-memory
store. Persistence was the smaller half of what that cost. The in-memory
store implements neither of `KVStore`'s lock methods, so it inherits the
single-node defaults, which acquire unconditionally. Every replica therefore
won its own issuance lease and its own fencing generation, opened its own
ACME order for the same hostname, and published its HTTP-01 token where no
peer could read it. The proxy now refuses to start instead, with an error
naming the backend.

**What an operator sees when it bites.** The process exits at startup rather
than serving, and the error reads `acme.storage_backend '<backend>' is a
shared certificate store and could not be opened`. No part of `storage_path`
is in the message: a Redis DSN carries a password and an object-store URL can
carry a query credential, so the message names the backend and the failure,
never the value. Under Kubernetes this is a pod that does not become ready,
which is visible immediately, rather than a fleet that looks healthy until
the CA rate-limits the domain days later.

**What to do before upgrading.** Grep the running proxies' startup logs for
`certs will NOT persist (in-memory fallback)`. That warn line is the old
build's only report of this condition, and a proxy that emitted it on a shared
backend is a proxy that will not start on the new build. Fix the backend, or
move to a pod-local `storage_backend` and a single replica. The new
`sbproxy_cert_store_degraded{backend}` gauge covers the pod-local half from
here on; the shared half no longer has a degraded state to report.

### Durable sink files are created `0o600` and existing ones are tightened

**Who this reaches.** Any config that names a path for a durable sink, and any
process outside the proxy that reads one of those files. The paths are
`meter.ledger.path` (and the audit chains built on it), `payments.state_path`,
`session_ledger.path`, `request_events.path`, and the AI gateway's
`usage.sink: jsonl_file` path. A deployment where only the proxy user ever
opens these files is unaffected in practice, though the mode on disk still
changes.

**What changes.** Every one of those files used to be opened with a plain
create-and-append, which asks the kernel for `0o666` and lets the process umask
subtract from it. On a host with the near-universal `0o022` they were all
`0o644`. They now carry `0o600`, requested in the open itself so the file never
exists at a wider mode, and reasserted afterwards so a file left behind by an
older build at `0o644` is tightened on the first open rather than inherited.
Directories the proxy creates for its own state, today only the parent of
`payments.state_path`, are created `0o700`.

Two things are deliberately left alone. A directory that already exists keeps
the mode it has, because a sink path may sit under a `/var/log` the operator
shares on purpose, and narrowing that would be a much larger change than
hardening one file. A path that resolves to something other than a regular file
(`/dev/stdout`, a fifo drained by a shipper, a device) is written to exactly as
before with no mode applied, since its permissions are the operator's and not
the proxy's.

**What an operator sees when it bites.** Nothing inside the proxy: it reads and
writes its own files as before. What breaks is outside it. A log shipper, a
backup job, or a metrics scraper running as a different user starts getting
`EACCES` on the first open after the upgrade, and keeps getting it, because the
tightening is applied every time the sink opens the file. If the proxy itself
cannot tighten a file, because another account owns it, the sink refuses to
start rather than appending to a file other accounts can read: the session
ledger and request event sinks warn and fall back to the logging sink, and the
usage ledger and settlement store fail startup with the path in the message.

**What to do before upgrading.** List every process that reads a sink file and
decide, per reader, which of these applies: run it as the proxy's user; give it
access explicitly at deployment time rather than through world-readable modes;
or point the sink at a fifo or `/dev/stdout` it already drains, which this
change does not touch. On Windows there are no POSIX permission bits, so files
and directories keep inheriting the containing directory's ACL and nothing
about this changes.

### Bedrock's catalog data posture is now `retains_data: true`

**Who this reaches.** Any action carrying
`data_posture: {allow_data_collection: false}` that can route to a
`bedrock`-typed provider entry with no operator posture override on it. A
config that leaves `allow_data_collection` at its default `true`, or that
sets `data_posture.retains_data: false` on the provider entry, is unaffected.
`require_zdr: true` is also unaffected: Bedrock still declares
`zdr_available: true`, because eligible customers can arrange full zero data
retention through their AWS account team.

**What changes.** Nothing in the request path changed. The catalog's claim
about the vendor did. AWS's platform default is still zero retention, but its
abuse-detection page carves out named models: classifier-flagged traffic to
the OpenAI GPT-5.x family on Bedrock is retained up to thirty days with no
opt-in. The model name passes straight through from the caller, so a stock
account reaches a retention window without ever asking for one. A catalog
entry that says `retains_data: false` promises the whole surface is
non-retaining, and for that account it is not, so the entry now says `true`
and the control closes rather than reading as a guarantee it cannot make.

**What an operator sees when it bites.** Bedrock drops out of the eligible
set for that action. If it was the only eligible provider, the call is
refused rather than routed to a retaining endpoint, which is the direction
this control is supposed to fail in.

**What to do before upgrading.** Check
[`GET /admin/ai-data-posture`](admin-api-reference.md#get-adminai-data-posture)
for your Bedrock entry's `effective.retains_data`, and its `excluded_providers`
for whether the entry has already dropped out. If your account has a ZDR
arrangement with AWS, or you route Bedrock only to models outside the
carve-out, declare it on the entry with `data_posture: {retains_data: false}`
and the previous behavior returns. That declaration is the operator saying
something about their own account that the catalog cannot know.

### A transcoded gRPC error now sets the HTTP status, not just the body

**Who this reaches.** Any origin with `action: {type: grpc, transcode: {...}}`
whose upstream returns a non-OK `grpc-status` in the *response headers*, which
is what tonic and grpc-go send for a unary handler that returns an error. An
origin with no `transcode` block is unaffected, and so is `grpc_web: true`:
gRPC-Web requires HTTP 200 with the outcome in the trailer frame, and that
path is untouched.

**What changes.** The transcoder already mapped the gRPC code to an HTTP
status for the JSON error envelope it puts in the body, and then threw the
mapped value away, so the response kept the upstream's 200. It is applied to
the status line now, using the same `google.rpc.Code` table `grpc-gateway`
uses: `NOT_FOUND` becomes 404, `PERMISSION_DENIED` 403, `FAILED_PRECONDITION`
and `INVALID_ARGUMENT` 400, `UNAVAILABLE` 503, `UNIMPLEMENTED` 501,
`RESOURCE_EXHAUSTED` 429, `CANCELLED` 499. A `status` response modifier on the
same origin still wins; it is applied later in the same filter.

**What an operator sees when it bites.** Calls that used to be logged and
metered as 2xx move into the 4xx and 5xx classes, so error-rate alerts,
the `status` label on `sbproxy_requests_total` and
`sbproxy_origin_requests_total`, and any downstream client that retries on 5xx
all see the change at once. Response caching for those
origins also changes, since a 4xx or 5xx is not stored the way a 200 was.
Three more surfaces read the status line at the same point and therefore
also move: the RFC 9209 `Proxy-Status` header, which is stamped on non-2xx
responses only, so a `proxy_status.enabled` origin starts emitting it on
failed RPCs; response `assert` policies; and `on_response` callbacks.
Nothing about the JSON body changed.

One surface deliberately does not move, and it is a change in its own
right. `fallback_origin.on_status` is no longer consulted at all on an
origin with `transcode` or `grpc_web: true`. Both translated modes own
the response body outright, so a fallback that fired there could commit
the fallback's status and `content-length` while the body downstream
stayed the translated one, and a body that does not match its declared
length desynchronizes a keep-alive connection. `on_error` is unaffected:
it fires before any upstream response exists, so there is no translated
body to conflict with. If you need a status fallback on a gRPC upstream,
put it on a plain-passthrough origin in front of it.

**What to do before upgrading.** Re-baseline error-rate alerts on the affected
origins, and check any client that treated a transcoded call as always-2xx and
read the outcome out of the body. The one shape that did not change is a
failure reported in real HTTP/2 trailers after the response headers, typically
a server-streaming method that fails partway: the status line is already
committed downstream when the trailers arrive, so that response stays 200 with
the error in the body.

### The translated gRPC paths now ask the upstream for `identity` framing

**Who this reaches.** Any origin with `action: {type: grpc}` and either
`transcode` or `grpc_web: true`. Plain gRPC passthrough is unaffected.

**What changes.** Both translated paths read the length-prefixed message
frames, and neither can read a compressed one. They now send
`grpc-accept-encoding: identity` on the request to the upstream, replacing
anything the client sent, so a compliant server stops compressing. Two
consequences follow. A compressed response frame that arrives anyway is
refused by the transcoder with a JSON error naming compression, where before
its bytes were handed to the protobuf decoder as if they were a message. And
the gRPC-Web bridge no longer strips a non-`identity` `grpc-encoding` response
header, since the frames under it are forwarded byte for byte.

**What an operator sees when it bites.** An upstream configured to compress
responses stops doing so on these origins, which shows up as larger response
bodies between the proxy and that upstream. An upstream that compresses
unconditionally, ignoring the negotiation, surfaces as a JSON body of
`{"error": "gRPC response transcoding failed", "detail": "...compressed..."}`
instead of the previous protobuf decode error. That body arrives with the
upstream's own status, normally 200, because the frame's compression flag is
only readable once the status line has gone downstream.

**What to do before upgrading.** If you rely on gRPC message compression
between the proxy and a gRPC upstream, keep that origin on plain passthrough
rather than `transcode` or `grpc_web`.

---

## Selected field stability reference

The tables below cover representative and high-impact leaves. They do not
assign a tier to every property accepted by the configuration parser. Use the
tier definitions above only where a field is listed explicitly.

### Top-level fields

| Field | Type | Stability | Notes |
|---|---|---|---|
| `proxy` | object | **stable** | Server configuration block. |
| `origins` | object (map) | **stable** | Map of hostname to origin config. |

### `proxy` - ProxyServerConfig

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `http_bind_port` | integer | 8080 | **stable** | Plain HTTP listener port. |
| `https_bind_port` | integer | - | **stable** | TLS listener port. Optional. |
| `tls_cert_file` | string | - | **stable** | Path to PEM cert for manual TLS. |
| `tls_key_file` | string | - | **stable** | Path to PEM key for manual TLS. |
| `acme` | object | - | **beta** | Automatic TLS via ACME. |
| `http3` | object | - | **disabled** | Reserved HTTP/3 (QUIC) listener shape. `enabled: true` is rejected. |

### `proxy.acme` - AcmeConfig

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `enabled` | boolean | false | **beta** | Activates ACME. |
| `email` | string | "" | **beta** | Contact email for the ACME account. |
| `directory_url` | string | Let's Encrypt prod | **beta** | ACME directory endpoint URL. |
| `challenge_types` | array | `[http-01]` | **beta** | Challenge method preference list. `tls-alpn-01` is accepted in the list but not yet served. |
| `storage_backend` | string | `redb` | **beta** | Cert persistence backend. |
| `storage_path` | string | `/var/lib/sbproxy/certs` | **beta** | Filesystem path for cert storage. |
| `renew_before_days` | integer | 30 | **beta** | Days before expiry to renew. |

### `proxy.http3` - Http3Config

HTTP/3 is not served by this build. The block is retained for forward compatibility: omission or `enabled: false` compiles, while `enabled: true` fails config compilation and says so plainly.

The build-time key registry pins all three leaves `config_only` rather than `unsupported`, because the block itself stays legal and only the one value is refused. See the [`disabled`](#disabled) tier for why the two labels disagree on purpose.

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `enabled` | boolean | false | **disabled** | Must remain false until HTTP/3 is served. |
| `max_streams` | integer | 100 | **disabled** | Reserved max concurrent QUIC streams per connection. No QUIC listener starts, so nothing is capped. |
| `idle_timeout_secs` | integer | 30 | **disabled** | Reserved QUIC idle timeout in seconds. No QUIC listener starts, so nothing times out. |

The two tuning leaves have one live effect, and it is not on traffic:
`proxy.http3.**` carries a Restart blast radius, so editing either of
them turns an `sbproxy plan` reload into a restart.

### Origin Config (each entry under `origins:`)

| Field | Alias | Type | Default | Stability | Notes |
|---|---|---|---|---|---|
| `action` | - | object | required | **stable** | What the proxy does with requests. |
| `authentication` | `auth` | object | - | **stable** | Auth plugin config. |
| `policies` | - | array | `[]` | **stable** | Policy plugin list. |
| `transforms` | - | array | `[]` | **beta** | Body transform plugin list. |
| `request_modifiers` | - | array | `[]` | **stable** | Request modification steps. |
| `response_modifiers` | - | array | `[]` | **stable** | Response modification steps. |
| `cors` | - | object | - | **stable** | CORS policy. Presence of the block is what enables CORS. The legacy `enable: false` inside it fails config load, because it never turned CORS off. |
| `hsts` | - | object | - | **stable** | HSTS policy. |
| `compression` | - | object | - | **stable** | Response compression. |
| `session` | `session_config` | object | - | **beta** | Session cookie management. |
| `force_ssl` | - | boolean | false | **stable** | Redirect HTTP to HTTPS. |
| `allowed_methods` | - | array | `[]` (all) | **stable** | HTTP method allowlist. |
| `forward_rules` | - | array | `[]` | **beta** | Conditional routing rules. The inline origin's `hostname`, `version`, and `workspace_id` metadata fields fail config load. |
| `fallback_origin` | - | object | - | **beta** | Secondary origin on primary failure. |
| `response_cache` | - | object | - | **beta** | Response caching config. The `key_event` and `admit_event` decision events inside it are **alpha**, and an `engine` of `cel` or `wasm` on either fails config load. |
| `variables` | - | object | `{}` | **beta** | Named template variables. |
| `on_request` | - | array | `[]` | **alpha** | Request event hook plugins. |
| `on_response` | - | array | `[]` | **alpha** | Response event hook plugins. |
| `bot_detection` | - | object | - | **alpha** | Bot detection config. |
| `threat_protection` | - | object | - | **alpha** | Dynamic threat blocklist config. |
| `error_pages` | - | array | - | **beta** | Custom error page entries, each matching one status or a list of statuses. |
| `traffic_capture` | - | object | - | **refused** | No consumer; setting it fails config load. Use `mirror`. |
| `connection_pool` | - | object | - | **stable** | Only `idle_timeout_secs` is read, as the legacy spelling of `timeouts.idle_ms`. `max_connections` and `max_lifetime_secs` fail config load. |
| `message_signatures` | - | object | - | **alpha** | HTTP message signing config. |

### CORS Config (`cors:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `allowed_origins` | `allow_origins` | array | `[]` | **stable** |
| `allowed_methods` | `allow_methods` | array | `[]` | **stable** |
| `allowed_headers` | `allow_headers` | array | `[]` | **stable** |
| `expose_headers` | - | array | `[]` | **stable** |
| `max_age` | - | integer | - | **stable** |
| `allow_credentials` | - | boolean | false | **stable**, **refused** with `allowed_origins: ["*"]` |
| `enable` | `enabled` | boolean | - | **refused** at `false` |

CORS is on for an origin exactly when that origin has a `cors:` block.
Nothing reads `enable`, so `false` never turned anything off and now
fails config load; `true` still compiles, because it agrees with what the
block does. Both spellings deserialize into the same field and are
checked together. Delete the block to turn CORS off.

### HSTS Config (`hsts:`)

| Field | Type | Default | Stability |
|---|---|---|---|
| `max_age` | integer | 31536000 | **stable** |
| `include_subdomains` | boolean | false | **stable** |
| `preload` | boolean | false | **stable** |

### Compression Config (`compression:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `enabled` | `enable` | boolean | true | **stable** |
| `algorithms` | - | array | `[]` | **stable**, entries **refused** outside `zstd`/`br`/`gzip` |
| `min_size` | - | integer | 0 | **stable** |
| `level` | - | integer | - | **beta** |

`algorithms` is a priority order. The list is walked as authored and the
first entry the client's `Accept-Encoding` accepts is served; an empty
list takes the built-in `zstd` > `br` > `gzip` order.

`level` is applied to whichever encoder the client negotiates, clamped
into that algorithm's native range (gzip 0-9, brotli 0-11, zstd 1-22).
Unset keeps each library's default (gzip and zstd defaults, brotli
quality 4).

### Session Config (`session:`, alias `session_config:`)

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `cookie_name` | - | string | - | **beta** |
| `max_age` | `cookie_max_age` | integer | - | **beta** |
| `http_only` | - | boolean | false | **beta** |
| `secure` | - | boolean | false | **beta** |
| `same_site` | `cookie_same_site` | string | - | **beta** |
| `allow_non_ssl` | - | boolean | false | **beta** |

### Response Cache (`response_cache:`)

The block is **beta** in the origin table above. The two decision events
are newer than the rest of it and their document shapes have not been
through a release yet, so they are tiered separately.

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `epoch` | integer | `0` | **beta** | Operator-controlled cache generation. Bumping it rotates this origin's cached entries and nothing else. The proxy already rotates them on any config change that alters what the upstream returns, so this is for the case it cannot see: an upstream that changed its response shape with no config change here. |
| `key_event` | object | - | **alpha** | Request-side `cache.key` script: `source` plus `engine`. Returns the dimensions folded into the cache key. |
| `admit_event` | object | - | **alpha** | Response-side `cache.admit` script, same shape. Returns whether the response is stored and for how long. Refused alongside a non-zero `stale_while_revalidate`, which the background refresh cannot evaluate it against. |
| `key_event.engine`, `admit_event.engine` | string | required | **alpha** | `lua` or `js`. `cel` and `wasm` fail config load; see the refusal rows above. |
| `key_event.source`, `admit_event.source` | string | required | **alpha** | Inline script body. An empty one fails config load. |

**The key these fields feed changed shape in the next release.** `vary` and
`key_event` are unchanged as config leaves: same names, same types, same
defaults, and a document that compiled before still compiles. What changed
is the key they contribute to. It is now versioned (`v2:`), its fields are
percent-escaped, and it carries three the host stamps on its own: the
tenant, a digest of the caller's credentials, and the set of content
codings the caller accepts. Two consequences for an existing config:

- Every entry written by an earlier build is unreadable to this one and
  ages out on its TTL. Expect one cold cache per origin on upgrade, and on
  a shared Redis or file store expect the old entries to hold space until
  they expire.
- On an origin whose callers authenticate or carry cookies, a shared entry
  becomes one entry per caller. That is the fix, not a side effect: the
  shared entry was serving one caller's response to another. See
  [configuration.md](configuration.md#who-a-cached-entry-belongs-to) for
  what to do if the content really is public.

### Request Modifier (`request_modifiers[]`)

| Field | Type | Stability | Notes |
|---|---|---|---|
| `headers` | object | **stable** | Header set/add/remove. |
| `url` | object | **stable** | Path rewrite. |
| `query` | object | **stable** | Query param set/add/remove. |
| `method` | string | **stable** | Override HTTP method. |
| `body` | object | **stable** | Body replacement. |
| `lua_script` | string | **beta** | Dynamic modification via Lua. |

### Response Modifier (`response_modifiers[]`)

| Field | Type | Stability | Notes |
|---|---|---|---|
| `headers` | object | **stable** | Header set/add/remove. |
| `status` | object | **stable** | Status code override. |
| `body` | object | **stable** | Body replacement. |
| `lua_script` | string | **beta** | Dynamic modification via Lua. |

### Header Modifiers

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `set` | - | object | `{}` | **stable** |
| `add` | - | object | `{}` | **stable** |
| `remove` | `delete` | array | `[]` | **stable** |

### Path Replace (`url.path.replace`)

| Field | Type | Stability |
|---|---|---|
| `old` | string | **stable** |
| `new` | string | **stable** |

### Query Modifier

| Field | Alias | Type | Default | Stability |
|---|---|---|---|---|
| `set` | - | object | `{}` | **stable** |
| `add` | - | object | `{}` | **stable** |
| `remove` | `delete` | array | `[]` | **stable** |

### `providers[].aws_sigv4` - AWS SigV4 request signing

| Field | Type | Default | Stability | Notes |
|---|---|---|---|---|
| `region` | string | required | **beta** | Credential scope. Independent of `base_url`; never inferred from the endpoint host. |
| `service` | string | from `provider_type` | **beta** | Signing service name. Defaults to `bedrock` / `sagemaker`. |
| `refresh_margin_secs` | integer | 900 | **beta** | Refresh window before a short-lived credential expires. Minimum 600. |
| `credentials.source` | string | `default_chain` | **beta** | `default_chain`, `static`, or `assume_role`. |
| `credentials.access_key_id` | string | - | **beta** | Read by `static` only. |
| `credentials.secret_access_key` | string | - | **beta** | Read by `static` only. Secret-resolving. |
| `credentials.session_token` | string | - | **beta** | Read by `static` only. Secret-resolving. Not renewable by SBproxy. |
| `credentials.role_arn` | string | - | **beta** | Read by `assume_role` only. |
| `credentials.external_id` | string | - | **beta** | Read by `assume_role` only. Secret-resolving. |
| `credentials.session_name` | string | `sbproxy` | **beta** | Read by `assume_role` only. |
| `credentials.session_duration_secs` | integer | role default | **beta** | Read by `assume_role` only. |
| `credentials.profile` | string | - | **beta** | Read by `default_chain` and by the `assume_role` base identity. |

The whole block is **beta** for its first release. The shape that is least
likely to move is `region` plus a credential source, and the part most likely
to gain fields is `credentials`, where AWS keeps adding provider kinds. Every
field a source does not read is refused rather than ignored, so a rename would
surface as a config error rather than as a silently unsigned request.
`api_key` and `aws_sigv4` on one provider entry are refused together.

### Body Modifier (request)

| Field | Type | Stability |
|---|---|---|
| `replace` | string | **stable** |
| `replace_json` | any | **stable** |

### Response Body Modifier

| Field | Type | Stability |
|---|---|---|
| `replace` | string | **stable** |
| `replace_json` | any | **stable** |

### Status Override

| Field | Type | Stability |
|---|---|---|
| `code` | integer | **stable** |
| `text` | string | **beta** |

`text` is emitted as the reason phrase on the HTTP/1.x status line; absent
means the canonical phrase for `code`. HTTP/2 has no reason phrase on the
wire, so the value is ignored there.
