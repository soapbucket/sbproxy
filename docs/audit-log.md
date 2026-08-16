# Audit log
*Last modified: 2026-08-16*

SBproxy's audit surface is a set of narrow, structured channels rather than one audit framework. This page documents what actually ships: the admin-action audit rows served at `/api/audit/recent`, the `config_audit` / `security_audit` / `key_audit` tracing channels, the tamper-evident chains the `security_audit` and `config_audit` channels can each be written to, the `AdminAuditEmitter` plugin seam, and the emission metric. There is no `sbproxy_audit` crate and no envelope middleware.

One thing on this page is durable and provable, and the rest is not. `audit.sink: chain` writes every `security_audit` event to a hash-chained, Ed25519-signed file that `sbproxy audit verify` re-derives from genesis. Setting `audit.config_path` on top of that opts `config_audit` events into their own chained file, verified the same way with `--channel config`; see [Tamper-evident security audit trail](#tamper-evident-security-audit-trail). Everything else here is either an in-memory ring that dies with the process or a tracing stream whose durability is whatever your collector gives it. Read the sections below with that split in mind, because a log stream is a record of what the proxy said rather than a record of what happened: whoever can write the file can rewrite it.

## Admin-action audit rows

Admin actions that change runtime state record an `AuditRow` (defined with the
module-owned state machine in
`crates/sbproxy-modules/src/policy/rate_limit_budget/runtime.rs`):

| Field | Type | Notes |
|---|---|---|
| `timestamp` | RFC 3339 string | Wall-clock time of the action. |
| `action` | string | What happened, e.g. `rate_limit_suspend`. |
| `target_kind` | string | The kind of entity acted on, e.g. `workspace`. |
| `target_id` | string | The identifier of the targeted entity. |
| `reason` | string | Human-readable explanation of why the action fired. |

The workspace rate-limit budget's auto-suspend and resume transitions are the emitters today. Each row is mirrored to the structured `security_audit` tracing target for external sinks and retained in an in-memory ring of the most recent 256 rows.

Query the ring through the admin API:

```
GET /api/audit/recent?limit=50
```

The response is a JSON array of rows, newest first. `limit` defaults to 50.

### The `audit:` block

The top-level `audit:` block selects whether the audit trail has a durable
form. It has two accepted values:

```yaml
audit:
  sink: memory        # the default: no durable trail
```

`memory` is what a proxy with no `audit:` block does. The most recent 256
admin-action rows stay queryable via `/api/audit/recent`, the unified ring
behind `/api/audit/events` holds the most recent 1000 events across every
channel, and each channel keeps emitting on its tracing target. All of it
is lost when the process is.

`chain` adds the durable, tamper-evident half; see the next section.

`tracing` was removed. It never selected anything: emission to the
`config_audit`, `security_audit`, and `key_audit` targets has always been
unconditional, so `tracing` and `memory` described the same proxy. A
config that still names it is refused at load with a message pointing at
both replacements, rather than being accepted and quietly meaning
`memory`. A `path` or a `sign_with` under any sink other than `chain` is
refused for the same reason: a path nothing writes to is the more
dangerous of the two mistakes, because it looks configured.

## Tamper-evident security audit trail

`audit.sink: chain` appends every `security_audit` event to a SHA-256
hash-chained, Ed25519-signed file:

```yaml
proxy:
  web_bot_auth:
    key_id: sbproxy-audit-2026
    ed25519_seed_hex: ${SBPROXY_AUDIT_SEED}

audit:
  sink: chain
  path: /var/lib/sbproxy/security-audit.jsonl
  sign_with: proxy.web_bot_auth
```

Three keys, and each one is doing something.

`sink: chain` turns the chain on. Nothing else changes: the tracing
targets and the in-memory rings keep working exactly as they did, and the
chained record is byte-for-byte the record the `security_audit` target
already ships, so your SIEM's copy of an event and the chain's copy cannot
disagree.

`path` is the file. It is opened once at boot, appended to under a mutex,
and flushed per record, so a record that reached the file survives the
process that wrote it. Put it on durable storage; parent directories are
created at boot.

`sign_with` is the signing identity, and the only value this build
resolves is `proxy.web_bot_auth`. That is deliberate: it is the proxy's
one Ed25519 identity, the same one `proxy.attestation.sign_with` names for
metering receipts, so a deployment that already publishes that key does
not acquire a second key-distribution problem by turning this on. Source
the seed from the environment or a vault reference rather than committing
it.

### The config chain

`audit.config_path` opts `config_audit` events into a second chained file,
signed with the same identity:

```yaml
audit:
  sink: chain
  path: /var/lib/sbproxy/security-audit.jsonl
  sign_with: proxy.web_bot_auth
  config_path: /var/lib/sbproxy/config-audit.jsonl
```

It is off by default: with no `config_path`, `config_audit` stays a
tracing stream and nothing else changes, which is the same behavior this
proxy has always had. Setting it requires `sink: chain`; naming it under
`sink: memory` is refused at load. It must also name a different file
than `path`, because the security and config chains carry different
payload shapes and verify independently, and one file cannot hold both
without breaking the digest walk partway through.

Everything the security chain gives you above applies to this one too:
each `ConfigAuditEntry` is hash-chained and signed the same way, the file
is its own write-ahead log, and `sbproxy audit verify` re-derives it from
genesis. What is chained is the change, never the document. A
`ConfigAuditEntry` carries which origins moved, which revision it moved
between, and who asked for it, and not one config value, which is why
chaining the record of a reload is safe even though chaining what it
loaded would not be.

`key_audit` is deliberately not chainable yet. Its entries carry a
before/after diff of a credential record, and writing that into a file
designed to be impossible to quietly amend needs its own answer to what
the diff may contain before it goes anywhere permanent.

### What the chain proves

Each record is `SHA-256(prev_hash || seq || recorded_at || event)` and
carries an Ed25519 signature over that raw digest. Three consequences an
auditor can rely on:

- **Editing a record is detectable.** The record's own digest stops
  matching its bytes, and every record after it chains onto a head that no
  longer exists.
- **Deleting a record is detectable.** Sequence numbers are contiguous
  from zero, so a removed line leaves a gap that verification reports.
  This is the case a plain log file cannot cover at all.
- **Rewriting the whole file is detectable.** Somebody with write access
  can produce an internally consistent chain, but not one that verifies
  against the published key.

### Verifying it

`sbproxy audit verify` re-derives a chain from genesis and reports the
first record that does not check out. Exit 0 verifies, exit 1 does not, so
it drops straight into cron or a CI lane:

```bash
sbproxy audit verify /var/lib/sbproxy/security-audit.jsonl \
  --signing-seed-hex "$SBPROXY_AUDIT_SEED"
```

`--channel` picks which chain the file at `path` is: `security` (the
default, the trail `audit.sink: chain` writes) or `config` (the trail
`audit.config_path` writes). The two channels write different payload
shapes to different files, so pass the channel that matches the file:

```bash
sbproxy audit verify /var/lib/sbproxy/config-audit.jsonl \
  --channel config --signing-seed-hex "$SBPROXY_AUDIT_SEED"
```

Without `--signing-seed-hex` only the hash chain is checked, which catches
an edit made by somebody who could not re-link the file and misses one
made by somebody who could. `--format json` emits a single object with
`entries`, `ok`, `broken_seq`, `reason`, and `signature_checked` for
tooling.

The command reads the file and nothing else. No config, no admin API, no
running proxy: an auditor with a copy of the trail and the public key can
verify a file the proxy that wrote it no longer has. The digest layout is
fixed and documented in the ledger module, so an auditor who would rather
not run our binary at all can reproduce it from any SHA-256 and Ed25519
implementation.

### What it does not cover yet

`config_audit` is chainable, but only when `audit.config_path` is set; see
[The config chain](#the-config-chain) above. `key_audit` is not chainable
at all yet, deliberately: it ships a before/after diff of a credential
record, and writing that into a file designed to be impossible to quietly
amend needs its own answer to what the diff may contain before it goes
anywhere permanent.

The admin-action ring at `/api/audit/recent` is not chained either, and
neither is the `sbproxy::admin::audit` tracing target that records admin
logins and config writes.

There is no rotation or segmentation on either chain: each is one file
that grows, and truncating it is by construction indistinguishable from
tampering with it. Size it accordingly, and archive by copying rather
than by trimming.

### What a record may contain

The chained record is a `SecurityAuditEntry` on the security chain, or a
`ConfigAuditEntry` on the config chain, and nothing more in either case.
Every field of the security entry is an identifier, a label, or a status:
hostname, client IP, request id, method, status code, tenant, the
recognized provider label, the credential mode, and the public
`api_key_id`. The config entry's fields are listed in
[`config_audit`: configuration changes](#config_audit-configuration-changes)
below: which origins moved, which revision to which revision, and the
operator name, never a config value. Neither type carries a credential, a
token, a header value, or a resolved config value, which is a property
each is required to keep rather than one it happens to have. Durability is
why it matters: a secret written into a hash chain cannot be quietly
removed later, because quiet removal is the thing the chain exists to
prevent.

The one operator-authored field on the security chain is `reason`, which
carries a policy's deny message. It is written verbatim, in the chain and
on the tracing target alike. If your deny messages interpolate request
data, that data reaches both.

### If the chain cannot be written

Opening either chain is a boot condition. A path that cannot be created, a
seed that is not 32 bytes of hex, or an existing file whose last line was
torn by a crash all stop the proxy from starting, and the error names
`audit.path` for the security chain or `audit.config_path` for the config
chain.

That is the opposite of what the metering chain does with the same
conditions, and the difference is deliberate. Metering defaults to
`degraded` because a full ledger disk must not take an API down and
billing can be reconciled afterwards. An audit trail cannot be
reconciled afterwards: the events that would fall in the hole are the ones
an investigator needs, and no later moment recovers them. An operator who
would rather have the proxy sets `sink: memory` and leaves `config_path`
unset.

An append that fails after boot cannot stop anything, because the request
or reload being audited is already going through and failing it a second
way would turn a full disk into an outage. Instead the emitter records the
loss: the outcome of that emission on
`sbproxy_audit_emit_duration_seconds` is `chain_error` rather than `ok`,
so the failure is visible on a dashboard, not just in the log; see
[Metrics](#metrics). The first such failure, and the first after any
recovery, is also logged at `error` on the `security_audit` or
`config_audit` target, whichever chain failed, which is the pipe you are
already watching. Repeats are suppressed so an attack against a proxy with
a full disk does not also produce one log line per refused request.

## Calling it

The runnable configuration is
[`examples/audit-log/`](../examples/audit-log/). It boots a proxied origin so
there is something to reload, enables the admin server on `:9090` behind basic
auth, and turns the access log on so both streams are visible together. Start
it:

```bash
make run CONFIG=examples/audit-log/sb.yml
```

`POST /admin/reload` is the canonical state-mutating admin call. The password
is the one in that config, `demo-change-me`:

```bash
curl -sS -X POST -u admin:demo-change-me http://127.0.0.1:9090/admin/reload
```

The call itself answers with the new revision:

```json
{"config_revision":"8f10eba811d1","loaded_at":"2026-08-01T15:02:21.996698+00:00","fully_applied":true,"degraded":[]}
```

Two lines land on the proxy's stdout. First the admin-action line, on the
`sbproxy::admin::audit` target, which records who called what:

```
INFO sbproxy::admin::audit: admin action operator=admin role=admin method=POST path=/admin/reload
```

Then the `config_audit` envelope, which is JSON because it is meant for a
sink rather than a human:

```json
{"timestamp":"2026-08-01T15:02:15.368528+00:00","source":"api","origins_added":[],"origins_removed":[],"origins_modified":[],"actor":"admin","prior_revision":"8f10eba811d1","next_revision":"8f10eba811d1"}
```

`source` is `api` because the change arrived through the admin endpoint; the
same reload triggered by editing the file on disk records `file_watcher` and
carries no `actor`. The three `origins_*` arrays are empty and
`prior_revision` equals `next_revision` because nothing in the file actually
changed between the two reads. That is the useful shape to recognize: a reload
that was applied but was a no-op looks exactly like this, and a reload that
changed something names the hostnames and moves the revision.

The admin-action audit ring is a separate surface, and on a fresh proxy it is
empty:

```bash
curl -sS -u admin:demo-change-me 'http://127.0.0.1:9090/api/audit/recent?limit=50'
```

```json
[]
```

That empty array is correct rather than a misconfiguration. As described
above, the rows in this ring come from the workspace rate-limit budget's
auto-suspend and resume transitions, which are its only emitters today. A
config reload does not produce one. If you are looking for a record of the
reload, it is the `config_audit` line, not this endpoint.

## Tracing audit channels

Three structured channels in `crates/sbproxy-observe/src/audit.rs` emit JSON records on dedicated `tracing` targets, so operators can route each one to its own sink (a SIEM, ClickHouse, a file) independently of the main application log.

### `config_audit`: configuration changes

One `ConfigAuditEntry` per applied configuration update, emitted at INFO on the `config_audit` target:

| Field | Notes |
|---|---|
| `timestamp` | RFC 3339. |
| `source` | What triggered the change: `file_watcher`, `api`, or `mesh_broadcast`. |
| `origins_added` | Hostnames added in this update. |
| `origins_removed` | Hostnames removed. |
| `origins_modified` | Hostnames whose configuration changed. |
| `tenant_id` | Tenant scope, omitted for proxy-wide changes. |
| `actor` | Operator that made the change, when it arrived through an authenticated admin surface. Omitted for file-watcher and mesh-broadcast changes. |
| `prior_revision` | Config revision before the change, when known. |
| `next_revision` | Config revision after the change, when known. Equal to `prior_revision` when the reload found nothing to change. |

Every field after `origins_modified` is omitted rather than nulled when it
does not apply.

### `security_audit`: security-relevant rejections

One `SecurityAuditEntry` per security-relevant rejection, on the `security_audit` target. The `event_type` names the class of rejection and the `reason` field carries a stable discriminator within it, so a SIEM rule can route on the pair without parsing prose. `framing_violation` (request-smuggling defenses) uses `dual_cl_te`, `duplicate_cl`, `malformed_te`, `duplicate_te`, and `control_chars`, which match the `sbproxy_http_framing_blocks_total{reason}` metric label exactly. `mcp_transport_denied` uses `mcp_modern_missing_trust_anchor`, `mcp_modern_authority`, and `mcp_modern_origin`. Rate limiting, the WAF, A2A, and object authorization emit here too.

The schema deliberately omits the offending header value: including attacker-controlled bytes in a SIEM log is a poisoning vector. Entries carry hostname, client IP, request id, method, status code, and tenant when known. `hostname` is always the request's origin, so denials correlate across event classes.

### `key_audit`: key and credential mutations

One `KeyAuditEntry` per key or credential mutation (`create`, `update`, `delete`, `revoke`, `block`, `unblock`, `rotate`) on the `key_audit` target. The record carries the public record id, the acting principal when known, the tenant, and redacted before/after snapshots. It never carries a plaintext secret or hash.

## Plugin seam: `AdminAuditEmitter`

`crates/sbproxy-plugin/src/audit.rs` defines the seam between the request path and an out-of-tree audit sink:

```rust,no_run
pub trait AdminAuditEmitter: Send + Sync + 'static {
    fn record_projection_refresh(&self, event: ProjectionRefreshEvent);
}
```

The default build registers a no-op emitter (`NoOpAdminAuditEmitter`); a downstream build installs its own with `install_admin_audit_emitter`. Projection regeneration is the first consumer: every refresh emits one `ProjectionRefreshEvent` per `(hostname, projection_kind, config_version)` tuple, carrying the SHA-256 of the canonical document body and its byte length so an external auditor can verify that the served document matches what was recorded at reload time. Implementations must not block, panic, or propagate errors back to the request path.

## Failure handling

Audit emission failure never fails the underlying request or config operation. A `ConfigAuditEntry` that fails JSON serialization is dropped and the drop is visible in the metric below. A configured chain that rejects an append (a full disk, for instance) also does not fail the request or reload; the emitter records the loss on the same metric instead. The tracing channels otherwise inherit the logging pipeline's delivery semantics.

## Metrics

Each emission on the tracing channels records its wall-clock duration on:

```
sbproxy_audit_emit_duration_seconds{channel, outcome}
```

`channel` is `config`, `security`, or `key`. `outcome` is `ok`, `serialize_error`, or `chain_error`. `serialize_error` means the audit record failed to encode and was dropped entirely, on any channel. `chain_error` means encoding succeeded, the tracing target still got the record, but a configured chain (`audit.path` on the security channel, `audit.config_path` on the config channel) rejected the append, so that record is not in the durable trail; `key` never reports `chain_error` because `key_audit` has no chain to append to. Either non-`ok` outcome is worth alerting on: `outcome!="ok"` firing means either an audit record vanished or your tamper-evident trail has a gap. The histogram carries the active trace as an exemplar so a slow audit sink links back to the originating span.

## See also

- [ai-usage-ledger.md](ai-usage-ledger.md) and [metering.md](metering.md) - the other two chains built on the same primitive, for LLM spend and for metering receipts.
- [observability.md](observability.md) - the logging pipeline the tracing targets flow through.
- [access-log.md](access-log.md) - routine request records; reads are not audited, they are access-logged.
- [admin-api-reference.md](admin-api-reference.md) - the admin surface that serves `/api/audit/recent`.
