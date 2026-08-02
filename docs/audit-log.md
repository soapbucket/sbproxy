# Audit log
*Last modified: 2026-08-01*

SBproxy's audit surface is a set of narrow, structured channels rather than one audit framework. This page documents what actually ships: the admin-action audit rows served at `/api/audit/recent`, the `config_audit` / `security_audit` / `key_audit` tracing channels, the `AdminAuditEmitter` plugin seam, and the emission metric. There is no `sbproxy_audit` crate, no envelope middleware, and no append-only storage trait in the OSS tree; durable persistence and hash-chained verification live in the commercial distribution.

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

### Compatibility-only sink selector

The top-level `audit:` block remains parseable, but the OSS runtime does not
use its `sink` value:

```yaml
audit:
  sink: memory        # accepted for compatibility; no runtime effect
```

Admin-action rows always use both live paths: the most recent 256 rows remain
queryable via `/api/audit/recent`, and every row is mirrored to the structured
`security_audit` tracing target. Explicitly authoring `audit.sink` emits a
config-only warning.

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
changed between the two reads. That is the useful shape to recognise: a reload
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

One `SecurityAuditEntry` per security-relevant rejection, on the `security_audit` target. Today the event class is `framing_violation` (request-smuggling defenses); the `reason` field carries a stable discriminator (`dual_cl_te`, `duplicate_cl`, `malformed_te`, `duplicate_te`, `control_chars`) that matches the `sbproxy_http_framing_blocks_total{reason}` metric label exactly. The schema deliberately omits the offending header value: including attacker-controlled bytes in a SIEM log is a poisoning vector. Entries carry hostname, client IP, request id, method, status code, and tenant when known.

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

Audit emission failure never fails the underlying request or config operation. A `ConfigAuditEntry` that fails JSON serialization is dropped and the drop is visible in the metric below; the tracing channels otherwise inherit the logging pipeline's delivery semantics.

## Metrics

Each emission on the tracing channels records its wall-clock duration on:

```
sbproxy_audit_emit_duration_seconds{channel, outcome}
```

`channel` is `config`, `security`, or `key`; `outcome` is `ok` or `serialize_error`. A `serialize_error` outcome means the audit record was dropped, which is itself worth alerting on. The histogram carries the active trace as an exemplar so a slow audit sink links back to the originating span.

## See also

- [observability.md](observability.md) - the logging pipeline the tracing targets flow through.
- [access-log.md](access-log.md) - routine request records; reads are not audited, they are access-logged.
- [admin-api-reference.md](admin-api-reference.md) - the admin surface that serves `/api/audit/recent`.
