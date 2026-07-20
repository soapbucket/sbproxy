# audit-log

*Last modified: 2026-07-09*

Every state-mutating admin call emits a typed `AdminAuditEvent`
envelope on the structured-log stream. Pair this example with the
[`access-log`](../access-log/) example to see the two streams
side by side: the access log carries one row per request, the
audit log carries one envelope per mutation.

See [`docs/audit-log.md`](../../docs/audit-log.md) for the full
envelope schema (subject / action / target enums), the append-only
contract, and the structured-log sink notes.

## Run

```bash
# password defaults to demo-change-me in sb.yml
make run CONFIG=examples/audit-log/sb.yml
```

The proxy binds on `:8080`, the admin server on `:9090` (loopback only).

## Trigger an audited mutation

`/admin/reload` is the canonical mutating admin call; it reloads the
config without dropping connections and emits an audit envelope per
reload.

```bash
curl -s -X POST -u admin:demo http://127.0.0.1:9090/admin/reload
```

## What you see on stdout

One access-log row for the admin request, plus one audit envelope
for the reload mutation:

```json
{
  "event_id": "01H...",
  "schema_version": 0,
  "ts": "2026-06-04T01:23:45Z",
  "tenant_id": "default",
  "subject": {
    "kind": "user",
    "user_id": "admin"
  },
  "action": "reload_config",
  "target": {
    "target_kind": "config",
    "config_id": "current"
  },
  "before": null,
  "after": {
    "config_path": "examples/audit-log/sb.yml",
    "loaded_at": "2026-06-04T01:23:45Z"
  },
  "result": "Success",
  "request_id": "01H...",
  "trace_id": "",
  "span_id": "",
  "ip": "127.0.0.1"
}
```

The `before` / `after` snapshots are redacted per
`docs/audit-log.md` (secrets stripped); the `reason` field is
operator-supplied and not redacted.

## What is audited (and what is not)

Audit emission is **on writes by default**. Routine reads (`/api/agents`,
`/api/balance`, etc.) are NOT audited - those land in the access log
and the request-event stream. Read-audit only fires on three classes:

1. Reads against the audit log itself (an auditor must be auditable).
2. Reads against secret material (key-management endpoints, even when
   the response redacts the secret).
3. Bulk-export endpoints.

Adding read-audit to a routine endpoint requires an ADR amendment
because the cardinality cost is high.

## Where to ship the lines

The OSS structured-log sink is "stdout, JSON, one event per line".
Production deployments pair that with whatever log shipper they
already run (Fluent Bit, Vector, OTel Collector). Durable, indexed
audit storage (Postgres, S3, hash-chained verification, the
verifier CLI) ships with the commercial distribution; the OSS
sink is the breadcrumb path your shipper picks up.

## Mutating verbs to try

| `curl` | What it audits |
|---|---|
| `POST -u admin:demo /admin/reload` | Config reload (the example above) |
| `POST -u admin:demo /admin/log-level?level=debug` | Log-level change (where supported) |

See [`docs/admin-api-reference.md`](../../docs/admin-api-reference.md)
for the full route list and per-route schema.
