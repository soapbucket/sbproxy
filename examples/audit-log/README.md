# audit-log

*Last modified: 2026-07-09*

Every state-mutating admin call emits an admin-action line and, for a
config change, a `config_audit` envelope on the structured-log stream.
Pair this example with the
[`access-log`](../access-log/) example to see the two streams
side by side: the access log carries one row per request, the
audit log carries one envelope per mutation.

See [`docs/audit-log.md`](../../docs/audit-log.md) for the field
reference on each channel (`config_audit`, `security_audit`,
`key_audit`), the `/api/audit/recent` ring, and the structured-log
sink notes.

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
curl -s -X POST -u admin:demo-change-me http://127.0.0.1:9090/admin/reload
```

## What you see on stdout

The call answers with the new revision:

```json
{"config_revision":"8f10eba811d1","loaded_at":"2026-08-01T15:02:21.996698+00:00","fully_applied":true,"degraded":[]}
```

Two lines land on stdout. The admin-action line records who called what:

```
INFO sbproxy::admin::audit: admin action operator=admin role=admin method=POST path=/admin/reload
```

Then the `config_audit` envelope:

```json
{"timestamp":"2026-08-01T15:02:15.368528+00:00","source":"api","origins_added":[],"origins_removed":[],"origins_modified":[],"actor":"admin","prior_revision":"8f10eba811d1","next_revision":"8f10eba811d1"}
```

`source` is `api` because the reload arrived through the admin endpoint;
the same reload from a file edit records `file_watcher` and carries no
`actor`. Empty `origins_*` arrays with an unchanged revision mean the
reload applied but found nothing to change.

Redaction rules for these channels are in `docs/audit-log.md`.

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
| `POST -u admin:demo-change-me /admin/reload` | Config reload (the example above) |
| `POST -u admin:demo-change-me /admin/log-level?level=debug` | Log-level change (where supported) |

See [`docs/admin-api-reference.md`](../../docs/admin-api-reference.md)
for the full route list and per-route schema.
