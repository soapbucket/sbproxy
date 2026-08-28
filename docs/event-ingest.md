# Event ingest: NATS and ClickHouse

*Last modified: 2026-08-27*

The request-event stream is one fully populated record per terminating
request: request id, workspace, host, latency, status, and, on an AI
request, the provider, model, token counts, and cost. `request_events:`
decides where it goes. Two of the destinations put it somewhere other than
this machine.

## Optional means optional

Neither destination runs, dials, or allocates a queue until an operator
configures it. `request_events.sink` is `none` by default and stays that
way; the local `logging` and `file` sinks remain the answer for deployments
that want the stream without a broker.

This follows the OpenTelemetry Collector's distribution model, which is
worth naming because it is the design being copied: a small default set,
optional exporters that exist but do nothing until a pipeline names them,
and configuring one is not the same as enabling it.

What SBproxy does differently is refuse to pay for that split at build time.
There is no `nats` or `clickhouse` cargo feature. Both destinations are
always compiled, so a release cannot ship a binary whose config schema
advertises a sink it cannot construct, and `sbproxy validate` tells you
about a typo instead of a startup on a differently-built binary doing so.

Neither adds a dependency, either. NATS's core protocol is a handful of text
commands over TCP; ClickHouse's HTTP interface takes `INSERT ... FORMAT
JSONEachRow` as a POST body. Both are about two hundred lines here, against
client libraries whose reconnect policy and TLS stack this project would
then own the behavior of without controlling it.

## NATS

`request_events:` is a top-level block, a sibling of `proxy:` rather than a
key inside it.

```yaml
request_events:
  sink: nats
  queue_capacity: 8192
  watermark_store_path: /var/lib/sbproxy/event-ingest.redb
  nats:
    address: "nats.internal:4222"
    subject_prefix: sb.events
    token: vault://kv/data/sbproxy#nats_token
```

`address` is `host:port`, not a URL. The core protocol is plain TCP, and a
`nats://` string would suggest a URL parser that is not here; one is refused
at startup rather than parsed loosely.

`token` is a secret reference resolved through `proxy.secrets`, the same
machinery every other credential in this config uses. A reference that will
not resolve falls back to the `logging` sink with a warning rather than
sending the reference itself to the broker as a token.

**The token crosses the network in the clear.** This client speaks the core
protocol over plain TCP and does not implement the NATS TLS handshake, so
`CONNECT` carries `auth_token` unencrypted. Keep the broker on a segment you
trust, or front it with a TLS terminator that this proxy dials in plaintext
from inside that segment.

A broker that advertises `tls_required` in its `INFO` greeting is **refused
at connect**, with a line saying why, rather than handed the token on a
socket the server is about to fail the handshake on. It would have been
handed it again on the next batch, and the next, since each batch redials.

### Subjects

```
<subject_prefix>.<workspace_id>.<event_type>
sb.events.acme.request_completed
```

The workspace id is the one caller-influenced value that reaches a routing
decision, so it is sanitized before it gets there: anything outside
`[A-Za-z0-9_-]` collapses to `_`, and the result is capped at 128 bytes. A
workspace id containing a `.` would otherwise create a subject one level
deeper than intended, and one containing `>` or `*` would name a wildcard,
so a subscriber filtering `sb.events.acme.>` would receive another
workspace's traffic or miss its own.

### Delivery

One JSON message per event, published in batches of up to 256, each batch
flushed with a `PING` and confirmed by the broker's `PONG`. That is the
documented NATS flush idiom: the server processes commands in order, so a
`PONG` after N publishes says the server took all N.

The connect handshake ends in the same round trip, and that is load bearing.
NATS answers a rejected `CONNECT` with `-ERR` rather than closing
immediately, so without the ping a bad token looks exactly like a good one
until the first publish disappears into a socket the server is about to
close.

A broker that is down at boot does not stop the proxy from booting: the
first dial happens on the first batch. A broker that goes away mid-run costs
one reconnect and a retried batch; a second failure drops the batch and
counts it.

The retry is deliberately narrower than "any failure". A batch whose write
completed is one the server already has, because NATS processes commands in
order, so a flush or `PONG` that then times out is a lost acknowledgement
rather than a lost batch. That batch is **not** resent: resending it is how
256 events become 512 rows, and this page promises they will not. It is
counted as published, with a `warn` saying the acknowledgement never
arrived.

The client reads `max_payload` out of the server's `INFO` and skips any
message past it, counting the skip under `outcome="oversize"`. NATS answers
an oversized `PUB` with `-ERR` and then closes the connection, so without
this one event with a large `properties` map would take the other 255 events
in its batch with it, and do it again on the next batch carrying a neighbor
like it.

## ClickHouse

```yaml
request_events:
  sink: clickhouse
  watermark_store_path: /var/lib/sbproxy/event-ingest.redb
  clickhouse:
    url: http://clickhouse.internal:8123
    database: sbproxy
    table: sbproxy_request_events
    user: sbproxy_writer
    password: vault://kv/data/sbproxy#clickhouse_password
```

`database` and `table` are refused unless they match `[A-Za-z0-9_]+`,
because they are interpolated into the statement rather than bound: the
validation is what stops a hostile config from turning one into a second
statement.

The POST goes through the same governed egress loop as every other
credential-carrying outbound path here, so the destination is authorized
against the `egress:` allowlist when one is armed, the dial is pinned to the
addresses the SSRF guard resolved, and a redirect is re-authorized rather
than followed. That last one matters: the credential rides
`X-ClickHouse-Key`, a header no HTTP client's built-in credential stripping
has heard of, and a `307` replays a body verbatim.

### The table

SBproxy never applies DDL. Applying schema to somebody's warehouse from a
proxy is a privilege nobody asked it to have, and an operator running
ClickHouse already has a way to run DDL. Create the table first; the sink
fails loudly against a missing one.

The sink POSTs `serde_json::to_vec(event)` verbatim, so the table needs a
column for every field a `RequestEvent` carries. All thirty are below.
`key_mode` in particular is set on **every** row, so a table missing it
fails every insert on a server with `input_format_skip_unknown_fields=0`,
and silently discards the field on one with the modern default of `1`.

```sql
CREATE TABLE IF NOT EXISTS sbproxy_request_events (
    request_id           String,
    parent_request_id    String,
    workspace_id         String,
    tenant_id            String,
    hostname             String,
    timestamp_ms         UInt64,
    timestamp            DateTime64(3) MATERIALIZED toDateTime64(timestamp_ms / 1000.0, 3),
    latency_ms           UInt32,
    event_type           LowCardinality(String),
    session_id           String,
    parent_session_id    String,
    user_id              String,
    user_id_source       LowCardinality(String),
    api_key_id           String,
    key_provider         LowCardinality(String),
    key_mode             LowCardinality(String),
    properties           Map(String, String),
    provider             LowCardinality(String),
    model                LowCardinality(String),
    prompt_tokens_est    UInt32,
    prompt_fingerprint   String,
    tokens_in            UInt32,
    tokens_out           UInt32,
    tokens_cached        UInt32,
    tokens_cache_write   UInt32,
    cost_usd_micros      UInt64,
    status_code          UInt32,
    error_class          LowCardinality(String),
    guardrail_category   LowCardinality(String),
    guardrail_action     LowCardinality(String),
    request_geo          LowCardinality(String),
    inserted_at          DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(inserted_at)
PARTITION BY (workspace_id, toYYYYMMDD(timestamp))
ORDER BY (workspace_id, timestamp, request_id, event_type)
TTL timestamp + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;
```

Every optional field is serialized as `null` when it is absent, so the
inserting user needs `input_format_null_as_default=1`, which is ClickHouse's
default for `JSONEachRow`. If you drop a column you do not want, set
`input_format_skip_unknown_fields=1` on the same user and know that the
field is being discarded rather than stored.

`ReplacingMergeTree` on `(workspace_id, timestamp, request_id, event_type)`
means a duplicate insert collapses on the next background merge, which is
what makes a re-run of a backfill safe. The partition key is what lets a
retention job drop a whole tenant-day without scanning rows.

A refused insert is a `warn` naming the database, the table, the status, and
a bounded slice of ClickHouse's own response, which is where it says
`Code: 60 ... does not exist` or `Code: 117 ... Unknown field`. Those are
two different things to go and fix.

## The watermark

```yaml
request_events:
  watermark_store_path: /var/lib/sbproxy/event-ingest.redb
```

After every batch the destination confirms, the sink records the **newest**
event in that batch, by `timestamp_ms`, plus a running delivered count, in
one embedded record. An operator reconciling their warehouse against the
proxy needs a position that survives a restart, and a position is one row,
which is not a reason to run a database. This is what replaces the Postgres
`reconciliation_state` table the same feature used elsewhere.

Newest rather than last, because `timestamp_ms` is request *start*: a
`request_completed` for a request that began thirty seconds ago is emitted
after one for a request that began a moment ago, so queue order is not time
order. The stored position never moves backwards, and a batch entirely older
than the checkpoint advances the count without moving it.

It is still a checkpoint, not a completeness boundary. `WHERE timestamp_ms >
:last_timestamp_ms` will re-read rows for requests that started before the
checkpoint and finished after it. Use it to answer "roughly how far has this
proxy got", and use `ReplacingMergeTree` for the rest.

A checkpoint written for one destination is not read as another's: a
deployment that switches from NATS to ClickHouse has delivered nothing to
ClickHouse yet, and reading the old position as its own would tell an
operator it was caught up when it is not.

Leaving `watermark_store_path` unset costs nothing and answers nothing.

## Backpressure, and what is lost

Publishing is one `try_send` on a bounded queue. Nothing on the request path
waits for a broker or a warehouse. A full queue discards the incoming event
and counts it under `outcome="dropped"`.

A batch the destination refuses is **lost**, and counted under
`outcome="error"`. This sink does not retry, for the reason
[notifications.md](notifications.md) sets out at more length: holding a
batch for later means a durable outbound spool with a scheduler and a
backpressure story of its own. The request-event stream is telemetry, and
the durable local copy is `sink: file`. If you need at-least-once delivery
into a warehouse, write the file and ship it with a tool built for that.

Say this out loud when planning: **this is at-most-once delivery**. What it
gives you is a live stream with visible loss, not a ledger.

## What an operator can see

`sbproxy_event_ingest_events_total{target,outcome}`, drawn on the **SBProxy
Mesh Admission and Storage** dashboard.

| `outcome` | Means |
|---|---|
| `published` | The destination confirmed the batch. |
| `dropped` | The hand-off queue was full; the request path outran the sink. |
| `error` | The destination did not take the batch, and it is gone. |
| `oversize` | A message past the broker's advertised `max_payload`, skipped so its batch could land. |
| `reconnected` | A broker redial, not counting the process's first dial. A steady rate here is a broker cycling. |
| `worker_stopped` | The worker thread is gone. Nothing will drain the queue. |

`target` is `nats` or `clickhouse`. Nothing is labeled by workspace,
subject, or table: the first is unbounded and the other two are derived from
it. The workspace is in the event, which is where you look when one tenant
is the problem.

There is no admin console page for this. A fire-and-forget telemetry sink
has no state an operator acts on beyond the counters above and the watermark
in the summary line it logs at boot, and a page that renders four numbers a
dashboard already draws is a page that goes stale. The subsystems on this
same store that do have decisions to make have pages:
[agent-registry.md](agent-registry.md) and
[notifications.md](notifications.md).

## Related

- [observability.md](observability.md) - the request-event stream, its fields, and the other `request_events` sinks.
- [notifications.md](notifications.md) - the retrying, deadlettering outbound path, and why this one is not that.
- [events.md](events.md) - the other event stream, and the difference between them.
