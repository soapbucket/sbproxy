# ClickHouse attribution

*Last modified: 2026-06-01*

A canonical ClickHouse schema for the SBproxy access log, plus sample queries for the three reports an operator most often wants: monthly project cost, top users by token spend, and tag-level burndown against a budget. The schema mirrors the JSON shape emitted by the structured logger (`sbproxy-observe::access_log::AccessLogEntry`), so a Vector / Fluent Bit pipeline can ingest the proxy's stdout into ClickHouse without an intermediate transform.

This guide assumes a recent ClickHouse (v24.3 or newer; `JSONEachRow` and `TIMESTAMP` semantics are unchanged across the LTS line). The schema uses `MergeTree` for the raw rows and `AggregatingMergeTree` for the materialised pre-aggregations.

## Why ClickHouse

The access log carries one row per terminated request. A production proxy emits 10 to 100 million rows per day. Three properties matter for an attribution warehouse:

1. **Columnar reads.** Almost every attribution query reads three to five columns from a row that has 60+. Columnar beats row-oriented by 10-20x on this shape.
2. **Time-partitioned writes.** UUIDv7 `request_id` already encodes the ingest millisecond in its leading 48 bits, so `ORDER BY (toDate(timestamp), request_id)` keeps writes append-only and partitions land naturally without a separate `_date` derived column.
3. **Pre-aggregation.** `AggregatingMergeTree` collapses the 10M-row daily volume to a few thousand per-day-per-project rows, so the dashboards point at a table that fits in memory regardless of fleet size.

## Raw row table

The schema mirrors `AccessLogEntry`. Optional fields land as `Nullable(...)` so a row with no AI fields (a vanilla reverse-proxy hit) inserts without sentinels. Strings stay `LowCardinality(String)` for the columns whose distinct count is bounded; freeform fields use plain `String`.

```sql
CREATE TABLE access_log
(
    -- Identity
    timestamp                 DateTime64(3, 'UTC'),
    request_id                String,
    origin                    LowCardinality(String),
    method                    LowCardinality(String),
    path                      String,
    query                     Nullable(String),
    protocol                  LowCardinality(Nullable(String)),
    scheme                    LowCardinality(Nullable(String)),
    host                      Nullable(String),
    user_agent                Nullable(String),
    referer                   Nullable(String),
    status                    UInt16,
    upstream_status           Nullable(UInt16),
    latency_ms                Float64,
    auth_ms                   Nullable(Float64),
    upstream_ttfb_ms          Nullable(Float64),
    response_filter_ms        Nullable(Float64),
    bytes_in                  UInt64,
    bytes_out                 UInt64,
    client_ip                 LowCardinality(String),

    -- Attribution
    workspace_id              LowCardinality(String),
    auth_type                 LowCardinality(Nullable(String)),
    principal_kind            LowCardinality(Nullable(String)),
    project                   LowCardinality(Nullable(String)),
    user                      LowCardinality(Nullable(String)),
    metadata                  Map(LowCardinality(String), String),

    -- AI gateway
    provider                  LowCardinality(Nullable(String)),
    model                     LowCardinality(Nullable(String)),
    prompt_name               LowCardinality(Nullable(String)),
    prompt_version            LowCardinality(Nullable(String)),
    tokens_in                 Nullable(UInt64),
    tokens_out                Nullable(UInt64),
    ai_surface                LowCardinality(Nullable(String)),

    -- Cache / cost
    cache_result              LowCardinality(Nullable(String)),
    tier                      LowCardinality(Nullable(String)),
    shape                     LowCardinality(Nullable(String)),
    price                     Nullable(UInt64),
    currency                  LowCardinality(Nullable(String)),
    rail                      LowCardinality(Nullable(String)),
    cost_usd_micros           Nullable(UInt64) MATERIALIZED if(
        price IS NOT NULL AND currency = 'USD',
        price,
        toNullable(0)
    ),

    -- Trace correlation
    trace_id                  Nullable(String),
    envelope_request_id       Nullable(String),
    user_id                   Nullable(String),
    session_id                Nullable(String),

    -- Captured headers (bounded by access-log capture caps)
    request_headers           Map(LowCardinality(String), String),
    response_headers          Map(LowCardinality(String), String),
    properties                Map(LowCardinality(String), String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (toDate(timestamp), workspace_id, project, request_id)
TTL toDate(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
```

The `TTL` is the recommended starting point for a SaaS deployment. Hot-data dashboards work off the last 30 days; the 90-day window covers month-end reconciliation. Compliance regimes that require longer retention (HIPAA, financial audit) should bump the TTL and budget the storage; ClickHouse compresses this schema to roughly 12-16 bytes per row in practice.

## Truncation policy for text fields

The proxy never persists raw prompt or completion text to the access log. The `prompt_name` and `prompt_version` columns identify the rendered prompt; the token counts (`tokens_in`, `tokens_out`) describe the volume. If an operator needs raw text for evals or audit, route those through a separate sink with redaction enabled and ingest into a parallel table:

```sql
CREATE TABLE prompt_audit
(
    timestamp     DateTime64(3, 'UTC'),
    request_id    String,
    role          LowCardinality(String),
    content_redacted String  -- emitted by the reversible PII pass; placeholders only
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (toDate(timestamp), request_id)
TTL toDate(timestamp) + INTERVAL 30 DAY;
```

Joining `prompt_audit` to `access_log` on `request_id` lets analysts trace a flagged response back to the redacted prompt without ever surfacing PII. The reversible-PII pass on the AI origin keeps the original out of every persisted artefact; only `<placeholder:...>` shapes ever land here. See the "Reversible PII redaction" section in `docs/observability.md` for the opt-in.

## Sample query 1: monthly project cost rollup

```sql
SELECT
    project,
    toStartOfMonth(timestamp)            AS month,
    countIf(provider IS NOT NULL)        AS ai_requests,
    sumIf(tokens_in,  provider IS NOT NULL) AS input_tokens,
    sumIf(tokens_out, provider IS NOT NULL) AS output_tokens,
    sum(cost_usd_micros) / 1e6            AS usd_spend
FROM access_log
WHERE workspace_id = {workspace:String}
  AND timestamp >= now() - INTERVAL 6 MONTH
  AND project   IS NOT NULL
GROUP BY project, month
ORDER BY month DESC, usd_spend DESC;
```

The query partitions by month and project. `cost_usd_micros` is the materialised column from the schema; rows without a settled price contribute zero. Pass the operator's workspace_id as a parameter so a SaaS deployment can serve the report to multiple tenants from one table without a per-tenant view.

## Sample query 2: top-10 users by token spend in the last 24h

```sql
SELECT
    user,
    project,
    sumIf(tokens_in,  provider IS NOT NULL) AS input_tokens,
    sumIf(tokens_out, provider IS NOT NULL) AS output_tokens,
    (input_tokens + output_tokens)           AS total_tokens,
    sum(cost_usd_micros) / 1e6               AS usd_spend
FROM access_log
WHERE workspace_id = {workspace:String}
  AND timestamp >= now() - INTERVAL 24 HOUR
  AND user      IS NOT NULL
GROUP BY user, project
ORDER BY total_tokens DESC
LIMIT 10;
```

The `principal_kind` column lets a query filter to non-AI traffic when wanted; the example above implicitly leaves it untouched so virtual-key and bearer-token attribution merge into one report. To split:

```sql
WHERE ...
  AND principal_kind IN ('virtual_key', 'bearer')
```

## Sample query 3: tag-level burndown vs budget

The per-credential attribution metric `sbproxy_tokens_attributed_total{project, user, tag, direction}` rolls up at scrape time; the access-log query below mirrors it against per-credential budgets so dashboards can show "tag X has spent 7,200 of its 10,000 token allotment this week":

```sql
WITH (
    SELECT map(
        'cost_center=eng-001', 10000,
        'cost_center=ops-002', 5000,
        'team=foundation',     50000
    )
) AS tag_budgets

SELECT
    arrayJoin(mapKeys(metadata))   AS tag,
    metadata[tag]                   AS tag_value,
    sumIf(tokens_in + tokens_out, provider IS NOT NULL) AS spent_tokens,
    tag_budgets[concat(tag, '=', tag_value)]            AS budget_tokens,
    if(budget_tokens > 0,
       round(100.0 * spent_tokens / budget_tokens, 1),
       NULL)                                            AS percent_used
FROM access_log
WHERE workspace_id = {workspace:String}
  AND timestamp >= toStartOfWeek(now())
  AND notEmpty(metadata)
GROUP BY tag, tag_value
HAVING budget_tokens > 0
ORDER BY percent_used DESC;
```

The query reads tag values out of the `metadata` map column (populated from the AI virtual key's `metadata:` block; a follow-up wires the same map for the non-AI auth providers). Replace the inline `tag_budgets` map with a join against an operator-maintained budget table for production use.

## Materialised view: per-day-per-project pre-aggregation

Dashboards that render six months of monthly rollups every 30 seconds do not need to scan the raw 1.8B-row table on every refresh. A daily pre-aggregation collapses the volume to a few thousand rows per workspace:

```sql
CREATE TABLE access_log_daily_project
(
    day                  Date,
    workspace_id         LowCardinality(String),
    project              LowCardinality(String),
    ai_requests          AggregateFunction(count,  UInt64),
    input_tokens         AggregateFunction(sum,    UInt64),
    output_tokens        AggregateFunction(sum,    UInt64),
    usd_spend_micros     AggregateFunction(sum,    UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (day, workspace_id, project);

CREATE MATERIALIZED VIEW access_log_daily_project_mv
TO access_log_daily_project
AS SELECT
    toDate(timestamp)                                    AS day,
    workspace_id,
    project,
    countState(toUInt64(1))                              AS ai_requests,
    sumState(toUInt64(coalesce(tokens_in,  0)))          AS input_tokens,
    sumState(toUInt64(coalesce(tokens_out, 0)))          AS output_tokens,
    sumState(toUInt64(coalesce(cost_usd_micros, 0)))     AS usd_spend_micros
FROM access_log
WHERE project IS NOT NULL
GROUP BY day, workspace_id, project;
```

Read it with `*Merge` finalisers:

```sql
SELECT
    project,
    toStartOfMonth(day)                  AS month,
    countMerge(ai_requests)              AS ai_requests,
    sumMerge(input_tokens)               AS input_tokens,
    sumMerge(output_tokens)              AS output_tokens,
    sumMerge(usd_spend_micros) / 1e6     AS usd_spend
FROM access_log_daily_project
WHERE workspace_id = {workspace:String}
  AND day >= toDate(now()) - INTERVAL 6 MONTH
GROUP BY project, month
ORDER BY month DESC, usd_spend DESC;
```

The dashboard query reads `access_log_daily_project` instead of `access_log`. On a 100M-row-per-day fleet the pre-aggregated table holds ~3000 rows per month and answers a six-month rollup in single-digit milliseconds.

## Ingestion

Vector and Fluent Bit both speak ClickHouse's `JSONEachRow` format. A minimal Vector config that reads the proxy's stdout (or a sink configured under `proxy.observability.log.sinks` once dispatch lands) into the table above:

```toml
[sources.sbproxy_stdout]
type = "stdin"

[transforms.parse]
type = "remap"
inputs = ["sbproxy_stdout"]
source = '. = parse_json!(.message)'

[sinks.clickhouse]
type     = "clickhouse"
inputs   = ["parse"]
endpoint = "http://clickhouse:8123"
database = "sbproxy"
table    = "access_log"
encoding.codec = "json"
```

For multi-tenant fleets where each tenant operates its own ClickHouse, the sink declares its own endpoint; the proxy's per-tenant sink config (planned alongside the credentials epic) routes each tenant's lines to the tenant's collector without the operator running a fan-out service.

## Related reading

* `docs/observability.md` for the proxy-side log schema, redaction layers, and reversible PII semantics.
* `docs/access-log.md` for the per-field reference and capture caps.
* `docs/ai-gateway.md` for the AI virtual key shape that populates `project`, `user`, `metadata`, and the per-credential token attribution.
