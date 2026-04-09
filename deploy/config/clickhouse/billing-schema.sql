-- ClickHouse billing metrics schema
-- Stores aggregated usage metrics for billing and cost analysis

CREATE DATABASE IF NOT EXISTS proxy_billing;

USE proxy_billing;

-- Main billing metrics table
-- Stores hourly aggregated usage metrics per workspace and origin
CREATE TABLE IF NOT EXISTS metrics
(
    -- Time dimension
    timestamp DateTime64(3) DEFAULT now(),
    period DateTime DEFAULT toStartOfHour(timestamp),

    -- Dimensions
    workspace_id String,
    origin_id String,
    origin_hostname Nullable(String),
    provider_name Nullable(String),  -- for AI provider-specific metrics
    status String DEFAULT '200',     -- HTTP status or 'error'

    -- Request metrics
    request_count UInt64 DEFAULT 0,
    error_count UInt64 DEFAULT 0,

    -- Byte metrics
    bytes_in UInt64 DEFAULT 0,        -- client to proxy
    bytes_out UInt64 DEFAULT 0,       -- proxy to client
    bytes_backend UInt64 DEFAULT 0,   -- proxy to backend (charged cost)
    bytes_from_cache UInt64 DEFAULT 0, -- from cache (no cost)

    -- AI metrics
    tokens_used UInt64 DEFAULT 0,     -- for AI provider usage

    -- Performance metrics
    latency_seconds Float32 DEFAULT 0 -- average latency
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(period)
ORDER BY (period, workspace_id, origin_id, provider_name, status)
TTL period + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Daily aggregation view for cost calculations
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(period)
ORDER BY (period, workspace_id, origin_id)
SETTINGS allow_nullable_key = 1
AS SELECT
    toStartOfDay(period) as period,
    workspace_id,
    origin_id,
    origin_hostname,
    provider_name,
    sum(request_count) as request_count,
    sum(error_count) as error_count,
    sum(bytes_in) as bytes_in,
    sum(bytes_out) as bytes_out,
    sum(bytes_backend) as bytes_backend,
    sum(bytes_from_cache) as bytes_from_cache,
    sum(tokens_used) as tokens_used,
    avg(latency_seconds) as latency_seconds
FROM metrics
GROUP BY period, workspace_id, origin_id, origin_hostname, provider_name;

-- View: Cost summary by workspace (last 30 days)
CREATE VIEW IF NOT EXISTS workspace_cost_30d AS
SELECT
    workspace_id,
    sum(bytes_backend) as total_bytes_backend,
    sum(bytes_from_cache) as total_bytes_from_cache,
    sum(request_count) as total_requests,
    sum(tokens_used) as total_tokens,
    countIf(request_count > 0) as days_active,
    count() as metric_records
FROM metrics_daily
WHERE period >= now() - INTERVAL 30 DAY
GROUP BY workspace_id
ORDER BY total_bytes_backend DESC;

-- View: Origin performance (last 24 hours)
CREATE VIEW IF NOT EXISTS origin_performance_24h AS
SELECT
    workspace_id,
    origin_id,
    sum(request_count) as request_count,
    countIf(status >= '400') as error_count,
    sum(bytes_in) as bytes_in,
    sum(bytes_out) as bytes_out,
    sum(bytes_backend) as bytes_backend,
    avg(latency_seconds) as avg_latency_ms,
    quantile(0.95)(latency_seconds) as p95_latency_ms
FROM metrics
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY workspace_id, origin_id
ORDER BY request_count DESC;

-- View: AI token usage (last 7 days)
CREATE VIEW IF NOT EXISTS ai_token_usage_7d AS
SELECT
    workspace_id,
    provider_name,
    sum(tokens_used) as total_tokens,
    count() as query_count,
    avg(latency_seconds) as avg_latency_ms
FROM metrics
WHERE timestamp >= now() - INTERVAL 7 DAY
  AND tokens_used > 0
GROUP BY workspace_id, provider_name
ORDER BY total_tokens DESC;

-- View: Cache efficiency (last 24 hours)
CREATE VIEW IF NOT EXISTS cache_efficiency_24h AS
SELECT
    workspace_id,
    origin_id,
    sum(bytes_from_cache) as cached_bytes,
    sum(bytes_backend) as backend_bytes,
    sum(bytes_from_cache) + sum(bytes_backend) as total_bytes,
    round(100.0 * sum(bytes_from_cache) / (sum(bytes_from_cache) + sum(bytes_backend)), 2) as cache_hit_percent
FROM metrics
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND bytes_from_cache + bytes_backend > 0
GROUP BY workspace_id, origin_id
ORDER BY cache_hit_percent DESC;

-- View: Request status distribution (last 24 hours)
CREATE VIEW IF NOT EXISTS status_distribution_24h AS
SELECT
    workspace_id,
    status,
    count() as status_count,
    round(100.0 * count() / sum(count()) OVER (PARTITION BY workspace_id), 2) as percent
FROM metrics
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY workspace_id, status
ORDER BY workspace_id, status_count DESC;
