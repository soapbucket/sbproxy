-- ClickHouse database initialization script
-- Creates databases for proxy logs and billing metrics

CREATE DATABASE IF NOT EXISTS proxy_logs;
CREATE DATABASE IF NOT EXISTS proxy_billing;

USE proxy_logs;

-- Request logs table
-- Stores HTTP request/response logs with full context
CREATE TABLE IF NOT EXISTS request_logs
(
    timestamp DateTime64(3) DEFAULT now(),
    level LowCardinality(String),
    message String,
    caller String,

    -- Request fields
    request_id String DEFAULT '',
    request_method LowCardinality(String) DEFAULT '',
    request_path String DEFAULT '',
    request_host String DEFAULT '',
    request_remote_addr String DEFAULT '',
    request_user_agent String DEFAULT '',
    request_content_length Nullable(Int64),
    request_content_type Nullable(String),
    request_referer Nullable(String),
    request_scheme LowCardinality(String) DEFAULT '',
    request_url Nullable(String),
    request_query Nullable(String),
    request_protocol LowCardinality(String) DEFAULT '',
    request_origin Nullable(String),
    request_accept Nullable(String),
    request_accept_encoding Nullable(String),
    request_accept_language Nullable(String),
    request_x_forwarded_for Nullable(String),
    request_x_forwarded_proto Nullable(String),
    request_x_real_ip Nullable(String),
    request_cookie_count Nullable(Int32),
    request_has_authorization Bool DEFAULT false,
    request_depth Nullable(Int32),
    request_timestamp Nullable(String),
    request_body Nullable(String),
    request_headers_full Nullable(String),

    -- Response fields
    response_status_code Nullable(Int16),
    response_bytes Nullable(Int64),
    response_duration_ms Nullable(Float64),
    response_content_type Nullable(String),
    response_content_encoding Nullable(String),
    response_cache_control Nullable(String),
    response_timestamp Nullable(String),
    response_body Nullable(String),
    response_headers_full Nullable(String),
    response_cache_hit Bool DEFAULT false,
    response_cache_key Nullable(String),
    signature_cache_hit Bool DEFAULT false,
    signature_cache_key Nullable(String),

    -- Origin fields
    origin_id String DEFAULT '',
    origin_hostname Nullable(String),
    origin_type LowCardinality(Nullable(String)),
    workspace_id String DEFAULT '',
    config_id String DEFAULT '',
    config_hostname Nullable(String),
    config_version Nullable(String),
    version String DEFAULT '',
    environment Nullable(String),
    parent_config_id Nullable(String),
    parent_config_hostname Nullable(String),
    tags Array(String) DEFAULT [],

    -- User fields
    user_id Nullable(String),
    user_email Nullable(String),
    user_roles Array(String),
    auth_data_present Bool DEFAULT false,

    -- Session fields
    session_id Nullable(String),

    -- Tracing fields
    trace_id Nullable(String),
    span_id Nullable(String),
    parent_span_id Nullable(String),

    -- Program info
    app_version Nullable(String),
    build_hash Nullable(String),
    app_env LowCardinality(String),
    proxy_version Nullable(String),

    -- Error fields
    error Nullable(String),
    error_type Nullable(String),
    error_code Nullable(String),

    -- Location fields
    country Nullable(String),
    country_code LowCardinality(Nullable(String)),
    asn Nullable(String),
    as_name Nullable(String),
    source_ip Nullable(String),

    -- Fingerprint fields
    fingerprint Nullable(String),
    fingerprint_composite Nullable(String),
    fingerprint_cookie_count Nullable(Int32),
    fingerprint_version Nullable(String),

    -- Original request (pre-modification)
    original_request_method Nullable(String),
    original_request_path Nullable(String),
    original_request_body_size Nullable(Int32),

    -- Body capture
    body_captured Bool DEFAULT false,
    body_truncated Bool DEFAULT false,

    -- AI proxy fields
    ai_provider LowCardinality(Nullable(String)),
    ai_model LowCardinality(Nullable(String)),
    ai_input_tokens Nullable(Int32),
    ai_output_tokens Nullable(Int32),
    ai_total_tokens Nullable(Int32),
    ai_cached_tokens Nullable(Int32),
    ai_cost_usd Nullable(Float64),
    ai_routing_strategy LowCardinality(Nullable(String)),
    ai_streaming Bool DEFAULT false,
    ai_agent Nullable(String),
    ai_session_id Nullable(String),
    ai_api_key_name Nullable(String),
    ai_api_key_hash Nullable(String),
    ai_cached Bool DEFAULT false,
    ai_cache_type LowCardinality(Nullable(String)),
    ai_model_downgraded Bool DEFAULT false,
    ai_original_model Nullable(String),
    ai_prompt_id Nullable(String),
    ai_prompt_environment Nullable(String),
    ai_prompt_version Nullable(Int32),
    ai_budget_scope Nullable(String),
    ai_budget_scope_value Nullable(String),
    ai_budget_utilization Nullable(Float64),
    ai_prompt_hash Nullable(String),
    ai_response_hash Nullable(String),
    ai_tags Map(String, String) DEFAULT map(),
    ai_streaming_guardrail_mode LowCardinality(Nullable(String)),
    ai_provider_exclusions Array(String) DEFAULT [],

    -- Raw JSON for full log context (optional, for advanced queries)
    raw_log String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, request_id, workspace_id, origin_id)
TTL timestamp + INTERVAL 90 DAY
SETTINGS
    index_granularity = 8192,
    allow_nullable_key = 1;

-- Materialized view for aggregated statistics (optional)
CREATE MATERIALIZED VIEW IF NOT EXISTS request_logs_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, workspace_id, origin_id, response_status_code)
SETTINGS allow_nullable_key = 1
AS SELECT
    toStartOfMinute(timestamp) as timestamp,
    workspace_id,
    origin_id,
    response_status_code,
    count() as request_count,
    sum(response_bytes) as total_bytes,
    avg(response_duration_ms) as avg_duration_ms
FROM request_logs
GROUP BY timestamp, workspace_id, origin_id, response_status_code;

-- Views for common query patterns

-- View: Recent requests (last hour)
CREATE VIEW IF NOT EXISTS recent_requests AS
SELECT
    timestamp,
    request_method,
    request_path,
    request_host,
    response_status_code,
    response_duration_ms,
    origin_id,
    request_remote_addr
FROM request_logs
WHERE timestamp >= now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC;

-- View: Requests by origin (last 24 hours)
CREATE VIEW IF NOT EXISTS requests_by_origin_24h AS
SELECT
    workspace_id,
    origin_id,
    count() as request_count,
    countIf(response_status_code >= 400) as error_count,
    avg(response_duration_ms) as avg_duration_ms,
    quantile(0.95)(response_duration_ms) as p95_duration_ms,
    sum(response_bytes) as total_bytes
FROM request_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY workspace_id, origin_id
ORDER BY request_count DESC;

-- View: Requests by tenant (last 24 hours)
CREATE VIEW IF NOT EXISTS requests_by_workspace_24h AS
SELECT
    workspace_id,
    count() as request_count,
    countIf(response_status_code >= 400) as error_count,
    avg(response_duration_ms) as avg_duration_ms,
    quantile(0.95)(response_duration_ms) as p95_duration_ms,
    sum(response_bytes) as total_bytes,
    uniq(origin_id) as unique_origins
FROM request_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY workspace_id
ORDER BY request_count DESC;

-- View: Error requests (last 24 hours)
CREATE VIEW IF NOT EXISTS error_requests_24h AS
SELECT
    timestamp,
    request_method,
    request_path,
    request_host,
    response_status_code,
    error,
    error_type,
    origin_id,
    request_remote_addr,
    response_duration_ms
FROM request_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND response_status_code >= 400
ORDER BY timestamp DESC;

-- View: Slow requests (P95+ latency, last 24 hours)
CREATE VIEW IF NOT EXISTS slow_requests_24h AS
SELECT
    timestamp,
    request_method,
    request_path,
    request_host,
    response_status_code,
    response_duration_ms,
    origin_id,
    request_remote_addr
FROM request_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND response_duration_ms > (
    SELECT quantile(0.95)(response_duration_ms)
    FROM request_logs
    WHERE timestamp >= now() - INTERVAL 24 HOUR
  )
ORDER BY response_duration_ms DESC;

-- View: Requests by status code (last 24 hours)
CREATE VIEW IF NOT EXISTS requests_by_status_24h AS
SELECT
    response_status_code,
    count() as request_count,
    avg(response_duration_ms) as avg_duration_ms,
    sum(response_bytes) as total_bytes
FROM request_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND response_status_code IS NOT NULL
GROUP BY response_status_code
ORDER BY response_status_code;

-- View: Top paths by request count (last 24 hours)
CREATE VIEW IF NOT EXISTS top_paths_24h AS
SELECT
    request_path,
    request_method,
    count() as request_count,
    avg(response_duration_ms) as avg_duration_ms,
    countIf(response_status_code >= 400) as error_count
FROM request_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY request_path, request_method
ORDER BY request_count DESC
LIMIT 100;

-- Query timeout and resource limit settings
-- Prevents runaway queries from consuming all server resources
SET max_execution_time = 30 GLOBAL;
SET max_memory_usage = 2147483648 GLOBAL;
SET max_rows_to_read = 100000000 GLOBAL;
SET max_bytes_to_read = 10737418240 GLOBAL;
SET max_result_rows = 50000000 GLOBAL;
SET max_result_bytes = 1073741824 GLOBAL;
SET receive_timeout = 600 GLOBAL;
SET send_timeout = 600 GLOBAL;
SET connect_timeout = 10 GLOBAL;
SET group_by_two_level_threshold = 100000 GLOBAL;
SET max_bytes_before_external_sort = 1073741824 GLOBAL;
