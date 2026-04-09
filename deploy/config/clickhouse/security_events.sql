-- Security and AI policy events table
-- Stores guardrail violations, PII detections, prompt injections, budget exceeded, WAF blocks, etc.

USE proxy_logs;

CREATE TABLE IF NOT EXISTS security_events
(
    timestamp DateTime64(3) DEFAULT now(),

    -- Event classification
    event_type LowCardinality(String),           -- ai_guardrail_triggered, ai_pii_detected, ai_prompt_injection, ai_budget_exceeded, threat_detected, rate_limit_exceeded, etc.
    severity LowCardinality(String),             -- low, medium, high, critical
    action LowCardinality(String),               -- authenticate, guardrail_check, pii_scan, injection_check, budget_check, waf_check, rate_limit_check, etc.
    result LowCardinality(String),               -- blocked, flagged, detected, redacted, exceeded, success, failure

    -- Request context
    request_id String DEFAULT '',
    request_method LowCardinality(String) DEFAULT '',
    request_path String DEFAULT '',
    request_host String DEFAULT '',
    request_ip String DEFAULT '',

    -- Origin context
    config_id String DEFAULT '',
    workspace_id String DEFAULT '',

    -- Tracing
    trace_id Nullable(String),
    span_id Nullable(String),

    -- AI-specific fields
    guardrail_type LowCardinality(Nullable(String)),   -- pii_detection, prompt_injection, toxicity, etc.
    guardrail_action LowCardinality(Nullable(String)), -- block, transform, flag
    phase LowCardinality(Nullable(String)),            -- input, output
    model Nullable(String),
    detail String DEFAULT '',

    -- PII-specific fields
    pii_types Nullable(String),                        -- comma-separated: ssn,credit_card,email

    -- Budget-specific fields
    budget_scope LowCardinality(Nullable(String)),     -- workspace, api_key, user, model
    budget_scope_value Nullable(String),
    budget_period LowCardinality(Nullable(String)),    -- hourly, daily, monthly
    budget_action_taken LowCardinality(Nullable(String)), -- block, log, downgrade
    budget_current_usd Nullable(Float64),
    budget_limit_usd Nullable(Float64),

    -- Auth-specific fields
    auth_type LowCardinality(Nullable(String)),        -- jwt, api_key, basic, bearer, oauth
    username Nullable(String),

    -- WAF-specific fields
    waf_rule_id Nullable(String),
    waf_rule_name Nullable(String),
    threat_type Nullable(String),

    -- Rate limit fields
    rate_limit_type Nullable(String),
    rate_limit_value Nullable(Int32),
    rate_limit_window Nullable(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, event_type, workspace_id, config_id)
TTL timestamp + INTERVAL 365 DAY
SETTINGS
    index_granularity = 8192,
    allow_nullable_key = 1;

-- Materialized view: security event counts per minute
CREATE MATERIALIZED VIEW IF NOT EXISTS security_events_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, workspace_id, event_type, severity, result)
SETTINGS allow_nullable_key = 1
AS SELECT
    toStartOfMinute(timestamp) as timestamp,
    workspace_id,
    event_type,
    severity,
    result,
    count() as event_count
FROM security_events
GROUP BY timestamp, workspace_id, event_type, severity, result;

-- View: AI guardrail violations (last 24 hours)
CREATE VIEW IF NOT EXISTS ai_guardrail_violations_24h AS
SELECT
    timestamp,
    guardrail_type,
    guardrail_action,
    phase,
    model,
    detail,
    config_id,
    workspace_id,
    request_id,
    request_path,
    request_ip
FROM security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND event_type IN ('ai_guardrail_triggered', 'ai_pii_detected', 'ai_prompt_injection')
ORDER BY timestamp DESC;

-- View: budget violations (last 7 days)
CREATE VIEW IF NOT EXISTS ai_budget_violations_7d AS
SELECT
    timestamp,
    budget_scope,
    budget_scope_value,
    budget_period,
    budget_action_taken,
    budget_current_usd,
    budget_limit_usd,
    config_id,
    workspace_id
FROM security_events
WHERE timestamp >= now() - INTERVAL 7 DAY
  AND event_type = 'ai_budget_exceeded'
ORDER BY timestamp DESC;

-- View: authentication failures (last 24 hours)
CREATE VIEW IF NOT EXISTS auth_failures_24h AS
SELECT
    timestamp,
    auth_type,
    username,
    request_ip,
    detail,
    config_id,
    workspace_id
FROM security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND event_type = 'authentication_failure'
ORDER BY timestamp DESC;

-- View: top security events by type (last 24 hours)
CREATE VIEW IF NOT EXISTS security_events_summary_24h AS
SELECT
    event_type,
    severity,
    result,
    count() as event_count,
    uniq(request_ip) as unique_ips,
    uniq(workspace_id) as unique_workspaces
FROM security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY event_type, severity, result
ORDER BY event_count DESC;
