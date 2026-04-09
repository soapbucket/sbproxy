-- AI Memory table for structured AI conversation storage
-- Captures parsed request/response pairs from AI proxy with session grouping

CREATE TABLE IF NOT EXISTS proxy_logs.ai_memory
(
    -- Identity
    id                  UUID DEFAULT generateUUIDv4(),
    request_id          String DEFAULT '',
    timestamp           DateTime64(3),
    workspace_id        String,
    origin_id           String DEFAULT '',
    hostname            LowCardinality(String) DEFAULT '',

    -- Session grouping
    session_id          String,
    session_sequence    UInt32 DEFAULT 0,

    -- User attribution (from auth framework)
    auth_type           LowCardinality(String) DEFAULT '',
    auth_identifier     String DEFAULT '',
    auth_key_hash       String DEFAULT '',

    -- Agent identity
    agent               String DEFAULT '',
    tags                Map(String, String) DEFAULT map(),

    -- Request metadata
    provider            LowCardinality(String),
    model               LowCardinality(String),
    is_streaming        Bool DEFAULT false,
    stop_reason         LowCardinality(String) DEFAULT '',

    -- Token usage
    input_tokens        UInt32 DEFAULT 0,
    output_tokens       UInt32 DEFAULT 0,
    total_tokens        UInt32 DEFAULT 0,
    cached_tokens       UInt32 DEFAULT 0,
    cost_usd            Float64 DEFAULT 0,

    -- Timing
    latency_ms          UInt32 DEFAULT 0,
    ttft_ms             UInt32 DEFAULT 0,

    -- Conversation content (JSON strings)
    system_prompt       String DEFAULT '',
    input_messages      String DEFAULT '',
    output_content      String DEFAULT '',

    -- Tool tracking
    tools_available     Array(String) DEFAULT [],
    tools_called        Array(String) DEFAULT [],
    has_tool_use        Bool DEFAULT false,

    -- Classification
    error               String DEFAULT '',
    input_message_count UInt16 DEFAULT 0,
    capture_scope       LowCardinality(String) DEFAULT 'full',

    -- Compliance
    prompt_hash         String DEFAULT '',
    response_hash       String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (workspace_id, session_id, timestamp, id)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- Indexes for common queries
ALTER TABLE proxy_logs.ai_memory ADD INDEX IF NOT EXISTS idx_auth      auth_identifier  TYPE bloom_filter    GRANULARITY 4;
ALTER TABLE proxy_logs.ai_memory ADD INDEX IF NOT EXISTS idx_model     model            TYPE set(100)        GRANULARITY 4;
ALTER TABLE proxy_logs.ai_memory ADD INDEX IF NOT EXISTS idx_agent     agent            TYPE bloom_filter    GRANULARITY 4;
ALTER TABLE proxy_logs.ai_memory ADD INDEX IF NOT EXISTS idx_tools     tools_called     TYPE bloom_filter    GRANULARITY 4;
ALTER TABLE proxy_logs.ai_memory ADD INDEX IF NOT EXISTS idx_sys       system_prompt    TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4;
ALTER TABLE proxy_logs.ai_memory ADD INDEX IF NOT EXISTS idx_output    output_content   TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4;
ALTER TABLE proxy_logs.ai_memory ADD INDEX IF NOT EXISTS idx_input     input_messages   TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4;
ALTER TABLE proxy_logs.ai_memory ADD INDEX IF NOT EXISTS idx_req       request_id       TYPE bloom_filter    GRANULARITY 4;

-- Session-level aggregates (auto-maintained)
CREATE MATERIALIZED VIEW IF NOT EXISTS proxy_logs.ai_memory_sessions_mv
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(min_ts)
ORDER BY (workspace_id, session_id)
AS SELECT
    workspace_id,
    session_id,
    min(timestamp)                        AS min_ts,
    max(timestamp)                        AS max_ts,
    count()                               AS entry_count,
    sum(input_tokens)                     AS total_input_tokens,
    sum(output_tokens)                    AS total_output_tokens,
    sum(cost_usd)                         AS total_cost_usd,
    groupUniqArrayState(model)            AS models_used,
    groupUniqArrayState(tools_called)     AS tools_called_agg,
    anyState(auth_type)                   AS auth_type,
    anyState(auth_identifier)             AS auth_identifier,
    anyState(agent)                       AS agent,
    anyState(hostname)                    AS hostname,
    anyState(origin_id)                   AS origin_id
FROM proxy_logs.ai_memory
GROUP BY workspace_id, session_id;

-- Hourly cost rollup per user
CREATE MATERIALIZED VIEW IF NOT EXISTS proxy_logs.ai_memory_cost_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (workspace_id, auth_identifier, model, hour)
AS SELECT
    workspace_id,
    auth_identifier,
    model,
    toStartOfHour(timestamp)    AS hour,
    count()                     AS request_count,
    sum(input_tokens)           AS input_tokens,
    sum(output_tokens)          AS output_tokens,
    sum(cost_usd)               AS cost_usd
FROM proxy_logs.ai_memory
GROUP BY workspace_id, auth_identifier, model, hour;

-- Tool usage patterns
CREATE MATERIALIZED VIEW IF NOT EXISTS proxy_logs.ai_memory_tools_daily_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (workspace_id, tool_name, day)
AS SELECT
    workspace_id,
    arrayJoin(tools_called)     AS tool_name,
    toDate(timestamp)           AS day,
    count()                     AS call_count
FROM proxy_logs.ai_memory
WHERE has_tool_use = true
GROUP BY workspace_id, tool_name, day;
