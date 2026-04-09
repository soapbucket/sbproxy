-- AI Gateway materialized views (ClickHouse)
-- Phase 6: Hourly cost rollup by provider/model

CREATE MATERIALIZED VIEW IF NOT EXISTS ai_cost_hourly_mv
ENGINE = SummingMergeTree()
ORDER BY (workspace_id, provider, model, hour)
AS SELECT
    workspace_id,
    ai_provider AS provider,
    ai_model AS model,
    toStartOfHour(timestamp) AS hour,
    sum(ai_cost_usd) AS total_cost,
    sum(ai_input_tokens) AS total_input_tokens,
    sum(ai_output_tokens) AS total_output_tokens,
    count() AS request_count
FROM request_logs
WHERE ai_provider != ''
GROUP BY workspace_id, provider, model, hour;

-- Phase 2.5: Daily cost rollup by agent
CREATE MATERIALIZED VIEW IF NOT EXISTS ai_cost_by_agent_daily_mv
ENGINE = SummingMergeTree()
ORDER BY (workspace_id, agent, day)
AS SELECT
    workspace_id,
    ai_agent AS agent,
    toStartOfDay(timestamp) AS day,
    sum(ai_cost_usd) AS total_cost,
    sum(ai_input_tokens) AS total_input_tokens,
    sum(ai_output_tokens) AS total_output_tokens,
    sum(ai_total_tokens) AS total_tokens,
    count() AS request_count
FROM request_logs
WHERE ai_provider != '' AND ai_agent != ''
GROUP BY workspace_id, agent, day;

-- Phase 2.5: Daily guardrail trigger counts
CREATE MATERIALIZED VIEW IF NOT EXISTS ai_guardrails_daily_mv
ENGINE = SummingMergeTree()
ORDER BY (workspace_id, guardrail, day)
AS SELECT
    workspace_id,
    arrayJoin(ai_guardrails_triggered) AS guardrail,
    toStartOfDay(timestamp) AS day,
    count() AS trigger_count
FROM request_logs
WHERE length(ai_guardrails_triggered) > 0
GROUP BY workspace_id, guardrail, day;

-- Phase 2.5: Hourly cost rollup by model (used for model comparison)
CREATE MATERIALIZED VIEW IF NOT EXISTS ai_cost_by_model_hourly_mv
ENGINE = SummingMergeTree()
ORDER BY (workspace_id, model, hour)
AS SELECT
    workspace_id,
    ai_model AS model,
    toStartOfHour(timestamp) AS hour,
    sum(ai_cost_usd) AS total_cost,
    sum(ai_input_tokens) AS total_input_tokens,
    sum(ai_output_tokens) AS total_output_tokens,
    count() AS request_count,
    countIf(ai_cached) AS cache_hits,
    countIf(ai_model_downgraded) AS downgrades
FROM request_logs
WHERE ai_provider != ''
GROUP BY workspace_id, model, hour;
