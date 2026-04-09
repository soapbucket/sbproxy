-- AI Gateway columns for request_logs table (ClickHouse)
-- Phase 6: LLM Observability

ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_provider String DEFAULT '' AFTER response_size;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_model String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_input_tokens UInt32 DEFAULT 0;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_output_tokens UInt32 DEFAULT 0;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_total_tokens UInt32 DEFAULT 0;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_cost_usd Float64 DEFAULT 0;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_ttft_ms UInt32 DEFAULT 0;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_itl_avg_ms UInt32 DEFAULT 0;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_cached Bool DEFAULT false;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_cache_type String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_guardrails_triggered Array(String) DEFAULT [];
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_routing_strategy String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_fallback_used Bool DEFAULT false;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_budget_scope String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_budget_scope_value String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_tags Map(String, String) DEFAULT map();

-- Phase 2.5: Agent identity and observability columns
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_agent String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_session_id String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_cached_tokens UInt32 DEFAULT 0;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_budget_utilization Float64 DEFAULT 0;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_model_downgraded Bool DEFAULT false;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_original_model String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_api_key_name String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_streaming Bool DEFAULT false;

-- Phase 2.7: Compliance audit columns
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_api_key_hash String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_prompt_hash String DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS ai_response_hash String DEFAULT '';

-- Environment and tags for reporting and filtering
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS environment LowCardinality(String) DEFAULT '';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS tags Array(String) DEFAULT [];
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS proxy_version LowCardinality(String) DEFAULT '';
