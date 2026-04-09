-- Body capture columns for request_logs table
-- Enables ClickHouse-based HAR capture (replacing Redis)

ALTER TABLE proxy_logs.request_logs ADD COLUMN IF NOT EXISTS request_body String DEFAULT '';
ALTER TABLE proxy_logs.request_logs ADD COLUMN IF NOT EXISTS response_body String DEFAULT '';
ALTER TABLE proxy_logs.request_logs ADD COLUMN IF NOT EXISTS request_headers_full Map(String, String) DEFAULT map();
ALTER TABLE proxy_logs.request_logs ADD COLUMN IF NOT EXISTS response_headers_full Map(String, String) DEFAULT map();
ALTER TABLE proxy_logs.request_logs ADD COLUMN IF NOT EXISTS body_captured Bool DEFAULT false;
ALTER TABLE proxy_logs.request_logs ADD COLUMN IF NOT EXISTS body_truncated Bool DEFAULT false;

-- Token bloom filter indexes on bodies for keyword search
ALTER TABLE proxy_logs.request_logs ADD INDEX IF NOT EXISTS idx_request_body
    request_body TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4;
ALTER TABLE proxy_logs.request_logs ADD INDEX IF NOT EXISTS idx_response_body
    response_body TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4;
