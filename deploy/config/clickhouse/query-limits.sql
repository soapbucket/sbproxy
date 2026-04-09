-- Query timeout and resource limit settings for ClickHouse
-- Prevents runaway queries from consuming all server resources
-- These settings protect against accidental or malicious resource exhaustion

-- Set global defaults for query execution
-- These can be overridden per-query if needed

-- Maximum execution time: 30 seconds (Soft limit - query warning/info logging)
-- Note: Query will continue to completion but will log a warning
SET max_execution_time = 30 GLOBAL;

-- Maximum memory usage per query: 2 GB
-- Query will be killed if it exceeds this amount
SET max_memory_usage = 2147483648 GLOBAL;  -- 2 * 1024^3

-- Maximum rows to read from the table
-- Prevents queries from scanning massive datasets accidentally
SET max_rows_to_read = 100000000 GLOBAL;  -- 100 million rows

-- Maximum bytes to read from the table
-- Second line of defense against scanning too much data
SET max_bytes_to_read = 10737418240 GLOBAL;  -- 10 * 1024^3

-- Result size limit: 50 million rows
-- Prevents returning massive result sets that could crash clients
SET max_result_rows = 50000000 GLOBAL;

-- Result size in bytes limit: 1 GB
-- Prevents returning gigabytes of data to clients
SET max_result_bytes = 1073741824 GLOBAL;

-- Read timeout: 600 seconds (10 minutes)
-- Individual network read operations must complete within this time
SET receive_timeout = 600 GLOBAL;

-- Write timeout: 600 seconds (10 minutes)
SET send_timeout = 600 GLOBAL;

-- Connection timeout: 10 seconds
SET connect_timeout = 10 GLOBAL;

-- Distributed query timeout: 300 seconds
-- For distributed queries across multiple replicas
SET distributed_product_mode = 'deny' GLOBAL;

-- Limit for GROUP BY cardinality
-- Prevents GROUP BY on extremely high-cardinality columns
SET group_by_two_level_threshold = 100000 GLOBAL;

-- Limit for ORDER BY size
-- Prevents sorting massive datasets
SET max_bytes_before_external_sort = 1073741824 GLOBAL;

-- Enable these settings for monitoring:
-- - log_queries: Log all queries (optional, may impact performance)
-- - log_queries_min_type: Only log queries of certain types
-- - log_queries_min_query_duration_ms: Only log slow queries

-- Settings specifically for analytics/dashboards to prevent data warehouse scans:
-- For backend dashboard queries:
SET session_name = 'dashboard' GLOBAL;

-- For API queries returning to users:
SET session_name = 'api' GLOBAL;

-- Note: These global defaults apply to all queries unless overridden per-connection
-- Backend code can override these by sending:
-- curl -X POST "http://clickhouse:8123/" \
--   --data-urlencode "query=SELECT ..." \
--   -d "max_execution_time=60" \
--   -d "max_memory_usage=4294967296"  # 4GB if needed for large query
