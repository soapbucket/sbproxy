# E2E Testing Environment

Complete end-to-end testing environment for the SoapBucket Proxy with full logging stack, monitoring, and test fixtures.

## Quick Start

```bash
cd /Users/rick/projects/proxy/test
bash run_e2e_tests.sh
```

This will:
- Start all services (Proxy, PostgreSQL, Redis, ClickHouse, ELK Stack, Prometheus, Grafana)
- Wait for services to be healthy
- Load test fixtures into database
- Run smoke tests
- Display service status and endpoints

## Service URLs & Access

### Core Services

| Service | URL | Default Credentials | Purpose |
|---------|-----|---------------------|---------|
| **Proxy HTTP** | http://localhost:8080 | - | Main proxy application |
| **Proxy HTTPS** | https://localhost:8443 | - | HTTPS endpoint (HTTP/2, HTTP/3) |
| **Proxy Metrics** | http://localhost:8888/metrics | - | Prometheus metrics endpoint |
| **E2E Test Server** | http://localhost:8090 | - | Backend test server |

### Database Services

| Service | URL | Default Credentials | Purpose |
|---------|-----|---------------------|---------|
| **PostgreSQL** | localhost:5433 | `proxy` / `proxy` | Origin configuration storage |
| **Redis** | localhost:6380 | - | L1/L2 cache |

### Logging Stack

| Service | URL | Default Credentials | Purpose |
|---------|-----|---------------------|---------|
| **ClickHouse** | http://localhost:8123 | `default` / (empty) | Request log analytics |
| **Elasticsearch** | http://localhost:9200 | - | Application/security log search |
| **Kibana** | http://localhost:5601 | - | Log visualization UI |

### Monitoring Stack

| Service | URL | Default Credentials | Purpose |
|---------|-----|---------------------|---------|
| **Prometheus** | http://localhost:9090 | - | Metrics collection |
| **Grafana** | http://localhost:3000 | `admin` / `admin` | Metrics visualization |

## Initialized Components & Data Access

The E2E test environment automatically initializes dashboards, schemas, and index patterns. Here's how to access and query each component:

### Grafana Dashboards

**Access:** http://localhost:3000 (admin/admin)

**Auto-loaded Dashboards:**
- **SoapBucket Dashboards** folder (auto-provisioned from `conf/grafana/dashboards/`):
  - System Overview
  - ClickHouse Request Logs
  - Per-Origin Performance
  - Security Metrics
  - Infrastructure Metrics

**Direct Dashboard URLs:**
- Browse all dashboards: http://localhost:3000/dashboards
- Explore metrics: http://localhost:3000/explore

**Example PromQL Queries (use in Grafana Explore or dashboard panels):**

```promql
# Request rate per second
rate(http_req_total[5m])

# Error rate
rate(http_server_errors_total[5m])

# Response time p95
histogram_quantile(0.95, rate(http_response_time_seconds_bucket[5m]))

# Response time p50 (median)
histogram_quantile(0.50, rate(http_response_time_seconds_bucket[5m]))

# Active connections
active_connections

# Success rate percentage
(rate(http_req_ok_total[5m]) / rate(http_req_total[5m])) * 100

# Config cache hit rate
rate(sb_config_cache_hits_total[5m]) / (rate(sb_config_cache_hits_total[5m]) + rate(sb_config_cache_misses_total[5m]))

# WAF blocks per second
rate(sb_waf_blocks_total[5m])

# Load balancer requests
rate(sb_lb_requests_total[5m])
```

**ClickHouse Data Source:**
- ClickHouse datasource is auto-configured
- Access ClickHouse data directly from Grafana: http://localhost:3000/explore?orgId=1&left=%5B%22now-1h%22,%22now%22,%22ClickHouse%22%5D

### Kibana Dashboards & Index Patterns

**Access:** http://localhost:5601

**Auto-loaded Components:**
- **Index Patterns** (auto-created by `kibana-init.sh`):
  - `proxy-application-*` (Time field: `@timestamp`)
  - `proxy-security-*` (Time field: `@timestamp`)
- **Dashboards** (auto-imported from `conf/kibana/dashboards.ndjson`):
  - SoapBucket Proxy - Application Logs
  - SoapBucket Proxy - Security Logs

**Direct URLs:**
- Discover logs: http://localhost:5601/app/discover
- View dashboards: http://localhost:5601/app/dashboards
- Index patterns: http://localhost:5601/app/management/kibana/indexPatterns

**Example Kibana Queries:**

```kibana
# Search all application logs
index: "proxy-application-*"

# Search for errors
index: "proxy-application-*" AND level: "error"

# Search by hostname
index: "proxy-application-*" AND hostname: "basic-proxy.test"

# Search security logs
index: "proxy-security-*"

# Search by time range (last hour)
index: "proxy-application-*" AND @timestamp:[now-1h TO now]

# Search with field filters
index: "proxy-application-*" AND message: "*timeout*"
```

**Kibana API Examples:**

```bash
# List all index patterns
curl http://localhost:5601/api/saved_objects/_find?type=index-pattern

# Search application logs
curl -X POST "http://localhost:5601/api/search" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "params": {
      "index": "proxy-application-*",
      "body": {
        "query": { "match_all": {} },
        "size": 10,
        "sort": [{ "@timestamp": { "order": "desc" }}]
      }
    }
  }'
```

### ClickHouse Database & Tables

**Access:** http://localhost:8123 (default user, no password)

**Auto-initialized Schema:**
- Database: `proxy_logs` (created from `sql/clickhouse-init.sql`)
- Table: `request_logs` (request/response logging)

**Direct Query Interface:**
- Web UI: http://localhost:8123/play
- CLI: `docker exec -it test-clickhouse clickhouse-client`

**Example ClickHouse Queries:**

```sql
-- View recent requests (last 100)
SELECT 
    timestamp,
    request_method,
    request_path,
    request_host,
    response_status_code,
    response_duration_ms,
    request_size_bytes,
    response_size_bytes
FROM proxy_logs.request_logs
ORDER BY timestamp DESC
LIMIT 100;

-- Request statistics (last hour)
SELECT 
    count() as total_requests,
    countIf(response_status_code >= 200 AND response_status_code < 300) as success_count,
    countIf(response_status_code >= 400) as error_count,
    avg(response_duration_ms) as avg_duration_ms,
    quantile(0.50)(response_duration_ms) as p50_duration_ms,
    quantile(0.95)(response_duration_ms) as p95_duration_ms,
    quantile(0.99)(response_duration_ms) as p99_duration_ms
FROM proxy_logs.request_logs
WHERE timestamp >= now() - INTERVAL 1 HOUR;

-- Requests by status code
SELECT 
    response_status_code,
    count() as count,
    avg(response_duration_ms) as avg_duration_ms
FROM proxy_logs.request_logs
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY response_status_code
ORDER BY count DESC;

-- Requests by hostname
SELECT 
    request_host,
    count() as requests,
    avg(response_duration_ms) as avg_duration_ms,
    quantile(0.95)(response_duration_ms) as p95_duration_ms
FROM proxy_logs.request_logs
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY request_host
ORDER BY requests DESC;

-- Top slowest requests
SELECT 
    timestamp,
    request_method,
    request_path,
    request_host,
    response_status_code,
    response_duration_ms
FROM proxy_logs.request_logs
WHERE timestamp >= now() - INTERVAL 1 HOUR
ORDER BY response_duration_ms DESC
LIMIT 20;

-- Request rate over time (5-minute buckets)
SELECT 
    toStartOfFiveMinute(timestamp) as time_bucket,
    count() as requests,
    avg(response_duration_ms) as avg_duration_ms
FROM proxy_logs.request_logs
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY time_bucket
ORDER BY time_bucket DESC;

-- Error rate by path
SELECT 
    request_path,
    count() as error_count,
    count() * 100.0 / (SELECT count() FROM proxy_logs.request_logs WHERE timestamp >= now() - INTERVAL 1 HOUR) as error_percentage
FROM proxy_logs.request_logs
WHERE timestamp >= now() - INTERVAL 1 HOUR
  AND response_status_code >= 400
GROUP BY request_path
ORDER BY error_count DESC
LIMIT 20;
```

**ClickHouse HTTP API Examples:**

```bash
# Query via HTTP
curl "http://localhost:8123/?query=SELECT%20count()%20FROM%20proxy_logs.request_logs"

# Query with parameters
curl -X POST "http://localhost:8123/" \
  -d "SELECT count() FROM proxy_logs.request_logs WHERE timestamp >= now() - INTERVAL 1 HOUR"

# Get query result as JSON
curl "http://localhost:8123/?query=SELECT%20*%20FROM%20proxy_logs.request_logs%20LIMIT%2010&format=JSON"
```

### Elasticsearch Indices & Templates

**Access:** http://localhost:9200

**Auto-initialized Components:**
- **Index Template:** `proxy-logs` (created by `elasticsearch-init.sh`)
- **Indices** (auto-created by Fluent Bit):
  - `proxy-application-YYYY.MM.DD` (application logs)
  - `proxy-security-YYYY.MM.DD` (security logs)

**Check Health:**
```bash
curl http://localhost:9200/_cluster/health?pretty
```

**Example Elasticsearch Queries:**

```bash
# List all proxy indices
curl "http://localhost:9200/_cat/indices/proxy-*?v"

# Get index template
curl "http://localhost:9200/_index_template/proxy-logs?pretty"

# Search application logs (last 10)
curl -X GET "http://localhost:9200/proxy-application-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": { "match_all": {} },
    "size": 10,
    "sort": [{ "@timestamp": { "order": "desc" }}]
  }'

# Search for errors
curl -X GET "http://localhost:9200/proxy-application-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "match": { "level": "error" }
    },
    "size": 20,
    "sort": [{ "@timestamp": { "order": "desc" }}]
  }'

# Search by hostname
curl -X GET "http://localhost:9200/proxy-application-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "term": { "hostname": "basic-proxy.test" }
    },
    "size": 10
  }'

# Search with time range
curl -X GET "http://localhost:9200/proxy-application-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "range": {
        "@timestamp": {
          "gte": "now-1h",
          "lte": "now"
        }
      }
    },
    "size": 10
  }'

# Aggregate by level
curl -X GET "http://localhost:9200/proxy-application-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "by_level": {
        "terms": { "field": "level" }
      }
    }
  }'

# Search security logs
curl -X GET "http://localhost:9200/proxy-security-*/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": { "match_all": {} },
    "size": 10,
    "sort": [{ "@timestamp": { "order": "desc" }}]
  }'
```

### Prometheus Metrics & Queries

**Access:** http://localhost:9090

**Auto-configured:**
- Prometheus scrapes proxy metrics from `test-proxy:8888/metrics`
- Configuration: `conf/prometheus.yml`

**Example Prometheus Queries:**

```promql
# Request rate (requests per second)
rate(http_req_total[5m])

# Request rate by status code
rate(http_req_total[5m]) by (status)

# Error rate
rate(http_server_errors_total[5m])

# Response time percentiles
histogram_quantile(0.95, rate(http_response_time_seconds_bucket[5m]))
histogram_quantile(0.50, rate(http_response_time_seconds_bucket[5m]))
histogram_quantile(0.99, rate(http_response_time_seconds_bucket[5m]))

# Active connections
active_connections

# Success rate
(rate(http_req_ok_total[5m]) / rate(http_req_total[5m])) * 100

# SoapBucket-specific metrics
rate(sb_config_cache_hits_total[5m])
rate(sb_config_cache_misses_total[5m])
rate(sb_waf_blocks_total[5m])
rate(sb_lb_requests_total[5m])

# List all available metrics
{__name__=~".+"}
```

**Prometheus API Examples:**

```bash
# Query instant value
curl "http://localhost:9090/api/v1/query?query=http_req_total"

# Query range (last hour)
curl "http://localhost:9090/api/v1/query_range?query=rate(http_req_total[5m])&start=$(date -u -d '1 hour ago' +%s)&end=$(date -u +%s)&step=15s"

# List all metrics
curl "http://localhost:9090/api/v1/label/__name__/values"

# Check targets
curl "http://localhost:9090/api/v1/targets"
```

## Service Details

### Proxy Application

**Endpoints:**
- HTTP: http://localhost:8080
- HTTPS: https://localhost:8443
- Metrics: http://localhost:8888/metrics

**Test with curl:**
```bash
# Basic request
curl -H "Host: basic-proxy.test" http://localhost:8080/

# Check metrics
curl http://localhost:8888/metrics | grep http_requests_total
```

### ClickHouse (Request Logs)

**Access:**
- Web UI: http://localhost:8123
- Native Protocol: localhost:9000
- Default Credentials: `default` / (empty)

**Auto-initialized:**
- Database: `proxy_logs`
- Table: `request_logs`

**Quick Access:**
```bash
# Interactive CLI
docker exec -it test-clickhouse clickhouse-client

# Query via HTTP
curl "http://localhost:8123/?query=SELECT%20count()%20FROM%20proxy_logs.request_logs"
```

**📖 See [Initialized Components & Data Access](#initialized-components--data-access) section above for comprehensive query examples.**

### Elasticsearch (Application/Security Logs)

**Access:**
- API: http://localhost:9200
- No authentication (development mode)

**Auto-initialized:**
- Index Template: `proxy-logs`
- Indices: `proxy-application-YYYY.MM.DD`, `proxy-security-YYYY.MM.DD`

**Quick Checks:**
```bash
# Health check
curl http://localhost:9200/_cluster/health?pretty

# List indices
curl http://localhost:9200/_cat/indices/proxy-*?v
```

**📖 See [Initialized Components & Data Access](#initialized-components--data-access) section above for comprehensive query examples.**

### Kibana (Log Visualization)

**Access:**
- Web UI: http://localhost:5601
- No authentication (development mode)

**Auto-initialized:**
- Index Patterns: `proxy-application-*`, `proxy-security-*`
- Dashboards: SoapBucket Proxy - Application Logs, SoapBucket Proxy - Security Logs

**Quick Access:**
- Discover: http://localhost:5601/app/discover
- Dashboards: http://localhost:5601/app/dashboards

**📖 See [Initialized Components & Data Access](#initialized-components--data-access) section above for comprehensive query examples.**

### Prometheus (Metrics)

**Access:**
- Web UI: http://localhost:9090
- No authentication

**Auto-configured:**
- Scrapes proxy metrics from `test-proxy:8888/metrics`
- Configuration: `conf/prometheus.yml`

**Important:** Standard HTTP metrics do NOT have the `sb_` prefix. Only SoapBucket-specific metrics use the `sb_` prefix.

**Metric Naming Convention:**
- **Standard HTTP metrics:** `http_req_total`, `http_req_ok_total`, `http_response_time_seconds`, `active_connections`
- **SoapBucket-specific metrics:** `sb_config_cache_hits_total`, `sb_lb_requests_total`, `sb_storage_operations_total`, etc.

**📖 See [Initialized Components & Data Access](#initialized-components--data-access) section above for comprehensive query examples.**

**Verify Metrics Are Being Scraped:**

1. **Check if Prometheus can reach the proxy:**
   ```bash
   # From inside Prometheus container
   docker exec test-prometheus wget -qO- http://test-proxy:8888/metrics | head -20
   
   # Or from host (if proxy metrics endpoint is accessible)
   curl http://localhost:8888/metrics | head -20
   ```

2. **Check Prometheus targets:**
   - Open http://localhost:9090/targets
   - Verify `proxy` target shows as "UP" (green)
   - If "DOWN", check network connectivity and proxy health

3. **Verify metrics are being collected:**
   ```promql
   # List all HTTP metrics (standard)
   {__name__=~"http_.*"}
   
   # List all SB-specific metrics
   {__name__=~"sb_.*"}
   
   # Count available metrics
   count({__name__=~"http_.*"}) + count({__name__=~"sb_.*"})
   ```

**Query Examples (Correct Metric Names):**

**Standard HTTP Metrics (no `sb_` prefix):**

```promql
# Total HTTP requests (counter)
http_req_total

# Request rate (requests per second)
rate(http_req_total[5m])

# Request rate by status code
rate(http_req_total[5m]) by (status)

# Successful requests (2xx)
rate(http_req_ok_total[5m])

# Client errors (4xx)
rate(http_client_errors_total[5m])

# Server errors (5xx)
rate(http_server_errors_total[5m])

# Error rate percentage
(rate(http_server_errors_total[5m]) / rate(http_req_total[5m])) * 100

# Response time (95th percentile)
histogram_quantile(0.95, rate(http_response_time_seconds_bucket[5m]))

# Response time (50th percentile / median)
histogram_quantile(0.50, rate(http_response_time_seconds_bucket[5m]))

# Response time (99th percentile)
histogram_quantile(0.99, rate(http_response_time_seconds_bucket[5m]))

# Average response time
rate(http_response_time_seconds_sum[5m]) / rate(http_response_time_seconds_count[5m])

# Active connections
active_connections

# Total requests in last hour
increase(http_req_total[1h])

# Requests per minute
rate(http_req_total[1m]) * 60
```

**SoapBucket-Specific Metrics (with `sb_` prefix):**

```promql
# Load balancer requests
rate(sb_lb_requests_total[5m]) by (origin_id, target_url)

# Load balancer errors
rate(sb_lb_request_errors_total[5m]) by (origin_id, error_type)

# Cache hit rate
rate(sb_cacher_hits_total[5m]) / (rate(sb_cacher_hits_total[5m]) + rate(sb_cacher_misses_total[5m]))

# Config cache efficiency
rate(sb_config_cache_hits_total[5m]) / (rate(sb_config_cache_hits_total[5m]) + rate(sb_config_cache_misses_total[5m]))

# Storage operations
rate(sb_storage_operations_total[5m]) by (operation)

# Storage errors
rate(sb_storage_operation_errors_total[5m])

# TLS handshake failures
rate(sb_tls_handshake_failures_total[5m])

# Authentication failures
rate(sb_auth_failures_total[5m])

# Rate limit violations
rate(sb_rate_limit_violations_total[5m])

# WAF blocks
rate(sb_waf_blocks_total[5m])
```

**Troubleshooting No Metrics:**

1. **Check proxy metrics endpoint:**
   ```bash
   curl http://localhost:8888/metrics | grep http_req_total
   ```
   Should return metric output. If empty, proxy may not be running or metrics not enabled.

2. **Check Prometheus can reach proxy:**
   ```bash
   docker exec test-prometheus wget -qO- http://test-proxy:8888/metrics | grep http_req_total
   ```

3. **Check Prometheus scrape configuration:**
   - Open http://localhost:9090/config
   - Verify `job_name: 'proxy'` has `targets: ['test-proxy:8888']`
   - Check `metrics_path: '/metrics'` is set

4. **Check Prometheus logs:**
   ```bash
   docker logs test-prometheus | grep -i error
   docker logs test-prometheus | grep -i proxy
   ```

5. **Reload Prometheus config (if needed):**
   ```bash
   curl -X POST http://localhost:9090/-/reload
   ```

6. **Verify proxy is generating metrics:**
   ```bash
   # Make some test requests to generate metrics
   curl -H "Host: basic-proxy.test" http://localhost:8080/
   
   # Wait a few seconds, then check metrics
   curl http://localhost:8888/metrics | grep http_req_total
   ```

### Grafana (Dashboards)

**Access:**
- Web UI: http://localhost:3000
- **Username:** `admin`
- **Password:** `admin`

**First Login:**
1. Open http://localhost:3000
2. Login with `admin` / `admin`
3. Change password (optional, can skip)
4. Dashboards are auto-provisioned in the **"Proxy"** folder

**Available Dashboards:**
- Proxy Overview - Request rate, error rate, latency, connections

**Note:** The default dashboard may use incorrect metric names. Use the queries below in Grafana's Explore or create custom panels.

**Grafana Query Examples:**

Create new panels in Grafana using these queries:

**Request Rate Panel:**
```promql
rate(http_req_total[5m])
```
- Visualization: Time series
- Unit: reqps (requests per second)
- Legend: `{{status}}` or `Total`

**Error Rate Panel:**
```promql
rate(http_server_errors_total[5m])
```
- Visualization: Time series
- Unit: reqps
- Legend: `Server Errors`

**Response Time (p95) Panel:**
```promql
histogram_quantile(0.95, rate(http_response_time_seconds_bucket[5m]))
```
- Visualization: Time series
- Unit: seconds (s) or milliseconds (ms)
- Legend: `p95 Latency`

**Response Time (p50) Panel:**
```promql
histogram_quantile(0.50, rate(http_response_time_seconds_bucket[5m]))
```
- Visualization: Time series
- Unit: seconds (s) or milliseconds (ms)
- Legend: `p50 Latency`

**Active Connections Panel:**
```promql
active_connections
```
- Visualization: Time series or Stat
- Unit: short
- Legend: `Active Connections`

**Total Requests Panel:**
```promql
http_req_total
```
- Visualization: Stat
- Unit: short
- Calculation: Total

**Success Rate Panel:**
```promql
(rate(http_req_ok_total[5m]) / rate(http_req_total[5m])) * 100
```
- Visualization: Time series or Stat
- Unit: percent (0-100)
- Legend: `Success Rate %`

**Troubleshooting Dashboards Not Updating:**

1. **Verify Prometheus datasource:**
   - Go to Configuration → Data Sources
   - Click on "Prometheus"
   - Test the connection (should show "Data source is working")
   - Verify URL is `http://prometheus:9090`

2. **Check if metrics exist in Prometheus:**
   - Go to Explore in Grafana
   - Select Prometheus datasource
   - Run query: `{__name__=~"http_.*"}` or `{__name__=~"sb_.*"}`
   - If no results, metrics aren't being scraped (see Prometheus troubleshooting above)

3. **Verify time range:**
   - Check dashboard time range (top right)
   - Set to "Last 15 minutes" or "Last 1 hour"
   - Metrics only appear for time ranges where data exists

4. **Check panel queries:**
   - Edit panel → Query tab
   - Verify HTTP metrics use no prefix (e.g., `http_req_total`)
   - Verify SB-specific metrics use `sb_` prefix (e.g., `sb_config_cache_hits_total`)
   - Test query in Prometheus UI first (http://localhost:9090)

5. **Refresh dashboard:**
   - Click refresh button (top right)
   - Or set auto-refresh to 5s or 10s

### PostgreSQL (Origin Storage)

**Access:**
- Host: `localhost`
- Port: `5433` (custom port to avoid conflicts)
- Database: `proxy`
- **Username:** `proxy`
- **Password:** `proxy`

**Connect:**
```bash
# Using Docker
docker exec -it test-postgres psql -U proxy -d proxy

# Using local psql client
psql -h localhost -p 5433 -U proxy -d proxy
```

**View Loaded Origins:**
```sql
SELECT key FROM config_storage ORDER BY key;
```

**Count Origins:**
```sql
SELECT COUNT(*) FROM config_storage;
```

### Redis (Cache)

**Access:**
- Host: `localhost`
- Port: `6380` (custom port to avoid conflicts)
- No password (development mode)

**Connect:**
```bash
# Using Docker
docker exec -it test-redis redis-cli

# Using local redis-cli
redis-cli -h localhost -p 6380
```

**Test:**
```bash
redis-cli -h localhost -p 6380 ping
# Should return: PONG
```

### E2E Test Server

**Access:**
- HTTP: http://localhost:8090
- HTTPS: https://localhost:9443
- WebSocket: ws://localhost:8091
- GraphQL: http://localhost:8092

**Test Endpoints:**
```bash
# Simple 200 response
curl http://localhost:8090/test/simple-200

# JSON response
curl http://localhost:8090/test/json-response

# Headers endpoint
curl http://localhost:8090/api/headers
```

## Testing Workflow

### 1. Start Environment

```bash
cd /Users/rick/projects/proxy/test
bash run_e2e_tests.sh
```

### 2. Configure /etc/hosts (for browser testing)

Add test hostnames to `/etc/hosts`:

```bash
sudo bash -c 'cat >> /etc/hosts << EOF
127.0.0.1 basic-proxy.test proxy-headers.test proxy-rewrite.test proxy-query.test
127.0.0.1 html-transform.test json-transform.test string-replace.test
127.0.0.1 jwt-auth.test rate-limit.test waf.test security-headers.test
127.0.0.1 cors.test https-proxy.test forward-rules.test callbacks.test
127.0.0.1 complex.test google-oauth.test jwt-encrypted.test
EOF'
```

### 3. Run Tests

**Basic Proxy Test:**
```bash
curl -H "Host: basic-proxy.test" http://localhost:8080/
```

**Check Logs in ClickHouse:**
```bash
docker exec test-clickhouse clickhouse-client --query "
SELECT count() FROM proxy_logs.request_logs
WHERE timestamp >= now() - INTERVAL 1 HOUR
"
```

**Check Logs in Elasticsearch:**
```bash
curl "http://localhost:9200/proxy-application-*/_count?pretty"
```

**View in Kibana:**
- Open http://localhost:5601
- Go to Discover
- Select `proxy-application-*` index pattern

**View Metrics in Grafana:**
- Open http://localhost:3000
- Login: `admin` / `admin`
- Navigate to Proxy → Proxy Overview dashboard

## Service Management

### Start Services

```bash
cd /Users/rick/projects/proxy/docker
docker compose up -d
```

### Reload Database and Restart Proxy

```bash
cd /Users/rick/projects/proxy/test
bash ../scripts/reload_database.sh
```

This is useful when you've updated origin configurations and need the proxy to pick up the changes.

### Stop Services

```bash
docker compose down
```

### Stop and Remove All Data

```bash
docker compose down -v
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f proxy
docker compose logs -f clickhouse
```

### Restart Service

```bash
docker compose restart [service-name]
```

### Rebuild Services

```bash
# Rebuild all
docker compose build

# Rebuild specific service

# Or use the build script
bash build-services.sh
```

## Test Fixtures

All test origin configurations are in `fixtures/origins/`:

- **01-basic-proxy.json** - Simple proxy
- **02-proxy-with-headers.json** - Headers modification
- **03-proxy-path-rewrite.json** - Path rewriting
- **04-proxy-query-params.json** - Query parameters
- **05-proxy-conditional-modifiers.json** - Conditional logic
- **06-html-transform-basic.json** - HTML transformation
- **07-html-transform-advanced.json** - Advanced HTML
- **08-json-transform.json** - JSON transformation
- **09-string-replace.json** - String replacement
- **10-redirect.json** - Redirects
- **11-static-content.json** - Static content
- **12-graphql-proxy.json** - GraphQL proxy
- **13-websocket-proxy.json** - WebSocket proxy
- **14-loadbalancer.json** - Load balancing
- **15-jwt-authentication.json** - JWT auth
- **16-rate-limiting.json** - Rate limiting
- **17-waf-policy.json** - WAF rules
- **18-security-headers.json** - Security headers
- **19-ip-filtering.json** - IP filtering
- **20-cors-headers.json** - CORS headers
- **21-https-proxy.json** - HTTPS proxy
- **22-forward-rules.json** - Forward rules
- **23-callbacks.json** - Callbacks
- **24-complex-combined.json** - Complex combined
- **25-google-oauth.json** - Google OAuth
- **26-jwt-encrypted.json** - JWT with encrypted secrets

**Load Fixtures:**
```bash
cd /Users/rick/projects/proxy/test
bash ../scripts/load_database.sh
```

**Reload Database and Restart Proxy:**
```bash
cd /Users/rick/projects/proxy/test
bash ../scripts/reload_database.sh
```

This script will:
- Combine and load all origin fixtures into PostgreSQL
- Restart the proxy service to pick up new configurations
- Verify the proxy is healthy after restart

## Common Test Scenarios

### Basic Proxy Test

```bash
curl -H "Host: basic-proxy.test" http://localhost:8080/
```

### JWT Authentication Test

```bash
# Get token
TOKEN=$(jq -r '.tokens.admin.token' fixtures/jwt_tokens.json)

# Test with token
curl -H "Host: jwt-auth.test" \
     -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/test/auth-required
```

### Rate Limiting Test

```bash
# Make multiple requests (should rate limit after 10)
for i in {1..15}; do
  curl -s -H "Host: rate-limit.test" http://localhost:8080/test/simple-200
  sleep 1
done
```

### HTML Transform Test

```bash
curl -H "Host: html-transform.test" http://localhost:8080/ | head -20
```

### GraphQL Test

```bash
curl -H "Host: graphql.test" \
     -H "Content-Type: application/json" \
     -d '{"query": "{ users { name } }"}' \
     http://localhost:8080/graphql
```

## Monitoring & Debugging

### Check All Services

```bash
cd /Users/rick/projects/proxy/docker
docker compose ps
```

### Service Health Checks

```bash
# Proxy
curl http://localhost:8888/metrics

# ClickHouse
curl http://localhost:8123/ping

# Elasticsearch
curl http://localhost:9200/_cluster/health?pretty

# Kibana
curl http://localhost:5601/api/status


# Prometheus
curl http://localhost:9090/-/healthy

# Grafana
curl http://localhost:3000/api/health
```

### View Service Logs

```bash
# Proxy
docker logs test-proxy -f

# ClickHouse
docker logs test-clickhouse -f

# Elasticsearch
docker logs test-elasticsearch -f

# Kibana
docker logs test-kibana -f

```

### Database Queries

**PostgreSQL:**
```bash
docker exec test-postgres psql -U proxy -d proxy -c "SELECT key FROM config_storage LIMIT 10;"
```

**ClickHouse:**
```bash
docker exec test-clickhouse clickhouse-client --query "SELECT count() FROM proxy_logs.request_logs"
```

**Elasticsearch:**
```bash
curl "http://localhost:9200/proxy-application-*/_count?pretty"
```

## Troubleshooting

### Prometheus Not Showing Metrics

**Symptoms:** No metrics appear in Prometheus UI or Grafana dashboards.

**Diagnosis Steps:**

1. **Verify proxy metrics endpoint is accessible:**
   ```bash
   curl http://localhost:8888/metrics | head -30
   ```
   Should show metrics starting with `# HELP http_` or `# HELP sb_` and `# TYPE http_` or `# TYPE sb_`.

2. **Check Prometheus can scrape proxy:**
   ```bash
   # From Prometheus container
   docker exec test-prometheus wget -qO- http://test-proxy:8888/metrics | head -30
   ```

3. **Check Prometheus targets:**
   - Open http://localhost:9090/targets
   - Look for `proxy` job
   - Status should be "UP" (green)
   - If "DOWN", check:
     - Network connectivity: `docker exec test-prometheus ping test-proxy`
     - Proxy is running: `docker ps | grep test-proxy`
     - Proxy health: `curl http://localhost:8888/healthz`

4. **Check Prometheus configuration:**
   - Open http://localhost:9090/config
   - Search for `job_name: 'proxy'`
   - Verify:
     - `targets: ['test-proxy:8888']` (not `localhost:8888`)
     - `metrics_path: '/metrics'`
     - `scrape_interval: 5s` (or similar)

5. **Generate test metrics:**
   ```bash
   # Make requests to generate metrics
   for i in {1..10}; do
     curl -H "Host: basic-proxy.test" http://localhost:8080/ > /dev/null 2>&1
   done
   
   # Wait 10 seconds for scrape
   sleep 10
   
   # Check metrics in Prometheus
   # Query: sb_http_req_total
   ```

6. **Check Prometheus logs:**
   ```bash
   docker logs test-prometheus 2>&1 | grep -i error
   docker logs test-prometheus 2>&1 | grep -i proxy
   ```

7. **Reload Prometheus config:**
   ```bash
   curl -X POST http://localhost:9090/-/reload
   ```

**Common Issues:**

- **Wrong target host:** Prometheus config uses `test-proxy:8888` (Docker service name), not `localhost:8888`
- **Proxy not generating metrics:** Make some HTTP requests through the proxy first
- **Network issues:** Services must be on same Docker network (`test_net`)
- **Proxy metrics disabled:** Check proxy config has telemetry enabled

### Grafana Dashboards Not Updating

**Symptoms:** Dashboards show "No data" or don't update.

**Diagnosis Steps:**

1. **Verify Prometheus datasource:**
   - Grafana → Configuration → Data Sources
   - Click "Prometheus"
   - Click "Test" button
   - Should show "Data source is working"

2. **Test query in Grafana Explore:**
   - Grafana → Explore
   - Select "Prometheus" datasource
   - Query: `http_req_total` (standard HTTP metric)
   - Query: `sb_config_cache_hits_total` (SB-specific metric)
   - Should show data if metrics exist

3. **Check dashboard queries:**
   - Edit dashboard panel
   - Verify HTTP metrics use no prefix (e.g., `http_req_total`, not `sb_http_req_total`)
   - Verify SB-specific metrics use `sb_` prefix (e.g., `sb_config_cache_hits_total`)
   - Test query in Prometheus UI first

4. **Verify time range:**
   - Dashboard time range (top right)
   - Set to "Last 15 minutes" or wider
   - Metrics only show for time ranges with data

5. **Check auto-refresh:**
   - Click refresh dropdown (top right)
   - Set to 5s or 10s for live updates

### Services Not Starting

```bash
# Check logs
docker compose logs [service-name]

# Check port conflicts
lsof -i :8080  # Proxy
lsof -i :5433  # PostgreSQL
lsof -i :8123  # ClickHouse
lsof -i :9200  # Elasticsearch
```

### Logs Not Appearing

**ClickHouse:**
```bash
# Check if database exists
docker exec test-clickhouse clickhouse-client --query "SHOW DATABASES"

# Check table
docker exec test-clickhouse clickhouse-client --query "SHOW TABLES FROM proxy_logs"
```

**Elasticsearch:**
```bash
# Check indices
curl http://localhost:9200/_cat/indices/proxy-*?v

# Check Fluent Bit connection to Elasticsearch
docker logs test-fluent-bit | grep -i elasticsearch
```

### Permission Issues

**L3 Cache:**
```bash
# Check data directory
docker exec test-proxy ls -la /app/data

# Fix permissions (if needed)
docker compose restart proxy-data-init
```

### Database Connection Issues

```bash
# Test PostgreSQL
docker exec test-postgres pg_isready -U proxy

# Test Redis
docker exec test-redis redis-cli ping
```

## Configuration Files

- **Proxy Config:** `conf/sb.yml`
- **Fluent Bit Config:** `conf/fluent-bit.conf`
- **Fluent Bit Parsers:** `conf/parsers.conf`
- **ClickHouse Schema:** `../../sql/clickhouse-init.sql`
- **Elasticsearch Template:** `conf/elasticsearch-templates/proxy-logs-template.json`
- **Prometheus Config:** `conf/prometheus.yml`
- **Grafana Dashboards:** `conf/grafana/dashboards/`

## Additional Resources

- **Main Docker README:** `/Users/rick/projects/proxy/docker/README.md`
- **Logging Stack Guide:** `LOGGING_STACK.md`
- **E2E Setup Guide:** `E2E_SETUP_UPDATED.md`
- **Test Coverage:** `E2E_TEST_COVERAGE.md`

## Quick Reference

### All Service URLs

```
Proxy HTTP:        http://localhost:8080
Proxy HTTPS:       https://localhost:8443
Proxy Metrics:     http://localhost:8888/metrics
E2E Test Server:   http://localhost:8090
PostgreSQL:        localhost:5433 (proxy/proxy)
Redis:             localhost:6380
ClickHouse:        http://localhost:8123 (default/)
Elasticsearch:     http://localhost:9200
Kibana:            http://localhost:5601
Fluent Bit:        http://localhost:2020
Prometheus:        http://localhost:9090
Grafana:           http://localhost:3000 (admin/admin)
```

### Default Credentials Summary

| Service | Username | Password |
|---------|----------|----------|
| Grafana | `admin` | `admin` |
| PostgreSQL | `proxy` | `proxy` |
| ClickHouse | `default` | (empty) |
| Redis | - | (none) |
| Elasticsearch | - | (disabled) |
| Kibana | - | (disabled) |

### Useful Commands

```bash
# Start everything
cd /Users/rick/projects/proxy/test && bash run_e2e_tests.sh

# View all logs
cd ../docker && export ENV_PREFIX="test-" && export ENV_NETWORK="test_net" && docker compose logs -f

# Check service health
docker compose ps

# Access ClickHouse
docker exec -it test-clickhouse clickhouse-client

# Access PostgreSQL
docker exec -it test-postgres psql -U proxy -d proxy

# Access Redis
docker exec -it test-redis redis-cli

# Stop everything
cd ../docker && export ENV_PREFIX="test-" && export ENV_NETWORK="test_net" && docker compose down

# Clean slate (removes all data)
cd ../docker && export ENV_PREFIX="test-" && export ENV_NETWORK="test_net" && docker compose down -v
```

### Quick Prometheus Query Reference

**Most Common Queries:**

**Standard HTTP Metrics (no prefix):**
```promql
# Request rate (req/s)
rate(http_req_total[5m])

# Error rate (req/s)
rate(http_server_errors_total[5m])

# Response time p95 (seconds)
histogram_quantile(0.95, rate(http_response_time_seconds_bucket[5m]))

# Response time p50/median (seconds)
histogram_quantile(0.50, rate(http_response_time_seconds_bucket[5m]))

# Active connections
active_connections

# Total requests
http_req_total

# Success rate (%)
(rate(http_req_ok_total[5m]) / rate(http_req_total[5m])) * 100
```

**SoapBucket-Specific Metrics (sb_ prefix):**
```promql
# Config cache efficiency
rate(sb_config_cache_hits_total[5m]) / (rate(sb_config_cache_hits_total[5m]) + rate(sb_config_cache_misses_total[5m]))

# Load balancer requests
rate(sb_lb_requests_total[5m])

# WAF blocks
rate(sb_waf_blocks_total[5m])
```

**List Available Metrics:**
```promql
# All HTTP metrics
{__name__=~"http_.*"}

# All SB-specific metrics
{__name__=~"sb_.*"}
```

**Verify Metrics Are Working:**

1. Check proxy exposes metrics:
   ```bash
   curl http://localhost:8888/metrics | grep http_req_total
   ```

2. Check Prometheus can scrape:
   ```bash
   docker exec test-prometheus wget -qO- http://test-proxy:8888/metrics | grep http_req_total
   ```

3. Check Prometheus targets:
   - Open http://localhost:9090/targets
   - Verify `proxy` target is "UP"

4. Test query in Prometheus:
   - Open http://localhost:9090
   - Query: `http_req_total` (standard HTTP metric)
   - Query: `sb_config_cache_hits_total` (SB-specific metric)
   - Should show data if requests have been made
