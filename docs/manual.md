# SBproxy Runtime Manual

*Last modified: 2026-04-12*

**Version:** 0.1.0
**Module:** `github.com/soapbucket/sbproxy`
**Vendor:** Soap Bucket LLC - [www.soapbucket.com](https://www.soapbucket.com)

This manual is the operational reference for running sbproxy in production. It covers installation, CLI usage, runtime behavior, observability, TLS, connection tuning, and deployment patterns.

---

## Table of Contents

1. [Installation](#1-installation)
2. [CLI Reference](#2-cli-reference)
3. [Runtime Behavior](#3-runtime-behavior)
4. [Logging](#4-logging)
5. [Metrics and Observability](#5-metrics-and-observability)
6. [Health Checks](#6-health-checks)
7. [TLS and Certificates](#7-tls-and-certificates)
8. [Connection Tuning](#8-connection-tuning)
9. [Hot Reload](#9-hot-reload)
10. [Feature Flags](#10-feature-flags)
11. [Docker Deployment](#11-docker-deployment)
12. [Kubernetes Deployment](#12-kubernetes-deployment)
13. [Environment Variables Reference](#13-environment-variables-reference)

---

## 1. Installation

### Binary Download

Pre-built binaries are available for Linux, macOS, and Windows from the releases page. Download the archive for your platform, extract it, and place the `sbproxy` binary somewhere in your `PATH`.

```bash
# Linux (amd64)
curl -L https://github.com/soapbucket/sbproxy/releases/latest/download/sbproxy_linux_amd64.tar.gz | tar -xz
sudo mv sbproxy /usr/local/bin/sbproxy

# macOS (arm64)
curl -L https://github.com/soapbucket/sbproxy/releases/latest/download/sbproxy_darwin_arm64.tar.gz | tar -xz
sudo mv sbproxy /usr/local/bin/sbproxy
```

Verify the installation:

```bash
sbproxy --version
# sbproxy v0.1.0 (commit: abc1234, built: 2026-04-08T00:00:00Z, go: go1.25.5, platform: linux/amd64)
```

### Docker

The official image is built from `alpine:3.21` with no external runtime dependencies.

```bash
# Pull the image
docker pull ghcr.io/soapbucket/sbproxy:latest

# Run with a local config directory
docker run --rm \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /path/to/config:/etc/sbproxy \
  ghcr.io/soapbucket/sbproxy:latest

# Run with a specific config file
docker run --rm \
  -p 8080:8080 \
  -v /path/to/sb.yml:/etc/sbproxy/sb.yml:ro \
  ghcr.io/soapbucket/sbproxy:latest serve -f /etc/sbproxy/sb.yml
```

### From Source

Requires Go 1.25 or later. The binary is built with `CGO_ENABLED=0` and has no C dependencies.

```bash
# Clone and build
git clone https://github.com/soapbucket/sbproxy.git
cd sbproxy
make build
# Binary is placed at bin/sbproxy

# Or install directly to GOPATH/bin
go install github.com/soapbucket/sbproxy/cmd/sbproxy@latest
```

Build with version metadata injected:

```bash
make build
# Equivalent to:
go build \
  -ldflags="-s -w \
    -X github.com/soapbucket/sbproxy/internal/version.Version=0.1.0 \
    -X github.com/soapbucket/sbproxy/internal/version.BuildHash=$(git rev-parse --short HEAD) \
    -X github.com/soapbucket/sbproxy/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/sbproxy ./cmd/sbproxy/
```

---

## 2. CLI Reference

sbproxy exposes two top-level commands: `serve` and `validate`.

```
sbproxy [flags]
sbproxy serve [flags]
sbproxy validate [flags]
```

### `serve` - Start the Proxy

Starts the proxy server with all configured listeners.

```bash
sbproxy serve
sbproxy serve -c /etc/sbproxy
sbproxy serve -f /etc/sbproxy/sb.yaml
sbproxy serve --log-level debug --grace-time 30
```

### `validate` - Validate Configuration

Loads and parses the configuration file without starting any servers. Exits with code `0` if the configuration is valid, or `1` if errors are found. Use this in CI/CD pipelines before deploying a new config.

```bash
sbproxy validate
sbproxy validate -c /etc/sbproxy
sbproxy validate -f /path/to/sb.yaml

# Example CI check
sbproxy validate -f staging/sb.yaml && echo "Config OK"
```

### Flags

All flags accept environment variables as alternatives. Environment variables take precedence over flag defaults but are overridden by explicit flag values on the command line.

#### `-c, --config-dir` (string)

The directory where sbproxy looks for its configuration file. This is also the base path for relative file references within the config (TLS certificates, Lua scripts, database files, etc.).

- **Default:** `.` (current directory)
- **Environment:** `SB_CONFIG_DIR`
- **Config file names searched:** `sb.json`, `sb.yaml`, `sb.toml`, `sb.hcl`, and Java properties format

```bash
sbproxy serve -c /etc/sbproxy
SB_CONFIG_DIR=/etc/sbproxy sbproxy serve
```

#### `-f, --config-file` (string)

Path to the configuration file. Can be absolute or relative to `--config-dir`. When this flag is set without an explicit `--config-dir`, the config directory is derived from the file's parent directory automatically.

- **Default:** (empty, auto-discovered from `--config-dir`)
- **Environment:** `SB_CONFIG_FILE`

```bash
sbproxy serve -f /etc/sbproxy/sb.yaml
sbproxy serve -f ./configs/production.yaml
```

#### `--log-level` (string)

Sets the application log level. Controls the verbosity of the structured application logger (startup, shutdown, config reload events, and component-level messages). This is separate from the request log level.

- **Values:** `debug`, `info`, `warn`, `error`
- **Default:** `info`
- **Environment:** `SB_LOG_LEVEL`

```bash
sbproxy serve --log-level debug
SB_LOG_LEVEL=warn sbproxy serve
```

#### `--request-log-level` (string)

Sets the request log level independently from the application log. When empty, the request logger inherits from `--log-level`. Set to `none` to disable request logging entirely, which eliminates all per-request I/O overhead.

- **Values:** `debug`, `info`, `warn`, `error`, `none`
- **Default:** (empty, inherits from `--log-level`)
- **Environment:** `SB_REQUEST_LOG_LEVEL`

```bash
# Quiet application logs but verbose request logs
sbproxy serve --log-level warn --request-log-level debug

# Disable request logging entirely
sbproxy serve --request-log-level none
```

#### `--grace-time` (int)

Number of seconds to wait for in-flight requests to complete before forcing shutdown. A value of `0` uses the default of 30 seconds. Set higher values for long-running streaming connections.

- **Default:** `0` (uses 30-second built-in default)
- **Environment:** `SB_GRACE_TIME`

```bash
sbproxy serve --grace-time 60
SB_GRACE_TIME=120 sbproxy serve
```

#### `--disable-host-filter` (bool)

Disables the bloom filter that pre-screens incoming requests by hostname. When disabled, every request goes through the full origin lookup path regardless of whether a matching origin exists. Useful for debugging configuration discovery issues.

- **Default:** `false` (host filter is enabled)
- **Environment:** `SB_DISABLE_HOST_FILTER`

```bash
sbproxy serve --disable-host-filter
SB_DISABLE_HOST_FILTER=true sbproxy serve
```

#### `--disable-sb-flags` (bool)

Disables `X-Sb-Flags` header and `_sb.*` query parameter processing. When disabled, clients cannot enable debug mode, bypass caches, or control tracing via request headers. Use in production for tighter control over proxy behavior.

- **Default:** `false` (sb-flags processing is enabled)
- **Environment:** `SB_DISABLE_SB_FLAGS`

```bash
sbproxy serve --disable-sb-flags
SB_DISABLE_SB_FLAGS=true sbproxy serve
```

---

## 3. Runtime Behavior

### GOMAXPROCS and CPU Quota

sbproxy uses `go.uber.org/automaxprocs` to automatically detect and apply the Linux container CPU quota as `GOMAXPROCS`. In a container with a 2-CPU quota, the Go scheduler will use 2 OS threads for user-space goroutines, matching actual available CPU capacity and avoiding CPU throttling.

To override the auto-detected value, set the standard Go environment variable:

```bash
GOMAXPROCS=4 sbproxy serve
```

In environments without cgroup CPU quotas (bare-metal, macOS), `automaxprocs` falls back to the number of logical CPUs as reported by the OS.

### Startup Sequence

sbproxy initializes subsystems in a fixed order. Each step must succeed before the next begins. The process is marked ready only after all steps complete.

1. **Config load** - Reads `sb.yaml` (or equivalent) from the config directory and validates all fields.
2. **Logger init** - Initializes the structured application logger (zap-based), request logger, and security logger. All subsequent log output uses the configured level and format.
3. **Embedded data** - Loads embedded static assets and data files compiled into the binary. Logs the generated-at timestamp and file count.
4. **Buffer pools** - Initializes adaptive buffer pools and zerocopy I/O pools used across the request path to minimize allocations.
5. **Server variables** - Populates the server context singleton with version, hostname, PID, and any operator-defined custom variables from the `var` config section.
6. **DNS resolver** - Initializes the caching DNS resolver with a 10-second timeout. If DNS initialization times out, the proxy continues with the system resolver.
7. **Telemetry** - Sets up the OpenTelemetry tracing provider (OTLP gRPC or HTTP). Errors are logged but do not prevent startup.
8. **AI providers** - Loads AI provider configurations from the config directory.
9. **Manager** - Creates the core manager with storage, messenger, GeoIP, UA parser, and crypto settings. Loads workspace configurations and registers callbacks.
10. **Vaults** - Initializes configured secret vault backends (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, etc.).
11. **Feature flags** - Loads and caches workspace-level feature flags from the messenger.
12. **Host filter** - Builds the bloom filter from all known hostnames. Used to short-circuit requests for unknown hostnames before full origin lookup.
13. **Build router** - Assembles the HTTP router with all middleware, auth handlers, and proxy engine endpoints.
14. **Start servers** - Binds and listens on configured HTTP, HTTPS, and HTTP/3 (QUIC) ports.
15. **Start subscribers** - Starts background goroutines that subscribe to messenger topics for real-time config updates, cache invalidation, and feature flag changes.
16. **Mark ready** - Sets the health manager's ready flag to `true`. The `/ready` and `/readyz` endpoints begin returning `200`.
17. **Hot reload watcher** - Starts the fsnotify file watcher on the config file.

On successful startup, the log includes:

```json
{"level":"info","msg":"service started","startup_time":"342ms"}
```

### Signal Handling

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown |
| `SIGINT` (Ctrl+C) | Graceful shutdown |
| `SIGHUP` | Config reload (log level changes take effect immediately) |

### Graceful Shutdown

When sbproxy receives `SIGTERM` or `SIGINT`:

1. The health manager is marked as shutting down. `/ready` and `/readyz` immediately return `503`. Load balancers should stop routing new traffic within one health check interval.
2. sbproxy waits up to `--grace-time` seconds for in-flight requests to complete, polling every 100ms.
3. After all in-flight requests drain (or grace time expires), background subscribers and the reload watcher are stopped.
4. The HTTP, HTTPS, and telemetry servers call `Shutdown()` with a 10-second deadline.
5. Flush operations on logging backends and AI cost tracking complete.
6. The process exits with code `0`.

---

## 4. Logging

### Log Streams

sbproxy produces three independent log streams, each independently configurable:

| Stream | Purpose | Default Level |
|--------|---------|---------------|
| Application | Service lifecycle, config events, errors | `info` |
| Request | Per-request access log | `info` |
| Security | Auth failures, policy triggers, IP blocks | `info` |

All streams produce structured JSON output by default. A human-readable `dev` format is available for local development by setting `proxy.logging.format: dev` in `sb.yaml`.

### Log Levels

- **debug** - High-volume diagnostic output. Health check calls, cache lookups, DNS resolutions, goroutine activity. Use only when troubleshooting.
- **info** - Normal operational events. Startup, shutdown, config changes, connection established/closed.
- **warn** - Recoverable issues. Degraded dependency, DNS timeout, config reload with partial errors.
- **error** - Failures requiring attention. Failed to bind port, upstream unreachable, cert rotation error.

The log level can be changed at runtime via `SIGHUP` or by updating `SB_LOG_LEVEL` and sending `SIGHUP`. The change takes effect within the 500ms debounce window.

### Two-Level Log Configuration

Set the application and request log levels independently to avoid burying access logs in debug noise:

```bash
# Quiet application log, verbose request log
sbproxy serve --log-level warn --request-log-level debug
```

Or in `sb.yaml`:

```yaml
proxy:
  logging:
    application:
      level: warn
    request:
      level: info
      fields:
        headers: true
        query_string: true
        cookies: false
        cache_info: true
        auth_info: true
        location: true
```

### Request Log Fields

The request logger supports opt-in field groups. All fields default to the values below unless configured:

| Field Group | Default | Description |
|-------------|---------|-------------|
| `timestamps` | `true` | Request start time, end time, duration |
| `headers` | `false` | All incoming request headers |
| `forwarded_headers` | `true` | `X-Forwarded-For`, `X-Real-IP`, `Via` |
| `query_string` | `true` | Raw URL query string |
| `cookies` | `false` | Cookie names and values |
| `original_request` | `false` | Original request before any modifications |
| `cache_info` | `true` | Cache hit/miss, cache key, TTL |
| `auth_info` | `true` | Auth method, user ID, token metadata |
| `app_version` | `false` | Proxy version in each log line |
| `location` | `false` | GeoIP country, city, ASN |

Example request log entry (JSON):

```json
{
  "level": "info",
  "ts": "2026-04-08T12:00:00.123Z",
  "msg": "request",
  "method": "GET",
  "path": "/api/users",
  "status": 200,
  "duration_ms": 42,
  "bytes": 1284,
  "remote_addr": "203.0.113.5:51234",
  "host": "api.example.com",
  "request_id": "01HWQMB5GBMR3X4ZF9KVFD7R8P",
  "origin_id": "abc123",
  "cache_status": "HIT",
  "cache_key": "GET:api.example.com:/api/users:"
}
```

### Sampling

Request logging supports 1-in-N sampling to reduce log volume on high-traffic origins. Errors (status >= 500) and slow requests are always logged regardless of sampling rate.

```yaml
proxy:
  logging:
    request:
      sampling:
        enabled: true
        rate: 100  # log 1 in 100 requests; errors always logged
      slow_request_threshold: 5s
```

### Log Outputs

Each stream can write to multiple outputs simultaneously:

```yaml
proxy:
  logging:
    request:
      outputs:
        - type: stderr
        - type: file
          file:
            path: /var/log/sbproxy/requests.log
            max_size: 100mb
            max_backups: 5
```

---

## 5. Metrics and Observability

### Prometheus Metrics

sbproxy exposes Prometheus metrics on the telemetry server (default port `8888`). Configure the telemetry server in `sb.yaml`:

```yaml
telemetry:
  bind_address: "0.0.0.0"
  bind_port: 8888
  enable_profiler: false  # set true to enable pprof at /debug/pprof/
```

Scrape the metrics endpoint:

```
GET http://localhost:8888/metrics
```

#### Core HTTP Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `http_req_total` | Counter | Total HTTP requests served |
| `http_req_ok_total` | Counter | Requests with 2xx status |
| `http_client_errors_total` | Counter | Requests with 4xx status |
| `http_server_errors_total` | Counter | Requests with 5xx status |
| `http_response_time_seconds` | Histogram | Request duration |

#### Load Balancer Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `sb_lb_requests_total` | `origin_id`, `target_url`, `target_index` | Requests per target |
| `sb_lb_request_duration_seconds` | `origin_id`, `target_url`, `target_index` | Request duration per target |
| `sb_lb_request_errors_total` | `origin_id`, `target_url`, `target_index`, `error_type` | Errors per target |
| `sb_lb_active_connections` | `origin_id`, `target_url`, `target_index` | Active connections per target |
| `sb_lb_target_healthy` | `origin_id`, `target_url`, `target_index` | Target health (1=healthy, 0=unhealthy) |
| `sb_lb_health_checks_total` | `origin_id`, `target_url`, `target_index`, `result` | Health check outcomes |
| `sb_lb_target_selections_total` | `origin_id`, `target_url`, `target_index`, `selection_method` | Times each target was selected |
| `sb_lb_circuit_breaker_state` | `origin_id`, `target_url`, `target_index` | Circuit breaker state (0=closed, 1=half_open, 2=open) |
| `sb_lb_circuit_breaker_state_changes_total` | `origin_id`, `target_url`, `target_index`, `new_state` | State transitions |

#### Config Cache Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `sb_config_cache_hits_total` | `hostname` | Origin config cache hits |
| `sb_config_cache_misses_total` | `hostname` | Origin config cache misses |
| `sb_config_cache_size` | (none) | Current entries in config cache |
| `sb_origins_active` | `hostname`, `workspace_id`, `origin_id` | Active origins |
| `sb_config_loads_total` | `hostname`, `type`, `result` | Config load attempts |
| `sb_config_load_duration_seconds` | `hostname`, `type` | Time to load config |

### Example Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: sbproxy
    static_configs:
      - targets: ["sbproxy-pod:8888"]
    scrape_interval: 15s
```

### OpenTelemetry Tracing

sbproxy exports distributed traces via OTLP. Configure in `sb.yaml`:

```yaml
otel:
  enabled: true
  service_name: sbproxy
  environment: production
  otlp_endpoint: "otel-collector:4317"
  otlp_protocol: grpc      # or "http"
  otlp_insecure: false
  sample_rate: 1.0          # 1.0 = 100%, 0.1 = 10%
  headers:
    - "Authorization=Bearer ${OTEL_TOKEN}"
```

For HTTP export:

```yaml
otel:
  enabled: true
  otlp_endpoint: "https://otel-collector.example.com:4318"
  otlp_protocol: http
  otlp_insecure: false
```

### pprof Profiler

Enable the Go pprof profiler on the telemetry server for CPU and memory profiling:

```yaml
telemetry:
  bind_port: 8888
  enable_profiler: true   # exposes /debug/pprof/
```

```bash
# Capture a 30-second CPU profile
go tool pprof http://localhost:8888/debug/pprof/profile?seconds=30

# Capture heap snapshot
go tool pprof http://localhost:8888/debug/pprof/heap
```

---

## 6. Health Checks

sbproxy exposes multiple health endpoints. All responses are `application/json`.

### Endpoints

| Endpoint | Purpose | Success | Failure |
|----------|---------|---------|---------|
| `/health` | Full status with component checks | `200` | `503` |
| `/healthz` | Dependency status (cached 5s) | `200` | `503` |
| `/ready` | Simple readiness flag | `200` | `503` |
| `/readyz` | Readiness with dependency checks | `200` | `503` |
| `/live` | Simple liveness flag | `200` | `503` |
| `/livez` | Always-alive check for K8s | `200` | never |

Health endpoints are available on the main proxy port (not the telemetry port). In most deployments you should use `/readyz` for the K8s readiness probe and `/livez` for the liveness probe.

### /health Response

```json
{
  "status": "ok",
  "timestamp": "2026-04-08T12:00:00Z",
  "version": "0.1.0",
  "build_hash": "abc1234",
  "uptime": "3h42m15s",
  "checks": {
    "redis": "ok",
    "config_store": "ok"
  }
}
```

Status values: `"ok"`, `"degraded"` (200), `"error"` (503).

### /readyz Response

Returns `200` with `{"ready": true}` when the service is fully initialized and all critical dependencies are reachable. Returns `503` during startup, shutdown, or when a critical dependency is unreachable (after the 30-second startup grace period).

```json
{"ready": true}
```

Failure:

```json
{
  "ready": false,
  "reason": "dependency_failure",
  "failed_deps": {"redis": "error"}
}
```

During shutdown:

```json
{
  "ready": false,
  "reason": "shutting_down"
}
```

### /livez Response

Always returns `200` as long as the process is running. Use this for K8s liveness probes. It never returns `503` under normal conditions.

```json
{"alive": true}
```

### Load Balancer Target Health Checks

Per-origin health checks for load balancer targets are configured under the origin's action:

```yaml
origins:
  "api.example.com":
    action:
      type: load_balancer
      targets:
        - url: https://backend-1.internal
        - url: https://backend-2.internal
      health_check:
        path: /health
        interval: 10s
        timeout: 3s
        healthy_threshold: 2
        unhealthy_threshold: 3
        expected_status: 200
```

Unhealthy targets are removed from rotation. The `sb_lb_target_healthy` metric tracks health state per target.

### Component Registration

Subsystems register named health checkers with the health manager. The registered names appear in the `checks` map of the `/health` and `/healthz` responses. Components report `"ok"` or `"error"` status strings.

---

## 7. TLS and Certificates

### Manual TLS

Provide a certificate and key as file paths relative to the config directory:

```yaml
proxy:
  https_bind_port: 8443
  tls_cert: certs/server.crt
  tls_key: certs/server.key
```

Or use the `certificate_settings` block for additional controls:

```yaml
proxy:
  https_bind_port: 8443
  certificate_settings:
    certificate_dir: certs
    certificate_key_dir: certs
    min_tls_version: 13     # 12 = TLS 1.2, 13 = TLS 1.3 (default)
    tls_cipher_suites:
      - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

The default minimum TLS version is 1.3. To allow TLS 1.2 connections (not recommended for production), set `min_tls_version: 12`.

### ACME Auto-TLS

sbproxy integrates with any ACME-compatible certificate authority via `certmagic`. By default, it uses Let's Encrypt production. Certificates are obtained on first request for each domain and renewed automatically.

```yaml
proxy:
  https_bind_port: 8443
  certificate_settings:
    use_acme: true
    acme_email: ops@example.com
    acme_domains:
      - api.example.com
      - proxy.example.com
    acme_cache_dir: /var/lib/sbproxy/acme-cache
    # acme_directory_url: ""  # empty = Let's Encrypt production
```

For Let's Encrypt staging (testing):

```yaml
certificate_settings:
  use_acme: true
  acme_email: test@example.com
  acme_directory_url: https://acme-staging-v02.api.letsencrypt.org/directory
  acme_cache_dir: /tmp/acme-cache
```

For the Pebble test ACME server (local development, used by the Docker Compose stack):

```yaml
certificate_settings:
  use_acme: true
  acme_email: test@example.com
  acme_directory_url: https://pebble:14000/dir
  acme_insecure_skip_verify: true   # only for self-signed ACME test servers
  acme_ca_cert_file: pebble-ca.pem  # optional: trust Pebble's CA
  acme_cache_dir: /etc/sbproxy/certs
```

### Mutual TLS (mTLS) for Inbound Connections

To require clients to present certificates when connecting to sbproxy, configure `client_auth` under `certificate_settings`:

```yaml
proxy:
  certificate_settings:
    use_acme: true
    acme_email: ops@example.com
    client_auth: require_and_verify
    client_ca_cert_file: certs/ca.crt
```

Available `client_auth` values:

| Value | Behavior |
|-------|----------|
| `none` | No client certificate required (default) |
| `request` | Request a certificate but do not require it |
| `require` | Require a certificate but do not verify it against a CA |
| `verify_if_given` | Verify the certificate if one is presented |
| `require_and_verify` | Require a certificate and verify it against the configured CA |

The CA can also be provided as base64-encoded PEM data instead of a file path:

```yaml
certificate_settings:
  client_auth: require_and_verify
  client_ca_cert_data: "LS0tLS1CRUdJTi..."  # base64-encoded PEM
```

### Generating Development Certificates

The project includes a script to generate a local CA, server certificate, and client certificate for development and testing:

```bash
make certs
# Generates in ./certs/:
#   ca.crt, ca.key
#   server.crt, server.key
#   client.crt, client.key
```

---

## 8. Connection Tuning

Connection pool behavior and timeouts are configurable per origin. These settings are placed at the origin level alongside the `action` block.

### Per-Origin Transport Fields

| Field | Default | Max | Description |
|-------|---------|-----|-------------|
| `dial_timeout` | `10s` | `1m` | Maximum time to establish a TCP connection to the upstream |
| `tls_handshake_timeout` | `10s` | `1m` | Maximum time to complete TLS handshake with upstream |
| `idle_conn_timeout` | `60s` | `1m` | Time an idle keep-alive connection stays in the pool |
| `keep_alive` | `30s` | `1m` | TCP keep-alive interval on upstream connections |
| `timeout` | `30s` | `1m` | End-to-end request timeout (dial + headers + body) |
| `response_header_timeout` | `30s` | `1m` | Time to wait for upstream to send response headers after request is sent |
| `expect_continue_timeout` | `1s` | `1m` | Time to wait for upstream `100 Continue` before sending body |
| `max_idle_conns` | unlimited | `5000` | Maximum idle connections across all upstream hosts |
| `max_idle_conns_per_host` | unlimited | `500` | Maximum idle connections per upstream host |
| `max_conns_per_host` | unlimited | `5000` | Maximum total connections per upstream host |
| `max_connections` | unlimited | `10000` | Maximum concurrent connections from clients for this origin |
| `write_buffer_size` | `64KB` | `10MB` | Write buffer size per upstream connection |
| `read_buffer_size` | `64KB` | `10MB` | Read buffer size per upstream connection |
| `max_redirects` | `0` | `20` | Number of redirects to follow automatically |
| `http11_only` | `false` | - | Force HTTP/1.1 (disable HTTP/2 and HTTP/3) |
| `skip_tls_verify_host` | `false` | - | Skip TLS certificate verification for upstream (use only in dev) |
| `min_tls_version` | (global) | - | Minimum TLS version for outbound: `"1.2"` or `"1.3"` |
| `enable_http3` | `false` | - | Enable HTTP/3 (QUIC) for upstream connections |

Example - aggressive tuning for a low-latency internal API:

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.internal
    dial_timeout: 2s
    tls_handshake_timeout: 3s
    timeout: 10s
    response_header_timeout: 8s
    max_idle_conns_per_host: 100
    max_conns_per_host: 500
    idle_conn_timeout: 30s
```

Example - conservative tuning for a slow third-party API:

```yaml
origins:
  "slow-api.example.com":
    action:
      type: proxy
      url: https://slow-vendor.com
    timeout: 60s
    response_header_timeout: 55s
    dial_timeout: 10s
    max_idle_conns_per_host: 10
```

### HTTP/2 Connection Coalescing

HTTP/2 coalescing allows multiple hostnames that resolve to the same IP and share a TLS certificate to share a single TCP connection. This is enabled globally by default.

Global settings in `sb.yaml`:

```yaml
proxy:
  http2_coalescing:
    disabled: false
    max_idle_conns_per_host: 20
    idle_conn_timeout: 90s
    max_conn_lifetime: 1h
    allow_ip_based_coalescing: true
    allow_cert_based_coalescing: true
    strict_cert_validation: false
```

Per-origin override:

```yaml
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://backend.example.com
    http2_coalescing:
      disabled: true  # disable coalescing for this origin only
```

### Request Coalescing

Request coalescing deduplicates simultaneous identical upstream requests by having only one goroutine make the upstream call while others wait for the result. Disabled by default.

```yaml
proxy:
  request_coalescing:
    enabled: true
    max_inflight: 1000
    coalesce_window: 100ms
    max_waiters: 100
    cleanup_interval: 30s
    key_strategy: default  # or "method_url"
```

### HTTP/3 (QUIC)

HTTP/3 support is available for both inbound connections and upstream forwarding.

Enable inbound HTTP/3 on the proxy server:

```yaml
proxy:
  http3_bind_port: 8443   # typically same port as HTTPS, uses UDP
  enable_http3: true
```

Enable HTTP/3 for upstream connections on a specific origin:

```yaml
origins:
  "fast.example.com":
    action:
      type: proxy
      url: https://backend.example.com
    enable_http3: true
```

HTTP/3 requires that the HTTPS port also be bound, since the `Alt-Svc` header is sent on the HTTPS response to signal QUIC availability to clients.

---

## 9. Hot Reload

### File Watcher

sbproxy uses `fsnotify` to watch the configuration file for changes. When a write or create event is detected, a 500ms debounce timer is started. If no further events arrive within the debounce window, the reload is triggered. This prevents redundant reloads when editors write files in multiple stages.

The watcher monitors the resolved path of the config file. If no config file can be resolved (e.g., when using a config directory without a named file), the watcher logs a warning and hot reload is disabled.

### SIGHUP Trigger

Send `SIGHUP` to manually trigger a configuration reload without modifying any file:

```bash
kill -HUP $(pgrep sbproxy)
# or
kill -HUP $(cat /var/run/sbproxy.pid)
```

### What Reloads

| Change Type | Reload Behavior |
|-------------|-----------------|
| Log level (`SB_LOG_LEVEL` or config `level`) | Applied immediately |
| Request log level | Applied immediately |
| Any other config change | Requires process restart |

When a reload completes, the log includes:

```json
{"level":"info","msg":"configuration reloaded successfully","reload_count":3,"duration":"12ms"}
```

If the reload fails (e.g., malformed YAML), an error is logged and the previous configuration remains active:

```json
{"level":"error","msg":"configuration reload failed","error":"yaml: line 42: mapping values are not allowed in this context"}
```

### Why Full Restarts Are Required for Origin Changes

Origin configurations are parsed and compiled at startup into in-memory routing structures. Changing origin routing, upstream URLs, TLS settings, or authentication requires rebuilding these structures safely. A restart with a load balancer health-check-based rollout is the recommended pattern for zero-downtime config changes.

---

## 10. Feature Flags

Feature flags are per-request hints that alter proxy behavior. They can be injected by clients via headers, by operators via config, and are evaluated in CEL expressions and Lua scripts via the `features` namespace.

### Built-in Flags

| Flag | Key | Effect |
|------|-----|--------|
| Debug | `debug` | Enables per-request debug logging and adds debug headers to responses |
| Trace | `trace` | Enables distributed trace propagation and detailed span events |
| No-Cache | `no-cache` | Bypasses the response cache for this request (cache-control: no-cache semantics) |

### Setting Flags via Header

Clients can set flags on a per-request basis using the `x-sb-flags` header. Multiple flags are comma-separated (or semicolon-separated):

```bash
# Enable debug for this request
curl -H "x-sb-flags: debug" https://api.example.com/endpoint

# Enable multiple flags
curl -H "x-sb-flags: debug, trace" https://api.example.com/endpoint

# Flag with a value
curl -H "x-sb-flags: no-cache, env=staging" https://api.example.com/endpoint
```

### Setting Flags via Query Parameter

The magic query parameter prefix `_sb.` is recognized:

```bash
curl "https://api.example.com/endpoint?_sb.debug&_sb.no-cache"
```

### Using Flags in CEL Expressions

```yaml
request_rules:
  - match: 'features["debug"] == ""'
    action: allow
```

### Using Flags in Lua Scripts

```lua
function match_request(req, ctx)
  local flags = ctx.features or {}
  if flags["debug"] ~= nil then
    ctx.log("debug mode active")
  end
  return true
end
```

### Workspace-Level Feature Flags

Workspace-level flags are managed via the messenger pub/sub system and cached in memory. They are distinct from per-request flags and represent persistent configuration toggles for a workspace. These are set and managed through the sbproxy management API and are not exposed to end clients.

---

## 11. Docker Deployment

### Single Container

Mount a config directory and map ports. The container exposes `8080/tcp`, `8443/tcp`, and `8443/udp` (UDP is required for HTTP/3 QUIC).

```bash
docker run -d \
  --name sbproxy \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /etc/sbproxy:/etc/sbproxy:ro \
  -e SB_LOG_LEVEL=info \
  ghcr.io/soapbucket/sbproxy:latest
```

For a read-only config with a writable ACME cache directory:

```bash
docker run -d \
  --name sbproxy \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /etc/sbproxy/sb.yaml:/etc/sbproxy/sb.yaml:ro \
  -v sbproxy-acme-cache:/etc/sbproxy/certs \
  -e SB_LOG_LEVEL=info \
  ghcr.io/soapbucket/sbproxy:latest
```

### Docker Compose Stack

The repository ships a Docker Compose stack for local development that includes sbproxy, a Pebble ACME test server, and Redis.

Start the stack:

```bash
make docker-up
# Equivalent to: docker compose -f docker/docker-compose.yml up --build -d
```

Stop the stack:

```bash
make docker-down
# Equivalent to: docker compose -f docker/docker-compose.yml down
```

The compose file (`docker/docker-compose.yml`):

```yaml
services:
  sbproxy:
    build:
      context: ..
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
      - "8443:8443"
      - "8443:8443/udp"
    volumes:
      - ./sb.yml:/etc/sbproxy/sb.yml:ro
      - pebble-certs:/etc/sbproxy/certs
    environment:
      - SB_LOG_LEVEL=info
    depends_on:
      redis:
        condition: service_healthy
      pebble:
        condition: service_started

  pebble:
    image: letsencrypt/pebble:latest
    command: pebble -config /test/config/pebble-config.json
    ports:
      - "14000:14000"
    environment:
      - PEBBLE_VA_NOSLEEP=1
      - PEBBLE_VA_ALWAYS_VALID=1

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
```

### Building the Docker Image

```bash
make docker
# Equivalent to:
docker build \
  --build-arg VERSION=$(cat VERSION) \
  --build-arg GIT_HASH=$(git rev-parse --short HEAD) \
  -t sbproxy:latest .
```

Build arguments:

| Argument | Description |
|----------|-------------|
| `VERSION` | Version string injected at compile time (default: `dev`) |
| `GIT_HASH` | Git commit hash injected at compile time (default: `unknown`) |

The image uses a multi-stage build. The builder stage uses `golang:1.25-alpine` with `CGO_ENABLED=0`. The final image is `alpine:3.21` with only `ca-certificates` and `tzdata` added.

---

## 12. Kubernetes Deployment

### Deployment and Service

A minimal Deployment and Service for sbproxy. The telemetry sidecar port is exposed separately for Prometheus scraping.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sbproxy
  namespace: proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sbproxy
  template:
    metadata:
      labels:
        app: sbproxy
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8888"
        prometheus.io/path: "/metrics"
    spec:
      terminationGracePeriodSeconds: 60
      containers:
        - name: sbproxy
          image: ghcr.io/soapbucket/sbproxy:0.1.0
          args: ["serve", "-c", "/etc/sbproxy"]
          env:
            - name: SB_LOG_LEVEL
              value: info
            - name: SB_GRACE_TIME
              value: "30"
            - name: GOMAXPROCS
              valueFrom:
                resourceFieldRef:
                  resource: limits.cpu
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - name: https
              containerPort: 8443
              protocol: TCP
            - name: https-udp
              containerPort: 8443
              protocol: UDP
            - name: telemetry
              containerPort: 8888
              protocol: TCP
          volumeMounts:
            - name: config
              mountPath: /etc/sbproxy
              readOnly: true
          livenessProbe:
            httpGet:
              path: /livez
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: http
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 2
            successThreshold: 1
          resources:
            requests:
              cpu: 250m
              memory: 128Mi
            limits:
              cpu: "2"
              memory: 512Mi
      volumes:
        - name: config
          configMap:
            name: sbproxy-config
---
apiVersion: v1
kind: Service
metadata:
  name: sbproxy
  namespace: proxy
spec:
  selector:
    app: sbproxy
  ports:
    - name: http
      port: 80
      targetPort: http
      protocol: TCP
    - name: https
      port: 443
      targetPort: https
      protocol: TCP
```

### UDP Support for HTTP/3

HTTP/3 uses QUIC over UDP. Kubernetes Services with `type: ClusterIP` do not support UDP and TCP on the same port number by default; you need separate Service objects or use `type: LoadBalancer` with a cloud provider that supports mixed protocols.

For AWS Network Load Balancer with mixed protocol support:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sbproxy-nlb
  namespace: proxy
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: "ip"
spec:
  type: LoadBalancer
  selector:
    app: sbproxy
  ports:
    - name: http
      port: 80
      targetPort: 8080
      protocol: TCP
    - name: https-tcp
      port: 443
      targetPort: 8443
      protocol: TCP
    - name: https-udp
      port: 443
      targetPort: 8443
      protocol: UDP
```

### Resource Recommendations

These are starting-point guidelines. Actual requirements depend on traffic volume, origin count, and enabled features.

| Workload | CPU Request | CPU Limit | Memory Request | Memory Limit |
|----------|-------------|-----------|----------------|--------------|
| Low traffic (< 1k rps) | 100m | 500m | 64Mi | 256Mi |
| Medium traffic (1k-10k rps) | 250m | 2000m | 128Mi | 512Mi |
| High traffic (10k+ rps) | 500m | 4000m | 256Mi | 1Gi |

When running in a CPU-limited container, set `GOMAXPROCS` via `resourceFieldRef` as shown in the Deployment example above. This ensures `automaxprocs` uses the correct CPU limit rather than the node's total CPU count.

### ConfigMap for Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sbproxy-config
  namespace: proxy
data:
  sb.yaml: |
    proxy:
      http_bind_port: 8080
      https_bind_port: 8443
      certificate_settings:
        use_acme: true
        acme_email: ops@example.com
        acme_cache_dir: /tmp/acme-cache

    telemetry:
      bind_address: "0.0.0.0"
      bind_port: 8888

    origins:
      "api.example.com":
        action:
          type: proxy
          url: https://backend.internal
```

### PodDisruptionBudget

Ensure at least one replica is available during rolling updates:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: sbproxy-pdb
  namespace: proxy
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: sbproxy
```

---

## 13. Environment Variables Reference

All `SB_*` variables correspond to CLI flags. Environment variables are applied at process start. Most can be changed at runtime by modifying the value and sending `SIGHUP`, though only log level changes take effect without restart.

| Variable | CLI Flag | Default | Description |
|----------|----------|---------|-------------|
| `SB_CONFIG_DIR` | `-c, --config-dir` | `.` | Configuration directory path |
| `SB_CONFIG_FILE` | `-f, --config-file` | (empty) | Explicit config file path |
| `SB_LOG_LEVEL` | `--log-level` | `info` | Application log level: `debug`, `info`, `warn`, `error` |
| `SB_REQUEST_LOG_LEVEL` | `--request-log-level` | (inherits) | Request log level: `debug`, `info`, `warn`, `error`, `none` |
| `SB_GRACE_TIME` | `--grace-time` | `0` (30s) | Graceful shutdown wait in seconds (0 = 30s default) |
| `SB_DISABLE_HOST_FILTER` | `--disable-host-filter` | `false` | Disable hostname bloom filter |
| `SB_DISABLE_SB_FLAGS` | `--disable-sb-flags` | `false` | Disable X-Sb-Flags header and _sb.* query param processing |

### OpenTelemetry Standard Variables

sbproxy also respects standard OpenTelemetry SDK environment variables when the OTel provider is enabled:

| Variable | Description |
|----------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Override OTLP endpoint |
| `OTEL_EXPORTER_OTLP_HEADERS` | Additional OTLP headers (e.g., auth tokens) |
| `OTEL_SERVICE_NAME` | Override service name |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes as `key=value,key=value` |

### Go Runtime Variables

| Variable | Description |
|----------|-------------|
| `GOMAXPROCS` | Override automatic CPU quota detection. Set to the number of CPUs the process should use. |

In Kubernetes, bind this to the CPU limit using `resourceFieldRef`:

```yaml
env:
  - name: GOMAXPROCS
    valueFrom:
      resourceFieldRef:
        resource: limits.cpu
```

### Quick Reference - Common Configurations

**Minimal production startup:**

```bash
SB_CONFIG_DIR=/etc/sbproxy \
SB_LOG_LEVEL=info \
SB_GRACE_TIME=30 \
sbproxy serve
```

**Debug troubleshooting session:**

```bash
SB_CONFIG_DIR=/etc/sbproxy \
SB_LOG_LEVEL=debug \
SB_REQUEST_LOG_LEVEL=debug \
SB_DISABLE_HOST_FILTER=true \
sbproxy serve
```

**Validate before deploy:**

```bash
SB_CONFIG_FILE=/deploy/sb.yaml sbproxy validate
echo "Exit code: $?"
```

**Container with all options:**

```bash
docker run --rm \
  -e SB_CONFIG_DIR=/etc/sbproxy \
  -e SB_LOG_LEVEL=info \
  -e SB_GRACE_TIME=30 \
  -e GOMAXPROCS=2 \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /etc/sbproxy:/etc/sbproxy:ro \
  ghcr.io/soapbucket/sbproxy:0.1.0
```

---

*For configuration file reference, see `docs/configuration.md`.*
*For scripting (CEL, Lua) reference, see `docs/scripting.md`.*
*For AI gateway setup, see `docs/ai-gateway.md`.*
