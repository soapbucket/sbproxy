# SBproxy Runtime Manual

*Last modified: 2026-06-08*

Vendor: Soap Bucket LLC - [www.soapbucket.com](https://www.soapbucket.com)

This manual is the operational reference for running SBproxy in production. It covers installation, CLI usage, runtime behavior, observability, TLS, connection tuning, and deployment patterns. The proxy is built on Cloudflare's Pingora framework.

For configuration, see [configuration.md](configuration.md). For features, see [features.md](features.md). For architecture, see [architecture.md](architecture.md). For upgrade notes, see [upgrade.md](upgrade.md).

---

## Table of contents

1. [Installation](#1-installation)
2. [CLI reference](#2-cli-reference)
3. [Runtime behavior](#3-runtime-behavior)
4. [Logging](#4-logging)
5. [Metrics and observability](#5-metrics-and-observability)
6. [Health checks](#6-health-checks)
7. [TLS and certificates](#7-tls-and-certificates)
8. [Connection tuning](#8-connection-tuning)
9. [Hot reload](#9-hot-reload)
10. [Feature flags](#10-feature-flags)
11. [Docker deployment](#11-docker-deployment)
12. [Kubernetes deployment](#12-kubernetes-deployment)
13. [Environment variables reference](#13-environment-variables-reference)

---

## 1. Installation

### Binary download

Pre-built binaries for Linux, macOS, and Windows are on the releases page. Download the archive for your platform, extract it, and put the `sbproxy` binary somewhere in your `PATH`.

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

### From source

Building from source requires a recent stable Rust toolchain (`rustup` install).

```bash
git clone https://github.com/soapbucket/sbproxy
cd sbproxy
make build-release
# Binary at target/release/sbproxy

# Install to a system path
install -m 0755 target/release/sbproxy /usr/local/bin/sbproxy
```

`make run CONFIG=<path>` is a convenience wrapper that builds and starts the proxy with a chosen config file.

---

## 2. CLI reference

The binary exposes a small surface. Everything that the runtime reads
from disk lives in `sb.yml`; the CLI only points the binary at the
config file and tunes the few process-level knobs that cannot live in
config (log filter, shutdown timing, validation-only mode).

```
sbproxy --config <path>
sbproxy serve -f <path> [--log-level <level>] [--request-log-level <level>]
                        [--log-format compact|pretty|json]
                        [--shutdown-grace-ms <ms>] [--grace-time <secs>]
                        [--disable-sb-flags]
sbproxy validate <path> [--format text|json]
sbproxy --config <path> --check
sbproxy plan -f <yaml> [--against <yaml>] [--format json|text] [--out <plan-file>]
sbproxy apply -f <yaml>
sbproxy apply -p <plan-file>
sbproxy projections render --kind <kind> --config <path> [--hostname <h>]
sbproxy completions {bash|zsh|fish|powershell|elvish}
sbproxy --version
sbproxy --help
```

Argv parsing is `clap` derive, so every subcommand also accepts
`--help` for a focused usage block (`sbproxy plan --help`,
`sbproxy projections render --help`, etc.).

### `serve` - start the proxy

The default mode. Reads the config file, compiles the pipeline, and
starts the configured listeners. Either `--config <path>` (canonical)
or `-f <path>` (alias) works; a positional path is also accepted. When
no path is given on the command line, the binary falls back to
`SB_CONFIG_FILE`.

```bash
sbproxy --config /etc/sbproxy/sb.yml
sbproxy serve -f /etc/sbproxy/sb.yml
sbproxy serve -f /etc/sbproxy/sb.yml --log-level debug --request-log-level info --grace-time 30
SB_CONFIG_FILE=/etc/sbproxy/sb.yml sbproxy
```

### `validate` - check configuration without starting

Loads and compiles the config without binding any listener. Exits 0 if
the file compiles, 2 otherwise. Suitable for CI gates before a
rolling deployment.

```bash
sbproxy validate /etc/sbproxy/sb.yml
sbproxy --config /etc/sbproxy/sb.yml --check
```

Add `--format json` to emit a single JSON object instead of the human
line, so CI can parse the result. A valid config prints
`{"valid":true,"path":"..."}`; an invalid one prints
`{"valid":false,"path":"...","error":"..."}` and still exits 2. The
default is `--format text`.

```bash
sbproxy validate /etc/sbproxy/sb.yml --format json
```

### `plan` - diff a proposed config against a baseline

Compiles the proposed YAML, parses both baseline and proposed into
`ConfigFile`, runs plan-time semantic validation (orphan refs, missing
secrets, unknown module types), and emits a structured diff. Output is
a terraform-style text diff by default; `--format json` emits the
stable plan envelope for tooling. `--out <file>` writes the JSON
plan-file envelope (which records the baseline revision) so a later
`sbproxy apply -p <file>` can replay against the same baseline and
refuse on drift. See [adr-config-plan-apply.md](adr-config-plan-apply.md)
for the envelope schema.

```bash
sbproxy plan -f proposed.yml
sbproxy plan -f proposed.yml --against live.yml --format json
sbproxy plan -f proposed.yml --out /tmp/sb.plan
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | No changes between baseline and proposed. |
| 1 | CLI / IO error. |
| 2 | Changes present (informational, not an error). |
| 3 | Semantic-validation errors. The findings section spells out which rules fired. |

When `--against` is omitted, the baseline is empty, so every origin in
the proposed config surfaces as `added`. The `--running` baseline
(pulled from a live admin socket) is deferred.

### `apply` - validate and reload in place

Two flows:

```bash
sbproxy apply -f proposed.yml          # validate + reload from YAML
sbproxy apply -p /tmp/sb.plan          # replay a plan file
```

`apply -f` validates the proposed YAML, runs plan-time semantic
checks, and calls the same hot-reload primitive the SIGHUP handler
and file watcher use. `apply -p` reads a plan file from a prior
`plan --out`, recomputes the plan against the current baseline, and
refuses (exit 5) if the recorded `baseline_revision` no longer
matches the live one. Both flows take an exclusive `flock(2)` on
`<yaml_path>.applylock` so two operators cannot race the same
reload.

The `-p` form is intentionally env-var driven for the YAML path and
baseline: the plan file does not embed an on-disk path, so the
operator points apply at the YAML through `SB_APPLY_CONFIG` and
optionally overrides the baseline with `SB_APPLY_BASELINE`. See
[adr-config-plan-apply.md](adr-config-plan-apply.md) for the
rationale.

```bash
SB_APPLY_CONFIG=/etc/sbproxy/sb.yml sbproxy apply -p /tmp/sb.plan
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Reload applied cleanly. |
| 1 | CLI / IO / reload error. |
| 3 | Semantic-validation errors. Apply refused. |
| 5 | Plan file is stale. Rerun `plan` and re-apply. |
| 6 | Another `apply` already holds the applylock. |

### `projections render` - serve-time documents on demand

Renders the per-origin projection document (robots.txt, llms.txt,
llms-full.txt, licenses, TDMRep) to stdout without binding any
listener. Useful for previewing the surface a crawler will see, or for
piping into a CI fixture comparison.

```bash
sbproxy projections render --kind robots --config sb.yml
sbproxy projections render --kind llms-full --config sb.yml --hostname api.example.com
```

When `--hostname` is omitted, the first origin in the config is
chosen. Accepted `--kind` values: `robots`, `llms`, `llms-full`,
`licenses`, `tdmrep`.

### `completions` - shell tab-completion scripts

Writes a `clap_complete`-generated completion script to stdout for
the requested shell. Pipe it into the shell's completion sink and the
binary, every subcommand, and every flag become tab-completable.

```bash
sbproxy completions bash > /etc/bash_completion.d/sbproxy
sbproxy completions zsh > "${fpath[1]}/_sbproxy"
sbproxy completions fish > ~/.config/fish/completions/sbproxy.fish
```

Accepted shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.
Homebrew users get completions wired automatically at install time;
the manual paths above are for source builds.

### Flags

Each flag has an environment-variable fallback. The command-line value
wins; if no flag is set, the env var is used; otherwise the documented
default applies.

#### `-f`, `--config` (path)

Path to the YAML config. Required for `serve`; optional for `validate`
when the path is given positionally.

- **Default:** none. Falls back to `SB_CONFIG_FILE`.
- **Environment:** `SB_CONFIG_FILE`

```bash
sbproxy --config /etc/sbproxy/sb.yml
SB_CONFIG_FILE=/etc/sbproxy/sb.yml sbproxy
```

#### `--log-level` (string)

Filter passed to `tracing-subscriber`. Accepts a bare level
(`info`, `debug`, `trace`, `warn`, `error`) or a per-target filter
string (`sbproxy=debug,h2=warn,pingora=info`).

- **Default:** `info`.
- **Priority:** `--log-level` > `SB_LOG_LEVEL` > `RUST_LOG` > `info`.
- **Environment:** `SB_LOG_LEVEL`

```bash
sbproxy --config sb.yml --log-level debug
SB_LOG_LEVEL=sbproxy=trace sbproxy --config sb.yml
```

#### `--log-format` (`compact`, `pretty`, `json`)

Selects the `tracing-subscriber` output format.

- `compact` (default): one short line per event. Best for tailing a
  terminal.
- `pretty`: multi-line with span trees. Best for local debugging.
- `json`: structured records. Best for shipping to a log aggregator
  (Loki, Datadog, CloudWatch).

Invalid values fail the parse with a clap error listing the accepted
names, so the proxy never starts with a silently ignored selector.

- **Default:** `compact`.
- **Priority:** `--log-format` > `SB_LOG_FORMAT` > `compact`.
- **Environment:** `SB_LOG_FORMAT`

```bash
sbproxy --config sb.yml --log-format json
SB_LOG_FORMAT=pretty sbproxy --config sb.yml
```

#### `--request-log-level` (string)

Convenience filter for the `access_log` tracing target. This is appended
to the effective `--log-level` / `SB_LOG_LEVEL` / `RUST_LOG` filter as
`access_log=<level>`, so power users can still pass the full
per-target filter themselves.

- **Default:** unset; access logs inherit the effective global filter.
- **Priority:** `--request-log-level` > `SB_REQUEST_LOG_LEVEL` > unset.
- **Environment:** `SB_REQUEST_LOG_LEVEL`

```bash
sbproxy --config sb.yml --log-level warn --request-log-level debug
SB_REQUEST_LOG_LEVEL=trace sbproxy --config sb.yml
```

#### `--shutdown-grace-ms` (milliseconds)

Milliseconds Pingora waits for in-flight requests to complete on
SIGTERM before closing connections. Applied to both Pingora's
`grace_period_seconds` and `graceful_shutdown_timeout_seconds`
(rounded up to the next whole second). Supersedes `--grace-time`.

- **Default:** `30000` (30 seconds), matching Kubernetes' default
  `terminationGracePeriodSeconds` so a pod eviction in a
  default-configured cluster drains cleanly. Set to `0` for instant
  shutdown in test runners.
- **Environment:** `SBPROXY_SHUTDOWN_GRACE_MS`
- **Priority:** CLI flag wins over the env var; either wins over the
  legacy `--grace-time` / `SB_GRACE_TIME`.

```bash
sbproxy --config sb.yml --shutdown-grace-ms 30000
SBPROXY_SHUTDOWN_GRACE_MS=60000 sbproxy --config sb.yml
```

When SBproxy receives SIGTERM or SIGINT it emits a structured
`shutdown_signal_received` tracing event that includes the resolved
grace budget so operators can confirm the drain started before the
orchestrator's hard kill.

#### `--grace-time` (seconds, legacy)

Seconds Pingora waits for in-flight requests to complete on SIGTERM
before closing connections. Kept for back-compat; new deployments
should use `--shutdown-grace-ms` (which is the spelling the
Kubernetes operator and the docs lead with).

- **Default:** unset, so `--shutdown-grace-ms` resolves to its 30s
  default. Setting `--grace-time` suppresses the 30s default so the
  legacy value wins.
- **Environment:** `SB_GRACE_TIME`

```bash
sbproxy --config sb.yml --grace-time 30
SB_GRACE_TIME=60 sbproxy --config sb.yml
```

#### `--disable-sb-flags` (bare flag)

Lock off the per-request feature-flag surface (`x-sb-flags` header and
`?_sb.<k>` query params). When set, every built-in flag reads `false`
and the `extra` map is empty; CEL expressions that branch on
`features.*` see the same shape as a request with no flags. Use this
to harden production deployments that do not expect clients to drive
proxy behaviour.

- **Default:** off; the flag surface is active.
- **Environment:** `SB_DISABLE_SB_FLAGS` (accepts `1`, `true`, `yes`,
  `on`, case-insensitive).
- **Priority:** CLI flag wins over the env var.

```bash
sbproxy --config sb.yml --disable-sb-flags
SB_DISABLE_SB_FLAGS=1 sbproxy --config sb.yml
```

See [§10. Feature flags](#10-feature-flags) for the surface the kill
switch disables.

#### `--check`

Validates the config and exits without starting the listener. Equivalent
to `sbproxy validate <path>`. Exit status 0 on success, 2 on a config
that fails to compile.

```bash
sbproxy --config sb.yml --check
```

### Planned, not yet wired

The following flag appears in older release notes but is not honoured
by the v1.0 binary:

- `--config-dir` / `SB_CONFIG_DIR`. Pass an absolute or relative path
  to `--config`; the loader does not search a directory for known
  filenames.

---

## 3. Runtime behavior

### CPU detection

SBproxy sizes its Pingora worker pool to `std::thread::available_parallelism()`, which honours cgroup CPU quotas on Linux. In a container with a 2-CPU quota, the proxy spawns workers that match the actual available CPU capacity instead of getting throttled. To override (pin a benchmark to a known worker count, or cap workers below the cgroup quota), set `SB_WORKER_THREADS` to a positive integer:

```bash
SB_WORKER_THREADS=4 sbproxy --config sb.yml
```

Values that are not positive integers are ignored and the auto-detected value is used. There is no equivalent CLI flag; this is an environment-only knob because it is rarely changed and its right value is deployment-shape-specific.

In environments without cgroup CPU quotas (bare metal, macOS), the proxy falls back to the number of logical CPUs as reported by the OS.

### Startup sequence

SBproxy initializes subsystems in a fixed order. Each step must succeed before the next begins. The process is marked ready only after all steps complete.

1. **Config load**: reads `sb.yaml` (or equivalent) from the config directory and validates all fields.
2. **Logger init**: initializes the structured application logger, request logger, and security logger. All subsequent log output uses the configured level and format.
3. **Embedded data**: loads embedded static assets and data files compiled into the binary. Logs the generated-at timestamp and file count.
4. **Buffer pools**: initializes adaptive buffer pools used across the request path to minimize allocations.
5. **Server variables**: populates the server context singleton with version, hostname, PID, and any operator-defined custom variables from the `var` config section.
6. **DNS resolver**: initializes the caching DNS resolver with a 10-second timeout. If DNS initialization times out, the proxy falls back to the system resolver.
7. **Telemetry**: sets up the OpenTelemetry tracing provider (OTLP gRPC or HTTP). Errors are logged but do not prevent startup.
8. **AI providers**: loads AI provider configurations from the config directory.
9. **Manager**: creates the core manager with storage, messenger, GeoIP, UA parser, and crypto settings. Loads workspace configurations and registers callbacks.
10. **Vaults**: initializes configured secret vault backends (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, and so on).
11. **Feature flags**: loads and caches workspace-level feature flags from the messenger.
12. **Host filter**: builds the bloom filter from all known hostnames. Short-circuits requests for unknown hostnames before full origin lookup.
13. **Build router**: assembles the HTTP router with all middleware, auth handlers, and proxy engine endpoints.
14. **Start servers**: binds and listens on configured HTTP and HTTPS ports. (The HTTP/3 (QUIC) listener is currently disabled pending native Pingora HTTP/3, so no QUIC port is bound even when `http3` is configured.)
15. **Start subscribers**: starts background workers that subscribe to messenger topics for real-time config updates, cache invalidation, and feature flag changes.
16. **Mark ready**: sets the health manager's ready flag to `true`. The `/ready` and `/readyz` endpoints begin returning `200`.
17. **Hot reload watcher**: starts the file watcher on the config file.

On successful startup, the log includes:

```json
{"level":"info","msg":"service started","startup_time":"342ms"}
```

### Signal handling

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown (drain in-flight requests up to the grace budget) |
| `SIGINT` (Ctrl+C) | Fast shutdown (drop in-flight requests immediately) |
| `SIGQUIT` | Graceful upgrade (zero-downtime binary swap, when configured) |
| `SIGHUP` | Config reload (log level changes take effect immediately) |

Both the `sbproxy` binary and the `sbproxy-k8s-operator` install
handlers for SIGTERM and SIGINT. Each receipt emits a structured
`shutdown_signal_received` tracing event with the signal name and the
resolved grace budget so operators can confirm the drain started.

### Graceful shutdown

On `SIGTERM`, SBproxy proceeds as follows:

1. The health manager is marked as shutting down. `/ready` and `/readyz` immediately return `503`. Load balancers should stop routing new traffic within one health check interval.
2. SBproxy emits the `shutdown_signal_received` event with `signal=SIGTERM` and the resolved `grace_seconds`.
3. SBproxy waits up to `--shutdown-grace-ms` milliseconds for in-flight requests to complete, polling every 100ms.
4. After all in-flight requests drain (or grace time expires), background subscribers and the reload watcher are stopped.
5. The HTTP and HTTPS listeners shut down with a 10-second deadline.
6. Flush operations on logging backends and AI cost tracking complete.
7. The process exits with code `0` on clean shutdown. The Kubernetes operator exits with code `1` when the grace window is exceeded so the orchestrator surfaces an alert.

On `SIGINT`, Pingora skips the grace window and tears down listeners immediately; in-flight requests see a connection close. Use this only for fast local-dev shutdowns.

---

## 4. Logging

### Log streams

SBproxy produces three independent log streams, each independently configurable:

| Stream | Purpose | Default Level |
|--------|---------|---------------|
| Application | Service lifecycle, config events, errors | `info` |
| Request | Per-request access log | `info` |
| Security | Auth failures, policy triggers, IP blocks | `info` |

All streams produce structured JSON output by default. For local development, set `proxy.logging.format: dev` in `sb.yaml` for a human-readable format.

### Log levels

- **debug**: high-volume diagnostic output. Health check calls, cache lookups, DNS resolutions, worker activity. Reserve for troubleshooting.
- **info**: normal operational events. Startup, shutdown, config changes, connection established or closed.
- **warn**: recoverable issues. Degraded dependency, DNS timeout, config reload with partial errors.
- **error**: failures requiring attention. Failed to bind port, upstream unreachable, cert rotation error.

Change the log level at runtime by sending `SIGHUP`, or by updating `SB_LOG_LEVEL` and then sending `SIGHUP`. The change takes effect within the 500ms debounce window.

### Two-level log configuration

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

### Request log fields

The request logger supports opt-in field groups. Defaults are below unless overridden:

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

Access logging supports probabilistic sampling to reduce log volume on
high-traffic origins. `always_log_errors` and
`slow_request_threshold_ms` force matching requests through before the
sampler runs.

```yaml
access_log:
  enabled: true
  sample_rate: 0.01
  always_log_errors: true
  slow_request_threshold_ms: 1000
```

### Log outputs

By default, access-log lines are emitted via the `access_log` tracing
target. To write access logs directly to disk:

```yaml
access_log:
  enabled: true
  output:
    type: file
    path: /var/log/sbproxy/access.log
    max_size_mb: 100
    max_backups: 5
    compress: true
```

---

## 5. Metrics and observability

### Prometheus metrics

The proxy serves `/metrics` on its main HTTP port (`http_bind_port`, default `8080`). There is no separate telemetry listener. Scrapes are rate-limited to one per second; back-to-back requests get an empty body.

```
GET http://localhost:8080/metrics
```

Label cardinality is capped by `metrics.max_cardinality_per_label` (default `1000`). The `hostname` label uses its ADR budget by default and can be overridden with `metrics.cardinality.hostname_cap`. Values past the effective cap collapse into the literal `__other__`.

#### Hostname-scoped metrics

| Metric | Type | Labels |
|--------|------|--------|
| `sbproxy_requests_total` | Counter | `hostname`, `method`, `status` |
| `sbproxy_request_duration_seconds` | Histogram | `hostname` |
| `sbproxy_errors_total` | Counter | `hostname`, `error_type` |
| `sbproxy_active_connections` | Gauge | (none) |
| `sbproxy_cache_hits_total` | Counter | `hostname`, `result` (`hit`, `miss`) |
| `sbproxy_ai_tokens_total` | Counter | `hostname`, `provider`, `direction` (`input`, `output`) |

#### Agent detection metrics

| Metric | Type | Labels |
|--------|------|--------|
| `sbproxy_agent_detect_total` | Counter | `agent_id`, `provenance` |
| `sbproxy_agent_detect_score` | Histogram | (none) |
| `sbproxy_agent_detect_inference_seconds` | Histogram | (none) |

#### Per-origin metrics

| Metric | Type | Labels |
|--------|------|--------|
| `sbproxy_origin_requests_total` | Counter | `origin`, `method`, `status` |
| `sbproxy_origin_request_duration_seconds` | Histogram | `origin`, `method`, `status` |
| `sbproxy_origin_active_connections` | Gauge | `origin` |
| `sbproxy_bytes_total` | Counter | `origin`, `direction` (`in`, `out`) |
| `sbproxy_auth_results_total` | Counter | `origin`, `auth_type`, `result` (`allow`, `deny`) |
| `sbproxy_policy_triggers_total` | Counter | `origin`, `policy_type`, `action` |
| `sbproxy_cache_results_total` | Counter | `origin`, `result` |
| `sbproxy_circuit_breaker_transitions_total` | Counter | `origin`, `from_state`, `to_state` |

### Example Prometheus scrape config

```yaml
scrape_configs:
  - job_name: sbproxy
    static_configs:
      - targets: ["sbproxy-pod:8080"]
    scrape_interval: 15s
```

### OpenTelemetry tracing

SBproxy exports distributed traces via OTLP. Configure in `sb.yaml`:

```yaml
proxy:
  observability:
    telemetry:
      enabled: true
      endpoint: "http://otel-collector:4317"
      transport: grpc        # grpc | http
      service_name: sbproxy
      sample_rate: 1.0       # 1.0 = 100%, 0.1 = 10%
      always_sample_errors: true
      keep_over_budget_usd: 1.00
      keep_slower_than_secs: 2.0
      resource_attrs:
        deployment.environment: production
```

For HTTP export:

```yaml
proxy:
  observability:
    telemetry:
      enabled: true
      endpoint: "https://otel-collector.example.com:4318/v1/traces"
      transport: http
```

### Admin API

The embedded admin server (separate from `/metrics` above; lives on
its own port) exposes operator routes for request log, per-target
health, hot reload, drift detection, and the emitted OpenAPI
document. See [admin-api-reference.md](admin-api-reference.md) for
the full per-route schema and [section 9](#9-hot-reload) for the
hot-reload workflow.

---

## 6. Health checks

SBproxy exposes three probe endpoints, each with a bare alias. All
responses are `application/json` and unauthenticated. Endpoints are
served from the embedded admin listener, alongside `/metrics`.

### Endpoints

| Endpoint        | Aliases    | Purpose                | Success | Failure |
|-----------------|-----------|-------------------------|---------|---------|
| `/livez`        | `/live`   | Liveness; process is up  | `200`   | never   |
| `/readyz`       | `/ready`  | Readiness; ready to serve | `200`   | `503`   |
| `/healthz`      | (none)    | Liveness; trivial body   | `200`   | never   |
| `/health`       | (none)    | Rich operator health     | `200`   | `503`   |

The bare `/live` and `/ready` aliases return identical bodies to
`/livez` and `/readyz`. `/health` is intentionally different: it is the
rich operator/SIEM endpoint. K8s readiness probes should hit `/readyz`;
K8s liveness probes should hit `/livez`.

### `/livez`

Returns `200` as long as the binary is running, regardless of registry
state. Used for "should I restart this pod?". The body is intentionally
a single field so a load balancer can pattern-match it cheaply.

```json
{"alive": true}
```

### `/healthz`

Pure liveness. Returns `200` with body `{"status":"ok"}` whenever the
binary is running.

```json
{"status": "ok"}
```

### `/health`

Rich health report for humans, dashboards, and SIEM ingestion. It
includes the binary version, embedded git revision, current timestamp,
process uptime, and the same component checks used by readiness:

```json
{
  "status": "ok",
  "version": "1.1.0",
  "build_hash": "5e8cfa8",
  "timestamp": "2026-05-04T18:30:00Z",
  "uptime_seconds": 12345,
  "checks": [
    {"name": "ledger", "status": "healthy"},
    {"name": "stripe", "status": "not_configured", "detail": "not yet wired in this wave"}
  ]
}
```

When any readiness component is unhealthy, `/health` returns `503` and
the top-level `status` is `"unready"`. `/healthz` remains a fixed-size
liveness response for load balancers.

### `/readyz`

Walks the registered component readiness probes (TLS, ACME, AI
provider catalog, ML classifier, ledger client, etc.) and returns
`200` only when every probe reports ready. The body carries a
per-component breakdown so a dashboard can surface which component
failed:

```json
{
  "status": "ok",
  "components": {
    "tls": {"status": "ready"},
    "acme": {"status": "ready"}
  }
}
```

When a component is not ready, the envelope's `status` flips to
`"unready"` and the response is `503`:

```json
{
  "status": "unready",
  "components": {
    "tls": {"status": "ready"},
    "acme": {"status": "unready", "detail": "cert renewal pending"}
  }
}
```

The set of components depends on which features the live config
enabled; an OSS deployment with no ACME has only the always-on probes
in the registry.

### Load balancer target health checks

Configure per-origin health checks for load balancer targets under the origin's action:

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

Unhealthy targets drop out of rotation. The `sb_lb_target_healthy` metric tracks health state per target.

### Component registration

Subsystems register named health checkers with the health manager. The registered names appear in `/readyz`'s `components` array and `/health`'s `checks` array. Components report `"healthy"`, `"degraded"`, `"unhealthy"`, or `"not_configured"` status strings.

---

## 7. TLS and certificates

### Manual TLS

Provide a certificate and key as file paths relative to the config directory:

```yaml
proxy:
  https_bind_port: 8443
  tls_cert: certs/server.crt
  tls_key: certs/server.key
```

Or use the `certificate_settings` block for finer control:

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

The default minimum TLS version is 1.3. To allow TLS 1.2 connections (not recommended in production), set `min_tls_version: 12`.

### ACME auto-TLS

SBproxy works with any ACME-compatible certificate authority. The default is Let's Encrypt production. Certificates are obtained on first request for each domain and renewed automatically.

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

### Mutual TLS (mTLS) for inbound connections

To require clients to present certificates when connecting to SBproxy, configure `client_auth` under `certificate_settings`:

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

### Generating development certificates

The project includes a script to generate a local CA, server certificate, and client certificate for development and testing:

```bash
make certs
# Generates in ./certs/:
#   ca.crt, ca.key
#   server.crt, server.key
#   client.crt, client.key
```

---

## 8. Connection tuning

Connection pool behavior and timeouts are configurable per origin. Place these settings at the origin level alongside the `action` block.

### Per-origin transport fields

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
| `enable_http3` | `false` | - | Enable HTTP/3 (QUIC) for upstream connections. Currently inert; HTTP/3 is disabled pending native Pingora HTTP/3. |

Example: aggressive tuning for a low-latency internal API:

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

Example: conservative tuning for a slow third-party API:

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

### HTTP/2 connection coalescing

HTTP/2 coalescing lets multiple hostnames that resolve to the same IP and share a TLS certificate share a single TCP connection. Enabled globally by default.

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

### Request coalescing

Request coalescing deduplicates simultaneous identical upstream requests: one task makes the upstream call, the others wait for the result. Disabled by default.

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

HTTP/3 is temporarily disabled until native QUIC support lands in Pingora. The `http3` config and the `enable_http3` flags below still parse, but they are currently ignored: no QUIC listener is started, no `Alt-Svc` header is advertised, and setting `enable_http3: true` only logs a warning. HTTP/2 is the highest version served. The configuration and the UDP, port, and firewall mechanics below are documented for when HTTP/3 returns.

Enable inbound HTTP/3 on the proxy server (currently has no effect):

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

When HTTP/3 returns, it will require the HTTPS port to also be bound: the `Alt-Svc` header is sent on the HTTPS response to signal QUIC availability to clients. Today no `Alt-Svc` header is emitted.

---

## 9. Hot reload

### File watcher

SBproxy watches the configuration file for changes via `notify`. When a write or create event arrives, a 500ms debounce timer starts. If no further events arrive within the debounce window, the reload fires. This prevents redundant reloads when editors write files in multiple stages.

The watcher monitors the resolved path of the config file. If no config file can be resolved (for example, when using a config directory without a named file), the watcher logs a warning and hot reload is disabled.

### SIGHUP trigger

Send `SIGHUP` to manually trigger a configuration reload without modifying any file:

```bash
kill -HUP $(pgrep sbproxy)
# or
kill -HUP $(cat /var/run/sbproxy.pid)
```

### Admin endpoint trigger

When the embedded admin server is enabled (`proxy.admin.enabled: true`), an authenticated `POST /admin/reload` re-reads the same on-disk config the file watcher monitors and hot-swaps the pipeline.

```bash
curl -X POST \
  -u admin:secret \
  http://127.0.0.1:9090/admin/reload
```

Successful responses return JSON with the new revision tag:

```json
{"config_revision":"a3f2d1c0","loaded_at":"2026-04-26T18:32:11Z"}
```

Status codes:

| Code | Meaning |
|------|---------|
| 200 | Reload succeeded; the response body carries `config_revision` and `loaded_at`. |
| 400 | YAML parse error. The response sanitises the file path so error envelopes never leak the absolute path on disk. |
| 401 | Missing or invalid basic auth. |
| 405 | Wrong HTTP method (only `POST` is accepted). |
| 409 | Another reload is already in flight. The proxy serialises the file watcher and the admin route on the same single-flight guard. |
| 500 | Pipeline compile or filesystem read failed. |
| 503 | Admin server is running without a configured `config_path` (typical for embedded test fixtures). |

The reload endpoint uses the same auth, IP filter, and rate limiter as the read-only admin routes. The single-flight guard means a manual reload during a file-watcher reload does not race; one wins, the other returns `409`. This is the integration point the OSS Kubernetes operator uses to drive hot-reload on `kubectl apply` instead of triggering a rolling restart - see [kubernetes.md](kubernetes.md).

For the complete per-route schema of every admin endpoint (`/api/requests`, `/api/health`, `/api/health/targets`, `/api/stats`, `/api/openapi.{json,yaml}`, `/admin/reload`, `/admin/drift`, plus the unauthenticated probe routes), see [admin-api-reference.md](admin-api-reference.md).

### What reloads

| Change Type | Reload Behavior |
|-------------|-----------------|
| Log level (`SB_LOG_LEVEL` or config `level`) | Applied immediately |
| Request log level | Applied immediately |
| Any other config change | Requires process restart |

When a reload completes, the log includes:

```json
{"level":"info","msg":"configuration reloaded successfully","reload_count":3,"duration":"12ms"}
```

If the reload fails (for example, malformed YAML), an error is logged and the previous configuration stays active:

```json
{"level":"error","msg":"configuration reload failed","error":"yaml: line 42: mapping values are not allowed in this context"}
```

### Why full restarts are required for origin changes

Origin configurations are parsed and compiled at startup into in-memory routing structures. Changing origin routing, upstream URLs, TLS settings, or authentication requires safely rebuilding those structures. The recommended pattern for zero-downtime config changes is a restart behind a load balancer with health-check-driven rollout.

---

## 10. Feature flags

Feature flags are per-request hints that alter proxy behavior. Clients can inject them via headers, operators can set them in config, and CEL expressions and Lua scripts read them through the `features` namespace.

### Built-in flags

| Flag | Key | Effect |
|------|-----|--------|
| Debug | `debug` | Enables per-request debug logging and adds debug headers to responses |
| Trace | `trace` | Enables distributed trace propagation and detailed span events |
| No-Cache | `no-cache` | Bypasses the response cache for this request (cache-control: no-cache semantics) |

### Setting flags via header

Clients can set flags per-request using the `x-sb-flags` header. Multiple flags are comma-separated or semicolon-separated:

```bash
# Enable debug for this request
curl -H "x-sb-flags: debug" https://api.example.com/endpoint

# Enable multiple flags
curl -H "x-sb-flags: debug, trace" https://api.example.com/endpoint

# Flag with a value
curl -H "x-sb-flags: no-cache, env=staging" https://api.example.com/endpoint
```

### Setting flags via query parameter

The magic query parameter prefix `_sb.` is recognized:

```bash
curl "https://api.example.com/endpoint?_sb.debug&_sb.no-cache"
```

### Using flags in CEL expressions

The `features` namespace exposes the parsed flags. Built-ins are
booleans; extra `key=value` pairs are strings. Hyphenated keys like
`no-cache` need bracket access because hyphens are not valid CEL
identifiers:

```yaml
policies:
  - type: expression
    expression: 'features.debug == false'
    deny_status: 403
```

Available accessors:

| CEL              | Type   | Meaning |
|------------------|--------|---------|
| `features.debug`     | bool   | `x-sb-flags: debug` or `?_sb.debug`. |
| `features.trace`     | bool   | `x-sb-flags: trace` or `?_sb.trace`. |
| `features["no-cache"]` | bool | `x-sb-flags: no-cache` or `?_sb.no-cache`. |
| `features.any_set`   | bool   | True when any flag (built-in or extra) is set. |
| `features["env"]`, etc. | string | Free-form `k=v` pairs from the header / query. Empty string when not provided. |

When the kill switch (`--disable-sb-flags` / `SB_DISABLE_SB_FLAGS=1`)
is engaged, all built-ins read `false` and `extra` is empty.

### Workspace-level feature flags (planned)

Workspace-level flags via messenger pub/sub are documented in earlier
release notes. They are not implemented in v1.0; only per-request
header / query parsing is wired today.

---

## 11. Docker deployment

### Single container

Mount a config directory and map ports. The container exposes `8080/tcp`, `8443/tcp`, and `8443/udp` (UDP will be required for HTTP/3 QUIC when HTTP/3 returns; HTTP/3 is currently disabled, so the UDP mapping is presently unused).

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

### Docker Compose stack

The repository ships a Docker Compose stack for local development with SBproxy, a Pebble ACME test server, and Redis.

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

### Building the Docker image

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

The image uses a multi-stage build: the builder stage compiles a fully static binary, and the final image is a small distroless or `alpine:3.21` runtime with `ca-certificates` and `tzdata` added.

---

## 12. Kubernetes deployment

### Deployment and Service

A minimal Deployment and Service for SBproxy. Prometheus scrapes `/metrics` on the main HTTP port.

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
        prometheus.io/port: "8080"
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
            - name: SB_WORKER_THREADS
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

### UDP support for HTTP/3

HTTP/3 is currently disabled pending native Pingora HTTP/3, so no QUIC/UDP listener is started today and the UDP wiring below is not needed yet. It is documented for when HTTP/3 returns.

HTTP/3 uses QUIC over UDP. Kubernetes Services with `type: ClusterIP` do not support UDP and TCP on the same port number by default; you need separate Service objects, or `type: LoadBalancer` with a cloud provider that supports mixed protocols.

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

### Resource recommendations

Starting-point guidelines. Actual requirements depend on traffic volume, origin count, and enabled features. See [performance.md](performance.md) for benchmark data.

| Workload | CPU Request | CPU Limit | Memory Request | Memory Limit |
|----------|-------------|-----------|----------------|--------------|
| Low traffic (< 1k rps) | 100m | 500m | 64Mi | 256Mi |
| Medium traffic (1k-10k rps) | 250m | 2000m | 128Mi | 512Mi |
| High traffic (10k+ rps) | 500m | 4000m | 256Mi | 1Gi |

When running in a CPU-limited container, set `SB_WORKER_THREADS` via `resourceFieldRef` as shown in the Deployment example above. The proxy's worker pool then matches the actual CPU limit rather than the node's total CPU count.

### ConfigMap for configuration

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

## 13. Environment variables reference

The binary reads three `SB_*` variables, each a fallback for a CLI flag.
Variables are applied at process start; changes require a restart.

| Variable | CLI Flag | Default | Description |
|----------|----------|---------|-------------|
| `SB_CONFIG_FILE` | `-f`, `--config` | (empty) | Path to `sb.yml`. Required if no flag and no positional arg. |
| `SB_LOG_LEVEL` | `--log-level` | `info` | Filter for `tracing-subscriber`. Wins over `RUST_LOG`. |
| `SB_REQUEST_LOG_LEVEL` | `--request-log-level` | (unset) | Appends an `access_log=<level>` target filter for request/access logs. |
| `SBPROXY_SHUTDOWN_GRACE_MS` | `--shutdown-grace-ms` | `30000` | SIGINT/SIGTERM drain budget in milliseconds. Wins over `SB_GRACE_TIME`. |
| `SB_GRACE_TIME` | `--grace-time` | (unset) | Legacy Pingora grace period and shutdown timeout in seconds. Superseded by `SBPROXY_SHUTDOWN_GRACE_MS`. |
| `SB_WORKER_THREADS` | (none) | (auto) | Override the auto-detected Pingora worker thread count. Positive integers only. |
| `SB_DISABLE_SB_FLAGS` | `--disable-sb-flags` | `false` | Lock off the per-request `x-sb-flags` surface. Accepts `1`, `true`, `yes`, `on`. |
| `SB_APPLY_CONFIG` | (none) | (unset) | Path to the proposed YAML used by `sbproxy apply -p <plan-file>`. Required for the `-p` flow because the plan file does not embed the YAML path. |
| `SB_APPLY_BASELINE` | (none) | (unset) | Optional baseline override for `sbproxy apply -p`. When set, apply compares the plan's recorded baseline revision against this YAML's revision; otherwise the empty config is the baseline. |

In addition, the standard `RUST_LOG` env var is honoured when neither
`--log-level` nor `SB_LOG_LEVEL` is set.

### OpenTelemetry standard variables

When the OTel provider is enabled, SBproxy also respects the standard OpenTelemetry SDK environment variables:

| Variable | Description |
|----------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Override OTLP endpoint |
| `OTEL_EXPORTER_OTLP_HEADERS` | Additional OTLP headers (e.g., auth tokens) |
| `OTEL_SERVICE_NAME` | Override service name |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes as `key=value,key=value` |

### Quick reference - common configurations

Minimal production startup:

```bash
SB_CONFIG_FILE=/etc/sbproxy/sb.yml \
SB_LOG_LEVEL=info \
SB_GRACE_TIME=30 \
sbproxy
```

Debug troubleshooting session:

```bash
SB_CONFIG_FILE=/etc/sbproxy/sb.yml \
SB_LOG_LEVEL=debug \
sbproxy
```

Validate before deploy:

```bash
sbproxy validate /deploy/sb.yml
echo "Exit code: $?"
```

Container with the canonical environment:

```bash
docker run --rm \
  -e SB_CONFIG_FILE=/etc/sbproxy/sb.yml \
  -e SB_LOG_LEVEL=info \
  -e SB_GRACE_TIME=30 \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /etc/sbproxy:/etc/sbproxy:ro \
  ghcr.io/soapbucket/sbproxy:latest
```

### HTTP/3 limitations

HTTP/3 is currently disabled entirely until native QUIC support lands in Pingora. No QUIC listener is started, so there is no HTTP/3 dispatch path and the previous per-auth and per-action limitations over HTTP/3 do not currently apply. All traffic is served over HTTP/1.1 and HTTP/2, where every auth and action module is supported. These limitations will be revisited when HTTP/3 returns.

---

*For configuration file reference, see [configuration.md](configuration.md).*
*For scripting (CEL, Lua, JavaScript, WASM) reference, see [scripting.md](scripting.md).*
*For AI gateway setup, see [ai-gateway.md](ai-gateway.md).*
*For troubleshooting and runbooks, see [troubleshooting.md](troubleshooting.md).*
