# SBproxy Runtime Manual

*Last modified: 2026-07-09*

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

This section is the canonical install reference; other docs link here rather than repeating it.

### Install script

The quickest path on macOS and Linux. The script detects your OS and architecture, fetches the matching release binary, and drops it in `~/.local/bin`:

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

### Homebrew

```bash
brew install soapbucket/tap/sbproxy
```

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

The official image runs the statically-linked binary on a distroless base (`gcr.io/distroless/cc-debian12`); there is no shell or package manager in the runtime layer.

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
sbproxy config {migrate|import-litellm|print}
sbproxy projections render --kind <kind> --config <path> [--hostname <h>]
sbproxy run <model> [--name <alias>]
sbproxy models [list|show <id>]
sbproxy update [--self]
sbproxy ai ledger <subcommand>
sbproxy doctor [--format text|json]
sbproxy completions {bash|zsh|fish|powershell|elvish}
sbproxy version
sbproxy --version
sbproxy --help
```

The full subcommand set, one line each:

| Subcommand | What it does |
|------------|--------------|
| `serve` | Run the proxy. Synonym for the no-subcommand run form. |
| `validate` | Validate an `sb.yml` without starting the proxy. |
| `plan` | Diff a proposed config against a baseline. |
| `apply` | Validate and reload a config in place; the same primitive the SIGHUP handler and file watcher use. |
| `config` | Config maintenance: `migrate` rewrites deprecated syntax to the current form, `import-litellm` converts a LiteLLM `config.yaml` into an sbproxy `sb.yml`, `print` shows the effective config with secret values masked. |
| `projections` | Render projection documents (robots.txt, llms.txt, ...) for an origin without starting the proxy. |
| `run` | Serve a model in one command, with no YAML: synthesizes a minimal serving config and boots an OpenAI-compatible endpoint on loopback. |
| `models` | Discover models: one row per catalog model with a per-GPU fit verdict and cache status; `models show <id>` prints the full entry. |
| `update` | Check the engine release feed and cached models for freshness; `--self` also checks the sbproxy binary. Report-only. |
| `ai` | AI gateway tools; `ai ledger` verifies the usage ledger. |
| `doctor` | Diagnose what this binary can do on the current host. |
| `completions` | Print a shell-completion script for the requested shell. |
| `version` | Print the version line. Synonym for `--version`. |

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
`{"path":"...","valid":true}`; an invalid one prints
`{"error":"...","path":"...","valid":false}` and still exits 2. The
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
refuse on drift.

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
optionally overrides the baseline with `SB_APPLY_BASELINE`.

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

### `doctor` - what can this binary do on this host

Prints a host-capability report: the capability features the binary
was compiled with, the GPUs the local model host would see (same probe
as the `serve:` admission path, so the two can never disagree), which
inference engine binaries (`vllm`, `llama-server`) resolve on `PATH`,
the default model-weight cache directory, and a final verdict on
whether a `serve:` provider could admit a model on this host, with
every blocker listed when it could not.

```bash
sbproxy doctor
sbproxy doctor --format json
```

Collection is read-only: no engine starts, nothing is written. The
released binary ships with GPU discovery compiled in and loads the
NVIDIA driver library at runtime (falling back to `nvidia-smi`), so
the same artifact reports "ready" on a GPU host and lists what is
missing everywhere else. Always exits 0 once the report is produced;
"this host cannot serve local models" is a finding, not an error. See
[model-host.md](model-host.md) for the `serve:` block itself.

The same host state is checked at startup and on every hot reload:
when a loaded config declares `serve:` but the host is missing a
prerequisite (no visible GPU, or a serve entry whose engine has no
binary and no container runtime), the proxy logs a warning naming the
model, the resolved engine, and the blocker. Requests still degrade
gracefully (admission rejects, the attempt fails over to the next
provider), but the gap surfaces when the config lands instead of on
the first request.

#### Engine acquisition

sbproxy acquires inference engines itself; a bare box serves without a
manual install. When a `serve:` entry needs an engine, the runtime
resolves it in this order:

- **A binary already on `PATH` wins.** If `llama-server` (or `vllm`)
  resolves on `PATH`, sbproxy uses it. This is also the escape hatch
  for custom builds: put a CUDA-built `llama-server` on `PATH` and it
  takes over with no config change.
- **llama.cpp** (GGUF models): sbproxy fetches a pinned ggml-org
  prebuilt release for the host platform (a fixed tag, never `latest`,
  with an optional sha256 to verify). No compiler or build step on the
  box. An explicit `acquire.source: path` pins an operator-provided
  binary instead.
- **vLLM** (safetensors): vLLM is a Python package, not a binary, so
  sbproxy fetches `uv` (Astral's single static binary, also a pinned
  release) and runs vLLM through `uv tool run`, a.k.a. `uvx`. uv
  provisions and caches the environment, including its own Python, on
  first use. Opt in with `engines.vllm.acquire.source: uvx`; `sbproxy
  run <model>` sets it for you.

GPU drivers are never installed by sbproxy; a missing driver is
reported with guidance only. See [model-host.md](model-host.md) for
the `serve:` block, per-engine details, and host prerequisites.

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
by the current binary:

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

SBproxy initializes subsystems in a fixed order. A config or pipeline
compile error aborts startup; most optional subsystems (telemetry, key
plane, enterprise hooks) log and degrade instead of blocking.

1. **Config load and compile**: reads the single YAML file named by
   `--config` / `SB_CONFIG_FILE`, interpolates `${ENV}` references, and
   compiles it. A compile error is fatal.
2. **Observability wiring**: applies the metrics cardinality limiter
   (`proxy.metrics`), the log redaction state
   (`proxy.observability.log.redact`), per-tenant cardinality caps, and
   the declared log sinks.
3. **Scripting limits**: installs the Lua sandbox budgets from
   `proxy.scripting.lua.sandbox`.
4. **AI provider catalog**: loads the embedded provider catalog, or the
   override file named by `proxy.ai_providers_file` when readable.
5. **Rate-limit budgets, key plane, session ledger**: installs the
   workspace rate-limit budget registry, the dynamic key plane
   (`proxy.key_management`), and the session-ledger sink when enabled.
   These keep accumulated state across reloads.
6. **Detection singletons**: installs the agent-class resolver, the
   TLS-fingerprint catalogue, and the agent-detect scorer.
7. **Pipeline compile**: builds the routing pipeline (origins, actions,
   auth, policies) and loads `listings/*.yaml` from the config file's
   directory. A pipeline compile error is fatal.
8. **Hot reload**: stores the pipeline in the hot-reload slot, starts
   the config file watcher, and installs the SIGHUP handler.
9. **TLS**: initializes TLS state when `https_bind_port`,
   `tls_cert_file`, or an enabled `proxy.acme` block is present.
10. **Listeners**: creates the Pingora server (worker count from
    `SB_WORKER_THREADS` or auto-detection), binds the plain HTTP
    listener on `http_bind_port`, and adds the HTTPS listener (manual
    certs or the ACME dynamic-certificate resolver, with optional
    mTLS). No QUIC port is bound even when `proxy.http3` is
    configured; an enabled `http3` block only logs a warning.
11. **Admin server**: when `proxy.admin.enabled: true`, spawns the
    embedded admin listener (default `127.0.0.1:9090`) and registers
    the component health probes that `/readyz` and `/health` report.
12. **Background tasks**: starts the ACME renewal and OCSP-stapling
    refresh tasks when TLS is active, then hands control to Pingora's
    run loop.

Startup progress is visible in the log; the listener bind is announced
with a line like:

```
INFO starting sbproxy on 0.0.0.0:8080
```

### Signal handling

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown (drain in-flight requests up to the grace budget) |
| `SIGINT` (Ctrl+C) | Fast shutdown (drop in-flight requests immediately) |
| `SIGHUP` | Full config reload: recompile the YAML and hot-swap the pipeline |

Pingora handles SIGTERM and SIGINT itself; SBproxy subscribes to the
server's execution-phase broadcast and mirrors each phase into
structured tracing events (`shutdown_signal_received` on a graceful
SIGTERM, then `shutdown_started`, `shutdown_grace_period`,
`shutdown_runtimes`, and finally `shutdown_complete`) so operators can
confirm the drain started and finished.

### Graceful shutdown

On `SIGTERM`, SBproxy proceeds as follows:

1. The `shutdown_signal_received` event is logged with
   `signal=SIGTERM` and the resolved `grace_seconds` budget.
2. Pingora stops accepting new connections and waits up to the
   resolved grace budget (`--shutdown-grace-ms`, default 30 seconds)
   for in-flight requests to complete. The budget is applied to both
   Pingora's `grace_period_seconds` and
   `graceful_shutdown_timeout_seconds`.
3. The remaining shutdown phases are logged as they occur; the final
   `shutdown_complete` event marks the point where every listener and
   service runtime has exited.
4. The process exits with code `0` on clean shutdown.

On `SIGINT`, Pingora skips the grace window and tears down listeners immediately; in-flight requests see a connection close. Use this only for fast local-dev shutdowns.

---

## 4. Logging

### One subscriber, two targets

SBproxy logs through a single `tracing` subscriber. Application events
(lifecycle, config, errors) go to the default targets; per-request
access-log lines go to the dedicated `access_log` target so log
routers can split the two without extra plumbing.

The output format is `compact` by default (one short line per event).
Switch with `--log-format pretty` for local debugging or
`--log-format json` for a log aggregator; the env fallback is
`SB_LOG_FORMAT`.

### Log levels and filters

The filter is a standard `tracing-subscriber` directive: a bare level
(`info`, `debug`, `trace`, `warn`, `error`) or a per-target filter
string (`sbproxy=debug,h2=warn`).

- `--log-level` / `SB_LOG_LEVEL` sets the global filter (wins over
  `RUST_LOG`; default `info`).
- `--request-log-level` / `SB_REQUEST_LOG_LEVEL` appends an
  `access_log=<level>` directive so access logs can be tuned
  independently of the application log:

```bash
# Quiet application log, verbose request log
sbproxy serve -f sb.yml --log-level warn --request-log-level debug
```

The same knobs exist in YAML under `proxy.observability.log`, which
also carries per-level sampling, redaction, sink fan-out, and custom
access-log fields. CLI and env win over the YAML values.

```yaml
proxy:
  observability:
    log:
      level: info        # debug | info | warn | error
      format: compact    # compact | pretty | json
```

At runtime, the filter can be changed without a restart through the
admin API: `PUT /admin/log-level` with `{"level": "debug"}` (see
[admin-api-reference.md](admin-api-reference.md)).

### Access logs

Structured JSON access logging is opt-in via the top-level
`access_log` block. The full record schema (phase timings, AI token
fields, header capture) and the filter semantics live in
[access-log.md](access-log.md); the two knobs most deployments touch
are sampling and the output sink:

```yaml
access_log:
  enabled: true
  sample_rate: 0.01
  always_log_errors: true
  slow_request_threshold_ms: 1000
```

`always_log_errors` and `slow_request_threshold_ms` force matching
requests through before the sampler runs.

By default, access-log lines are emitted via the `access_log` tracing
target. To write them directly to a rotating file instead:

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

The proxy serves `/metrics` on its main HTTP port (`http_bind_port`, default `8080`). When the embedded admin server is enabled, the same series are mirrored on the admin listener so operators can scrape through the access-controlled port instead. Scrapes are not throttled.

```
GET http://localhost:8080/metrics
```

Label cardinality is capped by `metrics.max_cardinality_per_label` (default `1000`). The `hostname` label uses its ADR budget by default and can be overridden with `metrics.cardinality.hostname_cap`. Values past the effective cap collapse into the literal `__other__`.

#### Hostname-scoped metrics

| Metric | Type | Labels |
|--------|------|--------|
| `sbproxy_requests_total` | Counter | `hostname`, `method`, `status`, `agent_id`, `agent_class`, `agent_vendor`, `payment_rail`, `content_shape` |
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
| `sbproxy_policy_triggers_total` | Counter | `origin`, `policy_type`, `action`, `agent_id`, `agent_class` |
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

SBproxy exports distributed traces via OTLP. Configure in `sb.yml`:

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

SBproxy serves probe endpoints on two listeners. The main data plane
(`http_bind_port`, default `8080`) always serves a minimal `/health`
plus `/metrics`. The embedded admin listener (`proxy.admin`, default
`127.0.0.1:9090`) serves the full probe set unauthenticated, alongside
its authenticated operator routes. All responses are
`application/json`.

### Endpoints

| Endpoint        | Listener | Aliases    | Purpose                | Success | Failure |
|-----------------|----------|-----------|-------------------------|---------|---------|
| `/health`       | data plane | (none)  | Liveness; fixed body     | `200`   | never   |
| `/livez`        | admin    | `/live`   | Liveness; process is up  | `200`   | never   |
| `/readyz`       | admin    | `/ready`  | Readiness; ready to serve | `200`   | `503`   |
| `/healthz`      | admin    | (none)    | Liveness; trivial body   | `200`   | never   |
| `/health`       | admin    | (none)    | Rich operator health     | `200`   | `503`   |

The bare `/live` and `/ready` aliases return identical bodies to
`/livez` and `/readyz`. On the admin listener, `/health` is the rich
operator/SIEM endpoint; on the data plane it is a fixed liveness body
(`{"status":"ok"}`) suitable for load balancers that can only probe
the serving port. K8s readiness probes should hit `/readyz` and
liveness probes `/livez` when the admin listener is reachable from
the kubelet; otherwise use the data plane's `/health` for both (see
[section 12](#12-kubernetes-deployment)).

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

### `/health` (admin listener)

Rich health report for humans, dashboards, and SIEM ingestion. It
includes the binary version, embedded git revision, current timestamp,
process uptime, and the same component checks used by readiness:

```json
{
  "status": "ok",
  "version": "1.5.0",
  "build_hash": "5e8cfa8",
  "timestamp": "2026-05-04T18:30:00Z",
  "uptime_seconds": 12345,
  "checks": [
    {"name": "ledger", "status": "healthy"},
    {"name": "mesh_quorum", "status": "not_configured", "detail": "mesh not enabled"}
  ]
}
```

When any readiness component is unhealthy, `/health` returns `503` and
the top-level `status` is `"unready"`. `/healthz` remains a fixed-size
liveness response for load balancers.

### `/readyz`

Walks the registered component readiness probes (agent registry,
bot-auth key directory, usage ledger, mesh quorum, synthetic pipeline
probe, etc.) and returns `200` only when every probe reports ready
(`healthy`, `degraded`, and `not_configured` all count as ready). The
body's `components` field is an array, sorted by component name, so a
dashboard can surface which component failed:

```json
{
  "status": "ok",
  "components": [
    {"name": "agent_registry", "status": "healthy"},
    {"name": "ledger", "status": "not_configured", "detail": "no ledger append yet"}
  ]
}
```

When a component is `unhealthy`, the envelope's `status` flips to
`"unready"` and the response is `503`:

```json
{
  "status": "unready",
  "components": [
    {"name": "agent_registry", "status": "healthy"},
    {"name": "mesh_quorum", "status": "unhealthy", "detail": "isolated: 0 of 1 min peers alive"}
  ]
}
```

The set of components depends on which features the live config
enabled; a deployment with no mesh or ledger reports those probes as
`not_configured` rather than dropping them.

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

Unhealthy targets drop out of rotation. Per-target health state is exposed through the admin API's `GET /api/health/targets` route (see [admin-api-reference.md](admin-api-reference.md)); there is no per-target Prometheus metric.

### Component registration

Subsystems register named health probes with the health registry. The registered names appear in `/readyz`'s `components` array and `/health`'s `checks` array. Components report `"healthy"`, `"degraded"`, `"unhealthy"`, or `"not_configured"` status strings; only `"unhealthy"` fails readiness.

---

## 7. TLS and certificates

### Manual TLS

Provide a PEM certificate chain and key as file paths under `proxy`.
Setting `https_bind_port` requires either the manual pair or an
enabled `acme` block:

```yaml
proxy:
  https_bind_port: 8443
  tls_cert_file: certs/server-cert.pem
  tls_key_file: certs/server-key.pem
```

The HTTPS listener negotiates HTTP/2 and HTTP/1.1 via ALPN. There are
no YAML knobs for minimum TLS version or cipher suites; the rustls
defaults apply.

### ACME auto-TLS

SBproxy works with any ACME-compatible certificate authority; the
default directory is Let's Encrypt production. Certificates are issued
per hostname in the config, stored in the configured backing store,
and renewed automatically. Until the first issuance completes, the
listener serves a self-signed fallback certificate so handshakes do
not fail outright. Issued and renewed certificates are swapped in live
via SNI, with no restart.

```yaml
proxy:
  http_bind_port: 8080
  https_bind_port: 8443
  acme:
    enabled: true
    email: ops@example.com
    # directory_url: https://acme-v02.api.letsencrypt.org/directory
    # challenge_types: ["http-01"]
    # storage_backend: redb
    # storage_path: /var/lib/sbproxy/certs
    # renew_before_days: 30
```

Field reference:

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Master switch for ACME-managed certificates |
| `email` | (empty) | Account contact registered with the ACME directory |
| `directory_url` | Let's Encrypt production | ACME directory URL |
| `challenge_types` | `["http-01"]` | Allowed challenge types in priority order. `http-01` is the only type the proxy drives today; `tls-alpn-01` parses but is not served |
| `storage_backend` | `redb` | Backing store for issued certificates |
| `storage_path` | `/var/lib/sbproxy/certs` | Filesystem path for the certificate store |
| `renew_before_days` | `30` | Days before expiry to attempt renewal |

The `http-01` challenge is answered on the plain HTTP listener, so
keep `http_bind_port` reachable from the CA. For Let's Encrypt
staging, point `directory_url` at
`https://acme-staging-v02.api.letsencrypt.org/directory`. The Docker
Compose stack ships a Pebble test CA for local development
(`https://pebble:14000/dir`).

### Mutual TLS (mTLS) for inbound connections

To require clients to present certificates when connecting to SBproxy,
add a `proxy.mtls` block. It applies to the HTTPS listener (manual
certs or ACME) and requires `https_bind_port`:

```yaml
proxy:
  https_bind_port: 8443
  tls_cert_file: certs/server-cert.pem
  tls_key_file: certs/server-key.pem
  mtls:
    client_ca_file: certs/ca-cert.pem
    require: true
    allowed_cn_patterns:
      - "^service-[a-z]+$"
```

Field reference:

| Field | Default | Description |
|-------|---------|-------------|
| `client_ca_file` | (required) | PEM CA bundle used to verify client certificates |
| `require` | `true` | When `true`, the handshake fails without a valid client cert. When `false`, certless clients connect and the upstream sees `X-Client-Cert-Verified: 0` so it can decide |
| `allowed_cn_patterns` | `[]` | Regex allowlist for the client certificate CN. Empty accepts any CN signed by the CA |

Verified client-certificate metadata is forwarded to the upstream as
`X-Client-Cert-*` headers.

### Generating development certificates

The repository includes a script that generates a local CA, a server
certificate, and a client certificate for development and mTLS
testing:

```bash
./scripts/generate-certs.sh
# Generates in ./certs/:
#   ca-cert.pem, ca-key.pem
#   server-cert.pem, server-key.pem
#   client-cert.pem, client-key.pem
```

---

## 8. Connection tuning

Upstream connection behavior is tuned per origin with a single
`connection_pool` block, placed at the origin level alongside the
`action` block.

![ten concurrent requests completing over a bounded upstream pool, per-request timing shown](assets/connection-pool.gif)

A 32-connection pool with idle and lifetime caps absorbs the burst ([config](../examples/connection-pool/)).

### Per-origin connection pool

| Field | Default | Description |
|-------|---------|-------------|
| `max_connections` | `128` | Maximum concurrent connections to the upstream. Additional requests queue until a connection frees up |
| `idle_timeout_secs` | `90` | Idle keep-alive connections unused for longer than this are dropped from the pool |
| `max_lifetime_secs` | `300` | Hard ceiling on any single connection's lifetime; older connections are replaced even when healthy |

```yaml
origins:
  "api.example.com":
    connection_pool:
      max_connections: 32
      idle_timeout_secs: 60
      max_lifetime_secs: 300
    action:
      type: proxy
      url: https://backend.internal
```

Tune these when an upstream is sensitive to concurrent connection
count, or when a load balancer aggressively terminates long-lived TCP
sessions. Origins without a `connection_pool` block get the defaults
above. There are no other per-origin transport knobs; buffer sizes and
handshake timeouts follow Pingora's defaults.

### HTTP/3 (QUIC)

HTTP/3 is temporarily disabled until native QUIC support lands in
Pingora. The `proxy.http3` block still parses, but it is ignored: no
QUIC listener is started, no `Alt-Svc` header is advertised, and
setting `enabled: true` only logs a warning at startup. HTTP/2 is the
highest version served. The fields are documented for when HTTP/3
returns:

```yaml
proxy:
  http3:
    enabled: true          # currently ignored; logs a warning
    idle_timeout_secs: 30
    max_streams: 100
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Whether to start the HTTP/3 (QUIC) listener. Currently inert |
| `idle_timeout_secs` | `30` | Idle timeout for QUIC connections |
| `max_streams` | `100` | Maximum concurrent QUIC streams per connection |

---

## 9. Hot reload

### File watcher

SBproxy watches the directory containing the configuration file via `notify`. Every modify, create, or remove event in that directory triggers a reload of the config file; there is no debounce window. Back-to-back editor writes produce back-to-back reloads, which is harmless: each reload atomically swaps the compiled pipeline, and a failed compile leaves the previous pipeline serving.

### SIGHUP trigger

Send `SIGHUP` to manually trigger a configuration reload without modifying any file:

```bash
kill -HUP $(pgrep sbproxy)
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

Every reload path (SIGHUP, file watcher, `sbproxy apply`,
`POST /admin/reload`) runs the same primitive: recompile the YAML and
atomically swap the live pipeline. That covers most of the config
surface:

| Change Type | Reload Behavior |
|-------------|-----------------|
| Origins: routing, upstream URLs, actions, auth, policies | Hot-reloaded; the new pipeline serves the next request |
| AI provider catalog (`proxy.ai_providers_file`) | Hot-reloaded |
| Agent classes, detection settings, key management, log redaction, sinks, Lua sandbox limits | Hot-reloaded |
| Listener and server-level settings: `http_bind_port`, `https_bind_port`, TLS listener shape, `proxy.admin`, worker threads | Requires process restart |
| Rate-limit budget accumulators, session-ledger sink registration | Registered at startup; state survives reloads, registration changes need a restart |

The runtime log filter is not part of config reload; change it with
`--log-level` at start or `PUT /admin/log-level` at runtime.

When a reload completes, the log includes the line `config reloaded
successfully`, and the `sbproxy_config_reload_total{result="success"}`
counter increments. If the reload fails (for example, malformed YAML),
the watcher logs `reload failed; serving prior pipeline` with the
error, `sbproxy_config_reload_total{result="failure"}` increments, and
the previous configuration stays active.

---

## 10. Feature flags

Feature flags are per-request hints that alter proxy behavior. Clients inject them via a request header or query parameters, and CEL expressions and Lua scripts read them through the `features` namespace.

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

Mount a config directory containing `sb.yml` and map ports; the image's default command is `serve -f /etc/sbproxy/sb.yml`. The container exposes `8080/tcp`, `8443/tcp`, and `8443/udp` (UDP will be required for HTTP/3 QUIC when HTTP/3 returns; HTTP/3 is currently disabled, so the UDP mapping is presently unused).

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

For a read-only config with a writable ACME certificate store (the default `proxy.acme.storage_path` is `/var/lib/sbproxy/certs`):

```bash
docker run -d \
  --name sbproxy \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 8443:8443/udp \
  -v /etc/sbproxy/sb.yml:/etc/sbproxy/sb.yml:ro \
  -v sbproxy-acme-certs:/var/lib/sbproxy/certs \
  -e SB_LOG_LEVEL=info \
  ghcr.io/soapbucket/sbproxy:latest
```

### Docker Compose stack

The repository ships a Docker Compose stack for local development at
[`docker/docker-compose.yml`](../docker/docker-compose.yml). It runs
six services on a shared bridge network:

- **sbproxy**: the proxy itself, built from the repository and started
  with the stack's `docker/sb.yml`, ports `8080` and `8443` mapped.
- **pebble**: a Let's Encrypt Pebble test ACME server for exercising
  the ACME issuance path locally (directory on port `14000`).
- **redis**: shared-state backend for the L2 cache and distributed
  rate limiting.
- **prometheus**: scrapes the proxy using `docker/prometheus.yml`
  (port `9090`).
- **grafana**: dashboards with anonymous admin access for local use,
  pre-provisioned with the Prometheus datasource (port `3000`).
- **jaeger**: all-in-one trace backend with OTLP intake on `4317` and
  the UI on `16686`.

Start and stop the stack:

```bash
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml down
```

### Building the Docker image

```bash
make docker
# Equivalent to:
docker build -f Dockerfile.cloudbuild -t sbproxy:dev .
```

The image uses a multi-stage build: the builder stages compile the
binary and the embedded admin UI, and the final image is
`gcr.io/distroless/cc-debian12`, with no shell or package manager. The
default command is `serve -f /etc/sbproxy/sb.yml`, so mounting a
config at that path is all a derived deployment needs.

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
          image: ghcr.io/soapbucket/sbproxy:1.5.0
          args: ["serve", "-f", "/etc/sbproxy/sb.yaml"]
          env:
            - name: SB_LOG_LEVEL
              value: info
            - name: SBPROXY_SHUTDOWN_GRACE_MS
              value: "30000"
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
          volumeMounts:
            - name: config
              mountPath: /etc/sbproxy
              readOnly: true
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /health
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

### Probes

The example above probes `/health` on the serving port (`8080`), which
returns a fixed `200` whenever the process is up. That is the simplest
working configuration and needs nothing beyond the default config.

The richer `/livez` and `/readyz` endpoints live on the embedded admin
listener, not the serving port. To use them as probes, enable the
admin server and make it reachable from the kubelet: set
`proxy.admin.enabled: true`, `bind: "0.0.0.0"`, and an `allow_ips`
list covering the node network (the probe endpoints themselves are
unauthenticated, but the admin listener's IP allowlist applies to
every connection). Then point the probes at port `9090`:

```yaml
livenessProbe:
  httpGet:
    path: /livez
    port: 9090
readinessProbe:
  httpGet:
    path: /readyz
    port: 9090
```

`/readyz` folds in the registered component probes (ledger, mesh
quorum, synthetic pipeline), so it can take a pod out of rotation on a
component failure instead of only on process death. See
[section 6](#6-health-checks).

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
      acme:
        enabled: true
        email: ops@example.com
        # The config mount is read-only; point the certificate
        # store at a writable volume (an emptyDir loses certs on
        # pod restart, a PVC keeps them).
        storage_path: /var/lib/sbproxy/certs

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

The binary reads ten environment variables, most of them fallbacks for
CLI flags. Variables are applied at process start; changes require a
restart.

| Variable | CLI Flag | Default | Description |
|----------|----------|---------|-------------|
| `SB_CONFIG_FILE` | `-f`, `--config` | (empty) | Path to `sb.yml`. Required if no flag and no positional arg. |
| `SB_LOG_LEVEL` | `--log-level` | `info` | Filter for `tracing-subscriber`. Wins over `RUST_LOG`. |
| `SB_LOG_FORMAT` | `--log-format` | `compact` | Output format for the tracing subscriber: `compact`, `pretty`, or `json`. |
| `SB_REQUEST_LOG_LEVEL` | `--request-log-level` | (unset) | Appends an `access_log=<level>` target filter for request/access logs. |
| `SBPROXY_SHUTDOWN_GRACE_MS` | `--shutdown-grace-ms` | `30000` | SIGINT/SIGTERM drain budget in milliseconds. Wins over `SB_GRACE_TIME`. |
| `SB_GRACE_TIME` | `--grace-time` | (unset) | Legacy Pingora grace period and shutdown timeout in seconds. Superseded by `SBPROXY_SHUTDOWN_GRACE_MS`. |
| `SB_WORKER_THREADS` | (none) | (auto) | Override the auto-detected Pingora worker thread count. Positive integers only. |
| `SB_DISABLE_SB_FLAGS` | `--disable-sb-flags` | `false` | Lock off the per-request `x-sb-flags` surface. Accepts `1`, `true`, `yes`, `on`. |
| `SB_APPLY_CONFIG` | (none) | (unset) | Path to the proposed YAML used by `sbproxy apply -p <plan-file>`. Required for the `-p` flow because the plan file does not embed the YAML path. |
| `SB_APPLY_BASELINE` | (none) | (unset) | Optional baseline override for `sbproxy apply -p`. When set, apply compares the plan's recorded baseline revision against this YAML's revision; otherwise the empty config is the baseline. |

In addition, the standard `RUST_LOG` env var is honoured when neither
`--log-level` nor `SB_LOG_LEVEL` is set.

### OpenTelemetry configuration

SBproxy does not read the standard `OTEL_*` SDK environment variables.
The OTLP exporter (endpoint, transport, service name, sampling,
resource attributes) is configured entirely in YAML under
`proxy.observability.telemetry`; see
[section 5](#5-metrics-and-observability).

### Quick reference - common configurations

Minimal production startup:

```bash
SB_CONFIG_FILE=/etc/sbproxy/sb.yml \
SB_LOG_LEVEL=info \
SBPROXY_SHUTDOWN_GRACE_MS=30000 \
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
  -e SBPROXY_SHUTDOWN_GRACE_MS=30000 \
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
