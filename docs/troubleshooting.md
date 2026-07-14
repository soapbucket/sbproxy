# Troubleshooting
*Last modified: 2026-07-11*

When something breaks, this is the first place to look. Each section is one failure: the symptom, the likely cause, and the fix. For *why* these things happen, see [architecture.md](architecture.md); for what the proxy does on its own while a dependency is down, see [degradation.md](degradation.md); for the dashboard-to-action triage flow, see [operator-runbook.md](operator-runbook.md).

Jump by symptom:

| Symptom | Section |
|---|---|
| A config key does nothing | [A config setting seems to be ignored](#a-config-setting-seems-to-be-ignored) |
| 404 on every request | [404, origin not found](#404-origin-not-found) |
| 502 on one origin | [Clients get 502 Bad Gateway](#clients-get-502-bad-gateway) |
| Errors come in bursts, then pause | [A circuit breaker keeps opening](#a-circuit-breaker-keeps-opening) |
| Config edits don't take effect | [Hot reload did not pick up changes](#hot-reload-did-not-pick-up-changes) |
| A config change made things worse | [Rolling back a bad config change](#rolling-back-a-bad-config-change) |
| AI routes erroring | [AI requests fail with provider error](#ai-requests-fail-with-provider-error) |
| Unexpected 429s | [Rate limiter rejecting requests unexpectedly](#rate-limiter-rejecting-requests-unexpectedly) |
| High latency | [Requests are slow](#requests-are-slow) |
| No access-log lines | [No access-log lines appear](#no-access-log-lines-appear) |
| Prometheus scrape empty or failing | [The metrics endpoint returns an empty body](#the-metrics-endpoint-returns-an-empty-body) |
| No traces in the backend | [Traces never arrive at the collector](#traces-never-arrive-at-the-collector) |
| Admin port dead or 401/403 | [The admin server is unreachable or rejects you](#the-admin-server-is-unreachable-or-rejects-you) |
| Dashboards empty | [Grafana dashboards show no data](#grafana-dashboards-show-no-data) |
| Cluster limits or shared cache misbehaving | [Redis went down and cluster behavior changed](#redis-went-down-and-cluster-behavior-changed) |
| TLS errors | [TLS handshake fails](#tls-handshake-fails) |
| Cert expiring, renewal not happening | [ACME renewal is failing](#acme-renewal-is-failing) |
| No HTTP/3 | [HTTP/3 requests fall back to HTTP/2](#http3-requests-fall-back-to-http2) |
| Local model never becomes ready | [A local model will not serve](#a-local-model-will-not-serve) |
| Cluster node unhealthy or placement differs | [The model cluster does not converge](#the-model-cluster-does-not-converge) |
| Example compose stack broken | [An example docker compose stack will not start](#an-example-docker-compose-stack-will-not-start) |

## A config setting seems to be ignored

You set a config key and nothing changes.

Where the key sits decides what happens:

- A misspelled or misplaced key nested inside `proxy:`, an origin, or a security block is a hard failure: boot and `sbproxy validate` both reject the config and print the full key path, for example `unknown or misspelled config key(s): origins.api.example.com.forward_rules.0.rules.0.user_agent`. If the proxy is running at all, no nested key in the loaded file is being silently ignored.
- A misspelled top-level key (a sibling of `proxy:` and `origins:`) is dropped with a boot-time warning, and everything under it takes defaults. This is the usual way a whole feature block "does nothing": `key_management:` at the top level instead of nested under `proxy:` leaves the feature off.

Check:
- Run `sbproxy validate sb.yml`. Nested unknown keys fail the run; dropped top-level keys print the same `ignored unknown/misspelled top-level key(s)` warning the server logs.
- Grep the boot log for `ignored unknown/misspelled top-level key(s)`.
- Compare the key against `schemas/sb-config.schema.json`, the generated source of truth for every valid key and its nesting.
- Out-of-tree blocks belong under `proxy.extensions:` (or an origin's `extensions:`); that is the one place unrecognized keys are expected and passed through.

## 404, origin not found

The `Host` header on the request does not match any configured origin.

Check:
- Run `sbproxy validate --config sb.yml` to confirm the config parses.
- Confirm the request's `Host` header matches the origin name exactly, including any port suffix.
- SBproxy uses a bloom filter for fast hostname lookup. If you just added an origin via hot reload, wait a second and retry.
- These 404s land in `sbproxy_requests_total` under the client-supplied hostname (the cardinality limiter collapses excess values into `__other__`) and in the access log with `error_class: "not_found"`, so a flood of them is visible: it is usually a DNS record pointing at the proxy for a hostname you never configured, or scanning traffic.

## Clients get 502 Bad Gateway

The upstream behind that origin is unreachable: connect refused, DNS failure, timeout, or the retry chain exhausted itself against 5xx responses.

Check:
- Look at the access-log line for the failed request. A missing `upstream_ttfb_ms` field means the proxy never got a first byte from the upstream, so the failure was at connect time, not a slow backend. A present `upstream_status` shows what the upstream actually said before a retry or fallback rewrote it.
- Curl the upstream directly from the proxy host. If that fails too, the backend or the network path is down and the proxy is reporting it accurately.
- Confirm `sbproxy_requests_total{hostname="...",status="502"}` is rising for one origin only. If every origin is failing at once, suspect DNS or an egress network change instead of one dead backend.
- If the origin is a `load_balancer`, check which targets are ejected via `GET /api/health/targets` on the admin server. Active health checks, outlier detection, and the circuit breaker each eject targets independently; with every target ejected the LB falls back to the unfiltered list rather than failing the client.
- Give the origin `retry` (connect errors and 502/503 are retryable), and consider a `fallback_origin` block so callers get a degraded response instead of the 502 while the upstream heals. See [degradation.md](degradation.md) and `examples/fallback-origin/`.

## A circuit breaker keeps opening

Errors arrive in bursts separated by quiet periods: the breaker trips on consecutive failures, holds requests off the target for `open_duration_secs`, lets a few probes through in HalfOpen, then trips again because the target is still bad.

Check:
- `sbproxy_circuit_breaker_transitions_total{origin,from_state,to_state}` tells you how often and in which direction the breaker is moving. A steady `open -> half_open -> open` cycle means the upstream never actually recovered.
- Fix the upstream, or if a recent origin config change caused the failures, roll it back and watch the transitions stop.
- Do not just raise `failure_threshold` to quiet the breaker; that trades fast isolation for more client-visible failures. Tune `open_duration_secs` and `success_threshold` if the defaults recover too slowly for your workload.

## Hot reload did not pick up changes

Usually one of: file watcher debounce, ConfigMap symlink swap, or a validation failure.

Check:
- A config with a validation error gets logged and rejected. The old config keeps running. Run `sbproxy validate --config sb.yml` to see the error.
- The file watcher reacts to in-place writes. Saves that replace the file by atomic rename (many editors, `sed -i`, and Kubernetes ConfigMap symlink swaps) may not be detected. After a ConfigMap update, send `SIGHUP` or restart the pod to force the reload.
- The `agent_classes`, `agent_detect`, and `tls_fingerprint` installers are applied at startup and re-applied on every hot reload; each swaps its live state atomically, so changes to those blocks take effect without a restart.
- Watch `sbproxy_config_reload_total{result}`: a rising `failure` count or a stalled `success` cadence is the reload path telling you it is stuck.

## Rolling back a bad config change

Traffic degraded right after a config rollout and you need the old behavior back now.

Check:
- Revert `sb.yml` to the last-good revision, then send `SIGHUP` or `POST /admin/reload`. Validation runs first and a config that fails validation is rejected while the old pipeline keeps serving, so a rushed rollback cannot take the proxy down.
- Before re-applying, `sbproxy plan -f sb.yml --against last-good.yml` prints the added, changed, and removed origins with a max-blast-radius line. Exit code 0 means no-op, 2 means changes present, 3 means semantic errors. Wire it into CI so oversized diffs stop before they ship.
- One thing hot reload deliberately does not reset: the AI budget accumulators. Budget windows are wall-clock-relative, so a reload (or rollback) does not zero already-spent budget. There is no admin endpoint for resetting a budget; to zero one intentionally, restart the process.
- On Kubernetes, `helm history sbproxy` and `helm rollback` walk the same ladder at the deployment layer; [operator-runbook.md](operator-runbook.md) has the exact commands.

## AI requests fail with provider error

Check in order:
1. Confirm the provider API key is set correctly. Check the `api_key` field or the environment variable it references.
2. Run `sbproxy validate --config sb.yml` to confirm the provider block parses correctly.
3. Check the structured log for `provider` and `status_code` fields on the failed request.
4. If using a fallback chain, check that at least one provider in the chain has available capacity. The log will show which provider was attempted last.
5. If the error is "context window exceeded," the requested model does not support the token count in the prompt. Add a model with a larger context window to the provider list.
6. `sbproxy_ai_provider_errors_total{provider,error_kind}` splits the failures into transport, timeout, 4xx, 5xx, and parse classes, and `sbproxy_ai_failovers_total` shows whether the routing chain is absorbing them.

## Rate limiter rejecting requests unexpectedly

Check:
- The `requests_per_second` limit is per-origin, not global. If you have multiple origins sharing an upstream, each origin has its own counter.
- The default token bucket allows short bursts up to `burst` size. A sustained rate above `requests_per_second` will be rejected once the bucket drains.
- If you are testing with many rapid requests, increase `burst` to permit the test pattern.
- Check the structured log for `policy` and `limit` fields to see which rule triggered.

## Requests are slow

SBproxy adds well under 1 ms of overhead under normal load. If you see more, the cause is almost always upstream or DNS.

1. Check `upstream_ttfb_ms` in the structured log. If it's high, the upstream is slow, not SBproxy.
2. If `upstream_ttfb_ms` is low but total latency is high, suspect DNS. Resolved addresses are cached and refreshed in the background by a refreshing resolver, so a request that lands right after a hostname goes stale pays the resolver round trip.
3. Turn on OpenTelemetry tracing (`telemetry` block) to get a per-span breakdown across the phase pipeline.
4. If you have Lua or JavaScript configured, cap runaway scripts with the per-engine sandbox budgets: `proxy.scripting.lua.sandbox.max_execution_ms` and `proxy.scripting.javascript.sandbox.budget_ms`.
5. The `sbproxy_phase_duration_seconds{phase}` histogram (and the matching `auth_ms` / `upstream_ttfb_ms` / `response_filter_ms` access-log fields) splits end-to-end latency into auth, upstream wait, and response transforms, so you can see which phase grew without tracing.

## No access-log lines appear

The access log is off by default. No `access_log` block, no lines; metrics and traces are unaffected.

Check:
- The config has `access_log.enabled: true` at the top level. See [access-log.md](access-log.md).
- `sample_rate: 0.0` disables emission entirely, and low sample rates drop most lines by design. Set `always_log_errors: true` and `slow_request_threshold_ms` so error and slow-request lines bypass the sampler.
- The lines are emitted at info level through the `access_log` tracing target. A log filter like `RUST_LOG=warn` silences them; use `RUST_LOG=warn,access_log=info` (or the `--request-log-level` flag) to keep operator logs quiet while keeping access logs.
- `status_codes` and `methods` filters narrow what gets logged; an empty list matches everything, but a list that omits your test request's method logs nothing for it.
- If you configured `output.type: file`, the lines go to that path, not stdout. Check the file and its rotation suffixes.

## The metrics endpoint returns an empty body

Two harmless-looking behaviors cause most confusion here.

Check:
- `/metrics` is served on the data-plane port (`http_bind_port`, default 8080), not a separate telemetry listener. The admin server exposes a second copy on its own port when enabled.
- Scrapes are rate-limited to one per second; back-to-back requests get an empty body. A curl right after your Prometheus scrape hits this. Wait a second and retry. Scrape intervals of 15s never notice.
- Metrics are per-instance. In a cluster, each process reports only its own counters; aggregate across instances in Prometheus (the bundled dashboards already sum with PromQL).

## Traces never arrive at the collector

Tracing is off by default; the exporter only starts when the telemetry block enables it.

Check:
- `proxy.observability.telemetry.enabled: true` is set and the process was restarted or reloaded after adding it.
- Transport and port agree: `transport: grpc` pairs with collector port 4317, `transport: http` with 4318. A gRPC exporter pointed at an HTTP receiver fails quietly.
- Sampling: with `sample_rate: 0.1`, ninety percent of healthy-traffic traces are dropped on purpose. Set `always_sample_errors: true` so error traces always export, and send a 5xx through the proxy as a test.
- The telemetry block does not expose per-exporter auth headers. For API-key backends (Datadog, Honeycomb, Langfuse Cloud), put an OpenTelemetry Collector in the middle and let it attach credentials. [observability.md](observability.md) has the verified backend matrix and Collector snippets.
- The reference Compose stack in `examples/observability-stack/` receives OTLP on host port 4327 (not 4317, which Tempo owns there).

## The admin server is unreachable or rejects you

The admin server is off by default, binds loopback only, and authenticates everything except the health probes.

Check:
- `proxy.admin.enabled: true` is set. Without it there is no admin listener at all.
- From another machine you need `bind` set to a reachable address and your caller's IP in `allow_ips`. An empty `allow_ips` keeps the loopback-only default even with `bind: 0.0.0.0`.
- A 401 means missing or wrong credentials: HTTP Basic with the configured `username` / `password`, or a browser session from `POST /admin/login`. A 403 on a mutation means your operator has the `read_only` role.
- With `tls` configured, plaintext requests to the port fail. Use `https://` (and `-k` for a self-signed cert).
- The probe routes (`/healthz`, `/health`, `/readyz`, `/livez`) are intentionally unauthenticated; if those work but `/api/requests` gets 401, connectivity is fine and the failure is credentials.
- The web UI at `/admin/ui` only exists in binaries built with the `embed-admin-ui` feature. The API works either way. See [admin.md](admin.md).

## Grafana dashboards show no data

The bundled dashboards under `dashboards/grafana/` render nothing when the datasource reference or the scrape is broken.

Check:
- Prometheus's targets page first. If the `sbproxy` job is down, fix the scrape: the target should be the data-plane port (default 8080) or the admin port, path `/metrics`.
- The dashboard JSON references the datasource as `${DS_PROMETHEUS}`. Importing through the Grafana UI resolves it with a prompt; file-based provisioning does not, so replace the placeholder with your datasource UID (the compose file in `examples/use-case-production-ops/` shows a one-line `sed` doing exactly this). See `dashboards/README.md`.
- Send some traffic. Counters that have never incremented emit no series, and a fresh proxy with zero requests renders empty panels that look broken but are not.
- Alert panels need the recording rules: `dashboards/prometheus/alerts.yml` references series computed by `dashboards/prometheus/recording-rules.yml`, so load both files.

## Redis went down and cluster behavior changed

With `proxy.l2_cache_settings` on Redis, an outage does not stop traffic, but shared state degrades to per-node until it reconnects.

Check:
- Expected during the outage: rate-limit counters go node-local (a multi-replica fleet lets slightly more traffic through a global limit), and response-cache entries written meanwhile stay local. This is the designed fallback behavior; see [degradation.md](degradation.md).
- There is no dedicated Redis metric family; confirm the outage in the logs, where failed Redis operations surface as errors on the rate-limit and cache paths.
- Reconnection is automatic: the client connects lazily and re-establishes the connection on the next operation once Redis is back. There is nothing to restart; fix Redis and the proxy re-attaches.
- Alert on this when running clustered, since the visible symptom (limits slightly leaky, cache hit rate down) is easy to miss.

## TLS handshake fails

Check:
- For ACME auto-cert, confirm `acme.email` is set and the DNS A/AAAA record points at this server. Let's Encrypt needs a successful HTTP-01 or TLS-ALPN-01 challenge.
- For BYO certificates, check that the cert and key paths are readable by the SBproxy process and the cert chain matches the leaf.
- Run `openssl s_client -servername <host> -connect <host>:443` to see the server's offered chain.
- The TLS layer uses `rustls` with the `ring` crypto provider. TLS 1.3 by default with TLS 1.2 fallback.

## ACME renewal is failing

Renewal failures are quiet at first because the existing certificate keeps serving until expiry.

Check:
- The log: every failed issuance or renewal logs an error naming the hostname (`ACME issuance failed`, directory fetch and account-key errors likewise). `sbproxy_acme_renewals_total{result}` counts attempts by outcome.
- The renewal loop re-checks every hostname on a 12 hour cadence (with an immediate first pass at startup), so a transient CA outage heals on a later pass. A renewal that has been failing for days is usually a changed DNS record, a firewall now blocking the challenge port, or an account/rate-limit problem at the CA.
- `sbproxy_cert_expiry_seconds{host}` gauges seconds until each served certificate expires; graph it or alert on it dropping below your comfort window. No bundled alert rule covers cert expiry, so add one to your own rules if you rely on ACME.
- If a listener has no usable cert at all (fresh boot, ACME never succeeded), the proxy serves a self-signed bootstrap cert and logs loudly rather than refusing to start. Clients will see trust errors until the first real issuance lands; that is the visible symptom to chase.

## HTTP/3 requests fall back to HTTP/2

Cause: HTTP/3 is currently disabled until native QUIC support lands in Pingora. The proxy does not start a QUIC listener and does not advertise `Alt-Svc`, so HTTP/2 is the highest version served. Clients that try HTTP/3 fall back to HTTP/2, which is expected.

Check:
- The `proxy.http3` block still parses, but it is inert. Setting `enabled: true` only logs a warning and starts no listener, so the absence of an `Alt-Svc: h3` header on responses is expected.
- If you need a UDP/QUIC path today, terminate HTTP/3 at an upstream edge or CDN and forward HTTP/2 to SBproxy.

## A local model will not serve

A managed deployment commits only after its catalog, artifact, engine, and
capacity checks pass. A failed reload preserves the last good runtime.

Check:
- Run `sbproxy doctor --format json`. It reports visible devices, engines,
  container runtime, cache, and availability as `available`, `acquirable`,
  `incompatible`, or `blocked`.
- Query `sbproxy models ps --format json` with admin credentials. Check the
  deployment's state, `reason_code`, bounded `last_error`, engine availability,
  artifact digest, selected device, and memory breakdown.
- `insufficient_capacity` means the selected device cannot hold weights, KV,
  runtime overhead, and safety margin together. Use a smaller variant, reduce
  context or concurrency, choose `rollout: recreate`, or free device memory.
- `queue_full` and `queue_timeout` are load signals. Adjust queue depth or
  timeout, reduce callers, or configure a fallback provider.
- `engine_unhealthy` and `crash_loop` retain the engine failure. Correct the
  version, runtime, artifact, or driver mismatch, then call
  `POST /admin/model-host/reset` before another load.
- `draining` means stop or replacement is still waiting on active stream
  permits. Check active and queued counts before forcing a process restart.
- Pull policy is per deployment. `manual` needs `sbproxy models pull -f sb.yml`;
  `on_demand` may make the first request wait for a large verified download;
  `on_boot` moves that work into candidate preparation.
- `sbproxy_model_host_deployment_state`, active and queued gauges, admission
  rejection counters, and weight-download timing separate lifecycle, load, and
  artifact failures.

Provider-level `serve:` blocks use the same runtime through compatibility
lowering. New configurations should use `proxy.model_host`. Live NVIDIA
remediation is verified in the final GCP integration PR; see
[model-host-certification.md](model-host-certification.md) before treating a
simulated device test as hardware evidence.

## The model cluster does not converge

Start with the authenticated cluster view, not a single worker log:

```bash
sbproxy cluster status --format json \
  | jq '{summary,nodes,unhealthy_nodes,deployments,deployment_authority}'
```

Check in this order:

- If the process fails at startup, verify unique local gossip and transport
  ports, reachable advertised addresses, and matching `cluster_id`, seeds, CA,
  server name, gossip key, and enrolled files under `state_dir`. The signed
  identity must match the configured node ID, roles, labels, server name, and
  certificate fingerprint. Canonical cluster bind and security failures are
  fatal. A legacy key-cache mesh may fall back locally, but `proxy.cluster`
  never does.
- If key-cache mesh fields are still present, they must exactly match
  `proxy.cluster` node ID, seeds, listeners, advertised addresses, shared key,
  and mTLS fields. Mismatch is rejected so one process cannot split into two
  clusters.
- Inspect `unhealthy_nodes[].reasons` and the matching full `nodes` row.
  `membership_suspect`, `membership_dead`, `snapshot_missing`,
  `snapshot_expired`, `snapshot_unreachable`, incompatible schema, reported health, missing model
  endpoint, engine incompatibility, and zero capacity all make a worker
  ineligible without removing it from the roster.
- Compare `directory_age_ms`, `snapshot_age_ms`, and `last_ack_age_ms` with
  `publish_interval_secs` and `snapshot_ttl_secs`. The snapshot lifetime must
  cover at least two publish intervals. Persistent age growth usually means
  transport reachability or the worker maintenance thread is failing.
- A dead node remains in the admin roster after `dead_peer_gc_secs` removes it
  from routing membership. That retained tombstone is expected; restart the
  same enrolled identity or remove it through a future explicit roster action.
- When `deployment_digest_mismatch` is true in file-managed mode, compare the
  normalized `proxy.model_host` deployment revision on every node. The cluster
  reports drift; it never overwrites a local file.
- For unplaced replicas, inspect each deployment's `rejections`. Fix missing
  labels/endpoints, incompatible variants or engines, insufficient memory, or
  manual-pull cache misses. A replicated homogeneous deployment must pin a
  variant unless `heterogeneous_variants: true` is explicit.
- During rolling replacement, `retained` is expected until all targets report
  exact generation, variant, artifact digest, and ready state. `timed_out: true`
  means `handoff_timeout_ms` elapsed; inspect the target workers before retrying.
- If a generation changes unexpectedly after restart, inspect
  `state_dir/model-deployment-generations.json` and directory permissions. Do
  not delete or copy this file between nodes; it is the local controller's
  monotonic high-water record.
- In cluster-authority mode, verify `deployment_authority.configured`, key ID,
  active revision, signer node, and cursor state. `invalid_bundle`,
  `stale_revision`, `revision_conflict`, and
  `deployment_authority_read_only` are stable admin error codes. Never copy the
  private signing key to a worker to bypass a read-only error.

A partition may temporarily overprovision because each side places only on its
reachable directory. That is an availability tradeoff. It must not produce a
cross-partition eligible route. Remote request dispatch is not part of this PR;
the private model endpoint becomes active only with the distributed data plane.

## An example docker compose stack will not start

The `use-case-*` stacks (and other recent examples) pull the published `soapbucket/sbproxy` image from Docker Hub; some older examples instead build the image from source in the container (`build: ../..`, `Dockerfile.cloudbuild`). Both kinds pull supporting images such as `wiremock/wiremock` from Docker Hub.

Check:
- Look for `pull access denied` or `auth.docker.io ... unexpected EOF` in the compose output. That is a Docker Hub connectivity problem, not an example defect.
- Confirm the daemon is up with `docker info`, and that the host can reach Docker Hub.
- Pre-pull the images (or, for the build-from-source examples, build the `sbproxy` image once) so a later `docker compose up` works from cache.
- The build-from-source examples compile the whole workspace inside the container on first run; a long silent period during `docker compose up` is the Rust build, not a hang.

## Build and run quick reference

```bash
# Debug build
make build                          # -> target/debug/sbproxy
# Release build (required by the e2e harness)
cargo build --release -p sbproxy    # -> target/release/sbproxy
# Validate a config offline before serving
sbproxy validate --config ./sb.yml
# Diff a proposed config against a baseline (exit 0 no-op / 2 changes / 3 errors)
sbproxy plan -f ./sb.yml --against ./last-good.yml
# Run
./target/release/sbproxy serve -f ./sb.yml
```

## Structured log fields reference

The fields below are the ones most useful when triage-grepping the JSON access log. The canonical, exhaustive schema (with optional fields and stability rules) is [access-log.md](./access-log.md); names here mirror that file exactly.

| Field | Meaning |
|---|---|
| `timestamp` | RFC 3339 UTC time of the log line. |
| `origin` | Origin name matched. |
| `method`, `path`, `status` | Request summary. |
| `latency_ms` | End-to-end request duration, milliseconds. |
| `auth_ms`, `upstream_ttfb_ms`, `response_filter_ms` | Phase splits of `latency_ms`; a missing `upstream_ttfb_ms` means the request never reached an upstream. |
| `upstream_status` | Upstream's status when a retry, fallback, or modifier rewrote what the client saw. |
| `client_ip` | Resolved client IP after trusted-proxy unwrapping. |
| `request_id`, `trace_id` | Correlation ids; `trace_id` is set when an OTLP exporter is wired. |
| `cache_result` | `hit`, `miss`, `stale`, or `bypass`. |
| `auth_provider` | Auth method that ran (`api_key`, `jwt`, etc.). |
| `policy_action` | When a policy intervened, the action it took. |
| `provider`, `model` | AI-gateway selection for the request (only on AI requests). |
| `tokens_in`, `tokens_out` | Token counts (only on AI requests). |
