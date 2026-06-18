# Frequently asked questions
*Last modified: 2026-06-08*

Quick answers to the questions operators hit most often when standing up SBproxy, picking between OSS and enterprise, debugging a config that will not load, or wiring observability. For the full reference of any feature, follow the link to the matching doc.

## Install + first run

### How do I install SBproxy?

Pick whichever fits your platform:

```bash
# Linux / macOS, single static binary, no Rust toolchain required:
curl -fsSL https://sbproxy.dev/install.sh | sh

# macOS via Homebrew:
brew install soapbucket/tap/sbproxy

# Docker / Kubernetes:
docker pull soapbucket/sbproxy:latest
```

See [manual.md](./manual.md) for systemd unit files, the Kubernetes manifest, and the Helm chart.

### How do I run SBproxy against my own config?

```bash
sbproxy serve --config sb.yml
```

The only required flag is `--config` (alias `-f`). Run `sbproxy --help` for the full surface; common alternates are `sbproxy validate --config sb.yml` (validate without starting) and `sbproxy version`.

There is no directory-loading mode. The binary reads a single YAML file; compose multi-file configs via your CI or a wrapper script.

### My config will not load. How do I see why?

```bash
sbproxy validate --config sb.yml
```

The validator runs the same schema check the server uses at boot, prints the offending field path plus a one-line explanation, and exits non-zero. JSON output is available via `sbproxy validate --format json sb.yml` for tooling.

See [troubleshooting.md](./troubleshooting.md) for the most common validation errors.

## OSS vs enterprise

### What is in the OSS distribution?

Everything in this repo:

* The full proxy: HTTP/1.1, HTTP/2, websockets, gRPC, GraphQL, MCP.
* The AI gateway: 66 native providers, routing strategies, guardrails, budgets, streaming, semantic cache, virtual keys.
* Every auth provider (API key, Basic, Bearer, JWT, Digest, forward-auth, Web Bot Auth, CAP, OIDC).
* Every policy (rate limit, WAF, IP filter, CORS, HSTS, CSRF, agent budget, content digest, BOLA / `object_authz`, ...).
* Every transform (25 types, including `json`, `template`, `wasm`).
* Scripting via CEL, Lua, JavaScript, and WebAssembly.
* The embedded admin server, the access log, the metrics and tracing wiring, the audit log.
* All examples and dashboards.

### What is enterprise-only?

Three categories: hosted infrastructure, multi-tenant orchestration, and analytics. Concretely:

* The hosted control plane (a managed cluster you point your OSS proxies at).
* The portal: per-workspace dashboards, billing, virtual-key issuance, audit search.
* Long-haul event ingestion (Kafka / NATS, S3 archives, Datadog / Splunk forwarders).
* HSM-backed key custody, SPIFFE workload identity, multi-source entitlements.

See [enterprise.md](./enterprise.md) for the buyer-facing overview.

### Can I run SBproxy in production?

Yes. SBproxy is licensed under the Apache License 2.0, which permits any use, including production and commercial deployment, with no field-of-use restriction.

## Auth + sessions

### Why does my request get a 401 even though I sent the right token?

The most common causes, in order:

1. The auth provider was never matched on the request's `Host`. SBproxy routes by `Host` first; an auth block on `api.example.com` does not apply to a request with `Host: api.test`. Check `sbproxy_auth_results_total{origin}` in metrics to confirm.
2. Trusted-proxy CIDRs are wrong. If SBproxy sits behind another LB, `X-Forwarded-For` headers from outside `proxy.trusted_proxies` are stripped on ingress and the real client IP is the LB. Auth providers that key off the client IP (rate-limit, IP allowlist, OIDC session bind) then see the wrong address.
3. The auth header was stripped by a transform. `headers_to_forward` on the upstream block is an allowlist; auth headers absent from it never reach the upstream. The proxy still validates them locally, but a downstream that re-validates will see nothing.

The structured access log carries `auth_provider` and `auth_ms` for every request; grep those to localise the failure.

### How do I configure OIDC?

`docs/configuration.md` has the full schema; for the minimal case:

```yaml
auth:
  type: oidc
  issuer: https://idp.example.com
  client_id: sbproxy
  client_secret: vault://primary/secret/data/oidc/client?key=client_secret
  cookie_secret: vault://primary/secret/data/oidc/cookie?key=cookie_secret
  authorization_endpoint: https://idp.example.com/authorize
  token_endpoint: https://idp.example.com/oauth/token
  jwks_uri: https://idp.example.com/.well-known/jwks.json
```

`cookie_secret` must be at least 32 bytes. Optional `userinfo_endpoint`, `end_session_endpoint`, and `post_logout_redirect_allowlist` enable the userinfo trust-header projection and RP-initiated logout.

## Observability

### Where are the metrics? How do I scrape them?

The Prometheus endpoint is served by the embedded admin server. Enable it in YAML:

```yaml
admin:
  enabled: true
  port: 9090
```

Then scrape `http://<host>:9090/metrics` from Prometheus. `admin.username` + `admin.password` gate the route via HTTP Basic.

The canonical metric catalog with stability promises is [metrics-stability.md](./metrics-stability.md).

### Where does the access log go?

`stderr` by default, structured JSON, one line per request. Enable via the top-level `access_log:` block; route to a file via stdout/stderr redirection, or to a sink (S3, Kafka, Datadog) via the enterprise build. The full schema is in [access-log.md](./access-log.md).

The log carries phase timings (`auth_ms`, `upstream_ttfb_ms`, `response_filter_ms`) so a slow request reveals which part of the pipeline produced the latency without cross-referencing histograms.

### Where do traces go?

OTLP exporter, configured via `OTEL_EXPORTER_OTLP_ENDPOINT`. The reference Compose stack at `examples/observability-stack/` runs an OTel Collector with Tempo, Grafana, Phoenix, and Langfuse for local development.

## Performance + capacity

### What overhead does SBproxy add per request?

Sub-millisecond p99 at 50k+ rps on commodity hardware for plain proxy paths; AI gateway paths add ~3-5ms for the routing decision and guardrail check, dominated by upstream latency. The `ai-lb-benchmark.md` page has measured P50/P95/P99/P99.9 across every router strategy under skewed load.

### How do I tune SBproxy for high concurrency?

`performance.md` has the operator-facing tuning guide. The two settings that move the needle: `proxy.workers` (defaults to `num_cpus`) and the connection pool sizes per upstream.

## Configuration patterns

### Where are the examples?

`examples/` in this repo, indexed in `examples/README.md`. 119 examples on disk; pick the one closest to your scenario, copy `sb.yml`, and edit from there. Every example validates against the schema and ships with a README plus runnable curl commands.

### How do I run an example against my local SBproxy?

```bash
make run CONFIG=examples/basic-proxy/sb.yml
# In another terminal:
curl -H 'Host: myapp.example.com' http://127.0.0.1:8080/echo
```

The `Host` header is the routing key; example READMEs show the host their `sb.yml` matches on.

## Logs + log level

### How do I get debug logs?

Three knobs, in precedence order:

```bash
sbproxy serve --config sb.yml --log-level debug
SB_LOG_LEVEL=debug sbproxy serve --config sb.yml
RUST_LOG=debug sbproxy serve --config sb.yml
```

Accepted levels: `trace`, `debug`, `info`, `warn`, `error`. Default is `info`. `trace` is firehose-grade and prints every Pingora callback; reserve it for short reproductions.

## See also

* [manual.md](./manual.md) - install, CLI, runtime, TLS, deployment patterns.
* [configuration.md](./configuration.md) - every `sb.yml` field with examples.
* [troubleshooting.md](./troubleshooting.md) - common failure modes and fixes.
* [enterprise.md](./enterprise.md) - the OSS / enterprise split.
