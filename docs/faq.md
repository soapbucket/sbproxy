# Frequently asked questions

*Last modified: 2026-08-21*

Quick answers to the questions operators hit most often when standing up SBproxy, debugging a config that will not load, or wiring observability. For the full reference of any feature, follow the link to the matching doc.

## Install + first run

### How do I install SBproxy?

Pick whichever fits your platform:

```bash
# Linux amd64/arm64 or Apple Silicon macOS, no Rust toolchain required:
curl -fsSL https://download.sbproxy.dev | sh

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

The serving command accepts `--config` (alias `-f`). Run `sbproxy --help` for
the full surface. To validate without starting, pass the config as a positional
path with `sbproxy validate sb.yml`.

There is no directory-loading mode. The binary reads a single YAML file; compose multi-file configs via your CI or a wrapper script.

### My config will not load. How do I see why?

```bash
sbproxy validate sb.yml
```

The validator runs the same schema check the server uses at boot, prints the offending field path plus a one-line explanation, and exits non-zero. JSON output is available via `sbproxy validate --format json sb.yml` for tooling.

See [troubleshooting.md](./troubleshooting.md) for the most common validation errors.

## Distribution

### What is included?

Everything in this repository ships under Apache-2.0:

* The full proxy: HTTP/1.1, HTTP/2, websockets, gRPC, GraphQL, MCP.
* The AI gateway: 70 native providers, routing strategies, guardrails, budgets, streaming, semantic cache, virtual keys.
* Every auth provider (API key, Basic, Bearer, JWT, Digest, forward-auth, Web Bot Auth, CAP, OIDC).
* Every policy (rate limit, WAF, IP filter, CORS, HSTS, CSRF, agent budget, content digest, BOLA / `object_authz`, ...).
* Every transform (26 types, including `json`, `template`, `wasm`).
* Scripting via CEL, Lua, JavaScript, and WebAssembly.
* The embedded admin server, the access log, the metrics and tracing wiring, the audit log.
* All examples and dashboards.

### Can I run SBproxy in production?

Yes. SBproxy is licensed under the Apache License 2.0, which permits any use, including production and commercial deployment, with no field-of-use restriction.

## Auth + sessions

### Why does my request get a 401 even though I sent the right token?

The most common causes, in order:

1. The auth provider was never matched on the request's `Host`. SBproxy routes by `Host` first; an auth block on `api.example.com` does not apply to a request with `Host: api.test`. Check `sbproxy_auth_results_total{origin}` in metrics to confirm.
2. Trusted-proxy CIDRs are wrong. If SBproxy sits behind another LB,
   `X-Forwarded-For` headers from outside `proxy.trusted_proxies` are stripped
   on ingress and the real client IP is the LB. This affects only policies and
   authentication that use the client address, such as IP filtering or an
   IP-based rate limit.
3. A forward-auth service never received the credential. On an
   `authentication.type: forward_auth` block, `headers_to_forward` controls
   which original request headers are copied into the authentication
   subrequest. Include `Authorization` or `Cookie` when that service needs it.

When authentication runs, the structured access log can include `auth_type`
and `auth_ms`. These fields are optional and can be absent on requests that did
not run an auth provider. In a query or dashboard, alias `auth_type` to
`auth_provider` when that name is clearer for operators.

### How do I configure OIDC?

`docs/configuration.md` has the full schema; for the minimal case:

```yaml
origins:
  "app.example.com":
    action:
      type: proxy
      url: http://upstream-app:3000
    authentication:
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

The same Prometheus series are available in two places. The main data-plane
listener always serves `/metrics` on `proxy.http_bind_port` (8080 by default)
without admin authentication:

```text
http://<host>:8080/metrics
```

For an access-controlled scrape, enable the admin listener:

```yaml
proxy:
  admin:
    enabled: true
    port: 9090
    username: metrics
    password: ${SB_ADMIN_PASSWORD}
```

Then scrape `http://<host>:9090/metrics` with HTTP Basic credentials. The
admin mirror sits behind `proxy.admin.username` and `proxy.admin.password`,
the same authentication used by the other protected admin routes. Health
probes remain unauthenticated.

The canonical metric catalog with stability promises is [metrics-stability.md](./metrics-stability.md).

### Where does the access log go?

`stderr` by default, structured JSON, one line per request. Enable via the top-level `access_log:` block; route to a file via stdout/stderr redirection. The full schema is in [access-log.md](./access-log.md).

The log carries phase timings (`auth_ms`, `upstream_ttfb_ms`, `response_filter_ms`) so a slow request reveals which part of the pipeline produced the latency without cross-referencing histograms.

### Where do traces go?

OTLP exporter, configured via `proxy.observability.telemetry.endpoint` in `sb.yml`. The value supports `${ENV_VAR}` interpolation, so `endpoint: ${OTEL_COLLECTOR_URL}` works. The reference Compose stack at `examples/observability-stack/` runs an OTel Collector with Tempo, Grafana, Phoenix, and Langfuse for local development.

## Performance + capacity

### What overhead does SBproxy add per request?

Sub-millisecond p99 at 50k+ rps on commodity hardware for plain proxy paths; AI gateway paths add ~3-5ms for the routing decision and guardrail check, dominated by upstream latency. The `ai-lb-benchmark.md` page has measured P50/P95/P99/P99.9 across every router strategy under skewed load.

### How do I tune SBproxy for high concurrency?

`performance.md` has the operator-facing tuning guide. The two settings that move the needle: the `SB_WORKER_THREADS` environment variable (defaults to the detected CPU parallelism, which honors cgroup quotas on Linux) and the connection pool sizes per upstream.

## Configuration patterns

### Where are the examples?

`examples/` in this repo, indexed in `examples/README.md`. Pick the directory
closest to your scenario, copy its `sb.yml`, and edit from there. The
configuration examples are checked in CI, and their READMEs carry the commands
needed to exercise each feature.

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
