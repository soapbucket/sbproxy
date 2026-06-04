# Getting started: Sovereign / multi-cloud deployment

*Last modified: 2026-06-04*

## What you will build

You will run SBproxy as a cluster-edge gateway that serves more than one tenant, where each tenant's data and secrets stay in its own cloud. The gateway recovers the real client IP behind a Kubernetes Ingress, re-resolves backend Pod endpoints as they rotate, and resolves each tenant's upstream credentials from a backend named per tenant scope, so the same `vault://` reference reads from a different vault depending on which tenant the request belongs to. Every key in this guide comes from the runnable `examples/k8s-gateway` and `examples/vault-reference` configs.

## Prerequisites

- Rust 1.82 or newer with `cargo` (the workspace `rust-version` is 1.82). Needed only if you build from source.
- `curl` for the test requests.
- A pre-built binary is fine too. You do not need the toolchain if you install with the release script, Homebrew, or Docker (see the next section).
- Scenario-specific: nothing extra to start. The example uses `vault://env/...` references, which the shipping resolver serves straight from the proxy process environment, so you can run the sovereign shape locally without standing up HashiCorp Vault, AWS Secrets Manager, or a cluster secret store. Those named backends (`hashi`, `aws`, `k8s`, `sqlite`) parse today and resolve once their backend block is wired in; the `env` backend works now.

## Install and build

Pick one install path. Do not push end users at `cargo install`.

Release script (detects OS and architecture, drops the binary in `~/.local/bin`):

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

Homebrew (macOS / Linux):

```bash
brew tap soapbucket/tap
brew install sbproxy
```

Docker:

```bash
docker pull ghcr.io/soapbucket/sbproxy:latest
```

From source. A debug build:

```bash
make build
```

Or an optimised release build, which produces `target/release/sbproxy`:

```bash
cargo build --release -p sbproxy
```

Run the binary against a config file:

```bash
./target/release/sbproxy serve -f sb.yml
```

`serve -f <config>` and the no-subcommand `--config <config>` form are equivalent. `make run CONFIG=<file>` wraps the debug build plus run in one step.

## Minimal config

Save this as `sb.yml`. It is the `examples/k8s-gateway` dataplane shape (trusted-proxy XFF recovery, service discovery, host override, correlation id, per-IP concurrency) with the `examples/vault-reference` multi-tenant model layered on: a declared tenant whose origin reads its upstream key from a tenant-scoped `vault://` reference. `test.sbproxy.dev` stands in for the cluster Service so the config runs locally.

```yaml
# yaml-language-server: $schema=../../schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080

  # The immediate TCP peer is the Ingress controller, not the real
  # client. Honour its X-Forwarded-For only from cluster-internal
  # ranges; strip spoofed XFF from anywhere else.
  trusted_proxies:
    - 10.0.0.0/8       # K8s Pod CIDR
    - 172.16.0.0/12    # K8s Service CIDR
    - 127.0.0.1/32     # localhost for local testing

  # Thread X-Request-Id through proxy, upstream, response, and
  # webhooks so trace IDs survive the cluster boundary.
  correlation_id:
    enabled: true
    header: X-Request-Id
    echo_response: true

  # Declared tenants. Each id is referenced by origin.tenant_id.
  # An origin that names an undeclared tenant fails config compile.
  # Per-tenant vault backends land with the credentials block; the
  # tenant scope itself resolves today.
  tenants:
    - id: acme-corp

origins:
  # Public-facing tenant hostname. Pin it to the acme-corp tenant so
  # its credentials resolve in acme-corp's scope.
  "api.acme.example.com":
    tenant_id: acme-corp
    action:
      type: proxy
      # In production this is the K8s Service DNS name, e.g.
      # url: http://backend.namespace.svc.cluster.local:8080
      url: https://test.sbproxy.dev
      host_override: backend.namespace.svc.cluster.local
      service_discovery:
        enabled: true
        refresh_secs: 30
        ipv6: true
      retry:
        max_attempts: 3
        retry_on: [connect_error, timeout]
        backoff_ms: 100

    # Inbound auth. The bearer token resolves through a vault://
    # reference. vault://env reads the proxy process environment and
    # is tenant-agnostic by construction; vault://hashi (and aws, k8s,
    # sqlite) resolve against the named backend in the tenant scope.
    authentication:
      type: bearer
      tokens:
        - vault://env/INTERNAL_BEARER_TOKEN

    policies:
      # Protect upstream Pods from a thundering herd. Per-IP keying
      # preserves headroom for other clients.
      - type: concurrent_limit
        max: 100
        key: ip
        status: 503
        error_body: '{"error":"too many concurrent requests"}'
```

## Run it + expected output

Export the bearer token the config references, then start the gateway:

```bash
export INTERNAL_BEARER_TOKEN=test-bearer-1
./target/release/sbproxy serve -f sb.yml
```

Send a request as if it arrived through the Ingress. The trusted-proxy block recovers the real client IP from `X-Forwarded-For`, and `correlation_id` echoes an `X-Request-Id` on the response:

```bash
curl -i \
  -H 'Host: api.acme.example.com' \
  -H 'Authorization: Bearer test-bearer-1' \
  -H 'X-Forwarded-For: 203.0.113.7' \
  http://127.0.0.1:8080/headers
```

You get a `200 OK`. The response carries an `X-Request-Id` header, and the JSON body (the echo upstream reflects what it received) shows the recovered `X-Forwarded-For: 203.0.113.7` and the `Host` rewritten to the override value:

```json
{
  "headers": {
    "Host": "backend.namespace.svc.cluster.local",
    "X-Forwarded-For": "203.0.113.7",
    "X-Request-Id": "…",
    "Authorization": "Bearer test-bearer-1"
  },
  "url": "https://test.sbproxy.dev/headers"
}
```

Reuse a client-supplied request id and the proxy honours it rather than minting a new one:

```bash
curl -i \
  -H 'Host: api.acme.example.com' \
  -H 'Authorization: Bearer test-bearer-1' \
  -H 'X-Request-Id: client-supplied-1234' \
  http://127.0.0.1:8080/headers
```

A spoofed XFF from outside the `trusted_proxies` ranges gets stripped, so the upstream sees the proxy's own IP, not the forged value:

```bash
curl -i \
  -H 'Host: api.acme.example.com' \
  -H 'Authorization: Bearer test-bearer-1' \
  -H 'X-Forwarded-For: 8.8.8.8' \
  http://127.0.0.1:8080/headers
```

A request with no token, or the wrong token, is rejected by the bearer auth before it reaches the upstream:

```bash
curl -i -H 'Host: api.acme.example.com' http://127.0.0.1:8080/headers
# 401 Unauthorized
```

## You are done when

- `curl -i -H 'Host: api.acme.example.com' -H 'Authorization: Bearer test-bearer-1' -H 'X-Forwarded-For: 203.0.113.7' http://127.0.0.1:8080/headers` returns `200 OK`.
- The response carries an `X-Request-Id` header (generated when absent, echoed back).
- The echoed JSON body shows `"X-Forwarded-For": "203.0.113.7"` and `"Host": "backend.namespace.svc.cluster.local"`.
- The same request with `X-Forwarded-For: 8.8.8.8` shows the proxy IP in the body, not `8.8.8.8`.
- A request with no `Authorization` header returns `401 Unauthorized`.

## Next steps

- [docs/multi-tenant.md](multi-tenant.md) - declared tenants, scope resolution, and per-tenant policy.
- [docs/secrets.md](secrets.md) - the `vault://` grammar and wiring each tenant to its own cloud vault (HashiCorp, AWS, Kubernetes, SQLite).
- [docs/kubernetes.md](kubernetes.md) - generating this dataplane from a `Gateway` plus `HTTPRoute` pair.
- [docs/operator-runbook.md](operator-runbook.md) - running, reloading, and observing the gateway in production.
