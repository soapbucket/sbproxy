# Getting started: Sovereign / multi-cloud deployment

*Last modified: 2026-07-09*

## What you will build

You will run SBproxy as a cluster-edge gateway that serves more than one tenant, where each tenant's data and secrets stay in its own cloud. The gateway recovers the real client IP behind a Kubernetes Ingress, re-resolves backend Pod endpoints as they rotate, and resolves each tenant's upstream credentials from a backend named per tenant scope, so the same provider reference can read from a different vault depending on which tenant the request belongs to. Every key in this guide comes from the runnable `examples/k8s-gateway` and `examples/vault-reference` configs.

## Prerequisites

- `curl` for the test requests.
- Scenario-specific: nothing extra to start. The runnable example uses `${ENV}` references, which the shipping resolver serves straight from the proxy process environment, so you can run the sovereign shape locally without standing up HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, or a cluster secret store. The provider-specific vault references are shown in `examples/vault-reference` for production wiring.

## Install

One line installs the prebuilt binary on macOS or Linux (the script detects OS and architecture and drops the binary in `~/.local/bin`):

```bash
curl -fsSL https://download.sbproxy.dev | sh
```

Homebrew, Docker, binary downloads, and source builds are in the [runtime manual's installation section](manual.md#1-installation). Run the binary against a config file:

```bash
sbproxy serve -f sb.yml
```

`serve -f <config>` and the no-subcommand `--config <config>` form are equivalent.

## Minimal config

Save this as `sb.yml`. It is the `examples/k8s-gateway` dataplane shape (trusted-proxy XFF recovery, service discovery, host override, correlation id, per-IP concurrency) with the `examples/vault-reference` multi-tenant model layered on: a declared tenant whose origin can read its upstream key from a tenant-scoped provider reference. `test.sbproxy.dev` stands in for the cluster Service so the config runs locally.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/soapbucket/sbproxy/main/schemas/sb-config.schema.json
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
      # Production value: the Service hostname the Pods route by, e.g.
      # host_override: backend.namespace.svc.cluster.local
      # The shared test upstream only serves its own hostname, so
      # override to that for the local run:
      host_override: test.sbproxy.dev
      service_discovery:
        enabled: true
        refresh_secs: 30
        ipv6: true
      retry:
        max_attempts: 3
        retry_on: [connect_error, timeout]
        backoff_ms: 100

    # Inbound auth. The runnable token resolves from the proxy process
    # environment. Production configs can use tenant-scoped provider
    # references such as vault://primary, awssm://primary,
    # gcpsm://primary, or k8ssecret://primary.
    authentication:
      type: bearer
      tokens:
        - ${INTERNAL_BEARER_TOKEN}

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
sbproxy serve -f sb.yml
```

Send a request as if it arrived through the Ingress. The trusted-proxy block recovers the real client IP from `X-Forwarded-For`, and `correlation_id` echoes an `X-Request-Id` on the response:

```bash
curl -i \
  -H 'Host: api.acme.example.com' \
  -H 'Authorization: Bearer test-bearer-1' \
  -H 'X-Forwarded-For: 203.0.113.7' \
  http://127.0.0.1:8080/headers
```

You get a `200 OK`. The response carries an `x-request-id` header, and the JSON body (the echo upstream reflects what it received, with header names lowercased) shows the `host` rewritten to the override value and the same request id the proxy stamped. The body below is trimmed; the hosted echo sits behind a CDN that adds headers of its own, and that CDN also rewrites the forwarding headers in transit, so verify the trusted-proxy behavior through `x-request-id` and the gateway's own access log rather than the echoed `x-forwarded-for`:

```json
{
  "headers": {
    "host": "test.sbproxy.dev",
    "x-request-id": "…",
    "authorization": "Bearer test-bearer-1",
    "…": "…"
  },
  "timestamp": "…"
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

The trusted-proxy rule is what decides whether that `X-Forwarded-For` counts. Your curl arrives from `127.0.0.1`, which is in `trusted_proxies`, so `203.0.113.7` is honored as the client IP for the gateway's own accounting: rate-limit keys and the `client_ip` field of the access log. The same header from a peer outside the trusted ranges is stripped before those decisions. Watch the gateway's access log to see which client IP each request was attributed to; the hosted echo cannot show it, because its CDN rewrites forwarding headers in transit.

A request with no token, or the wrong token, is rejected by the bearer auth before it reaches the upstream:

```bash
curl -i -H 'Host: api.acme.example.com' http://127.0.0.1:8080/headers
# 401 Unauthorized
```

## You are done when

- `curl -i -H 'Host: api.acme.example.com' -H 'Authorization: Bearer test-bearer-1' -H 'X-Forwarded-For: 203.0.113.7' http://127.0.0.1:8080/headers` returns `200 OK`.
- The response carries an `x-request-id` header (generated when absent, echoed back).
- The echoed JSON body shows `"host": "test.sbproxy.dev"` (the override value) and an `"x-request-id"` matching the response header.
- The same request with `X-Request-Id: client-supplied-1234` echoes that id back in both the response header and the body.
- A request with no `Authorization` header returns `401 Unauthorized`.

## Next steps

- [docs/multi-tenant.md](multi-tenant.md) - declared tenants, scope resolution, and per-tenant policy.
- [docs/secrets.md](secrets.md) - provider-specific secret references and wiring each tenant to its own cloud vault.
- [docs/kubernetes.md](kubernetes.md) - generating this dataplane from a `Gateway` plus `HTTPRoute` pair.
- [docs/operator-runbook.md](operator-runbook.md) - running, reloading, and observing the gateway in production.
