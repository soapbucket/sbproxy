# Docker Compose Setup

This directory contains a Docker Compose stack for running SBproxy locally with a full observability pipeline. The stack includes:

- **sbproxy** - the proxy, built from the project Dockerfile (ports 8080, 8443)
- **redis** - distributed rate limiting counters and pub/sub config reload events (port 6379)
- **pebble** - ACME test server for auto-TLS certificate issuance without hitting a public CA (ports 14000, 15000)
- **prometheus** - scrapes SBproxy metrics every 15 seconds (port 9090)
- **grafana** - pre-configured dashboard UI with Prometheus and Jaeger data sources (port 3000)
- **jaeger** - receives OpenTelemetry traces from SBproxy via OTLP/gRPC, with a built-in trace explorer UI (port 16686)

## File Structure

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Service definitions for all six services |
| `sb.yml` | sbproxy config: ACME, Redis, telemetry server, and OTel tracing |
| `pebble-config.json` | Pebble server configuration (listen ports, TLS key paths) |
| `prometheus.yml` | Prometheus scrape config targeting sbproxy:8888 |
| `grafana/datasources.yml` | Auto-provisioned Prometheus and Jaeger data sources for Grafana |
| `README.md` | This file |

The corresponding standalone example lives at `../examples/docker-redis-acme.yml`.

## Prerequisites

- Docker with the Compose plugin (`docker compose version` to confirm)
- Ports 8080, 8443, 6379, 8888, 9090, 3000, 16686, 4317, 14000, and 15000 must be free on the host

## Starting the Stack

From the repo root:

    docker compose -f docker/docker-compose.yml up --build

Or from inside the `docker/` directory:

    docker compose up --build

The `--build` flag rebuilds the SBproxy image from the project Dockerfile. Omit it on subsequent runs to reuse the cached image.

SBproxy waits for Redis and Jaeger to be ready before starting, so all services come up in the correct order.

## Accessing the UIs

| Service | URL | Notes |
|---------|-----|-------|
| Grafana | http://localhost:3000 | No login required. Prometheus and Jaeger are pre-configured as data sources. |
| Jaeger | http://localhost:16686 | Select "sbproxy" from the Service dropdown to browse traces. |
| Prometheus | http://localhost:9090 | Use the expression browser to query SBproxy metrics directly. |

## Generating Traffic and Viewing Metrics

Send a stream of requests to populate metrics and traces:

    for i in $(seq 1 20); do
      curl -s -o /dev/null -w "%{http_code}\n" \
        -H "Host: demo.localhost" http://localhost:8080/get
      sleep 0.5
    done

After a few seconds:

1. Open Grafana at http://localhost:3000 and explore the Prometheus data source. Query `sbproxy_requests_total` or browse available metrics with the metrics explorer.
2. Open Jaeger at http://localhost:16686, select "sbproxy" from the Service dropdown, and click "Find Traces" to see individual request spans.
3. Open Prometheus at http://localhost:9090 and try `rate(sbproxy_requests_total[1m])` to see per-second request rates.

## Viewing Traces in Jaeger

Every request through SBproxy produces an OpenTelemetry trace. Traces are sent to Jaeger via OTLP/gRPC on port 4317.

To inspect a trace:

1. Visit http://localhost:16686
2. Select **sbproxy** from the Service dropdown
3. Click **Find Traces**
4. Click any trace to see the full span waterfall, including upstream latency, policy evaluation, and response handling

## Testing Auto-TLS Certificate Issuance

Pebble issues certificates from a self-signed CA. To trust it, fetch the root certificate from the Pebble management API:

    curl -sk https://localhost:15000/roots/0 -o /tmp/pebble-root.pem

Verify SBproxy obtained a certificate and is serving HTTPS:

    curl --cacert /tmp/pebble-root.pem \
         -H "Host: demo.localhost" \
         https://localhost:8443/get

You should receive a JSON response from httpbin.org proxied through SBproxy over TLS.

If certificate issuance is still in progress, SBproxy falls back to HTTP until the cert is ready. Check the logs with:

    docker compose -f docker/docker-compose.yml logs sbproxy

Look for a line containing `certificate obtained` or `acme: cert obtained`.

### How Pebble Works

Pebble is configured with two environment variables:

- `PEBBLE_VA_NOSLEEP=1` - disables artificial delays during validation, so certificates are issued immediately.
- `PEBBLE_VA_ALWAYS_VALID=1` - skips real HTTP/DNS validation. Every challenge is accepted, which works in a private Docker network where the ACME validator cannot reach the public internet.

The ACME directory URL is `https://pebble:14000/dir`. SBproxy resolves `pebble` via the shared Docker network (`sbnet`).

## Testing Redis-Backed Rate Limiting

The `demo.localhost` origin is limited to 10 requests per minute per client IP. The counter is stored in Redis so it is shared across all SBproxy replicas.

Send 11 rapid requests to observe the rate limit:

    for i in $(seq 1 11); do
      curl -s -o /dev/null -w "%{http_code}\n" \
        -H "Host: demo.localhost" http://localhost:8080/get
    done

The first 10 requests return 200. The 11th returns 429.

Inspect the Redis counter directly:

    docker compose -f docker/docker-compose.yml exec redis redis-cli keys "*"

Rate limit counters appear as keys with a TTL matching the configured window (60 seconds).

### Verifying the L2 Cache Driver

Confirm SBproxy is using Redis as the L2 cache by checking the startup logs:

    docker compose -f docker/docker-compose.yml logs sbproxy | grep -i "l2\|redis\|cache"

## Testing the Echo Origin

The `echo.localhost` origin returns the incoming request as JSON, which is useful for inspecting headers:

    curl -H "Host: echo.localhost" http://localhost:8080/

## Customizing the Config

Edit `docker/sb.yml` and restart sbproxy:

    docker compose -f docker/docker-compose.yml restart sbproxy

Or, for a config-only change, send SBproxy a reload signal (if supported by your build):

    docker compose -f docker/docker-compose.yml kill -s HUP sbproxy

### Switching to Let's Encrypt Staging

For an end-to-end test with a real CA (without Pebble), change `acme_directory_url` in `sb.yml`:

    certificate_settings:
      use_acme: true
      acme_email: you@example.com
      acme_directory_url: https://acme-staging-v02.api.letsencrypt.org/directory
      acme_insecure_skip_verify: false
      acme_cache_dir: /etc/sbproxy/certs

Remove the `pebble` service from `docker-compose.yml` when doing this, as it is no longer needed.

### Adding More Origins

Append entries under the `origins` key in `sb.yml`. Each key is the `Host` header the proxy should match:

    origins:
      "myapi.localhost":
        action:
          type: proxy
          url: https://my-backend.internal
        policies:
          - type: rate_limit
            limit: 100
            window: 1m
            key: client_ip

Restart SBproxy after editing.

## Stopping and Cleaning Up

    docker compose -f docker/docker-compose.yml down

To also remove the named volume used for ACME certificate storage:

    docker compose -f docker/docker-compose.yml down -v
