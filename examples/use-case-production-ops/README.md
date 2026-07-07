# Production ops

*Last modified: 2026-07-06*

![Production ops](../../docs/assets/use-case-production-ops.gif)

The observability surface an on-call engineer works with: Prometheus metrics on `/metrics`, a JSON access log with forced emission for errors and slow requests, the admin server's health probes and request log, and graceful degradation when an upstream dies. Three origins tell the story: `app.local` is healthy, `checkout.local` points at a dead local port and returns 502, and `payments.local` points at the same dead port but serves a degraded 200 through a fallback origin. The full walkthrough is [docs/use-case-production-ops.md](../../docs/use-case-production-ops.md).

## Run it

Standalone, no external dependencies:

```bash
sbproxy sb.yml
```

Or with Prometheus and Grafana wired to the bundled dashboards from `dashboards/` (needs Docker Compose v2.23+):

```bash
docker compose up
```

## What to expect

```console
$ curl -s -H 'Host: app.local' http://127.0.0.1:8080/
{"service":"app","status":"ok"}

$ curl -si -H 'Host: checkout.local' http://127.0.0.1:8080/ | head -n 1
HTTP/1.1 502 Bad Gateway

$ curl -s -H 'Host: payments.local' http://127.0.0.1:8080/
{"message":"payments upstream temporarily unavailable, serving degraded response","retry_after_secs":30,"status":"degraded"}

$ curl -s http://127.0.0.1:8080/metrics | grep 'sbproxy_requests_total{'
sbproxy_requests_total{...,hostname="app.local",method="GET",...,status="200"} 1
sbproxy_requests_total{...,hostname="checkout.local",method="GET",...,status="502"} 1
sbproxy_requests_total{...,hostname="payments.local",method="GET",...,status="200"} 1
```

Each request also lands as one JSON access-log line on stdout. With the compose stack up, Grafana at `http://localhost:3000` (admin / admin) has the SBproxy dashboards pre-provisioned, Prometheus at `http://localhost:9090` evaluates the bundled alert rules, and the admin server at `http://localhost:9091` (admin / change-this) answers `/health` and `/api/requests`.
