# Operator runbook

*Last modified: 2026-07-09*

This runbook is the dashboard/action companion to
[`quickstart-operator.md`](quickstart-operator.md). Use the quickstart for first
deploys; use this page when a dashboard panel is red.

## Dashboard Triage

1. Confirm `/readyz` and `/health` from the affected proxy pod.
2. Open `dashboards/grafana/sbproxy-overview.json` first to decide whether the
   problem is global or isolated to one origin / feature area.
3. Use the panel description to jump to the section below.
4. Capture the current config revision, pod name, and request id before
   restarting or rolling back.

## Inbound Traffic

Healthy range: request rate follows expected load, p95/p99 latency stays within
the deployment SLO, and 5xx errors stay near zero.

When red:

- Check `/readyz` for stale dependencies.
- Tail access logs and compare successful 2xx requests against denied 4xx/5xx
  requests.
- If latency rose after a config change, roll back the latest `SBProxyConfig`
  and watch the latency panel for recovery.

## Security Controls

Healthy range: WAF, auth, IP filter, bot detection, and rate-limit blocks should
match expected traffic patterns. Sudden spikes require investigation even when
the proxy is behaving correctly.

When red:

- Inspect the top offending host, path, source IP, or agent label.
- Confirm the policy in `sb.yml` is intentional.
- For auth failures, verify the credential source or JWKS feed before loosening
  policy.
- For WAF/rate-limit spikes, preserve sample request ids for incident review.

## AI Gateway

Healthy range: provider request rate, token usage, and provider errors follow
known traffic. Budget utilization should stay below alert thresholds.

When red:

- Check provider credentials and model routing in the active config.
- Confirm fallback providers are healthy before disabling a primary provider.
- For budget alerts, decide whether to raise the configured budget or block the
  caller.

### Hot-reload behavior

A `SIGHUP`, an admin reload, or a watched edit of `sb.yml` rebuilds the AI
provider catalog, the live AI client, and the compiled handler chain in place
and swaps them atomically. Adding a provider, rotating a `default_base_url`, or
fixing a typo in `ai_providers.yml` no longer requires a restart, and in-flight
requests are not shed. The process-wide AI budget tracker is deliberately not
part of the swap: per-scope token and cost accumulators must survive reloads
because budget windows are wall-clock-relative (daily, monthly), and wiping
them on reload would let already-spent budget through twice. Budget state is
in-memory, so a full process restart resets every accumulator to zero; there
is no admin endpoint for resetting a budget. Treat restarts during an active
budget window accordingly: spend already recorded is forgotten.

## Origins

Healthy range: origin latency and errors stay within SLO; circuit breakers
remain closed; cache hit/miss trends are expected for the workload.

When red:

- Check the upstream service directly from inside the cluster.
- Confirm service discovery and DNS resolution are returning current endpoints.
- If a circuit breaker opened, wait for the configured half-open interval or
  roll back the origin config that triggered failures.

## Helm Value Reconciliation

The chart currently exposes operator-level values only. The following names were
used in early planning notes but are not Helm values in the merged chart:

- `proxy.notify.deadletter_capacity`
- `proxy.observability.otlp.queue_size`

Do not set those values in `deploy/helm/sbproxy/values.yaml`. Configure outbound
webhook behavior and OTLP behavior in `sb.yml` / proxy configuration as those
surfaces mature; keep Helm values for operator deployment concerns such as
image, replicas, leader election, RBAC, namespace, and dashboard provisioning.

## Rollback

Helm rollback:

```bash
helm history sbproxy -n sbproxy-system
helm rollback sbproxy 3 -n sbproxy-system
```

Config rollback:

```bash
kubectl apply -f sbproxyconfig.yaml
kubectl rollout status deploy/demo
```
