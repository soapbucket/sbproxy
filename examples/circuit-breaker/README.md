# Circuit breaker for load balancer targets

*Last modified: 2026-08-16*

Demonstrates the `circuit_breaker` block on a `load_balancer` action. The breaker is a formal Closed -> Open -> HalfOpen state machine, one instance per target. After `failure_threshold` consecutive failures (5xx, connect error, timeout) the breaker trips Open and every subsequent request to that target is rejected immediately and routed to a healthy peer. After `open_duration_secs` it enters HalfOpen and admits a small number of probe requests; on `success_threshold` consecutive successes it closes again, otherwise it re-opens. Distinct from `outlier_detection`, which ejects on a sliding-window failure rate. The two signals are complementary and run side by side in this example. When every target is tripped at once the load balancer falls back to the unfiltered list rather than 502'ing the client.

## Run

```bash
sbproxy serve -f sb.yml
```

No setup required. Target 1 is the live `test.sbproxy.dev` upstream; target 2 is a closed
local port (`127.0.0.1:9`) standing in for a hard-down replica, so every connection to it
fails immediately with `ECONNREFUSED` regardless of the requested path. (A `load_balancer`
target's own URL path is never applied to outbound requests, only `Action::Proxy` does
base-path prefixing, so two targets that only differ by path are indistinguishable to the
breaker; this example uses a genuinely different host instead.)

## Try it

Target 2 is down from the start, so round-robin alternates success/failure immediately:

```bash
$ for i in $(seq 1 10); do
    curl -s -o /dev/null -w "%{http_code} " -H 'Host: localhost' http://127.0.0.1:8080/get
  done; echo
200 502 200 502 200 502 200 502 200 502
```

Every other request lands on target 2 and fails at connect time (502). By the 10th request,
target 2 has taken 5 consecutive failures and its breaker trips Open (confirm with
`curl -u admin:... http://127.0.0.1:9090/api/health/targets`, if the admin server is
enabled - `"circuit_breaker_state":"open","eligible":false"` on target 2). `outlier_detection`
ejects it on the same request, since its failure rate also crosses `threshold` at
`min_requests: 5`.

```bash
# Subsequent requests skip the tripped target and land only on the healthy peer.
$ for i in 1 2 3 4; do
    curl -s -o /dev/null -w "%{http_code} " -H 'Host: localhost' http://127.0.0.1:8080/get
  done; echo
200 200 200 200
```

```bash
# After open_duration_secs (30s), the breaker transitions to HalfOpen and
# admits a probe again. Because target 2 in this demo is a closed port that
# never recovers, the probe fails and it re-opens - HalfOpen -> Open, not
# HalfOpen -> Closed. Against a target that genuinely comes back healthy,
# `success_threshold` (2) consecutive successful probes would close it.
sleep 31 && curl -s -H 'Host: localhost' http://127.0.0.1:8080/get
```

## What this exercises

- `circuit_breaker` - per-target Closed/Open/HalfOpen state machine with consecutive-failure and consecutive-success thresholds
- `outlier_detection` - sliding-window error-rate ejection running alongside the breaker
- `load_balancer` action with `algorithm: round_robin` across multiple `targets`
- Fallback to the unfiltered target list when every target is tripped at once

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/routing-strategies.md](../../docs/routing-strategies.md)
