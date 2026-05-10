# Circuit breaker for load balancer targets

*Last modified: 2026-04-27*

Demonstrates the `circuit_breaker` block on a `load_balancer` action. The breaker is a formal Closed -> Open -> HalfOpen state machine, one instance per target. After `failure_threshold` consecutive failures (5xx, connect error, timeout) the breaker trips Open and every subsequent request to that target is rejected immediately and routed to a healthy peer. After `open_duration_secs` it enters HalfOpen and admits a small number of probe requests; on `success_threshold` consecutive successes it closes again, otherwise it re-opens. Distinct from `outlier_detection`, which ejects on a sliding-window failure rate. The two signals are complementary and run side by side in this example. When every target is tripped at once the load balancer falls back to the unfiltered list rather than 502'ing the client.

## Run

```bash
sbproxy serve -f sb.yml
```

No setup required. Targets are `httpbin.org` and `httpbingo.org`; you can simulate failures by directing `/status/<code>` paths through one of them.

## Try it

```bash
# Healthy round-robin while the breaker stays Closed.
for i in 1 2 3 4; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H 'Host: localhost' http://127.0.0.1:8080/status/200
done
```

```bash
# Drive 5 consecutive 5xx through one target to trip its breaker.
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H 'Host: localhost' http://127.0.0.1:8080/status/503
done
# Subsequent requests skip the tripped target and only land on the healthy peer.
```

```bash
# After open_duration_secs (30s), HalfOpen probes resume. Two consecutive
# successes close the breaker again and rotation resumes across both targets.
sleep 31 && curl -s -H 'Host: localhost' http://127.0.0.1:8080/status/200
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
