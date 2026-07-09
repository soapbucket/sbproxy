# Outlier detection

*Last modified: 2026-07-09*

![Outlier detection](../../docs/assets/outlier-detection.gif)

A round-robin load balancer with two targets: `test.sbproxy.dev` and `test.sbproxy.dev/status/503`. Load balancer targets are addressed by scheme, host, and port only; the `/status/503` path on the second target is not applied to proxied requests, so both lanes reach the same echo upstream and stay healthy under normal traffic. The `outlier_detection` block tracks each target's success/failure rate over a 60-second sliding window. When the failure rate crosses `threshold: 0.5` and the target has seen at least `min_requests: 5` requests in the window, the target is ejected from selection for `ejection_duration_secs: 30` before being eligible again. Failures are recorded from upstream 5xx responses and from connect-error retries. Active health checks (example 77) feed this same store when both are configured.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# Drive 20 requests through the LB. Both lanes reach the same healthy
# echo upstream, so every request returns 200 and no ejection happens.
for i in $(seq 1 20); do
  curl -s -H 'Host: localhost' \
       http://127.0.0.1:8080/anything -o /dev/null \
       -w '%{http_code}\n'
done
# 200 (x20)

# Force failures. /status/500 on the echo upstream always 500s, and a
# 5xx is recorded as a failure against whichever lane served it.
for i in $(seq 1 10); do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/status/500 -o /dev/null -w '%{http_code}\n'
done
# 500 (x10)
# Each lane crosses min_requests with a failure rate above 0.5, so
# both are ejected for 30s. With every target ejected, the load
# balancer falls back to the unfiltered list rather than failing
# closed, so traffic keeps flowing.

# Requests during the ejection window still succeed on paths the
# upstream answers with 200.
for i in $(seq 1 5); do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/anything -o /dev/null -w '%{http_code}\n'
done
# 200 (x5)

# After 30s the ejected targets re-enter rotation. To watch a single
# lane get ejected and routed around, point one target at an upstream
# that genuinely fails (answers 5xx or refuses connections): its
# failures accumulate per lane and traffic shifts to the healthy peer.
```

## What this exercises

- `outlier_detection.threshold` (failure-rate ratio)
- `outlier_detection.window_secs` sliding window
- `outlier_detection.min_requests` minimum sample size
- `outlier_detection.ejection_duration_secs` cool-off period
- Passive ejection driven by 5xx and connect-error feedback

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
