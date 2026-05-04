# Outlier detection

*Last modified: 2026-04-27*

A round-robin load balancer with two targets: `httpbin.org` and `httpbingo.org`. The `outlier_detection` block tracks each target's success/failure rate over a 60-second sliding window. When the failure rate crosses `threshold: 0.5` and the target has seen at least `min_requests: 5` requests in the window, the target is ejected from selection for `ejection_duration_secs: 30` before being eligible again. Failures are recorded from upstream 5xx responses and from connect-error retries. Active health checks (example 77) feed this same store when both are configured.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# Drive 20 requests through the LB. With both upstreams healthy, traffic
# alternates and no ejection happens.
for i in $(seq 1 20); do
  curl -s -H 'Host: localhost' \
       http://127.0.0.1:8080/anything -o /dev/null \
       -w '%{http_code}\n'
done
# 200 (x20)

# Force one target to fail. /status/500 on httpbin always 500s; aim traffic
# at it to push the failure rate above 0.5.
for i in $(seq 1 10); do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/status/500 -o /dev/null -w '%{http_code}\n'
done
# 500 500 500 500 500 (httpbin) 500 500 (httpbingo) 200 200 200
# After 5+ requests with >50% failures, one target is ejected for 30s.

# During the ejection window, every request lands on the surviving target.
for i in $(seq 1 5); do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/anything | jq -r '.url // .headers.Host'
done
# httpbingo.org
# httpbingo.org
# httpbingo.org
# httpbingo.org
# httpbingo.org

# After 30s the ejected target re-enters rotation.
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
