# Active health checks

*Last modified: 2026-04-27*

A round-robin load balancer with two targets: `httpbin.org` and `httpbingo.org`. Each target has a `health_check` block, so the proxy runs a background probe loop on each: every `interval_secs: 10` it `GET`s the probe path (`/status/200`). `unhealthy_threshold: 3` consecutive failures mark the target unhealthy; `healthy_threshold: 2` consecutive successes bring it back. Unhealthy targets are excluded from `select_target` until they recover. Probe results also feed the outlier detector when one is configured, so passive and active signals share state.

## Run

```bash
sb run -c sb.yml
```

## Try it

```bash
# While both targets respond 2xx on /status/200, traffic alternates.
for i in $(seq 1 4); do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/get | jq -r '.url // .headers.Host'
done
# https://httpbin.org/get
# httpbingo.org
# https://httpbin.org/get
# httpbingo.org

# Block one target (drop httpbingo.org from /etc/hosts to simulate failure).
# After 3 consecutive failed probes (~30s with the defaults), it is excluded.
# Until then, traffic still hits both targets and slow-fails on the bad one.

# Inspect the proxy log to see probe rounds:
#   active_health_check target=https://httpbin.org status=ok consecutive_ok=2
#   active_health_check target=https://httpbingo.org status=fail consecutive_fail=1
#   active_health_check target=https://httpbingo.org status=fail consecutive_fail=2
#   active_health_check target=https://httpbingo.org status=fail consecutive_fail=3 -> unhealthy
#
# After unhealthy mark, every request lands on httpbin.org until the probe
# observes 2 consecutive 2xx responses.
```

## What this exercises

- `action.type: load_balancer` with per-target `health_check`
- `health_check.path`, `interval_secs`, `timeout_ms`
- `unhealthy_threshold` and `healthy_threshold` consecutive-counter policy
- Exclusion of unhealthy targets from selection
- Shared state with outlier detector

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
