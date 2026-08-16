# Active health checks

*Last modified: 2026-08-16*

![Active health checks](../../docs/assets/active-health-checks.gif)

A round-robin load balancer with two targets, both on the host `test.sbproxy.dev`. Each target has a `health_check` block, so the proxy runs a background probe loop on each: every `interval_secs: 10` it `GET`s the target's own probe path. The first target probes `/status/200` (always healthy); the second probes `/status/503` (always unhealthy), so it fails every round. `unhealthy_threshold: 3` consecutive failures mark a target unhealthy; `healthy_threshold: 2` consecutive successes bring it back. Unhealthy targets are excluded from `select_target` until they recover. Probe results also feed the outlier detector when one is configured, so passive and active signals share state.

Note: a target's `url` only ever contributes scheme/host/port to routing. Any path segment on it (the `/status/503` suffix on the second target below) is cosmetic and ignored when forwarding real traffic, so both targets serve `GET /get` identically. The `health_check.path` is what actually distinguishes them, and it is an absolute path applied to the target's host, not appended to the target's own path.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
for i in $(seq 1 4); do
  curl -s -H 'Host: localhost' http://127.0.0.1:8080/get | jq -r '.url'
done
# /get
# /get
# /get
# /get
```

Every response looks identical: both targets resolve to the same upstream host and both forward `GET /get` successfully, so this loop cannot show you which target answered. What the config actually demonstrates is the second target's own health-check probe failing and excluding it:

- The second target's `health_check.path` is `/status/503`, which always answers 503, so every probe against it fails.
- With `interval_secs: 10` and `unhealthy_threshold: 3`, the target is marked unhealthy after its third consecutive failed probe. tokio's interval fires its first tick immediately on startup, so the three failures land at roughly T+0s, T+10s, and T+20s: the target is excluded around 20 seconds after the proxy starts, and stays excluded (`healthy_threshold: 2` requires two consecutive 2xx probes to recover it, which never happens here since its probe path always 503s).
- Because the first target keeps answering `/get` the whole time, this exclusion has no visible effect on the curl output above. There is currently no log line or admin endpoint in this minimal config that surfaces per-probe results or target health state; the mechanism is verified by reading `crates/sbproxy-modules/src/action/loadbalancer.rs` (`run_health_probe_loop`, `target_is_healthy`) rather than by observing it live.

## What this exercises

- `action.type: load_balancer` with per-target `health_check`
- `health_check.path`, `interval_secs`, `timeout_ms`
- `unhealthy_threshold` and `healthy_threshold` consecutive-counter policy
- Exclusion of unhealthy targets from selection
- `health_check.path` is absolute and independent of the target's own `url` path

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
