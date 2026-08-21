# Multi-zone load balancing

*Last modified: 2026-08-20*

Zone-aware target selection. `proxy.zone: zone-a` tells the proxy which zone it is in, and each target carries a `zone` label. Selection prefers same-zone targets and spills across zones only when no same-zone target is healthy, so cross-zone traffic (latency, egress cost) is a failover path rather than a steady state. A proxy with no zone identity ignores the labels entirely and warns at boot, and single-zone configs behave exactly as before.

Both targets here point at `test.sbproxy.dev`, so the response body cannot show which zone answered. The admin API is the witness: `GET /api/health/targets` reports each target's zone beside the proxy's own resolved zone, and `GET /api/requests` reports a per-request `zone_locality` verdict, `local` or `spilled`.

## Run

```bash
export ADMIN_PASSWORD=change-me
sbproxy serve -f sb.yml
```

## Scenario 1: same-zone routing

Send traffic and read the verdicts back:

```bash
for i in $(seq 1 4); do
  curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.local' http://127.0.0.1:8080/get
done
curl -s -u admin:$ADMIN_PASSWORD http://127.0.0.1:9090/api/requests |
  jq -r '.[:4][] | [.path, (.status|tostring), .zone_locality] | @tsv'
```

```text
/get	200	local
/get	200	local
/get	200	local
/get	200	local
```

Every request reports `local`: the proxy is in `zone-a`, the `zone-a` target is healthy, and round-robin never leaves the local zone. The target-health view shows the same picture from the pool's side:

```bash
curl -s -u admin:$ADMIN_PASSWORD http://127.0.0.1:9090/api/health/targets |
  jq '{proxy_zone, origins: [.origins[] | {local_zone, targets: [.targets[] | {url, zone, healthy, eligible}]}]}'
```

```json
{
  "proxy_zone": "zone-a",
  "origins": [
    {
      "local_zone": "zone-a",
      "targets": [
        { "url": "https://test.sbproxy.dev", "zone": "zone-a", "healthy": true, "eligible": true },
        { "url": "https://test.sbproxy.dev", "zone": "zone-b", "healthy": true, "eligible": true }
      ]
    }
  ]
}
```

## Scenario 2: local zone down, spillover

Force the local zone down: in `sb.yml`, change the `zone-a` target's `health_check.path` from `/status/200` to `/status/503` and restart (or let the config watcher reload). The probe now fails every round; after `unhealthy_threshold: 2` consecutive failures, roughly 2 to 4 seconds, the same target-health query shows `zone-a` ejected:

```json
{
  "proxy_zone": "zone-a",
  "origins": [
    {
      "local_zone": "zone-a",
      "targets": [
        { "url": "https://test.sbproxy.dev", "zone": "zone-a", "healthy": false, "eligible": false },
        { "url": "https://test.sbproxy.dev", "zone": "zone-b", "healthy": true, "eligible": true }
      ]
    }
  ]
}
```

Traffic keeps flowing, but every request now spills to `zone-b` and says so. No request was blackholed at any point in between: failover is per-request, so the first selection after the ejection already lands cross-zone:

```text
$ for i in $(seq 1 4); do
    curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: shop.local' http://127.0.0.1:8080/get
  done
200
200
200
200
$ curl -s -u admin:$ADMIN_PASSWORD http://127.0.0.1:9090/api/requests |
    jq -r '.[:4][] | [.path, (.status|tostring), .zone_locality] | @tsv'
/get	200	spilled
/get	200	spilled
/get	200	spilled
/get	200	spilled
```

Change the probe path back and traffic snaps home the same way: the first selection after `zone-a` passes `healthy_threshold: 2` consecutive probes reports `local` again.

## Scenario 3: zone from the environment

Comment out `proxy.zone` in `sb.yml` and start the proxy with the zone in its environment instead:

```bash
SB_ZONE=zone-a sbproxy serve -f sb.yml
```

Behavior is identical; `SB_ZONE` is the knob a Kubernetes deployment populates from the node's `topology.kubernetes.io/zone` label. Config wins when both are set, so a stray variable can never re-zone a proxy whose config already says where it is. With neither set, selection ignores the labels and the boot log says so:

```text
WARN sbproxy_core::pipeline: load_balancer targets carry `zone` labels but the proxy
has no zone identity; set `proxy.zone` (or the `SB_ZONE` environment variable) to
activate same-zone preference, or remove the labels. Until then selection ignores them.
```

## What this exercises

- `proxy.zone` and the `SB_ZONE` fallback (config wins)
- `targets[].zone` as a live routing input: same-zone preference
- Per-request cross-zone spillover when the local zone has no healthy target, composed with active health checks
- `zone_locality` verdicts (`local` / `spilled`) in `GET /api/requests`
- `proxy_zone`, `origins[].local_zone`, and `targets[].zone` in `GET /api/health/targets`

## See also

- [docs/routing.md](../../docs/routing.md) for the full decision path, including `locality.min_pool_size`
- [docs/configuration.md](../../docs/configuration.md) for the field tables
- [docs/admin-api-reference.md](../../docs/admin-api-reference.md) for both admin surfaces
- [`examples/active-health-checks/`](../active-health-checks/) for the probe mechanics the drill leans on
