# Load balancer deployment mode

*Last modified: 2026-04-27*

A blue-green deployment split across two LB targets. The targets carry `group: blue` and `group: green` tags. With `deployment_mode.mode: blue_green` and `active: green`, every request is routed to the green group regardless of the round-robin algorithm. To make the active group visible without local infrastructure, the two groups point at distinct public APIs that produce different response shapes. Flip `active: blue` and reload to send traffic to the other group without touching the targets list.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# All six requests land on the green group's upstream (dummyjson.com)
# because active=green.
for i in $(seq 1 6); do
  curl -s -H 'Host: api.local' http://127.0.0.1:8080/products/1 | head -c 80
  echo
done
# {"id":1,"title":"Essence Mascara Lash Princess","description":"The iconic L
# {"id":1,"title":"Essence Mascara Lash Princess","description":"The iconic L
# ... (six identical green hits)

# Swap deployment_mode.active to blue, reload the proxy, and rerun.
# Now traffic goes to reqres.in (blue group):
# {"data":{"id":1,"name":"cerulean","year":2000,"color":"#98B2D1",...}}
```

## What this exercises

- `action.type: load_balancer` with `algorithm: round_robin`
- `deployment_mode.mode: blue_green` with `active` group selector
- Per-target `group` tagging
- Hot-swap of an entire target group via a single config field

## See also

- [docs/features.md](../../docs/features.md)
- [docs/configuration.md](../../docs/configuration.md)
- [docs/manual.md](../../docs/manual.md)
