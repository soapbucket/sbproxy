# Load balancer deployment mode

*Last modified: 2026-07-09*

![Load balancer deployment mode](../../docs/assets/load-balancer-deployment.gif)

A blue-green deployment split across two LB targets. The targets carry `group: blue` and `group: green` tags. With `deployment_mode.mode: blue_green` and `active: green`, every request is routed to the green group regardless of the round-robin algorithm. To make the active group visible without local infrastructure, the two groups point at distinct keyless public APIs that produce different response shapes for the same `/products/1` path. Flip `active: blue` and reload to send traffic to the other group without touching the targets list.

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
# {"id":1,"title":"Essence Mascara Lash Princess","description":"The Essence Masca
# {"id":1,"title":"Essence Mascara Lash Princess","description":"The Essence Masca
# ... (six identical green hits)

# Swap deployment_mode.active to blue, reload the proxy, and rerun.
# Now traffic goes to fakestoreapi.com (blue group):
# {"id":1,"title":"Fjallraven - Foldsack No. 1 Backpack, Fits 15 Laptops","price":
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
