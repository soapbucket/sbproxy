# A/B test routing

*Last modified: 2026-08-28*

A weighted 50/50 traffic split between two backend variants. The first request
from a client takes a weighted pick and the response hands back a sticky cookie;
every request after it that returns the cookie stays on the same variant. To make the
split visible without local infrastructure, the two variants point at the
same pair of keyless public APIs [`load-balancer-deployment`](../load-balancer-deployment/) uses: `fakestoreapi.com` (control) and `dummyjson.com` (experiment), which return different response shapes for the same `/products/1` path.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# No cookie: each request is an independent weighted roll, so the ten
# hits below land on a mix of both variants (roughly 50/50 over enough
# requests; any individual run can skew).
for i in $(seq 1 10); do
  curl -s -H 'Host: app.local' http://127.0.0.1:8080/products/1 | head -c 60
  echo
done
# {"id":1,"title":"Fjallraven - Foldsack No. 1 Backpack, Fits 15 Laptops"...
# {"id":1,"title":"Essence Mascara Lash Princess","description":"The Ess...
# ... (a mix of the two)

# With the sticky cookie set to a variant's name, every request pins to
# that variant regardless of the weighted roll.
for i in $(seq 1 5); do
  curl -s -H 'Host: app.local' -H 'Cookie: sb_ab_variant=experiment' \
    http://127.0.0.1:8080/products/1 | head -c 60
  echo
done
# {"id":1,"title":"Essence Mascara Lash Princess","description":"The Ess...
# ... (five identical experiment hits)
```

Look at the response headers on that first call and you will see the pin
the proxy set:

```bash
curl -si -H 'Host: app.local' http://127.0.0.1:8080/products/1 | grep -i set-cookie
# set-cookie: sb_ab_variant=experiment; Path=/; Max-Age=2592000; SameSite=Lax; HttpOnly
```

Send it back and the assignment holds:

```bash
curl -s -H 'Host: app.local' -H 'Cookie: sb_ab_variant=control' \
  http://127.0.0.1:8080/products/1 | head -c 120
# the control backend's response shape, on every repeat
```

A client that already carries the cookie is not restamped, so the
thirty-day window counts from its first visit rather than sliding forward
on every request. Do not set the same cookie from your application as
well: two `Set-Cookie` headers with one name leave it to the browser
which pin survives.

## What this exercises

- `action.type: abtest` with weighted `variants`
- Sticky-cookie variant pinning via `sticky_cookie`: the first request is
  handed a `Set-Cookie`, and every request after it that sends the cookie
  back reaches the same variant
- `sbproxy_action_abtest_variant_selected_total{origin, variant}` incrementing
  once per request that resolves to a usable upstream, whether the pick came
  from the cookie or a fresh roll

## See also

- [docs/configuration.md](../../docs/configuration.md#abtest)
- [docs/observability.md](../../docs/observability.md)
