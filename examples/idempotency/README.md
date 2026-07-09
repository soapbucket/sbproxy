# Idempotency middleware (IETF Idempotency-Key draft)

*Last modified: 2026-07-09*

The origin on `api.local` opts in to Idempotency-Key handling per the IETF draft draft-ietf-httpapi-idempotency-key-header for
POST / PUT / PATCH requests carrying an `Idempotency-Key` header. The
proxy caches each upstream response under `(workspace, key)` and
short-circuits retries: a replay with the same key + same body returns
the cached response without contacting the upstream; a replay with the
same key but a different body returns 409 `ledger.idempotency_conflict`.

The middleware sits ahead of policy enforcement so a cached replay does
not consume rate-limit slots.

## Run

```bash
sbproxy serve -f sb.yml
```

## Try it

```bash
# First call: forwarded to upstream.
curl -s -H 'Host: api.local' -H 'Idempotency-Key: order-42' \
     -H 'Content-Type: application/json' \
     -d '{"sku":"abc","qty":1}' \
     http://127.0.0.1:8080/orders

# Retry: same key + body. Replayed from cache (header marker present).
curl -sv -H 'Host: api.local' -H 'Idempotency-Key: order-42' \
     -H 'Content-Type: application/json' \
     -d '{"sku":"abc","qty":1}' \
     http://127.0.0.1:8080/orders 2>&1 | grep -i sbproxy
# < x-sbproxy-idempotency: HIT

# Same key, different body: 409 conflict per the draft.
curl -s -H 'Host: api.local' -H 'Idempotency-Key: order-42' \
     -H 'Content-Type: application/json' \
     -d '{"sku":"xyz","qty":99}' \
     http://127.0.0.1:8080/orders
# {"error":"ledger.idempotency_conflict",...}
```

## What this exercises

- `idempotency.enabled: true` opt-in
- Custom `header_name` (defaults to `Idempotency-Key`)
- `ttl_secs` cache lifetime (default 86400 s = 24 h)
- `methods` allowlist (default `[POST, PUT, PATCH]`)
- Cache hit replay carries `x-sbproxy-idempotency: HIT`
- Body-hash conflict surfaces as 409 with the
  `ledger.idempotency_conflict` body
- Workspace isolation: two workspaces using the same key never collide

## Backend selection

```yaml
idempotency:
  enabled: true
  backend: redis    # bind to proxy.l2_store for cluster-wide replay
```

The default `memory` backend is per-origin and per-replica; suitable
for single-instance deployments and clusters where retries land on the
same replica via sticky routing. Set `backend: redis` for cluster-wide
correctness; the cache binds to the L2 store declared at
`proxy.l2_store` and fails the config-load if that block is missing.

## See also

- [docs/configuration.md](../../docs/configuration.md)
- IETF draft draft-ietf-httpapi-idempotency-key-header: <https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/>
