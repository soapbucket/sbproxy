# Distributed dynamic key management (cluster)

Two sbproxy replicas share one Redis key store, so a virtual key is governed
fleet-wide: mint it on one replica and it works on the other, revoke it on one
and the next request on either is denied.

This is the clustered counterpart to [`../ai-dynamic-keys/`](../ai-dynamic-keys/),
which runs the same feature on a single local binary.

## How it clusters

Two pieces make the key plane coherent across replicas, both in `sb.yml`:

- `store.backend: redis` with `redis_source_of_truth: true` - Redis is the
  system of record, so every replica reads and writes the same keys.
- `cache.tier: redis` - the policy cache uses a Redis L2 tier that publishes an
  invalidation on every mutation, so a revoke or an update on one replica drops
  the cached entry on the others. Each replica still keeps a fast in-memory L1
  in front of it.

The crypto pepper and master key are shared through the environment so hashes
and envelopes are portable between replicas.

## Run it locally (single node)

You do not need Docker to try the feature. Point one binary at the single-node
example:

```bash
export SBPROXY_KEY_PEPPER=dev-pepper SBPROXY_KEY_MASTER=dev-master OPENAI_API_KEY=sk-...
make run CONFIG=examples/ai-dynamic-keys/sb.yml
```

## Run the two-replica cluster

```bash
cd examples/ai-dynamic-keys-cluster
export OPENAI_API_KEY=sk-...        # only needed for live upstream calls
docker compose up --build
```

This starts Redis, `sb1` (proxy on `:8081`, admin on `:9091`), and `sb2` (proxy
on `:8082`, admin on `:9092`).

### Cross-replica test

Mint a key on `sb1`:

```bash
TOKEN=$(curl -s -u admin:admin -X POST http://127.0.0.1:9091/admin/keys \
  -H 'Content-Type: application/json' \
  -d '{"name":"fleet-key","max_requests_per_minute":600}' | jq -r .token)
echo "$TOKEN"
```

Use it against `sb2` (a different replica). The key resolves there because Redis
is the shared source of truth, so the request passes the virtual-key gate:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8082/v1/chat/completions \
  -H 'Host: ai.localhost' -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# not 401/403 (the upstream call needs a real OPENAI_API_KEY to return 200)
```

Revoke it on `sb1`:

```bash
KEY_ID=$(curl -s -u admin:admin http://127.0.0.1:9091/admin/keys | jq -r '.keys[0].key_id')
curl -s -u admin:admin -X POST http://127.0.0.1:9091/admin/keys/$KEY_ID/revoke
```

The next request on `sb2` is denied. The revoke published an invalidation over
Redis, so `sb2` dropped its cached copy and re-resolved the now-revoked record:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8082/v1/chat/completions \
  -H 'Host: ai.localhost' -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# 403
```

Tear down with `docker compose down -v`.

## The mesh tier (Redis-free clustering)

`cache.tier: mesh` is the gossip-based alternative to the Redis tier: it backs
the policy cache with the mesh distributed cache (consistent-hash ring + gossip
replication) and adds CRDT-based cross-replica per-key spend and rate counters,
so a fleet can share key state without a Redis dependency. The cache tier and
the counters are in place; wiring the gossip cluster bootstrap (seed discovery
and transport) from config is the next step, so for a working multi-container
demo today use the Redis path above. See `docs/key-management.md`.
