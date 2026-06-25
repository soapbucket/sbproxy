# Distributed dynamic key management (cluster)

![Clustered key management: mint on node A, use and revoke from node B](../../docs/assets/ai-dynamic-keys-cluster.gif)

Two sbproxy replicas govern one set of virtual keys fleet-wide: mint a key on
one replica and it works on the other, revoke it on one and the next request on
either is denied.

This is the clustered counterpart to [`../ai-dynamic-keys/`](../ai-dynamic-keys/),
which runs the same feature on a single local binary.

## How it clusters

Resolution order is L1 in-memory cache, then the mesh distributed cache, then
the store. Two pieces in `sb.yml` make the key plane coherent across replicas:

- `store.backend: redis` with `redis_source_of_truth: true` - Redis is the
  durable system of record, so every replica reads and writes the same keys. A
  key minted on one replica is visible on the others as soon as it is written.
- `cache.tier: mesh` - the policy cache is backed by the mesh distributed cache:
  a SWIM gossip cluster with a consistent-hash ring. Reads and writes route to
  the replica that owns a key, so a record cached on one node is reachable from
  the others without a round trip to Redis, and an invalidation on revoke routes
  to the owner. Each replica still keeps a fast in-memory L1 in front of it.

Each replica's mesh identity (node id, advertised address, and seed peer) comes
from the environment, so one `sb.yml` boots every node. The replicas gossip over
ports 7946 (membership) and 8946 (cache transport), internal to the network. The
crypto pepper and master key are shared through the environment so hashes and
envelopes are portable between replicas.

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
# not 403: the key passes the gate. A 200 needs a real OPENAI_API_KEY; without
# one the upstream call itself fails (401), but the gate let the request through.
```

Revoke it on `sb1`:

```bash
KEY_ID=$(curl -s -u admin:admin http://127.0.0.1:9091/admin/keys | jq -r '.keys[0].key_id')
curl -s -u admin:admin -X POST http://127.0.0.1:9091/admin/keys/$KEY_ID/revoke
```

The next request on `sb2` is denied. The revoke updated the record in Redis and
routed a cache invalidation through the mesh, so `sb2` re-resolves the now-revoked
record and the gate rejects it before it reaches any upstream:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8082/v1/chat/completions \
  -H 'Host: ai.localhost' -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
# 403
```

Tear down with `docker compose down -v`.

## Going fully Redis-free

This example keeps Redis as the durable store and puts the mesh cache in front of
it. To drop Redis entirely, point `store.backend` at a shared secrets manager
(`secrets_manager`) and keep `cache.tier: mesh`; the gossip ring then carries the
cache, and CRDT-based per-key spend and rate counters keep budgets coherent
across replicas without a Redis dependency. The Redis-store setup above is the
runnable multi-container demo; the secrets-manager store is the further step. See
`docs/key-management.md`.
