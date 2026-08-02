# Mesh-replicated AI context compression

*Last modified: 2026-07-20*

This example runs the ordered AI context-compression pipeline with session
summaries stored on the cluster replication substrate instead of Redis. It is
the Redis-free variant of
[ai-context-compression-redis](../ai-context-compression-redis/): the same
`summary_buffer` and `window_fit` levers, with
`compression.state.backend: mesh` bound to `proxy.cluster.replication`.

Redis remains the default and recommended state backend. Choose mesh when a
fleet already runs cluster replication and accepts eventually consistent
session summaries. The contracts differ: Redis serializes writers with a
distributed lease and an atomic compare-and-set, while mesh resolves
cross-node races through a conditional put and a deterministic causal
last-writer-wins merge. The losing writer's request degrades safely and the
surviving record is flagged `conflict_detected`. See
[docs/ai-context-compression.md](../../docs/ai-context-compression.md) for the
full comparison and
[docs/mesh-replication.md](../../docs/mesh-replication.md) for the substrate.

## Prerequisites

- An SBproxy binary built from this checkout.
- `curl`, `jq`, and `openssl` for the commands below.
- An OpenAI API key. The primary request uses `gpt-4o`; internal summaries use
  the separately configured `gpt-4o-mini` provider entry.

No Redis is required. Session records live in replicated durable shards under
each node's `state_dir`.

## Run two nodes locally

Each node runs this same file with per-node environment overrides, exactly
like [model-cluster-symmetric](../model-cluster-symmetric/). Node A:

```bash
export OPENAI_API_KEY='<set this in your shell>'
export SB_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export SB_NODE_ID=node-a
export SB_STATE_DIR=./state/mesh-node-a

sbproxy serve --log-format json \
  -f examples/ai-context-compression-mesh/sb.yml
```

Node B, in another shell:

```bash
export OPENAI_API_KEY='<set this in your shell>'
export SB_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export SB_NODE_ID=node-b
export SB_STATE_DIR=./state/mesh-node-b
export SB_HTTP_PORT=8081
export SB_ADMIN_PORT=9091
export SB_GOSSIP_PORT=17947
export SB_TRANSPORT_PORT=18947
export SB_SEED=127.0.0.1:17946

sbproxy serve --log-format json \
  -f examples/ai-context-compression-mesh/sb.yml
```

## Exercise the summary state

Send a long conversation with a stable session ID to node A, then repeat the
turn against node B. The second node reuses the replicated summary instead of
re-summarizing:

```bash
SESSION_ID=01J0000000000000000000TEST

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Host: ai.local' \
  -H "X-Sb-Session-Id: ${SESSION_ID}" \
  -H 'Content-Type: application/json' \
  -d @long-conversation.json | jq .

curl -s http://127.0.0.1:8081/v1/chat/completions \
  -H 'Host: ai.local' \
  -H "X-Sb-Session-Id: ${SESSION_ID}" \
  -H 'Content-Type: application/json' \
  -d @long-conversation.json | jq .
```

Inspect the replicated session metadata from either node's Admin API:

```bash
curl -s -u "admin:${SB_ADMIN_PASSWORD}" \
  'http://127.0.0.1:9090/admin/compression/sessions?backend=mesh' | jq .
```

Deleting a record from one node tombstones it on every replica, and the
tombstone prevents stale copies from resurrecting after partitions or
restarts:

```bash
curl -s -X DELETE -u "admin:${SB_ADMIN_PASSWORD}" \
  "http://127.0.0.1:9090/admin/compression/sessions/<id>" | jq .
```

## What to watch

- `sbproxy_ai_compression_state_operations_total{backend="mesh"}` counts
  session state operations and their outcomes.
- `mesh_compression_coordination_total` counts worker-local contention and
  stale-version commit rejections.
- The `mesh_replication_*`, `mesh_anti_entropy_*`, and `mesh_tombstone_gc_*`
  families cover the replication substrate itself.
