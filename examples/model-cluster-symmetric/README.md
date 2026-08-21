# Symmetric managed-model cluster

This local development example runs two identical gateway/worker processes.
Both replicas use one canonical cluster handle for the model controller and mesh
key cache. The deployment pins one variant and spreads its two replicas across
the `zone` label. Each process accepts managed requests locally and can dispatch
to the other replica over its loopback development model plane.

Build once, then start node A:

```bash
export SB_ADMIN_PASSWORD=local-admin
export SB_NODE_ID=node-a SB_ZONE=local-a
export SB_HTTP_PORT=8081 SB_ADMIN_PORT=9091
export SB_GOSSIP_PORT=17946 SB_TRANSPORT_PORT=18946 SB_MODEL_PORT=19443
export SB_SEED=127.0.0.1:17947 SB_STATE_DIR=./state/node-a
export SB_MODEL_CACHE_DIR="$HOME/.cache/sbproxy-models"
sbproxy -f examples/model-cluster-symmetric/sb.yml
```

In another shell, start node B:

```bash
export SB_ADMIN_PASSWORD=local-admin
export SB_NODE_ID=node-b SB_ZONE=local-b
export SB_HTTP_PORT=8082 SB_ADMIN_PORT=9092
export SB_GOSSIP_PORT=17947 SB_TRANSPORT_PORT=18947 SB_MODEL_PORT=19444
export SB_SEED=127.0.0.1:17946 SB_STATE_DIR=./state/node-b
export SB_MODEL_CACHE_DIR="$HOME/.cache/sbproxy-models"
sbproxy -f examples/model-cluster-symmetric/sb.yml
```

Inspect either node:

```bash
export SB_ADMIN_URL=http://127.0.0.1:9091
export SB_ADMIN_USERNAME=admin SB_ADMIN_PASSWORD=local-admin
sbproxy cluster status --format text
sbproxy cluster status --format json \
  | jq '{summary,nodes,unhealthy_nodes,deployments}'
```

Send a request to either gateway:

```bash
curl --include http://127.0.0.1:8081/v1/chat/completions \
  -H 'Host: localhost' \
  -H 'content-type: application/json' \
  -d '{"model":"qwen","messages":[{"role":"user","content":"hello"}]}'
```

The `Host: localhost` header is required: it is the origin key in `sb.yml`,
and without it the request has no matching origin and gets a 404 rather than
reaching the deployment.

The response carries `x-sbproxy-logical-model` and `x-sbproxy-route-class`
headers (confirmed: `qwen` and `local`) but no port, model-plane endpoint, or
worker identity. `sbproxy cluster status --format json` (above) is where that
detail lives, gated behind the admin API.

Stop one process. The surviving status retains the failed node in `nodes`, adds
it to `unhealthy_nodes`, and excludes it from model eligibility. Start it again
to observe recovery.

This example deliberately uses `security.mode: shared_key` with
`development: true`. Use the split-role mTLS example or enrollment for
production identity. Its `http://` model endpoint is accepted only by explicit
development mode. Production workers require mTLS and an `https://` endpoint.
