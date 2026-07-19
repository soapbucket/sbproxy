# Model host

*Last modified: 2026-07-19*

SBproxy can own model processes on one worker or place them across a managed
cluster. Model-host control lives under `proxy.model_host`. Depending on its
authority mode, desired deployments come from that file block, the durable
admin store, or a signed cluster bundle. An AI provider with
`provider_type: managed_model` exposes a deployment to clients. Requests still
pass through the normal key, policy, budget, routing, and usage planes before
they reach a local engine.

Use this page for the managed runtime. Provider-level `serve:` blocks still
load during the compatibility window, but new configurations should use the
canonical form below.

## Current boundary

The worker-local runtime is complete enough to operate as one coherent system:

- Catalog v2 resolves a logical model to an immutable source revision, exact
  files, sizes, SHA-256 digests, format, and worker requirements.
- The artifact manager resumes downloads under cross-process locks, verifies
  every file, and publishes a content-addressed snapshot atomically.
- Typed llama.cpp and vLLM drivers receive verified local paths. They cannot
  replace those paths with a repository reference at launch.
- One process-wide manager owns deployment generations, per-device memory,
  request admission, keep-alive, drain, crash-loop state, and durable jobs.
- Startup and every reload path prepare the full candidate before changing
  routes. Parse, validation, and preparation failures do not publish the
  candidate; activation and rollback failures have the recovery boundary
  documented under desired-state authority.
- The CLI can pull, inspect, remove, list running deployments, and stop one.
- One process-owned cluster handle carries key-cache, model-control, and
  private model-plane state. Versioned worker snapshots feed a lock-free
  directory, deterministic placement, failure-domain spread, readiness-gated
  rollout, and authenticated local or peer dispatch.
- An authenticated admin status contract lists every member and separates
  unhealthy-node alerts from the complete node roster.
- File-managed clusters report deployment digest drift. Cluster-authority mode
  verifies an Ed25519-signed, content-addressed desired-state bundle before the
  same atomic runtime commit used by file reload.
- Authenticated catalog and deployment APIs back a mode-aware admin UI. The UI
  can replace the complete admin-managed map, publish a signed map from an
  authority node, run lifecycle actions, and inspect cluster operations.

The preview distributed data plane has local coverage for authenticated HTTP/2
dispatch, unary and streaming responses, cancellation, bounded worker
admission, coordinated cold starts, and failover before client output. A
dedicated executable consumer contract, strict distributed budget reservation,
complete dynamic-key introspection, and live NVIDIA multi-node certification
remain later gates. Live hardware support remains governed by executable
evidence. The generated [capability matrix](model-host-capabilities.md) records
this boundary.

## Canonical configuration

This is the smallest useful file-managed deployment:

```yaml
# yaml-language-server: $schema=../schemas/sb-config.schema.json
proxy:
  http_bind_port: 8080

  admin:
    enabled: true
    bind: 127.0.0.1
    port: 9090
    username: admin
    password: ${SB_ADMIN_PASSWORD}

  model_host:
    authority: file_managed
    max_parallel_prepares: 1
    safety_margin: 0.10
    shutdown_deadline_ms: 30000

    cache:
      directory: /var/lib/sbproxy/models
      budget_gib: 100
      max_resident_models: 2

    engines:
      llama_cpp:
        launch: binary
        version: b9905
        acceleration: auto
      vllm:
        launch: uv
        version: 0.10.0
        acceleration: auto

    deployments:
      local-qwen:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m
        replicas: 1
        pull: on_boot
        warm: true
        keep_alive_secs: 1800
        max_concurrency: 4
        max_queue_depth: 32
        queue_timeout_ms: 30000
        engine: auto
        rollout: recreate

origins:
  "localhost":
    action:
      type: ai_proxy
      providers:
        - name: local
          provider_type: managed_model
          deployment: local-qwen
          models: [qwen]
          default_model: qwen
```

The deployment ID, `local-qwen`, is an operator identity. The provider exposes
the client model name `qwen`. Several origins may reference the same deployment,
and one origin may expose a different public name, without creating another
engine process.

The complete runnable example is
[`examples/model-host-managed`](../examples/model-host-managed).

## Cluster configuration

`proxy.cluster` is the canonical cluster surface. Every process owns exactly
one local or distributed handle. When `key_management.cache.tier: mesh` is also
configured, its legacy mesh fields must match and the key cache reuses this
handle instead of opening a second gossip or transport listener.

The node-specific portion of a production worker looks like this:

```yaml
proxy:
  cluster:
    cluster_id: production-models
    node_id: worker-a
    roles: [worker]
    labels: {region: us-central1, zone: us-central1-a, accelerator: l4}
    seeds: [10.10.0.10:7946]
    gossip_port: 7946
    transport_port: 8946
    advertise_addr: 10.10.0.21:7946
    transport_advertise_addr: 10.10.0.21:8946
    model_bind: 0.0.0.0:9443
    model_endpoint: https://10.10.0.21:9443
    state_dir: /var/lib/sbproxy/cluster
    snapshot_ttl_secs: 30
    publish_interval_secs: 5
    dead_peer_gc_secs: 300
    security:
      mode: mtls
      shared_key: file:/var/lib/sbproxy/cluster/gossip.key
      cert_file: /var/lib/sbproxy/cluster/node.pem
      key_file: /var/lib/sbproxy/cluster/node-key.pem
      ca_file: /var/lib/sbproxy/cluster/ca.pem
      server_name: sbproxy-mesh
```

Roles are independent and may be combined:

- `gateway` accepts public traffic and applies caller policy;
- `worker` publishes model capacity and owns assigned replicas;
- `authority` enrolls nodes or signs deployment revisions.

`advertise_addr` is the authenticated UDP gossip address. Enrolled mTLS nodes
must advertise an explicit routable IP and port so later SWIM traffic can be
matched to the signed join.
`transport_advertise_addr` is the mTLS typed-state address. `model_bind` is the
worker's dedicated private HTTP/2 listener. `model_endpoint` is the absolute
origin advertised in authenticated worker state and used by gateways. A worker
with `model_bind` must also advertise `model_endpoint`; production mTLS requires
`https://`, while explicit shared-key development mode requires `http://` h2c.
Identity, roles, labels, listeners, seeds, endpoints, security material, state
directory, enrollment authority, and signing authority are restart-required
fields. Snapshot cadence can reload in place.

Production mode requires mTLS plus a separate authenticated gossip key. Shared
key mode must set `development: true` and is for local fixtures only. Canonical
mTLS supports built-in enrollment and operator-managed PKI. Enrolled identities
carry an authority-signed manifest; manual-PKI identities carry the same strict
claims in an SBproxy URI SAN. Every leaf carries its unique node ID as a DNS
SAN, and outbound transport verifies that node ID. A cluster must use one
attestation mode consistently.

### Managed request dispatch

A `managed_model` request follows one governed path:

```text
public request
  -> authenticate caller and compile provider/model policy
  -> resolve the logical model to a deployment
  -> snapshot current-generation eligible replicas
  -> prefer a ready local or peer candidate
  -> acquire worker-local admission and ensure the generation is ready
  -> call the loopback engine and stream with backpressure
```

Local candidates use the same execution and admission contract without a
network hop. Peer candidates use the dedicated HTTP/2 model plane. The gateway
creates a fresh signed envelope for each peer attempt. The envelope binds the
gateway and worker node IDs, request ID, nonce, issue and expiry time, one-hop
count, tenant and governed key IDs, policy revision, deployment and generation,
logical model, priority, method, path, content type, and exact body SHA-256. It
never includes the public bearer value. The worker rejects unknown paths,
public authorization headers, wrong audiences, stale generations, expired or
replayed nonces, body mismatches, and envelopes whose hop count is not one.

Production dispatch requires mTLS with HTTP/2 ALPN. The peer proof is bound to
the negotiated leaf-certificate fingerprint, the issuer must have the gateway
role, and the configured cluster CA and server-name SAN must verify. Explicit
`security.mode: shared_key` plus `development: true` uses h2c and an HMAC only
for local fixtures. The modes cannot be mixed.

Replica admission is authoritative at the worker. `max_concurrency`,
`max_queue_depth`, `queue_timeout_ms`, drain state, crash-loop state, and the
deployment generation are rechecked there. Concurrent requests for one cold
replica generation share its worker-local launch. `cold_start` controls what a
gateway does when no replica is ready:

- `wait` dispatches to an assigned cold replica and waits through bounded
  preparation and admission;
- `reject` returns `503` with `Retry-After: 1` and does not start an engine;
- `fallback` advances to the next configured provider without starting the
  managed deployment.

For `authority: file_managed`, an omitted policy follows the security profile:
production mTLS clusters use `fallback`, while development and non-clustered
runtimes use `wait`. Admin-managed and cluster-authority deployments must set
`cold_start` explicitly. A retryable candidate failure may move to another
current replica only before response headers reach the client. Once a stream
begins, SBproxy relays partial output and never replays the request. A partial
SSE stream closes without `data: [DONE]`. Dropping the client response drops
the peer and engine streams and releases the admission permit.

Every AI origin serves `GET /v1/models` and `GET /models` locally as one
OpenAI-compatible logical list built from configured eligible providers and
models. Managed entries include `ready`, `cold`, or `unavailable` state, ready
and desired replica counts, and bounded capability names. The listing does not
call ordinary provider discovery endpoints and does not include node IDs,
engine ports, certificate data, or model endpoints. Successful inference
responses add only:

```text
x-sbproxy-logical-model: qwen
x-sbproxy-route-class: local | peer | external
```

Managed availability and cold-start errors that expose a public reason use one
OpenAI-style body with `type: managed_model_error`, a stable `code`,
`request_id`, `retryable`, and matching `sbproxy_reason`. The
`no_ready_replica` rejection is a retryable `503`. Other resolution,
authentication, TLS, and transport failures use the gateway's generic error
path; private detail stays in bounded logs and metrics.

### Initialize and enroll

Create the authority identity once on a trusted host:

```bash
sbproxy cluster init \
  --dir /var/lib/sbproxy/cluster \
  --cluster-id production-models \
  --node-id authority-a \
  --role gateway \
  --role authority \
  --label region=us-central1 \
  --label zone=us-central1-a
```

Configure that process with `roles: [gateway, authority]` and:

```yaml
enrollment:
  authority_dir: /var/lib/sbproxy/cluster
```

The enrollment admin listener must use HTTPS. Create a bounded, one-time token
whose roles and exact labels match the new node:

```bash
export SBPROXY_CLUSTER_TOKEN="$(sbproxy cluster token create \
  --dir /var/lib/sbproxy/cluster \
  --role worker \
  --label region=us-central1 \
  --label zone=us-central1-b \
  --ttl-secs 900)"

sbproxy cluster enroll \
  --url https://authority.internal:9090 \
  --ca-cert admin-ca.pem \
  --node-id worker-b \
  --role worker \
  --label region=us-central1 \
  --label zone=us-central1-b \
  --out /var/lib/sbproxy/cluster
```

The token store keeps only token hashes. Successful consumption is atomic, so
replay and concurrent reuse fail. The installed directory contains the node
certificate and key, cluster CA, gossip key, identity document, and deployment
authority verification key. Every successful enrollment for a stable node ID
advances its durable identity epoch. Certificate rotation uses a new enrollment
and a controlled process restart; identity changes are never partially
hot-reloaded.

Signed joins bind node ID, advertised gossip and typed-state addresses, a
durable boot epoch, and a two-minute proof lifetime to the certificate key. A
captured join cannot resurrect a dead process. A restarted node advances its
boot epoch and incarnation beyond stale dead gossip. A higher identity epoch
permits certificate rotation; the same epoch with a different certificate is
rejected. Receivers persist these peer high-water marks, so restart does not
re-enable an older certificate or boot. Direct joins replay only the bounded
live authenticated roster. Typed cluster-state envelopes are signed by the
same key and pass the same durable identity-epoch fence; snapshot roles and
labels must exactly match the authenticated identity before placement can use
them.

### Operator-managed PKI

Manual PKI is a production canonical-cluster option when an external CA owns
issuance. The leaf certificate must have a DNS SAN equal to `node_id` and
exactly one SBproxy identity URI SAN:

```text
urn:sbproxy:identity:v1:<base64url-without-padding-of-json>
```

The decoded JSON is strict and versioned:

```json
{"schema_version":1,"cluster_id":"production-models","node_id":"worker-a","roles":["worker"],"labels":{"region":"us-central1","zone":"us-central1-a"},"server_name":"sbproxy-mesh","identity_epoch":1}
```

Encode those exact claims as URL-safe base64 without padding, add the resulting
URI and `DNS:worker-a` to the CA-signed leaf, and configure the certificate,
key, and CA paths normally. Leave `identity.json` and
`authority-verifying.key` absent from `state_dir`; having only one is a startup
error. All nodes must use manual PKI, and rotation for the same node ID must
increment `identity_epoch`. SBproxy verifies the CA chain, expiry, node DNS
SAN, identity URI, configured claims, and proof of key possession.

Runnable templates are in
[`examples/model-cluster-symmetric`](../examples/model-cluster-symmetric) and
[`examples/model-cluster-split`](../examples/model-cluster-split).

Controllers write `model-deployment-generations.json` under `state_dir` before
publishing a placement commit. It retains every deployment high-water mark,
including deployments with no surviving replica snapshot. Do not copy this
file between node identities or delete it during an ordinary restart. A failed
prepared revision may consume a generation number; gaps are expected and let a
last-good configuration return without reusing the failed identity.

## Desired-state authority

`authority` says which system owns deployment definitions:

| Value | Behavior |
|---|---|
| `file_managed` | `sb.yml` is authoritative. The UI displays the configured map read-only and gives the exact edit and reload instruction. Every node computes placement from the same desired state and reports a digest mismatch when files differ. |
| `admin_managed` | The versioned store at `store_path` is authoritative. Authenticated API and UI writes replace its complete deployment map with optimistic concurrency, then the store supplies the same map after restart. |
| `cluster_authority` | One authority signs and publishes complete restricted deployment bundles. Its UI can publish; verifier nodes display the canonical signed map read-only. Every node verifies the signer, digest, schema, catalog, monotonic revision, and expiry before applying it. |

`admin_managed` is a single-node authority and cannot be combined with the new
cluster model-control plane. Multi-node admin publication uses
`cluster_authority`; invalid mixed configuration fails validation before a
runtime candidate is prepared.

### File-managed edits

The model-management UI never rewrites `sb.yml`. In `file_managed` mode it
disables persistent Add, Edit, and Remove controls and instructs the operator to
edit `proxy.model_host.deployments` in `sb.yml`, then reload SBproxy. Use either
of these explicit reload paths after saving the file:

```bash
sbproxy apply -f /etc/sbproxy/sb.yml

curl -u "admin:${SB_ADMIN_PASSWORD}" \
  -X POST \
  "${SB_ADMIN_URL}/admin/reload"
```

The file watcher and SIGHUP use the same prepare-and-commit transaction.
Lifecycle actions remain available for deployments already defined by the
file. Parse, validation, and preparation failures happen before runtime or
request-pipeline publication. A later activation failure can occur after a
recreate rollout has stopped an old generation. SBproxy attempts to restore
that generation, but restoration can fail and leave the current runtime
degraded. Inspect model-host status and logs, correct `sb.yml` or its runtime
dependencies, and reload again. Restart only after the authoritative file is
safe to apply.

### Authenticated catalog and local deployment API

All model-management routes use the admin server's authentication, RBAC, and
browser-session CSRF checks. `GET /admin/model-host/catalog` returns bounded
operator metadata from the active catalog. It includes each logical model's
family, parameter count, license, and context length, plus each variant's
format, quantization, compatible engines and accelerators, minimum memory,
download size, certification evidence, and support level.

This request selects one catalog entry from the full response:

```bash
curl -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/model-host/catalog" \
  | jq '{schema_version, catalog_revision, model: .models["qwen2.5-0.5b-instruct"]}'
```

The built-in catalog returns:

```json
{
  "schema_version": 1,
  "catalog_revision": "builtin-2026-07-10",
  "model": {
    "params": "0.5B",
    "license": "apache-2.0",
    "family": "qwen",
    "context_length": 32768,
    "variants": [
      {
        "id": "q4_k_m",
        "format": "gguf",
        "quant": "Q4_K_M",
        "engines": ["llama_cpp"],
        "accelerators": ["cpu", "metal", "cuda"],
        "min_memory_bytes": 1073741824,
        "download_size_bytes": 491400032,
        "certification": "bootstrap-metadata-2026-07-10",
        "stability": "preview"
      }
    ]
  }
}
```

`GET /admin/model-host/deployments` returns the complete map visible to the
local process together with its authority and write boundary:

```bash
curl -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/model-host/deployments" \
  | jq '{schema_version, authority, read_only, revision, deployments}'
```

An empty admin-managed store starts with this response:

```json
{
  "schema_version": 1,
  "authority": "admin_managed",
  "read_only": false,
  "revision": null,
  "deployments": {}
}
```

The unfiltered response also has `content_digest`. Both `revision` and
`content_digest` are `null` until the first admin-managed revision is stored.
File-managed and cluster-authority responses set `read_only: true` and do not
expose a local durable revision through this endpoint.

`PUT /admin/model-host/deployments` is available only in `admin_managed` mode.
Its `deployments` object is a complete replacement map, not a patch. Omitting an
existing ID removes it; renaming sends the new ID and omits the old ID. Read the
current document immediately before a write. Send `expected_revision: null`
only when the returned revision is `null`; otherwise send the exact unsigned
integer returned by GET. Admin JSON integers are capped at
`9,007,199,254,740,991`, JavaScript's largest exactly representable integer;
larger cursors are rejected instead of being rounded by the browser.

Local admin-managed state is single-node: a deployment runs any number of
replicas on this node's devices, but carries no cross-node placement intent
(heterogeneous variants, required labels, or spread keys). A deployment may set
`replicas` and a fixed `tensor_parallel` degree; each replica claims its own
disjoint device set, so `replicas` times `tensor_parallel` cannot exceed the
node's serving devices, and a request for more is rejected with the shortfall
named. A deployment with more than one replica must pin a variant. Cross-node
placement belongs in a signed cluster bundle published by the configured
authority node.

```bash
curl -u "admin:${SB_ADMIN_PASSWORD}" \
  -X PUT \
  -H 'content-type: application/json' \
  -d '{
    "expected_revision": null,
    "deployments": {
      "local-qwen": {
        "model": "qwen2.5-0.5b-instruct",
        "variant": "q4_k_m",
        "heterogeneous_variants": false,
        "replicas": 1,
        "required_labels": {},
        "spread_by": [],
        "pull": "on_demand",
        "warm": false,
        "keep_alive_secs": 1800,
        "max_concurrency": 4,
        "max_queue_depth": 32,
        "queue_timeout_ms": 30000,
        "engine": "llama_cpp",
        "rollout": "rolling"
      }
    }
  }' \
  "${SB_ADMIN_URL}/admin/model-host/deployments" \
  | jq '{schema_version, revision, plan}'
```

The first successful replacement returns:

```json
{
  "schema_version": 1,
  "revision": 1,
  "plan": {
    "added": ["local-qwen"],
    "changed": [],
    "removed": [],
    "preserved": []
  }
}
```

`200` means the new desired and runtime snapshot was published. Cleanup of an
old generation still uses a bounded drain after publication. A drain timeout or
retirement failure is not included in this PUT response, so inspect runtime
status and logs when a replacement or removal retires a running generation.

The unfiltered response also returns the 64-character SHA-256
`content_digest`. The server validates the strict body, complete desired-state
semantics, and catalog references first. Under one commit lock it then checks
the durable expected revision, assigns the next revision, and prepares the
complete runtime candidate before the durable compare-and-swap. A preparation
failure writes nothing. If another process advances the store during
preparation, the final compare-and-swap fails and the server tears down the
staged work. After a successful compare-and-swap, the server activates the
prepared revision in the live runtime. Activation preserves unaffected
generations and attempts to restore a stopped recreate generation when an
error occurs. That rollback can also fail. The durable revision then remains
advanced while the runtime can be degraded or only partly recovered.

Do not retry from the old cursor. Read the deployment document, runtime status,
and logs first. Recovery is explicit: repair the reported artifact, engine, or
capacity problem and submit a corrected complete map using the current durable
revision. Use Reset or Load when the reported lifecycle state calls for it, or
restart after confirming the persisted desired map and its dependencies are
safe. The persisted revision is loaded from `store_path` on restart.

The deployment API owns only `proxy.model_host` desired state. Provider routes
under `origins[].action.providers` remain configuration-owned and are never
added, renamed, or removed by an API or UI mutation. Configure a
`provider_type: managed_model` route to the deployment ID before exposing it to
clients. Add the desired deployment before adding its provider route. Remove or
retarget every provider route before removing or renaming its deployment;
otherwise PUT returns `400 invalid_desired`. The model-management API never
rewrites `sb.yml`.

Mutation failures use these status and code pairs:

| Status | Code | Meaning |
|---|---|---|
| `403` | `authority_read_only` | Local deployment replacement is disabled for the current authority. |
| `409` | `revision_conflict` | `expected_revision` differs from durable state. The response includes `expected_revision` and `actual_revision` when present. |
| `422` | A bounded preparation, admission, or compatibility reason such as `prepare_failed`, `insufficient_capacity`, `engine_incompatible`, or `artifact_not_ready` | The candidate could not be prepared before the durable compare-and-swap, so the store remains unchanged. |
| `502` | `runtime_commit_failed` | The compare-and-swap succeeded but runtime publication failed. The response sets `durable_state_advanced: true` and returns the new `revision` and `content_digest`. Reload desired state and runtime status before any correction. |
| `502` | A bounded infrastructure reason such as `prepare_infrastructure_failed`, `store_failed`, or an engine failure code | Storage, artifact transport, provisioning, or runtime infrastructure failed before durable publication. Detailed paths and transport diagnostics remain in server logs. |
| `413` | `request_body_too_large` | The admin request body exceeds the signed bundle limit of 512 KiB. |

Malformed bodies, unknown fields, duplicate map keys, invalid desired state,
and unknown catalog models or variants return `400` with a stable code such as
`invalid_body`, `invalid_desired`, `unknown_catalog_model`, or
`unknown_catalog_variant`.

Every authenticated mutation emits an audit record with `operator`, `role`,
`method`, and `path`. A successful local replacement also emits
`action=model_deployments_replace`, `source_mode=admin_managed`,
`prior_revision`, `next_revision`, `content_digest`, and `deployment_count` on
the `sbproxy::admin::audit` target. A post-CAS publication failure emits the
same cursor fields with `outcome=runtime_commit_failed`.

### Model-management UI

The Model host page joins catalog, desired-state, runtime, metrics, and cluster
authority responses without treating one stale response as current proof. Its
catalog browser keeps stable and preview variants available when they name at
least one engine and accelerator. Config-only, unsupported, and incomplete
variants remain visible as evidence but cannot be selected. The evidence panel
shows family, parameters, license, context, exact variant, format, quantization,
minimum memory, download size, engines, accelerators, certification, and
support level. An unavailable exact pin is shown as unavailable; the UI does
not substitute evidence from a different variant. Pickle variants fail closed
unless the logical catalog entry explicitly opts in with `allow_pickle: true`.

Creating a deployment or changing its logical model requires explicit license
acknowledgement. The form covers deployment ID, logical model, automatic or
exact variant selection, heterogeneous variants, replicas, required labels,
spread keys, pull policy, warm behavior, engine, rollout policy, keep-alive,
maximum concurrency, queue depth, and queue timeout. Add, edit, rename, and
remove operations always build one complete replacement map.

The local admin API accepts a deployment's `replicas` and `tensor_parallel`
directly, so multi-replica local deployments are configured through the
deployments endpoint or the config file. The local admin form currently fixes
replicas at one and hides heterogeneous, required-label, and spread controls;
those cross-node placement fields appear only for an authority node publishing
signed cluster placement intent.

Removal requires a fresh lifecycle response. A deployment in `ready`,
`preparing`, or `draining` state must be stopped first. If a write returns
`409`, the UI preserves the form and attempted complete map, displays the raw
response, reloads the current authority state, and shows an add/change/remove
comparison. Retry stays disabled unless the refreshed catalog, authority,
revision, digest, signer, and desired-map proof are coherent. Edit and rename
retries also verify that the original deployment baseline has not changed and
that the target ID did not appear. Removal retries fetch fresh lifecycle state
again before sending another write.

For any other mutation failure, the UI reloads catalog, desired state, and
runtime status because durable state may already have advanced. Signed cluster
failures also reload the authority cursor and bundle. The draft stays open.

### Cluster-authority publication

Cluster-authority bundles contain only the catalog revision, numbered desired
revision, deployments, and placement rules. Unknown fields and duplicate
deployment IDs are rejected. The authority publishes signed content and its
current pointer through the authenticated cluster state store before any
worker applies the revision. Each worker verifies the bundle and reconciles
placement, persists deployment generation fences, derives its local desired
state, and persists the authority cursor. Only then does it prepare and commit
the local runtime. After a successful commit, the worker publishes the new
cluster plan locally and marks the verified bundle active.

Runtime preparation or commit can fail after generation fences and the cursor
advance. The previous runtime may remain active, but those durable markers stay
advanced. If activation stopped a recreate generation, SBproxy attempts to
restore it. A failed restore leaves the worker degraded. Use cluster status,
model-host status, and logs to choose an authority-specific recovery.

Every node configures the public verification key and durable cursor state. The
authority alone also configures the private signing key:

```yaml
proxy:
  cluster:
    state_dir: /var/lib/sbproxy/cluster
    deployment_authority:
      verifying_key_file: /var/lib/sbproxy/cluster/authority-verifying.key
      # Authority node only:
      signing_key_file: /var/lib/sbproxy/cluster/authority-signing.key
  model_host:
    authority: cluster_authority
```

Publish a strict draft to the authority admin listener:

```bash
curl -u "admin:${SB_ADMIN_PASSWORD}" \
  -H 'content-type: application/json' \
  -d '{
    "catalog_revision":"builtin-2026-07-10",
    "revision":1,
    "deployments":{
      "local-qwen":{
        "model":"qwen2.5-0.5b-instruct",
        "variant":"q4_k_m",
        "replicas":2,
        "spread_by":["zone"],
        "pull":"on_boot",
        "warm":true,
        "engine":"llama_cpp",
        "rollout":"rolling"
      }
    }
  }' \
  "${SB_ADMIN_URL}/admin/cluster/deployments"
```

The authority returns this response shape:

```json
{
  "schema_version": 1,
  "revision": 1,
  "content_digest": "<64-character SHA-256>",
  "signer_node_id": "authority-1",
  "signer_key_id": "<configured verification-key ID>",
  "status": "published"
}
```

`202` confirms only that the authority signed the bundle and published its
content and current pointer. It does not prove that a worker accepted the
catalog revision, prepared an engine, received placement, or became ready.
Use `GET /admin/cluster/status` for worker application, placement, readiness,
and rollout truth. `GET /admin/cluster/deployments` returns the locally active
verified bundle and whether this node can publish. A node without the signing
key returns `403 deployment_authority_read_only` for POST and displays the
verified map read-only in the UI.

The UI publishes from the signed bundle's complete deployment map, never from a
worker-local projection. It accepts that map as canonical only when fresh
cluster status and bundle responses agree on the authority revision, content
digest, signer node, signer key, and active catalog revision. With no active
bundle, a fresh `404` whose parsed body has
`code: deployment_bundle_missing`, plus a fresh authority status whose active
revision is `null`, proves an empty canonical map; the first publication uses
revision `1`. A generic proxy or intermediary `404` is not publication proof.

The UI uses exactly the next revision. The backend also accepts any higher
positive revision and treats the same revision with the same digest as an
idempotent publication. A lower revision returns `409 stale_revision`; an equal
revision with different content returns `409 revision_conflict`. The UI handles
either conflict with the same preserved draft and coherent-proof reload used
for local admin conflicts. A revision lower than the durable cursor is also
rejected after restart. The active bundle is republished before its bounded
seven-day state lifetime expires.

## Deployment fields

`model` must be a catalog v2 logical ID. `variant` pins one exact artifact.
Omitting it lets the worker choose a compatible variant, but a deployment with
more than one replica must pin a variant unless
`heterogeneous_variants: true` is explicit.

Pull policy controls cache misses:

- `on_boot` verifies the artifact while the candidate revision is prepared.
- `on_demand` waits until the first request needs the deployment.
- `manual` refuses a cache miss. Run `sbproxy models pull` first.

`warm: true` goes beyond artifact verification and starts the engine before the
revision becomes active. Use it when readiness must mean the first token path is
available. A warm failure prevents local runtime activation. It does not prove
that authority state stayed unchanged: an admin deployment-store revision or a
cluster worker's generation fences and authority cursor may already have
advanced. Read desired state, model-host status, and logs before recovery. Fix
and reload the authoritative file, submit a corrected admin map from the
current revision, or repair the cluster worker and reconcile the signed bundle,
depending on the active authority.

`cold_start` is `wait`, `reject`, or `fallback`. `wait` coordinates one launch
per selected cold replica generation and holds callers within admission bounds.
`reject` starts nothing and returns a retryable `503` with `Retry-After: 1`.
`fallback` starts nothing and advances to the next provider in the route. With
`authority: file_managed`, omission follows the security profile: production
mTLS clusters use `fallback`, while development and non-clustered runtimes use
`wait`. Admin-managed and cluster-authority deployments must set the field
explicitly.

`rollout: rolling` starts target assignments before draining losing
assignments. The old generation remains retained until every target reports the
exact generation, variant, artifact digest, and ready state, or until
`handoff_timeout_ms` expires. `recreate` emits a drain-only step before it may
start the target. Placement rejection happens before generation fences or the
authority cursor advance. Worker-local preparation happens after those writes;
its failure leaves the previous local plan unpublished and the prior runtime
may remain active, while fences and the cursor stay advanced.

`required_labels` filters workers before ranking. `spread_by` is an ordered set
of failure-domain labels, such as `[zone, rack]`; placement prefers a new value
at each level before comparing the weighted rendezvous score. A missing label
is an explicit `unknown` domain. Input order never affects the result, and
adding or removing one worker moves only assignments whose ranking changes.

Replicas greater than one must pin `variant` unless
`heterogeneous_variants: true` is explicit. A manual-pull deployment can be
assigned only to workers that already report the exact verified artifact.
`on_boot` and `on_demand` assignments may acquire the artifact locally after
placement. Each worker projection is exact-variant pinned, warm, single-replica,
and fenced to the cluster deployment generation.

## Serve model settings

An inline `serve:` provider hosts one or more models under `serve.models[]`.
Each entry accepts these settings.

| Setting | Purpose |
|---|---|
| `model` | Catalog id (`qwen3-32b`) or a raw `hf:Org/Repo[:QUANT]` reference. Required. |
| `name` | Client-facing model id that routing, budgets, and the ledger see. Defaults to the catalog id, and is required for a raw `hf:` reference. |
| `variant` | Exact catalog v2 artifact variant to run. Omitting it lets the worker select a compatible variant. |
| `engine` | Engine to serve with: `auto` (default), `vllm`, `sglang`, `llama_cpp`, or `embedded`. |
| `modality` | Task the model performs: `chat` (default), `embedding`, `rerank`, `speech_to_text`, `text_to_speech`, or `image`. It drives the engine's task flag (`embedding` serves `--task embed`, `rerank` serves `--task score`) and zeroes the KV-cache term in the fit. Set it to serve an embedding or rerank model from a raw `hf:` reference, which has no catalog entry to carry the modality. |
| `max_context` | Context length to plan VRAM for and pass to the engine. |
| `keep_alive` | Idle time before the engine unloads, as a duration like `30m` or `1h`. Omitting it keeps the engine resident until eviction. |
| `kv_quant` | KV-cache quantization: `auto` (default), `f16`, `fp8`, `int8`, or `int4`. |
| `pinned` | Keep the model resident and never evict it to make room. |
| `gguf_file` | Exact GGUF filename to serve from a multi-file llama.cpp repo. |
| `extra_args` | Extra engine flags appended after the runtime's own arguments, one argv element each, filtered against an allowlist. |
| `tool_call_parser` | vLLM tool-call parser (`hermes`, `llama3_json`, `mistral`) that enables auto tool choice. |
| `swap_space_gib` | CPU KV-cache tier in GiB (vLLM `--swap-space`). |
| `cpu_offload_gib` | GiB of weights kept in CPU RAM (vLLM `--cpu-offload-gb`). |
| `reference` | Hosted model this local model displaces, used to price the dollars-saved value report. |

Host-wide settings sit on the `serve:` block itself.

| Setting | Purpose |
|---|---|
| `catalog_file` | Operator catalog file that replaces the built-in certified catalog. |
| `cache_dir` | Directory for the content-addressed weight cache. |
| `cache_budget_gib` | Disk budget in GiB for the weight cache before garbage collection. |
| `eviction` | VRAM-pressure policy: `lru` (default) or `never`. |
| `engines` | Per-engine provisioning map (`launch`, `image`, `acquire`, `shm_size_gib`). |
| `max_concurrent_requests` | Cap on concurrently dispatched served-lane requests. |
| `queue_timeout_ms` | How long a queued request waits for a slot before failover. Default 30000, read only when `max_concurrent_requests` is set. |

## Value delivered

The authenticated `GET /admin/model-host/value` endpoint reports two separate
sources of value:

- locally served completions priced against each model's configured
  `reference`;
- target-model input tokens and gross input cost avoided by each successful
  context-compression lever.

Compression does not count as a local or cloud completion. The request path
records it only after the terminal provider attempt returns a billable `2xx`.
Each `compression` row names the target `model`, closed `lever`,
`tokens_saved`, `gross_cost_saved_micros`, and `token_count_precision`.
`compression_totals` aggregates those rows by lever, and the top-level
`total_compression_tokens_saved` and
`total_compression_gross_cost_saved_micros` give the complete compression
total.

The precision value is `model_tokenizer` when the target model resolves to a
registered tokenizer, or `heuristic` when SBproxy uses its UTF-8 byte-length
fallback. Unknown input pricing yields zero gross cost and keeps the token
saving. The amount is gross because dedicated summarizer spend remains in the
normal usage stream instead of being silently netted out.

```bash
curl -fsS -u "admin:${SB_ADMIN_PASSWORD}" \
  "${SB_ADMIN_URL}/admin/model-host/value" \
  | jq '{models,compression,compression_totals,total_compression_tokens_saved}'
```

The same endpoint is available when no local model is configured. In that
compression-only case, `models` contains a zeroed local-serving row for each
compression target, while all local and cloud completion totals remain zero.
Compression uses a bounded in-memory ledger unless an AI handler initializes
the current durable compatibility path: one provider-level
`providers[].serve` block must both contain at least one `models[].reference`
and set `cache_dir`, which stores the process-wide ledger at
`<cache_dir>/value-ledger.redb`. Later activation promotes the same shared
in-memory ledger in place and merges existing totals, preserving preexisting
value sinks and Admin readers. The first successful durable path is canonical;
a conflicting later path emits a bounded warning and keeps using it.
`proxy.model_host.cache.directory` does not currently activate that ledger.

The ledger caps the complete lane set at 1,000 entries, including the
deterministic `__other__` overflow lane. After 999 non-overflow model names,
additional names combine under `__other__`.

## Artifacts and cache safety

The cache root contains `blobs/sha256`, `snapshots`, `metadata`, `partials`,
`locks`, and `jobs`. A snapshot becomes ready only after every declared file
matches its exact byte length and SHA-256. Unsafe pickle artifacts require an
explicit catalog opt-in and a supply-chain scan.

Source credentials are transport-only. They are redacted in errors, zeroized on
drop, and never written to snapshot or job metadata. Explicit pulls accept
`HF_TOKEN` and `HUGGING_FACE_HUB_TOKEN` for gated repositories.

`cache.budget_gib` is enforced by explicit pull-time collection. Collection
protects configured, resident, pinned, locked, downloading, verifying, and
deleting artifacts, and it accounts for shared blobs. A live runtime holds a
cross-process digest lease, so another CLI process cannot remove its snapshot
between a stale status check and deletion. Continuous collection after every
on-demand acquisition is still outside the stable contract.

### Lifecycle commands

Progress always goes to stderr. JSON goes to stdout without ANSI control bytes
or carriage returns.

```bash
# Pull every configured deployment plus catalog entries marked on_boot.
sbproxy models pull -f sb.yml

# Pull one exact artifact without allowing network access.
sbproxy models pull qwen2.5-0.5b-instruct \
  --variant q4_k_m \
  --offline \
  --format json

# Inspect the catalog and cache.
sbproxy models list --format json
sbproxy models show qwen2.5-0.5b-instruct --format json

# Remove one exact artifact. Configured or resident artifacts fail closed.
sbproxy models remove qwen2.5-0.5b-instruct \
  --variant q4_k_m \
  --cache-dir /var/lib/sbproxy/models \
  --format json

# Reclaim content-addressed blobs referenced by no cached artifact,
# such as orphans left by an interrupted pull. --dry-run reports the
# reclaimable bytes without deleting anything.
sbproxy models prune --cache-dir /var/lib/sbproxy/models --dry-run
sbproxy models prune --cache-dir /var/lib/sbproxy/models
```

Because the weight store is content-addressed, two models that share a shard
store it once, and `prune` reclaims only blobs that no cached artifact still
references, so a shared blob survives while its last reference remains. Prune
runs under the same collection lock as the cache-budget sweep, so it never
races a concurrent pull.

Every JSON command uses `schema_version: 1` and a stable command name such as
`models.pull`, `models.remove`, or `models.prune`. Pull and removal results
include durable job IDs when a mutation occurred.

## Managed engines

The runtime reports one of four availability states before provisioning:

| State | Meaning |
|---|---|
| `available` | A compatible executable is already present. |
| `acquirable` | The pinned engine can be fetched, built, or provisioned. |
| `incompatible` | The artifact, engine, or worker cannot run together. |
| `blocked` | Host policy or an incomplete pin prevents safe provisioning. |

### llama.cpp

llama.cpp consumes one verified GGUF path. The driver prefers an explicitly
allowlisted path, then a compatible executable on `PATH`, then pinned
acquisition. The built-in b9905 release assets have checked-in per-platform
SHA-256 digests. Downloads use a release lock and publish under an
asset-identity directory only after verification, so later starts reuse the
same archive and executable. Apple Silicon uses Metal, and a CPU worker uses
system RAM.

llama.cpp is the engine for GGUF models on CPU and Apple Metal. NVIDIA GPU
serving is handled by the vLLM and SGLang container engines, not llama.cpp, so
point a GPU deployment at one of those.

```yaml
engines:
  llama_cpp:
    launch: binary
    version: b9905
    acceleration: auto   # Metal on Apple Silicon, otherwise CPU
```

Live CUDA validation is part of the final GCP PR, so this path remains preview
despite deterministic source-build coverage in CI.

### vLLM in a container (default)

The most reliable way to serve a GPU model is a digest-pinned engine container.
The image ships the whole CUDA and Python toolchain, so the host needs nothing
beyond a container runtime and an NVIDIA driver, and there is no host build
cascade to hit. This is the default: when the worker has a container runtime
(Docker or Podman) and you have not configured vLLM provisioning yourself,
SBproxy runs vLLM from a curated digest-pinned image. The smallest useful
config names no image at all and still serves in a container.

Container mode accepts only an immutable `repository@sha256:<digest>` image.
The runtime creates a private internal network, mounts the verified artifact
read-only, publishes the engine only on loopback, scopes the selected NVIDIA
devices, and passes shared memory as a validated typed setting.

To pin your own image instead of the curated default, set it explicitly:

```yaml
engines:
  vllm:
    launch: container
    # Replace this example digest with the approved image digest.
    image: vllm/vllm-openai@sha256:0000000000000000000000000000000000000000000000000000000000000000
    acceleration: cuda
    shm_size_gib: 8
```

Tagged images, `latest`, writable artifact mounts, arbitrary container argv, and
unscoped devices are rejected. Live container certification is deferred to the
final GCP PR.

### vLLM with uv (no-docker fallback)

Where a host cannot run containers, vLLM can run from a managed, version-pinned
uv environment in the engine cache instead. This is the advanced path: it
builds vLLM against the host, so the host itself must supply the toolchain the
container would otherwise carry.

```yaml
engines:
  vllm:
    launch: uv
    version: 0.10.0
    acceleration: cuda
```

Before choosing this path, make sure the host provides what the vLLM wheel and
its Triton JIT need, on top of the NVIDIA driver:

- Python development headers matching the engine's Python (`Python.h`, from
  `python3-dev` / `python3-devel`).
- `ninja`, the build tool the compile step invokes.
- A CUDA development toolchain, meaning `nvcc` and the CUDA headers, not just
  the runtime driver.

A box missing any of these fails the compatibility check with a bounded
remediation rather than falling back to an unrelated Python environment. That
missing-toolchain cascade is exactly what the container path avoids, so prefer
the container unless you genuinely cannot run one. Launch bounds `max-num-seqs`
to deployment concurrency and derives the engine KV-cache byte limit from the
admitted memory estimate.

### SGLang

SGLang runs the same OpenAI-compatible server model as vLLM and loads the same
safetensors weights on a CUDA worker. The real launch is `python -m
sglang.launch_server`, so there is no single binary to install: the runtime
provisions it from a digest-pinned container or a pinned uv environment, the
same two paths vLLM uses and with the same container-first preference. The
readiness probe and dispatch path are identical.

```yaml
engines:
  sglang:
    launch: uv
    version: 0.4.6.post1
    acceleration: cuda
models:
  - model: qwen3-32b
    engine: sglang
```

Choose SGLang when you want RadixAttention prefix caching, higher structured-output
throughput, or better behavior under high-concurrency agent traffic. It shares
tensor parallelism, quantization, and context sizing with vLLM, and the runtime
owns `--model-path`, `--host`, `--port`, and `--tp-size` so config cannot
contradict the device placement. Its stable extra-argument allowlist is
`--enable-torch-compile`, `--disable-radix-cache`, `--schedule-conservativeness`,
and `--mem-fraction-static`.

vLLM stays the default. SGLang is an explicit opt-in: `engine: auto` never
resolves to it, and you name `engine: sglang` on a model or an `sglang` block
under `engines:` to select it. It ships at preview support until it is certified
on real NVIDIA hardware, and it targets CUDA only for now.

## Admission and residency

Each deployment has its own active cap and bounded queue. Priority is read from
the authenticated key record, never from a client header. Waiting requests are
FIFO within a class, with `interactive` ahead of `standard`, then `batch`.

Memory admission uses the selected device and a full estimate:

```text
weights + KV cache + runtime overhead + safety margin = reserved bytes
```

The residency manager never evicts active, queued, preparing, draining, or
pinned generations. It does not substitute the largest device's free memory for
the selected device's capacity. `cache.max_resident_models` is one global count
across all devices. Compatibility `eviction: never` rejects a load that would
displace any resident generation.

Stable admission reason codes are:

| Reason | Operator action |
|---|---|
| `insufficient_capacity` | Choose a smaller variant, reduce context or concurrency, use `recreate`, or move the deployment to a larger device. |
| `queue_full` | Increase `max_queue_depth`, reduce callers, or add a fallback provider. |
| `queue_timeout` | Raise `queue_timeout_ms`, reduce load, or add a fallback. |
| `engine_unhealthy` | Inspect the retained engine error and reset after correcting the cause. |
| `crash_loop` | Fix the engine or artifact problem, then call reset. Automatic retries stay bounded. |
| `draining` | Wait for the stop or replacement operation to finish. |

Keep-alive starts after the last request permit is released. Active or queued
work pauses expiry. A draining deployment rejects new work and waits up to the
configured shutdown deadline for active requests.

## Status and operations

The admin listener is authenticated and should remain on loopback unless TLS,
an IP allowlist, and an operator network are configured together.

```bash
export SB_ADMIN_URL=http://127.0.0.1:9090
export SB_ADMIN_USERNAME=admin
export SB_ADMIN_PASSWORD='replace-me'

sbproxy models ps --format json
sbproxy models stop local-qwen --format json
```

`models ps` reports deployment generation, state, engine availability, artifact
digest, selected devices, complete memory estimate, loopback engine port, active
and queued counts, reason code, job ID, and bounded last error. `models stop`
enters drain and then stops the selected deployment. The verified artifact stays
in cache for a later restart.

The equivalent authenticated routes are:

```text
GET    /admin/model-host/catalog
GET    /admin/model-host/deployments
PUT    /admin/model-host/deployments
GET    /admin/model-host/status
GET    /admin/model-host/files
DELETE /admin/model-host/artifacts/{digest}
POST   /admin/model-host/gc
POST   /admin/model-host/load
POST   /admin/model-host/stop
POST   /admin/model-host/drain
POST   /admin/model-host/evict
POST   /admin/model-host/reset
GET    /admin/cluster/artifacts
```

Load, stop, drain, evict, and reset accept
`{"deployment":"local-qwen"}`. Stop and drain perform the same bounded drain
and shutdown; evict is their compatibility alias. The legacy `model` request
field remains an input alias during the compatibility window. The Model host UI
exposes Load, Stop, and Reset against these shared lifecycle actions.

Cluster operators use the same admin credentials:

```bash
sbproxy cluster status --admin-url "${SB_ADMIN_URL}" --format text
sbproxy cluster status --admin-url "${SB_ADMIN_URL}" --format json
```

`GET /admin/cluster/status` is the stable cluster-view backend. It always lists
the complete membership roster, including unhealthy and excluded nodes. Each
node includes membership state, acknowledgement age, health, stable reasons,
roles, labels, model endpoint, snapshot age and generation, engine/device and
artifact counts, replica truth, model eligibility, and exclusion reason. The
top-level `unhealthy_nodes` array repeats only actionable nodes so an admin UI
can render a prominent alert without hiding them from the main table.

Routing membership may remove a dead peer after `dead_peer_gc_secs`. The model
directory separately retains a bounded long-lived tombstone with the last safe
snapshot and current exclusion reason, so the admin roster and unhealthy alert
do not silently lose failed nodes after routing GC.

The response also includes healthy/degraded/unhealthy counts, eligible workers
and replicas, deployment digest consistency, exact target assignments,
unplaced replicas and rejection reasons, retained and draining assignments,
rollout phase and deadline, and signed-authority state. Suspect, dead,
unreachable, stale, incompatible, and explicitly unhealthy workers remain
visible but receive no new assignments.

The Cluster page renders every node in a health rail and keeps unhealthy nodes
in two places: prominent alert cards for immediate action and the complete
roster for full membership context. The rail links each node to its roster row.
A failed status refresh leaves the last loaded snapshot visible under a stale
warning, while a stale model directory receives its own control-plane warning.

Deployment rollout rows show desired, placed, and unplaced replicas; generation
and phase; target readiness and timeout; handoff deadline; exact assignments;
retained and draining generations; and bounded placement rejection reasons.
Fleet metrics are secondary telemetry fetched independently from cluster status.
A missing, loading, or failed metrics response does not hide the primary health,
roster, alert, or rollout state.

Useful metrics include `sbproxy_model_host_active_requests`,
`sbproxy_model_host_queued_requests`, `sbproxy_model_host_deployment_state`,
`sbproxy_model_host_admission_rejections_total`, GPU VRAM, compute utilization,
and memory occupancy. Distributed request signals are
`sbproxy_managed_replica_attempts_total`,
`sbproxy_managed_replica_failovers_total`,
`sbproxy_model_plane_peer_dispatch_seconds`,
`sbproxy_model_plane_stream_cancellations_total`, and
`sbproxy_model_plane_rejections_total`. Their route, outcome, reason, and retry
labels are bounded, and no label contains a node ID or endpoint. Unknown compute
utilization stays absent; memory occupancy is a separate measurement and never
masquerades as compute activity.

## Reload behavior

The runtime collects canonical and compatibility deployments from every origin.
It validates the complete catalog, cache and engine policy, and routes while it
stages the candidate. During commit it reserves capacity, then starts each warm
engine before snapshot activation. On success it preserves unchanged engine
generations and replaces only changed deployments. Validation and initial
preparation failures tear down staged work before runtime publication. A later
warm or recreate activation failure attempts to restore any stopped prior
generation. Restore can fail and leave that generation degraded, so status and
logs are part of recovery.

A cache root, catalog revision, or engine foundation cannot change under a
resident deployment. Reconcile to an empty desired state first, then apply the
new foundation. This rule prevents two incompatible artifact stores or engine
sets from living in one worker process.

For `admin_managed` authority, the empty durable store adopts the new catalog
as its next monotonic revision under the cross-process store lock. A nonempty
store remains catalog-fenced and the reload fails until the operator drains it.

Cluster reconciliation shares that commit lock. Every process computes the
same global target from one immutable directory view, then filters it to exact
assignments for its stable node ID. The worker persists generation fences and
the authority cursor before it prepares and commits that local projection. It
publishes the new local cluster plan and marks the bundle active only after the
runtime commit succeeds. Preparation or commit failure can therefore leave the
cursor and fences advanced while the prior runtime and plan may remain active.
An activation restore failure can instead leave the node degraded.
Control-only nodes keep a catalog-aligned empty runtime and never create an
engine merely to participate in placement.

## One-command local run

`sbproxy run` is the fastest route to the same canonical runtime:

```bash
sbproxy run qwen2.5-0.5b-instruct --variant q4_k_m
```

It accepts certified catalog IDs, resolves the exact artifact against the real
worker, generates a high-entropy loopback admin credential, writes a private
temporary config, enables `pull: on_boot` and `warm: true`, and waits for the
deployment to report `ready`. Only then does it print the endpoint, admin
credential, curl request, `OPENAI_BASE_URL`, and `OPENAI_API_KEY` settings.
The owner-only temporary config is removed when the command returns, including
startup and readiness failures.

Raw `hf:` references are deliberately rejected by this command because they
bypass the catalog v2 identity. Set `proxy.model_host.catalog_file` to select a
catalog v2 document for canonical managed deployments. Relative paths resolve
from the directory containing `sb.yml`; omission uses the built-in catalog.

## Migrating from provider `serve:`

Compatibility lowering reads every provider-level `serve:` block, assigns a
deterministic deployment ID, and routes its public model name through the same
runtime manager. Equivalent declarations deduplicate. Conflicting routes, cache
roots, or host policies reject the entire candidate instead of picking the first
origin.

Move host policy to `proxy.model_host`, then replace each provider block:

```yaml
# Compatibility form
- name: local
  models: [qwen]
  serve:
    cache_dir: /var/lib/sbproxy/models
    models:
      - model: qwen2.5-0.5b-instruct
        name: qwen
        variant: q4_k_m
        engine: llama_cpp
        keep_alive: 30m
```

with:

```yaml
proxy:
  model_host:
    cache:
      directory: /var/lib/sbproxy/models
    deployments:
      local-qwen:
        model: qwen2.5-0.5b-instruct
        variant: q4_k_m
        engine: llama_cpp
        keep_alive_secs: 1800

origins:
  "localhost":
    action:
      type: ai_proxy
      providers:
        - name: local
          provider_type: managed_model
          deployment: local-qwen
          models: [qwen]
```

Raw repository references, `gguf_file`, arbitrary legacy engine knobs, and
unsupported LoRA, speculative, chunked-prefill, parser, swap, or offload fields
do not silently survive canonical preparation. Pin a catalog v2 artifact and
remove unsupported fields before the compatibility window closes.

## Related guides

- [quickstart-serve.md](quickstart-serve.md) covers the first local completion.
- [security-model-host.md](security-model-host.md) defines process, artifact,
  credential, and container boundaries.
- [admin.md](admin.md) covers admin authentication and lifecycle routes.
- [model-host-certification.md](model-host-certification.md) is the hardware
  validation procedure and current evidence ledger.
