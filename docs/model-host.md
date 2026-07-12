# Model host

*Last modified: 2026-07-11*

SBproxy can own model processes on one worker or place them across a managed
cluster. Desired models live under `proxy.model_host`; an AI provider with
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
  routes. A bad candidate leaves the last good runtime in place.
- The CLI can pull, inspect, remove, list running deployments, and stop one.
- One process-owned cluster handle carries key-cache and model-control state.
  Versioned worker snapshots feed a lock-free directory, deterministic
  placement, failure-domain spread, and readiness-gated rollout.
- An authenticated admin status contract lists every member and separates
  unhealthy-node alerts from the complete node roster.
- File-managed clusters report deployment digest drift. Cluster-authority mode
  verifies an Ed25519-signed, content-addressed desired-state bundle before the
  same atomic runtime commit used by file reload.

This PR completes the cluster control plane, not the distributed inference data
plane. A gateway can inspect placement and operate a co-located assigned
replica, but it does not dispatch a request to a remote worker until the next
data-plane PR. Persistent model selection and desired-state editing in the
admin UI remain in the operator-product PR. Live NVIDIA and multi-node
certification on GCP is deliberately reserved for the final integration PR.
The generated
[capability matrix](model-host-capabilities.md) records this boundary.

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
`transport_advertise_addr` is the mTLS typed-state address. A worker also needs
an HTTPS `model_endpoint`; PR 3 records it for placement, while PR 4 will use it
for remote inference. Identity, roles, labels, listeners, seeds, endpoints,
security material, state directory, enrollment authority, and signing authority
are restart-required fields. Snapshot cadence can reload in place.

Production mode requires mTLS plus a separate authenticated gossip key. Shared
key mode must set `development: true` and is for local fixtures only. Canonical
mTLS supports built-in enrollment and operator-managed PKI. Enrolled identities
carry an authority-signed manifest; manual-PKI identities carry the same strict
claims in an SBproxy URI SAN. Every leaf carries its unique node ID as a DNS
SAN, and outbound transport verifies that node ID. A cluster must use one
attestation mode consistently.

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
| `file_managed` | `sb.yml` is authoritative. Every node computes placement from the same desired state and reports a digest mismatch when files differ. |
| `admin_managed` | A revision store at `store_path` is authoritative. The runtime and restart-safe store contract exist, but public desired-state CRUD and the management UI ship in a later PR. |
| `cluster_authority` | One authority signs and publishes strict deployment bundles. Every node verifies the signer, digest, schema, monotonic revision, and expiry before applying it. Non-authority writes return `deployment_authority_read_only`. |

`file_managed` participates in ordinary config reload. Editing the file,
`sbproxy apply`, the file watcher, and `POST /admin/reload` all use the same
prepare-and-commit transaction.

Cluster-authority bundles contain only the catalog revision, numbered desired
revision, deployments, and placement rules. Unknown fields and duplicate
deployment IDs are rejected. The current pointer and content are published
separately through the authenticated cluster state store, and readers retain
their last good revision after signature, identity, rollback, or runtime
prepare failure.

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

The authority returns `202` with the revision, content digest, signer node, and
signer key. `GET /admin/cluster/deployments` returns the locally active verified
bundle. A revision lower than the durable cursor is rejected after restart;
equal revision with different content returns `revision_conflict`. The active
bundle is republished before its bounded seven-day state lifetime expires.

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
available. A warm failure aborts the candidate revision.

`rollout: rolling` starts target assignments before draining losing
assignments. The old generation remains retained until every target reports the
exact generation, variant, artifact digest, and ready state, or until
`handoff_timeout_ms` expires. `recreate` emits a drain-only step before it may
start the target. A failed placement or worker-local prepare preserves the
prior committed plan and runtime.

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
```

Every JSON command uses `schema_version: 1` and a stable command name such as
`models.pull` or `models.remove`. Pull and removal results include durable job
IDs when a mutation occurred.

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

Linux CUDA can build the pinned llama.cpp source archive on the node. The build
requires Linux x86-64, an NVIDIA driver, `nvcc`, CMake, a C or C++ compiler, and
`tar`. The source URL and SHA-256 are fixed, concurrent builders share one lock,
and only an executable final binary is published. A custom source tag needs an
explicit archive digest.

```yaml
engines:
  llama_cpp:
    launch: binary
    version: b9905
    acceleration: cuda
```

Live CUDA validation is part of the final GCP PR, so this path remains preview
despite deterministic source-build coverage in CI.

### vLLM with uv

vLLM consumes a read-only verified snapshot and requires a CUDA worker. Managed
uv mode creates a version-pinned environment in the engine cache:

```yaml
engines:
  vllm:
    launch: uv
    version: 0.10.0
    acceleration: cuda
```

Compatibility checks report Python, torch, CUDA, and vLLM mismatches with a
bounded remediation. A failed check does not fall back to an unrelated Python
environment. Launch bounds `max-num-seqs` to deployment concurrency and derives
the engine KV-cache byte limit from the admitted memory estimate.

### vLLM in a container

Container mode accepts only an immutable `repository@sha256:<digest>` image.
The runtime creates a private internal network, mounts the verified artifact
read-only, publishes the engine only on loopback, scopes the selected NVIDIA
devices, and passes shared memory as a validated typed setting.

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
unscoped devices are rejected. Live container certification is also deferred to
the final GCP PR.

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
GET  /admin/model-host/status
POST /admin/model-host/load
POST /admin/model-host/stop
POST /admin/model-host/drain
POST /admin/model-host/reset
```

Load, stop, drain, and reset accept `{"deployment":"local-qwen"}`. The legacy
`model` request field remains an input alias during the compatibility window.

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

The built-in model-management UI consumes this contract in the operator-product
PR. That view will show the node table and unhealthy callouts alongside model
selection and deployment mutation. PR 3 deliberately ships the authenticated
backend and CLI first; it does not claim that persistent UI mutation is ready.

Useful metrics include `sbproxy_model_host_active_requests`,
`sbproxy_model_host_queued_requests`, `sbproxy_model_host_deployment_state`,
`sbproxy_model_host_admission_rejections_total`, GPU VRAM, compute utilization,
and memory occupancy. Unknown compute utilization stays absent; memory occupancy
is a separate measurement and never masquerades as compute activity.

## Reload behavior

The runtime collects canonical and compatibility deployments from every origin.
It validates the complete catalog, cache and engine policy, routes, capacity,
and warm preparations before commit. Capacity is reserved before a staged warm
engine starts. On success it preserves unchanged engine generations and
replaces only changed deployments. On failure it tears down staged work and
keeps the prior routes and resident engines. A recreate launch failure also
restarts the stopped prior generation before returning the error.

A cache root, catalog revision, or engine foundation cannot change under a
resident deployment. Reconcile to an empty desired state first, then apply the
new foundation. This rule prevents two incompatible artifact stores or engine
sets from living in one worker process.

Cluster reconciliation shares that commit lock. Every process computes the
same global target from one immutable directory view, then filters it to exact
assignments for its stable node ID. The worker prepares that local projection
before publishing the new plan. A failed artifact, engine, or runtime prepare
therefore leaves both the previous local runtime and previous cluster plan
active. Control-only nodes keep a catalog-aligned empty runtime and never create
an engine merely to participate in placement.

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
