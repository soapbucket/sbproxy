# Model host

*Last modified: 2026-07-10*

SBproxy can own a model process on the same node as the gateway. The stable
single-node configuration lives under `proxy.model_host`; an AI provider with
`provider_type: managed_model` exposes a deployment to clients. Requests still
pass through the normal key, policy, budget, routing, and usage planes before
they reach the engine.

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

This PR is a single-node runtime. Persistent desired-state editing in the admin
UI, cluster membership, placement, peer dispatch, and fleet commands are later
work. Apple Metal receives a real completion test before this PR is published.
Live NVIDIA and multi-node certification on GCP is deliberately reserved for
the final integration PR. The generated
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

## Desired-state authority

`authority` says which system owns deployment definitions:

| Value | Behavior |
|---|---|
| `file_managed` | `sb.yml` is authoritative. This is the recommended and stable mode for this PR. |
| `admin_managed` | A revision store at `store_path` is authoritative. The runtime and restart-safe store contract exist, but public desired-state CRUD and the management UI ship in a later PR. |
| `cluster_authority` | A cluster controller will publish revisions. Multi-node membership and placement are not available yet. |

`file_managed` participates in ordinary config reload. Editing the file,
`sbproxy apply`, the file watcher, and `POST /admin/reload` all use the same
prepare-and-commit transaction.

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

`rollout: rolling` prepares a replacement generation before draining the old
one. This needs enough memory for both generations. `recreate` drains first and
is usually the safer choice on a single full GPU.

`required_labels` and replicas are part of the desired-state contract, but this
PR has no multi-node placement service. Keep replicas at one for a real
single-node deployment.

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
deleting artifacts, and it accounts for shared blobs. Continuous collection
after every on-demand acquisition is still outside the stable contract.

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
acquisition. Apple Silicon uses Metal, and a CPU worker uses system RAM.

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
environment.

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
the selected device's capacity.

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

Useful metrics include `sbproxy_model_host_active_requests`,
`sbproxy_model_host_queued_requests`, `sbproxy_model_host_deployment_state`,
`sbproxy_model_host_admission_rejections_total`, GPU VRAM, compute utilization,
and memory occupancy. Unknown compute utilization stays absent; memory occupancy
is a separate measurement and never masquerades as compute activity.

## Reload behavior

The runtime collects canonical and compatibility deployments from every origin.
It validates the complete catalog, cache and engine policy, routes, capacity,
and warm preparations before commit. On success it preserves unchanged engine
generations and replaces only changed deployments. On failure it tears down
staged work and keeps the prior routes and resident engines.

A cache root, catalog revision, or engine foundation cannot change under a
resident deployment. Reconcile to an empty desired state first, then apply the
new foundation. This rule prevents two incompatible artifact stores or engine
sets from living in one worker process.

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

Raw `hf:` references are deliberately rejected by this command because they
bypass the catalog v2 identity. Operator catalog selection remains available
through compatibility `serve.catalog_file` in this PR. Canonical custom-catalog
selection moves into the later model-management plane.

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
